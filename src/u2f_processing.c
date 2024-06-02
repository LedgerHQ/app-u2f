/*
*******************************************************************************
*   Ledger App FIDO U2F
*   (c) 2022 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#include <string.h>

#include "os.h"
#include "os_io_seproxyhal.h"
#include "cx.h"
#include "ux.h"

#include "u2f_processing.h"
#include "u2f_service.h"
#include "u2f_transport.h"
#include "u2f_impl.h"

#include "config.h"
#include "crypto.h"
#include "crypto_data.h"
#include "credential.h"
#include "ui_shared.h"
#include "globals.h"
#include "fido_known_apps.h"

#define U2F_VERSION      "U2F_V2"
#define U2F_VERSION_SIZE (sizeof(U2F_VERSION) - 1)

#define OFFSET_CLA  0
#define OFFSET_INS  1
#define OFFSET_P1   2
#define OFFSET_P2   3
#define OFFSET_DATA 7

#define FIDO_CLA             0x00
#define FIDO_INS_ENROLL      0x01
#define FIDO_INS_SIGN        0x02
#define FIDO_INS_GET_VERSION 0x03
#define FIDO_INS_CTAP2_PROXY 0x10

#define P1_U2F_CHECK_IS_REGISTERED    0x07
#define P1_U2F_REQUEST_USER_PRESENCE  0x03
#define P1_U2F_OPTIONAL_USER_PRESENCE 0x08

#define SW_NO_ERROR                 0x9000
#define SW_WRONG_LENGTH             0x6700
#define SW_CONDITIONS_NOT_SATISFIED 0x6985
#define SW_WRONG_DATA               0x6A80
#define SW_INCORRECT_P1P2           0x6A86
#define SW_INS_NOT_SUPPORTED        0x6D00
#define SW_CLA_NOT_SUPPORTED        0x6E00
#define SW_PROPRIETARY_INTERNAL     0x6FFF

#define U2F_ENROLL_RESERVED 0x05
static const uint8_t DUMMY_ZERO[] = {0x00};
#define SIGN_USER_PRESENCE_MASK 0x01
static const uint8_t DUMMY_USER_PRESENCE[] = {SIGN_USER_PRESENCE_MASK};

/********************************************************************/
/*  Temporary definition of u2f_get_cmd_msg_data_length             */
/*                                                                  */
/* This is necessary until all SDK are updated to expose it.        */
/* As some SDK already exposes it, this redefinition is a weak one. */
/********************************************************************/

#define APDU_MIN_HEADER      4
#define LC_FIRST_BYTE_OFFSET 4
#define LONG_ENC_LC_SIZE     3
#define LONG_ENC_LE_SIZE     2  // considering only scenarios where Lc is present

__attribute__((weak)) int u2f_get_cmd_msg_data_length(const uint8_t *buffer, uint16_t length) {
    /* Parse buffer to retrieve the data length.
       Only Extended encoding is supported */

    if (length < APDU_MIN_HEADER) {
        return -1;
    }

    if (length == APDU_MIN_HEADER) {
        // Either short or extended encoding with Lc and Le omitted
        return 0;
    }

    if (length == APDU_MIN_HEADER + 1) {
        // Short encoding, with next byte either Le or Lc with the other one omitted
        // There is no way to tell so no way to check the value
        // but anyway the data length is 0

        // Support this particular short encoding APDU as Fido Conformance Tool v1.7.0
        // is using it even though spec requires that short encoding should not be used
        // over HID.
        return 0;
    }

    if (length < APDU_MIN_HEADER + 3) {
        // Short encoding or bad length
        // We don't support short encoding
        return -1;
    }

    if (length == APDU_MIN_HEADER + 3) {
        if (buffer[4] != 0) {
            // Short encoding or bad length
            // We don't support short encoding
            return -1;
        }
        // Can't be short encoding as Lc = 0x00 would lead to invalid length
        // so extended encoding and either:
        // - Lc = 0x00 0x00 0x00 and Le is omitted
        // - Lc omitted and Le = 0x00 0xyy 0xzz
        // so no way to check the value
        // but anyway the data length is 0
        return 0;
    }

    if (buffer[LC_FIRST_BYTE_OFFSET] != 0) {
        // Short encoding or bad length
        // We don't support short encoding
        return -1;
    }

    // Can't be short encoding as Lc = 0 would lead to invalid length
    // so extended encoding with Lc field present, optionally Le (2B) is present too
    uint32_t dataLength =
        (buffer[LC_FIRST_BYTE_OFFSET + 1] << 8) | (buffer[LC_FIRST_BYTE_OFFSET + 2]);

    // Ensure that Lc value is consistent
    if ((APDU_MIN_HEADER + LONG_ENC_LC_SIZE + dataLength != length) &&
        (APDU_MIN_HEADER + LONG_ENC_LC_SIZE + dataLength + LONG_ENC_LE_SIZE != length)) {
        return -1;
    }

    return dataLength;
}

/******************************************/
/*     U2F message payload structures     */
/******************************************/

/* Registration Request Message
 *
 * +-------------------------+
 * | Challenge | Application |
 * +-------------------------+
 * | 32 bytes  |  32 bytes   |
 * +-------------------------+
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_reg_req_t {
    uint8_t challenge_param[32];
    uint8_t application_param[32];
} u2f_reg_req_t;

/* Registration Response Message: Success
 *
 * +----------+----------+----------------+------------+-------------+-----------*
 * | Reserved | User key | Key handle len | Key handle | Attestation | Signature |
 * +----------+----------+----------------+------------+-------------+-----------*
 * |  1 byte  | 65 bytes |    1 byte      |  L bytes   |             |           |
 * +----------+----------+----------------+------------+-------------+-----------*
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_reg_resp_base_t {
    uint8_t reserved_byte;
    uint8_t user_key[65];
    uint8_t key_handle_length;
    uint8_t key_handle[CREDENTIAL_MINIMAL_SIZE];  // We generate fix size key handles
    // attestation certificate: not in this base struct due to not const length
    // signature: not in this base struct due to not const offset nor length
} u2f_reg_resp_base_t;

/* Authentication Request Message
 *
 * +-------------------------+----------------+------------+
 * | Challenge | Application | Key handle len | Key handle |
 * +-------------------------+----------------+------------+
 * | 32 bytes  |  32 bytes   |    1 byte      |  L bytes   |
 * +-------------------------+----------------+------------+
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_auth_req_base_t {
    uint8_t challenge_param[32];
    uint8_t application_param[32];
    uint8_t key_handle_length;
    // key handle: not in this base struct due to not const length
} u2f_auth_req_base_t;

/* Authentication Response Message: Success
 *
 * +---------------+---------+-----------*
 * | User presence | Counter | Signature |
 * +---------------+---------+-----------*
 * |  1 byte       | 4 bytes |           |
 * +---------------+---------+-----------*
 */
// __attribute__((__packed__)) not necessary as we use only uint8_t
typedef struct u2f_auth_resp_base_t {
    uint8_t user_presence;
    uint8_t counter[4];
    // signature: not in this base struct due to not const length
} u2f_auth_resp_base_t;

/******************************************/
/*         U2F response helpers           */
/******************************************/

static int u2f_fill_status_code(uint16_t status_code, uint8_t *buffer) {
    buffer[0] = status_code >> 8;
    buffer[1] = status_code;
    return 2;
}

static void u2f_send_error(uint16_t status_code, unsigned short *tx) {
    *tx = u2f_fill_status_code(status_code, G_io_apdu_buffer);
}

static void u2f_compute_enroll_response_hash(u2f_reg_resp_base_t *reg_resp_base,
                                             uint16_t key_handle_length,
                                             uint8_t *data_hash) {
    cx_sha256_t hash;

    cx_sha256_init(&hash);
    cx_hash(&hash.header, 0, DUMMY_ZERO, 1, NULL, 0);
    cx_hash(&hash.header,
            0,
            globals_get_u2f_data()->application_param,
            sizeof(globals_get_u2f_data()->application_param),
            NULL,
            0);
    cx_hash(&hash.header,
            0,
            globals_get_u2f_data()->challenge_param,
            sizeof(globals_get_u2f_data()->challenge_param),
            NULL,
            0);
    cx_hash(&hash.header, 0, reg_resp_base->key_handle, key_handle_length, NULL, 0);
    cx_hash(&hash.header,
            CX_LAST,
            reg_resp_base->user_key,
            sizeof(reg_resp_base->user_key),
            data_hash,
            CX_SHA256_SIZE);
}

static int u2f_prepare_enroll_response(void) {
    int offset = 0;
    int result = -1;
    int key_handle_length;

    u2f_reg_resp_base_t *reg_resp_base = (u2f_reg_resp_base_t *) G_io_apdu_buffer;
    offset += sizeof(u2f_reg_resp_base_t);

    // Fill reserved byte
    reg_resp_base->reserved_byte = U2F_ENROLL_RESERVED;

    // Generate nonce
    cx_rng_no_throw(globals_get_u2f_data()->nonce, CREDENTIAL_NONCE_SIZE);

    // Generate private and public key and fill public key
    {
        cx_ecfp_private_key_t private_key;

        if (crypto_generate_private_key(globals_get_u2f_data()->nonce,
                                        &private_key,
                                        CX_CURVE_SECP256R1) != 0) {
            goto exit;
        }
        if (crypto_generate_public_key(&private_key, reg_resp_base->user_key, CX_CURVE_SECP256R1) <=
            0) {
            explicit_bzero(&private_key, sizeof(private_key));
            goto exit;
        }

        // Generate key handle
        // This also generate nonce needed for public key generation
        key_handle_length = credential_wrap(globals_get_u2f_data()->application_param,
                                            globals_get_u2f_data()->nonce,
                                            &private_key,
                                            reg_resp_base->key_handle,
                                            sizeof(reg_resp_base->key_handle));

        explicit_bzero(&private_key, sizeof(private_key));
    }

    // We only support generating key_handle with length of 64 bytes
    if (key_handle_length == sizeof(reg_resp_base->key_handle)) {
        // Fill key handle length
        reg_resp_base->key_handle_length = key_handle_length;

        // Fill attestation certificate
        memmove(G_io_apdu_buffer + offset, ATTESTATION_CERT, sizeof(ATTESTATION_CERT));
        offset += sizeof(ATTESTATION_CERT);

        // Prepare signature
        uint8_t data_hash[CX_SHA256_SIZE];
        u2f_compute_enroll_response_hash(reg_resp_base, key_handle_length, data_hash);

        // Fill signature
        uint8_t *signature = (G_io_apdu_buffer + offset);
        result = crypto_sign_attestation(data_hash, signature);
        if (result > 0) {
            offset += result;

            // Fill status code
            uint8_t *status = (G_io_apdu_buffer + offset);
            offset += u2f_fill_status_code(SW_NO_ERROR, status);
            result = offset;
        }
    }

exit:
    if (result < 0) {
        result = u2f_fill_status_code(SW_PROPRIETARY_INTERNAL, G_io_apdu_buffer);
    }

    return result;
}

static void u2f_compute_sign_response_hash(u2f_auth_resp_base_t *auth_resp_base,
                                           uint8_t *data_hash) {
    cx_sha256_t hash;

    cx_sha256_init(&hash);
    cx_hash(&hash.header,
            0,
            globals_get_u2f_data()->application_param,
            sizeof(globals_get_u2f_data()->application_param),
            NULL,
            0);
    cx_hash(&hash.header, 0, DUMMY_USER_PRESENCE, 1, NULL, 0);
    cx_hash(&hash.header, 0, auth_resp_base->counter, sizeof(auth_resp_base->counter), NULL, 0);
    cx_hash(&hash.header,
            CX_LAST,
            globals_get_u2f_data()->challenge_param,
            sizeof(globals_get_u2f_data()->challenge_param),
            data_hash,
            CX_SHA256_SIZE);
}

static int u2f_prepare_sign_response(void) {
    int offset = 0;
    int result = -1;

    u2f_auth_resp_base_t *auth_resp_base = (u2f_auth_resp_base_t *) G_io_apdu_buffer;
    offset += sizeof(u2f_auth_resp_base_t);

    // Fill user presence byte
    auth_resp_base->user_presence = SIGN_USER_PRESENCE_MASK;

    // Fill counter
    config_increase_and_get_authentification_counter(auth_resp_base->counter);

    // Prepare signature
    uint8_t data_hash[CX_SHA256_SIZE];
    u2f_compute_sign_response_hash(auth_resp_base, data_hash);

    // Generate private key and fill signature
    {
        cx_ecfp_private_key_t private_key;
        uint8_t *signature = (G_io_apdu_buffer + offset);

        if (crypto_generate_private_key(globals_get_u2f_data()->nonce,
                                        &private_key,
                                        CX_CURVE_SECP256R1) != 0) {
            goto exit;
        }
        result = crypto_sign_application(data_hash, &private_key, signature);

        explicit_bzero(&private_key, sizeof(private_key));

        if (result > 0) {
            offset += result;

            // Fill status code
            uint8_t *status = (G_io_apdu_buffer + offset);
            offset += u2f_fill_status_code(SW_NO_ERROR, status);
            result = offset;
        }
    }

exit:
    if (result < 0) {
        result = u2f_fill_status_code(SW_PROPRIETARY_INTERNAL, G_io_apdu_buffer);
    }

    return result;
}

static int u2f_process_user_presence_confirmed(void) {
    switch (globals_get_u2f_data()->user_presence_request_type) {
        case FIDO_INS_ENROLL:
            return u2f_prepare_enroll_response();

        case FIDO_INS_SIGN:
            return u2f_prepare_sign_response();

        default:
            break;
    }
    return u2f_fill_status_code(SW_PROPRIETARY_INTERNAL, G_io_apdu_buffer);
}

static int u2f_process_user_presence_cancelled(void) {
    return u2f_fill_status_code(SW_PROPRIETARY_INTERNAL, G_io_apdu_buffer);
}

/******************************************/
/*             U2F UX Flows               */
/******************************************/

#if defined(HAVE_BAGL)

static unsigned int u2f_callback_cancel(const bagl_element_t *element) {
    UNUSED(element);

    uint16_t tx = u2f_process_user_presence_cancelled();
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    ui_idle();
    return 0;  // DO NOT REDISPLAY THE BUTTON
}

static unsigned int u2f_callback_confirm(const bagl_element_t *element) {
    UNUSED(element);

    uint16_t tx = u2f_process_user_presence_confirmed();
    PRINTF("u2f_callback_confirm %d\n", tx);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    ui_idle();
    return 0;  // DO NOT REDISPLAY THE BUTTON
}

/* Register Flow */
UX_STEP_CB(ux_register_flow_0_step,
           pbb,
           u2f_callback_confirm(NULL),
           {
               &C_icon_validate_14,
               "Register",
               verifyName,
           });
UX_STEP_NOCB(ux_register_flow_1_step,
             bnnn_paging,
             {
                 .title = "Identifier",
                 .text = verifyHash,
             });
UX_STEP_CB(ux_register_flow_2_step,
           pbb,
           u2f_callback_cancel(NULL),
           {
               &C_icon_crossmark,
               "Abort",
               "register",
           });

UX_FLOW(ux_register_flow,
        &ux_register_flow_0_step,
        &ux_register_flow_1_step,
        &ux_register_flow_2_step,
        FLOW_LOOP);

/* Authenticate Flow */
UX_STEP_CB(ux_login_flow_0_step,
           pbb,
           u2f_callback_confirm(NULL),
           {
               &C_icon_validate_14,
               "Login",
               verifyName,
           });
UX_STEP_NOCB(ux_login_flow_1_step,
             bnnn_paging,
             {
                 .title = "Identifier",
                 .text = verifyHash,
             });
UX_STEP_CB(ux_login_flow_2_step,
           pbb,
           u2f_callback_cancel(NULL),
           {
               &C_icon_crossmark,
               "Abort",
               "login",
           });

UX_FLOW(ux_login_flow,
        &ux_login_flow_0_step,
        &ux_login_flow_1_step,
        &ux_login_flow_2_step,
        FLOW_LOOP);

#elif defined(HAVE_NBGL)

#include "nbgl_use_case.h"
#include "nbgl_page.h"
#include "nbgl_layout.h"

static nbgl_layoutTagValue_t pairs[2];
static nbgl_layout_t *layout;

enum { REGISTER_TOKEN = 0, LOGIN_TOKEN, TITLE_TOKEN };

static void u2f_review_register_choice(bool confirm) {
    if (confirm) {
        uint16_t tx = u2f_process_user_presence_confirmed();
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
        nbgl_useCaseStatus("REGISTRATION\nDONE", true, ui_idle);
    } else {
        uint16_t tx = u2f_process_user_presence_cancelled();
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
        nbgl_useCaseStatus("Registration\ncancelled", false, ui_idle);
    }
}

static void u2f_review_login_choice(bool confirm) {
    if (confirm) {
        uint16_t tx = u2f_process_user_presence_confirmed();
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
        nbgl_useCaseStatus("AUTHENTICATION\nSHARED", true, ui_idle);
    } else {
        uint16_t tx = u2f_process_user_presence_cancelled();
        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
        nbgl_useCaseStatus("Authentication\ncancelled", false, ui_idle);
    }
}

static void onActionCallback(int token, uint8_t index) {
    // Release the review layout.
    nbgl_layoutRelease(layout);

    if (token == REGISTER_TOKEN) {
        u2f_review_register_choice(index == 0);
    } else if (token == LOGIN_TOKEN) {
        u2f_review_login_choice(index == 0);
    }
}

static void start_review(uint8_t token, const char *confirm_text) {
    nbgl_layoutDescription_t layoutDescription;

    layoutDescription.modal = false;
    layoutDescription.withLeftBorder = true;
    layoutDescription.onActionCallback = onActionCallback;
    layoutDescription.tapActionText = NULL;
    layoutDescription.ticker.tickerCallback = NULL;

    layout = nbgl_layoutGet(&layoutDescription);

    nbgl_layoutBar_t bar;
    bar.text = APPNAME;
    bar.subText = NULL;
    bar.iconRight = NULL;
    bar.iconLeft = NULL;
    bar.token = TITLE_TOKEN;
    bar.centered = true;
    bar.inactive = false;
    bar.tuneId = TUNE_TAP_CASUAL;
    nbgl_layoutAddTouchableBar(layout, &bar);
    nbgl_layoutAddSeparationLine(layout);

    nbgl_layoutTagValueList_t tagValueList;
    pairs[0].item = "Domain";
    pairs[0].value = verifyName;
    pairs[1].item = "Domain id hash";
    pairs[1].value = verifyHash;
    tagValueList.nbPairs = 2;
    tagValueList.pairs = pairs;
    tagValueList.smallCaseForValue = false;
    tagValueList.nbMaxLinesForValue = 0;
    tagValueList.wrapping = false;
    nbgl_layoutAddTagValueList(layout, &tagValueList);

    nbgl_layoutChoiceButtons_t buttonsInfo = {.bottomText = (char *) PIC("Cancel"),
                                              .token = token,
                                              .topText = (char *) PIC(confirm_text),
                                              .style = ROUNDED_AND_FOOTER_STYLE,
                                              .tuneId = TUNE_TAP_CASUAL};
    nbgl_layoutAddChoiceButtons(layout, &buttonsInfo);

    nbgl_layoutDraw(layout);

    nbgl_refresh();
}

#endif

static void u2f_prompt_user_presence(bool enroll, uint8_t *applicationParameter) {
    UX_WAKE_UP();

    snprintf(verifyHash, sizeof(verifyHash), "%.*H", 32, applicationParameter);
    strcpy(verifyName, "Unknown");

    const char *name = fido_match_known_appid(applicationParameter);
    if (name != NULL) {
        strlcpy(verifyName, name, sizeof(verifyName));
    }

#if defined(HAVE_BAGL)
    G_ux.externalText = NULL;
    if (enroll) {
        ux_flow_init(0, ux_register_flow, NULL);
    } else {
        ux_flow_init(0, ux_login_flow, NULL);
    }
#elif defined(HAVE_NBGL)
    if (enroll) {
        start_review(REGISTER_TOKEN, "Register");
    } else {
        start_review(LOGIN_TOKEN, "Login");
    }
#endif
}

/******************************************/
/*           U2F APDU handlers            */
/******************************************/

static void u2f_handle_apdu_enroll(unsigned char *flags, unsigned short *tx, uint32_t data_length) {
    // Parse request and check length validity
    u2f_reg_req_t *reg_req = (u2f_reg_req_t *) (G_io_apdu_buffer + OFFSET_DATA);
    if (data_length != sizeof(u2f_reg_req_t)) {
        return u2f_send_error(SW_WRONG_LENGTH, tx);
    }

    // Check P1
    if (G_io_apdu_buffer[OFFSET_P1] != 0) {
        if (G_io_apdu_buffer[OFFSET_P1] == P1_U2F_REQUEST_USER_PRESENCE) {
            // Some platforms wrongly uses 0x03 as P1 for enroll:
            // https://searchfox.org/mozilla-central/source/third_party/rust/authenticator/src/consts.rs#55
            // https://github.com/Yubico/python-u2flib-host/issues/34
            // We choose to allow it.
        } else {
            return u2f_send_error(SW_INCORRECT_P1P2, tx);
        }
    }
    // Check P2
    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        return u2f_send_error(SW_INCORRECT_P1P2, tx);
    }

    // Backup challenge and application parameters to be used if user accept the request
    memmove(globals_get_u2f_data()->challenge_param,
            reg_req->challenge_param,
            sizeof(reg_req->challenge_param));
    memmove(globals_get_u2f_data()->application_param,
            reg_req->application_param,
            sizeof(reg_req->application_param));

#ifndef HAVE_NO_USER_PRESENCE_CHECK
    globals_get_u2f_data()->user_presence_request_type = G_io_apdu_buffer[OFFSET_INS];
    if (G_io_u2f.media == U2F_MEDIA_USB) {
        u2f_message_set_autoreply_wait_user_presence(&G_io_u2f, true);
    }
    u2f_prompt_user_presence(true, globals_get_u2f_data()->application_param);
    *flags |= IO_ASYNCH_REPLY;
#else
#warning Having no user presence check is against U2F standard
    *tx = u2f_process_user_presence_confirmed();
#endif
}

static void u2f_handle_apdu_sign(unsigned char *flags, unsigned short *tx, uint32_t data_length) {
    uint8_t *nonce;
    // Parse request base and check length validity
    u2f_auth_req_base_t *auth_req_base = (u2f_auth_req_base_t *) (G_io_apdu_buffer + OFFSET_DATA);
    if (data_length < sizeof(u2f_auth_req_base_t)) {
        return u2f_send_error(SW_WRONG_LENGTH, tx);
    }

    // Parse request key handle and check length validity
    uint8_t *key_handle = G_io_apdu_buffer + OFFSET_DATA + sizeof(u2f_auth_req_base_t);
    if (data_length != sizeof(u2f_auth_req_base_t) + auth_req_base->key_handle_length) {
        return u2f_send_error(SW_WRONG_LENGTH, tx);
    }

    // Parse request P1
    bool sign = false;
    switch (G_io_apdu_buffer[OFFSET_P1]) {
        case P1_U2F_CHECK_IS_REGISTERED:
            break;
        case P1_U2F_REQUEST_USER_PRESENCE:
        case P1_U2F_OPTIONAL_USER_PRESENCE:  // proof of user presence is always required (1.2)
            sign = true;
            break;
        default:
            return u2f_send_error(SW_INCORRECT_P1P2, tx);
    }

    // Check P2
    if (G_io_apdu_buffer[OFFSET_P2] != 0) {
        return u2f_send_error(SW_INCORRECT_P1P2, tx);
    }

    // Check the key handle validity immediately
    // Store the nonce in globals u2f_data for response generation
    if (credential_unwrap(auth_req_base->application_param,
                          key_handle,
                          auth_req_base->key_handle_length,
                          &nonce) < 0) {
        return u2f_send_error(SW_WRONG_DATA, tx);
    }

    // If we only check user presence, get rid of the private key and answer immediately
    if (!sign) {
        return u2f_send_error(SW_CONDITIONS_NOT_SATISFIED, tx);
    }

    // Backup nonce, challenge and application parameters to be used if user accept the request
    memmove(globals_get_u2f_data()->nonce, nonce, CREDENTIAL_NONCE_SIZE);
    memmove(globals_get_u2f_data()->challenge_param,
            auth_req_base->challenge_param,
            sizeof(auth_req_base->challenge_param));
    memmove(globals_get_u2f_data()->application_param,
            auth_req_base->application_param,
            sizeof(auth_req_base->application_param));

#ifndef HAVE_NO_USER_PRESENCE_CHECK
    globals_get_u2f_data()->user_presence_request_type = G_io_apdu_buffer[OFFSET_INS];
    if (G_io_u2f.media == U2F_MEDIA_USB) {
        u2f_message_set_autoreply_wait_user_presence(&G_io_u2f, true);
    }
    u2f_prompt_user_presence(false, globals_get_u2f_data()->application_param);
    *flags |= IO_ASYNCH_REPLY;
#else
#warning Having no user presence check is against U2F standard
    *tx = u2f_process_user_presence_confirmed();
#endif
}

static void u2f_handle_apdu_get_version(unsigned char *flags,
                                        unsigned short *tx,
                                        uint32_t data_length) {
    UNUSED(flags);

    int offset = 0;

    if (data_length != 0) {
        return u2f_send_error(SW_WRONG_LENGTH, tx);
    }

    if ((G_io_apdu_buffer[OFFSET_P1] != 0) || (G_io_apdu_buffer[OFFSET_P2] != 0)) {
        return u2f_send_error(SW_INCORRECT_P1P2, tx);
    }

    // Fill version
    memmove(G_io_apdu_buffer, U2F_VERSION, U2F_VERSION_SIZE);
    offset += U2F_VERSION_SIZE;

    // Fill status code
    uint8_t *status = (G_io_apdu_buffer + offset);
    offset += u2f_fill_status_code(SW_NO_ERROR, status);

    *tx = offset;
}

void handleApdu(unsigned char *flags, unsigned short *tx, unsigned short length) {
    PRINTF("Media handleApdu %d\n", G_io_app.apdu_state);

    int data_length = u2f_get_cmd_msg_data_length(G_io_apdu_buffer, length);
    if (data_length < 0) {
        return u2f_send_error(SW_WRONG_LENGTH, tx);
    }

    if (G_io_apdu_buffer[OFFSET_CLA] != FIDO_CLA) {
        return u2f_send_error(SW_CLA_NOT_SUPPORTED, tx);
    }

    switch (G_io_apdu_buffer[OFFSET_INS]) {
        case FIDO_INS_ENROLL:
            PRINTF("enroll\n");
            u2f_handle_apdu_enroll(flags, tx, data_length);
            break;
        case FIDO_INS_SIGN:
            PRINTF("sign\n");
            u2f_handle_apdu_sign(flags, tx, data_length);
            break;
        case FIDO_INS_GET_VERSION:
            PRINTF("version\n");
            u2f_handle_apdu_get_version(flags, tx, data_length);
            break;
        default:
            PRINTF("unsupported\n");
            return u2f_send_error(SW_INS_NOT_SUPPORTED, tx);
    }
}
