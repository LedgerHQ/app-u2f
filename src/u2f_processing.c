/*
*******************************************************************************
*   Portable FIDO U2F implementation
*   (c) 2016 Ledger
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

#include <stdint.h>
#include <string.h>
#include "u2f_service.h"
#include "u2f_transport.h"
#include "u2f_processing.h"
#include "u2f_crypto.h"
#include "u2f_counter.h"

static const uint8_t SW_SUCCESS[] = {0x90, 0x00};
static const uint8_t SW_PROOF_OF_PRESENCE_REQUIRED[] = {0x69, 0x85};
static const uint8_t SW_BAD_KEY_HANDLE[] = {0x6A, 0x80};

static const uint8_t VERSION[] = {'U', '2', 'F', '_', 'V', '2', 0x90, 0x00};
static const uint8_t DUMMY_ZERO[] = {0x00};

static const uint8_t SW_UNKNOWN_INSTRUCTION[] = {0x6d, 0x00};
static const uint8_t SW_UNKNOWN_CLASS[] = {0x6e, 0x00};
static const uint8_t SW_WRONG_LENGTH[] = {0x67, 0x00};

static const uint8_t NOTIFY_USER_PRESENCE_NEEDED[] = {
    KEEPALIVE_REASON_TUP_NEEDED};

#define INIT_U2F_VERSION 0x02
#define INIT_DEVICE_VERSION_MAJOR 0
#define INIT_DEVICE_VERSION_MINOR 1
#define INIT_BUILD_VERSION 0
#define INIT_CAPABILITIES 0x00

#define FIDO_CLA 0x00
#define FIDO_INS_ENROLL 0x01
#define FIDO_INS_SIGN 0x02
#define FIDO_INS_GET_VERSION 0x03

#define FIDO_INS_PROP_GET_COUNTER 0xC0 // U2F_VENDOR_FIRST

#define P1_SIGN_CHECK_ONLY 0x07
#define P1_SIGN_SIGN 0x03

#define U2F_ENROLL_RESERVED 0x05
#define SIGN_USER_PRESENCE_MASK 0x01

#define MAX_SEQ_TIMEOUT_MS 500
#define MAX_KEEPALIVE_TIMEOUT_MS 500

static const uint8_t DUMMY_USER_PRESENCE[] = {SIGN_USER_PRESENCE_MASK};

void u2f_handle_ux_callback(u2f_service_t *service) {
    if (service->transportMedia == U2F_MEDIA_USB) {
        // u2f_send_fragmented_response(service, U2F_CMD_MSG,
        // (uint8_t*)SW_PROOF_OF_PRESENCE_REQUIRED,
        // sizeof(SW_PROOF_OF_PRESENCE_REQUIRED), false);
        u2f_send_fragmented_response(
            service, U2F_CMD_MSG, (uint8_t *)SW_PROOF_OF_PRESENCE_REQUIRED,
            sizeof(SW_PROOF_OF_PRESENCE_REQUIRED), true);
    } else if (service->transportMedia == U2F_MEDIA_BLE) {
        u2f_send_fragmented_response(
            service, U2F_CMD_KEEPALIVE, (uint8_t *)NOTIFY_USER_PRESENCE_NEEDED,
            sizeof(NOTIFY_USER_PRESENCE_NEEDED), false);
    }
}

void u2f_handle_enroll(u2f_service_t *service, uint8_t p1, uint8_t p2,
                       uint8_t *buffer, uint16_t length) {
    uint8_t challengeParameter[32];
    uint8_t applicationParameter[32];

    (void)p1;
    (void)p2;
    if (length != 32 + 32) {
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     (uint8_t *)SW_WRONG_LENGTH,
                                     sizeof(SW_WRONG_LENGTH), true);
        return;
    }
    if (!u2f_crypto_available()) {
        u2f_response_error(service, ERROR_PROP_DEVICE_NOT_SETUP, true,
                           service->channel);
        return;
    }

    os_memmove(challengeParameter, buffer, 32);
    os_memmove(applicationParameter, buffer + 32, 32);

#ifdef TEST_FAKE_USER_PRESENCE
    if (0) {
#else
    if (!service->userPresence) {
#endif
        // screen_printf("user presence\n");
        // TODO : answer before/after depending on the implementation internal
        // logic
        if (!service->promptUserPresence) {
            service->promptUserPresence = true;
            service->promptUserPresenceFunction(service, true,
                                                applicationParameter);
        }

        /* will be sent after UX asynch replied
        if (service->transportMedia == U2F_MEDIA_USB) {
            // u2f_send_fragmented_response(service, U2F_CMD_MSG,
            // (uint8_t*)SW_PROOF_OF_PRESENCE_REQUIRED,
            // sizeof(SW_PROOF_OF_PRESENCE_REQUIRED), false);
            u2f_send_fragmented_response(
                service, U2F_CMD_MSG, (uint8_t *)SW_PROOF_OF_PRESENCE_REQUIRED,
                sizeof(SW_PROOF_OF_PRESENCE_REQUIRED), true);
        } else if (service->transportMedia == U2F_MEDIA_BLE) {
            u2f_send_fragmented_response(service, U2F_CMD_KEEPALIVE,
                                         (uint8_t *)NOTIFY_USER_PRESENCE_NEEDED,
                                         sizeof(NOTIFY_USER_PRESENCE_NEEDED),
                                         false);
            service->requireKeepalive = true;
        }

        */
        if (service->transportMedia == U2F_MEDIA_BLE) {
            service->requireKeepalive = true;
        }
    } else {
        // screen_printf("ok to proceed\n");
        uint16_t offset = 0;
        uint16_t keyHandleLength;
        uint16_t signatureLength;
#ifndef HAVE_NO_USER_PRESENCE_CHECK
        service->userPresence = false;
#endif // HAVE_NO_USER_PRESENCE_CHECK
        service->messageBuffer[offset++] = U2F_ENROLL_RESERVED;
        keyHandleLength = u2f_crypto_generate_key_and_wrap(
            applicationParameter, service->messageBuffer + offset,
            service->messageBuffer + offset + 65 + 1);
        if ((keyHandleLength == 0) || (keyHandleLength > 255)) {
            goto internal_error;
        }
        offset += 65;
        service->messageBuffer[offset++] = keyHandleLength;
        offset += keyHandleLength;
        offset += u2f_crypto_copy_attestation_certificate(
            service->messageBuffer + offset);
        // Compute signature
        if (!u2f_sign_init() || !u2f_sign_update(DUMMY_ZERO, 1) ||
            !u2f_sign_update(applicationParameter, 32) ||
            !u2f_sign_update(challengeParameter, 32) ||
            !u2f_sign_update(service->messageBuffer + 1 + 65 + 1,
                             keyHandleLength) ||
            !u2f_sign_update(service->messageBuffer + 1, 65)) {
            goto internal_error;
        }
        signatureLength =
            u2f_crypto_sign_attestation(service->messageBuffer + offset);
        if (signatureLength == 0) {
            goto internal_error;
        }
        offset += signatureLength;
        os_memmove(service->messageBuffer + offset, SW_SUCCESS,
                   sizeof(SW_SUCCESS));
        offset += sizeof(SW_SUCCESS);
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     service->messageBuffer, offset, true);
    }
    return;
internal_error:
    // screen_printf("internal error\n");
    u2f_response_error(service, ERROR_PROP_INTERNAL_ERROR_APDU, true,
                       service->channel);
    u2f_crypto_reset();
}

void u2f_handle_sign(u2f_service_t *service, uint8_t p1, uint8_t p2,
                     uint8_t *buffer, uint16_t length) {
    (void)p2;
    uint8_t challengeParameter[32];
    uint8_t applicationParameter[32];
    uint8_t keyHandle[64];
    uint8_t keyHandleLength;
    bool sign = (p1 == P1_SIGN_SIGN);

    if (length < 32 + 32 + 1) {
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     (uint8_t *)SW_WRONG_LENGTH,
                                     sizeof(SW_WRONG_LENGTH), true);
        return;
    }
    if ((p1 != P1_SIGN_CHECK_ONLY) && (p1 != P1_SIGN_SIGN)) {
        u2f_response_error(service, ERROR_PROP_INVALID_PARAMETERS_APDU, true,
                           service->channel);
        return;
    }
    if (!u2f_crypto_available()) {
        u2f_response_error(service, ERROR_PROP_DEVICE_NOT_SETUP, true,
                           service->channel);
        return;
    }
    os_memmove(challengeParameter, buffer, 32);
    os_memmove(applicationParameter, buffer + 32, 32);
    keyHandleLength = buffer[64];
    if (keyHandleLength > sizeof(keyHandle)) {
        u2f_response_error(service, ERROR_PROP_INVALID_DATA_APDU, true,
                           service->channel);
        return;
    }
    os_memmove(keyHandle, buffer + 65, keyHandleLength);

    // Check the key handle validity immediately
    if (!u2f_crypto_unwrap(keyHandle, keyHandleLength, applicationParameter)) {
        u2f_crypto_reset();
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     (uint8_t *)SW_BAD_KEY_HANDLE,
                                     sizeof(SW_BAD_KEY_HANDLE), true);
        return;
    }
    // screen_printf("unwrapped\n");
    // If we only check user presence, get rid of the private key immediately
    if (!sign) {
        u2f_crypto_reset();
    }

#ifndef HAVE_NO_USER_PRESENCE_CHECK
    // If the application parameter doesn't match the last validated one, reset
    // the user presence
    if (service->confirmedApplicationParameter != NULL) {
        if (!compare_constantTime(applicationParameter,
                                  service->confirmedApplicationParameter, 32)) {
            service->userPresence = false;
        }
    }
#endif // HAVE_NO_USER_PRESENCE_CHECK

#ifdef TEST_FAKE_USER_PRESENCE
    if (0) {
#else
    if (!service->userPresence) {
#endif
        // TODO : answer before/after depending on the implementation internal
        // logic
        if (!service->promptUserPresence) {
            service->promptUserPresence = true;
            if (service->confirmedApplicationParameter != NULL) {
                os_memmove(service->confirmedApplicationParameter,
                           applicationParameter, 32);
            }
            service->promptUserPresenceFunction(service, false,
                                                applicationParameter);
        }
        /* send response after UX asynch reply
        if (service->transportMedia == U2F_MEDIA_USB) {
            // u2f_send_fragmented_response(service, U2F_CMD_MSG,
            // (uint8_t*)SW_PROOF_OF_PRESENCE_REQUIRED,
            // sizeof(SW_PROOF_OF_PRESENCE_REQUIRED), false);
            u2f_send_fragmented_response(
                service, U2F_CMD_MSG, (uint8_t *)SW_PROOF_OF_PRESENCE_REQUIRED,
                sizeof(SW_PROOF_OF_PRESENCE_REQUIRED), true);
        } else if (service->transportMedia == U2F_MEDIA_BLE) {
            u2f_send_fragmented_response(service, U2F_CMD_KEEPALIVE,
                                         (uint8_t *)NOTIFY_USER_PRESENCE_NEEDED,
                                         sizeof(NOTIFY_USER_PRESENCE_NEEDED),
                                         false);
            service->requireKeepalive = true;
        }
        */
        if (service->transportMedia == U2F_MEDIA_BLE) {
            service->requireKeepalive = true;
        }
    } else {
        uint16_t offset = 0;
        uint16_t signatureLength;
#ifdef HAVE_NO_USER_PRESENCE_CHECK
        if (!sign && !service->userPresence)
#else  // HAVE_NO_USER_PRESENCE_CHECK
        if (!sign)
#endif // HAVE_NO_USER_PRESENCE_CHECK
        {
            u2f_send_fragmented_response(
                service, U2F_CMD_MSG, (uint8_t *)SW_PROOF_OF_PRESENCE_REQUIRED,
                sizeof(SW_PROOF_OF_PRESENCE_REQUIRED), true);
            return;
        }
#ifndef HAVE_NO_USER_PRESENCE_CHECK
        service->userPresence = false;
#endif // HAVE_NO_USER_PRESENCE_CHECK

        // screen_printf("confirming\n");
        service->messageBuffer[offset++] = SIGN_USER_PRESENCE_MASK;
        offset += u2f_counter_increase_and_get(service->messageBuffer + offset);
        // Compute signature
        if (!u2f_sign_init() || !u2f_sign_update(applicationParameter, 32) ||
            !u2f_sign_update(DUMMY_USER_PRESENCE, 1) ||
            !u2f_sign_update(service->messageBuffer + 1, 4) ||
            !u2f_sign_update(challengeParameter, 32)) {
            goto internal_error;
        }
        signatureLength =
            u2f_crypto_sign_application(service->messageBuffer + offset);
        if (signatureLength == 0) {
            goto internal_error;
        }
        offset += signatureLength;
        os_memmove(service->messageBuffer + offset, SW_SUCCESS,
                   sizeof(SW_SUCCESS));
        offset += sizeof(SW_SUCCESS);
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     service->messageBuffer, offset, true);
    }
    return;
internal_error:
    u2f_response_error(service, ERROR_PROP_INTERNAL_ERROR_APDU, true,
                       service->channel);
    u2f_crypto_reset();
}

void u2f_handle_get_version(u2f_service_t *service, uint8_t p1, uint8_t p2,
                            uint8_t *buffer, uint16_t length) {
    // screen_printf("U2F version\n");
    (void)p1;
    (void)p2;
    (void)buffer;
    if (length != 0) {
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     (uint8_t *)SW_WRONG_LENGTH,
                                     sizeof(SW_WRONG_LENGTH), true);
        return;
    }
    u2f_send_fragmented_response(service, U2F_CMD_MSG, (uint8_t *)VERSION,
                                 sizeof(VERSION), true);
}

void u2f_handle_prop_get_counter(u2f_service_t *service, uint8_t p1, uint8_t p2,
                                 uint8_t *buffer, uint16_t length) {
    // screen_printf("U2F version\n");
    (void)p1;
    (void)p2;
    (void)buffer;
    uint8_t counterLength;
    if (length != 0) {
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     (uint8_t *)SW_WRONG_LENGTH,
                                     sizeof(SW_WRONG_LENGTH), true);
        return;
    }

    counterLength = u2f_counter_get(service->messageBuffer);
    u2f_send_fragmented_response(service, U2F_CMD_MSG, service->messageBuffer,
                                 counterLength, true);
}

void u2f_handle_cmd_init(u2f_service_t *service, uint8_t *buffer,
                         uint16_t length, uint8_t *channelInit) {
    // screen_printf("U2F init\n");
    uint8_t channel[4];
    (void)length;
    uint16_t offset = 0;
    if (u2f_is_channel_forbidden(channelInit)) {
        u2f_response_error(service, ERROR_INVALID_CID, true, channelInit);
        return;
    }
    if (u2f_is_channel_broadcast(channelInit)) {
        u2f_crypto_random(channel, 4);
    } else {
        os_memmove(channel, channelInit, 4);
    }
    os_memmove(service->messageBuffer + offset, buffer, 8);
    offset += 8;
    os_memmove(service->messageBuffer + offset, channel, 4);
    offset += 4;
    service->messageBuffer[offset++] = INIT_U2F_VERSION;
    service->messageBuffer[offset++] = INIT_DEVICE_VERSION_MAJOR;
    service->messageBuffer[offset++] = INIT_DEVICE_VERSION_MINOR;
    service->messageBuffer[offset++] = INIT_BUILD_VERSION;
    service->messageBuffer[offset++] = INIT_CAPABILITIES;
    if (u2f_is_channel_broadcast(channelInit)) {
        os_memset(service->channel, 0xff, 4);
    } else {
        os_memmove(service->channel, channel, 4);
    }
    service->keepUserPresence = true;
    u2f_send_fragmented_response(service, U2F_CMD_INIT, service->messageBuffer,
                                 offset, true);
    // os_memmove(service->channel, channel, 4);
}

void u2f_handle_cmd_ping(u2f_service_t *service, uint8_t *buffer,
                         uint16_t length) {
    // screen_printf("U2F ping\n");
    u2f_send_fragmented_response(service, U2F_CMD_PING, buffer, length, true);
}

void u2f_handle_cmd_msg(u2f_service_t *service, uint8_t *buffer,
                        uint16_t length) {
    // screen_printf("U2F msg\n");
    uint8_t cla = buffer[0];
    uint8_t ins = buffer[1];
    uint8_t p1 = buffer[2];
    uint8_t p2 = buffer[3];
    uint32_t dataLength = (buffer[4] << 16) | (buffer[5] << 8) | (buffer[6]);
    if ((dataLength != (uint16_t)(length - 9)) &&
        (dataLength != (uint16_t)(length - 7))) { // Le is optional
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     (uint8_t *)SW_WRONG_LENGTH,
                                     sizeof(SW_WRONG_LENGTH), true);
        return;
    }
    if (cla != FIDO_CLA) {
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     (uint8_t *)SW_UNKNOWN_CLASS,
                                     sizeof(SW_UNKNOWN_CLASS), true);
        return;
    }
    switch (ins) {
    case FIDO_INS_ENROLL:
        // screen_printf("enroll\n");
        u2f_handle_enroll(service, p1, p2, buffer + 7, dataLength);
        break;
    case FIDO_INS_SIGN:
        // screen_printf("sign\n");
        u2f_handle_sign(service, p1, p2, buffer + 7, dataLength);
        break;
    case FIDO_INS_GET_VERSION:
        // screen_printf("version\n");
        u2f_handle_get_version(service, p1, p2, buffer + 7, dataLength);
        break;
    case FIDO_INS_PROP_GET_COUNTER:
        u2f_handle_prop_get_counter(service, p1, p2, buffer + 7, dataLength);
        break;
    default:
        // screen_printf("unsupported\n");
        u2f_send_fragmented_response(service, U2F_CMD_MSG,
                                     (uint8_t *)SW_UNKNOWN_INSTRUCTION,
                                     sizeof(SW_UNKNOWN_INSTRUCTION), true);
        return;
    }
}

void u2f_process_message(u2f_service_t *service, uint8_t *buffer,
                         uint8_t *channel) {
    uint8_t cmd = buffer[0];
    uint16_t length = (buffer[1] << 8) | (buffer[2]);
    switch (cmd) {
    case U2F_CMD_INIT:
        u2f_handle_cmd_init(service, buffer + 3, length, channel);
        break;
    case U2F_CMD_PING:
        service->pendingContinuation = false;
        u2f_handle_cmd_ping(service, buffer + 3, length);
        break;
    case U2F_CMD_MSG:
        service->pendingContinuation = false;
        if (!service->noReentry && service->runningCommand) {
            u2f_response_error(service, ERROR_CHANNEL_BUSY, false,
                               service->channel);
            break;
        }
        service->runningCommand = true;
        u2f_handle_cmd_msg(service, buffer + 3, length);
        break;
    }
}

void u2f_timeout(u2f_service_t *service) {
    service->timerNeedGeneralStatus = true;
    if ((service->transportMedia == U2F_MEDIA_USB) &&
        (service->pendingContinuation)) {
        service->seqTimeout += service->timerInterval;
        if (service->seqTimeout > MAX_SEQ_TIMEOUT_MS) {
            service->pendingContinuation = false;
            u2f_response_error(service, ERROR_MSG_TIMEOUT, true,
                               service->lastContinuationChannel);
        }
    }
    if ((service->transportMedia == U2F_MEDIA_BLE) &&
        (service->requireKeepalive)) {
        service->keepaliveTimeout += service->timerInterval;
        if (service->keepaliveTimeout > MAX_KEEPALIVE_TIMEOUT_MS) {
            service->keepaliveTimeout = 0;
            u2f_send_fragmented_response(service, U2F_CMD_KEEPALIVE,
                                         (uint8_t *)NOTIFY_USER_PRESENCE_NEEDED,
                                         sizeof(NOTIFY_USER_PRESENCE_NEEDED),
                                         false);
        }
    }
}
