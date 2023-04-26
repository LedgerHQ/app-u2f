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
#include "cx.h"

#include "config.h"
#include "crypto_data.h"
#include "credential.h"

bool crypto_compare(const uint8_t *a, const uint8_t *b, uint16_t length) {
    uint16_t given_length = length;
    uint8_t status = 0;
    uint16_t counter = 0;

    if (length == 0) {
        return false;
    }
    while ((length--) != 0) {
        status |= a[length] ^ b[length];
        counter++;
    }
    if (counter != given_length) {
        return false;
    }
    return (status == 0);
}

int crypto_generate_private_key(const uint8_t *nonce,
                                cx_ecfp_private_key_t *private_key,
                                cx_curve_t curve) {
    int status = 0;
    uint8_t private_key_data[CREDENTIAL_PRIVATE_KEY_SIZE];

    cx_hmac_sha256((const uint8_t *) N_u2f.privateHmacKey,
                   sizeof(N_u2f.privateHmacKey),
                   nonce,
                   CREDENTIAL_NONCE_SIZE,
                   private_key_data,
                   CREDENTIAL_PRIVATE_KEY_SIZE);
    if (cx_ecfp_init_private_key_no_throw(curve,
                                          private_key_data,
                                          CREDENTIAL_PRIVATE_KEY_SIZE,
                                          private_key) != CX_OK) {
        PRINTF("Fail to init private key\n");
        status = -1;
    }

    // Reset the private key so that it doesn't stay in RAM.
    explicit_bzero(private_key_data, CREDENTIAL_PRIVATE_KEY_SIZE);

    return status;
}

int crypto_generate_public_key(cx_ecfp_private_key_t *private_key,
                               uint8_t *public_key,
                               cx_curve_t curve) {
    cx_ecfp_public_key_t app_public_key;

    if (cx_ecfp_generate_pair_no_throw(curve, &app_public_key, private_key, 1) != CX_OK) {
        PRINTF("Fail to generate pair\n");
        return -1;
    }
    memmove(public_key, app_public_key.W, app_public_key.W_len);

    return app_public_key.W_len;
}

static int crypto_sign(const uint8_t *data_hash,
                       cx_ecfp_private_key_t *private_key,
                       uint8_t *signature) {
    size_t length;
    size_t domain_length;

    if (cx_ecdomain_parameters_length(CX_CURVE_SECP256R1, &domain_length) != CX_OK) {
        return -1;
    }

    length = 6 + 2 * (domain_length + 1);
    if (cx_ecdsa_sign_no_throw(private_key,
                               CX_RND_TRNG | CX_LAST,
                               CX_NONE,
                               data_hash,
                               CX_SHA256_SIZE,
                               signature,
                               &length,
                               NULL) != CX_OK) {
        PRINTF("Fail to sign\n");
        return -1;
    }
    signature[0] = 0x30;
    return length;
}

int crypto_sign_application(const uint8_t *data_hash,
                            cx_ecfp_private_key_t *private_key,
                            uint8_t *signature) {
    return crypto_sign(data_hash, private_key, signature);
}

int crypto_sign_attestation(const uint8_t *data_hash, uint8_t *signature) {
    cx_ecfp_private_key_t attestation_private_key;

    if (cx_ecfp_init_private_key_no_throw(CX_CURVE_SECP256R1,
                                          ATTESTATION_KEY,
                                          32,
                                          &attestation_private_key) != CX_OK) {
        return -1;
    }

    return crypto_sign(data_hash, &attestation_private_key, signature);
}
