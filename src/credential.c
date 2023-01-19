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

#include "credential.h"
#include "crypto.h"
#include "config.h"

static void compute_signature(const uint8_t *rpIdHash,
                              const cx_ecfp_private_key_t *private_key,
                              uint8_t *signatureBuffer) {
    cx_hmac_sha256_t hmacCtx;

    cx_hmac_sha256_init(&hmacCtx,
                        (const uint8_t *) N_u2f.privateHmacKey,
                        sizeof(N_u2f.privateHmacKey));
    cx_hmac((cx_hmac_t *) &hmacCtx, 0, rpIdHash, CX_SHA256_SIZE, NULL, 0);
    cx_hmac((cx_hmac_t *) &hmacCtx,
            CX_LAST,
            private_key->d,
            32,
            signatureBuffer,
            CREDENTIAL_SIGNATURE_SIZE);
}

int credential_wrap(const uint8_t *rpIdHash,
                    const uint8_t *nonce,
                    const cx_ecfp_private_key_t *private_key,
                    uint8_t *buffer,
                    uint32_t bufferLen) {
    int offset = 0;

    // TODO make it retrocompatible

    // Check for minimal size
    if (bufferLen < CREDENTIAL_MINIMAL_SIZE) {
        PRINTF("Bad size\n");
        return -1;
    }

    // Add nonce to the credential
    if (nonce == NULL) {
        PRINTF("Missing nonce\n");
        return -1;
    }
    memcpy(buffer + offset, nonce, CREDENTIAL_NONCE_SIZE);
    offset += CREDENTIAL_NONCE_SIZE;

    compute_signature(rpIdHash, private_key, buffer + offset);
    offset += CREDENTIAL_SIGNATURE_SIZE;

    return offset;
}

int credential_unwrap(const uint8_t *rpIdHash,
                      uint8_t *credId,
                      uint32_t credIdLen,
                      uint8_t **noncePtr) {
    cx_ecfp_private_key_t private_key;
    uint8_t computedSignature[CREDENTIAL_SIGNATURE_SIZE];

    // Check for exact size
    if (credIdLen != CREDENTIAL_MINIMAL_SIZE) {
        PRINTF("wrong size\n");
        return -1;
    }

    // Generate private key
    crypto_generate_private_key(credId, &private_key, CX_CURVE_SECP256R1);

    // Check credential signature
    compute_signature(rpIdHash, &private_key, computedSignature);
    explicit_bzero(&private_key, sizeof(private_key));

    if (!crypto_compare(computedSignature,
                        credId + CREDENTIAL_NONCE_SIZE,
                        CREDENTIAL_SIGNATURE_SIZE)) {
        PRINTF("Wrong signature\n");
        explicit_bzero(computedSignature, sizeof(computedSignature));
        return -1;
    }

    // Parse nonce field
    if (noncePtr != NULL) {
        *noncePtr = credId;
    }

    return 0;
}
