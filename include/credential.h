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

#ifndef __CREDENTIAL_H__
#define __CREDENTIAL_H__

#define CREDENTIAL_NONCE_SIZE       32
#define CREDENTIAL_PRIVATE_KEY_SIZE CX_SHA256_SIZE
#define CREDENTIAL_SIGNATURE_SIZE   CX_SHA256_SIZE

#define CREDENTIAL_MINIMAL_SIZE (CREDENTIAL_NONCE_SIZE + CREDENTIAL_SIGNATURE_SIZE)

/**
 * Wrap credential to be sent to platform:
 * inputs:
 *  - rpIdHash (or application parameter in U2F)
 *  - the random nonce to be associated to this credential
 *  - the private key associated to this credential
 *
 * outputs:
 * - credId will be stored in buffer
 *
 * Return:
 * - > 0 the credIdLen
 * - < 0 an error occurred
 */
int credential_wrap(const uint8_t *rpIdHash,
                    const uint8_t *nonce,
                    const cx_ecfp_private_key_t *private_key,
                    uint8_t *buffer,
                    uint32_t bufferLen);

/**
 * Check and unwrap credential from credId received from platform:
 * inputs:
 *  - rpIdHash (or application parameter in U2F)
 *  - credId and credIdLen
 *
 * outputs:
 * - the random nonce to associated to this credential
 *
 * Return:
 * - == 0 if everything went fine
 * - < 0 an error occurred (wrong size, wrong signature, ...)
 */
int credential_unwrap(const uint8_t *rpIdHash,
                      uint8_t *credId,
                      uint32_t credIdLen,
                      uint8_t **nonce);

#endif
