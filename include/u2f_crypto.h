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
#include <stdbool.h>

#ifndef __U2F_CRYPTO_H__

#define __U2F_CRYPTO_H__

void u2f_crypto_init(void);
bool u2f_crypto_available(void);
bool u2f_crypto_random(uint8_t *buffer, uint16_t length);
uint16_t u2f_crypto_copy_attestation_certificate(uint8_t *buffer);
uint16_t u2f_crypto_generate_key_and_wrap(const uint8_t *applicationParameter,
                                          uint8_t *publicKey,
                                          uint8_t *keyHandle);
bool u2f_crypto_unwrap(const uint8_t *keyHandle, uint16_t keyHandleLength,
                       const uint8_t *applicationParameter);
bool u2f_sign_init(void);
bool u2f_sign_update(const uint8_t *message, uint16_t length);
uint16_t u2f_crypto_sign_application(uint8_t *signature);
uint16_t u2f_crypto_sign_attestation(uint8_t *signature);
void u2f_crypto_reset(void);

bool compare_constantTime(const uint8_t *a, const uint8_t *b, uint16_t length);

#ifdef HAVE_TEST_INTEROP

#define U2F_CRYPTO_TEST_WRONG_REGISTER_SIGNATURE 0x01
#define U2F_CRYPTO_TEST_WRONG_AUTHENTICATE_SIGNATURE 0x02

void u2f_crypto_set_modifier(const uint8_t modifier);
uint8_t u2f_crypto_get_modifier(void);

#endif

#endif
