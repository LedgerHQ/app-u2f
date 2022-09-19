/*
*******************************************************************************
*   Portable FIDO U2F implementation
*   Ledger Blue specific initialization
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

#include "u2f_crypto.h"
#include "os.h"
#include "cx.h"
#include "u2f_config.h"
#include <stdint.h>
#include <string.h>

#ifndef PERSO_CLUBCOIN
#include "u2f_crypto_data.h"
#else
#include "u2f_crypto_data_clubcoin.h"
#endif

cx_ecfp_private_key_t attestation_private_key;
cx_ecfp_private_key_t app_private_key;
cx_ecfp_public_key_t app_public_key;
cx_sha256_t hash;

#ifdef HAVE_TEST_INTEROP

uint8_t modifier;

#endif

bool compare_constantTime(const uint8_t *a, const uint8_t *b, uint16_t length) {
  uint16_t givenLength = length;
  uint8_t status = 0;
  uint16_t counter = 0;

  if (length == 0) {
    return false;
  }
  while ((length--) != 0) {
    status |= a[length] ^ b[length];
    counter++;
  }
  if (counter != givenLength) {
    return false;
  }
  return ((status == 0) ? true : false);
}

void u2f_crypto_init() {
  cx_ecdsa_init_private_key(CX_CURVE_256R1, ATTESTATION_KEY, 32,
                            &attestation_private_key);
#ifdef HAVE_TEST_INTEROP
  modifier = 0;
#endif
}

bool u2f_crypto_available() {
  return true;
}

uint16_t u2f_crypto_copy_attestation_certificate(uint8_t *buffer) {
  os_memmove(buffer, ATTESTATION_CERT, sizeof(ATTESTATION_CERT));
  return sizeof(ATTESTATION_CERT);
}

#ifdef DERIVE_JOHOE

#define KEY_PATH_LEN 32
#define KEY_PATH_ENTRIES (1 + KEY_PATH_LEN / sizeof(uint32_t))
#define KEY_HANDLE_LEN (KEY_PATH_LEN + 32)

uint16_t u2f_crypto_generate_key_and_wrap(const uint8_t *applicationParameter,
                                          uint8_t *publicKey,
                                          uint8_t *keyHandle) {
  uint32_t i, key_path[KEY_PATH_ENTRIES];
  uint8_t privateKeyData[32];
  cx_hmac_sha256_t hmac;

  key_path[0] = U2F_KEY_PATH;
  for (i = 1; i < KEY_PATH_ENTRIES; i++) {
    uint8_t tmp[4];
    cx_rng(tmp, 4);
    key_path[i] =
        0x80000000 | (tmp[0] << 24) | (tmp[1] << 16) | (tmp[2] << 8) | tmp[3];
  }
  os_memmove(keyHandle, &key_path[1], KEY_PATH_LEN);
  os_perso_derive_node_bip32(CX_CURVE_256R1, key_path, KEY_PATH_ENTRIES,
                             privateKeyData, NULL);
  cx_ecdsa_init_private_key(CX_CURVE_256R1, privateKeyData, 32,
                            &app_private_key);
  cx_ecdsa_init_public_key(CX_CURVE_256R1, NULL, 0, &app_public_key);
  cx_ecfp_generate_pair(CX_CURVE_256R1, &app_public_key, &app_private_key, 1);
  os_memmove(publicKey, app_public_key.W, 65);
  cx_hmac_sha256_init(&hmac, privateKeyData, sizeof(privateKeyData));
  cx_hmac(&hmac, 0, applicationParameter, 32, keyHandle + KEY_PATH_LEN, 32);
  cx_hmac(&hmac, CX_LAST, keyHandle, KEY_PATH_LEN, keyHandle + KEY_PATH_LEN, 32);
  os_memset(privateKeyData, 0, sizeof(privateKeyData));
  os_memset(&hmac, 0, sizeof(hmac));
  os_memset(&app_private_key, 0, sizeof(cx_ecfp_private_key_t));
  return KEY_HANDLE_LEN;
}

bool u2f_crypto_unwrap(const uint8_t *keyHandle, uint16_t keyHandleLength,
                       const uint8_t *applicationParameter) {
  uint32_t key_path[KEY_PATH_ENTRIES];
  uint8_t privateKeyData[32];
  uint8_t mac[32];
  cx_hmac_sha256_t hmac;
  if (keyHandleLength != KEY_HANDLE_LEN) {
    return false;
  }
  key_path[0] = U2F_KEY_PATH;
  os_memmove(&key_path[1], keyHandle, KEY_PATH_LEN);
  os_perso_derive_node_bip32(CX_CURVE_256R1, key_path, KEY_PATH_ENTRIES,
                             privateKeyData, NULL);
  cx_hmac_sha256_init(&hmac, privateKeyData, sizeof(privateKeyData));
  cx_hmac(&hmac, 0, applicationParameter, 32, mac, 32);
  cx_hmac(&hmac, CX_LAST, keyHandle, KEY_PATH_LEN, mac, 32);
  cx_ecdsa_init_private_key(CX_CURVE_256R1, privateKeyData, 32,
                            &app_private_key);
  os_memset(privateKeyData, 0, sizeof(privateKeyData));
  os_memset(&hmac, 0, sizeof(hmac));
  return compare_constantTime(mac, keyHandle + KEY_PATH_LEN, 32);
}

#else

#define KEY_HANDLE_LEN 64

uint16_t u2f_crypto_generate_key_and_wrap(const uint8_t *applicationParameter,
                                          uint8_t *publicKey,
                                          uint8_t *keyHandle) {
  uint8_t nonce[32];
  uint8_t privateKeyData[32];
  cx_hmac_sha256_t hmac;
  // Generate specific key for the request
  cx_rng(nonce, sizeof(nonce));
  cx_hmac_sha256_init(&hmac, N_u2f.hmacKey, sizeof(N_u2f.hmacKey));
  cx_hmac(&hmac, CX_LAST, nonce, sizeof(nonce), privateKeyData, 32);
  cx_ecdsa_init_private_key(CX_CURVE_256R1, privateKeyData, 32,
                            &app_private_key);
  cx_ecdsa_init_public_key(CX_CURVE_256R1, NULL, 0, &app_public_key);
  cx_ecfp_generate_pair(CX_CURVE_256R1, &app_public_key, &app_private_key, 1);
  os_memmove(publicKey, app_public_key.W, 65);
  // Compute its hash in the key handle
  os_memmove(keyHandle, nonce, 32);
  cx_hmac_sha256_init(&hmac, N_u2f.hmacKey, sizeof(N_u2f.hmacKey));
  cx_hmac(&hmac, 0, applicationParameter, 32, keyHandle + 32, 32);
  cx_hmac(&hmac, CX_LAST, privateKeyData, 32, keyHandle + 32, 32);
  os_memset(privateKeyData, 0, sizeof(privateKeyData));
  return KEY_HANDLE_LEN;
}

bool u2f_crypto_unwrap(const uint8_t *keyHandle, uint16_t keyHandleLength,
                       const uint8_t *applicationParameter) {
  uint8_t privateKeyData[32];
  uint8_t mac[32];
  cx_hmac_sha256_t hmac;
  if (keyHandleLength != KEY_HANDLE_LEN) {
    return false;
  }
  cx_hmac_sha256_init(&hmac, N_u2f.hmacKey, sizeof(N_u2f.hmacKey));
  cx_hmac(&hmac, CX_LAST, keyHandle, 32, privateKeyData, 32);
  cx_ecdsa_init_private_key(CX_CURVE_256R1, privateKeyData, 32,
                            &app_private_key);
  cx_hmac_sha256_init(&hmac, N_u2f.hmacKey, sizeof(N_u2f.hmacKey));
  cx_hmac(&hmac, 0, applicationParameter, 32, mac, 32);
  cx_hmac(&hmac, CX_LAST, privateKeyData, 32, mac, 32);
  return compare_constantTime(mac, keyHandle + 32, 32);
}

#endif

bool u2f_sign_init(void) {
  cx_sha256_init(&hash);
  return true;
}

bool u2f_sign_update(const uint8_t *message, uint16_t length) {
  cx_hash(&hash.header, 0, message, length, NULL, 32);
  return true;
}

static uint16_t u2f_crypto_sign(cx_ecfp_private_key_t *privateKey,
                                uint8_t *signature) {
  uint8_t hashData[32];
  cx_hash(&hash.header, CX_LAST, hashData, 0, hashData, 32);
  uint16_t length;
  size_t domain_length;
  cx_ecdomain_parameters_length(CX_CURVE_SECP256R1, &domain_length);
  length = cx_ecdsa_sign(privateKey, CX_RND_TRNG | CX_LAST, CX_NONE, hashData,
                         sizeof(hashData), signature, 6 + 2 * (domain_length + 1), NULL);
  signature[0] = 0x30;
  return length;
}

uint16_t u2f_crypto_sign_application(uint8_t *signature) {
  uint16_t result = u2f_crypto_sign(&app_private_key, signature);
#ifdef HAVE_TEST_INTEROP
  if ((modifier & U2F_CRYPTO_TEST_WRONG_AUTHENTICATE_SIGNATURE) != 0) {
    signature[10] = 0xde;
    signature[11] = 0xad;
    signature[12] = 0xf1;
    signature[13] = 0xd0;
  }
#endif
  return result;
}

uint16_t u2f_crypto_sign_attestation(uint8_t *signature) {
  uint16_t result = u2f_crypto_sign(&attestation_private_key, signature);
#ifdef HAVE_TEST_INTEROP
  if ((modifier & U2F_CRYPTO_TEST_WRONG_REGISTER_SIGNATURE) != 0) {
    signature[10] = 0xde;
    signature[11] = 0xad;
    signature[12] = 0xf1;
    signature[13] = 0xd0;
  }
#endif
  return result;
}

void u2f_crypto_reset() {
  os_memset(app_private_key.d, 0, 32);
}

bool u2f_crypto_random(uint8_t *buffer, uint16_t length) {
  cx_rng(buffer, length);
  return true;
}

#ifdef HAVE_TEST_INTEROP

void u2f_crypto_set_modifier(const uint8_t modifierData) {
  modifier = modifierData;
}

uint8_t u2f_crypto_get_modifier(void) {
  return modifier;
}

#endif
