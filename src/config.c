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

#include "os.h"
#include "cx.h"

#include "config.h"
#include "globals.h"

#define RNG_MODULO 5

config_t const N_u2f_real;

static void derive_and_store_keys(void) {
    uint8_t key[64];
    uint32_t keyPath[1];

    keyPath[0] = PRIVATE_KEY_PATH;

    // privateHmacKey
    keyPath[0] = PRIVATE_KEY_PATH;
    os_perso_derive_node_bip32(CX_CURVE_SECP256R1, keyPath, 1, key, key + 32);
    if (memcmp(key, (uint8_t *) N_u2f.privateHmacKey, sizeof(N_u2f.privateHmacKey)) == 0) {
        // Keys are already initialized with the proper seed and resetGeneration
        return;
    }
    nvm_write((void *) N_u2f.privateHmacKey, (void *) key, sizeof(N_u2f.privateHmacKey));
}

void config_init(void) {
    uint32_t tmp32;
    uint8_t tmp8;

    if (N_u2f.initialized != 1) {
#ifdef HAVE_COUNTER_MARKER
        tmp32 = 0xF1D0C001;
#else
        tmp32 = 1;
#endif
        nvm_write((void *) &N_u2f.authentificationCounter, (void *) &tmp32, sizeof(uint32_t));

        // Initialize keys derived from seed
        derive_and_store_keys();

        tmp8 = 1;
        nvm_write((void *) &N_u2f.initialized, (void *) &tmp8, sizeof(uint8_t));
    } else {
        // Check that the seed did not change - if it did, overwrite the keys
        derive_and_store_keys();
    }
}

uint8_t config_increase_and_get_authentification_counter(uint8_t *buffer) {
    uint32_t counter = N_u2f.authentificationCounter;
    counter++;
    nvm_write((void *) &N_u2f.authentificationCounter, &counter, sizeof(uint32_t));
    buffer[0] = ((counter >> 24) & 0xff);
    buffer[1] = ((counter >> 16) & 0xff);
    buffer[2] = ((counter >> 8) & 0xff);
    buffer[3] = (counter & 0xff);
    return 4;
}
