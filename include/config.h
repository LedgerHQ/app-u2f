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

#ifndef __CONFIG_H__
#define __CONFIG_H__

#define PRIVATE_KEY_PATH 0x80553246  // "U2F".encode("ascii").hex()

typedef struct config_t {
    uint32_t authentificationCounter;
    uint8_t initialized;
    uint8_t privateHmacKey[64];
} config_t;

extern config_t const N_u2f_real;

#define N_u2f (*(volatile config_t *) PIC(&N_u2f_real))

void config_init(void);

uint8_t config_increase_and_get_authentification_counter(uint8_t *buffer);

#endif
