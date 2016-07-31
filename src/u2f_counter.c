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

#include <stdint.h>
#include <string.h>
#include "os.h"
#include "u2f_config.h"

extern u2f_config_t const WIDE N_u2f;

void u2f_counter_init(void) {
}

uint8_t u2f_counter_increase_and_get(uint8_t *buffer) {
    uint32_t counter = N_u2f.counter;
    // screen_printf("Counter %d\n", counter);
    counter++;
    nvm_write(&N_u2f.counter, &counter, sizeof(uint32_t));
    buffer[0] = ((counter >> 24) & 0xff);
    buffer[1] = ((counter >> 16) & 0xff);
    buffer[2] = ((counter >> 8) & 0xff);
    buffer[3] = (counter & 0xff);
    return 4;
}

uint8_t u2f_counter_get(uint8_t *buffer) {
    buffer[0] = ((N_u2f.counter >> 24) & 0xff);
    buffer[1] = ((N_u2f.counter >> 16) & 0xff);
    buffer[2] = ((N_u2f.counter >> 8) & 0xff);
    buffer[3] = (N_u2f.counter & 0xff);
    return 4;
}

uint8_t u2f_counter_set(uint32_t counter) {
    if (counter <= N_u2f.counter) {
        return 0;
    }
    nvm_write(&N_u2f.counter, &counter, sizeof(uint32_t));
    return 1;
}
