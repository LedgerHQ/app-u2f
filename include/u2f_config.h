/*
*******************************************************************************
*   Portable FIDO U2F implementation
*   Ledger Blue specific implementation
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

#ifndef __U2F_CONFIG_H__

#define __U2F_CONFIG_H__

#include "os.h"
#include "cx.h"

#define U2F_KEY_PATH 0x80553246

typedef struct u2f_config_t {
    uint32_t counter;
    uint8_t initialized;
#ifndef DERIVE_JOHOE
    uint8_t hmacKey[64];
#endif
} u2f_config_t;

#endif
