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

#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#include "u2f_service.h"

#include "credential.h"
#include "u2f_process.h"

extern char verifyHash[65];
extern char verifyName[20];

extern u2f_service_t G_io_u2f;

typedef struct shared_ctx_s {
    union shared_ctx_u {
        u2f_data_t u2fData;
    } u;
    uint8_t sharedBuffer[500];
} shared_ctx_t;

extern shared_ctx_t shared_ctx;

static inline u2f_data_t *globals_get_u2f_data(void) {
    return &shared_ctx.u.u2fData;
}

#endif
