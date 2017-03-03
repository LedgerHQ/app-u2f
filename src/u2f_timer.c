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

#include "os_io_seproxyhal.h"

#include "u2f_timer.h"

void u2f_timer_init() {
}

void u2f_timer_register(uint32_t timerMs, u2fTimer_t timerCallback) {
    /*
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_SET_TICKER_INTERVAL;
    G_io_seproxyhal_spi_buffer[1] = 0;
    G_io_seproxyhal_spi_buffer[2] = 2;
    G_io_seproxyhal_spi_buffer[3] = (timerMs >> 8);
    G_io_seproxyhal_spi_buffer[4] = (timerMs & 0xff);
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);
    */
}

void u2f_timer_cancel() {
    /*
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_SET_TICKER_INTERVAL;
    G_io_seproxyhal_spi_buffer[1] = 0;
    G_io_seproxyhal_spi_buffer[2] = 2;
    G_io_seproxyhal_spi_buffer[3] = 0;
    G_io_seproxyhal_spi_buffer[4] = 0;
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);
    */
}
