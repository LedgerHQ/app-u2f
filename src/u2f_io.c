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

#include "u2f_io.h"
#include "u2f_transport.h"

extern void u2f_reset_display(void);

volatile unsigned char u2fCommandSent = 0;
volatile unsigned char u2fFirstCommand = 0;
volatile unsigned char u2fClosed = 0;

void u2f_io_open_session(void) {
    // screen_printf("u2f_io_open_session\n");
    u2fCommandSent = 0;
    u2fFirstCommand = 1;
    u2fClosed = 0;
}

void u2f_io_send(uint8_t *buffer, uint16_t length,
                 u2f_transport_media_t media) {
    unsigned char segment[MAX_SEGMENT_SIZE];
    if (media == U2F_MEDIA_USB) {
        os_memset(segment, 0, sizeof(segment));
    }
    os_memmove(segment, buffer, length);
    // screen_printf("u2f_io_send\n");
    if (u2fFirstCommand) {
        u2fFirstCommand = 0;
    }
    switch (media) {
    case U2F_MEDIA_USB:
        io_usb_send_apdu_data(segment, USB_SEGMENT_SIZE);
        break;
    case U2F_MEDIA_BLE:
        G_io_seproxyhal_spi_buffer[0] =
            SEPROXYHAL_TAG_BLE_NOTIFY_INDICATE_STATUS;
        G_io_seproxyhal_spi_buffer[1] = ((length + 3) >> 8);
        G_io_seproxyhal_spi_buffer[2] = (length + 3);
        G_io_seproxyhal_spi_buffer[3] = 1; // default notify handle
        G_io_seproxyhal_spi_buffer[4] = (length >> 8);
        G_io_seproxyhal_spi_buffer[5] = (length);
        os_memmove(G_io_seproxyhal_spi_buffer + 6, buffer, length);
        io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, length + 6);
        break;
    default:
        screen_printf("Request to send on unsupported media %d\n", media);
        break;
    }
}

void u2f_io_close_session(void) {
    // screen_printf("u2f_close_session\n");
    if (!u2fClosed) {
        u2f_reset_display();
        u2fClosed = 1;
    }
}
