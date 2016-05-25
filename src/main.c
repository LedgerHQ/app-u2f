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

#include "os.h"
#include "cx.h"

#include "os_io_seproxyhal.h"
#include "string.h"

#include "u2f_config.h"
#include "u2f_service.h"
#include "u2f_crypto.h"
#include "u2f_counter.h"

extern u2f_config_t const WIDE N_u2f;
unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#if defined(HAVE_BAGL)

void u2f_reset_display(void);

#define MAX_PIN 32

volatile unsigned char uiDoneAfterDraw;
volatile unsigned char uiDone;
volatile unsigned int current_element;
volatile bagl_element_t *active_screen;
volatile unsigned int active_screen_element_count;
volatile unsigned char display_changed;
volatile enum {
    BAGL_U2F_IDLE,
    BAGL_U2F_VERIFY,
} u2f_ui_mode = BAGL_U2F_IDLE;

volatile char verifyName[20];

#define U2F_MAX_MESSAGE_SIZE 1100 // fits a 1024 bytes payload

volatile u2f_service_t u2fService;
volatile unsigned char u2fInputBuffer[64];
volatile unsigned char u2fOutputBuffer[64];
volatile unsigned char u2fMessageBuffer[U2F_MAX_MESSAGE_SIZE];
volatile unsigned char u2fConfirmedApplicationParameter[32];
volatile unsigned char u2fReportAcceptedStatus;
volatile unsigned char u2fAcceptedStatus;
volatile unsigned char u2fPendingResetDisplay;

#ifdef HAVE_TEST_INTEROP
volatile unsigned char deviceState[10];
#endif

const bagl_element_t bagl_ui_erase_all[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 480, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

};

unsigned int u2f_callback_exit(const bagl_element_t *element);
unsigned int u2f_callback_cancel(const bagl_element_t *element);
unsigned int u2f_callback_confirm(const bagl_element_t *element);

#ifdef HAVE_TEST_INTEROP
unsigned int u2f_callback_bad_enroll(const bagl_element_t *element);
unsigned int u2f_callback_bad_authenticate(const bagl_element_t *element);
#endif

// TODO : add advertise button

const bagl_element_t bagl_ui_idle[] = {

    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Ledger Blue / FIDO U2F",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 90, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "$DEVICENAME",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
#ifdef HAVE_TEST_INTEROP
    {{BAGL_LABEL, 0x00, 0, 150, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     deviceState,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
#else
    {{BAGL_LABEL, 0x00, 0, 150, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "U2F Ready",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
#endif

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 225, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "Exit",
     0,
     0x37ae99,
     0xF9F9F9,
     u2f_callback_exit,
     NULL,
     NULL},

#ifdef HAVE_TEST_INTEROP
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 270, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "Bad enroll",
     0,
     0x37ae99,
     0xF9F9F9,
     u2f_callback_bad_enroll,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 315, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "Bad auth",
     0,
     0x37ae99,
     0xF9F9F9,
     u2f_callback_bad_authenticate,
     NULL,
     NULL},
#endif

};

const bagl_element_t bagl_ui_verify[] = {
    // type                                 id    x    y    w    h    s  r  fill
    // fg        bg        font icon   text, out, over, touch
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 60, 0, 0, BAGL_FILL, 0x1d2028, 0x1d2028,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 20, 0, 320, 60, 0, 0, BAGL_FILL, 0xFFFFFF, 0x1d2028,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
     "Ledger Blue",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 35, 385, 120, 40, 0, 6,
      BAGL_FILL, 0xcccccc, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CANCEL",
     0,
     0x37ae99,
     0xF9F9F9,
     u2f_callback_cancel,
     NULL,
     NULL},
    {{BAGL_BUTTON | BAGL_FLAG_TOUCHABLE, 0x00, 165, 385, 120, 40, 0, 6,
      BAGL_FILL, 0x41ccb4, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x37ae99,
     0xF9F9F9,
     u2f_callback_confirm,
     NULL,
     NULL},

    {{BAGL_LABEL, 0x00, 0, 147, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "CONFIRM U2F ACTION",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABEL, 0x00, 0, 185, 320, 32, 0, 0, 0, 0x000000, 0xF9F9F9,
      BAGL_FONT_OPEN_SANS_LIGHT_14px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     verifyName,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

#endif

// Main application

#ifdef HAVE_BAGL

void io_seproxyhal_display(const bagl_element_t *e) {
    io_seproxyhal_display_default(e);
    display_changed = 1;
}

void display_init(void) {
    uiDone = 0;
    uiDoneAfterDraw = 0;
    display_changed = 0;
}

void displayHome() {
    u2f_ui_mode = BAGL_U2F_IDLE;
    current_element = 0;
    active_screen_element_count = sizeof(bagl_ui_idle) / sizeof(bagl_element_t);
    active_screen = bagl_ui_idle;
    io_seproxyhal_display(&bagl_ui_erase_all[0]);
}

unsigned int u2f_callback_exit(const bagl_element_t *element) {
    /*
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_DEVICE_OFF;
    G_io_seproxyhal_spi_buffer[1] = 0;
    G_io_seproxyhal_spi_buffer[2] = 0;
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 3);
    */
    u2f_timer_cancel();
    os_sched_exit(0);
    return 0;
}
unsigned int u2f_callback_cancel(const bagl_element_t *element) {
    u2fService.reportUserPresence = true;
    u2fService.userPresence = false;
    displayHome();
    return 0; // DO NOT REDISPLAY THE BUTTON
}
unsigned int u2f_callback_confirm(const bagl_element_t *element) {
    u2fService.reportUserPresence = true;
    u2fService.userPresence = true;
    displayHome();
    return 0; // DO NOT REDISPLAY THE BUTTON
}

#ifdef HAVE_TEST_INTEROP

void getDeviceState() {
    uint8_t modifier = u2f_crypto_get_modifier();
    deviceState[0] = 'E';
    if (modifier & U2F_CRYPTO_TEST_WRONG_REGISTER_SIGNATURE) {
        deviceState[1] = 'K';
        deviceState[2] = 'O';
    } else {
        deviceState[1] = 'O';
        deviceState[2] = 'K';
    }
    deviceState[3] = ' ';
    deviceState[4] = 'A';
    if (modifier & U2F_CRYPTO_TEST_WRONG_AUTHENTICATE_SIGNATURE) {
        deviceState[5] = 'K';
        deviceState[6] = 'O';
    } else {
        deviceState[5] = 'O';
        deviceState[6] = 'K';
    }
    deviceState[7] = '\0';
}

unsigned int u2f_callback_bad_enroll(const bagl_element_t *element) {
    uint8_t modifier = u2f_crypto_get_modifier();
    u2f_crypto_set_modifier(modifier ^
                            U2F_CRYPTO_TEST_WRONG_REGISTER_SIGNATURE);
    getDeviceState();
    displayHome();
    return 0; // DO NOT REDISPLAY THE BUTTON
}

unsigned int u2f_callback_bad_authenticate(const bagl_element_t *element) {
    uint8_t modifier = u2f_crypto_get_modifier();
    u2f_crypto_set_modifier(modifier ^
                            U2F_CRYPTO_TEST_WRONG_AUTHENTICATE_SIGNATURE);
    getDeviceState();
    displayHome();
    return 0; // DO NOT REDISPLAY THE BUTTON
}

#endif

#endif

unsigned int usb_enable_request;
unsigned int timer_enable_request;
unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed
    unsigned int offset = 0;

    // just reply "amen"
    // add a "pairing ok" tag if necessary
    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_BLE_PAIRING_ATTEMPT_EVENT:
        G_io_seproxyhal_spi_buffer[offset++] = SEPROXYHAL_TAG_PAIRING_STATUS;
        G_io_seproxyhal_spi_buffer[offset++] = 0;
        G_io_seproxyhal_spi_buffer[offset++] = 1;
        G_io_seproxyhal_spi_buffer[offset++] = 1;
        io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, offset);
        break;

    // Make automatically discoverable again when disconnected

    case SEPROXYHAL_TAG_BLE_CONNECTION_EVENT:
        if (G_io_seproxyhal_spi_buffer[3] == 0) {
            // TODO : cleaner reset sequence
            // first disable BLE before turning it off
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 0;
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);
            // send BLE power on (default parameters)
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 2;
            G_io_seproxyhal_spi_buffer[3] = 3; // ble on & advertise
            G_io_seproxyhal_spi_buffer[4] = 1; // use U2F profile
            io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);
        }
        goto general_status;

    // Override regular APDU logic for BLE events

    case SEPROXYHAL_TAG_BLE_WRITE_REQUEST_EVENT:
        u2f_transport_handle(
            &u2fService, G_io_seproxyhal_spi_buffer + 6,
            U2(G_io_seproxyhal_spi_buffer[4], G_io_seproxyhal_spi_buffer[5]),
            U2F_MEDIA_BLE);
        if (u2fService.transportState == U2F_HANDLE_SEGMENTED) {
            goto general_status;
        }
        break;

    case SEPROXYHAL_TAG_BLE_NOTIFY_INDICATE_EVENT:
        // Last BLE send acknowledged, move on if there's something new to
        // process
        if ((u2fService.sendLength == 0) ||
            (u2fService.sendOffset == u2fService.sendLength)) {
            goto general_status;
        }
        u2f_continue_sending_fragmented_response(&u2fService);
        break;

#ifdef HAVE_BAGL
    case SEPROXYHAL_TAG_FINGER_EVENT:
        // TOUCH & RELEASE
        display_changed = 0; // detect screen display requests, to determine if
                             // general status is required or not
        io_seproxyhal_touch(active_screen, active_screen_element_count,
                            (G_io_seproxyhal_spi_buffer[4] << 8) |
                                (G_io_seproxyhal_spi_buffer[5] & 0xFF),
                            (G_io_seproxyhal_spi_buffer[6] << 8) |
                                (G_io_seproxyhal_spi_buffer[7] & 0xFF),
                            // map events
                            G_io_seproxyhal_spi_buffer[3]);
        if (!display_changed) {
            goto general_status;
        }
        break;
#endif // HAVE_BAGL

    case SEPROXYHAL_TAG_SESSION_START_EVENT:
        // send BLE power on (default parameters)
        G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
        G_io_seproxyhal_spi_buffer[1] = 0;
        G_io_seproxyhal_spi_buffer[2] = 2;
        G_io_seproxyhal_spi_buffer[3] = 3; // ble on & advertise
        G_io_seproxyhal_spi_buffer[4] = 1; // use U2F profile
        io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 5);

        // request usb startup after display done
        usb_enable_request = 1;
        timer_enable_request = 1;

#ifdef HAVE_BAGL

        display_init();

        displayHome();

        // goto general_status;
        break;
#else
        // finished warming up
        goto general_status;
#endif // HAVE_BAGL

    case SEPROXYHAL_TAG_TICKER_EVENT:
        if (u2fService.timeoutFunction != NULL) {
            u2fService.timerNeedGeneralStatus = false;
            u2fService.timeoutFunction(&u2fService);
            if (u2fService.timerNeedGeneralStatus) {
                goto general_status;
            }
        }
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if (current_element < active_screen_element_count) {
            // continue displaying element if any to be processed again
            io_seproxyhal_display(&active_screen[current_element++]);
            break;
        }
#ifdef HAVE_IO_USB
        if (usb_enable_request) {
            // enable usb support
            io_usb_enable(1);

            usb_enable_request = 0;
        }
#endif // HAVE_IO_USB
        if (uiDoneAfterDraw) {
            // Top level handle the general status along with the APDU response
            uiDoneAfterDraw = 0;
            uiDone = 1;
            break;
        }
        if (u2fService.reportUserPresence) {
            bool resume = (u2fService.userPresence &&
                           (u2fService.transportMedia == U2F_MEDIA_BLE));
            u2fService.reportUserPresence = false;
            u2f_confirm_user_presence(&u2fService, u2fService.userPresence,
                                      resume);
            if (resume) {
                break;
            }
        }
        if (timer_enable_request) {
            timer_enable_request = 0;
            u2f_timer_register(u2fService.timerInterval,
                               u2fService.timeoutFunction);
        }
    // no break is intentional: always a general status after display event

    default:
    general_status:
        // send a general status last command
        offset = 0;
        G_io_seproxyhal_spi_buffer[offset++] = SEPROXYHAL_TAG_GENERAL_STATUS;
        G_io_seproxyhal_spi_buffer[offset++] = 0;
        G_io_seproxyhal_spi_buffer[offset++] = 2;
        G_io_seproxyhal_spi_buffer[offset++] =
            SEPROXYHAL_TAG_GENERAL_STATUS_LAST_COMMAND >> 8;
        G_io_seproxyhal_spi_buffer[offset++] =
            SEPROXYHAL_TAG_GENERAL_STATUS_LAST_COMMAND;
        io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, offset);
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

void u2f_prompt_user_presence(u2f_service_t *service, bool enroll,
                              uint8_t *applicationParameter) {
    if (enroll) {
        os_memmove(verifyName, "Enroll", 7);
    } else {
        os_memmove(verifyName, "Authenticate", 13);
    }
    uiDone = 0;
    uiDoneAfterDraw = 1;
    u2f_ui_mode = BAGL_U2F_VERIFY;
    current_element = 0;
    u2fReportAcceptedStatus = 0;
    u2fPendingResetDisplay = 0;
    active_screen_element_count =
        sizeof(bagl_ui_verify) / sizeof(bagl_element_t);
    active_screen = bagl_ui_verify;
    io_seproxyhal_display(&bagl_ui_erase_all[0]);
    // Loop on the UI, general status will be sent when all components are
    // displayed
    while (!uiDone) {
        unsigned int rx_len;
        rx_len = io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                                        sizeof(G_io_seproxyhal_spi_buffer), 0);
        if (rx_len - 3 !=
            U2(G_io_seproxyhal_spi_buffer[1], G_io_seproxyhal_spi_buffer[2])) {
            continue;
        }
        io_event(CHANNEL_SPI);
    }
}

void u2f_reset_display() {
    if (u2fPendingResetDisplay) {
        u2fPendingResetDisplay = 0;
        uiDone = 0;
        uiDoneAfterDraw = 1;
        displayHome();
        // Loop on the UI, general status will be sent when all components are
        // displayed
        while (!uiDone) {
            unsigned int rx_len;
            rx_len =
                io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                                       sizeof(G_io_seproxyhal_spi_buffer), 0);
            if (rx_len - 3 != U2(G_io_seproxyhal_spi_buffer[1],
                                 G_io_seproxyhal_spi_buffer[2])) {
                continue;
            }
            io_event(CHANNEL_SPI);
        }
    }
}

void reset(void) {
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
    case CHANNEL_KEYBOARD:
        break;

    // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
    case CHANNEL_SPI:
        if (tx_len) {
            io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

            if (channel & IO_RESET_AFTER_REPLIED) {
                reset();
            }
            return 0; // nothing received from the master so far (it's a tx
                      // transaction)
        } else {
            return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                                          sizeof(G_io_apdu_buffer), 0);
        }

    default:
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

void main_continue(void) {
    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            screen_printf("ST31_APP booted.\n");

            // fake the session start event
            G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_SESSION_START_EVENT;
            G_io_seproxyhal_spi_buffer[1] = 0;
            G_io_seproxyhal_spi_buffer[2] = 1;
            G_io_seproxyhal_spi_buffer[3] = 0;
            io_event(CHANNEL_SPI);

            // Initialize U2F service

            if (N_u2f.initialized != 1) {
                u2f_config_t u2fConfig;
                u2fConfig.counter = 1;
                u2fConfig.initialized = 1;
#ifndef DERIVE_JOHOE
                uint32_t keyPath[1];
                keyPath[0] = U2F_KEY_PATH;
                os_perso_derive_seed_bip32(keyPath, 1, u2fConfig.hmacKey,
                                           u2fConfig.hmacKey + 32);
#endif
                nvm_write(&N_u2f, &u2fConfig, sizeof(u2f_config_t));
            }

            u2f_crypto_init();
            u2f_counter_init();
            u2f_timer_init();
            u2fPendingResetDisplay = 0;
            os_memset((unsigned char *)&u2fService, 0, sizeof(u2fService));
            u2fService.promptUserPresenceFunction = u2f_prompt_user_presence;
            u2fService.inputBuffer = u2fInputBuffer;
            u2fService.outputBuffer = u2fOutputBuffer;
            u2fService.messageBuffer = u2fMessageBuffer;
            u2fService.messageBufferSize = U2F_MAX_MESSAGE_SIZE;
            u2fService.confirmedApplicationParameter =
                u2fConfirmedApplicationParameter;
            u2fService.bleMtu = 20;
            u2f_initialize_service(&u2fService);

#ifdef HAVE_TEST_INTEROP
            getDeviceState();
#endif

            // btchip_context_init();
            // app_main();

            // Just loop on an exchange

            for (;;) {
                io_exchange(CHANNEL_APDU, 0);
            }
        }
        CATCH_ALL {
            for (;;)
                ;
        }
        FINALLY {
        }
    }
    END_TRY;
}

__attribute__((section(".boot"))) void main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    main_continue();
}
