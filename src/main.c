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

void u2f_reset_display(void);

#define MAX_PIN 32

ux_state_t ux;

volatile char verifyName[20];

volatile u2f_service_t u2fService;
volatile unsigned char u2fInputBuffer[64];
volatile unsigned char u2fOutputBuffer[64];
volatile unsigned char u2fMessageBuffer[U2F_MAX_MESSAGE_SIZE];
volatile unsigned char u2fConfirmedApplicationParameter[32];

#ifdef HAVE_TEST_INTEROP
volatile unsigned char deviceState[10];
#endif

unsigned int u2f_callback_exit(const bagl_element_t *element);
unsigned int u2f_callback_cancel(const bagl_element_t *element);
unsigned int u2f_callback_confirm(const bagl_element_t *element);

#ifdef HAVE_TEST_INTEROP
unsigned int u2f_callback_bad_enroll(const bagl_element_t *element);
unsigned int u2f_callback_bad_authenticate(const bagl_element_t *element);
#endif

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;
unsigned int ui_stepper_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        switch (element->component.userid) {
        case 1:
            io_seproxyhal_setup_ticker(2000);
            break;
        case 2:
            io_seproxyhal_setup_ticker(3000);
            break;
        }
        return (ux_step == element->component.userid - 1);
    }
    return 1;
}

const unsigned char hex_digits[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void array_hexstr(char *strbuf, const void *bin, unsigned int len) {
    while (len--) {
        *strbuf++ = hex_digits[((*((char *)bin)) >> 4) & 0xF];
        *strbuf++ = hex_digits[(*((char *)bin)) & 0xF];
        bin = (const void *)((unsigned int)bin + 1);
    }
    *strbuf = 0; // EOS
}

// TODO : add advertise button

const bagl_element_t ui_idle_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 480, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

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

unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
}

const bagl_element_t ui_verify_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 0, 320, 480, 0, 0, BAGL_FILL, 0xf9f9f9, 0xf9f9f9,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

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

unsigned int ui_verify_blue_button(unsigned int button_mask,
                                   unsigned int button_mask_counter) {
}

const bagl_element_t ui_idle_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x01, 22, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_PEOPLE_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 43, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px, 0},
     "Ready to",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 43, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px, 0},
     "authenticate",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x01, 118, 14, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_DOWN},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x02, 29, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_DASHBOARD_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    //{{BAGL_LABELINE                       , 0x02,   0,   3, 128,  32, 0, 0, 0
    //, 0xFFFFFF, 0x000000,
    //BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  },
    //"authenticate", 0, 0, 0, NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x02, 50, 19, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Quit app",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x02, 3, 14, 7, 4, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_UP},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};
unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter);

unsigned int ui_idle_nanos_state;
unsigned int ui_idle_nanos_prepro(const bagl_element_t *element) {
    if (element->component.userid > 0) {
        return (ui_idle_nanos_state == element->component.userid - 1);
    }
    return 1;
}

const bagl_element_t ui_register_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x01, 20, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_LOCK_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 41, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 41, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "registration",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Service",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     verifyName,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    //{{BAGL_LABELINE                       , 0x02,   0,  26, 128,  32, 0, 0, 0
    //, 0xFFFFFF, 0x000000,
    //BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER, 0  },
    //verifyName, 0, 0, 0, NULL, NULL, NULL },

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_register_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter);

const bagl_element_t ui_auth_nanos[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF,
      0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x01, 32, 9, 14, 14, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_LOCK_BADGE},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 53, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 53, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px, 0},
     "log in",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x02, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_REGULAR_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Service",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x02, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     verifyName,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CROSS},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0,
      BAGL_GLYPH_ICON_CHECK},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
};

// unsigned int ui_auth_nanos_button(unsigned int button_mask, unsigned int
// button_mask_counter);

void ui_idle(void) {
    ux_step_count = 0; // avoid redisplay
    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
        if (ux.elements != ui_idle_blue) {
            UX_DISPLAY(ui_idle_blue, NULL);
        }
    } else {
        if (ux.elements != ui_idle_nanos) {
            ui_idle_nanos_state =
                0; // start by displaying the idle first screen
            UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
        }
    }
}

// Main application

void io_seproxyhal_display(const bagl_element_t *e) {
    io_seproxyhal_display_default(e);
}

unsigned int u2f_callback_exit(const bagl_element_t *element) {
    u2f_timer_cancel();
    os_sched_exit(0);
    return 0;
}
unsigned int u2f_callback_cancel(const bagl_element_t *element) {
    u2f_confirm_user_presence(&u2fService, false, false);
    // io_seproxyhal_setup_ticker(0);
    u2f_reset_display();
    return 0; // DO NOT REDISPLAY THE BUTTON
}
unsigned int u2f_callback_confirm(const bagl_element_t *element) {
#warning TODO the second parameter shall be processed by the u2f layer instead
    u2f_confirm_user_presence(&u2fService, true,
                              u2fService.transportMedia == U2F_MEDIA_BLE);
    // io_seproxyhal_setup_ticker(0);
    u2f_reset_display();
    return 0; // DO NOT REDISPLAY THE BUTTON
}

unsigned int ui_idle_nanos_button(unsigned int button_mask,
                                  unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // UP
        if (ui_idle_nanos_state == 1) {
            ui_idle_nanos_state = 0;
            UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
        }
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // DOWN
        if (ui_idle_nanos_state == 0) {
            ui_idle_nanos_state = 1;
            UX_DISPLAY(ui_idle_nanos, ui_idle_nanos_prepro);
        }
        break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // EXIT
        if (ui_idle_nanos_state == 1) {
            u2f_callback_exit(NULL);
        }
        break;
    }
    return 0;
}

// the same for both
#define ui_auth_nanos_button ui_register_nanos_button
unsigned int ui_register_nanos_button(unsigned int button_mask,
                                      unsigned int button_mask_counter) {
    switch (button_mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: // NO
        u2f_callback_cancel(NULL);
        break;

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // YES
        u2f_callback_confirm(NULL);
        break;
    }
    return 0;
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
    u2f_reset_display();
    return 0; // DO NOT REDISPLAY THE BUTTON
}

unsigned int u2f_callback_bad_authenticate(const bagl_element_t *element) {
    uint8_t modifier = u2f_crypto_get_modifier();
    u2f_crypto_set_modifier(modifier ^
                            U2F_CRYPTO_TEST_WRONG_AUTHENTICATE_SIGNATURE);
    getDeviceState();
    u2f_reset_display();
    return 0; // DO NOT REDISPLAY THE BUTTON
}

#endif

unsigned char io_event(unsigned char channel) {
    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
        UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
        UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
        break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
        if (u2fService.timeoutFunction != NULL) {
            u2fService.timeoutFunction(&u2fService);
        }
        // only redisplay if timeout has done nothing
        if (!io_seproxyhal_spi_is_status_sent() && ux_step_count > 0) {
            // prepare next screen
            ux_step = (ux_step + 1) % ux_step_count;
            // redisplay screen
            UX_REDISPLAY();
        }
        break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
        if (UX_DISPLAYED()) {
            // TODO perform actions after all screen elements have been
            // displayed
        } else {
            UX_DISPLAY_PROCESSED_EVENT();
        }
        break;

    default:
        break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

typedef struct {
    unsigned char sha256[32];
    const char *name;
} u2f_known_appid_t;
const u2f_known_appid_t const u2f_known_appid[] = {
    {
        // https://www.gstatic.com/securitykey/origins.json
        {0xa5, 0x46, 0x72, 0xb2, 0x22, 0xc4, 0xcf, 0x95, 0xe1, 0x51, 0xed, 0x8d,
         0x4d, 0x3c, 0x76, 0x7a, 0x6c, 0xc3, 0x49, 0x43, 0x59, 0x43, 0x79, 0x4e,
         0x88, 0x4f, 0x3d, 0x02, 0x3a, 0x82, 0x29, 0xfd},
        "Google",
    },
    {
        // https://www.dropbox.com/u2f-app-id.json
        {0xc5, 0x0f, 0x8a, 0x7b, 0x70, 0x8e, 0x92, 0xf8, 0x2e, 0x7a, 0x50, 0xe2,
         0xbd, 0xc5, 0x5d, 0x8f, 0xd9, 0x1a, 0x22, 0xfe, 0x6b, 0x29, 0xc0, 0xcd,
         0xf7, 0x80, 0x55, 0x30, 0x84, 0x2a, 0xf5, 0x81},
        "Dropbox",
    },
    {
        // https://github.com/u2f/trusted_facets
        {0x70, 0x61, 0x7d, 0xfe, 0xd0, 0x65, 0x86, 0x3a, 0xf4, 0x7c, 0x15, 0x55,
         0x6c, 0x91, 0x79, 0x88, 0x80, 0x82, 0x8c, 0xc4, 0x07, 0xfd, 0xf7, 0x0a,
         0xe8, 0x50, 0x11, 0x56, 0x94, 0x65, 0xa0, 0x75},
        "GitHub",
    },
    {
        // https://gitlab.com
        {0xe7, 0xbe, 0x96, 0xa5, 0x1b, 0xd0, 0x19, 0x2a, 0x72, 0x84, 0x0d, 0x2e,
         0x59, 0x09, 0xf7, 0x2b, 0xa8, 0x2a, 0x2f, 0xe9, 0x3f, 0xaa, 0x62, 0x4f,
         0x03, 0x39, 0x6b, 0x30, 0xe4, 0x94, 0xc8, 0x04},
        "GitLab",
    },
    {
        // https://bitbucket.org
        {0x12, 0x74, 0x3b, 0x92, 0x12, 0x97, 0xb7, 0x7f, 0x11, 0x35, 0xe4, 0x1f,
         0xde, 0xdd, 0x4a, 0x84, 0x6a, 0xfe, 0x82, 0xe1, 0xf3, 0x69, 0x32, 0xa9,
         0x91, 0x2f, 0x3b, 0x0d, 0x8d, 0xfb, 0x7d, 0x0e},
        "Bitbucket",
    },

    {
        {0x68, 0x20, 0x19, 0x15, 0xd7, 0x4c, 0xb4, 0x2a, 0xf5, 0xb3, 0xcc, 0x5c,
         0x95, 0xb9, 0x55, 0x3e, 0x3e, 0x3a, 0x83, 0xb4, 0xd2, 0xa9, 0x3b, 0x45,
         0xfb, 0xad, 0xaa, 0x84, 0x69, 0xff, 0x8e, 0x6e},
        "Dashlane",
    },
};

const char *u2f_match_known_appid(const uint8_t *applicationParameter) {
    unsigned int i;
    for (i = 0; i < sizeof(u2f_known_appid) / sizeof(u2f_known_appid[0]); i++) {
        if (os_memcmp(applicationParameter, u2f_known_appid[i].sha256, 32) ==
            0) {
            return (const char *)PIC(u2f_known_appid[i].name);
        }
    }
    return NULL;
}

#define HASH_LENGTH 4
void u2f_prompt_user_presence(u2f_service_t *service, bool enroll,
                              uint8_t *applicationParameter) {
#ifdef HAVE_NO_USER_PRESENCE_CHECK
#warning Having no user presence check is against U2F standard
    u2f_callback_confirm(NULL);
#else
    if (enroll) {
        // os_memmove(verifyName, "Enroll", 7);
    } else {
        // os_memmove(verifyName, "Authenticate", 13);
    }

    const uint8_t *name = u2f_match_known_appid(applicationParameter);
    if (name != NULL) {
        strcpy(verifyName, name);
    } else {
        array_hexstr(verifyName, applicationParameter, HASH_LENGTH / 2);
        verifyName[HASH_LENGTH / 2 * 2] = '.';
        verifyName[HASH_LENGTH / 2 * 2 + 1] = '.';
        verifyName[HASH_LENGTH / 2 * 2 + 2] = '.';
        array_hexstr(verifyName + HASH_LENGTH / 2 * 2 + 3,
                     applicationParameter + 32 - HASH_LENGTH / 2,
                     HASH_LENGTH / 2);
    }

    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_SCREEN_BIG) {
        UX_DISPLAY(ui_verify_blue, NULL);
    } else {
        ux_step = 0;
        ux_step_count = 2;
        io_seproxyhal_setup_ticker(2000);
        if (enroll) {
            UX_DISPLAY(ui_register_nanos, ui_stepper_prepro);
        } else {
            UX_DISPLAY(ui_auth_nanos, ui_stepper_prepro);
        }
    }
#endif
}

void u2f_reset_display() {
    ui_idle();
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    {
        THROW(INVALID_PARAMETER);
    }
    return 0;
}

void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

__attribute__((section(".boot"))) void main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    UX_INIT();

    // ensure exception will work as planned
    os_boot();

    BEGIN_TRY {
        TRY {
            io_seproxyhal_init();

            // Initialize U2F service
            u2f_init_config();

            u2f_crypto_init();
            u2f_counter_init();
            u2f_timer_init();
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

            if (os_seph_features() &
                SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_BLE) {
                BLE_set_u2fServiceReference(&u2fService);
                // screen_printf("BLE off\n");
                BLE_power(0, NULL);

                // restart IOs
                BLE_power(1, NULL);
            }

            USB_power(1);

            u2f_timer_register(u2fService.timerInterval,
                               u2fService.timeoutFunction);

#ifdef HAVE_TEST_INTEROP
            getDeviceState();
#endif

            ui_idle();

            // Just loop on an exchange, apdu are dispatched from within the io
            // stack
            for (;;) {
                io_exchange(CHANNEL_APDU, 0);
            }
        }
        CATCH_ALL {
        }
        FINALLY {
        }
    }
    END_TRY;

    app_exit();
}
