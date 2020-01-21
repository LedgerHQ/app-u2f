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

#include "glyphs.h"

#include "u2f_config.h"
#include "u2f_counter.h"
#include "u2f_crypto.h"

/*
Aramis version:
- power on:
-- if no usb, then led            black
-- if vbus, then led              green
-- if low bat, then led           orange
-- if not usb & ble not connected blink green
- paired/conn ble:
-- if low bat                     orange
-- if usb                         green
-- else                           black
- auth request:
-- if ble & low bat, then led     blink blue/orange
-- if ble & ok, then led          blue
-- if usb, then led               blue
- after auth validated
-- if usb, then led               green
-- if ble, poweroff
*/
#define BATT_FULL_VOLTAGE_MV 4200
#define BATT_LOW_VOLTAGE_MV 3750

#define LED_COLOR_LOW_BAT 0x200000
#define LED_COLOR_CHARGING_BAT 0x202000
#define LED_COLOR_USB_IDLE 0x002000
#define LED_COLOR_BLE_IDLE 0x000020

#define LED_COLOR_IDLE_CHARGING LED_COLOR_CHARGING_BAT
#define LED_COLOR_IDLE_LOW_BATT LED_COLOR_LOW_BAT

const unsigned int LED_COLOR_USB_ACTION[] = {0x002000, 0x000000};

const unsigned int LED_COLOR_BLE_ACTION[] = {0x000020, 0x000000};

void ui_aramis_update(void);
unsigned int ux_action_enroll;
unsigned int ui_power_off_ms;
unsigned int G_last_mcu_state;
unsigned int io_ble_discover_request;
unsigned int io_power_off_request;

volatile unsigned int led_color_step;
volatile unsigned int led_color_step_count;

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
#define tmp_string (&G_io_seproxyhal_spi_buffer[10])

uint16_t u2f_process_user_presence_cancelled(void);
uint16_t u2f_process_user_presence_confirmed(void);

void u2f_reset_display(void);

void u2f_process_timeout(void);

#define MAX_PIN 32

#ifdef HAVE_UX_FLOW
#include "ux.h"
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

#else // HAVE_UX_FLOW
ux_state_t ux;
#endif // HAVE_UX_FLOW

#ifdef TARGET_NANOX

void BLE_power_mac(unsigned char powered, const char *discovered_name, const char *mac);

#endif

volatile char verifyName[20];
volatile char verifyHash[65];
volatile int battery_voltage_mv;

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

#ifndef HAVE_UX_FLOW

const bagl_element_t *ui_menu_item_out_over(const bagl_element_t *e) {
  // the selection rectangle is after the none|touchable
  e = (const bagl_element_t *)(((unsigned int)e) + sizeof(bagl_element_t));
  return e;
}

// display stepped screens
unsigned int ux_step;
unsigned int ux_step_count;
unsigned int ui_stepper_prepro(const bagl_element_t *element) {
  if (element->component.userid > 0) {
    switch (element->component.userid) {
    case 1:
      UX_CALLBACK_SET_INTERVAL(2000);
      break;
    case 2:
      UX_CALLBACK_SET_INTERVAL(3000);
      break;
    }
    return (ux_step == element->component.userid - 1);
  }
  return 1;
}

#endif

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

#define BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH 10
#define BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH 8
#define MAX_CHAR_PER_LINE 25

#define COLOR_BG_1 0xF9F9F9
#define COLOR_APP 0x099999
#define COLOR_APP_LIGHT 0x80CCCC

// TODO : add advertise button

#if defined(TARGET_BLUE)
const bagl_icon_details_t ui_blue_people_gif = {
    .bpp = GLYPH_badge_people_blue_BPP,
    .colors = C_badge_people_blue_colors,
    .bitmap = C_badge_people_blue_bitmap,
};

const bagl_element_t ui_idle_blue[] = {
    // type                               userid    x    y   w    h  str rad
    // fill      fg        bg      fid iid  txt   touchparams...       ]
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x00, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "FIDO U2F",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_DASHBOARD,
     0,
     COLOR_APP,
     0xFFFFFF,
     u2f_callback_exit,
     NULL,
     NULL},

    // BADGE_PEOPLE_BLUE.GIF
    {{BAGL_ICON, 0x00, 135, 178, 50, 50, 0, 0, BAGL_FILL, 0, COLOR_BG_1, 0, 0},
     &ui_blue_people_gif,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 270, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Ready to authenticate",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x00, 0, 308, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Connect your Ledger Blue and",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x00, 0, 331, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "register your device to authenticate.",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 450, 320, 14, 0, 0, 0, 0x999999, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_8_11PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Log in requests will show automatically.",
     10,
     0,
     COLOR_BG_1,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_idle_blue_button(unsigned int button_mask,
                                 unsigned int button_mask_counter) {
  return 0;
}

// reuse tmp_string for each line content
const char *ui_details_title;
const char *ui_details_content;
typedef void (*callback_t)(void);
callback_t ui_details_back_callback;

const bagl_element_t *
ui_details_blue_back_callback(const bagl_element_t *element) {
  ui_details_back_callback();
  return 0;
}

const bagl_element_t ui_details_blue[] = {
    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x01, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 19, 50, 44, 0, 0,
      BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
      BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     BAGL_FONT_SYMBOLS_0_LEFT,
     0,
     COLOR_APP,
     0xFFFFFF,
     ui_details_blue_back_callback,
     NULL,
     NULL},
    //{{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264,  19,  56,  44, 0, 0,
    //BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
    //BAGL_FONT_SYMBOLS_0|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE,
    //0 }, BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, COLOR_APP, 0xFFFFFF,
    //u2f_callback_exit, NULL, NULL},

    {{BAGL_LABELINE, 0x00, 30, 106, 320, 30, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     "VALUE",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x10, 30, 136, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x11, 30, 159, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x12, 30, 182, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x13, 30, 205, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x14, 30, 228, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x15, 30, 251, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x16, 30, 274, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x17, 30, 297, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x18, 30, 320, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    //"..." at the end if too much
    {{BAGL_LABELINE, 0x19, 30, 343, 260, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 0, 450, 320, 14, 0, 0, 0, 0x999999, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_8_11PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Review the whole value before continuing.",
     10,
     0,
     COLOR_BG_1,
     NULL,
     NULL,
     NULL},
};

unsigned int ui_details_blue_prepro(const bagl_element_t *element) {
  if (element->component.userid == 1) {
    strcpy(tmp_string, ui_details_title);
  } else if (element->component.userid > 0) {
    unsigned int length = strlen(ui_details_content);
    if (length >= (element->component.userid & 0xF) * MAX_CHAR_PER_LINE) {
      os_memset(tmp_string, 0, MAX_CHAR_PER_LINE + 1);
      os_memmove(
          tmp_string,
          ui_details_content +
              (element->component.userid & 0xF) * MAX_CHAR_PER_LINE,
          MIN(length - (element->component.userid & 0xF) * MAX_CHAR_PER_LINE,
              MAX_CHAR_PER_LINE));
      return 1;
    }
    // nothing to draw for this line
    return 0;
  }
  return 1;
}
unsigned int ui_details_blue_button(unsigned int button_mask,
                                    unsigned int button_mask_counter) {
  return 0;
}

void ui_details_init(const char *title, const char *content,
                     callback_t back_callback) {
  ui_details_title = title;
  ui_details_content = content;
  ui_details_back_callback = back_callback;
  UX_DISPLAY(ui_details_blue, ui_details_blue_prepro);
}

const bagl_icon_details_t ui_blue_lock_gif = {
    .bpp = GLYPH_badge_lock_blue_BPP,
    .colors = C_badge_lock_blue_colors,
    .bitmap = C_badge_lock_blue_bitmap,
};

void ui_transaction_blue_init(void);

const bagl_element_t *
ui_transaction_blue_service_details(const bagl_element_t *e) {
  if (strlen(verifyName) * BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
      160) {
    ui_details_init("SERVICE", verifyName, ui_transaction_blue_init);
  }
  return 0;
};

const bagl_element_t *
ui_transaction_blue_identifier_details(const bagl_element_t *e) {
  if (strlen(verifyHash) * BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
      160) {
    ui_details_init("IDENTIFIER", verifyHash, ui_transaction_blue_init);
  }
  return 0;
};

typedef struct ui_transaction_strings_s {
  const char *title;
  const char *subtitle;
  // const char* button;
} ui_transaction_strings_t;

ui_transaction_strings_t *G_ui_transaction_strings;

const bagl_element_t ui_transaction_blue[] = {
    {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, BAGL_FILL, COLOR_BG_1,
      0x000000, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    // erase screen (only under the status bar)
    {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, BAGL_FILL, COLOR_APP,
      COLOR_APP, 0, 0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    /// TOP STATUS BAR
    {{BAGL_LABELINE, 0x30, 0, 45, 320, 30, 0, 0, BAGL_FILL, 0xFFFFFF, COLOR_APP,
      BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    //{{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264,  19,  56,  44, 0, 0,
    //BAGL_FILL, COLOR_APP, COLOR_APP_LIGHT,
    //BAGL_FONT_SYMBOLS_0|BAGL_FONT_ALIGNMENT_CENTER|BAGL_FONT_ALIGNMENT_MIDDLE,
    //0 }, BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, COLOR_APP, 0xFFFFFF,
    //u2f_callback_exit, NULL, NULL},

    // BADGE_LOCK_BLUE.GIF
    {{BAGL_ICON, 0x00, 30, 98, 50, 50, 0, 0, BAGL_FILL, 0, COLOR_BG_1, 0, 0},
     &ui_blue_lock_gif,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x31, 100, 117, 320, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_10_13PX, 0},
     tmp_string,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x00, 100, 138, 320, 30, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_REGULAR_8_11PX, 0},
     "Check and confirm values",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 30, 196, 100, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     "SERVICE",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // x-18 when ...
    {{BAGL_LABELINE, 0x01, 130, 196, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     verifyName,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x11, 284, 196, 6, 16, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     BAGL_FONT_SYMBOLS_0_MINIRIGHT,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 168, 320, 48, 0, 9, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_transaction_blue_service_details,
     ui_menu_item_out_over,
     ui_menu_item_out_over},
    {{BAGL_RECTANGLE, 0x11, 0, 168, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1,
      COLOR_BG_1, 0, 0},
     NULL,
     0,
     0x41CCB4,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE, 0x00, 30, 216, 260, 1, 1, 0, 0, 0xEEEEEE, COLOR_BG_1, 0,
      0},
     NULL,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_LABELINE, 0x00, 30, 245, 100, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1, BAGL_FONT_OPEN_SANS_SEMIBOLD_8_11PX, 0},
     "IDENTIFIER",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    // x-18 when ...
    {{BAGL_LABELINE, 0x02, 130, 245, 160, 30, 0, 0, BAGL_FILL, 0x000000,
      COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     verifyHash,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x12, 284, 245, 6, 16, 0, 0, BAGL_FILL, 0x999999,
      COLOR_BG_1, BAGL_FONT_SYMBOLS_0 | BAGL_FONT_ALIGNMENT_RIGHT, 0},
     BAGL_FONT_SYMBOLS_0_MINIRIGHT,
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_NONE | BAGL_FLAG_TOUCHABLE, 0x00, 0, 217, 320, 48, 0, 9, BAGL_FILL,
      0xFFFFFF, 0x000000, 0, 0},
     NULL,
     0,
     0xEEEEEE,
     0x000000,
     ui_transaction_blue_identifier_details,
     ui_menu_item_out_over,
     ui_menu_item_out_over},
    {{BAGL_RECTANGLE, 0x12, 0, 217, 5, 48, 0, 0, BAGL_FILL, COLOR_BG_1,
      COLOR_BG_1, 0, 0},
     NULL,
     0,
     0x41CCB4,
     0,
     NULL,
     NULL,
     NULL},

    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 40, 414, 115, 36, 0, 18,
      BAGL_FILL, 0xCCCCCC, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "REJECT",
     0,
     0xB7B7B7,
     COLOR_BG_1,
     u2f_callback_cancel,
     NULL,
     NULL},
    {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 165, 414, 115, 36, 0, 18,
      BAGL_FILL, 0x41ccb4, COLOR_BG_1,
      BAGL_FONT_OPEN_SANS_REGULAR_11_14PX | BAGL_FONT_ALIGNMENT_CENTER |
          BAGL_FONT_ALIGNMENT_MIDDLE,
      0},
     "CONFIRM",
     0,
     0x3ab7a2,
     COLOR_BG_1,
     u2f_callback_confirm,
     NULL,
     NULL},
};

bagl_element_t tmp_element;
const bagl_element_t *
ui_transaction_blue_prepro(const bagl_element_t *element) {
  // none elements are skipped
  if ((element->component.type & (~BAGL_FLAG_TOUCHABLE)) == BAGL_NONE) {
    return 0;
  } else {
    switch (element->component.userid) {
    case 0x30:
      strcpy(tmp_string, (const char *)PIC(G_ui_transaction_strings->title));
      break;
    case 0x31:
      strcpy(tmp_string, (const char *)PIC(G_ui_transaction_strings->subtitle));
      break;
      /*
      case 0x32:
        strcpy(tmp_string, (const char*)PIC(G_ui_transaction_strings->button));
        break;
      */

    case 0x01:
      if (strlen(verifyName) * BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH >=
          160) {
        os_memmove(&tmp_element, element, sizeof(bagl_element_t));
        tmp_element.component.x -= 18;
        return &tmp_element;
      }
      break;
    case 0x11:
      return strlen(verifyName) * BAGL_FONT_OPEN_SANS_LIGHT_16_22PX_AVG_WIDTH >=
             160;

    case 0x02:
      if (strlen(verifyHash) * BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
          160) {
        os_memmove(&tmp_element, element, sizeof(bagl_element_t));
        tmp_element.component.x -= 18;
        return &tmp_element;
      }
      break;
    case 0x12:
      return strlen(verifyHash) *
                 BAGL_FONT_OPEN_SANS_REGULAR_10_13PX_AVG_WIDTH >=
             160;
    }
  }
  return 1;
}
unsigned int ui_transaction_blue_button(unsigned int button_mask,
                                        unsigned int button_mask_counter) {
  return 0;
}

void ui_transaction_blue_init(void) {
  UX_DISPLAY(ui_transaction_blue, ui_transaction_blue_prepro);
}

const ui_transaction_strings_t ui_transaction_login_blue = {
    .title = "CONFIRM LOG IN", .subtitle = "Authentication details",
    //.button = "LOG IN",
};

const ui_transaction_strings_t ui_transaction_register_blue = {
    .title = "CONFIRM REGISTRATION", .subtitle = "Registration details",
    //.button = "REGISTER",
};

void ui_confirm_login_blue(void) {
  G_ui_transaction_strings = &ui_transaction_login_blue;
  ui_transaction_blue_init();
}

void ui_confirm_register_blue(void) {
  G_ui_transaction_strings = &ui_transaction_register_blue;
  ui_transaction_blue_init();
}
#endif // #if defined(TARGET_BLUE)

#if defined(TARGET_NANOS) && !defined(HAVE_UX_FLOW)

const ux_menu_entry_t menu_main[];

const ux_menu_entry_t menu_about[] = {
    {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
    {menu_main, NULL, 1, &C_icon_back, "Back", NULL, 61, 40},
    UX_MENU_END};

const ux_menu_entry_t menu_main[] = {
    {NULL, NULL, 0, &C_icon_people, "Ready to", "authenticate", 37, 16},
    {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
    {NULL, os_sched_exit, 0, &C_icon_dashboard, "Quit app", NULL, 50, 29},
    UX_MENU_END};

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

    //{{BAGL_ICON                           , 0x01,  20,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_LOCK_BADGE  }, NULL, 0, 0, 0,
    //NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
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

    //{{BAGL_ICON                           , 0x01,  32,   9,  14,  14, 0, 0, 0
    //, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_LOCK_BADGE  }, NULL, 0, 0, 0,
    //NULL, NULL, NULL },
    {{BAGL_LABELINE, 0x01, 0, 12, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "Confirm",
     0,
     0,
     0,
     NULL,
     NULL,
     NULL},
    {{BAGL_LABELINE, 0x01, 0, 26, 128, 32, 0, 0, 0, 0xFFFFFF, 0x000000,
      BAGL_FONT_OPEN_SANS_EXTRABOLD_11px | BAGL_FONT_ALIGNMENT_CENTER, 0},
     "login",
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
#endif // #if defined(TARGET_NANOS) && !defined(HAVE_UX_FLOW)

#if defined(HAVE_UX_FLOW)

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
    ux_idle_flow_1_step, 
    nn, 
    {
      "Ready to",
      "authenticate",
    });
UX_STEP_NOCB(
    ux_idle_flow_2_step, 
    bn, 
    {
      "Version",
      APPVERSION,
    });
UX_STEP_VALID(
    ux_idle_flow_3_step,
    pb,
    os_sched_exit(-1),
    {
      &C_icon_dashboard,
      "Quit",
    });
UX_FLOW(ux_idle_flow,
  &ux_idle_flow_1_step,
  &ux_idle_flow_2_step,
  &ux_idle_flow_3_step
);

//////////////////////////////////////////////////////////////////////
#if 0
UX_STEP_NOCB(
    ux_register_flow_1_step, 
    pnn, 
    {
      &C_icon_certificate,
      "Confirm",
      "registration",
    });
UX_STEP_NOCB(
    ux_register_flow_2_step, 
    bnnn_paging, 
    {
      .title = "Service",
      .text = verifyHash,
    });
UX_STEP_VALID(
    ux_register_flow_3_step,
    pbb,
    u2f_callback_confirm(NULL),
    {
      &C_icon_validate_14,
      "Approve",
      "registration",
    });
UX_STEP_VALID(
    ux_register_flow_4_step,
    pbb,
    u2f_callback_cancel(NULL),
    {
      &C_icon_crossmark,
      "Abort",
      "registration",
    });

UX_FLOW(ux_register_flow,
  &ux_register_flow_1_step,
  &ux_register_flow_2_step,
  &ux_register_flow_3_step,
  &ux_register_flow_4_step
);
#endif

UX_STEP_VALID(
    ux_register_flow_0_step,
    pbb,
    u2f_callback_confirm(NULL),
    {
      &C_icon_validate_14,
      "Register",
      verifyName,
    });
UX_STEP_NOCB(
    ux_register_flow_1_step, 
    bnnn_paging, 
    {
      .title = "Identifier",
      .text = verifyHash,
    });
UX_STEP_VALID(
    ux_register_flow_2_step,
    pbb,
    u2f_callback_cancel(NULL),
    {
      &C_icon_crossmark,
      "Abort",
      "register",
    });

UX_FLOW(ux_register_flow,
  &ux_register_flow_0_step,
  &ux_register_flow_1_step,
  &ux_register_flow_2_step,
  FLOW_LOOP
);


//////////////////////////////////////////////////////////////////////
#if 0
UX_STEP_NOCB(
    ux_login_flow_1_step, 
    pnn, 
    {
      &C_icon_eye,
      "Confirm",
      "login",
    });
UX_STEP_NOCB(
    ux_login_flow_2_step, 
    bnnn_paging, 
    {
      .title = "Service",
      .text = verifyHash,
    });
UX_STEP_VALID(
    ux_login_flow_3_step,
    pbb,
    u2f_callback_confirm(NULL),
    {
      &C_icon_validate_14,
      "Approve",
      "login",
    });
UX_STEP_VALID(
    ux_login_flow_4_step,
    pbb,
    u2f_callback_cancel(NULL),
    {
      &C_icon_crossmark,
      "Abort",
      "login",
    });

UX_FLOW(ux_login_flow,
  &ux_login_flow_1_step,
  &ux_login_flow_2_step,
  &ux_login_flow_3_step,
  &ux_login_flow_4_step
);
#endif

UX_STEP_VALID(
    ux_login_flow_0_step,
    pbb,
    u2f_callback_confirm(NULL),
    {
      &C_icon_validate_14,
      "Login",
      verifyName,
    });
UX_STEP_NOCB(
    ux_login_flow_1_step, 
    bnnn_paging, 
    {
      .title = "Identifier",
      .text = verifyHash,
    });
UX_STEP_VALID(
    ux_login_flow_2_step,
    pbb,
    u2f_callback_cancel(NULL),
    {
      &C_icon_crossmark,
      "Abort",
      "login",
    });

UX_FLOW(ux_login_flow,
  &ux_login_flow_0_step,
  &ux_login_flow_1_step,
  &ux_login_flow_2_step,
  FLOW_LOOP
);


#endif

unsigned int ui_register_aramis_button(unsigned int button_mask,
                                       unsigned int button_mask_counter);

void ui_set_led(uint32_t color) {
  G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_SET_LED;
  G_io_seproxyhal_spi_buffer[1] = 0;
  G_io_seproxyhal_spi_buffer[2] = 5;

  G_io_seproxyhal_spi_buffer[3] = 0; // led id

  G_io_seproxyhal_spi_buffer[4] = 0x00;        // A
  G_io_seproxyhal_spi_buffer[5] = color >> 16; // R
  G_io_seproxyhal_spi_buffer[6] = color >> 8;  // G
  G_io_seproxyhal_spi_buffer[7] = color;       // B

  io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 8);
}

void ui_idle(void) {
#ifndef HAVE_UX_FLOW  
  ux_step_count = 0; // avoid redisplay
#endif  
#if defined(TARGET_BLUE)
  if (ux.elements != ui_idle_blue) {
    UX_DISPLAY(ui_idle_blue, NULL);
  }
#elif defined(HAVE_UX_FLOW)  
  // reserve a display stack slot if none yet
  if(G_ux.stack_count == 0) {
    ux_stack_push();
  }
  ux_flow_init(0, ux_idle_flow, NULL);
#elif defined(TARGET_NANOS)
  UX_MENU_DISPLAY(0, menu_main, NULL);
#elif defined(TARGET_ARAMIS)
  led_color_step = 0;
  led_color_step_count = 2;
  // disable interpretation of the user presence button
  ux.button_push_handler = NULL;

  ui_aramis_update();
#endif // #if TARGET_ID
}

// Main application

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
  // common icon element display,
  if ((element->component.type & (~BAGL_FLAG_TOUCHABLE)) == BAGL_ICON
      // this is a streamed icon from the app content
      && element->component.icon_id == 0 && element->text != NULL) {
    bagl_icon_details_t *icon = (bagl_icon_details_t *)PIC(element->text);
    // here could avoid the loop and do a pure aysnch stuff, but it's way too
    // sluggish
    io_seproxyhal_display_icon(element, icon);
    return;
  }
  io_seproxyhal_display_default((bagl_element_t *)element);
}

unsigned int u2f_callback_exit(const bagl_element_t *element) {
  // u2f_timer_cancel();
  os_sched_exit(0);
  return 0;
}
unsigned int u2f_callback_cancel(const bagl_element_t *element) {
  uint16_t tx = u2f_process_user_presence_cancelled();
  io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
  u2f_reset_display();  
  return 0; // DO NOT REDISPLAY THE BUTTON
}
unsigned int u2f_callback_confirm(const bagl_element_t *element) {
  uint16_t tx = u2f_process_user_presence_confirmed();
  io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
  u2f_reset_display();
  return 0; // DO NOT REDISPLAY THE BUTTON
}

#if defined(TARGET_NANOS) && !defined(HAVE_UX_FLOW)

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
#endif // #if defined(TARGET_NANOS) && !defined(HAVE_UX_FLOW)

#if defined(TARGET_ARAMIS)
void ui_aramis_update(void) {
  if (G_last_mcu_state != 0) {
    // awaiting user confirmation
    if (ux.button_push_handler != NULL) {
      if (u2fService.transportMedia == U2F_MEDIA_BLE) {
        ui_set_led(LED_COLOR_BLE_ACTION[led_color_step]);
      } else {
        ui_set_led(LED_COLOR_USB_ACTION[led_color_step]);
      }
    } else {
      if (G_last_mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_CHARGING) {
        ui_set_led(LED_COLOR_IDLE_CHARGING);
      } else if (battery_voltage_mv <= BATT_LOW_VOLTAGE_MV) {
        ui_set_led(LED_COLOR_IDLE_LOW_BATT);
      }
      // if usb poewered, use usb idle, else use ble idle
      else if (G_last_mcu_state &
               SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED) {
        ui_set_led(LED_COLOR_USB_IDLE);
      } else {
        ui_set_led(LED_COLOR_BLE_IDLE);
      }
    }
  }
}
#endif // #if defined(TARGET_ARAMIS)

#if defined(TARGET_BLUE) || defined(TARGET_ARAMIS)
#ifdef HAVE_BLE

void BLE_discoverable(void) {
  BLE_set_u2fServiceReference(&u2fService);
  BLE_power(0, NULL);

  // restart IOs
  BLE_power(1, NULL);
}

#endif // HAVE_BLE
#endif // TARGET_BLUE || TARGET_ARAMIS

#if defined(TARGET_ARAMIS)
void libbluenrg_event_connected(void) {
  if (os_seph_features() & SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_LEDRGB) {
    ui_power_off_ms = 0;
    UX_WAKE_UP();
    ui_aramis_update();
  }
}
#endif // #if defined(TARGET_ARAMIS)

// power off on disconnect to save power
void libbluenrg_event_disconnected(void) {
  /*

  OTO: last change to avoid exiting the the app direct

  if (G_last_mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED) {
    io_ble_discover_request = 1;
  }
  else {
    io_ble_discover_request = 1;
  }
  */
  THROW(EXCEPTION_IO_RESET);
}

#if defined(TARGET_ARAMIS)
unsigned int ui_register_aramis_button(unsigned int button_mask,
                                       unsigned int button_mask_counter) {
  if (button_mask & BUTTON_EVT_RELEASED) {
    ux.button_push_handler = NULL;

    u2f_callback_confirm(NULL);

    // upon auth, disconnect
    if (!ux_action_enroll) {
      // poweroff after transaction on aramis
      if (!(G_last_mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED) &&
          (os_seph_features() &
           SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_LEDRGB)) {
        ui_power_off_ms = 1000;
      }

      // request a ble reset, never 2 auth in the same BLE connection
      // io_ble_discover_request = 1;
    }

    // clear the led
    ui_aramis_update();
  }
}
#endif // #if defined(TARGET_ARAMIS)

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
  u2f_crypto_set_modifier(modifier ^ U2F_CRYPTO_TEST_WRONG_REGISTER_SIGNATURE);
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

#endif // HAVE_TEST_INTEROP

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
    UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {

      // defaulty retrig very soon (will be overriden during stepper_prepro)
      UX_CALLBACK_SET_INTERVAL(500);      
      /*
      // avoid idling in USB, stay awake to process request anytime
      if ((G_last_mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
        UX_WAKE_UP();
      }
      */

      // a power off request has been issued
      if (ui_power_off_ms) {
        ui_power_off_ms -= MIN(500, ui_power_off_ms);
        if (!ui_power_off_ms) {
          io_power_off_request = 1;
        }
      }

      // group all commands that are sending commands to make sure executing
      // them ONLY if status not sent by the BOLOS_UX app (event has been
      // delegated to bolos_ux before executing here)
      if (!io_seproxyhal_spi_is_status_sent()) {

#if defined(TARGET_BLUE) || defined(TARGET_ARAMIS)
#ifdef HAVE_BLE
        if ((os_seph_features() &
             SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_BLE)) {
          if (io_ble_discover_request) {
            io_ble_discover_request = 0;
            // blink waiting pairing
            led_color_step = 0;
            led_color_step_count = 2;

            BLE_discoverable();
          }
        }
#endif // HAVE_BLE
#endif // defined(TARGET_BLUE) || defined(TARGET_ARAMIS)

        u2f_process_timeout();

#if !defined(HAVE_UX_FLOW)
        // only redisplay if timeout has done nothing
        if (ux_step_count > 0 && UX_ALLOWED) {
          // prepare next screen
          ux_step = (ux_step + 1) % ux_step_count;
          // redisplay screen (precall stepper prepro which will retrig ticker
          // sooner or later)
          UX_REDISPLAY();
        }
#endif        

#if defined(TARGET_ARAMIS)
        // a power off request has been issued
        if (io_power_off_request) {
          io_seproxyhal_power_off();
        }

        // led mgmt
        if (os_seph_features() &
            SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_LEDRGB) {
          if (led_color_step_count) {
            led_color_step = (led_color_step + 1) % led_color_step_count;
            ui_aramis_update();
          }
        }
#endif // #if defined(TARGET_ARAMIS)
      }
    });
    break;

  case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
    UX_DISPLAYED_EVENT({});
    break;

  // check current power level for aramis
  case SEPROXYHAL_TAG_STATUS_EVENT: {
    unsigned int io_reset_requested = 0;
    unsigned int mcu_state;
#if defined(TARGET_ARAMIS)
    if (os_seph_features() &
        SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_LEDRGB) {
      mcu_state = U4BE(G_io_seproxyhal_spi_buffer, 3);
      battery_voltage_mv = U4BE(G_io_seproxyhal_spi_buffer, 12);

      // start BLE only if not USB plugged
      // if (! (mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED))  //
      // do both at once
      {}
      // set led color
      ui_aramis_update();
    }
#endif // #if defined(TARGET_ARAMIS)

    // immediate power off when unplugged
    if (G_last_mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED) {
      if (!(mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
        io_seproxyhal_power_off();
      }
    }
    // at least a mcu state has been received
    else if (G_last_mcu_state) {
      // ensure correct IO stuff, resetting the dongle
      if ((mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
        io_reset_requested = 1;
      }
    }
    G_last_mcu_state = mcu_state;

    if (io_reset_requested ||
        (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
         !(mcu_state & SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED))) {
      THROW(EXCEPTION_IO_RESET);
    }
    // no break is intentional
  }
  default:
    UX_DEFAULT_EVENT();
    break;
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
    // U2F: www.binance.com
    { 0xc3, 0x40, 0x8c, 0x04, 0x47, 0x88, 0xae, 0xa5, 0xb3, 0xdf, 0x30, 0x89, 0x52, 0xfd, 0x8c, 0xa3, 0xc7, 0x0e, 0x21, 0xfe, 0xf4, 0xf6, 0xc1, 0xc2, 0x37, 0x4c, 0xaa, 0x1d, 0xf9, 0xb2, 0x8d, 0xdd },
    "Binance"
  },    
  {
    // U2F: https://bitbucket.org
    { 0x12, 0x74, 0x3b, 0x92, 0x12, 0x97, 0xb7, 0x7f, 0x11, 0x35, 0xe4, 0x1f, 0xde, 0xdd, 0x4a, 0x84, 0x6a, 0xfe, 0x82, 0xe1, 0xf3, 0x69, 0x32, 0xa9, 0x91, 0x2f, 0x3b, 0x0d, 0x8d, 0xfb, 0x7d, 0x0e },
    "Bitbucket"
  },
  {
    // U2F: https://www.bitfinex.com
    { 0x30, 0x2f, 0xd5, 0xb4, 0x49, 0x2a, 0x07, 0xb9, 0xfe, 0xbb, 0x30, 0xe7, 0x32, 0x69, 0xec, 0xa5, 0x01, 0x20, 0x5c, 0xcf, 0xe0, 0xc2, 0x0b, 0xf7, 0xb4, 0x72, 0xfa, 0x2d, 0x31, 0xe2, 0x1e, 0x63 },
    "Bitfinex"
  },
  {
    // U2F: https://vault.bitwarden.com/app-id.json
    { 0xa3, 0x4d, 0x30, 0x9f, 0xfa, 0x28, 0xc1, 0x24, 0x14, 0xb8, 0xba, 0x6c, 0x07, 0xee, 0x1e, 0xfa, 0xe1, 0xa8, 0x5e, 0x8a, 0x04, 0x61, 0x48, 0x59, 0xa6, 0x7c, 0x04, 0x93, 0xb6, 0x95, 0x61, 0x90 },
    "Bitwarden"
  },
  {
    // U2F: coinbase.com
    { 0xe2, 0x7d, 0x61, 0xb4, 0xe9, 0x9d, 0xe0, 0xed, 0x98, 0x16, 0x3c, 0xb3, 0x8b, 0x7a, 0xf9, 0x33, 0xc6, 0x66, 0x5e, 0x55, 0x09, 0xe8, 0x49, 0x08, 0x37, 0x05, 0x58, 0x13, 0x77, 0x8e, 0x23, 0x6a },
    "Coinbase"
  },  
  {
    // U2F: https://www.dashlane.com
    { 0x68, 0x20, 0x19, 0x15, 0xd7, 0x4c, 0xb4, 0x2a, 0xf5, 0xb3, 0xcc, 0x5c, 0x95, 0xb9, 0x55, 0x3e, 0x3e, 0x3a, 0x83, 0xb4, 0xd2, 0xa9, 0x3b, 0x45, 0xfb, 0xad, 0xaa, 0x84, 0x69, 0xff, 0x8e, 0x6e },
    "Dashlane"
  },
  {
    // U2F: https://www.dropbox.com/u2f-app-id.json
    { 0xc5, 0x0f, 0x8a, 0x7b, 0x70, 0x8e, 0x92, 0xf8, 0x2e, 0x7a, 0x50, 0xe2, 0xbd, 0xc5, 0x5d, 0x8f, 0xd9, 0x1a, 0x22, 0xfe, 0x6b, 0x29, 0xc0, 0xcd, 0xf7, 0x80, 0x55, 0x30, 0x84, 0x2a, 0xf5, 0x81 },
    "Dropbox"
  },
  {
    // WebAuthn: www.dropbox.com
    { 0x82, 0xf4, 0xa8, 0xc9, 0x5f, 0xec, 0x94, 0xb2, 0x6b, 0xaf, 0x9e, 0x37, 0x25, 0x0e, 0x95, 0x63, 0xd9, 0xa3, 0x66, 0xc7, 0xbe, 0x26, 0x1c, 0xa4, 0xdd, 0x01, 0x01, 0xf4, 0xd5, 0xef, 0xcb, 0x83 },
    "Dropbox"
  },
  {
    // U2F: https://api-9dcf9b83.duosecurity.com
    { 0xf3, 0xe2, 0x04, 0x2f, 0x94, 0x60, 0x7d, 0xa0, 0xa9, 0xc1, 0xf3, 0xb9, 0x5e, 0x0d, 0x2f, 0x2b, 0xb2, 0xe0, 0x69, 0xc5, 0xbb, 0x4f, 0xa7, 0x64, 0xaf, 0xfa, 0x64, 0x7d, 0x84, 0x7b, 0x7e, 0xd6 },
    "Duo"
  },
  {
    // U2F: https://www.fastmail.com
    { 0x69, 0x66, 0xab, 0xe3, 0x67, 0x4e, 0xa2, 0xf5, 0x30, 0x79, 0xeb, 0x71, 0x01, 0x97, 0x84, 0x8c, 0x9b, 0xe6, 0xf3, 0x63, 0x99, 0x2f, 0xd0, 0x29, 0xe9, 0x89, 0x84, 0x47, 0xcb, 0x9f, 0x00, 0x84 },
    "FastMail"
  },
  {
    // U2F: https://id.fedoraproject.org/u2f-origins.json
    { 0x9d, 0x61, 0x44, 0x2f, 0x5c, 0xe1, 0x33, 0xbd, 0x46, 0x54, 0x4f, 0xc4, 0x2f, 0x0a, 0x6d, 0x54, 0xc0, 0xde, 0xb8, 0x88, 0x40, 0xca, 0xc2, 0xb6, 0xae, 0xfa, 0x65, 0x14, 0xf8, 0x93, 0x49, 0xe9 },
    "Fedora"
  },
  {
    // U2F: https://account.gandi.net/api/u2f/trusted_facets.json
    { 0xa4, 0xe2, 0x2d, 0xca, 0xfe, 0xa7, 0xe9, 0x0e, 0x12, 0x89, 0x50, 0x11, 0x39, 0x89, 0xfc, 0x45, 0x97, 0x8d, 0xc9, 0xfb, 0x87, 0x76, 0x75, 0x60, 0x51, 0x6c, 0x1c, 0x69, 0xdf, 0xdf, 0xd1, 0x96 },
    "Gandi"
  },
  {
    // U2F: https://github.com/u2f/trusted_facets
    { 0x70, 0x61, 0x7d, 0xfe, 0xd0, 0x65, 0x86, 0x3a, 0xf4, 0x7c, 0x15, 0x55, 0x6c, 0x91, 0x79, 0x88, 0x80, 0x82, 0x8c, 0xc4, 0x07, 0xfd, 0xf7, 0x0a, 0xe8, 0x50, 0x11, 0x56, 0x94, 0x65, 0xa0, 0x75 },
    "GitHub"
  },
  {
    // U2F: https://gitlab.com
    { 0xe7, 0xbe, 0x96, 0xa5, 0x1b, 0xd0, 0x19, 0x2a, 0x72, 0x84, 0x0d, 0x2e, 0x59, 0x09, 0xf7, 0x2b, 0xa8, 0x2a, 0x2f, 0xe9, 0x3f, 0xaa, 0x62, 0x4f, 0x03, 0x39, 0x6b, 0x30, 0xe4, 0x94, 0xc8, 0x04 },
    "GitLab"
  },
  {
    // U2F: https://www.gstatic.com/securitykey/origins.json
    { 0xa5, 0x46, 0x72, 0xb2, 0x22, 0xc4, 0xcf, 0x95, 0xe1, 0x51, 0xed, 0x8d, 0x4d, 0x3c, 0x76, 0x7a, 0x6c, 0xc3, 0x49, 0x43, 0x59, 0x43, 0x79, 0x4e, 0x88, 0x4f, 0x3d, 0x02, 0x3a, 0x82, 0x29, 0xfd },
    "Google"
  },
  {
    // U2F: https://keepersecurity.com
    { 0x53, 0xa1, 0x5b, 0xa4, 0x2a, 0x7c, 0x03, 0x25, 0xb8, 0xdb, 0xee, 0x28, 0x96, 0x34, 0xa4, 0x8f, 0x58, 0xae, 0xa3, 0x24, 0x66, 0x45, 0xd5, 0xff, 0x41, 0x8f, 0x9b, 0xb8, 0x81, 0x98, 0x85, 0xa9 },
    "Keeper"
  },
  {
    // U2F: https://lastpass.com
    { 0xd7, 0x55, 0xc5, 0x27, 0xa8, 0x6b, 0xf7, 0x84, 0x45, 0xc2, 0x82, 0xe7, 0x13, 0xdc, 0xb8, 0x6d, 0x46, 0xff, 0x8b, 0x3c, 0xaf, 0xcf, 0xb7, 0x3b, 0x2e, 0x8c, 0xbe, 0x6c, 0x08, 0x84, 0xcb, 0x24 },
    "LastPass"
  },
  {
    // U2F: https://slushpool.com/static/security/u2f.json
    { 0x08, 0xb2, 0xa3, 0xd4, 0x19, 0x39, 0xaa, 0x31, 0x66, 0x84, 0x93, 0xcb, 0x36, 0xcd, 0xcc, 0x4f, 0x16, 0xc4, 0xd9, 0xb4, 0xc8, 0x23, 0x8b, 0x73, 0xc2, 0xf6, 0x72, 0xc0, 0x33, 0x00, 0x71, 0x97 },
    "Slush Pool"
  },
  {
    // U2F: https://dashboard.stripe.com
    { 0x2a, 0xc6, 0xad, 0x09, 0xa6, 0xd0, 0x77, 0x2c, 0x44, 0xda, 0x73, 0xa6, 0x07, 0x2f, 0x9d, 0x24, 0x0f, 0xc6, 0x85, 0x4a, 0x70, 0xd7, 0x9c, 0x10, 0x24, 0xff, 0x7c, 0x75, 0x59, 0x59, 0x32, 0x92 },
    "Stripe"
  },
  {
    // U2F: https://u2f.bin.coffee
    { 0x1b, 0x3c, 0x16, 0xdd, 0x2f, 0x7c, 0x46, 0xe2, 0xb4, 0xc2, 0x89, 0xdc, 0x16, 0x74, 0x6b, 0xcc, 0x60, 0xdf, 0xcf, 0x0f, 0xb8, 0x18, 0xe1, 0x32, 0x15, 0x52, 0x6e, 0x14, 0x08, 0xe7, 0xf4, 0x68 },
    "u2f.bin.coffee"
  },
  {
    // WebAuthn: webauthn.bin.coffee
    { 0xa6, 0x42, 0xd2, 0x1b, 0x7c, 0x6d, 0x55, 0xe1, 0xce, 0x23, 0xc5, 0x39, 0x98, 0x28, 0xd2, 0xc7, 0x49, 0xbf, 0x6a, 0x6e, 0xf2, 0xfe, 0x03, 0xcc, 0x9e, 0x10, 0xcd, 0xf4, 0xed, 0x53, 0x08, 0x8b },
    "webauthn.bin.coffee"
  },
  {
    // WebAuthn: webauthn.io
    { 0x74, 0xa6, 0xea, 0x92, 0x13, 0xc9, 0x9c, 0x2f, 0x74, 0xb2, 0x24, 0x92, 0xb3, 0x20, 0xcf, 0x40, 0x26, 0x2a, 0x94, 0xc1, 0xa9, 0x50, 0xa0, 0x39, 0x7f, 0x29, 0x25, 0x0b, 0x60, 0x84, 0x1e, 0xf0 },
    "WebAuthn.io"
  },
  {
    // WebAuthn: webauthn.me
    { 0xf9, 0x5b, 0xc7, 0x38, 0x28, 0xee, 0x21, 0x0f, 0x9f, 0xd3, 0xbb, 0xe7, 0x2d, 0x97, 0x90, 0x80, 0x13, 0xb0, 0xa3, 0x75, 0x9e, 0x9a, 0xea, 0x3d, 0x0a, 0xe3, 0x18, 0x76, 0x6c, 0xd2, 0xe1, 0xad },
    "WebAuthn.me"
  },
  {
    // WebAuthn: demo.yubico.com
    { 0xc4, 0x6c, 0xef, 0x82, 0xad, 0x1b, 0x54, 0x64, 0x77, 0x59, 0x1d, 0x00, 0x8b, 0x08, 0x75, 0x9e, 0xc3, 0xe6, 0xd2, 0xec, 0xb4, 0xf3, 0x94, 0x74, 0xbf, 0xea, 0x69, 0x69, 0x92, 0x5d, 0x03, 0xb7 },
    "demo.yubico.com"
  },
};

const char *u2f_match_known_appid(const uint8_t *applicationParameter) {
  unsigned int i;
  for (i = 0; i < sizeof(u2f_known_appid) / sizeof(u2f_known_appid[0]); i++) {
    if (os_memcmp(applicationParameter, u2f_known_appid[i].sha256, 32) == 0) {
      return (const char *)PIC(u2f_known_appid[i].name);
    }
  }
  return NULL;
}

#define HASH_LENGTH 4
void u2f_prompt_user_presence(bool enroll, uint8_t *applicationParameter) {
  ux_action_enroll = enroll;

  UX_WAKE_UP();

#ifdef HAVE_NO_USER_PRESENCE_CHECK
#warning Having no user presence check is against U2F standard
  u2f_callback_confirm(NULL);
#else // HAVE_NO_USER_PRESENCE_CHECK
  snprintf(verifyHash, sizeof(verifyHash), "%.*H", 32, applicationParameter);
  strcpy(verifyName, "Unknown");

  const uint8_t *name = u2f_match_known_appid(applicationParameter);
  if (name != NULL) {
    strcpy(verifyName, name);
// #if defined(TARGET_NANOX)    
//     strcpy(verifyHash, name);
// #endif    
  }

#if defined(TARGET_BLUE)
  if (enroll) {
    ui_confirm_register_blue();
  } else {
    ui_confirm_login_blue();
  }
#elif defined(HAVE_UX_FLOW)    
  if (enroll) {
    ux_flow_init(0, ux_register_flow, NULL);
  }
  else {
    ux_flow_init(0, ux_login_flow, NULL);
  }
  // next timer callback in 500 ms
  UX_CALLBACK_SET_INTERVAL(500);        
#elif defined(TARGET_NANOS)
  if (name == NULL) {
    array_hexstr(verifyName, applicationParameter, HASH_LENGTH / 2);
    verifyName[HASH_LENGTH / 2 * 2] = '.';
    verifyName[HASH_LENGTH / 2 * 2 + 1] = '.';
    verifyName[HASH_LENGTH / 2 * 2 + 2] = '.';
    array_hexstr(verifyName + HASH_LENGTH / 2 * 2 + 3,
                 applicationParameter + 32 - HASH_LENGTH / 2, HASH_LENGTH / 2);
  }

  ux_step = 0;
  ux_step_count = 2;
  if (enroll) {
    UX_DISPLAY(ui_register_nanos, ui_stepper_prepro);
  } else {
    UX_DISPLAY(ui_auth_nanos, ui_stepper_prepro);
  }
#elif defined(TARGET_ARAMIS)
  // ensure the button is used to validate transactions
  ux.button_push_handler = ui_register_aramis_button;

  led_color_step = 0;
  led_color_step_count = 2;
  ui_aramis_update();

  // ready to process commands
  io_seproxyhal_general_status();
#endif // #if TARGET_ID
#endif // HAVE_NO_USER_PRESENCE_CHECK
}

void u2f_reset_display() {
  ui_idle();
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

void sample_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(0x6982);
                }

                handleApdu(&flags, &tx, rx);
            }
            CATCH(EXCEPTION_IO_RESET) {
              THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                case 0x9000:
                    // All is well
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                if (e != 0x9000) {
                    flags &= ~IO_ASYNCH_REPLY;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}


void app_main(void) {
  G_last_mcu_state = 0;

  for (;;) {
    BEGIN_TRY {
      TRY {
        unsigned int mcu_features = 0;

        // call the check api level
        io_seproxyhal_init();        

        mcu_features = os_seph_features();
        io_power_off_request = 0;
        io_ble_discover_request = 0;

        // Initialize U2F service
        u2f_init_config();

        u2f_crypto_init();
        u2f_counter_init();

#ifdef HAVE_TEST_INTEROP
        getDeviceState();
#endif
        // request device status (charging/usbpower/etc)
        io_seproxyhal_request_mcu_status();

        UX_WAKE_UP();

        // BLE is always active for the Blue (not always for aramis)
#if defined(TARGET_BLUE)
        // setup the status bar colors (remembered after wards, even more if
        // another app does not resetup after app switch)
        UX_SET_STATUS_BAR_COLOR(0xFFFFFF, COLOR_APP);
#endif // #if defined(TARGET_BLUE)

        // enable BLE if platform is BLE enabled
        if ((os_seph_features() &
             SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_BLE)) {
          io_ble_discover_request = 1;

          /* not blinking anymore
          if (mcu_features & SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_LEDRGB)
          {
            // start blinking until paired
            led_color_step = 0;
            led_color_step_count = 2;
          }
          */
        }

        // do that at the latest momen to ensure huge delay between usb(0) and
        // USB(1) upon io_reset exception
        USB_power(0);
        USB_power(1);

        ui_idle();

#if defined(TARGET_NANOX)        
        // grab the current plane mode setting
        G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);        
#ifdef HAVE_BLE
        BLE_power(0, NULL);
        BLE_power_mac(1, "Nano X", u2f_get_ble_mac());
#endif // HAVE_BLE        
#endif        

#if !defined(TARGET_NANOX) && !defined(HAVE_UX_FLOW)
        // next timer callback in 500 ms
        UX_CALLBACK_SET_INTERVAL(500);        
#endif        

        // no display process sent in this mode
        if (mcu_features & SEPROXYHAL_TAG_SESSION_START_EVENT_FEATURE_LEDRGB) {
          io_seproxyhal_general_status();
        }

        sample_main();

      }
      // catch BLE disconnect event
      CATCH(EXCEPTION_IO_RESET) {
        USB_power(0); // ensure disconnecting pull before reconnecting

        continue;
      }
      FINALLY {
      }
    }
    END_TRY;
  }
}

__attribute__((section(".boot"))) void main(void) {
  // exit critical section
  __asm volatile("cpsie i");

  // ensure exception will work as planned
  os_boot();

  for (;;) {
    BEGIN_TRY {
      TRY {
        UX_INIT();

        app_main();
      }
      CATCH_OTHER(e) {
        app_exit();
      }
      FINALLY {
      }
    }
    END_TRY;
  }
}
