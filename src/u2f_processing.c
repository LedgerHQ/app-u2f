#include "os.h"
#include "cx.h"
#include "u2f_counter.h"
#include "u2f_crypto.h"
#include "u2f_service.h"
#include "u2f_transport.h"
#include <stdint.h>
#include <string.h>

static const uint8_t VERSION[] = {'U', '2', 'F', '_', 'V', '2' };

#ifdef HAVE_BLE

static const uint8_t BLE_KEEPALIVE[] = { U2F_CMD_KEEPALIVE, 0x00, 0x01, KEEPALIVE_REASON_PROCESSING };

#endif

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_DATA 7

#define FIDO_CLA 0x00
#define FIDO_INS_ENROLL 0x01
#define FIDO_INS_SIGN 0x02
#define FIDO_INS_GET_VERSION 0x03

#define FIDO_INS_PROP_GET_COUNTER 0xC0 // U2F_VENDOR_FIRST

#define P1_SIGN_CHECK_ONLY 0x07
#define P1_SIGN_SIGN 0x03
#define P1_SIGN_SIGN_OPTIONAL_USER_PRESENCE 0x08

#define SW_WRONG_LENGTH 0x6700
#define SW_UNKNOWN_CLASS 0x6E00
#define SW_UNKNOWN_INSTRUCTION 0x6D00
#define SW_BAD_KEY_HANDLE 0x6A80
#define SW_PROOF_OF_PRESENCE_REQUIRED 0x6985
#define SW_PROPRIETARY_CRYPTO_NOT_AVAILABLE 0x6F01
#define SW_PROPRIETARY_USER_CANCELLED 0x6F02
#define SW_PROPRIETARY_INVALID_PARAMETERS_APDU 0x6F03
#define SW_PROPRIETARY_INVALID_DATA_APDU 0x6F04
#define SW_PROPRIETARY_INTERNAL 0x6FFF

#define U2F_ENROLL_RESERVED 0x05
static const uint8_t DUMMY_ZERO[] = {0x00};
#define SIGN_USER_PRESENCE_MASK 0x01
static const uint8_t DUMMY_USER_PRESENCE[] = {SIGN_USER_PRESENCE_MASK};

extern u2f_service_t G_io_u2f;

void u2f_prompt_user_presence(bool enroll, uint8_t *applicationParameter);

uint16_t u2f_process_user_presence_cancelled(void) {
  u2f_crypto_reset();
  G_io_apdu_buffer[0] = 0x6F;
  G_io_apdu_buffer[1] = 0xFF;      
  return 2;
}

uint16_t u2f_process_user_presence_confirmed(void) {
  uint16_t offset = 0;
  uint8_t challengeParameter[32];
  uint8_t applicationParameter[32];

  os_memmove(challengeParameter, G_io_apdu_buffer + OFFSET_DATA, 32);
  os_memmove(applicationParameter, G_io_apdu_buffer + OFFSET_DATA + 32, 32);
    
  switch(G_io_apdu_buffer[OFFSET_INS]) {
    case FIDO_INS_ENROLL: {
      uint16_t keyHandleLength;
      uint16_t signatureLength;

      G_io_apdu_buffer[offset++] = U2F_ENROLL_RESERVED;
      keyHandleLength = u2f_crypto_generate_key_and_wrap(
        applicationParameter, G_io_apdu_buffer + offset,
        G_io_apdu_buffer + offset + 65 + 1);
      if ((keyHandleLength == 0) || (keyHandleLength > 255)) {
        goto internal_error_enroll;
      }
      offset += 65;
      G_io_apdu_buffer[offset++] = keyHandleLength;
      offset += keyHandleLength;
      offset += u2f_crypto_copy_attestation_certificate(G_io_apdu_buffer + offset);
      // Compute signature
      if (!u2f_sign_init() || !u2f_sign_update(DUMMY_ZERO, 1) ||
          !u2f_sign_update(applicationParameter, 32) ||
          !u2f_sign_update(challengeParameter, 32) ||
          !u2f_sign_update(G_io_apdu_buffer + 1 + 65 + 1,
                         keyHandleLength) ||
          !u2f_sign_update(G_io_apdu_buffer + 1, 65)) {
        goto internal_error_enroll;
      }
      signatureLength =
        u2f_crypto_sign_attestation(G_io_apdu_buffer + offset);
      if (signatureLength == 0) {
        goto internal_error_enroll;
      }
      offset += signatureLength;      
      G_io_apdu_buffer[offset++] = 0x90;
      G_io_apdu_buffer[offset++] = 0x00;
      break;      
internal_error_enroll:
      u2f_crypto_reset();
      G_io_apdu_buffer[0] = 0x6F;
      G_io_apdu_buffer[1] = 0xFF;      
      offset = 2;
      break;
    }

    case FIDO_INS_SIGN: {
      uint16_t signatureLength;
      G_io_apdu_buffer[offset++] = SIGN_USER_PRESENCE_MASK;
      offset += u2f_counter_increase_and_get(G_io_apdu_buffer + offset);
      // Compute signature
      if (!u2f_sign_init() || !u2f_sign_update(applicationParameter, 32) ||
          !u2f_sign_update(DUMMY_USER_PRESENCE, 1) ||
          !u2f_sign_update(G_io_apdu_buffer + 1, 4) ||
          !u2f_sign_update(challengeParameter, 32)) {
        goto internal_error_sign;
      }
      signatureLength =
        u2f_crypto_sign_application(G_io_apdu_buffer + offset);
      if (signatureLength == 0) {
        goto internal_error_sign;
      }
      offset += signatureLength;
      G_io_apdu_buffer[offset++] = 0x90;
      G_io_apdu_buffer[offset++] = 0x00;
      break;
internal_error_sign:
      u2f_crypto_reset();
      G_io_apdu_buffer[0] = 0x6F;
      G_io_apdu_buffer[1] = 0xFF;      
      offset = 2;
      break;
    }    

    default:
      THROW(SW_PROPRIETARY_INTERNAL);
  }  
  return offset;
}

void u2f_apdu_enroll(volatile unsigned int *flags, volatile unsigned int *tx, uint32_t dataLength) {
  uint8_t applicationParameter[32];

  if (dataLength != 32 + 32) {
    THROW(SW_WRONG_LENGTH);
  }
  if (!u2f_crypto_available()) {
    THROW(SW_PROPRIETARY_CRYPTO_NOT_AVAILABLE);
    return;
  }

  os_memmove(applicationParameter, G_io_apdu_buffer + OFFSET_DATA + 32, 32);

#ifndef HAVE_NO_USER_PRESENCE_CHECK
  if (G_io_u2f.media == U2F_MEDIA_USB) {
    u2f_message_set_autoreply_wait_user_presence(&G_io_u2f, true);
  }
  else
  if (G_io_u2f.media == U2F_MEDIA_BLE) {
    G_io_u2f.requireKeepalive = true;
  }
  u2f_prompt_user_presence(true, applicationParameter);
  *flags |= IO_ASYNCH_REPLY;
#else
  *tx = u2f_process_user_presence_confirmed();
#endif    
}

void u2f_apdu_sign(volatile unsigned int *flags, volatile unsigned int *tx, uint32_t dataLength) {
  uint8_t challengeParameter[32];
  uint8_t applicationParameter[32];
  uint8_t keyHandle[64];
  uint8_t keyHandleLength;
  bool sign = false;
  if (dataLength < 32 + 32 + 1) {
    THROW(SW_WRONG_LENGTH);
  }
  switch(G_io_apdu_buffer[OFFSET_P1]) {
    case P1_SIGN_CHECK_ONLY:
      break;
    case P1_SIGN_SIGN:
    case P1_SIGN_SIGN_OPTIONAL_USER_PRESENCE: // proof of user presence is always required (1.2)
      sign = true;
      break;
    default:
      THROW(SW_PROPRIETARY_INVALID_PARAMETERS_APDU);
  }
  if (!u2f_crypto_available()) {
      THROW(SW_PROPRIETARY_CRYPTO_NOT_AVAILABLE);
  }
  os_memmove(challengeParameter, G_io_apdu_buffer + OFFSET_DATA, 32);
  os_memmove(applicationParameter, G_io_apdu_buffer + OFFSET_DATA + 32, 32);
  keyHandleLength = G_io_apdu_buffer[OFFSET_DATA + 64];
  if (keyHandleLength > sizeof(keyHandle)) {
    THROW(SW_BAD_KEY_HANDLE);
  }
  os_memmove(keyHandle, G_io_apdu_buffer + OFFSET_DATA + 65, keyHandleLength);

  // Check the key handle validity immediately
  if (!u2f_crypto_unwrap(keyHandle, keyHandleLength, applicationParameter)) {
    u2f_crypto_reset();
    THROW(SW_BAD_KEY_HANDLE);
  }
  // screen_printf("unwrapped\n");
  // If we only check user presence, get rid of the private key immediately
  if (!sign) {
    u2f_crypto_reset();
    THROW(SW_PROOF_OF_PRESENCE_REQUIRED);
  }  

#ifndef HAVE_NO_USER_PRESENCE_CHECK
  if (G_io_u2f.media == U2F_MEDIA_USB) {
    u2f_message_set_autoreply_wait_user_presence(&G_io_u2f, true);
  }
  else
  if (G_io_u2f.media == U2F_MEDIA_BLE) {
    G_io_u2f.requireKeepalive = true;
  }  
  u2f_prompt_user_presence(false, applicationParameter);
  *flags |= IO_ASYNCH_REPLY;
#else
  *tx = u2f_process_user_presence_confirmed();
#endif    
}

void u2f_apdu_get_version(volatile unsigned int *flags, volatile unsigned int *tx, uint32_t dataLength) {
  if (dataLength != 0) {
    THROW(SW_WRONG_LENGTH);
  }
  os_memmove(G_io_apdu_buffer, VERSION, sizeof(VERSION));
  *tx = sizeof(VERSION);
  THROW(0x9000);
}

void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx, uint32_t length) {
  // in extended length G_io_apdu_buffer[4] must be 0
  uint32_t dataLength = /*(G_io_apdu_buffer[4] << 16) |*/ (G_io_apdu_buffer[5] << 8) | (G_io_apdu_buffer[6]);
  if (dataLength == (uint16_t)(length - 9) || dataLength == (uint16_t)(length - 7)) {
    // Le is optional
    // nominal case from the specification
  }
  // circumvent google chrome extended length encoding done on the last byte only (module 256) but all data being transferred
  else if (dataLength == (uint16_t)(length - 9)%256) {
    dataLength = length - 9;
  }
  else if (dataLength == (uint16_t)(length - 7)%256) {
    dataLength = length - 7;
  }    
  else {
    THROW(SW_WRONG_LENGTH);
  }

  if (G_io_apdu_buffer[OFFSET_CLA] != FIDO_CLA) {
    THROW(SW_UNKNOWN_CLASS);
  }

  switch (G_io_apdu_buffer[OFFSET_INS]) {
    case FIDO_INS_ENROLL:
        // screen_printf("enroll\n");
        u2f_apdu_enroll(flags, tx, dataLength);
        break;
    case FIDO_INS_SIGN:
        // screen_printf("sign\n");
        u2f_apdu_sign(flags, tx, dataLength);
        break;
    case FIDO_INS_GET_VERSION:
        // screen_printf("version\n");
        u2f_apdu_get_version(flags, tx, dataLength);
        break;

    default:
        // screen_printf("unsupported\n");
        THROW(SW_UNKNOWN_INSTRUCTION);
        return;
    }
}

void u2f_process_timeout() {

#ifdef HAVE_BLE

  if ((G_io_u2f.media == U2F_MEDIA_BLE) && (G_io_u2f.requireKeepalive)) {
    BLE_protocol_send(BLE_KEEPALIVE, sizeof(BLE_KEEPALIVE));
  }

#endif  
}

