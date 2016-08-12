/*******************************************************************************
*   Ledger Blue - Non secure firmware
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
*   See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************/

#ifdef HAVE_BLE

// not used for now
#define THROW(x) return; // for(;;);

#include "u2f_io.h"

#include "osal.h"
#include "hci.h"
#include "hal.h"
#include "bluenrg_interface.h"
#include "hal_types.h"
#include "string.h"
#include "gp_timer.h"
#include "sm.h"
#include "bluenrg_gap.h"
#include "bluenrg_hal_aci.h"
#include "bluenrg_gatt_aci.h"
#include "bluenrg_gap_aci.h"
#include "hci_const.h"
#include "bluenrg_gatt_server.h"
#include "bluenrg_aci_const.h"

#include "os_io_seproxyhal.h"

#include "u2f_config.h"
#include "u2f_service.h"

tBleStatus Add_U2F_Service(void);
tBleStatus Add_DIS_Service(void);

volatile struct ble_state_s {
    unsigned int powered;

#ifdef BLE_PACKET_ACK
    unsigned char apdu_transport_ack;
#endif // BLE_PACKET_ACK

    // public
    unsigned short gap_service_handle;
    unsigned short gap_dev_name_char_handle;
    unsigned short gap_appearance_char_handle;

    unsigned short service_handle, tx_characteristic_handle,
        rx_characteristic_handle;

    unsigned short u2f_controlpointlength_handle, u2f_servicerevision_handle;
    unsigned short dis_service_handle;
    unsigned short dis_manufacturer_name_handle, dis_model_number_handle,
        dis_hw_rev_string_handle, dis_fw_rev_string_handle;

    unsigned char client_link_established;
    unsigned short apdu_transport_remlen;
    unsigned short apdu_transport_seq;
    unsigned char *apdu_transport_ptr;
    unsigned char apdu_transport_busy_sending;
    unsigned char apdu_transport_lock;
    unsigned char connection_reset;
    unsigned int connection_timeout_ms;
    unsigned char connection_timeout_enabled;

    unsigned char *last_discovered_name;

    unsigned int tx_pool_available;
} G_io_ble;

volatile u2f_service_t *u2fServiceReference;

/** @addtogroup BlueNRG_Shield
 *  @{
 */

#define BLE_TIMEOUT_CONNECTION_MS 5000UL
// defined by the characteristic length, use minimal to be wide usable
#define BLE_CHUNK_LENGTH_B 20

/** @defgroup BlueNRG_Shield_Sample_Application
 *  @brief Sample application for BlueNR // not used for now
#define THROW(x) for(;;);G Shield on STM32 Nucleo boards.
 *  @{
 */

/* Private defines
 * ------------------------------------------------------------*/
/* Private macros
 * -------------------------------------------------------------*/
#define BDADDR_SIZE 6

/* Private variables ---------------------------------------------------------*/


/**
 * The server-peripheral mac : leet(Wallet-000002)
 * Little endian encoding
 */
const unsigned char SERVER_BDADDR_CONST[] = {0x02, 0x00, 0x00,
                                             0xe7, 0x11, 0x3A};
const unsigned char DEFAULT_NAME_CONST[] = {
    AD_TYPE_COMPLETE_LOCAL_NAME, 'x', ' ', 'U', '2', 'F', '\0'};
const uint8_t u2f_serviceUUIDList[] = {AD_TYPE_16_BIT_SERV_UUID, 0xfd, 0xff};
unsigned char SERVER_BDADDR[16];
unsigned char DEFAULT_NAME[32];

/* ==========================================================================================
 * ==========================================================================================
 * ==========================================================================================
 */

void BLE_set_u2fServiceReference(u2f_service_t *reference) {
    u2fServiceReference = reference;
}

void BLE_diversify_name_address() {
    const char hexdigits[] = "0123456789ABCDEF";
    uint32_t uid;
    // const unsigned int * UID = (unsigned int *)0x00800000;
    // uid = UID[0] ^ UID[1];
    uid = 0x12345678;
    memset(DEFAULT_NAME, 0,
           sizeof(DEFAULT_NAME)); // ensure no uninit during strlen
    memset(SERVER_BDADDR, 0, sizeof(SERVER_BDADDR));
    memcpy(SERVER_BDADDR, SERVER_BDADDR_CONST, sizeof(SERVER_BDADDR_CONST));
    memcpy(DEFAULT_NAME, DEFAULT_NAME_CONST, sizeof(DEFAULT_NAME_CONST));
    memcpy(&SERVER_BDADDR[0], &uid, 4);
}

void BLE_make_discoverable(const char *discovered_name) {
    unsigned char ret;

    // make discoverable
    // TODO limit the time it is done, to go back to sleep in case timeout

    if (discovered_name == NULL) {
        discovered_name = DEFAULT_NAME;
    }

    G_io_ble.last_discovered_name = discovered_name;

    /* disable scan response */ // good for low power // need to be reactivated
                                // for reconnection later but btle chip will get
                                // resetted
    ret = hci_le_set_scan_resp_data(0, NULL);
    if (ret) {
        THROW(EXCEPTION);
    }

    // set device name
    const char *name = "Ledger";
    ret = aci_gatt_update_char_value(G_io_ble.gap_service_handle,
                                     G_io_ble.gap_dev_name_char_handle, 0,
                                     strlen(name), (uint8_t *)name);
    if (ret) {
        PRINTF("aci_gatt_update_char_value device name failed. %d\n", ret);
    }

    // set appearance value (generic keyring)
    unsigned short appearance = 576;
    ret = aci_gatt_update_char_value(G_io_ble.gap_service_handle,
                                     G_io_ble.gap_appearance_char_handle, 0, 2,
                                     (uint8_t *)&appearance);
    if (ret) {
        PRINTF("aci_gatt_update_char_value appearance failed. %d\n", ret);
    }

    /*
    // remove manufacturer advertisement data
    ret = aci_gap_delete_ad_type(0xFF);
    if (ret) {
      PRINTF("aci_gap_delete_ad_type manufacturer failed. %d\n", ret);
    }
    */

    /*
    #warning TODO
    // TODO use advert data to advertise the product ID instead of changing the
    Name
    ret = aci_gap_update_adv_data(0, NULL);
    if (ret) {
      THROW(EXCEPTION);
    }
    */

    // PRINTF("General Discoverable Mode ");
    /*
    Advertising_Event_Type, Adv_Interval_Min, Adv_Interval_Max, Address_Type,
    Adv_Filter_Policy,
    Local_Name_Length, Local_Name, Service_Uuid_Length, Service_Uuid_List,
    Slave_Conn_Interval_Min,
    Slave_Conn_Interval_Max
    */
    ret = aci_gap_set_discoverable(
        ADV_IND,
        // low power leverage
        500 * 625 / 1000, 3000 * 625 / 1000, PUBLIC_ADDR, NO_WHITE_LIST_USE,
        strlen(discovered_name), discovered_name, sizeof(u2f_serviceUUIDList),
        u2f_serviceUUIDList,
        // low power leverage
        6 * 1250 / 1000,
        50 * 1250 / 1000); // (50) bigger than this it's far too long
    if (ret) {
        PRINTF("set discoverable failed.\n");
        THROW(EXCEPTION);
    }

    // TODO set a timeout to stop advertising (could be power off btw)

    // PRINTF("%d\n",ret);
}

/**
 * Upon first reply of the bluenrg we must setup the BLE operating parameters
 */
void BLE_setup(unsigned char *discovered_name) {
    tBleStatus ret;

    // PRINTF("setup\n");
    BLE_diversify_name_address();
    // PRINTF("diversify\n");

    // reset ble state
    memset(&G_io_ble, 0, sizeof(G_io_ble));

    HCI_Init();
    // PRINTF("hci\n");
    // probably not a good idea to do this each at each startup
    ret = aci_hal_write_config_data(CONFIG_DATA_PUBADDR_OFFSET,
                                    CONFIG_DATA_PUBADDR_LEN, SERVER_BDADDR);
    if (ret) {
        PRINTF("Setting BD_ADDR failed.\n");
        THROW(EXCEPTION);
    }

    ret = aci_gatt_init();
    PRINTF("GATT\n");
    if (ret) {
        PRINTF("GATT_Init failed.\n");
        THROW(EXCEPTION);
    }

#ifdef BLUENRG_MS
    ret = aci_gap_init(GAP_PERIPHERAL_ROLE, 0, 7, &G_io_ble.gap_service_handle,
                       &G_io_ble.gap_dev_name_char_handle,
                       &G_io_ble.gap_appearance_char_handle);
#else
    ret = aci_gap_init(GAP_PERIPHERAL_ROLE, &G_io_ble.gap_service_handle,
                       &G_io_ble.gap_dev_name_char_handle,
                       &G_io_ble.gap_appearance_char_handle);
#endif

    if (ret != BLE_STATUS_SUCCESS) {
        PRINTF("GAP_Init failed.\n");
        THROW(EXCEPTION);
    }

    // limit exchanges and data security to limit power, moreover apdus are
    // public (f)
    //#if 0
    ret = aci_gap_set_auth_requirement(
        MITM_PROTECTION_REQUIRED, OOB_AUTH_DATA_ABSENT, NULL, 7, 16,
        USE_FIXED_PIN_FOR_PAIRING, 123456, BONDING);
//#endif

    // PRINTF("auth\n");
    if (ret != BLE_STATUS_SUCCESS) {
        PRINTF("BLE Stack Initialized.\n");
        THROW(EXCEPTION);
    }

    // PRINTF("SERVER: BLE Stack Initialized\n");
    ret = Add_U2F_Service();
    if (ret == BLE_STATUS_SUCCESS) {
        ret = Add_DIS_Service();
    }
    if (ret != BLE_STATUS_SUCCESS) {
        PRINTF("Error while adding service.\n");
        THROW(EXCEPTION);
    }

    /* Set output power level */
    ret = aci_hal_set_tx_power_level(1, 7); // max power
    // ret = aci_hal_set_tx_power_level(0, 0); // lowest power
    if (ret) {
        THROW(EXCEPTION);
    }

    G_io_ble.client_link_established = FALSE;
    G_io_ble.connection_timeout_enabled = 0;

    BLE_make_discoverable(discovered_name);
}

void BLE_power(unsigned char powered, const char *discovered_name) {
    G_io_seproxyhal_spi_buffer[0] = SEPROXYHAL_TAG_BLE_RADIO_POWER;
    G_io_seproxyhal_spi_buffer[1] = 0;
    G_io_seproxyhal_spi_buffer[2] = 1;
    G_io_seproxyhal_spi_buffer[3] = powered ? 3 : 0;
    io_seproxyhal_spi_send(G_io_seproxyhal_spi_buffer, 4);

    if (powered) {
        BLE_setup(discovered_name);
    }
}

#define COPY_UUID_128(uuid_struct, uuid_15, uuid_14, uuid_13, uuid_12,         \
                      uuid_11, uuid_10, uuid_9, uuid_8, uuid_7, uuid_6,        \
                      uuid_5, uuid_4, uuid_3, uuid_2, uuid_1, uuid_0)          \
    do {                                                                       \
        uuid_struct.uuid128[0] = uuid_0;                                       \
        uuid_struct.uuid128[1] = uuid_1;                                       \
        uuid_struct.uuid128[2] = uuid_2;                                       \
        uuid_struct.uuid128[3] = uuid_3;                                       \
        uuid_struct.uuid128[4] = uuid_4;                                       \
        uuid_struct.uuid128[5] = uuid_5;                                       \
        uuid_struct.uuid128[6] = uuid_6;                                       \
        uuid_struct.uuid128[7] = uuid_7;                                       \
        uuid_struct.uuid128[8] = uuid_8;                                       \
        uuid_struct.uuid128[9] = uuid_9;                                       \
        uuid_struct.uuid128[10] = uuid_10;                                     \
        uuid_struct.uuid128[11] = uuid_11;                                     \
        uuid_struct.uuid128[12] = uuid_12;                                     \
        uuid_struct.uuid128[13] = uuid_13;                                     \
        uuid_struct.uuid128[14] = uuid_14;                                     \
        uuid_struct.uuid128[15] = uuid_15;                                     \
    } while (0)

const uint8_t u2f_service_uuid[2] = {0xfd, 0xff};
const uint8_t u2f_charUuidTX[16] = {0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9,
                                    0x2f, 0xb4, 0xee, 0xec, 0xaa, 0xde,
                                    0xf2, 0xff, 0xd0, 0xf1};
const uint8_t u2f_charUuidRX[16] = {0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9,
                                    0x2f, 0xb4, 0xee, 0xec, 0xaa, 0xde,
                                    0xf1, 0xff, 0xd0, 0xf1};
const uint8_t u2f_controlPointLength[16] = {0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9,
                                            0x2f, 0xb4, 0xee, 0xec, 0xaa, 0xde,
                                            0xf3, 0xff, 0xd0, 0xf1};
const uint8_t u2f_controlPointLength_value[2] = {0x00, 0x14};
const uint8_t u2f_serviceRevision[2] = {0x28, 0x2a};
const uint8_t u2f_serviceRevision_value[3] = "1.0";

const uint8_t dis_service_uuid[2] = {0x0a, 0x18};
const uint8_t dis_manufacturer_name[2] = {0x29, 0x2a};
const uint8_t dis_manufacturer_name_value[6] = "Ledger";
const uint8_t dis_model_number[2] = {0x24, 0x2a};
const uint8_t dis_model_number_value[6] = "U2FAPP";
const uint8_t dis_hw_rev_string[2] = {0x27, 0x2a};
const uint8_t dis_hw_rev_string_value[3] = "1.0";
const uint8_t dis_fw_rev_string[2] = {0x26, 0x2a};
const uint8_t dis_fw_rev_string_value[3] = "1.0";

tBleStatus Add_DIS_Service(void) {
    tBleStatus ret;

    PRINTF("Add DIS\n");

    ret = aci_gatt_add_serv(UUID_TYPE_16, dis_service_uuid, PRIMARY_SERVICE, 10,
                            &G_io_ble.dis_service_handle); /* original is 9?? */
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("Service added\n");

    ret = aci_gatt_add_char(
        G_io_ble.dis_service_handle, UUID_TYPE_16, dis_manufacturer_name,
        BLE_CHUNK_LENGTH_B, CHAR_PROP_READ /*|CHAR_PROP_WRITE_WITHOUT_RESP*/,
        ATTR_PERMISSION_NONE, 0, 16, 1, &G_io_ble.dis_manufacturer_name_handle);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("manufacturer name added\n");

    ret = aci_gatt_update_char_value(
        G_io_ble.dis_service_handle, G_io_ble.dis_manufacturer_name_handle, 0,
        sizeof(dis_manufacturer_name_value), dis_manufacturer_name_value);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("manufacturer name set\n");

    ret = aci_gatt_add_char(
        G_io_ble.dis_service_handle, UUID_TYPE_16, dis_model_number,
        BLE_CHUNK_LENGTH_B, CHAR_PROP_READ /*|CHAR_PROP_WRITE_WITHOUT_RESP*/,
        ATTR_PERMISSION_NONE, 0, 16, 1, &G_io_ble.dis_model_number_handle);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("model number added\n");

    ret = aci_gatt_update_char_value(
        G_io_ble.dis_service_handle, G_io_ble.dis_model_number_handle, 0,
        sizeof(dis_model_number_value), dis_model_number_value);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("model number set\n");

    ret = aci_gatt_add_char(
        G_io_ble.dis_service_handle, UUID_TYPE_16, dis_hw_rev_string,
        BLE_CHUNK_LENGTH_B, CHAR_PROP_READ /*|CHAR_PROP_WRITE_WITHOUT_RESP*/,
        ATTR_PERMISSION_NONE, 0, 16, 1, &G_io_ble.dis_hw_rev_string_handle);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("hw rev string added\n");

    ret = aci_gatt_update_char_value(
        G_io_ble.dis_service_handle, G_io_ble.dis_hw_rev_string_handle, 0,
        sizeof(dis_hw_rev_string_value), dis_hw_rev_string_value);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("hw rev string set\n");

    ret = aci_gatt_add_char(
        G_io_ble.dis_service_handle, UUID_TYPE_16, dis_fw_rev_string,
        BLE_CHUNK_LENGTH_B, CHAR_PROP_READ /*|CHAR_PROP_WRITE_WITHOUT_RESP*/,
        ATTR_PERMISSION_NONE, 0, 16, 1, &G_io_ble.dis_fw_rev_string_handle);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("fw rev string added\n");

    ret = aci_gatt_update_char_value(
        G_io_ble.dis_service_handle, G_io_ble.dis_fw_rev_string_handle, 0,
        sizeof(dis_fw_rev_string_value), dis_fw_rev_string_value);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("fw rev string set\n");

    return BLE_STATUS_SUCCESS;

fail:
    PRINTF("Error while adding DIS Service.\n");
    return BLE_STATUS_ERROR;
}

//#if 0
#define PERMISSION_U2F_READ                                                    \
    ATTR_PERMISSION_AUTHOR_READ | ATTR_PERMISSION_ENCRY_READ
#define PERMISSION_U2F_WRITE                                                   \
    ATTR_PERMISSION_AUTHOR_WRITE | ATTR_PERMISSION_ENCRY_WRITE
//#endif


tBleStatus Add_U2F_Service(void) {
    tBleStatus ret;

    PRINTF("Add U2F\n");

    ret = aci_gatt_add_serv(UUID_TYPE_16, u2f_service_uuid, PRIMARY_SERVICE, 10,
                            &G_io_ble.service_handle); /* original is 9?? */
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("Service added\n");

    ret = aci_gatt_add_char(G_io_ble.service_handle, UUID_TYPE_128,
                            u2f_charUuidTX, BLE_CHUNK_LENGTH_B,
                            CHAR_PROP_NOTIFY, PERMISSION_U2F_READ, 0, 16, 1,
                            &G_io_ble.tx_characteristic_handle);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("Notify added\n");

    ret = aci_gatt_add_char(
        G_io_ble.service_handle, UUID_TYPE_128, u2f_charUuidRX,
        BLE_CHUNK_LENGTH_B, CHAR_PROP_WRITE /*|CHAR_PROP_WRITE_WITHOUT_RESP*/,
        PERMISSION_U2F_WRITE, GATT_NOTIFY_WRITE_REQ_AND_WAIT_FOR_APPL_RESP, 16,
        1, &G_io_ble.rx_characteristic_handle);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("Write added\n");

    /* Additional U2F endpoints */

    ret = aci_gatt_add_char(
        G_io_ble.service_handle, UUID_TYPE_128, u2f_controlPointLength,
        BLE_CHUNK_LENGTH_B, CHAR_PROP_READ /*|CHAR_PROP_WRITE_WITHOUT_RESP*/,
        PERMISSION_U2F_READ, 0, 16, 1, &G_io_ble.u2f_controlpointlength_handle);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("controlpoint added\n");

    ret = aci_gatt_update_char_value(
        G_io_ble.service_handle, G_io_ble.u2f_controlpointlength_handle, 0,
        sizeof(u2f_controlPointLength_value), u2f_controlPointLength_value);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("controlpoint set\n");

    ret = aci_gatt_add_char(
        G_io_ble.service_handle, UUID_TYPE_16, u2f_serviceRevision,
        BLE_CHUNK_LENGTH_B, CHAR_PROP_READ /*|CHAR_PROP_WRITE_WITHOUT_RESP*/,
        PERMISSION_U2F_READ, 0, 16, 1, &G_io_ble.u2f_servicerevision_handle);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("serviceRevision added\n");

    ret = aci_gatt_update_char_value(
        G_io_ble.service_handle, G_io_ble.u2f_servicerevision_handle, 0,
        sizeof(u2f_serviceRevision_value), u2f_serviceRevision_value);
    if (ret != BLE_STATUS_SUCCESS)
        goto fail;

    PRINTF("serviceRevision set\n");

    // PRINTF("Sample Service added.\nTX Char Handle %04X, RX Char Handle
    // %04X\n", G_io_ble.tx_characteristic_handle,
    // G_io_ble.rx_characteristic_handle);
    return BLE_STATUS_SUCCESS;

fail:
    PRINTF("Error while adding U2F Service.\n");
    return BLE_STATUS_ERROR;
}

/**
 * @brief  This function is used to send data related to the sample service
 *         (to be sent over the air to the remote board).
 * @param  data_buffer : pointer to data to be sent
 * @param  Nb_bytes : number of bytes to send
 * @retval None
 */
// OTO handle = G_io_ble.tx_characteristic_handle for default apdu tranport
void BLE_send(unsigned short handle, uint8_t *data_buffer, uint8_t Nb_bytes) {
    unsigned char ret;
    unsigned int retries = 10;

    // consume pool by default, to avoid races
    G_io_ble.tx_pool_available = 0;

    for (;;) {
        ret = aci_gatt_update_char_value(G_io_ble.service_handle, handle, 0,
                                         Nb_bytes, data_buffer);
        // likely the link could be busy
        if (ret == BLE_STATUS_INSUFFICIENT_RESOURCES) {
            // wait for the tx pool ready event
            do {
                // ack the received event we have processed
                io_seproxyhal_general_status();

                io_seproxyhal_spi_recv(G_io_seproxyhal_spi_buffer,
                                       sizeof(G_io_seproxyhal_spi_buffer), 0);
                // process IOs, and BLE fetch, ble queue is updated through
                // common code
                io_seproxyhal_handle_event();
            } while (!G_io_ble.tx_pool_available);

            // TODO go low power, before retrying
            retries--;
            if (retries == 0) {
                PRINTF("BLE SEND ERROR\n");
                return;
            }
        } else if (ret == BLE_STATUS_SUCCESS) {
            return;
        }
    }
}

/**
 * @brief  This function is called when an attribute gets modified
 * @param  handle : handle of the attribute
 * @param  data_length : size of the modified attribute data
 * @param  att_data : pointer to the modified attribute data
 * @retval None
 */

#define IS_BLE_APDU_AVAILABLE()                                                \
    (G_io_apdu_length > 0 && G_io_ble.apdu_transport_remlen == 0)

#define BLE_OFFSET_TAG 0
#define BLE_OFFSET_SEQH 1
#define BLE_OFFSET_SEQL 2
#define BLE_SEQ0_OFFSET_LENH 3
#define BLE_SEQ0_OFFSET_LENL 4
#define BLE_SEQ0_OFFSET_DATA 5 // TAG, SEQ2, LEN2, DATA
#define BLE_SEQN_OFFSET_DATA 3 // TAG, SEQ2, DATA

// instruction supported
#define BLE_TAG_VERSION 0
#define BLE_TAG_INIT 1
#define BLE_TAG_ECHO 2
#define BLE_TAG_APDU 5
#ifdef BLE_PACKET_ACK
#define BLE_TAG_ACK                                                            \
    6  // ack each packet of transmitted by the server to avoid overwritting
       // properties before the client read it.
#endif // BLE_PACKET_ACK
#define BLE_TAG_FLASHBACK 7
#define BLE_TAG_ERROR 0xE

#define os_memmove memmove
#define os_memset memset

/**
 * Function called when a complete command apdu has been received and is ready
 * for processing
 */
void BLE_protocol_command_apdu_CB() {
    // avoid BLE timeout
    G_io_ble.connection_timeout_enabled = 0;
}

/**
 * Receive and concat Command APDU chunks
 * Calls
 */
void BLE_protocol_recv(unsigned char data_length, unsigned char *att_data) {
    // not processable, must be resent by the client (a chunk is being output
    // btw)
    if (G_io_ble.apdu_transport_lock) {
        // PRINTF("lock\n");
        return;
    }

    u2f_transport_handle(u2fServiceReference, att_data, data_length,
                         U2F_MEDIA_BLE);
    if (u2fServiceReference->transportState == U2F_HANDLE_SEGMENTED) {
        // PRINTF("segmented\n");
        // io_seproxyhal_general_status();
    } else {
        // PRINTF("handled\n");
    }
}

/**
 * Split and send the Response APDU chunks
 */
#define BLE_protocol_send_RET_OK 0
#define BLE_protocol_send_RET_BUSY 1
#define BLE_protocol_send_RET_ABORTED 2
#define BLE_protocol_send_RET_INVALID 3
// TODO ensure not being stuck in case disconnect or timeout during reply.
// add a timeout for reply operation
char BLE_protocol_send(unsigned char *data, unsigned short length) {
    if (length > BLE_CHUNK_LENGTH_B) {
        PRINTF("too long\n");
        return BLE_protocol_send_RET_INVALID;
    }

    // error if already sending (inception)
    if (G_io_ble.apdu_transport_busy_sending) {
        PRINTF("busy\n");
        return BLE_protocol_send_RET_BUSY;
    }

    G_io_ble.apdu_transport_busy_sending = 1;

    G_io_ble.apdu_transport_lock = 1;
    // TAG_INIT called under isr
    if (!G_io_ble.apdu_transport_busy_sending) {
        G_io_ble.apdu_transport_lock = 0;
        // aborted by previous interrupt
        PRINTF("aborted\n");
        return BLE_protocol_send_RET_ABORTED;
    }

    BLE_send(G_io_ble.tx_characteristic_handle, data, length);
    // release the seal (f)
    G_io_ble.apdu_transport_lock = 0;

    G_io_ble.apdu_transport_busy_sending = 0;

    return BLE_protocol_send_RET_OK;
}


void BLE_reset_connection(void) {
    THROW(EXCEPTION_DISCONNECT);
    /*
      G_io_ble.client_link_established = FALSE;
      G_io_ble.connection_timeout_enabled = 0;

      // TODO remove me
      //BEGIN
      BLE_power(0, NULL);

        // seems ok since ENABLE_SPI_FIX and pendsv
      G_io_ble.client_link_established = FALSE;
      G_io_ble.connection_timeout_enabled = 0;
      BLE_make_discoverable(G_io_ble.last_discovered_name);
    */
}

/**
 * @brief  This function is called when there is a LE Connection Complete event.
 * @param  addr : Address of peer device
 * @param  handle : Connection handle
 * @retval None
 */
void GAP_ConnectionComplete_CB(uint8_t addr[6], uint16_t handle) {
    UNUSED(addr);
    UNUSED(handle);
    PRINTF("BLE client connected\n");

    /*
    PRINTF("client connected\n");
    screen_update();
    */

    G_io_ble.client_link_established = FALSE;
    /*
    // wait until notification registration is performed
    G_io_ble.connection_timeout_ms = BLE_TIMEOUT_CONNECTION_MS;
    G_io_ble.connection_timeout_enabled = 1;
    */
}

/**
 * @brief  This function is called when the peer device get disconnected.
 * @param  None
 * @retval None
 */
void GAP_DisconnectionComplete_CB(void) {
    PRINTF("BLE client disconnected\n");

    THROW(EXCEPTION_DISCONNECT);

    G_io_ble.client_link_established = FALSE;
}

/**
 * @brief  This function is called whenever there is an ACI event to be
 * processed.
 * @note   Inside this function each event must be identified and correctly
 *         parsed.
 * @param  pckt  Pointer to the ACI packet
 * @retval None
 */
void HCI_Event_CB(void *pckt) {
    hci_uart_pckt *hci_pckt = pckt;
    hci_event_pckt *event_pckt = (hci_event_pckt *)hci_pckt->data;

    if (hci_pckt->type != HCI_EVENT_PKT) {
        return;
    }

    switch (event_pckt->evt) {
    case EVT_DISCONN_COMPLETE: {
        GAP_DisconnectionComplete_CB();
        PRINTF("disconnection complete\n");
    } break;

    case EVT_LE_META_EVENT: {
        evt_le_meta_event *evt = (void *)event_pckt->data;

        switch (evt->subevent) {
        case EVT_LE_CONN_COMPLETE: {
            evt_le_connection_complete *cc = (void *)evt->data;
            GAP_ConnectionComplete_CB(cc->peer_bdaddr, cc->handle);
            PRINTF("connection complete\n");
        } break;
        }
    } break;

    case EVT_VENDOR: {
        evt_blue_aci *blue_evt = (void *)event_pckt->data;
        switch (blue_evt->ecode) {
        case EVT_BLUE_GATT_ATTRIBUTE_MODIFIED: {
            evt_gatt_attr_modified *evt =
                (evt_gatt_attr_modified *)blue_evt->data;
            if (evt->attr_handle == G_io_ble.tx_characteristic_handle + 2) {
                // tx char handle attribute is triggered, the client registered
                // to notification reception
                if (evt->att_data[0] == 0x01 && evt->att_data[1] == 0) {
                    G_io_ble.client_link_established = TRUE;
                    PRINTF("notifications enabled\n");
                } else if (evt->att_data[0] == 0x01 && evt->att_data[1] == 0) {
                    G_io_ble.client_link_established = FALSE;
                    PRINTF("notifications disabled\n");
                }
            }
        } break;

        case EVT_BLUE_GATT_WRITE_PERMIT_REQ: {
            evt_gatt_write_permit_req *evt =
                (evt_gatt_write_permit_req *)blue_evt->data;

            if (evt->attr_handle == G_io_ble.rx_characteristic_handle + 1) {
                // accept the write request
                // Accept it before processing its data to avoid deadlock in spi
                // access within attribute modified
                aci_gatt_write_response(evt->conn_handle, evt->attr_handle,
                                        0,                // accept the write
                                        0,                // no error
                                        evt->data_length, // TODO must check
                                                          // it's the size of
                                                          // the chunk
                                        evt->data);

                // check if client completely connected
                if (G_io_ble.client_link_established) {
                    // decapsulate BLE framing to reconstruct the command.
                    // command set :
                    //  - reset
                    //  - DFU
                    //  - apdu transport (to deliver the SE, whom will
                    //  afterwards drive the screen and request a pin code
                    BLE_protocol_recv(evt->data_length, evt->data);
                }
            }
        } break;

        case EVT_BLUE_GATT_TX_POOL_AVAILABLE:
            G_io_ble.tx_pool_available = 1;
            break;
        }
    } break;
    }
}

#endif // HAVE_BLE
