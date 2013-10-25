/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#define BLUEZ_HAL_MTU 1024

static const char BLUEZ_HAL_SK_PATH[] = "\0bluez_hal_socket";

struct hal_hdr {
	uint8_t service_id;
	uint8_t opcode;
	uint16_t len;
	uint8_t payload[0];
} __attribute__((packed));

#define HAL_MINIMUM_EVENT		0x81

#define HAL_SERVICE_ID_CORE		0
#define HAL_SERVICE_ID_BLUETOOTH	1
#define HAL_SERVICE_ID_SOCK		2
#define HAL_SERVICE_ID_HIDHOST		3
#define HAL_SERVICE_ID_PAN		4
#define HAL_SERVICE_ID_HANDSFREE	5
#define HAL_SERVICE_ID_AD2P		6
#define HAL_SERVICE_ID_HEALTH		7
#define HAL_SERVICE_ID_AVRCP		8
#define HAL_SERVICE_ID_GATT		9

#define HAL_SERVICE_ID_MAX HAL_SERVICE_ID_GATT

/* Core Service */

#define HAL_ERROR_FAILED		0x01
#define HAL_ERROR_NOT_READY		0x02
#define HAL_ERROR_NOMEM			0x03
#define HAL_ERROR_BUSY			0x04
#define HAL_ERROR_DONE			0x05
#define HAL_ERROR_UNSUPPORTED		0x06
#define HAL_ERROR_INVALID		0x07
#define HAL_ERROR_UNHANDLED		0x08
#define HAL_ERROR_AUTH_FAILURE		0x09
#define HAL_ERROR_REMOTE_DEVICE_DOWN	0x0a

#define HAL_OP_ERROR			0x00
struct hal_error {
	uint8_t status;
} __attribute__((packed));

#define HAL_OP_REGISTER_MODULE		0x01
struct hal_cmd_register_module {
	uint8_t service_id;
} __attribute__((packed));
struct hal_rsp_register_module {
	uint8_t service_id;
} __attribute__((packed));

#define HAL_OP_UNREGISTER_MODULE	0x02
struct hal_cmd_unregister_module {
	uint8_t service_id;
} __attribute__((packed));

/* Bluetooth Core HAL API */

#define HAL_OP_ENABLE			0x01

#define HAL_OP_DISABLE			0x02

#define HAL_OP_GET_ADAPTER_PROPS	0x03

#define HAL_OP_GET_ADAPTER_PROP		0x04
struct hal_cmd_get_adapter_prop {
	uint8_t type;
} __attribute__((packed));

#define HAL_PROP_ADAPTER_NAME			0x01
#define HAL_PROP_ADAPTER_ADDR			0x02
#define HAL_PROP_ADAPTER_UUIDS			0x03
#define HAL_PROP_ADAPTER_CLASS			0x04
#define HAL_PROP_ADAPTER_TYPE			0x05
#define HAL_PROP_ADAPTER_SERVICE_REC		0x06
#define HAL_PROP_ADAPTER_SCAN_MODE		0x07
#define HAL_PROP_ADAPTER_BONDED_DEVICES		0x08
#define HAL_PROP_ADAPTER_DISC_TIMEOUT		0x09

#define HAL_PROP_DEVICE_NAME			0x01
#define HAL_PROP_DEVICE_ADDR			0x02
#define HAL_PROP_DEVICE_UUIDS			0x03
#define HAL_PROP_DEVICE_CLASS			0x04
#define HAL_PROP_DEVICE_TYPE			0x05
#define HAL_PROP_DEVICE_SERVICE_REC		0x06
#define HAL_PROP_DEVICE_FRIENDLY_NAME		0x0a
#define HAL_PROP_DEVICE_RSSI			0x0b
#define HAL_PROP_DEVICE_VERSION_INFO		0x0c
#define HAL_PROP_DEVICE_TIMESTAMP		0xFF

#define HAL_OP_SET_ADAPTER_PROP		0x05
struct hal_cmd_set_adapter_prop {
	uint8_t  type;
	uint16_t len;
	uint8_t  val[0];
} __attribute__((packed));

#define HAL_OP_GET_REMOTE_DEVICE_PROPS	0x06
struct hal_cmd_get_remote_device_props {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_GET_REMOTE_DEVICE_PROP	0x07
struct hal_cmd_get_remote_device_prop {
	uint8_t bdaddr[6];
	uint8_t type;
} __attribute__((packed));

#define HAL_OP_SET_REMOTE_DEVICE_PROP	0x08
struct hal_cmd_set_remote_device_prop {
	uint8_t  bdaddr[6];
	uint8_t  type;
	uint16_t len;
	uint8_t  val[0];
} __attribute__((packed));

#define HAL_OP_GET_REMOTE_SERVICE_REC	0x09
struct hal_cmd_get_remote_service_rec {
	uint8_t bdaddr[6];
	uint8_t uuid[16];
} __attribute__((packed));

#define HAL_OP_GET_REMOTE_SERVICE	0x0a
struct hal_cmd_get_remote_service {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_START_DISCOVERY		0x0b

#define HAL_OP_CANCEL_DISCOVERY		0x0c

#define HAL_OP_CREATE_BOND		0x0d
struct hal_cmd_create_bond {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_REMOVE_BOND		0x0d
struct hal_cmd_remove_bond {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_CANCEL_BOND		0x0f
struct hal_cmd_cancel_bond {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_PIN_REPLY		0x10
struct hal_cmd_pin_reply {
	uint8_t bdaddr[6];
	uint8_t accept;
	uint8_t pin_len;
	uint8_t pin_code[16];
} __attribute__((packed));

#define HAL_SSP_VARIANT_CONFIRM		0x00
#define HAL_SSP_VARIANT_ENTRY		0x01
#define HAL_SSP_VARIANT_CONSENT		0x02
#define HAL_SSP_VARIANT_NOTIF		0x03

#define HAL_OP_SSP_REPLY		0x11
struct hal_cmd_ssp_reply {
	uint8_t  bdaddr[6];
	uint8_t  ssp_variant;
	uint8_t  accept;
	uint32_t passkey;
} __attribute__((packed));

#define HAL_OP_DUT_MODE_CONF		0x12
struct hal_cmd_dut_mode_conf {
	uint8_t enable;
} __attribute__((packed));

#define HAL_OP_DUT_MODE_SEND		0x13
struct hal_cmd_dut_mode_send {
	uint16_t opcode;
	uint8_t  len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_OP_LE_TEST_MODE		0x14
struct hal_cmd_le_test_mode {
	uint16_t opcode;
	uint8_t  len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_OP_HID_CONNECT		0x01
struct hal_cmd_hid_connect {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HID_DISCONNECT		0x02
struct hal_cmd_hid_disconnect {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HID_VP			0x03
struct hal_cmd_hid_vp {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HID_SET_INFO		0x04
struct hal_cmd_hid_set_info {
	uint8_t bdaddr[6];
	uint8_t attr;
	uint8_t subclass;
	uint8_t app_id;
	uint16_t vendor;
	uint16_t product;
	uint16_t country;
	uint16_t descr_len;
	uint8_t descr[0];
} __attribute__((packed));

#define HAL_HID_REPORT_PROTOCOL		0x00
#define HAL_HID_BOOT_PROTOCOL		0x01
#define HAL_HID_UNSUPPORTED_PROTOCOL	0xff

#define HAL_OP_HID_GET_PROTOCOL	0x05
struct hal_cmd_hid_get_protocol {
	uint8_t bdaddr[6];
	uint8_t mode;
} __attribute__((packed));

#define HAL_OP_HID_SET_PROTOCOL	0x06
struct hal_cmd_hid_set_protocol {
	uint8_t bdaddr[6];
	uint8_t mode;
} __attribute__((packed));

#define HAL_HID_INPUT_REPORT		0x01
#define HAL_HID_OUTPUT_REPORT		0x02
#define HAL_HID_FEATURE_REPORT		0x03

#define HAL_OP_HID_GET_REPORT		0x07
struct hal_cmd_hid_get_report {
	uint8_t bdaddr[6];
	uint8_t type;
	uint8_t id;
	uint16_t buf;
} __attribute__((packed));

#define HAL_OP_HID_SET_REPORT		0x08
struct hal_cmd_hid_set_report {
	uint8_t bdaddr[6];
	uint8_t type;
} __attribute__((packed));

#define HAL_OP_HID_SEND_DATA		0x09
struct hal_cmd_hid_send_data {
	uint8_t bdaddr[6];
} __attribute__((packed));

/* Notifications and confirmations */


#define HAL_POWER_OFF			0x00
#define HAL_POWER_ON			0x01

#define HAL_EV_ADAPTER_STATE_CHANGED	0x81
struct hal_ev_adapter_state_changed {
	uint8_t state;
} __attribute__((packed));

#define HAL_EV_ADAPTER_PROPS_CHANGED	0x82
struct hal_property {
	uint8_t  type;
	uint16_t len;
	uint8_t  val[0];
} __attribute__((packed));
struct hal_ev_adapter_props_changed {
	uint8_t              status;
	uint8_t              num_props;
	struct  hal_property props[0];
} __attribute__((packed));

#define HAL_EV_REMOTE_DEVICE_PROPS	0x83
struct hal_ev_remote_device_props {
	uint8_t             status;
	uint8_t             bdaddr[6];
	uint8_t             num_props;
	struct hal_property props[0];
} __attribute__((packed));

#define HAL_EV_DEVICE_FOUND		0x84
struct hal_ev_device_found {
	uint8_t             num_props;
	struct hal_property props[0];
} __attribute__((packed));

#define HAL_EV_DISCOVERY_STATE_CHANGED	0x85
struct hal_ev_discovery_state_changed {
	uint8_t state;
} __attribute__((packed));

#define HAL_EV_PIN_REQUEST		0x86
struct hal_ev_pin_request {
	uint8_t bdaddr[6];
	uint8_t name[249 - 1];
	uint8_t class_of_dev[3];
} __attribute__((packed));

#define HAL_EV_SSP_REQUEST		0x87
struct hal_ev_ssp_request {
	uint8_t  bdaddr[6];
	uint8_t  name[249 - 1];
	uint8_t  class_of_dev[3];
	uint8_t  pairing_variant;
	uint32_t passkey;
} __attribute__((packed));

#define HAL_EV_BOND_STATE_CHANGED	0x88
struct hal_ev_bond_state_changed {
	uint8_t status;
	uint8_t bdaddr[6];
	uint8_t state;
} __attribute__((packed));

#define HAL_EV_ACL_STATE_CHANGED	0x89
struct hal_ev_acl_state_changed {
	uint8_t status;
	uint8_t bdaddr[6];
	uint8_t state;
} __attribute__((packed));

#define HAL_EV_DUT_MODE_RECEIVE		0x8a
struct hal_ev_dut_mode_receive {
	uint16_t opcode;
	uint8_t  len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_EV_LE_TEST_MODE		0x8b
struct hal_ev_le_test_mode {
	uint8_t  status;
	uint16_t num_packets;
} __attribute__((packed));
