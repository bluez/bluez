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
	uint8_t  service_id;
	uint8_t  opcode;
	uint16_t len;
	uint8_t  payload[0];
} __attribute__((packed));

#define HAL_MINIMUM_EVENT		0x81

#define HAL_SERVICE_ID_CORE		0
#define HAL_SERVICE_ID_BLUETOOTH	1
#define HAL_SERVICE_ID_SOCK		2
#define HAL_SERVICE_ID_HIDHOST		3
#define HAL_SERVICE_ID_PAN		4
#define HAL_SERVICE_ID_HANDSFREE	5
#define HAL_SERVICE_ID_A2DP		6
#define HAL_SERVICE_ID_HEALTH		7
#define HAL_SERVICE_ID_AVRCP		8
#define HAL_SERVICE_ID_GATT		9

#define HAL_SERVICE_ID_MAX HAL_SERVICE_ID_GATT

/* Core Service */

#define HAL_STATUS_SUCCESS		0x00
#define HAL_STATUS_FAILED		0x01
#define HAL_STATUS_NOT_READY		0x02
#define HAL_STATUS_NOMEM		0x03
#define HAL_STATUS_BUSY			0x04
#define HAL_STATUS_DONE			0x05
#define HAL_STATUS_UNSUPPORTED		0x06
#define HAL_STATUS_INVALID		0x07
#define HAL_STATUS_UNHANDLED		0x08
#define HAL_STATUS_AUTH_FAILURE		0x09
#define HAL_STATUS_REMOTE_DEVICE_DOWN	0x0a

#define HAL_OP_STATUS			0x00
struct hal_status {
	uint8_t code;
} __attribute__((packed));

#define HAL_OP_REGISTER_MODULE		0x01
struct hal_cmd_register_module {
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

#define HAL_MAX_NAME_LENGTH		249

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

#define HAL_ADAPTER_SCAN_MODE_NONE		0x00
#define HAL_ADAPTER_SCAN_MODE_CONN		0x01
#define HAL_ADAPTER_SCAN_MODE_CONN_DISC	0x02

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

#define HAL_OP_GET_REMOTE_SERVICES	0x0a
struct hal_cmd_get_remote_services {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_START_DISCOVERY		0x0b

#define HAL_OP_CANCEL_DISCOVERY		0x0c

#define HAL_OP_CREATE_BOND		0x0d
struct hal_cmd_create_bond {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_REMOVE_BOND		0x0e
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

/* Bluetooth Socket HAL api */

#define HAL_OP_SOCK_LISTEN		0x01
struct hal_cmd_sock_listen {
	uint8_t  type;
	uint8_t  name[256];
	uint8_t  uuid[16];
	uint16_t channel;
	uint8_t  flags;
} __attribute__((packed));

#define HAL_OP_SOCK_CONNECT		0x02
struct hal_cmd_sock_connect {
	uint8_t  bdaddr[6];
	uint8_t  type;
	uint8_t  uuid[16];
	uint16_t channel;
	uint8_t  flags;
} __attribute__((packed));

#define HAL_OP_HIDHOST_CONNECT		0x01
struct hal_cmd_hidhost_connect {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HIDHOST_DISCONNECT		0x02
struct hal_cmd_hidhost_disconnect {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HIDHOST_VIRTUAL_UNPLUG		0x03
struct hal_cmd_hidhost_virtual_unplug {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HIDHOST_SET_INFO		0x04
struct hal_cmd_hidhost_set_info {
	uint8_t  bdaddr[6];
	uint8_t  attr;
	uint8_t  subclass;
	uint8_t  app_id;
	uint16_t vendor;
	uint16_t product;
	uint16_t country;
	uint16_t descr_len;
	uint8_t  descr[0];
} __attribute__((packed));

#define HAL_HIDHOST_REPORT_PROTOCOL		0x00
#define HAL_HIDHOST_BOOT_PROTOCOL		0x01
#define HAL_HIDHOST_UNSUPPORTED_PROTOCOL	0xff

#define HAL_OP_HIDHOST_GET_PROTOCOL	0x05
struct hal_cmd_hidhost_get_protocol {
	uint8_t bdaddr[6];
	uint8_t mode;
} __attribute__((packed));

#define HAL_OP_HIDHOST_SET_PROTOCOL	0x06
struct hal_cmd_hidhost_set_protocol {
	uint8_t bdaddr[6];
	uint8_t mode;
} __attribute__((packed));

#define HAL_HIDHOST_INPUT_REPORT		0x01
#define HAL_HIDHOST_OUTPUT_REPORT		0x02
#define HAL_HIDHOST_FEATURE_REPORT		0x03

#define HAL_OP_HIDHOST_GET_REPORT		0x07
struct hal_cmd_hidhost_get_report {
	uint8_t  bdaddr[6];
	uint8_t  type;
	uint8_t  id;
	uint16_t buf_size;
} __attribute__((packed));

#define HAL_OP_HIDHOST_SET_REPORT		0x08
struct hal_cmd_hidhost_set_report {
	uint8_t  bdaddr[6];
	uint8_t  type;
	uint16_t len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_OP_HIDHOST_SEND_DATA		0x09
struct hal_cmd_hidhost_send_data {
	uint8_t  bdaddr[6];
	uint16_t len;
	uint8_t  data[0];
} __attribute__((packed));

/* a2dp HAL API */

#define HAL_OP_A2DP_CONNECT	0x01
struct hal_cmd_a2dp_connect {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_A2DP_DISCONNECT	0x02
struct hal_cmd_a2dp_disconnect {
	uint8_t bdaddr[6];
} __attribute__((packed));

/* PAN HAL API */

/* PAN Roles */
#define HAL_PAN_ROLE_NONE	0x00
#define HAL_PAN_ROLE_NAP	0x01
#define HAL_PAN_ROLE_PANU	0x02

/* PAN Control states */
#define HAL_PAN_CTRL_ENABLED	0x00
#define HAL_PAN_CTRL_DISABLED	0x01

/* PAN Connection states */
#define HAL_PAN_STATE_CONNECTED		0x00
#define HAL_PAN_STATE_CONNECTING	0x01
#define HAL_PAN_STATE_DISCONNECTED	0x02
#define HAL_PAN_STATE_DISCONNECTING	0x03

/* PAN status values */
#define HAL_PAN_STATUS_FAIL		0x01
#define HAL_PAN_STATUS_NOT_READY	0x02
#define HAL_PAN_STATUS_NO_MEMORY	0x03
#define HAL_PAN_STATUS_BUSY		0x04
#define HAL_PAN_STATUS_DONE		0x05
#define HAL_PAN_STATUS_UNSUPORTED	0x06
#define HAL_PAN_STATUS_INVAL		0x07
#define HAL_PAN_STATUS_UNHANDLED	0x08
#define HAL_PAN_STATUS_AUTH_FAILED	0x09
#define HAL_PAN_STATUS_DEVICE_DOWN	0x0A

#define HAL_OP_PAN_ENABLE	0x01
struct hal_cmd_pan_enable {
	uint8_t local_role;
} __attribute__((packed));

#define HAL_OP_PAN_GET_ROLE	0x02
struct hal_rsp_pan_get_role {
	uint8_t local_role;
} __attribute__((packed));

#define HAL_OP_PAN_CONNECT	0x03
struct hal_cmd_pan_connect {
	uint8_t bdaddr[6];
	uint8_t local_role;
	uint8_t remote_role;
} __attribute__((packed));

#define HAL_OP_PAN_DISCONNECT	0x04
struct hal_cmd_pan_disconnect {
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

#define HAL_DISCOVERY_STATE_STOPPED	0x00
#define HAL_DISCOVERY_STATE_STARTED	0x01

#define HAL_EV_DISCOVERY_STATE_CHANGED	0x85
struct hal_ev_discovery_state_changed {
	uint8_t state;
} __attribute__((packed));

#define HAL_EV_PIN_REQUEST		0x86
struct hal_ev_pin_request {
	uint8_t  bdaddr[6];
	uint8_t  name[249];
	uint32_t class_of_dev;
} __attribute__((packed));

#define HAL_EV_SSP_REQUEST		0x87
struct hal_ev_ssp_request {
	uint8_t  bdaddr[6];
	uint8_t  name[249];
	uint32_t class_of_dev;
	uint8_t  pairing_variant;
	uint32_t passkey;
} __attribute__((packed));

#define HAL_BOND_STATE_NONE 0
#define HAL_BOND_STATE_BONDING 1
#define HAL_BOND_STATE_BONDED 2

#define HAL_EV_BOND_STATE_CHANGED	0x88
struct hal_ev_bond_state_changed {
	uint8_t status;
	uint8_t bdaddr[6];
	uint8_t state;
} __attribute__((packed));

#define HAL_ACL_STATE_CONNECTED		0x00
#define HAL_ACL_STATE_DISCONNECTED	0x01

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

#define HAL_HIDHOST_STATE_CONNECTED		0x00
#define HAL_HIDHOST_STATE_CONNECTING	0x01
#define HAL_HIDHOST_STATE_DISCONNECTED	0x02
#define HAL_HIDHOST_STATE_DISCONNECTING	0x03
#define HAL_HIDHOST_STATE_NO_HID		0x07
#define HAL_HIDHOST_STATE_FAILED		0x08
#define HAL_HIDHOST_STATE_UNKNOWN		0x09

#define HAL_EV_HIDHOST_CONN_STATE		0x81
struct hal_ev_hidhost_conn_state {
	uint8_t bdaddr[6];
	uint8_t state;
} __attribute__((packed));

#define HAL_HIDHOST_STATUS_OK		0x00
#define HAL_HIDHOST_GENERAL_ERROR	0x06

#define HAL_EV_HIDHOST_INFO			0x82
struct hal_ev_hidhost_info {
	uint8_t  bdaddr[6];
	uint8_t  attr;
	uint8_t  subclass;
	uint8_t  app_id;
	uint16_t vendor;
	uint16_t product;
	uint16_t version;
	uint8_t  country;
	uint16_t descr_len;
	uint8_t  descr[884];
} __attribute__((packed));

#define HAL_EV_HIDHOST_PROTO_MODE		0x83
struct hal_ev_hidhost_proto_mode {
	uint8_t bdaddr[6];
	uint8_t status;
	uint8_t mode;
} __attribute__((packed));

#define HAL_EV_HIDHOST_GET_REPORT		0x84
struct hal_ev_hidhost_get_report {
	uint8_t  bdaddr[6];
	uint8_t  status;
	uint16_t len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_EV_HIDHOST_VIRTUAL_UNPLUG		0x85
struct hal_ev_hidhost_virtual_unplug {
	uint8_t  bdaddr[6];
	uint8_t  status;
} __attribute__((packed));

#define HAL_EV_PAN_CTRL_STATE			0x81
struct hal_ev_pan_ctrl_state {
	uint8_t  state;
	uint8_t  status;
	uint8_t  local_role;
	uint8_t  name[17];
} __attribute__((packed));

#define HAL_EV_PAN_CONN_STATE			0x82
struct hal_ev_pan_conn_state {
	uint8_t  state;
	uint8_t  status;
	uint8_t  bdaddr[6];
	uint8_t  local_role;
	uint8_t  remote_role;
} __attribute__((packed));

#define HAL_A2DP_STATE_DISCONNECTED		0x00
#define HAL_A2DP_STATE_CONNECTING		0x01
#define HAL_A2DP_STATE_CONNECTED		0x02
#define HAL_A2DP_STATE_DISCONNECTING		0x03

#define HAL_EV_A2DP_CONN_STATE			0x81
struct hal_ev_a2dp_conn_state {
	uint8_t state;
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_EV_A2DP_AUDIO_STATE			0x82
struct hal_ev_a2dp_audio_state {
	uint8_t state;
	uint8_t bdaddr[6];
} __attribute__((packed));
