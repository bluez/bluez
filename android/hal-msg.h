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
struct hal_prop_device_service_rec {
	uint8_t uuid[16];
	uint16_t channel;
	uint8_t name_len;
	uint8_t name[];
} __attribute__((packed));

#define HAL_PROP_DEVICE_FRIENDLY_NAME		0x0a
#define HAL_PROP_DEVICE_RSSI			0x0b
#define HAL_PROP_DEVICE_VERSION_INFO		0x0c
struct hal_prop_device_info {
	uint8_t version;
	uint16_t sub_version;
	uint16_t manufacturer;
} __attribute__((packed));

#define HAL_PROP_DEVICE_TIMESTAMP		0xFF

#define HAL_ADAPTER_SCAN_MODE_NONE		0x00
#define HAL_ADAPTER_SCAN_MODE_CONN		0x01
#define HAL_ADAPTER_SCAN_MODE_CONN_DISC	0x02

#define HAL_TYPE_BREDR				0x01
#define HAL_TYPE_LE				0x02
#define HAL_TYPE_DUAL				0x03

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

#define HAL_SOCK_RFCOMM		0x01
#define HAL_SOCK_SCO		0x02
#define HAL_SOCK_L2CAP		0x03

#define HAL_SOCK_FLAG_ENCRYPT	0x01
#define HAL_SOCK_FLAG_AUTH	0x02

#define HAL_OP_SOCKET_LISTEN		0x01
struct hal_cmd_socket_listen {
	uint8_t type;
	uint8_t name[256];
	uint8_t uuid[16];
	int32_t channel;
	uint8_t flags;
} __attribute__((packed));

#define HAL_OP_SOCKET_CONNECT		0x02
struct hal_cmd_socket_connect {
	uint8_t bdaddr[6];
	uint8_t type;
	uint8_t uuid[16];
	int32_t channel;
	uint8_t flags;
} __attribute__((packed));

/* Bluetooth HID Host HAL API */

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

/* Handsfree HAL API */

#define HAL_OP_HANDSFREE_CONNECT		0x01
struct hal_cmd_handsfree_connect {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HANDSFREE_DISCONNECT		0x02
struct hal_cmd_handsfree_disconnect {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HANDSFREE_CONNECT_AUDIO		0x03
struct hal_cmd_handsfree_connect_audio {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HANDSFREE_DISCONNECT_AUDIO	0x04
struct hal_cmd_handsfree_disconnect_audio {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_OP_HANDSFREE_START_VR		0x05

#define HAL_OP_HANDSFREE_STOP_VR		0x06

#define HAL_HANDSFREE_VOLUME_TYPE_SPEAKER	0x00
#define HAL_HANDSFREE_VOLUME_TYPE_MIC		0x01

#define HAL_OP_HANDSFREE_VOLUME_CONTROL		0x07
struct hal_cmd_handsfree_volume_control {
	uint8_t type;
	uint8_t volume;
} __attribute__((packed));

#define HAL_HANDSFREE_NETWORK_STATE_NOT_AVAILABLE	0x00
#define HAL_HANDSFREE_NETWORK_STATE_AVAILABLE		0x01

#define HAL_HANDSFREE_SERVICE_TYPE_HOME		0x00
#define HAL_HANDSFREE_SERVICE_TYPE_ROAMING	0x01

#define HAL_OP_HANDSFREE_DEVICE_STATUS_NOTIF	0x08
struct hal_cmd_handsfree_device_status_notif {
	uint8_t state;
	uint8_t type;
	uint8_t signal;
	uint8_t battery;
} __attribute__((packed));

#define HAL_OP_HANDSFREE_COPS_RESPONSE		0x09
struct hal_cmd_handsfree_cops_response {
	uint16_t len;
	uint8_t buf[0];
} __attribute__((packed));

#define HAL_HANDSFREE_CALL_STATE_ACTIVE		0x00
#define HAL_HANDSFREE_CALL_STATE_HELD		0x01
#define HAL_HANDSFREE_CALL_STATE_DIALING	0x02
#define HAL_HANDSFREE_CALL_STATE_ALERTING	0x03
#define HAL_HANDSFREE_CALL_STATE_INCOMING	0x04
#define HAL_HANDSFREE_CALL_STATE_WAITING	0x05
#define HAL_HANDSFREE_CALL_STATE_IDLE		0x06

#define HAL_OP_HANDSFREE_CIND_RESPONSE		0x0A
struct hal_cmd_handsfree_cind_response {
	uint8_t svc;
	uint8_t num_active;
	uint8_t num_held;
	uint8_t state;
	uint8_t signal;
	uint8_t roam;
	uint8_t batt_chg;
} __attribute__((packed));

#define HAL_OP_HANDSFREE_FORMATTED_AT_RESPONSE	0x0B
struct hal_cmd_handsfree_formatted_at_response {
	uint16_t len;
	uint8_t buf[0];
} __attribute__((packed));

#define HAL_HANDSFREE_AT_RESPONSE_ERROR		0x00
#define HAL_HANDSFREE_AT_RESPONSE_OK		0x01

#define HAL_OP_HANDSFREE_AT_RESPONSE		0x0C
struct hal_cmd_handsfree_at_response {
	uint8_t response;
	uint8_t error;
} __attribute__((packed));

#define HAL_HANDSFREE_CALL_DIRECTION_OUTGOING	0x00
#define HAL_HANDSFREE_CALL_DIRECTION_INCOMING	0x01

#define HAL_HANDSFREE_CALL_TYPE_VOICE		0x00
#define HAL_HANDSFREE_CALL_TYPE_DATA		0x01
#define HAL_HANDSFREE_CALL_TYPE_FAX		0x02

#define HAL_HANDSFREE_CALL_MPTY_TYPE_SINGLE	0x00
#define HAL_HANDSFREE_CALL_MPTY_TYPE_MULTI	0x01

#define HAL_HANDSFREE_CALL_ADDRTYPE_UNKNOWN	0x81
#define HAL_HANDSFREE_CALL_ADDRTYPE_INTERNATIONAL	0x91

#define HAL_OP_HANDSFREE_CLCC_RESPONSE		0x0D
struct hal_cmd_handsfree_clcc_response {
	uint8_t index;
	uint8_t dir;
	uint8_t state;
	uint8_t mode;
	uint8_t mpty;
	uint8_t type;
	uint16_t number_len;
	uint8_t number[0];
} __attribute__((packed));

#define HAL_OP_HANDSFREE_PHONE_STATE_CHANGE	0x0E
struct hal_cmd_handsfree_phone_state_change {
	uint8_t num_active;
	uint8_t num_held;
	uint8_t state;
	uint8_t type;
	uint16_t number_len;
	uint8_t number[0];
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

#define HAL_EV_HIDHOST_IDLE_TIME		0x84
struct hal_ev_hidhost_idle_time {
	uint8_t bdaddr[6];
	uint8_t status;
	uint32_t idle_rate;
} __attribute__((packed));

#define HAL_EV_HIDHOST_GET_REPORT		0x85
struct hal_ev_hidhost_get_report {
	uint8_t  bdaddr[6];
	uint8_t  status;
	uint16_t len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_EV_HIDHOST_VIRTUAL_UNPLUG		0x86
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

#define HAL_AUDIO_SUSPEND			0x00
#define HAL_AUDIO_STOPPED			0x01
#define HAL_AUDIO_STARTED			0x02

#define HAL_EV_A2DP_AUDIO_STATE			0x82
struct hal_ev_a2dp_audio_state {
	uint8_t state;
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_EV_HANDSFREE_CONNECTION_STATE_DISCONNECTED	0x00
#define HAL_EV_HANDSFREE_CONNECTION_STATE_CONNECTING	0x01
#define HAL_EV_HANDSFREE_CONNECTION_STATE_CONNECTED	0x02
#define HAL_EV_HANDSFREE_CONNECTION_STATE_SLC_CONNECTED	0x03
#define HAL_EV_HANDSFREE_CONNECTION_STATE_DISCONNECTING	0x04

#define HAL_EV_HANDSFREE_CONN_STATE		0x81
struct hal_ev_handsfree_conn_state {
	uint8_t state;
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_EV_HANDSFREE_AUDIO_STATE_DISCONNECTED	0x00
#define HAL_EV_HANDSFREE_AUDIO_STATE_CONNECTING		0x01
#define HAL_EV_HANDSFREE_AUDIO_STATE_CONNECTED		0x02
#define HAL_EV_HANDSFREE_AUDIO_STATE_DISCONNECTING	0x03

#define HAL_EV_HANDSFREE_AUDIO_STATE		0x82
struct hal_ev_handsfree_audio_state {
	uint8_t state;
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_EV_HANDSFREE_VR		0x83
struct hal_ev_handsfree_vr_state {
	uint8_t state;
} __attribute__((packed));

#define HAL_EV_HANDSFREE_ANSWER		0x84

#define HAL_EV_HANDSFREE_HANGUP		0x85

#define HAL_EV_HANDSFREE_VOLUME		0x86
struct hal_ev_handsfree_volume {
	uint8_t type;
	uint8_t volume;
} __attribute__((packed));

#define HAL_EV_HANDSFREE_DIAL		0x87
struct hal_ev_handsfree_dial {
	uint16_t number_len;
	uint8_t number[0];
} __attribute__((packed));

#define HAL_EV_HANDSFREE_DTMF		0x88
struct hal_ev_handsfree_dtmf {
	uint8_t tone;
} __attribute__((packed));

#define HAL_HANDSFREE_NREC_STOP		0x00
#define HAL_HANDSFREE_NREC_STart	0x01

#define HAL_EV_HANDSFREE_NREC		0x89
struct hal_ev_handsfree_nrec {
	uint8_t nrec;
} __attribute__((packed));

#define HAL_HANDSFREE_CHLD_TYPE_RELEASEHELD			0x00
#define HAL_HANDSFREE_CHLD_TYPE_RELEASEACTIVE_ACCEPTHELD	0x01
#define HAL_HANDSFREE_CHLD_TYPE_HOLDACTIVE_ACCEPTHELD		0x02
#define HAL_HANDSFREE_CHLD_TYPE_ADDHELDTOCONF			0x03

#define HAL_EV_HANDSFREE_CHLD		0x8A
struct hal_ev_handsfree_chld {
	uint8_t chld;
} __attribute__((packed));


#define HAL_EV_HANDSFREE_CNUM		0x8B

#define HAL_EV_HANDSFREE_CIND		0x8C

#define HAL_EV_HANDSFREE_COPS		0x8D

#define HAL_EV_HANDSFREE_CLCC		0x8E

#define HAL_EV_HANDSFREE_UNKNOWN_AT	0x8F
struct hal_ev_handsfree_unknown_at {
	uint16_t len;
	uint8_t buf[0];
} __attribute__((packed));

#define HAL_EV_HANDSFREE_HSP_KEY_PRESS	0x90

/* AVRCP HAL API */

#define HAL_AVRCP_PLAY_STATUS_STOPPED	0x00
#define HAL_AVRCP_PLAY_STATUS_PLAYING	0x01
#define HAL_AVRCP_PLAY_STATUS_PAUSED	0x02
#define HAL_AVRCP_PLAY_STATUS_FWD_SEEK	0x03
#define HAL_AVRCP_PLAY_STATUS_REV_SEEK	0x04
#define HAL_AVRCP_PLAY_STATUS_ERROR	0xff

#define HAL_OP_AVRCP_GET_PLAY_STATUS	0x01
struct hal_cmd_avrcp_get_play_status {
	uint8_t status;
	uint32_t duration;
	uint32_t position;
} __attribute__((packed));

#define HAL_AVRCP_PLAYER_ATTR_EQUALIZER	0x01
#define HAL_AVRCP_PLAYER_ATTR_REPEAT	0x02
#define HAL_AVRCP_PLAYER_ATTR_SHUFFLE	0x03
#define HAL_AVRCP_PLAYER_ATTR_SCAN	0x04

#define HAL_OP_AVRCP_LIST_PLAYER_ATTRS	0x02
struct hal_cmd_avrcp_list_player_attrs {
	uint8_t number;
	uint8_t attrs[0];
} __attribute__((packed));

#define HAL_OP_AVRCP_LIST_PLAYER_VALUES	0x03
struct hal_cmd_avrcp_list_player_values {
	uint8_t number;
	uint8_t values[0];
} __attribute__((packed));

struct hal_avrcp_player_attr_value {
	uint8_t attr;
	uint8_t value;
} __attribute__((packed));

#define HAL_OP_AVRCP_GET_PLAYER_ATTRS	0x04
struct hal_cmd_avrcp_get_player_attrs {
	uint8_t number;
	struct hal_avrcp_player_attr_value attrs[0];
} __attribute__((packed));

struct hal_avrcp_player_setting_text {
	uint8_t id;
	uint8_t len;
	uint8_t text[0];
} __attribute__((packed));

#define HAL_OP_AVRCP_GET_PLAYER_ATTRS_TEXT	0x05
struct hal_cmd_avrcp_get_player_attrs_text {
	uint8_t number;
	struct hal_avrcp_player_setting_text attrs[0];
} __attribute__((packed));

#define HAL_OP_AVRCP_GET_PLAYER_VALUES_TEXT	0x06
struct hal_cmd_avrcp_get_player_values_text {
	uint8_t number;
	struct hal_avrcp_player_setting_text values[0];
} __attribute__((packed));

#define HAL_AVRCP_MEDIA_ATTR_TITLE		0x01
#define HAL_AVRCP_MEDIA_ATTR_ARTIST		0x02
#define HAL_AVRCP_MEDIA_ATTR_ALBUM		0x03
#define HAL_AVRCP_MEDIA_ATTR_TRACK_NUM		0x04
#define HAL_AVRCP_MEDIA_ATTR_NUM_TRACKS		0x05
#define HAL_AVRCP_MEDIA_ATTR_GENRE		0x06
#define HAL_AVRCP_MEDIA_ATTR_DURATION		0x07

#define HAL_OP_AVRCP_GET_ELEMENT_ATTRS_TEXT	0x07
struct hal_cmd_avrcp_get_element_attrs_text {
	uint8_t number;
	struct hal_avrcp_player_setting_text values[0];
} __attribute__((packed));

#define HAL_OP_AVRCP_SET_PLAYER_ATTRS_VALUE	0x08
struct hal_cmd_avrcp_set_player_attrs_value {
	uint8_t status;
} __attribute__((packed));

#define HAL_AVRCP_EVENT_STATUS_CHANGED		0x01
#define HAL_AVRCP_EVENT_TRACK_CHANGED		0x02
#define HAL_AVRCP_EVENT_TRACK_REACHED_END	0x03
#define HAL_AVRCP_EVENT_TRACK_REACHED_START	0x04
#define HAL_AVRCP_EVENT_POSITION_CHANGED	0x05
#define HAL_AVRCP_EVENT_SETTING_CHANGED		0x08

#define HAL_AVRCP_EVENT_TYPE_INTERIM		0x00
#define HAL_AVRCP_EVENT_TYPE_CHANGED		0x01

#define HAL_OP_AVRCP_REGISTER_NOTIFICATION	0x09
struct hal_cmd_avrcp_register_notification {
	uint8_t event;
	uint8_t type;
	uint8_t len;
	uint8_t data[0];
} __attribute__((packed));

#define HAL_OP_AVRCP_SET_VOLUME			0x0a
struct hal_cmd_avrcp_set_volume {
	uint8_t value;
};

#define HAL_EV_AVRCP_REMOTE_FEATURES		0x81
struct hal_ev_avrcp_remote_features {
	uint8_t bdaddr[6];
	uint8_t features;
} __attribute__((packed));

#define HAL_EV_AVRCP_GET_PLAY_STATUS		0x82
#define HAL_EV_AVRCP_LIST_PLAYER_ATTRS		0x83

#define HAL_EV_AVRCP_LIST_PLAYER_VALUES		0x84
struct hal_ev_avrcp_list_player_values {
	uint8_t attr;
} __attribute__((packed));

#define HAL_EV_AVRCP_GET_PLAYER_VALUES		0x85
struct hal_ev_avrcp_get_player_values {
	uint8_t number;
	uint8_t attrs[0];
} __attribute__((packed));

#define HAL_EV_AVRCP_GET_PLAYER_ATTRS_TEXT	0x86
struct hal_ev_avrcp_get_player_attrs_text {
	uint8_t number;
	uint8_t attrs[0];
} __attribute__((packed));

#define HAL_EV_AVRCP_GET_PLAYER_VALUES_TEXT	0x87
struct hal_ev_avrcp_get_player_values_text {
	uint8_t attr;
	uint8_t number;
	uint8_t values[0];
} __attribute__((packed));

#define HAL_EV_AVRCP_SET_PLAYER_VALUES		0x88
struct hal_ev_avrcp_set_player_values {
	uint8_t number;
	struct hal_avrcp_player_attr_value attrs[0];
} __attribute__((packed));

#define HAL_EV_AVRCP_GET_ELEMENT_ATTRS		0x89
struct hal_ev_avrcp_get_element_attrs {
	uint8_t number;
	uint8_t attrs[0];
} __attribute__((packed));

#define HAL_EV_AVRCP_REGISTER_NOTIFICATION	0x8a
struct hal_ev_avrcp_register_notification {
	uint8_t event;
	uint32_t param;
} __attribute__((packed));

#define HAL_EV_AVRCP_VOLUME_CHANGED		0x8b
struct hal_ev_avrcp_volume_changed {
	uint8_t volume;
	uint8_t type;
} __attribute__((packed));

#define HAL_EV_AVRCP_PASSTHROUGH_CMD		0x8c
struct hal_ev_avrcp_passthrough_cmd {
	uint8_t id;
	uint8_t state;
} __attribute__((packed));
