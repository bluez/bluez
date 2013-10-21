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

struct hal_msg_hdr {
	uint8_t service_id;
	uint8_t opcode;
	uint16_t len;
} __attribute__((packed));

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

/* Core Service */

#define HAL_MSG_OP_ERROR		0x00
struct hal_msg_rsp_error {
	uint8_t status;
} __attribute__((packed));

#define HAL_MSG_OP_REGISTER_MODULE	0x01
struct hal_msg_cmd_register_module {
	uint8_t service_id;
} __attribute__((packed));
struct hal_msg_rsp_register_module {
	uint8_t service_id;
} __attribute__((packed));

#define HAL_MSG_OP_UNREGISTER_MODULE	0x02
struct hal_msg_cmd_unregister_module {
	uint8_t service_id;
} __attribute__((packed));

/* Bluetooth Core HAL API */

#define HAL_MSG_OP_BT_ENABLE		0x01

#define HAL_MSG_OP_BT_DISABLE		0x02

#define HAL_MSG_OP_BT_GET_ADAPTER_PROPS	0x03

#define HAL_MSG_OP_BT_GET_ADAPTER_PROP	0x04
struct hal_msg_cmd_bt_get_adapter_prop {
	uint8_t type;
} __attribute__((packed));

#define HAL_MSG_OP_BT_SET_ADAPTER_PROP	0x05
struct hal_msg_cmd_bt_set_adapter_prop {
	uint8_t  type;
	uint16_t len;
	uint8_t  val[0];
} __attribute__((packed));

#define HAL_MSG_OP_BT_GET_REMOTE_DEVICE_PROPS	0x06
struct hal_msg_cmd_bt_get_remote_device_props {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_MSG_OP_BT_GET_REMOTE_DEVICE_PROP	0x07
struct hal_msg_cmd_bt_get_remote_device_prop {
	uint8_t bdaddr[6];
	uint8_t type;
} __attribute__((packed));

#define HAL_MSG_OP_BT_SET_REMOTE_DEVICE_PROP	0x08
struct hal_msg_cmd_bt_set_remote_device_prop {
	uint8_t  bdaddr[6];
	uint8_t  type;
	uint16_t len;
	uint8_t  val[0];
} __attribute__((packed));

#define HAL_MSG_OP_BT_GET_REMOTE_SERVICE_REC	0x09
struct hal_msg_cmd_bt_get_remote_service_rec {
	uint8_t bdaddr[6];
	uint8_t uuid[16];
} __attribute__((packed));

#define HAL_MSG_OP_BT_GET_REMOTE_SERVICE	0x0a
struct hal_msg_cmd_bt_get_remote_service {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_MSG_OP_BT_START_DISCOVERY	0x0b

#define HAL_MSG_OP_BT_CANCEL_DISCOVERY	0x0c

#define HAL_MSG_OP_BT_CREATE_BOND	0x0d
struct hal_msg_cmd_bt_create_bond {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_MSG_OP_BT_REMOVE_BOND	0x0d
struct hal_msg_cmd_bt_remove_bond {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_MSG_OP_BT_CANCEL_BOND	0x0f
struct hal_msg_cmd_bt_cancel_bond {
	uint8_t bdaddr[6];
} __attribute__((packed));

#define HAL_MSG_OP_BT_PIN_REPLY		0x10
struct hal_msg_cmd_bt_pin_reply {
	uint8_t bdaddr[6];
	uint8_t accept;
	uint8_t pin_len;
	uint8_t pin_code[16];
} __attribute__((packed));

#define HAL_MSG_OP_BT_SSP_REPLY		0x11
struct hal_msg_cmd_bt_ssp_reply {
	uint8_t  bdaddr[6];
	uint8_t  ssp_variant;
	uint8_t  accept;
	uint32_t passkey;
} __attribute__((packed));

#define HAL_MSG_OP_BT_DUT_MODE_CONF	0x12
struct hal_msg_cmd_bt_dut_mode_conf {
	uint8_t enable;
} __attribute__((packed));

#define HAL_MSG_OP_BT_DUT_MODE_SEND	0x13
struct hal_msg_cmd_bt_dut_mode_send {
	uint16_t opcode;
	uint8_t  len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_MSG_OP_BT_LE_TEST_MODE	0x14
struct hal_msg_cmd_bt_le_test_mode {
	uint16_t opcode;
	uint8_t  len;
	uint8_t  data[0];
} __attribute__((packed));

/* Notifications and confirmations */

#define HAL_MSG_EV_BT_ERROR			0x80

#define HAL_MSG_EV_BT_ADAPTER_STATE_CHANGED	0x81
struct hal_msg_ev_bt_adapter_state_changed {
	uint8_t state;
} __attribute__((packed));

#define HAL_MSG_EV_BT_ADAPTER_PROPS_CHANGED	0x82
struct hal_property {
	uint8_t  type;
	uint16_t len;
	uint8_t  val[0];
} __attribute__((packed));
struct hal_msg_ev_bt_adapter_props_changed {
	uint8_t              status;
	uint8_t              num_props;
	struct  hal_property props[0];
} __attribute__((packed));

#define HAL_MSG_EV_BT_REMOTE_DEVICE_PROPS	0x83
struct hal_msg_ev_bt_remote_device_props {
	uint8_t             status;
	uint8_t             bdaddr[6];
	uint8_t             num_props;
	struct hal_property props[0];
} __attribute__((packed));

#define HAL_MSG_EV_BT_DEVICE_FOUND		0x84
struct hal_msg_ev_bt_device_found {
	uint8_t             num_props;
	struct hal_property props[0];
} __attribute__((packed));

#define HAL_MSG_EV_BT_DISCOVERY_STATE_CHANGED	0x85
struct hal_msg_ev_bt_discovery_state_changed {
	uint8_t state;
} __attribute__((packed));

#define HAL_MSG_EV_BT_PIN_REQUEST		0x86
struct hal_msg_ev_bt_pin_request {
	uint8_t bdaddr[6];
	uint8_t name[249 - 1];
	uint8_t class_of_dev[3];
} __attribute__((packed));

#define HAL_MSG_EV_BT_SSP_REQUEST		0x87
struct hal_msg_ev_bt_ssp_request {
	uint8_t  bdaddr[6];
	uint8_t  name[249 - 1];
	uint8_t  class_of_dev[3];
	uint8_t  pairing_variant;
	uint32_t passkey;
} __attribute__((packed));

#define HAL_MSG_EV_BT_BOND_STATE_CHANGED	0x88
struct hal_msg_ev_bt_bond_state_changed {
	uint8_t status;
	uint8_t bdaddr[6];
	uint8_t state;
} __attribute__((packed));

#define HAL_MSG_EV_BT_ACL_STATE_CHANGED		0x89
struct hal_msg_ev_bt_acl_state_changed {
	uint8_t status;
	uint8_t bdaddr[6];
	uint8_t state;
} __attribute__((packed));

#define HAL_MSG_EV_BT_DUT_MODE_RECEIVE		0x8a
struct hal_msg_ev_bt_dut_mode_receive {
	uint16_t opcode;
	uint8_t  len;
	uint8_t  data[0];
} __attribute__((packed));

#define HAL_MSG_EV_BT_LE_TEST_MODE		0x8b
struct hal_msg_ev_bt_le_test_mode {
	uint8_t  status;
	uint16_t num_packets;
} __attribute__((packed));
