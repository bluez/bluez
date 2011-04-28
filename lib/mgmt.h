/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define MGMT_INDEX_NONE			0xFFFF

struct mgmt_hdr {
	uint16_t opcode;
	uint16_t index;
	uint16_t len;
} __packed;
#define MGMT_HDR_SIZE	6

#define MGMT_OP_READ_VERSION		0x0001
struct mgmt_rp_read_version {
	uint8_t version;
	uint16_t revision;
} __packed;

#define MGMT_OP_READ_FEATURES		0x0002
struct mgmt_rp_read_features {
	uint8_t features[8];
} __packed;

#define MGMT_OP_READ_INDEX_LIST		0x0003
struct mgmt_rp_read_index_list {
	uint16_t num_controllers;
	uint16_t index[0];
} __packed;

/* Reserve one extra byte for names in management messages so that they
 * are always guaranteed to be nul-terminated */
#define MGMT_MAX_NAME_LENGTH		(HCI_MAX_NAME_LENGTH + 1)

#define MGMT_OP_READ_INFO		0x0004
struct mgmt_rp_read_info {
	uint8_t type;
	uint8_t powered;
	uint8_t connectable;
	uint8_t discoverable;
	uint8_t pairable;
	uint8_t sec_mode;
	bdaddr_t bdaddr;
	uint8_t dev_class[3];
	uint8_t features[8];
	uint16_t manufacturer;
	uint8_t hci_ver;
	uint16_t hci_rev;
	uint8_t name[MGMT_MAX_NAME_LENGTH];
} __packed;

struct mgmt_mode {
	uint8_t val;
} __packed;

#define MGMT_OP_SET_POWERED		0x0005

#define MGMT_OP_SET_DISCOVERABLE	0x0006

#define MGMT_OP_SET_CONNECTABLE		0x0007

#define MGMT_OP_SET_PAIRABLE		0x0008

#define MGMT_OP_ADD_UUID		0x0009
struct mgmt_cp_add_uuid {
	uint8_t uuid[16];
	uint8_t svc_hint;
} __packed;

#define MGMT_OP_REMOVE_UUID		0x000A
struct mgmt_cp_remove_uuid {
	uint8_t uuid[16];
} __packed;

#define MGMT_OP_SET_DEV_CLASS		0x000B
struct mgmt_cp_set_dev_class {
	uint8_t major;
	uint8_t minor;
} __packed;

#define MGMT_OP_SET_SERVICE_CACHE	0x000C
struct mgmt_cp_set_service_cache {
	uint8_t enable;
} __packed;

struct mgmt_key_info {
	bdaddr_t bdaddr;
	uint8_t type;
	uint8_t val[16];
	uint8_t pin_len;
} __packed;

#define MGMT_OP_LOAD_KEYS		0x000D
struct mgmt_cp_load_keys {
	uint8_t debug_keys;
	uint16_t key_count;
	struct mgmt_key_info keys[0];
} __packed;

#define MGMT_OP_REMOVE_KEY		0x000E
struct mgmt_cp_remove_key {
	bdaddr_t bdaddr;
	uint8_t disconnect;
} __packed;

#define MGMT_OP_DISCONNECT		0x000F
struct mgmt_cp_disconnect {
	bdaddr_t bdaddr;
} __packed;
struct mgmt_rp_disconnect {
	bdaddr_t bdaddr;
} __packed;

#define MGMT_OP_GET_CONNECTIONS		0x0010
struct mgmt_rp_get_connections {
	uint16_t conn_count;
	bdaddr_t conn[0];
} __packed;

#define MGMT_OP_PIN_CODE_REPLY		0x0011
struct mgmt_cp_pin_code_reply {
	bdaddr_t bdaddr;
	uint8_t pin_len;
	uint8_t pin_code[16];
} __packed;

#define MGMT_OP_PIN_CODE_NEG_REPLY	0x0012
struct mgmt_cp_pin_code_neg_reply {
	bdaddr_t bdaddr;
} __packed;

#define MGMT_OP_SET_IO_CAPABILITY	0x0013
struct mgmt_cp_set_io_capability {
	uint8_t io_capability;
} __packed;

#define MGMT_OP_PAIR_DEVICE		0x0014
struct mgmt_cp_pair_device {
	bdaddr_t bdaddr;
	uint8_t io_cap;
} __packed;
struct mgmt_rp_pair_device {
	bdaddr_t bdaddr;
	uint8_t status;
} __packed;

#define MGMT_OP_USER_CONFIRM_REPLY	0x0015
struct mgmt_cp_user_confirm_reply {
	bdaddr_t bdaddr;
} __packed;
struct mgmt_rp_user_confirm_reply {
	bdaddr_t bdaddr;
	uint8_t status;
} __packed;

#define MGMT_OP_USER_CONFIRM_NEG_REPLY	0x0016

#define MGMT_OP_SET_LOCAL_NAME		0x0017
struct mgmt_cp_set_local_name {
	uint8_t name[MGMT_MAX_NAME_LENGTH];
} __packed;

#define MGMT_OP_READ_LOCAL_OOB_DATA	0x0018
struct mgmt_rp_read_local_oob_data {
	uint8_t hash[16];
	uint8_t randomizer[16];
} __packed;

#define MGMT_OP_ADD_REMOTE_OOB_DATA	0x0019
struct mgmt_cp_add_remote_oob_data {
	bdaddr_t bdaddr;
	uint8_t hash[16];
	uint8_t randomizer[16];
} __packed;

#define MGMT_OP_REMOVE_REMOTE_OOB_DATA	0x001A
struct mgmt_cp_remove_remote_oob_data {
	bdaddr_t bdaddr;
} __packed;

#define MGMT_OP_START_DISCOVERY		0x001B

#define MGMT_OP_STOP_DISCOVERY		0x001C

#define MGMT_EV_CMD_COMPLETE		0x0001
struct mgmt_ev_cmd_complete {
	uint16_t opcode;
	uint8_t data[0];
} __packed;

#define MGMT_EV_CMD_STATUS		0x0002
struct mgmt_ev_cmd_status {
	uint8_t status;
	uint16_t opcode;
} __packed;

#define MGMT_EV_CONTROLLER_ERROR	0x0003
struct mgmt_ev_controller_error {
	uint8_t error_code;
} __packed;

#define MGMT_EV_INDEX_ADDED		0x0004

#define MGMT_EV_INDEX_REMOVED		0x0005

#define MGMT_EV_POWERED			0x0006

#define MGMT_EV_DISCOVERABLE		0x0007

#define MGMT_EV_CONNECTABLE		0x0008

#define MGMT_EV_PAIRABLE		0x0009

#define MGMT_EV_NEW_KEY			0x000A
struct mgmt_ev_new_key {
	uint8_t store_hint;
	struct mgmt_key_info key;
} __packed;

#define MGMT_EV_DEVICE_CONNECTED	0x000B
struct mgmt_ev_device_connected {
	bdaddr_t bdaddr;
} __packed;

#define MGMT_EV_DEVICE_DISCONNECTED	0x000C
struct mgmt_ev_device_disconnected {
	bdaddr_t bdaddr;
} __packed;

#define MGMT_EV_CONNECT_FAILED		0x000D
struct mgmt_ev_connect_failed {
	bdaddr_t bdaddr;
	uint8_t status;
} __packed;

#define MGMT_EV_PIN_CODE_REQUEST	0x000E
struct mgmt_ev_pin_code_request {
	bdaddr_t bdaddr;
	uint8_t secure;
} __packed;

#define MGMT_EV_USER_CONFIRM_REQUEST	0x000F
struct mgmt_ev_user_confirm_request {
	bdaddr_t bdaddr;
	uint8_t confirm_hint;
	uint32_t value;
} __packed;

#define MGMT_EV_AUTH_FAILED		0x0010
struct mgmt_ev_auth_failed {
	bdaddr_t bdaddr;
	uint8_t status;
} __packed;

#define MGMT_EV_LOCAL_NAME_CHANGED	0x0011
struct mgmt_ev_local_name_changed {
	uint8_t name[MGMT_MAX_NAME_LENGTH];
} __packed;

#define MGMT_EV_DEVICE_FOUND		0x0012
struct mgmt_ev_device_found {
	bdaddr_t bdaddr;
	uint8_t dev_class[3];
	int8_t rssi;
	uint8_t eir[HCI_MAX_EIR_LENGTH];
} __packed;

#define MGMT_EV_REMOTE_NAME		0x0013
struct mgmt_ev_remote_name {
	bdaddr_t bdaddr;
	uint8_t name[MGMT_MAX_NAME_LENGTH];
} __packed;

#define MGMT_EV_DISCOVERING		0x0014
