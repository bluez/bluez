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

struct mgmt_hdr {
	uint16_t opcode;
	uint16_t len;
} __packed;
#define MGMT_HDR_SIZE	4

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

#define MGMT_OP_READ_INFO		0x0004
struct mgmt_cp_read_info {
	uint16_t index;
} __packed;
struct mgmt_rp_read_info {
	uint16_t index;
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
} __packed;

struct mgmt_mode {
	uint16_t index;
	uint8_t val;
} __packed;

#define MGMT_OP_SET_POWERED		0x0005

#define MGMT_OP_SET_DISCOVERABLE	0x0006

#define MGMT_OP_SET_CONNECTABLE		0x0007

#define MGMT_OP_SET_PAIRABLE		0x0008

#define MGMT_OP_ADD_UUID		0x0009
struct mgmt_cp_add_uuid {
	uint16_t index;
	uint8_t uuid[16];
	uint8_t svc_hint;
} __packed;

#define MGMT_OP_REMOVE_UUID		0x000A
struct mgmt_cp_remove_uuid {
	uint16_t index;
	uint8_t uuid[16];
} __packed;

#define MGMT_OP_SET_DEV_CLASS		0x000B
struct mgmt_cp_set_dev_class {
	uint16_t index;
	uint8_t major;
	uint8_t minor;
} __packed;

#define MGMT_OP_SET_SERVICE_CACHE	0x000C
struct mgmt_cp_set_service_cache {
	uint16_t index;
	uint8_t enable;
} __packed;

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
	uint16_t index;
	uint8_t error_code;
} __packed;

#define MGMT_EV_INDEX_ADDED		0x0004
struct mgmt_ev_index_added {
	uint16_t index;
} __packed;

#define MGMT_EV_INDEX_REMOVED		0x0005
struct mgmt_ev_index_removed {
	uint16_t index;
} __packed;

#define MGMT_EV_POWERED			0x0006

#define MGMT_EV_DISCOVERABLE		0x0007

#define MGMT_EV_CONNECTABLE		0x0008

#define MGMT_EV_PAIRABLE		0x0009
