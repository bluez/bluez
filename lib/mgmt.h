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
struct mgmt_read_version_rp {
	uint8_t version;
	uint16_t revision;
} __packed;
#define MGMT_READ_VERSION_RP_SIZE	3

#define MGMT_OP_READ_FEATURES		0x0002
struct mgmt_read_features_rp {
	uint8_t features[8];
} __packed;
#define MGMT_READ_FEATURES_RP_SIZE	8

#define MGMT_OP_READ_INDEX_LIST		0x0003
struct mgmt_read_index_list_rp {
	uint16_t num_controllers;
	uint16_t index[0];
} __packed;
#define MGMT_READ_INDEX_LIST_RP_SIZE	2

#define MGMT_OP_READ_INFO		0x0004
struct mgmt_read_info_cp {
	uint16_t index;
} __packed;
#define MGMT_READ_INFO_CP_SIZE		2
struct mgmt_read_info_rp {
	uint8_t status;
	uint16_t index;
	uint8_t type;
	bdaddr_t addr;
	uint8_t features[8];
} __packed;
#define MGMT_READ_INFO_RP_SIZE		18

#define MGMT_OP_READ_STATISTICS		0x0005
#define MGMT_OP_READ_MODE		0x0006
#define MGMT_OP_WRITE_MODE		0x0007

#define MGMT_EV_CMD_COMPLETE		0x0001
struct mgmt_cmd_complete_ev {
	uint16_t opcode;
	uint8_t data[0];
} __packed;
#define MGMT_CMD_COMPLETE_SIZE		2

#define MGMT_EV_CMD_STATUS		0x0002
#define MGMT_EV_CONTROLLER_ERROR	0x0003
