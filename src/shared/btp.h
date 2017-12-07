/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2017  Intel Corporation. All rights reserved.
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

#include <stdbool.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define BTP_INDEX_NON_CONTROLLER 0xff

#define BTP_ERROR_FAIL		0x01
#define BTP_ERROR_UNKNOWN_CMD	0x02
#define BTP_ERROR_NOT_READY	0x03
#define BTP_ERROR_INVALID_INDEX	0x04

#define BTP_CORE_SERVICE	0
#define BTP_GAP_SERVICE		1
#define BTP_GATT_SERVICE	2
#define BTP_L2CAP_SERVICE	3
#define BTP_MESH_NODE_SERVICE	4

struct btp_hdr {
	uint8_t service;
	uint8_t opcode;
	uint8_t index;
	uint16_t data_len;
	uint8_t data[0];
} __packed;

struct btp_error {
	uint8_t status;
} __packed;

#define BTP_OP_ERROR				0x00

#define BTP_OP_CORE_READ_SUPPORTED_COMMANDS	0x01

#define BTP_OP_CORE_READ_SUPPORTED_SERVICES	0x02

#define BTP_OP_CORE_REGISTER			0x03
struct btp_core_register_cp {
	uint8_t service_id;
} __packed;

#define BTP_OP_CORE_UNREGISTER			0x04
struct btp_core_unregister_cp {
	uint8_t service_id;
} __packed;

#define BTP_EV_CORE_READY			0x80

struct btp;

typedef void (*btp_destroy_func_t)(void *user_data);
typedef void (*btp_disconnect_func_t)(struct btp *btp, void *user_data);
typedef void (*btp_cmd_func_t)(uint8_t index, const void *param,
					uint16_t length, void *user_data);

struct btp *btp_new(const char *path);
void btp_cleanup(struct btp *btp);

bool btp_set_disconnect_handler(struct btp *btp, btp_disconnect_func_t callback,
				void *user_data, btp_destroy_func_t destroy);

bool btp_send_error(struct btp *btp, uint8_t service, uint8_t index,
								uint8_t status);
bool btp_send(struct btp *btp, uint8_t service, uint8_t opcode, uint8_t index,
					uint16_t length, const void *param);

unsigned int btp_register(struct btp *btp, uint8_t service, uint8_t opcode,
				btp_cmd_func_t callback, void *user_data,
				btp_destroy_func_t destroy);
bool btp_unregister(struct btp *btp, unsigned int id);
void btp_unregister_service(struct btp *btp, uint8_t service);
