/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdint.h>

typedef void (*bthost_send_func) (const void *data, uint16_t len,
							void *user_data);

struct bthost;

struct bthost *bthost_create(void);
void bthost_destroy(struct bthost *bthost);

void bthost_set_send_handler(struct bthost *bthost, bthost_send_func handler,
							void *user_data);

void bthost_receive_h4(struct bthost *bthost, const void *data, uint16_t len);

typedef void (*bthost_cmd_complete_cb) (uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data);

void bthost_set_cmd_complete_cb(struct bthost *bthost,
				bthost_cmd_complete_cb cb, void *user_data);

typedef void (*bthost_new_conn_cb) (uint16_t handle, void *user_data);

void bthost_set_connect_cb(struct bthost *bthost, bthost_new_conn_cb cb,
							void *user_data);

void bthost_hci_connect(struct bthost *bthost, const uint8_t *bdaddr,
							uint8_t addr_type);

typedef void (*bthost_l2cap_rsp_cb) (uint8_t code, const void *data,
						uint16_t len, void *user_data);

bool bthost_l2cap_req(struct bthost *bthost, uint16_t handle, uint8_t req,
				const void *data, uint16_t len,
				bthost_l2cap_rsp_cb cb, void *user_data);

void bthost_write_scan_enable(struct bthost *bthost, uint8_t scan);

void bthost_set_adv_enable(struct bthost *bthost, uint8_t enable);

void bthost_set_server_psm(struct bthost *bthost, uint16_t psm);

void bthost_start(struct bthost *bthost);
void bthost_stop(struct bthost *bthost);
