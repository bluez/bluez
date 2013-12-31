/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

struct ipc_handler {
	void (*handler) (const void *buf, uint16_t len);
	bool var_len;
	size_t data_len;
};

struct service_handler {
	const struct ipc_handler *handler;
	uint8_t size;
};

void ipc_init(void);
void ipc_cleanup(void);
GIOChannel *ipc_connect(const char *path, size_t size, GIOFunc connect_cb);
int ipc_handle_msg(struct service_handler *handlers, size_t max_index,
						const void *buf, ssize_t len);

void ipc_send_rsp(uint8_t service_id, uint8_t opcode, uint8_t status);
void ipc_send_rsp_full(uint8_t service_id, uint8_t opcode, uint16_t len,
							void *param, int fd);
void ipc_send_notif(uint8_t service_id, uint8_t opcode,  uint16_t len,
								void *param);
void ipc_send(int sk, uint8_t service_id, uint8_t opcode, uint16_t len,
							void *param, int fd);
void ipc_register(uint8_t service, const struct ipc_handler *handlers,
								uint8_t size);
void ipc_unregister(uint8_t service);
