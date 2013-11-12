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

typedef void (*bt_bluetooth_ready)(int err, const bdaddr_t *addr);
bool bt_bluetooth_start(int index, bt_bluetooth_ready cb);

typedef void (*bt_bluetooth_stopped)(void);
bool bt_bluetooth_stop(bt_bluetooth_stopped cb);

void bt_bluetooth_cleanup(void);

void bt_bluetooth_handle_cmd(int sk, uint8_t opcode, void *buf, uint16_t len);

bool bt_bluetooth_register(int sk);
void bt_bluetooth_unregister(void);

int bt_adapter_add_record(sdp_record_t *rec, uint8_t svc_hint);
void bt_adapter_remove_record(uint32_t handle);
