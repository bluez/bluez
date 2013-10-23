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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <glib.h>

#include "lib/bluetooth.h"

struct bt_adapter;

typedef void (*bt_adapter_ready)(struct bt_adapter *adapter, int err);

bool bt_adapter_init(uint16_t index, struct mgmt *mgmt_if,
						bt_adapter_ready func);

void bt_adapter_handle_cmd(GIOChannel *io, uint8_t opcode, void *buf,
								uint16_t len);

bool bt_adapter_register(GIOChannel *io);
void bt_adapter_unregister(void);
