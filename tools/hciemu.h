/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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

#include <stdbool.h>

struct hciemu;

struct hciemu *hciemu_new(void);

struct hciemu *hciemu_ref(struct hciemu *hciemu);
void hciemu_unref(struct hciemu *hciemu);

const char *hciemu_get_address(struct hciemu *hciemu);

typedef void (*hciemu_command_func_t)(uint16_t opcode, const void *data,
						uint8_t len, void *user_data);

bool hciemu_add_master_post_command_hook(struct hciemu *hciemu,
			hciemu_command_func_t function, void *user_data);
