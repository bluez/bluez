/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

#ifndef __BLUETOOTH_UUID_H
#define __BLUETOOTH_UUID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <bluetooth/bluetooth.h>

typedef struct {
	enum {
		BT_UUID_UNSPEC = 0,
		BT_UUID16 = 16,
		BT_UUID32 = 32,
		BT_UUID128 = 128,
	} type;
	union {
		uint16_t  u16;
		uint32_t  u32;
		uint128_t u128;
	} value;
} bt_uuid_t;

int bt_uuid16_create(bt_uuid_t *btuuid, uint16_t value);
int bt_uuid32_create(bt_uuid_t *btuuid, uint32_t value);
int bt_uuid128_create(bt_uuid_t *btuuid, uint128_t value);

int bt_uuid_cmp(const bt_uuid_t *uuid1, const bt_uuid_t *uuid2);
void bt_uuid_to_uuid128(const bt_uuid_t *src, bt_uuid_t *dst);

#define MAX_LEN_UUID_STR 37

int bt_uuid_to_string(const bt_uuid_t *uuid, char *str, size_t n);
int bt_string_to_uuid(bt_uuid_t *uuid, const char *string);

#ifdef __cplusplus
}
#endif

#endif /* __BLUETOOTH_UUID_H */
