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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include "uuid.h"

#if __BYTE_ORDER == __BIG_ENDIAN
static uint128_t bluetooth_base_uuid = {
	.data = {	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }
};

#define BASE_UUID16_OFFSET	2
#define BASE_UUID32_OFFSET	0

#else
static uint128_t bluetooth_base_uuid = {
	.data = {	0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

#define BASE_UUID16_OFFSET	12
#define BASE_UUID32_OFFSET	BASE_UUID16_OFFSET

#endif

static void bt_uuid16_to_uuid128(const bt_uuid_t *src, bt_uuid_t *dst)
{
	dst->value.u128 = bluetooth_base_uuid;
	dst->type = BT_UUID128;

	memcpy(&dst->value.u128.data[BASE_UUID16_OFFSET],
			&src->value.u16, sizeof(src->value.u16));
}

static void bt_uuid32_to_uuid128(const bt_uuid_t *src, bt_uuid_t *dst)
{
	dst->value.u128 = bluetooth_base_uuid;
	dst->type = BT_UUID128;

	memcpy(&dst->value.u128.data[BASE_UUID32_OFFSET],
				&src->value.u32, sizeof(src->value.u32));
}

void bt_uuid_to_uuid128(const bt_uuid_t *src, bt_uuid_t *dst)
{
	switch (src->type) {
	case BT_UUID128:
		memcpy(dst, src, sizeof(bt_uuid_t));
		break;
	case BT_UUID32:
		bt_uuid32_to_uuid128(src, dst);
		break;
	case BT_UUID16:
		bt_uuid16_to_uuid128(src, dst);
		break;
	default:
		break;
	}
}

static int bt_uuid128_cmp(const bt_uuid_t *u1, const bt_uuid_t *u2)
{
	return memcmp(&u1->value.u128, &u2->value.u128, sizeof(uint128_t));
}

int bt_uuid16_create(bt_uuid_t *btuuid, uint16_t value)
{
	memset(btuuid, 0, sizeof(bt_uuid_t));
	btuuid->type = BT_UUID16;
	btuuid->value.u16 = value;

	return 0;
}

int bt_uuid32_create(bt_uuid_t *btuuid, uint32_t value)
{
	memset(btuuid, 0, sizeof(bt_uuid_t));
	btuuid->type = BT_UUID32;
	btuuid->value.u32 = value;

	return 0;
}

int bt_uuid128_create(bt_uuid_t *btuuid, uint128_t value)
{
	memset(btuuid, 0, sizeof(bt_uuid_t));
	btuuid->type = BT_UUID128;
	btuuid->value.u128 = value;

	return 0;
}

int bt_uuid_cmp(const bt_uuid_t *uuid1, const bt_uuid_t *uuid2)
{
	bt_uuid_t u1, u2;

	bt_uuid_to_uuid128(uuid1, &u1);
	bt_uuid_to_uuid128(uuid2, &u2);

	return bt_uuid128_cmp(&u1, &u2);
}
