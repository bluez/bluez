/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include "gdbus/gdbus.h"

/* Largest Possible GATT Packet: Provisioning Public Key + type + sar */
#define MAX_GATT_SIZE	(64 + 1 + 1)

#define GATT_SAR_MASK		0xc0
#define GATT_SAR_COMPLETE	0x00
#define GATT_SAR_FIRST		0x40
#define GATT_SAR_CONTINUE	0x80
#define GATT_SAR_LAST		0xc0
#define GATT_TYPE_INVALID	0xff
#define GATT_TYPE_MASK		0x3f

uint16_t mesh_gatt_sar(uint8_t **pkt, uint16_t size);
bool mesh_gatt_is_child(GDBusProxy *proxy, GDBusProxy *parent,
			const char *name);
bool mesh_gatt_write(GDBusProxy *proxy, uint8_t *buf, uint16_t len,
			GDBusReturnFunction cb, void *user_data);
bool mesh_gatt_notify(GDBusProxy *proxy, bool enable, GDBusReturnFunction cb,
			void *user_data);
void mesh_gatt_cleanup(void);
