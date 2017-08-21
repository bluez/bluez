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

#define GENERIC_ONOFF_SERVER_MODEL_ID	0x1000
#define GENERIC_ONOFF_CLIENT_MODEL_ID	0x1001

#define OP_GENERIC_ONOFF_GET			0x8201
#define OP_GENERIC_ONOFF_SET			0x8202
#define OP_GENERIC_ONOFF_SET_UNACK		0x8203
#define OP_GENERIC_ONOFF_STATUS			0x8204

void onoff_set_node(const char *args);
bool onoff_client_init(uint8_t ele);
