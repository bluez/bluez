/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdint.h>

#define IPC_TYPE_CONNECT  0x0001

#define IPC_SOCKET_NAME "/org/bluez/audio"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

struct ipc_hdr {
	uint16_t id;
	uint16_t type;
	uint16_t seqnum;
	uint16_t length;
} __attribute__ ((packed));

struct ipc_connect_cmd {
	uint8_t src[6];
	uint8_t dst[6];
	uint16_t uuid;
} __attribute__ ((packed));

struct ipc_connect_evt {
	uint16_t id;
} __attribute__ ((packed));
