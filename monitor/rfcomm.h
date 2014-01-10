/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014 Intel Corporation
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

#define RFCOMM_SABM	0x2f
#define RFCOMM_DISC	0x43
#define RFCOMM_UA	0x63
#define RFCOMM_DM	0x0f
#define RFCOMM_UIH	0xef

#define RFCOMM_GET_TYPE(control)	((control) & 0xef)
#define RFCOMM_GET_DLCI(address)	((address & 0xfc) >> 2)
#define RFCOMM_GET_CHANNEL(address)	((address & 0xf8) >> 3)
#define RFCOMM_GET_DIR(address)		((address & 0x04) >> 2)
#define RFCOMM_TEST_EA(length)		((length & 0x01))

struct rfcomm_hdr {
	uint8_t address;
	uint8_t control;
	uint8_t length;
} __attribute__((packed));

struct rfcomm_cmd {
	uint8_t address;
	uint8_t control;
	uint8_t length;
	uint8_t fcs;
} __attribute__((packed));
