/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>

#include "src/shared/util.h"
#include "display.h"
#include "packet.h"
#include "lmp.h"
#include "ll.h"
#include "broadcom.h"

void broadcom_lm_diag(const void *data, uint8_t size)
{
	uint8_t type;
	uint32_t clock;
	const uint8_t *addr;
	const char *str;

	if (size != 63) {
		packet_hexdump(data, size);
		return;
	}

	type = *((uint8_t *) data);
	clock = get_be32(data + 1);

	switch (type) {
	case 0x00:
		str = "LMP sent";
		break;
	case 0x01:
		str = "LMP receive";
		break;
	case 0x80:
		str = "LL sent";
		break;
	case 0x81:
		str = "LL receive";
		break;
	default:
		str = "Unknown";
		break;
	}

	print_field("Type: %s (%u)", str, type);
	print_field("Clock: 0x%8.8x", clock);

	switch (type) {
	case 0x00:
		addr = data + 5;
		print_field("Address: --:--:%2.2X:%2.2X:%2.2X:%2.2X",
					addr[0], addr[1], addr[2], addr[3]);
		packet_hexdump(data + 9, 1);
		lmp_packet(data + 10, size - 10, true);
		break;
	case 0x01:
		addr = data + 5;
		print_field("Address: --:--:%2.2X:%2.2X:%2.2X:%2.2X",
					addr[0], addr[1], addr[2], addr[3]);
		packet_hexdump(data + 9, 4);
		lmp_packet(data + 13, size - 13, true);
		break;
	case 0x80:
	case 0x81:
		packet_hexdump(data + 5, 7);
		llcp_packet(data + 12, size - 12, true);
		break;
	default:
		packet_hexdump(data + 9, size - 9);
		break;
	}
}
