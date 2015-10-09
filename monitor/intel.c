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
#include "intel.h"

void intel_vendor_event(const void *data, uint8_t size)
{
	uint8_t evt, type, len;

	evt = *((uint8_t *) data);

	print_field("Event: 0x%2.2x", evt);

	switch (evt) {
	case 0x17:
		type = *((uint8_t *) (data + 1));

		switch (type) {
		case 0x00:
			len = size - 9;
			print_field("Type: RX LMP (0x%2.2x)", type);
			packet_hexdump(data + 2, 3);
			lmp_packet(data + 5, len, false);
			packet_hexdump(data + 5 + len, size - 5 - len);
			break;
		case 0x01:
			len = size - 10;
			print_field("Type: TX LMP (0x%2.2x)", type);
			packet_hexdump(data + 2, 3);
			lmp_packet(data + 5, len, false);
			packet_hexdump(data + 5 + len, size - 5 - len);
			break;
		case 0x03:
			len = size - 9;
			print_field("Type: RX LL (0x%2.2x)", type);
			packet_hexdump(data + 2, 7);
			llcp_packet(data + 9, len, false);
			break;
		case 0x04:
			len = size - 9;
			print_field("Type: TX LL (0x%2.2x)", type);
			packet_hexdump(data + 2, 7);
			llcp_packet(data + 9, len, false);
			break;
		default:
			print_field("Type: 0x%2.2x", type);
			packet_hexdump(data + 2, size - 2);
			break;
		}
		break;
	default:
		packet_hexdump(data + 1, size - 1);
		break;
	}
}
