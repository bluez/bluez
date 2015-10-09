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
	uint8_t evt, type, len, id;
	uint16_t handle, count;
	uint32_t clock;
	const char *str;

	evt = *((uint8_t *) data);

	print_field("Event: 0x%2.2x", evt);

	switch (evt) {
	case 0x17:
		type = *((uint8_t *) (data + 1));
		handle = get_le16(data + 2);

		switch (type) {
		case 0x00:
			str = "RX LMP";
			break;
		case 0x01:
			str = "TX LMP";
			break;
		case 0x02:
			str = "ACK LMP";
			break;
		case 0x03:
			str = "RX LL";
			break;
		case 0x04:
			str = "TX LL";
			break;
		case 0x05:
			str = "ACK LL";
			break;
		default:
			str = "Unknown";
			break;
		}

		print_field("Type: %s (0x%2.2x)", str, type);
		print_field("Handle: %u", handle);

		switch (type) {
		case 0x00:
			len = size - 9;
			clock = get_le32(data + 5 + len);

			packet_hexdump(data + 4, 1);
			lmp_packet(data + 5, len, false);
			print_field("Clock: 0x%8.8x", clock);
			break;
		case 0x01:
			len = size - 10;
			clock = get_le32(data + 5 + len);
			id = *((uint8_t *) (data + 5 + len + 4));

			packet_hexdump(data + 4, 1);
			lmp_packet(data + 5, len, false);
			print_field("Clock: 0x%8.8x", clock);
			print_field("ID: 0x%2.2x", id);
			break;
		case 0x02:
			clock = get_le32(data + 4);
			id = *((uint8_t *) (data + 4 + 4));

			print_field("Clock: 0x%8.8x", clock);
			print_field("ID: 0x%2.2x", id);
			break;
		case 0x03:
			len = size - 9;
			count = get_le16(data + 4);

			print_field("Count: 0x%4.4x", count);
			packet_hexdump(data + 4 + 2 + 1, 2);
			llcp_packet(data + 9, len, false);
			break;
		case 0x04:
			len = size - 9;
			count = get_le16(data + 4);
			id = *((uint8_t *) (data + 4 + 2));

			print_field("Count: 0x%4.4x", count);
			print_field("ID: 0x%2.2x", id);
			packet_hexdump(data + 4 + 2 + 1, 2);
			llcp_packet(data + 9, len, false);
			break;
		case 0x05:
			count = get_le16(data + 4);
			id = *((uint8_t *) (data + 4 + 2));

			print_field("Count: 0x%4.4x", count);
			print_field("ID: 0x%2.2x", id);
			break;
		default:
			packet_hexdump(data + 4, size - 4);
			break;
		}
		break;
	default:
		packet_hexdump(data + 1, size - 1);
		break;
	}
}
