/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2012  Intel Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>

#include "packet.h"
#include "l2cap.h"

#define print_field(fmt, args...) printf("%-12c" fmt "\n", ' ', ## args)

void l2cap_packet(const void *data, uint16_t size)
{
	const struct bt_l2cap_hdr *hdr = data;

	if (size < sizeof(*hdr)) {
		print_field("malformed packet");
		packet_hexdump(data, size);
		return;
	}

	print_field("Length: %d", btohs(hdr->len));
	print_field("Channel: %d", btohs(hdr->cid));

	if (btohs(hdr->len) != size - sizeof(*hdr)) {
		print_field("invalid packet size");
		packet_hexdump(data +  sizeof(*hdr), size -  sizeof(*hdr));
		return;
	}

	packet_hexdump(data +  sizeof(*hdr), size -  sizeof(*hdr));
}
