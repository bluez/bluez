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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "lib/bluetooth.h"

#include "src/shared/util.h"
#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "uuid.h"
#include "keys.h"
#include "sdp.h"
#include "bnep.h"

#define GET_PKT_TYPE(type) (type & 0x7f)
#define GET_EXTENSION(type) (type & 0x80)

struct bnep_frame {
	uint8_t type;
	int extension;
	struct l2cap_frame l2cap_frame;
};

struct bnep_data {
	uint8_t type;
	const char *str;
};

static const struct bnep_data bnep_table[] = {
	{ 0x00, "General Ethernet"},
	{ 0x01, "Control"},
	{ 0x02, "Compressed Ethernet"},
	{ 0x03, "Compressed Ethernet Src Only"},
	{ 0x04, "Compressed Ethernet Dest Only"},
	{ }
};

void bnep_packet(const struct l2cap_frame *frame)
{
	uint8_t type;
	struct bnep_frame bnep_frame;
	struct l2cap_frame *l2cap_frame;
	const struct bnep_data *bnep_data = NULL;
	const char *pdu_color, *pdu_str;
	int i;

	l2cap_frame_pull(&bnep_frame.l2cap_frame, frame, 0);
	l2cap_frame = &bnep_frame.l2cap_frame;

	if (!l2cap_frame_get_u8(l2cap_frame, &type))
		goto fail;

	bnep_frame.extension = GET_EXTENSION(type);
	bnep_frame.type = GET_PKT_TYPE(type);

	for (i = 0; bnep_table[i].str; i++) {
		if (bnep_table[i].type == bnep_frame.type) {
			bnep_data = &bnep_table[i];
			break;
		}
	}

	if (bnep_data) {
		if (frame->in)
			pdu_color = COLOR_MAGENTA;
		else
			pdu_color = COLOR_BLUE;
		pdu_str = bnep_data->str;
	} else {
		pdu_color = COLOR_WHITE_BG;
		pdu_str = "Unknown packet type";
	}

	print_indent(6, pdu_color, "BNEP: ", pdu_str, COLOR_OFF,
				" (0x%02x|%s)", bnep_frame.type,
				bnep_frame.extension ? "1" : "0");

	packet_hexdump(l2cap_frame->data, l2cap_frame->size);
	return;

fail:
	print_text(COLOR_ERROR, "frame too short");
	packet_hexdump(frame->data, frame->size);
}
