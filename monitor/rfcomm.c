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

#include <bluetooth/bluetooth.h>

#include "src/shared/util.h"
#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "uuid.h"
#include "keys.h"
#include "sdp.h"
#include "rfcomm.h"

#define GET_LEN8(length) ((length & 0xfe) >> 1)
#define GET_LEN16(length) ((length & 0xfffe) >> 1)
#define GET_CR(type)	((type & 0x02) >> 1)
#define GET_PF(ctr) (((ctr) >> 4) & 0x1)

struct rfcomm_lhdr {
	uint8_t address;
	uint8_t control;
	uint16_t length;
	uint8_t fcs;
	uint8_t credits; /* only for UIH frame */
} __attribute__((packed));

struct rfcomm_frame {
	struct rfcomm_lhdr hdr;
	struct l2cap_frame l2cap_frame;
};

static void print_rfcomm_hdr(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	struct rfcomm_lhdr hdr = rfcomm_frame->hdr;

	/* Address field */
	print_field("%*cAddress: 0x%2.2x cr %d dlci 0x%2.2x", indent, ' ',
					hdr.address, GET_CR(hdr.address),
					RFCOMM_GET_DLCI(hdr.address));

	/* Control field */
	print_field("%*cControl: 0x%2.2x poll/final %d", indent, ' ',
					hdr.control, GET_PF(hdr.control));

	/* Length and FCS */
	print_field("%*cLength: %d", indent, ' ', hdr.length);
	print_field("%*cFCS: 0x%2.2x", indent, ' ', hdr.fcs);
}

static bool uih_frame(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	uint8_t credits;
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	struct rfcomm_lhdr *hdr = &rfcomm_frame->hdr;

	if (!RFCOMM_GET_CHANNEL(hdr->address)) {
		/* MCC frame parser implementation */
		goto done;
	}

	/* fetching credits from UIH frame */
	if (GET_PF(hdr->control)) {
		if (!l2cap_frame_get_u8(frame, &credits))
			return false;
		hdr->credits = credits;
		print_field("%*cCredits: %d", indent, ' ', hdr->credits);
		return true;
	}

done:
	packet_hexdump(frame->data, frame->size);
	return true;
}

struct rfcomm_data {
	uint8_t frame;
	const char *str;
};

static const struct rfcomm_data rfcomm_table[] = {
	{ 0x2f, "Set Async Balance Mode (SABM) " },
	{ 0x63, "Unnumbered Ack (UA)" },
	{ 0x0f, "Disconnect Mode (DM)" },
	{ 0x43, "Disconnect (DISC)" },
	{ 0xef, "Unnumbered Info with Header Check (UIH)" },
	{ }
};

void rfcomm_packet(const struct l2cap_frame *frame)
{
	uint8_t ctype, length, ex_length, indent = 1;
	const char *frame_str, *frame_color;
	struct l2cap_frame *l2cap_frame, tmp_frame;
	struct rfcomm_frame rfcomm_frame;
	struct rfcomm_lhdr hdr;
	const struct rfcomm_data *rfcomm_data = NULL;
	int i;

	l2cap_frame_pull(&rfcomm_frame.l2cap_frame, frame, 0);

	l2cap_frame = &rfcomm_frame.l2cap_frame;

	if (frame->size < 4)
		goto fail;

	if (!l2cap_frame_get_u8(l2cap_frame, &hdr.address) ||
			!l2cap_frame_get_u8(l2cap_frame, &hdr.control) ||
			!l2cap_frame_get_u8(l2cap_frame, &length))
		goto fail;

	/* length maybe 1 or 2 octets */
	if (RFCOMM_TEST_EA(length))
		hdr.length = (uint16_t) GET_LEN8(length);
	else {
		if (!l2cap_frame_get_u8(l2cap_frame, &ex_length))
			goto fail;
		hdr.length = ((uint16_t)length << 8) | ex_length;
		hdr.length = GET_LEN16(hdr.length);
	}

	l2cap_frame_pull(&tmp_frame, l2cap_frame, l2cap_frame->size-1);

	if(!l2cap_frame_get_u8(&tmp_frame, &hdr.fcs))
		goto fail;

	/* Decoding frame type */
	ctype = RFCOMM_GET_TYPE(hdr.control);

	for (i = 0; rfcomm_table[i].str; i++) {
		if (rfcomm_table[i].frame == ctype) {
			rfcomm_data = &rfcomm_table[i];
			break;
		}
	}

	if (rfcomm_data) {
		if (frame->in)
			frame_color = COLOR_MAGENTA;
		else
			frame_color = COLOR_BLUE;
		frame_str = rfcomm_data->str;
	} else {
		frame_color = COLOR_WHITE_BG;
		frame_str = "Unknown";
	}

	if (!rfcomm_data) {
		packet_hexdump(frame->data, frame->size);
		return;
	}

	print_indent(6, frame_color, "RFCOMM: ", frame_str, COLOR_OFF,
						"(0x%2.2x)", ctype);

	rfcomm_frame.hdr = hdr;
	print_rfcomm_hdr(&rfcomm_frame, indent);

	/* UIH frame */
	if (ctype == 0xef)
		if (!uih_frame(&rfcomm_frame, indent))
			goto fail;

	return;

fail:
	print_text(COLOR_ERROR, "Frame too short");
	packet_hexdump(frame->data, frame->size);
	return;
}
