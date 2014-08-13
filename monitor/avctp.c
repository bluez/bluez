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
#include "avctp.h"

static const char *ctype2str(uint8_t ctype)
{
	return "Unknown";
}

static const char *subunit2str(uint8_t subunit)
{
	return "Reserved";
}

static const char *opcode2str(uint8_t opcode)
{
	return "Unknown";
}

static void avrcp_passthrough_packet(const struct l2cap_frame *frame)
{
}

static void avrcp_pdu_packet(const struct l2cap_frame *frame, uint8_t ctype,
				uint8_t indent)
{
}

static void avrcp_control_packet(const struct l2cap_frame *frame)
{
	uint8_t ctype, address, subunit, opcode, indent = 2;
	struct l2cap_frame avrcp_frame;

	ctype = *((uint8_t *) frame->data);
	address = *((uint8_t *) (frame->data + 1));
	opcode = *((uint8_t *) (frame->data + 2));

	print_field("AV/C: %s: address 0x%02x opcode 0x%02x",
				ctype2str(ctype), address, opcode);

	subunit = address >> 3;

	print_field("%*cSubunit: %s", indent, ' ', subunit2str(subunit));

	print_field("%*cOpcode: %s", indent, ' ', opcode2str(opcode));

	/* Skip non-panel subunit packets */
	if (subunit != 0x09) {
		packet_hexdump(frame->data, frame->size);
		return;
	}

	/* Not implemented should not contain any operand */
	if (ctype == 0x8) {
		packet_hexdump(frame->data, frame->size);
		return;
	}

	switch (opcode) {
	case 0x7c:
		avrcp_passthrough_packet(frame);
		break;
	case 0x00:
		print_field("%*cCompany ID: 0x%02x%02x%02x", indent, ' ',
					*((uint8_t *) (frame->data + 3)),
					*((uint8_t *) (frame->data + 4)),
					*((uint8_t *) (frame->data + 5)));

		l2cap_frame_pull(&avrcp_frame, frame, 6);
		avrcp_pdu_packet(&avrcp_frame, ctype, 10);
		break;
	default:
		packet_hexdump(frame->data, frame->size);
	}
}

static void avrcp_browsing_packet(const struct l2cap_frame *frame, uint8_t hdr)
{
}

static void avrcp_packet(const struct l2cap_frame *frame, uint8_t hdr)
{
	switch (frame->psm) {
	case 0x17:
		avrcp_control_packet(frame);
		break;
	case 0x1B:
		avrcp_browsing_packet(frame, hdr);
		break;
	default:
		packet_hexdump(frame->data, frame->size);
	}
}

void avctp_packet(const struct l2cap_frame *frame)
{
	uint8_t hdr;
	uint16_t pid;
	struct l2cap_frame avctp_frame;
	const char *pdu_color;

	if (frame->size < 3) {
		print_text(COLOR_ERROR, "frame too short");
		packet_hexdump(frame->data, frame->size);
		return;
        }

	hdr = *((uint8_t *) frame->data);

	pid = get_be16(frame->data + 1);

	if (frame->in)
		pdu_color = COLOR_MAGENTA;
	else
		pdu_color = COLOR_BLUE;

	print_indent(6, pdu_color, "AVCTP", "", COLOR_OFF,
				" %s: %s: type 0x%02x label %d PID 0x%04x",
				frame->psm == 23 ? "Control" : "Browsing",
				hdr & 0x02 ? "Response" : "Command",
				hdr & 0x0c, hdr >> 4, pid);

	l2cap_frame_pull(&avctp_frame, frame, 3);

	if (pid == 0x110e || pid == 0x110c)
		avrcp_packet(&avctp_frame, hdr);
	else
		packet_hexdump(frame->data + 3, frame->size - 3);
}
