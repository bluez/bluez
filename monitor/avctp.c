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

/* ctype entries */
#define AVC_CTYPE_CONTROL		0x0
#define AVC_CTYPE_STATUS		0x1
#define AVC_CTYPE_SPECIFIC_INQUIRY	0x2
#define AVC_CTYPE_NOTIFY		0x3
#define AVC_CTYPE_GENERAL_INQUIRY	0x4
#define AVC_CTYPE_NOT_IMPLEMENTED	0x8
#define AVC_CTYPE_ACCEPTED		0x9
#define AVC_CTYPE_REJECTED		0xA
#define AVC_CTYPE_IN_TRANSITION		0xB
#define AVC_CTYPE_STABLE		0xC
#define AVC_CTYPE_CHANGED		0xD
#define AVC_CTYPE_INTERIM		0xF

/* subunit type */
#define AVC_SUBUNIT_MONITOR		0x00
#define AVC_SUBUNIT_AUDIO		0x01
#define AVC_SUBUNIT_PRINTER		0x02
#define AVC_SUBUNIT_DISC		0x03
#define AVC_SUBUNIT_TAPE		0x04
#define AVC_SUBUNIT_TURNER		0x05
#define AVC_SUBUNIT_CA			0x06
#define AVC_SUBUNIT_CAMERA		0x07
#define AVC_SUBUNIT_PANEL		0x09
#define AVC_SUBUNIT_BULLETIN_BOARD	0x0a
#define AVC_SUBUNIT_CAMERA_STORAGE	0x0b
#define AVC_SUBUNIT_VENDOR_UNIQUE	0x0c
#define AVC_SUBUNIT_EXTENDED		0x1e
#define AVC_SUBUNIT_UNIT		0x1f

/* opcodes */
#define AVC_OP_VENDORDEP		0x00
#define AVC_OP_UNITINFO			0x30
#define AVC_OP_SUBUNITINFO		0x31
#define AVC_OP_PASSTHROUGH		0x7c

static const char *ctype2str(uint8_t ctype)
{
	switch (ctype & 0x0f) {
	case AVC_CTYPE_CONTROL:
		return "Control";
	case AVC_CTYPE_STATUS:
		return "Status";
	case AVC_CTYPE_SPECIFIC_INQUIRY:
		return "Specific Inquiry";
	case AVC_CTYPE_NOTIFY:
		return "Notify";
	case AVC_CTYPE_GENERAL_INQUIRY:
		return "General Inquiry";
	case AVC_CTYPE_NOT_IMPLEMENTED:
		return "Not Implemented";
	case AVC_CTYPE_ACCEPTED:
		return "Accepted";
	case AVC_CTYPE_REJECTED:
		return "Rejected";
	case AVC_CTYPE_IN_TRANSITION:
		return "In Transition";
	case AVC_CTYPE_STABLE:
		return "Stable";
	case AVC_CTYPE_CHANGED:
		return "Changed";
	case AVC_CTYPE_INTERIM:
		return "Interim";
	default:
		return "Unknown";
	}
}

static const char *subunit2str(uint8_t subunit)
{
	switch (subunit) {
	case AVC_SUBUNIT_MONITOR:
		return "Monitor";
	case AVC_SUBUNIT_AUDIO:
		return "Audio";
	case AVC_SUBUNIT_PRINTER:
		return "Printer";
	case AVC_SUBUNIT_DISC:
		return "Disc";
	case AVC_SUBUNIT_TAPE:
		return "Tape";
	case AVC_SUBUNIT_TURNER:
		return "Turner";
	case AVC_SUBUNIT_CA:
		return "CA";
	case AVC_SUBUNIT_CAMERA:
		return "Camera";
	case AVC_SUBUNIT_PANEL:
		return "Panel";
	case AVC_SUBUNIT_BULLETIN_BOARD:
		return "Bulleting Board";
	case AVC_SUBUNIT_CAMERA_STORAGE:
		return "Camera Storage";
	case AVC_SUBUNIT_VENDOR_UNIQUE:
		return "Vendor Unique";
	case AVC_SUBUNIT_EXTENDED:
		return "Extended to next byte";
	case AVC_SUBUNIT_UNIT:
		return "Unit";
	default:
		return "Reserved";
	}
}

static const char *opcode2str(uint8_t opcode)
{
	switch (opcode) {
	case AVC_OP_VENDORDEP:
		return "Vendor Dependent";
	case AVC_OP_UNITINFO:
		return "Unit Info";
	case AVC_OP_SUBUNITINFO:
		return "Subunit Info";
	case AVC_OP_PASSTHROUGH:
		return "Passthrough";
	default:
		return "Unknown";
	}
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
