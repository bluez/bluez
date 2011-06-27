/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011 Intel Corporation.
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>

#include "parser.h"

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

/* operands in passthrough commands */
#define AVC_PANEL_VOLUME_UP		0x41
#define AVC_PANEL_VOLUME_DOWN		0x42
#define AVC_PANEL_MUTE			0x43
#define AVC_PANEL_PLAY			0x44
#define AVC_PANEL_STOP			0x45
#define AVC_PANEL_PAUSE			0x46
#define AVC_PANEL_RECORD		0x47
#define AVC_PANEL_REWIND		0x48
#define AVC_PANEL_FAST_FORWARD		0x49
#define AVC_PANEL_EJECT			0x4a
#define AVC_PANEL_FORWARD		0x4b
#define AVC_PANEL_BACKWARD		0x4c

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

static char *op2str(uint8_t op)
{
	switch (op & 0x7f) {
	case AVC_PANEL_VOLUME_UP:
		return "VOLUME UP";
	case AVC_PANEL_VOLUME_DOWN:
		return "VOLUME DOWN";
	case AVC_PANEL_MUTE:
		return "MUTE";
	case AVC_PANEL_PLAY:
		return "PLAY";
	case AVC_PANEL_STOP:
		return "STOP";
	case AVC_PANEL_PAUSE:
		return "PAUSE";
	case AVC_PANEL_RECORD:
		return "RECORD";
	case AVC_PANEL_REWIND:
		return "REWIND";
	case AVC_PANEL_FAST_FORWARD:
		return "FAST FORWARD";
	case AVC_PANEL_EJECT:
		return "EJECT";
	case AVC_PANEL_FORWARD:
		return "FORWARD";
	case AVC_PANEL_BACKWARD:
		return "BACKWARD";
	default:
		return "UNKNOWN";
	}
}


static void avrcp_passthrough_dump(int level, struct frame *frm)
{
	uint8_t op, len;

	p_indent(level, frm);

	op = get_u8(frm);
	printf("Operation: 0x%02x (%s %s)\n", op, op2str(op),
					op & 0x80 ? "Released" : "Pressed");

	p_indent(level, frm);

	len = get_u8(frm);

	printf("Lenght: 0x%02x\n", len);

	raw_dump(level, frm);
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

void avrcp_dump(int level, struct frame *frm)
{
	uint8_t ctype, address, subunit, opcode;

	p_indent(level, frm);

	ctype = get_u8(frm);
	address = get_u8(frm);
	opcode = get_u8(frm);

	printf("AV/C: %s: address 0x%02x opcode 0x%02x\n", ctype2str(ctype),
							address, opcode);

	p_indent(level + 1, frm);

	subunit = address >> 3;
	printf("Subunit: %s\n", subunit2str(subunit));

	p_indent(level + 1, frm);

	printf("Opcode: %s\n", opcode2str(opcode));

	/* Skip non-panel subunit packets */
	if (subunit != AVC_SUBUNIT_PANEL) {
		raw_dump(level, frm);
		return;
	}

	switch (opcode) {
	case AVC_OP_PASSTHROUGH:
		avrcp_passthrough_dump(level + 1, frm);
		break;
	default:
		raw_dump(level, frm);
	}
}
