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

uint16_t proto = 0x0000;

struct bnep_frame {
	uint8_t type;
	int extension;
	struct l2cap_frame l2cap_frame;
};

static bool get_macaddr(struct bnep_frame *bnep_frame, char *str)
{
	uint8_t addr[6];
	struct l2cap_frame *frame = &bnep_frame->l2cap_frame;
	int i;

	for (i = 0; i < 6; i++)
		if (!l2cap_frame_get_u8(frame, &addr[i]))
			return false;

	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	return true;
}

static bool bnep_general(struct bnep_frame *bnep_frame,
					uint8_t indent,	int hdr_len)
{
	struct l2cap_frame *frame;
	char src_addr[20], dest_addr[20];

	if (!get_macaddr(bnep_frame, dest_addr))
		return false;

	if (!get_macaddr(bnep_frame, src_addr))
		return false;

	frame = &bnep_frame->l2cap_frame;

	if (!l2cap_frame_get_be16(frame, &proto))
		return false;

	print_field("%*cdst %s src %s [proto 0x%04x] ", indent,
					' ', dest_addr, src_addr, proto);

	return true;

}

struct bnep_control_data {
	uint8_t type;
	const char *str;
};

static const struct bnep_control_data bnep_control_table[] = {
	{ 0x00, "Command Not Understood",	},
	{ 0x01, "Setup Conn Req",		},
	{ 0x02, "Setup Conn Rsp",		},
	{ 0x03, "Filter NetType Set",		},
	{ 0x04, "Filter NetType Rsp",		},
	{ 0x05, "Filter MultAddr Set",		},
	{ 0x06, "Filter MultAddr Rsp",		},
	{ }
};

static bool bnep_control(struct bnep_frame *bnep_frame,
					uint8_t indent,	int hdr_len)
{
	uint8_t ctype;
	struct l2cap_frame *frame = &bnep_frame->l2cap_frame;
	const struct bnep_control_data *bnep_control_data = NULL;
	const char *type_str;
	int i;

	if (!l2cap_frame_get_u8(frame, &ctype))
		return false;

	for (i = 0; bnep_control_table[i].str; i++) {
		if (bnep_control_table[i].type == ctype) {
			bnep_control_data = &bnep_control_table[i];
			break;
		}
	}

	if (bnep_control_data)
		type_str = bnep_control_data->str;
	else
		type_str = "Unknown control type";

	print_field("%*c%s (0x%02x) ", indent, ' ', type_str, ctype);

	/* TODO: Handle BNEP control types */

	return true;
}

struct bnep_data {
	uint8_t type;
	const char *str;
	bool (*func) (struct bnep_frame *frame, uint8_t indent, int hdr_len);
};

static const struct bnep_data bnep_table[] = {
	{ 0x00, "General Ethernet",		bnep_general	},
	{ 0x01, "Control",			bnep_control	},
	{ 0x02, "Compressed Ethernet",				},
	{ 0x03, "Compressed Ethernet SrcOnly",			},
	{ 0x04, "Compressed Ethernet DestOnly",			},
	{ }
};

void bnep_packet(const struct l2cap_frame *frame)
{
	uint8_t type, indent = 1;
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
		if (bnep_data->func) {
			if (frame->in)
				pdu_color = COLOR_MAGENTA;
			else
				pdu_color = COLOR_BLUE;
		} else
			pdu_color = COLOR_WHITE_BG;
		pdu_str = bnep_data->str;
	} else {
		pdu_color = COLOR_WHITE_BG;
		pdu_str = "Unknown packet type";
	}

	print_indent(6, pdu_color, "BNEP: ", pdu_str, COLOR_OFF,
				" (0x%02x|%s)", bnep_frame.type,
				bnep_frame.extension ? "1" : "0");

	if (!bnep_data || !bnep_data->func) {
		packet_hexdump(l2cap_frame->data, l2cap_frame->size);
		return;
	}

	if (!bnep_data->func(&bnep_frame, indent, -1))
		goto fail;

	/* TODO: Handle BNEP packet with Extension Header */
	packet_hexdump(l2cap_frame->data, l2cap_frame->size);

	return;

fail:
	print_text(COLOR_ERROR, "frame too short");
	packet_hexdump(frame->data, frame->size);
}
