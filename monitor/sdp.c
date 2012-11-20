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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include <bluetooth/bluetooth.h>

#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "uuid.h"
#include "sdp.h"

#define SIZES(args...) ((uint8_t[]) { args, 0xff } )

static void print_uint(uint8_t indent, const uint8_t *data, uint32_t size)
{
	switch (size) {
	case 1:
		print_field("%*c0x%2.2x", indent, ' ', data[0]);
		break;
	case 2:
		print_field("%*c0x%4.4x", indent, ' ', bt_get_be16(data));
		break;
	case 4:
		print_field("%*c0x%8.8x", indent, ' ', bt_get_be32(data));
		break;
	}
}

static void print_uuid(uint8_t indent, const uint8_t *data, uint32_t size)
{
	switch (size) {
	case 2:
		print_field("%*c%s (0x%4.4x)", indent, ' ',
			uuid16_to_str(bt_get_be16(data)), bt_get_be16(data));
		break;
	}
}

static void print_string(uint8_t indent, const uint8_t *data, uint32_t size)
{
	char *str = strndupa((const char *) data, size);
	print_field("%*c%s [len %d]", indent, ' ', str, size);
}

static struct {
	uint8_t value;
	uint8_t *sizes;
	bool recurse;
	const char *str;
	void (*print) (uint8_t indent, const uint8_t *data, uint32_t size);
} type_table[] = {
	{ 0, SIZES(0),             false, "Nil"			},
	{ 1, SIZES(0, 1, 2, 3, 4), false, "Unsigned Integer",	print_uint },
	{ 2, SIZES(0, 1, 2, 3, 4), false, "Signed Integer"	},
	{ 3, SIZES(1, 2, 4),       false, "UUID",		print_uuid },
	{ 4, SIZES(5, 6, 7),       false, "String",		print_string },
	{ 5, SIZES(0),             false, "Boolean"		},
	{ 6, SIZES(5, 6, 7),       true,  "Sequence"		},
	{ 7, SIZES(5, 6, 7),       true,  "Alternative"		},
	{ 8, SIZES(5, 6, 7),       false, "URL",		print_string },
	{ }
};

static struct {
	uint8_t index;
	uint8_t bits;
	uint8_t size;
	const char *str;
} size_table[] = {
	{ 0,  0,  1, "1 byte"	},
	{ 1,  0,  2, "2 bytes"	},
	{ 2,  0,  4, "4 bytes"	},
	{ 3,  0,  8, "8 bytes"	},
	{ 4,  0, 16, "16 bytes"	},
	{ 5,  8,  0, "8 bits"	},
	{ 6, 16,  0, "16 bits"	},
	{ 7, 32,  0, "32 bits"	},
	{ }
};

static bool valid_size(uint8_t size, uint8_t *sizes)
{
	int i;

	for (i = 0; sizes[i] != 0xff; i++) {
		if (sizes[i] == size)
			return true;
	}

	return false;
}

static uint8_t get_bits(const uint8_t *data, uint16_t size)
{
	int i;

	for (i = 0; size_table[i].str; i++) {
		if (size_table[i].index == (data[0] & 0x07))
			return size_table[i].bits;
	}

	return 0;
}

static uint32_t get_size(const uint8_t *data, uint16_t size)
{
	int i;

	for (i = 0; size_table[i].str; i++) {
		if (size_table[i].index == (data[0] & 0x07)) {
			switch (size_table[i].bits) {
			case 0:
				if ((data[0] & 0xf8) == 0)
					return 0;
				else
					return size_table[i].size;
			case 8:
				return data[1];
			case 16:
				return bt_get_be16(data + 1);
			case 32:
				return bt_get_be32(data + 1);
			default:
				return 0;
			}
		}
	}

	return 0;
}

static void decode_data_elements(uint8_t indent,
					const uint8_t *data, uint16_t size)

{
	uint32_t datalen, elemlen;
	uint8_t extrabits;
	int i;

	if (!size)
		return;

	extrabits = get_bits(data, size);

	if (size < 1 + (extrabits / 8)) {
		print_text(COLOR_ERROR, "data element descriptor too short");
		return;
	}

	datalen = get_size(data, size);

	if (size < 1 + (extrabits / 8) + datalen) {
		print_text(COLOR_ERROR, "data element size too short");
		return;
	}

	elemlen = 1 + (extrabits / 8) + datalen;

	for (i = 0; type_table[i].str; i++) {
		uint8_t type = (data[0] & 0xf8) >> 3;

		if (type_table[i].value != type)
			continue;

		print_field("%*c%s (%d) with %u byte%s [%u extra bits] len %u",
					indent, ' ', type_table[i].str, type,
					datalen, datalen == 1 ? "" : "s",
					extrabits, elemlen);
		if (!valid_size(data[0] & 0x07, type_table[i].sizes)) {
			print_text(COLOR_ERROR, "invalid data element size");
			packet_hexdump(data + 1 + (extrabits / 8), datalen);
			break;
		}

		if (type_table[i].recurse)
			decode_data_elements(indent + 2,
					data + 1 + (extrabits / 8), datalen);
		else if (type_table[i].print)
			type_table[i].print(indent + 2,
					data + 1 + (extrabits / 8), datalen);
		break;
	}

	data += elemlen;
	size -= elemlen;

	decode_data_elements(indent, data, size);
}

static void print_continuation(const uint8_t *data, uint16_t size)
{
	if (data[0] != size - 1) {
		print_text(COLOR_ERROR, "invalid continuation state");
		packet_hexdump(data, size);
		return;
	}

	print_field("Continuation state: %d", data[0]);
	packet_hexdump(data + 1, size - 1);
}

static uint16_t get_bytes(const uint8_t *data, uint16_t size)
{
	switch (data[0] & 0x07) {
	case 5:
		return 2 + data[1];
	case 6:
		return 3 + bt_get_be16(data + 1);
	case 7:
		return 5 + bt_get_be32(data + 1);
	}

	return 0;
}

static void error_rsp(const struct l2cap_frame *frame)
{
	uint16_t error;

	if (frame->size < 2) {
		print_text(COLOR_ERROR, "invalid size");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	error = bt_get_be16(frame->data);

	print_field("Error code: 0x%2.2x", error);
}

static void service_req(const struct l2cap_frame *frame)
{
	uint16_t search_bytes;

	search_bytes = get_bytes(frame->data, frame->size);
	print_field("Search pattern: [len %d]", search_bytes);

	if (search_bytes > frame->size - 2) {
		print_text(COLOR_ERROR, "invalid search list length");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	decode_data_elements(2, frame->data, search_bytes);

	print_field("Max record count: %d",
				bt_get_be16(frame->data + search_bytes));

	print_continuation(frame->data + search_bytes + 2,
					frame->size - search_bytes - 2);
}

static void service_rsp(const struct l2cap_frame *frame)
{
	uint16_t count;
	int i;

	if (frame->size < 4) {
		print_text(COLOR_ERROR, "invalid size");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	count = bt_get_be16(frame->data + 2);

	print_field("Total record count: %d", bt_get_be16(frame->data));
	print_field("Current record count: %d", count);

	for (i = 0; i < count; i++)
		print_field("Record handle: 0x%4.4x",
				bt_get_be32(frame->data + 4 + (i * 4)));

	print_continuation(frame->data + 4 + (count * 4),
					frame->size - 4 - (count * 4));
}

static void attr_req(const struct l2cap_frame *frame)
{
	uint16_t attr_bytes;

	if (frame->size < 6) {
		print_text(COLOR_ERROR, "invalid size");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	print_field("Record handle: 0x%4.4x", bt_get_be32(frame->data));
	print_field("Max attribute bytes: %d", bt_get_be16(frame->data + 4));

	attr_bytes = get_bytes(frame->data + 6, frame->size - 6);
	print_field("Attribute list: [len %d]", attr_bytes);

	if (attr_bytes > frame->size - 6) {
		print_text(COLOR_ERROR, "invalid attribute list length");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	decode_data_elements(2, frame->data + 6, attr_bytes);

	print_continuation(frame->data + 6 + attr_bytes,
					frame->size - 6 - attr_bytes);
}

static void attr_rsp(const struct l2cap_frame *frame)
{
	uint16_t bytes;

	if (frame->size < 2) {
		print_text(COLOR_ERROR, "invalid size");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	bytes = bt_get_be16(frame->data);
	print_field("Attribute bytes: %d", bytes);

	if (bytes > frame->size - 2) {
		print_text(COLOR_ERROR, "invalid attribute size");
		return;
	}

	decode_data_elements(2, frame->data + 2, bytes);

	print_continuation(frame->data + 2 + bytes, frame->size - 2 - bytes);
}

static void search_attr_req(const struct l2cap_frame *frame)
{
	uint16_t search_bytes, attr_bytes;

	search_bytes = get_bytes(frame->data, frame->size);
	print_field("Search pattern: [len %d]", search_bytes);

	if (search_bytes > frame->size - 2) {
		print_text(COLOR_ERROR, "invalid search list length");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	decode_data_elements(2, frame->data, search_bytes);

	print_field("Max record count: %d",
				bt_get_be16(frame->data + search_bytes));

	attr_bytes = get_bytes(frame->data + search_bytes + 2,
				frame->size - search_bytes - 2);
	print_field("Attribte list: [len %d]", attr_bytes);

	decode_data_elements(2, frame->data + search_bytes + 2, attr_bytes);

	print_continuation(frame->data + search_bytes + 2 + attr_bytes,
				frame->size - search_bytes - 2 - attr_bytes);
}

static void search_attr_rsp(const struct l2cap_frame *frame)
{
	uint16_t bytes;

	if (frame->size < 2) {
		print_text(COLOR_ERROR, "invalid size");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	bytes = bt_get_be16(frame->data);
	print_field("Attribute list bytes: %d", bytes);

	decode_data_elements(2, frame->data + 2, bytes);

	print_continuation(frame->data + 2 + bytes, frame->size - 2 - bytes);
}

struct sdp_data {
	uint8_t pdu;
	const char *str;
	void (*func) (const struct l2cap_frame *frame);
};

static const struct sdp_data sdp_table[] = {
	{ 0x01, "Error Response",			error_rsp	},
	{ 0x02, "Service Search Request",		service_req	},
	{ 0x03, "Service Search Response",		service_rsp	},
	{ 0x04, "Service Attribute Request",		attr_req	},
	{ 0x05, "Service Attribute Response",		attr_rsp	},
	{ 0x06, "Service Search Attribute Request",	search_attr_req	},
	{ 0x07, "Service Search Attribute Response",	search_attr_rsp	},
	{ }
};

void sdp_packet(const struct l2cap_frame *frame)
{
	uint8_t pdu;
	uint16_t tid, plen;
	struct l2cap_frame sdp_frame;
	const struct sdp_data *sdp_data = NULL;
	const char *pdu_color, *pdu_str;

	int i;

	if (frame->size < 5) {
		print_text(COLOR_ERROR, "frame too short");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	pdu = *((uint8_t *) frame->data);
	tid = bt_get_be16(frame->data + 1);
	plen = bt_get_be16(frame->data + 3);

	if (frame->size != plen + 5) {
		print_text(COLOR_ERROR, "invalid frame size");
		packet_hexdump(frame->data, frame->size);
		return;
	}

	for (i = 0; sdp_table[i].str; i++) {
		if (sdp_table[i].pdu == pdu) {
			sdp_data = &sdp_table[i];
			break;
		}
	}

	if (sdp_data) {
		if (sdp_data->func) {
			if (frame->in)
				pdu_color = COLOR_MAGENTA;
			else
				pdu_color = COLOR_BLUE;
		} else
			pdu_color = COLOR_WHITE_BG;
		pdu_str = sdp_data->str;
	} else {
		pdu_color = COLOR_WHITE_BG;
		pdu_str = "Unknown";
	}

	print_indent(6, pdu_color, "SDP: ", pdu_str, COLOR_OFF,
				" (0x%2.2x) tid %d len %d", pdu, tid, plen);

	if (!sdp_data || !sdp_data->func) {
		packet_hexdump(frame->data + 5, frame->size - 5);
		return;
	}

	l2cap_frame_pull(&sdp_frame, frame, 5);
	sdp_data->func(&sdp_frame);
}
