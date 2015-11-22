/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Andrzej Kaczmarek <andrzej.kaczmarek@codecoup.pl>
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

#include "lib/bluetooth.h"

#include "src/shared/util.h"
#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "a2dp.h"

#define BASE_INDENT	4

/* Codec Types */
#define A2DP_CODEC_SBC		0x00
#define A2DP_CODEC_MPEG12	0x01
#define A2DP_CODEC_MPEG24	0x02
#define A2DP_CODEC_ATRAC	0x04
#define A2DP_CODEC_VENDOR	0xff

struct bit_desc {
	uint8_t bit_num;
	const char *str;
};

static const struct bit_desc sbc_frequency_table[] = {
	{  7, "16000" },
	{  6, "32000" },
	{  5, "44100" },
	{  4, "48000" },
	{ }
};

static const struct bit_desc sbc_channel_mode_table[] = {
	{  3, "Mono" },
	{  2, "Dual Channel" },
	{  1, "Stereo" },
	{  0, "Joint Stereo" },
	{ }
};

static const struct bit_desc sbc_blocklen_table[] = {
	{  7, "4" },
	{  6, "8" },
	{  5, "12" },
	{  4, "16" },
	{ }
};

static const struct bit_desc sbc_subbands_table[] = {
	{  3, "4" },
	{  2, "8" },
	{ }
};

static const struct bit_desc sbc_allocation_table[] = {
	{  1, "SNR" },
	{  0, "Loudness" },
	{ }
};

static void print_value_bits(uint8_t indent, uint32_t value,
						const struct bit_desc *table)
{
	int i;

	for (i = 0; table[i].str; i++) {
		if (value & (1 << table[i].bit_num))
			print_field("%*c%s", indent + 2, ' ', table[i].str);
	}
}

static const char *find_value_bit(uint32_t value,
						const struct bit_desc *table)
{
	int i;

	for (i = 0; table[i].str; i++) {
		if (value & (1 << table[i].bit_num))
			return table[i].str;
	}

	return "Unknown";
}

static bool codec_sbc_cap(uint8_t losc, struct l2cap_frame *frame)
{
	uint8_t cap = 0;

	if (losc != 4)
		return false;

	l2cap_frame_get_u8(frame, &cap);

	print_field("%*cFrequency: 0x%02x", BASE_INDENT, ' ', cap & 0xf0);
	print_value_bits(BASE_INDENT, cap & 0xf0, sbc_frequency_table);

	print_field("%*cChannel Mode: 0x%02x", BASE_INDENT, ' ', cap & 0x0f);
	print_value_bits(BASE_INDENT, cap & 0x0f, sbc_channel_mode_table);

	l2cap_frame_get_u8(frame, &cap);

	print_field("%*cBlock Length: 0x%02x", BASE_INDENT, ' ', cap & 0xf0);
	print_value_bits(BASE_INDENT, cap & 0xf0, sbc_blocklen_table);

	print_field("%*cSubbands: 0x%02x", BASE_INDENT, ' ', cap & 0x0c);
	print_value_bits(BASE_INDENT, cap & 0x0c, sbc_subbands_table);

	print_field("%*cAllocation Method: 0x%02x", BASE_INDENT, ' ',
								cap & 0x03);
	print_value_bits(BASE_INDENT, cap & 0x03, sbc_allocation_table);

	l2cap_frame_get_u8(frame, &cap);

	print_field("%*cMinimum Bitpool: %d", BASE_INDENT, ' ', cap);

	l2cap_frame_get_u8(frame, &cap);

	print_field("%*cMaximum Bitpool: %d", BASE_INDENT, ' ', cap);

	return true;
}

static bool codec_sbc_cfg(uint8_t losc, struct l2cap_frame *frame)
{
	uint8_t cap = 0;

	if (losc != 4)
		return false;

	l2cap_frame_get_u8(frame, &cap);

	print_field("%*cFrequency: %s (0x%02x)", BASE_INDENT, ' ',
			find_value_bit(cap & 0xf0, sbc_frequency_table),
			cap & 0xf0);

	print_field("%*cChannel Mode: %s (0x%02x)", BASE_INDENT, ' ',
			find_value_bit(cap & 0x0f, sbc_channel_mode_table),
			cap & 0x0f);

	l2cap_frame_get_u8(frame, &cap);

	print_field("%*cBlock Length: %s (0x%02x)", BASE_INDENT, ' ',
			find_value_bit(cap & 0xf0, sbc_blocklen_table),
			cap & 0xf0);

	print_field("%*cSubbands: %s (0x%02x)", BASE_INDENT, ' ',
			find_value_bit(cap & 0x0c, sbc_subbands_table),
			cap & 0x0c);

	print_field("%*cAllocation Method: %s (0x%02x)", BASE_INDENT, ' ',
			find_value_bit(cap & 0x03, sbc_allocation_table),
			cap & 0x03);

	l2cap_frame_get_u8(frame, &cap);

	print_field("%*cMinimum Bitpool: %d", BASE_INDENT, ' ', cap);

	l2cap_frame_get_u8(frame, &cap);

	print_field("%*cMaximum Bitpool: %d", BASE_INDENT, ' ', cap);

	return true;
}

bool a2dp_codec_cap(uint8_t codec, uint8_t losc, struct l2cap_frame *frame)
{
	switch (codec) {
	case A2DP_CODEC_SBC:
		return codec_sbc_cap(losc, frame);
	default:
		packet_hexdump(frame->data, losc);
		l2cap_frame_pull(frame, frame, losc);
		return true;
	}
}

bool a2dp_codec_cfg(uint8_t codec, uint8_t losc, struct l2cap_frame *frame)
{
	switch (codec) {
	case A2DP_CODEC_SBC:
		return codec_sbc_cfg(losc, frame);
	default:
		packet_hexdump(frame->data, losc);
		l2cap_frame_pull(frame, frame, losc);
		return true;
	}
}
