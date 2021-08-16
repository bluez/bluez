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

#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>

#include "src/shared/util.h"
#include "display.h"
#include "packet.h"
#include "vendor.h"
#include "msft.h"

#define COLOR_COMMAND		COLOR_BLUE
#define COLOR_COMMAND_UNKNOWN	COLOR_WHITE_BG

static void null_cmd(const void *data, uint16_t size)
{
}

static void null_rsp(const void *data, uint16_t size)
{
}

static void read_supported_features_rsp(const void *data, uint16_t size)
{
	uint8_t evt_prefix_len = get_u8(data + 8);

	packet_print_features_msft(data);
	print_field("Event prefix length: %u", evt_prefix_len);
	packet_hexdump(data + 9, size - 9);

	packet_set_msft_evt_prefix(data + 9, evt_prefix_len);
}

static void le_monitor_advertisement_cmd(const void *data, uint16_t size)
{
	int8_t threshold_high = get_s8(data);
	int8_t threshold_low = get_s8(data + 1);
	uint8_t threshold_low_time_interval = get_u8(data + 2);
	uint8_t sampling_period = get_u8(data + 3);

	packet_print_rssi("RSSI threshold high", threshold_high);
	packet_print_rssi("RSSI threshold low", threshold_low);
	print_field("RSSI threshold low time interval: %u sec (0x%2.2x)",
						threshold_low_time_interval,
						threshold_low_time_interval);
	print_field("RSSI sampling period: %u msec (0x%2.2x)",
						sampling_period * 100,
						sampling_period);
	packet_hexdump(data + 4, size - 4);
}

static void le_monitor_advertisement_rsp(const void *data, uint16_t size)
{
	uint8_t handle = get_u8(data);

	print_field("Monitor handle: %u", handle);
}

static void set_adv_filter_enable_cmd(const void *data, uint16_t size)
{
	uint8_t enable = get_u8(data);
	const char *str;

	switch (enable) {
	case 0x00:
		str = "Current allow list";
		break;
	case 0x01:
		str = "All filter conditions";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Enable: %s (0x%2.2x)", str, enable);
}

typedef void (*func_t) (const void *data, uint16_t size);

static const struct {
	uint8_t code;
	const char *str;
	func_t cmd_func;
	func_t rsp_func;
} cmd_table[] = {
	{ 0x00, "Read Supported Features",
			null_cmd,
			read_supported_features_rsp },
	{ 0x01, "Monitor RSSI" },
	{ 0x02, "Cancel Monitor RSSI" },
	{ 0x03, "LE Monitor Advertisement",
			le_monitor_advertisement_cmd,
			le_monitor_advertisement_rsp },
	{ 0x04, "LE Cancel Monitor Advertisement" },
	{ 0x05, "LE Set Advertisement Filter Enable",
			set_adv_filter_enable_cmd,
			null_rsp },
	{ 0x06, "Read Absolute RSSI" },
	{ }
};

static void msft_cmd(const void *data, uint8_t size)
{
	uint8_t code = get_u8(data);
	const char *code_color, *code_str = NULL;
	func_t code_func = NULL;
	int i;

	for (i = 0; cmd_table[i].str; i++) {
		if (cmd_table[i].code == code) {
			code_str = cmd_table[i].str;
			code_func = cmd_table[i].cmd_func;
			break;
		}
	}

	if (code_str) {
		if (code_func)
			code_color = COLOR_COMMAND;
		else
			code_color = COLOR_COMMAND_UNKNOWN;
	} else {
		code_color = COLOR_COMMAND_UNKNOWN;
		code_str = "Unknown";
	}

	print_indent(6, code_color, "", code_str, COLOR_OFF,
						" (0x%2.2x)", code);

	if (code_func)
		code_func(data + 1, size - 1);
	else
		packet_hexdump(data + 1, size - 1);
}

static void msft_rsp(const void *data, uint8_t size)
{
	uint8_t status = get_u8(data);
	uint8_t code = get_u8(data + 1);
	const char *code_color, *code_str = NULL;
	func_t code_func = NULL;
	int i;

	for (i = 0; cmd_table[i].str; i++) {
		if (cmd_table[i].code == code) {
			code_str = cmd_table[i].str;
			code_func = cmd_table[i].rsp_func;
			break;
		}
	}

	if (code_str) {
		if (code_func)
			code_color = COLOR_COMMAND;
		else
			code_color = COLOR_COMMAND_UNKNOWN;
	} else {
		code_color = COLOR_COMMAND_UNKNOWN;
		code_str = "Unknown";
	}

	print_indent(6, code_color, "", code_str, COLOR_OFF,
						" (0x%2.2x)", code);

	packet_print_error("Status", status);

	if (code_func)
		code_func(data + 2, size - 2);
	else
		packet_hexdump(data + 2, size - 2);
}

static const struct vendor_ocf vendor_ocf_entry = {
	0x000, "Extension", msft_cmd, 1, false, msft_rsp, 2, false
};

const struct vendor_ocf *msft_vendor_ocf(void)
{
	return &vendor_ocf_entry;
}

static void msft_evt(const void *data, uint8_t size)
{
	packet_hexdump(data, size);
}

static const struct vendor_evt vendor_evt_entry = {
	0x00, "Extension", msft_evt, 1, false
};

const struct vendor_evt *msft_vendor_evt(void)
{
	return &vendor_evt_entry;
}
