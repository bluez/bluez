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

#include "lib/bluetooth.h"
#include "lib/uuid.h"

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
	const struct msft_rsp_read_supported_features *rsp = data;

	packet_print_features_msft(rsp->features);
	print_field("Event prefix length: %u", rsp->evt_prefix_len);
	print_field("Event prefix:");
	packet_hexdump(rsp->evt_prefix, rsp->evt_prefix_len);
	packet_set_msft_evt_prefix(rsp->evt_prefix, rsp->evt_prefix_len);
}

static void monitor_rssi_cmd(const void *data, uint16_t size)
{
	const struct msft_cmd_monitor_rssi *cmd = data;

	print_field("Connection handle: 0x%04x", cmd->handle);
	packet_print_rssi("RSSI threshold high", cmd->rssi_high);
	packet_print_rssi("RSSI threshold low", cmd->rssi_low);
	print_field("RSSI threshold low time interval: %u sec (0x%2.2x)",
						cmd->rssi_low_interval,
						cmd->rssi_low_interval);
	print_field("RSSI sampling period: %u msec (0x%2.2x)",
						cmd->rssi_period * 100,
						cmd->rssi_period);
}

static void cancel_monitor_rssi_cmd(const void *data, uint16_t size)
{
	const struct msft_cmd_cancel_monitor_rssi *cmd = data;

	print_field("Connection handle: 0x%04x", cmd->handle);
}

static void le_monitor_advertisement_cmd(const void *data, uint16_t size)
{
	const struct msft_cmd_le_monitor_adv *cmd = data;
	const struct msft_le_monitor_adv_patterns *patterns;
	const struct msft_le_monitor_adv_uuid *uuid;
	const struct msft_le_monitor_adv_irk *irk;
	const struct msft_le_monitor_adv_addr *addr;
	const char *str;
	char uuidstr[MAX_LEN_UUID_STR];

	packet_print_rssi("RSSI threshold high", cmd->rssi_high);
	packet_print_rssi("RSSI threshold low", cmd->rssi_low);
	print_field("RSSI threshold low time interval: %u sec (0x%2.2x)",
						cmd->rssi_low_interval,
						cmd->rssi_low_interval);
	print_field("RSSI sampling period: %u msec (0x%2.2x)",
						cmd->rssi_period * 100,
						cmd->rssi_period);

	switch (cmd->type) {
	case MSFT_LE_MONITOR_ADV_PATTERN:
		print_field("Type: Pattern (0x%2.2x)", cmd->type);
		patterns = (void *)cmd->data;
		print_field("Number of patterns: %u", patterns->num);
		packet_hexdump((void *)patterns->data,
			       size - (sizeof(*cmd) + sizeof(*patterns)));
		break;
	case MSFT_LE_MONITOR_ADV_UUID:
		print_field("Type: UUID (0x%2.2x)", cmd->type);
		uuid = (void *)cmd->data;

		switch (uuid->type) {
		case 0x01:
			str = bt_uuid16_to_str(uuid->value.u16);
			print_field("UUID: %s (0x%4.4x)", str, uuid->value.u16);
			break;
		case 0x02:
			str = bt_uuid32_to_str(uuid->value.u32);
			print_field("UUID: %s (0x%8.8x)", str, uuid->value.u32);
			break;
		case 0x03:
			sprintf(uuidstr, "%8.8x-%4.4x-%4.4x-%4.4x-%8.8x%4.4x",
				get_le32(uuid->value.u128 + 12),
				get_le16(uuid->value.u128 + 10),
				get_le16(uuid->value.u128 + 8),
				get_le16(uuid->value.u128 + 6),
				get_le32(uuid->value.u128 + 2),
				get_le16(uuid->value.u128 + 0));
			str = bt_uuidstr_to_str(uuidstr);
			print_field("UUID: %s (%s)", str, uuidstr);
			break;
		default:
			packet_hexdump((void *)&uuid->value,
					size - sizeof(*cmd));
			break;
		}
		break;
	case MSFT_LE_MONITOR_ADV_IRK:
		print_field("Type: IRK (0x%2.2x)", cmd->type);
		irk = (void *)cmd->data;
		print_field("IRK:");
		packet_hexdump(irk->irk, size - sizeof(*cmd));
		break;
	case MSFT_LE_MONITOR_ADV_ADDR:
		print_field("Type: Adderss (0x%2.2x)", cmd->type);
		addr = (void *)cmd->data;
		packet_print_addr(NULL, addr->addr, addr->type);
		break;
	default:
		print_field("Type: Unknown (0x%2.2x)", cmd->type);
		packet_hexdump(cmd->data, size - sizeof(*cmd));
		break;
	}
}

static void le_monitor_advertisement_rsp(const void *data, uint16_t size)
{
	const struct msft_rsp_le_monitor_adv *rsp = data;

	print_field("Monitor handle: %u", rsp->handle);
}

static void le_cancel_monitor_adv_cmd(const void *data, uint16_t size)
{
	const struct msft_cmd_le_cancel_monitor_adv *cmd = data;

	print_field("Monitor handle: %u", cmd->handle);
}

static void set_adv_filter_enable_cmd(const void *data, uint16_t size)
{
	const struct msft_cmd_le_monitor_adv_enable *cmd = data;
	const char *str;

	switch (cmd->enable) {
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

	print_field("Enable: %s (0x%2.2x)", str, cmd->enable);
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
	{ 0x01, "Monitor RSSI",
			monitor_rssi_cmd },
	{ 0x02, "Cancel Monitor RSSI",
			cancel_monitor_rssi_cmd },
	{ 0x03, "LE Monitor Advertisement",
			le_monitor_advertisement_cmd,
			le_monitor_advertisement_rsp },
	{ 0x04, "LE Cancel Monitor Advertisement",
			le_cancel_monitor_adv_cmd },
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
		code_func(data, size);
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
		code_func(data, size);
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
