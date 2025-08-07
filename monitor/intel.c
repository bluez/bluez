// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011-2014  Intel Corporation
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <inttypes.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"

#include "src/shared/util.h"
#include "display.h"
#include "packet.h"
#include "lmp.h"
#include "ll.h"
#include "vendor.h"
#include "intel.h"

#define COLOR_UNKNOWN_EVENT_MASK	COLOR_WHITE_BG
#define COLOR_UNKNOWN_SCAN_STATUS	COLOR_WHITE_BG
#define COLOR_UNKNOWN_EXT_EVENT		COLOR_WHITE_BG

static void print_status(uint8_t status)
{
	packet_print_error("Status", status);
}

static void print_module(uint8_t module)
{
	const char *str;

	switch (module) {
	case 0x01:
		str = "BC";
		break;
	case 0x02:
		str = "HCI";
		break;
	case 0x03:
		str = "LLC";
		break;
	case 0x04:
		str = "OS";
		break;
	case 0x05:
		str = "LM";
		break;
	case 0x06:
		str = "SC";
		break;
	case 0x07:
		str = "SP";
		break;
	case 0x08:
		str = "OSAL";
		break;
	case 0x09:
		str = "LC";
		break;
	case 0x0a:
		str = "APP";
		break;
	case 0x0b:
		str = "TLD";
		break;
	case 0xf0:
		str = "Debug";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Module: %s (0x%2.2x)", str, module);
}

static void null_cmd(uint16_t index, const void *data, uint8_t size)
{
}

static void status_rsp(uint16_t index, const void *data, uint8_t size)
{
	uint8_t status = get_u8(data);

	print_status(status);
}

static void reset_cmd(uint16_t index, const void *data, uint8_t size)
{
	uint8_t reset_type = get_u8(data);
	uint8_t patch_enable = get_u8(data + 1);
	uint8_t ddc_reload = get_u8(data + 2);
	uint8_t boot_option = get_u8(data + 3);
	uint32_t boot_addr = get_le32(data + 4);
	const char *str;

	switch (reset_type) {
	case 0x00:
		str = "Soft software reset";
		break;
	case 0x01:
		str = "Hard software reset";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Reset type: %s (0x%2.2x)", str, reset_type);

	switch (patch_enable) {
	case 0x00:
		str = "Do not enable";
		break;
	case 0x01:
		str = "Enable";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Patch vectors: %s (0x%2.2x)", str, patch_enable);

	switch (ddc_reload) {
	case 0x00:
		str = "Do not reload";
		break;
	case 0x01:
		str = "Reload from OTP";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("DDC parameters: %s (0x%2.2x)", str, ddc_reload);

	switch (boot_option) {
	case 0x00:
		str = "Current image";
		break;
	case 0x01:
		str = "Specified address";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Boot option: %s (0x%2.2x)", str, boot_option);
	print_field("Boot address: 0x%8.8x", boot_addr);
}

struct intel_version_tlv {
	uint8_t type;
	uint8_t len;
	uint8_t val[];
};

static void print_version_tlv_u32(const struct intel_version_tlv *tlv,
				  const char *type_str)
{
	print_field("%s(%u): 0x%8.8x", type_str, tlv->type, get_le32(tlv->val));
}

static void print_version_tlv_u16(const struct intel_version_tlv *tlv,
				  const char *type_str)
{
	print_field("%s(%u): 0x%4.4x", type_str, tlv->type, get_le16(tlv->val));
}

static void print_version_tlv_u8(const struct intel_version_tlv *tlv,
				 const char *type_str)
{
	print_field("%s(%u): 0x%2.2x", type_str, tlv->type, get_u8(tlv->val));
}

static void print_version_tlv_enabled(const struct intel_version_tlv *tlv,
				      const char *type_str)
{
	print_field("%s(%u): %s(%u)", type_str, tlv->type,
					tlv->val[0] ? "Enabled" : "Disabled",
					tlv->val[0]);
}

static void print_version_tlv_cnvi_bt(const struct intel_version_tlv *tlv,
				      const char *type_str)
{
	const char *str;
	uint32_t cnvibt = get_le32(tlv->val);
	uint8_t variant = (cnvibt >> 16) & 0x3f;

	switch (variant) {
	case 0x17:
		str = "Typhoon Peak2";
		break;
	case 0x18:
		str = "Solar";
		break;
	case 0x19:
		str = "Solar F";
		break;
	case 0x1b:
		str = "Magnetor";
		break;
	case 0x1c:
		str = "Gale Peak2";
		break;
	case 0x1d:
		str = "BlazarU";
		break;
	case 0x1e:
		str = "BlazarI";
		break;
	case 0x1f:
		str = "Scorpious Peak";
		break;
	case 0x22:
		str = "BlazarIW";
		break;
	default:
		str = "Unknown";
		break;
	}

	print_field("%s(%u): 0x%8.8x - %s(0x%2.2x)", type_str, tlv->type,
			cnvibt, str, variant);
}

static void print_version_tlv_img_type(const struct intel_version_tlv *tlv,
				       const char *type_str)
{
	const char *str;

	switch (get_u8(tlv->val)) {
	case 0x01:
		str = "Bootloader";
		break;
	case 0x03:
		str = "Firmware";
		break;
	default:
		str = "Unknown";
		break;
	}
	print_field("%s(%u): %s(0x%2.2x)", type_str, tlv->type, str,
							get_u8(tlv->val));
}

static void print_version_tlv_timestamp(const struct intel_version_tlv *tlv,
					const char *type_str)
{
	print_field("%s(%u): %u-%u", type_str, tlv->type,
				tlv->val[1], tlv->val[0]);
}

static void print_version_tlv_min_fw(const struct intel_version_tlv *tlv,
				     const char *type_str)
{
	print_field("%s(%u): %u-%u.%u", type_str, tlv->type,
				tlv->val[0], tlv->val[1], 2000 + tlv->val[2]);
}

static void print_version_tlv_otp_bdaddr(const struct intel_version_tlv *tlv,
					 const char *type_str)
{
	packet_print_addr(type_str, tlv->val, 0x00);
}

static void print_version_tlv_unknown(const struct intel_version_tlv *tlv,
				      const char *type_str)
{
	print_field("%s(%u): ", type_str, tlv->type);
	packet_hexdump(tlv->val, tlv->len);
}

static void print_version_tlv_mfg(const struct intel_version_tlv *tlv,
					 const char *type_str)
{
	uint16_t mfg_id = get_le16(tlv->val);

	print_field("%s(%u): %s (%u)", type_str, tlv->type,
						bt_compidtostr(mfg_id), mfg_id);
}

static const struct intel_version_tlv_desc {
	uint8_t type;
	const char *type_str;
	void (*func)(const struct intel_version_tlv *tlv, const char *type_str);
} intel_version_tlv_table[] = {
	{ 16, "CNVi TOP", print_version_tlv_u32 },
	{ 17, "CNVr TOP", print_version_tlv_u32 },
	{ 18, "CNVi BT", print_version_tlv_cnvi_bt},
	{ 19, "CNVr BT", print_version_tlv_u32 },
	{ 20, "CNVi OTP", print_version_tlv_u16 },
	{ 21, "CNVr OTP", print_version_tlv_u16 },
	{ 22, "Device Rev ID", print_version_tlv_u16 },
	{ 23, "USB VID", print_version_tlv_u16 },
	{ 24, "USB PID", print_version_tlv_u16 },
	{ 25, "PCIE VID", print_version_tlv_u16 },
	{ 26, "PCIe DID", print_version_tlv_u16 },
	{ 27, "PCIe Subsystem ID", print_version_tlv_u16 },
	{ 28, "Image Type", print_version_tlv_img_type },
	{ 29, "Time Stamp", print_version_tlv_timestamp },
	{ 30, "Build Type", print_version_tlv_u8 },
	{ 31, "Build Num", print_version_tlv_u32 },
	{ 32, "FW Build Product", print_version_tlv_u8 },
	{ 33, "FW Build HW", print_version_tlv_u8 },
	{ 34, "FW Build Step", print_version_tlv_u8 },
	{ 35, "BT Spec", print_version_tlv_u8 },
	{ 36, "Manufacturer", print_version_tlv_mfg },
	{ 37, "HCI Revision", print_version_tlv_u16 },
	{ 38, "LMP SubVersion", print_version_tlv_u16 },
	{ 39, "OTP Patch Version", print_version_tlv_u8 },
	{ 40, "Secure Boot", print_version_tlv_enabled },
	{ 41, "Key From Header", print_version_tlv_enabled },
	{ 42, "OTP Lock", print_version_tlv_enabled },
	{ 43, "API Lock", print_version_tlv_enabled },
	{ 44, "Debug Lock", print_version_tlv_enabled },
	{ 45, "Minimum FW", print_version_tlv_min_fw },
	{ 46, "Limited CCE", print_version_tlv_enabled },
	{ 47, "SBE Type", print_version_tlv_u8 },
	{ 48, "OTP BDADDR", print_version_tlv_otp_bdaddr },
	{ 49, "Unlocked State", print_version_tlv_enabled },
	{ 0, NULL, NULL },
};

static void read_version_tlv_rsp(const void *data, uint8_t size)
{
	uint8_t status = get_u8(data);

	print_status(status);

	/* Consume the status */
	data++;
	size--;

	while (size > 0) {
		const struct intel_version_tlv *tlv = data;
		const struct intel_version_tlv_desc *desc = NULL;
		int i;

		for (i = 0; intel_version_tlv_table[i].type > 0; i++) {
			if (intel_version_tlv_table[i].type == tlv->type) {
				desc = &intel_version_tlv_table[i];
				break;
			}
		}

		if (desc)
			desc->func(tlv, desc->type_str);
		else
			print_version_tlv_unknown(tlv, "Unknown Type");

		data += sizeof(*tlv) + tlv->len;
		size -= sizeof(*tlv) + tlv->len;
	}
}

static void read_version_rsp(uint16_t index, const void *data, uint8_t size)
{
	uint8_t status = get_u8(data);
	uint8_t hw_platform = get_u8(data + 1);
	uint8_t hw_variant = get_u8(data + 2);
	uint8_t hw_revision = get_u8(data + 3);
	uint8_t fw_variant = get_u8(data + 4);
	uint8_t fw_revision = get_u8(data + 5);
	uint8_t fw_build_nn = get_u8(data + 6);
	uint8_t fw_build_cw = get_u8(data + 7);
	uint8_t fw_build_yy = get_u8(data + 8);
	uint8_t fw_patch = get_u8(data + 9);

	/* There are two different formats of the response for the
	 * HCI_Intel_Read_version command depends on the command parameters
	 * If the size is fixed to 10 and hw_platform is 0x37, then it is the
	 * legacy format, otherwise use the tlv based format.
	 */
	if (size != 10 && hw_platform != 0x37) {
		read_version_tlv_rsp(data, size);
		return;
	}

	print_status(status);
	print_field("Hardware platform: 0x%2.2x", hw_platform);
	print_field("Hardware variant: 0x%2.2x", hw_variant);
	print_field("Hardware revision: %u.%u", hw_revision >> 4,
						hw_revision & 0x0f);
	print_field("Firmware variant: 0x%2.2x", fw_variant);
	print_field("Firmware revision: %u.%u", fw_revision >> 4,
						fw_revision & 0x0f);

	print_field("Firmware build: %u-%u.%u", fw_build_nn,
					fw_build_cw, 2000 + fw_build_yy);
	print_field("Firmware patch: %u", fw_patch);
}

static void read_version_cmd(uint16_t index, const void *data, uint8_t size)
{
	const char *str;
	uint8_t type;

	/* This is the legacy read version command format and no further action
	 * is needed
	 */
	if (size == 0)
		return;

	print_field("Requested Type:");

	while (size > 0) {
		const struct intel_version_tlv_desc *desc = NULL;
		int i;

		type = get_u8(data);

		/* Get all supported types */
		if (type == 0xff)
			str = "All Supported Types";
		else {
			for (i = 0; intel_version_tlv_table[i].type > 0; i++) {
				if (intel_version_tlv_table[i].type == type) {
					desc = &intel_version_tlv_table[i];
					break;
				}
			}

			if (desc)
				str = desc->type_str;
			else
				str = "Unknown Type";
		}

		print_field("  %s(0x%2.2x)", str, type);

		data += sizeof(type);
		size -= sizeof(type);
	}
}

static void set_uart_baudrate_cmd(uint16_t index, const void *data,
							uint8_t size)
{
	uint8_t baudrate = get_u8(data);
	const char *str;

	switch (baudrate) {
	case 0x00:
		str = "9600 Baud";
		break;
	case 0x01:
		str = "19200 Baud";
		break;
	case 0x02:
		str = "38400 Baud";
		break;
	case 0x03:
		str = "57600 Baud";
		break;
	case 0x04:
		str = "115200 Baud";
		break;
	case 0x05:
		str = "230400 Baud";
		break;
	case 0x06:
		str = "460800 Baud";
		break;
	case 0x07:
		str = "921600 Baud";
		break;
	case 0x08:
		str = "1843200 Baud";
		break;
	case 0x09:
		str = "3250000 baud";
		break;
	case 0x0a:
		str = "2000000 baud";
		break;
	case 0x0b:
		str = "3000000 baud";
		break;
	case 0x0c:
		str = "3714286 baud";
		break;
	case 0x0d:
		str = "4333333 baud";
		break;
	case 0x0e:
		str = "6500000 baud";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Baudrate: %s (0x%2.2x)", str, baudrate);
}

static void secure_send_cmd(uint16_t index, const void *data, uint8_t size)
{
	uint8_t type = get_u8(data);
	const char *str;

	switch (type) {
	case 0x00:
		str = "Init";
		break;
	case 0x01:
		str = "Data";
		break;
	case 0x02:
		str = "Sign";
		break;
	case 0x03:
		str = "PKey";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s fragment (0x%2.2x)", str, type);

	packet_hexdump(data + 1, size - 1);
}

static void manufacturer_mode_cmd(uint16_t index, const void *data,
							uint8_t size)
{
	uint8_t mode = get_u8(data);
	uint8_t reset = get_u8(data + 1);
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Disabled";
		break;
	case 0x01:
		str = "Enabled";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode switch: %s (0x%2.2x)", str, mode);

	switch (reset) {
	case 0x00:
		str = "No reset";
		break;
	case 0x01:
		str = "Reset and deactivate patches";
		break;
	case 0x02:
		str = "Reset and activate patches";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Reset behavior: %s (0x%2.2x)", str, reset);
}

static void write_bd_data_cmd(uint16_t index, const void *data, uint8_t size)
{
	uint8_t features[8];

	packet_print_addr("Address", data, 0x00);
	packet_hexdump(data + 6, 6);

	memcpy(features, data + 12, 8);
	packet_print_features_lmp(features, 0);

	memcpy(features, data + 20, 1);
	memset(features + 1, 0, 7);
	packet_print_features_ll(features);

	packet_hexdump(data + 21, size - 21);
}

static void read_bd_data_rsp(uint16_t index, const void *data, uint8_t size)
{
	uint8_t status = get_u8(data);

	print_status(status);
	packet_print_addr("Address", data + 1, 0x00);
	packet_hexdump(data + 7, size - 7);
}

static void write_bd_address_cmd(uint16_t index, const void *data, uint8_t size)
{
	packet_print_addr("Address", data, 0x00);
}

static void act_deact_traces_cmd(uint16_t index, const void *data, uint8_t size)
{
	uint8_t tx = get_u8(data);
	uint8_t tx_arq = get_u8(data + 1);
	uint8_t rx = get_u8(data + 2);

	print_field("Transmit traces: 0x%2.2x", tx);
	print_field("Transmit ARQ: 0x%2.2x", tx_arq);
	print_field("Receive traces: 0x%2.2x", rx);
}

static void stimulate_exception_cmd(uint16_t index, const void *data,
							uint8_t size)
{
	uint8_t type = get_u8(data);
	const char *str;

	switch (type) {
	case 0x00:
		str = "Fatal Exception";
		break;
	case 0x01:
		str = "Debug Exception";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, type);
}

static const struct {
	uint8_t bit;
	const char *str;
} events_table[] = {
	{  0, "Bootup"			},
	{  1, "SCO Rejected via LMP"	},
	{  2, "PTT Switch Notification"	},
	{  7, "Scan Status"		},
	{  9, "Debug Exception"		},
	{ 10, "Fatal Exception"		},
	{ 11, "System Exception"	},
	{ 13, "LE Link Established"	},
	{ 14, "FW Trace String"		},
	{ }
};

static void set_event_mask_cmd(uint16_t index, const void *data, uint8_t size)
{
	const uint8_t *events_array = data;
	uint64_t mask, events = 0;
	int i;

	for (i = 0; i < 8; i++)
		events |= ((uint64_t) events_array[i]) << (i * 8);

	print_field("Mask: 0x%16.16" PRIx64, events);

	mask = events;

	for (i = 0; events_table[i].str; i++) {
		if (events & (((uint64_t) 1) << events_table[i].bit)) {
			print_field("  %s", events_table[i].str);
			mask &= ~(((uint64_t) 1) << events_table[i].bit);
		}
	}

	if (mask)
		print_text(COLOR_UNKNOWN_EVENT_MASK, "  Unknown mask "
						"(0x%16.16" PRIx64 ")", mask);
}

static void ddc_config_write_cmd(uint16_t index, const void *data, uint8_t size)
{
	while (size > 0) {
		uint8_t param_len = get_u8(data);
		uint16_t param_id = get_le16(data + 1);

		print_field("Identifier: 0x%4.4x", param_id);
		packet_hexdump(data + 3, param_len - 2);

		data += param_len + 1;
		size -= param_len + 1;
	}
}

static void ddc_config_write_rsp(uint16_t index, const void *data, uint8_t size)
{
	uint8_t status = get_u8(data);
	uint16_t param_id = get_le16(data + 1);

	print_status(status);
	print_field("Identifier: 0x%4.4x", param_id);
}

static void memory_write_cmd(uint16_t index, const void *data, uint8_t size)
{
	uint32_t addr = get_le32(data);
	uint8_t mode = get_u8(data + 4);
	uint8_t length = get_u8(data + 5);
	const char *str;

	print_field("Address: 0x%8.8x", addr);

	switch (mode) {
	case 0x00:
		str = "Byte access";
		break;
	case 0x01:
		str = "Half word access";
		break;
	case 0x02:
		str = "Word access";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
	print_field("Length: %u", length);

	packet_hexdump(data + 6, size - 6);
}

static void read_supported_features_cmd(uint16_t index, const void *data,
							uint8_t size)
{
	uint8_t page = get_u8(data);

	print_field("Page: 0x%2.2x", page);
}

static void read_supported_features_rsp(uint16_t index, const void *data,
							uint8_t size)
{
	uint8_t status = get_u8(data);
	uint8_t page = get_u8(data + 1);
	uint8_t max_pages = get_u8(data + 2);

	print_status(status);
	print_field("Page: 0x%2.2x", page);
	print_field("Max Pages: 0x%2.2x", max_pages);
	print_field("Supported Features:");
	packet_hexdump(data + 3, size - 3);
}

static void ppag_enable(uint16_t index, const void *data, uint8_t size)
{
	uint32_t enable = get_le32(data);
	char *ppag_enable_flags;

	switch (enable) {
	case 0x01:
		ppag_enable_flags = "EU";
		break;
	case 0x02:
		ppag_enable_flags = "China";
		break;
	case 0x03:
		ppag_enable_flags = "EU and China";
		break;
	default:
		ppag_enable_flags = "Unknown";
		break;
	}

	print_field("Enable: %s (0x%8.8x)", ppag_enable_flags, enable);
}

static const struct vendor_ocf vendor_ocf_table[] = {
	{ 0x001, "Reset",
			reset_cmd, 8, true,
			status_rsp, 1, true },
	{ 0x002, "No Operation" },
	{ 0x005, "Read Version",
			read_version_cmd, 0, false,
			read_version_rsp, 1, false },
	{ 0x006, "Set UART Baudrate",
			set_uart_baudrate_cmd, 1, true,
			status_rsp, 1, true },
	{ 0x007, "Enable LPM" },
	{ 0x008, "PCM Write Configuration" },
	{ 0x009, "Secure Send",
			secure_send_cmd, 1, false,
			status_rsp, 1, true },
	{ 0x00d, "Read Secure Boot Params",
			null_cmd, 0, true },
	{ 0x00e, "Write Secure Boot Params" },
	{ 0x00f, "Unlock" },
	{ 0x010, "Change UART Baudrate" },
	{ 0x011, "Manufacturer Mode",
			manufacturer_mode_cmd, 2, true,
			status_rsp, 1, true },
	{ 0x012, "Read Link RSSI" },
	{ 0x022, "Get Exception Info" },
	{ 0x024, "Clear Exception Info" },
	{ 0x02f, "Write BD Data",
			write_bd_data_cmd, 6, false },
	{ 0x030, "Read BD Data",
			null_cmd, 0, true,
			read_bd_data_rsp, 7, false },
	{ 0x031, "Write BD Address",
			write_bd_address_cmd, 6, true,
			status_rsp, 1, true },
	{ 0x032, "Flow Specification" },
	{ 0x034, "Read Secure ID" },
	{ 0x038, "Set Synchronous USB Interface Type" },
	{ 0x039, "Config Synchronous Interface" },
	{ 0x03f, "SW RF Kill",
			null_cmd, 0, true,
			status_rsp, 1, true },
	{ 0x043, "Activate Deactivate Traces",
			act_deact_traces_cmd, 3, true },
	{ 0x04d, "Stimulate Exception",
			stimulate_exception_cmd, 1, true,
			status_rsp, 1, true },
	{ 0x050, "Read HW Version" },
	{ 0x052, "Set Event Mask",
			set_event_mask_cmd, 8, true,
			status_rsp, 1, true },
	{ 0x053, "Config_Link_Controller" },
	{ 0x089, "DDC Write" },
	{ 0x08a, "DDC Read" },
	{ 0x08b, "DDC Config Write",
			ddc_config_write_cmd, 3, false,
			ddc_config_write_rsp, 3, true },
	{ 0x08c, "DDC Config Read" },
	{ 0x08d, "Memory Read" },
	{ 0x08e, "Memory Write",
			memory_write_cmd, 6, false,
			status_rsp, 1, true },
	{ 0x0a6, "Read Supported Features",
			read_supported_features_cmd, 1, true,
			read_supported_features_rsp, 19, true },
	{ 0x20b, "PPAG Enable",
			ppag_enable, 4, true,
			status_rsp, 1, true },
	{ }
};

const struct vendor_ocf *intel_vendor_ocf(uint16_t ocf)
{
	int i;

	for (i = 0; vendor_ocf_table[i].str; i++) {
		if (vendor_ocf_table[i].ocf == ocf)
			return &vendor_ocf_table[i];
	}

	return NULL;
}

static void startup_evt(struct timeval *tv, uint16_t index,
				const void *data, uint8_t size)
{
}

static void fatal_exception_evt(struct timeval *tv, uint16_t index,
				const void *data, uint8_t size)
{
	uint16_t line = get_le16(data);
	uint8_t module = get_u8(data + 2);
	uint8_t reason = get_u8(data + 3);

	print_field("Line: %u", line);
	print_module(module);
	print_field("Reason: 0x%2.2x", reason);
}

static void bootup_evt(struct timeval *tv, uint16_t index,
				const void *data, uint8_t size)
{
	uint8_t zero = get_u8(data);
	uint8_t num_packets = get_u8(data + 1);
	uint8_t source = get_u8(data + 2);
	uint8_t reset_type = get_u8(data + 3);
	uint8_t reset_reason = get_u8(data + 4);
	uint8_t ddc_status = get_u8(data + 5);
	const char *str;

	print_field("Zero: 0x%2.2x", zero);
	print_field("Number of packets: %d", num_packets);

	switch (source) {
	case 0x00:
		str = "Bootloader";
		break;
	case 0x01:
		str = "Operational firmware";
		break;
	case 0x02:
		str = "Self test firmware";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Source: %s (0x%2.2x)", str, source);

	switch (reset_type) {
	case 0x00:
		str = "Hardware reset";
		break;
	case 0x01:
		str = "Soft watchdog reset";
		break;
	case 0x02:
		str = "Soft software reset";
		break;
	case 0x03:
		str = "Hard watchdog reset";
		break;
	case 0x04:
		str = "Hard software reset";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Reset type: %s (0x%2.2x)", str, reset_type);

	switch (reset_reason) {
	case 0x00:
		str = "Power on";
		break;
	case 0x01:
		str = "Reset command";
		break;
	case 0x02:
		str = "Intel reset command";
		break;
	case 0x03:
		str = "Watchdog";
		break;
	case 0x04:
		str = "Fatal exception";
		break;
	case 0x05:
		str = "System exception";
		break;
	case 0xff:
		str = "Unknown";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Reset reason: %s (0x%2.2x)", str, reset_reason);

	switch (ddc_status) {
	case 0x00:
		str = "Firmware default";
		break;
	case 0x01:
		str = "Firmware default plus OTP";
		break;
	case 0x02:
		str = "Persistent RAM";
		break;
	case 0x03:
		str = "Not used";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("DDC status: %s (0x%2.2x)", str, ddc_status);
}

static void default_bd_data_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint8_t mem_status = get_u8(data);
	const char *str;

	switch (mem_status) {
	case 0x02:
		str = "Invalid manufacturing data";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Memory status: %s (0x%2.2x)", str, mem_status);
}

static void secure_send_commands_result_evt(struct timeval *tv, uint16_t index,
						const void *data, uint8_t size)
{
	uint8_t result = get_u8(data);
	uint16_t opcode = get_le16(data + 1);
	uint16_t ogf = cmd_opcode_ogf(opcode);
	uint16_t ocf = cmd_opcode_ocf(opcode);
	uint8_t status = get_u8(data + 3);
	const char *str;

	switch (result) {
	case 0x00:
		str = "Success";
		break;
	case 0x01:
		str = "General failure";
		break;
	case 0x02:
		str = "Hardware failure";
		break;
	case 0x03:
		str = "Signature verification failed";
		break;
	case 0x04:
		str = "Parsing error of command buffer";
		break;
	case 0x05:
		str = "Command execution failure";
		break;
	case 0x06:
		str = "Command parameters error";
		break;
	case 0x07:
		str = "Command missing";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Result: %s (0x%2.2x)", str, result);
	print_field("Opcode: 0x%4.4x (0x%2.2x|0x%4.4x)", opcode, ogf, ocf);
	print_status(status);
}

static void debug_exception_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint16_t line = get_le16(data);
	uint8_t module = get_u8(data + 2);
	uint8_t reason = get_u8(data + 3);

	print_field("Line: %u", line);
	print_module(module);
	print_field("Reason: 0x%2.2x", reason);
}

static void le_link_established_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint16_t handle = get_le16(data);
	uint32_t access_addr = get_le32(data + 10);

	print_field("Handle: %u", handle);

	packet_hexdump(data + 2, 8);

	print_field("Access address: 0x%8.8x", access_addr);

	packet_hexdump(data + 14, size - 14);
}

static void scan_status_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint8_t enable = get_u8(data);

	print_field("Inquiry scan: %s",
				(enable & 0x01) ? "Enabled" : "Disabled");
	print_field("Page scan: %s",
				(enable & 0x02) ? "Enabled" : "Disabled");

	if (enable & 0xfc)
		print_text(COLOR_UNKNOWN_SCAN_STATUS,
				"  Unknown status (0x%2.2x)", enable & 0xfc);

}

static void act_deact_traces_complete_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint8_t status = get_u8(data);

	print_status(status);
}

static void lmp_pdu_trace_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint8_t type, len, id;
	uint16_t handle, count;
	uint32_t clock;
	const char *str;

	type = get_u8(data);
	handle = get_le16(data + 1);

	switch (type) {
	case 0x00:
		str = "RX LMP";
		break;
	case 0x01:
		str = "TX LMP";
		break;
	case 0x02:
		str = "ACK LMP";
		break;
	case 0x03:
		str = "RX LL";
		break;
	case 0x04:
		str = "TX LL";
		break;
	case 0x05:
		str = "ACK LL";
		break;
	default:
		str = "Unknown";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, type);
	print_field("Handle: %u", handle);

	switch (type) {
	case 0x00:
		len = size - 8;
		clock = get_le32(data + 4 + len);

		packet_hexdump(data + 3, 1);
		lmp_packet(data + 4, len, false);
		print_field("Clock: 0x%8.8x", clock);
		break;
	case 0x01:
		len = size - 9;
		clock = get_le32(data + 4 + len);
		id = get_u8(data + 4 + len + 4);

		packet_hexdump(data + 3, 1);
		lmp_packet(data + 4, len, false);
		print_field("Clock: 0x%8.8x", clock);
		print_field("ID: 0x%2.2x", id);
		break;
	case 0x02:
		clock = get_le32(data + 3);
		id = get_u8(data + 3 + 4);

		print_field("Clock: 0x%8.8x", clock);
		print_field("ID: 0x%2.2x", id);
		break;
	case 0x03:
		len = size - 8;
		count = get_le16(data + 3);

		print_field("Count: 0x%4.4x", count);
		packet_hexdump(data + 3 + 2 + 1, 2);
		llcp_packet(data + 8, len, false);
		break;
	case 0x04:
		len = size - 8;
		count = get_le16(data + 3);
		id = get_u8(data + 3 + 2);

		print_field("Count: 0x%4.4x", count);
		print_field("ID: 0x%2.2x", id);
		packet_hexdump(data + 3 + 2 + 1, 2);
		llcp_packet(data + 8, len, false);
		break;
	case 0x05:
		count = get_le16(data + 3);
		id = get_u8(data + 3 + 2);

		print_field("Count: 0x%4.4x", count);
		print_field("ID: 0x%2.2x", id);
		break;
	default:
		packet_hexdump(data + 3, size - 3);
		break;
	}
}

static void write_bd_data_complete_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint8_t status = get_u8(data);

	print_status(status);
}

static void sco_rejected_via_lmp_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint8_t reason = get_u8(data + 6);

	packet_print_addr("Address", data, 0x00);
	packet_print_error("Reason", reason);
}

static void ptt_switch_notification_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint16_t handle = get_le16(data);
	uint8_t table = get_u8(data + 2);
	const char *str;

	print_field("Handle: %u", handle);

	switch (table) {
	case 0x00:
		str = "Basic rate";
		break;
	case 0x01:
		str = "Enhanced data rate";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Packet type table: %s (0x%2.2x)", str, table);
}

static void system_exception_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	uint8_t type = get_u8(data);
	const char *str;

	switch (type) {
	case 0x00:
		str = "No Exception";
		break;
	case 0x01:
		str = "Undefined Instruction";
		break;
	case 0x02:
		str = "Prefetch abort";
		break;
	case 0x03:
		str = "Data abort";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, type);

	packet_hexdump(data + 1, size - 1);
}

static const struct vendor_evt vendor_evt_table[] = {
	{ 0x00, "Startup",
			startup_evt, 0, true },
	{ 0x01, "Fatal Exception",
			fatal_exception_evt, 4, true },
	{ 0x02, "Bootup",
			bootup_evt, 6, true },
	{ 0x05, "Default BD Data",
			default_bd_data_evt, 1, true },
	{ 0x06, "Secure Send Commands Result",
			secure_send_commands_result_evt, 4, true },
	{ 0x08, "Debug Exception",
			debug_exception_evt, 4, true },
	{ 0x0f, "LE Link Established",
			le_link_established_evt, 26, true },
	{ 0x11, "Scan Status",
			scan_status_evt, 1, true },
	{ 0x16, "Activate Deactivate Traces Complete",
			act_deact_traces_complete_evt, 1, true },
	{ 0x17, "LMP PDU Trace",
			lmp_pdu_trace_evt, 3, false },
	{ 0x19, "Write BD Data Complete",
			write_bd_data_complete_evt, 1, true },
	{ 0x25, "SCO Rejected via LMP",
			sco_rejected_via_lmp_evt, 7, true },
	{ 0x26, "PTT Switch Notification",
			ptt_switch_notification_evt, 3, true },
	{ 0x29, "System Exception",
			system_exception_evt, 133, true },
	{ 0x2c, "FW Trace String" },
	{ 0x2e, "FW Trace Binary" },
	{ }
};

/*
 * An Intel telemetry subevent is of the TLV format.
 * - Type: takes 1 byte. This is the subevent_id.
 * - Length: takes 1 byte.
 * - Value: takes |Length| bytes.
 */
struct intel_tlv {
	uint8_t subevent_id;
	uint8_t length;
	uint8_t value[];
};

#define TLV_SIZE(tlv) (*((const uint8_t *) tlv + 1) + 2 * sizeof(uint8_t))
#define NEXT_TLV(tlv) (const struct intel_tlv *) \
					((const uint8_t *) tlv + TLV_SIZE(tlv))

static void ext_evt_type(const struct intel_tlv *tlv)
{
	uint8_t evt_type = get_u8(tlv->value);
	const char *str;

	switch (evt_type) {
	case 0x00:
		str = "System Exception";
		break;
	case 0x01:
		str = "Fatal Exception";
		break;
	case 0x02:
		str = "Debug Exception";
		break;
	case 0x03:
		str = "Connection Event for BR/EDR Link Type";
		break;
	case 0x04:
		str = "Disconnection Event";
		break;
	case 0x05:
		str = "Performance Stats";
		break;

	default:
		print_text(COLOR_UNKNOWN_EXT_EVENT,
			"Unknown extended telemetry event type (0x%2.2x)",
			evt_type);
		packet_hexdump((const void *) tlv,
					tlv->length + 2 * sizeof(uint8_t));
		return;
	}

	print_field("Extended event type (0x%2.2x): %s (0x%2.2x)",
			tlv->subevent_id, str, evt_type);
}

static void ext_acl_evt_conn_handle(const struct intel_tlv *tlv)
{
	uint16_t conn_handle = get_le16(tlv->value);

	print_field("ACL connection handle (0x%2.2x): 0x%4.4x",
			tlv->subevent_id, conn_handle);
}

static void ext_acl_evt_hec_errors(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Rx HEC errors (0x%2.2x): %d", tlv->subevent_id, num);
}

static void ext_acl_evt_crc_errors(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Rx CRC errors (0x%2.2x): %d", tlv->subevent_id, num);
}

static void ext_acl_evt_num_pkt_from_host(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Packets from host (0x%2.2x): %d",
			tlv->subevent_id, num);
}

static void ext_acl_evt_num_tx_pkt_to_air(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Tx packets (0x%2.2x): %d", tlv->subevent_id, num);
}

static void ext_acl_evt_num_tx_pkt_retry(const struct intel_tlv *tlv)
{
	char *subevent_str;
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	switch (tlv->subevent_id) {
	case 0x4f:
		subevent_str = "Tx packets 0 retries";
		break;
	case 0x50:
		subevent_str = "Tx packets 1 retries";
		break;
	case 0x51:
		subevent_str = "Tx packets 2 retries";
		break;
	case 0x52:
		subevent_str = "Tx packets 3 retries";
		break;
	case 0x53:
		subevent_str = "Tx packets 4 retries and more";
		break;
	default:
		subevent_str = "Unknown";
		break;
	}

	print_field("%s (0x%2.2x): %d", subevent_str, tlv->subevent_id, num);
}

static void ext_acl_evt_num_tx_pkt_type(const struct intel_tlv *tlv)
{
	char *packet_type_str;
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	switch (tlv->subevent_id) {
	case 0x54:
		packet_type_str = "DH1";
		break;
	case 0x55:
		packet_type_str = "DH3";
		break;
	case 0x56:
		packet_type_str = "DH5";
		break;
	case 0x57:
		packet_type_str = "2DH1";
		break;
	case 0x58:
		packet_type_str = "2DH3";
		break;
	case 0x59:
		packet_type_str = "2DH5";
		break;
	case 0x5a:
		packet_type_str = "3DH1";
		break;
	case 0x5b:
		packet_type_str = "3DH3";
		break;
	case 0x5c:
		packet_type_str = "3DH5";
		break;
	default:
		packet_type_str = "Unknown";
		break;
	}

	print_field("Tx %s packets (0x%2.2x): %d",
			packet_type_str, tlv->subevent_id, num);
}

static void ext_acl_evt_num_rx_pkt_from_air(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Rx packets (0x%2.2x): %d",
			tlv->subevent_id, num);
}

static void ext_acl_evt_link_throughput(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("ACL link throughput (bps) (0x%2.2x): %d",
			tlv->subevent_id, num);
}

static void ext_acl_evt_max_packet_latency(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("ACL max packet latency (us) (0x%2.2x): %d",
			tlv->subevent_id, num);
}

static void ext_acl_evt_avg_packet_latency(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("ACL avg packet latency (us) (0x%2.2x): %d",
			tlv->subevent_id, num);
}

static void ext_acl_evt_rssi_moving_avg(const struct intel_tlv *tlv)
{
	uint32_t num = get_le16(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("ACL RX RSSI moving avg (0x%2.2x): %d",
			tlv->subevent_id, num);
}

static void ext_acl_evt_bad_cnt(const char *prefix, const struct intel_tlv *tlv)
{
	uint32_t c_1m = get_le32(tlv->value);
	uint32_t c_2m = get_le32(tlv->value + 4);
	uint32_t c_3m = get_le32(tlv->value + 8);

	/* Skip if all 0 */
	if (!c_1m && !c_2m && !c_3m)
		return;

	print_field("%s (0x%2.2x): 1M %d 2M %d 3M %d",
			prefix, tlv->subevent_id, c_1m, c_2m, c_3m);
}

static void ext_acl_evt_snr_bad_cnt(const struct intel_tlv *tlv)
{
	ext_acl_evt_bad_cnt("ACL RX SNR Bad Margin Counter", tlv);
}

static void ext_acl_evt_rx_rssi_bad_cnt(const struct intel_tlv *tlv)
{
	ext_acl_evt_bad_cnt("ACL RX RSSI Bad Counter", tlv);
}

static void ext_acl_evt_tx_rssi_bad_cnt(const struct intel_tlv *tlv)
{
	ext_acl_evt_bad_cnt("ACL TX RSSI Bad Counter", tlv);
}

static void ext_sco_evt_conn_handle(const struct intel_tlv *tlv)
{
	uint16_t conn_handle = get_le16(tlv->value);

	print_field("SCO/eSCO connection handle (0x%2.2x): 0x%4.4x",
			tlv->subevent_id, conn_handle);
}

static void ext_sco_evt_num_rx_pkt_from_air(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Packets from host (0x%2.2x): %d", tlv->subevent_id, num);
}

static void ext_sco_evt_num_tx_pkt_to_air(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Tx packets (0x%2.2x): %d", tlv->subevent_id, num);
}

static void ext_sco_evt_num_rx_payloads_lost(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Rx payload lost (0x%2.2x): %d", tlv->subevent_id, num);
}

static void ext_sco_evt_num_tx_payloads_lost(const struct intel_tlv *tlv)
{

	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Tx payload lost (0x%2.2x): %d", tlv->subevent_id, num);
}

static void slots_errors(const struct intel_tlv *tlv, const char *type_str)
{
	/* The subevent has 5 slots where each slot is of the uint32_t type. */
	uint32_t num[5];
	const uint8_t *data = tlv->value;
	int i;

	if (tlv->length != 5 * sizeof(uint32_t)) {
		print_text(COLOR_UNKNOWN_EXT_EVENT,
				"  Invalid subevent length (%d)", tlv->length);
		return;
	}

	for (i = 0; i < 5; i++) {
		num[i] = get_le32(data);
		data += sizeof(uint32_t);
	}

	print_field("%s (0x%2.2x): %d %d %d %d %d", type_str, tlv->subevent_id,
			num[0], num[1], num[2], num[3], num[4]);
}

static void ext_sco_evt_num_no_sync_errors(const struct intel_tlv *tlv)
{
	slots_errors(tlv, "Rx No SYNC errors");
}

static void ext_sco_evt_num_hec_errors(const struct intel_tlv *tlv)
{
	slots_errors(tlv, "Rx HEC errors");
}

static void ext_sco_evt_num_crc_errors(const struct intel_tlv *tlv)
{
	slots_errors(tlv, "Rx CRC errors");
}

static void ext_sco_evt_num_naks(const struct intel_tlv *tlv)
{
	slots_errors(tlv, "Rx NAK errors");
}

static void ext_sco_evt_num_failed_tx_by_wifi(const struct intel_tlv *tlv)
{
	slots_errors(tlv, "Failed Tx due to Wifi coex");
}

static void ext_sco_evt_num_failed_rx_by_wifi(const struct intel_tlv *tlv)
{
	slots_errors(tlv, "Failed Rx due to Wifi coex");
}

static void ext_sco_evt_samples_inserted(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Late samples inserted based on CDC (0x%2.2x): %d",
			tlv->subevent_id, num);
}

static void ext_sco_evt_samples_dropped(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Samples dropped (0x%2.2x): %d", tlv->subevent_id, num);
}

static void ext_sco_evt_mute_samples(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("Mute samples sent at initial connection (0x%2.2x): %d",
			tlv->subevent_id, num);
}

static void ext_sco_evt_plc_injection_data(const struct intel_tlv *tlv)
{
	uint32_t num = get_le32(tlv->value);

	/* Skip if 0 */
	if (!num)
		return;

	print_field("PLC injection data (0x%2.2x): %d", tlv->subevent_id, num);
}

static const struct intel_ext_subevent {
	uint8_t subevent_id;
	uint8_t length;
	void (*func)(const struct intel_tlv *tlv);
} intel_ext_subevent_table[] = {
	{ 0x01, 1, ext_evt_type },

	/* ACL audio link quality subevents */
	{ 0x4a, 2, ext_acl_evt_conn_handle },
	{ 0x4b, 4, ext_acl_evt_hec_errors },
	{ 0x4c, 4, ext_acl_evt_crc_errors },
	{ 0x4d, 4, ext_acl_evt_num_pkt_from_host },
	{ 0x4e, 4, ext_acl_evt_num_tx_pkt_to_air },
	{ 0x4f, 4, ext_acl_evt_num_tx_pkt_retry },
	{ 0x50, 4, ext_acl_evt_num_tx_pkt_retry },
	{ 0x51, 4, ext_acl_evt_num_tx_pkt_retry },
	{ 0x52, 4, ext_acl_evt_num_tx_pkt_retry },
	{ 0x53, 4, ext_acl_evt_num_tx_pkt_retry },
	{ 0x54, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x55, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x56, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x57, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x58, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x59, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x5a, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x5b, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x5c, 4, ext_acl_evt_num_tx_pkt_type },
	{ 0x5d, 4, ext_acl_evt_num_rx_pkt_from_air },
	{ 0x5e, 4, ext_acl_evt_link_throughput },
	{ 0x5f, 4, ext_acl_evt_max_packet_latency },
	{ 0x60, 4, ext_acl_evt_avg_packet_latency },
	{ 0x61, 2, ext_acl_evt_rssi_moving_avg },
	{ 0x62, 12, ext_acl_evt_snr_bad_cnt },
	{ 0x63, 12, ext_acl_evt_rx_rssi_bad_cnt },
	{ 0x64, 12, ext_acl_evt_tx_rssi_bad_cnt },

	/* SCO/eSCO audio link quality subevents */
	{ 0x6a, 2, ext_sco_evt_conn_handle },
	{ 0x6b, 4, ext_sco_evt_num_rx_pkt_from_air },
	{ 0x6c, 4, ext_sco_evt_num_tx_pkt_to_air },
	{ 0x6d, 4, ext_sco_evt_num_rx_payloads_lost },
	{ 0x6e, 4, ext_sco_evt_num_tx_payloads_lost },
	{ 0x6f, 20, ext_sco_evt_num_no_sync_errors },
	{ 0x70, 20, ext_sco_evt_num_hec_errors },
	{ 0x71, 20, ext_sco_evt_num_crc_errors },
	{ 0x72, 20, ext_sco_evt_num_naks },
	{ 0x73, 20, ext_sco_evt_num_failed_tx_by_wifi },
	{ 0x74, 20, ext_sco_evt_num_failed_rx_by_wifi },
	{ 0x75, 4, ext_sco_evt_samples_inserted },
	{ 0x76, 4, ext_sco_evt_samples_dropped },
	{ 0x77, 4, ext_sco_evt_mute_samples },
	{ 0x78, 4, ext_sco_evt_plc_injection_data },

	/* end */
	{ 0x0, 0}
};

static const struct intel_tlv *process_ext_subevent(const struct intel_tlv *tlv,
					const struct intel_tlv *last_tlv)
{
	const struct intel_tlv *next_tlv = NEXT_TLV(tlv);
	const struct intel_ext_subevent *subevent = NULL;
	int i;

	for (i = 0; intel_ext_subevent_table[i].length > 0; i++) {
		if (intel_ext_subevent_table[i].subevent_id ==
							tlv->subevent_id) {
			subevent = &intel_ext_subevent_table[i];
			break;
		}
	}

	if (!subevent) {
		print_text(COLOR_UNKNOWN_EXT_EVENT,
				"Unknown extended subevent 0x%2.2x",
				tlv->subevent_id);
		packet_hexdump(tlv->value, tlv->length);
		return next_tlv;
	}

	if (tlv->length != subevent->length) {
		print_text(COLOR_ERROR, "Invalid length %d of subevent 0x%2.2x",
				tlv->length, tlv->subevent_id);
		return NULL;
	}

	if (next_tlv > last_tlv) {
		print_text(COLOR_ERROR, "Subevent exceeds the buffer size.");
		return NULL;
	}

	subevent->func(tlv);

	return next_tlv;
}

static void intel_vendor_ext_evt(struct timeval *tv, uint16_t index,
					const void *data, uint8_t size)
{
	/* The data pointer points to a number of tlv.*/
	const struct intel_tlv *tlv = data;
	const struct intel_tlv *last_tlv = data + size;

	/* Process every tlv subevent until reaching last_tlv.
	 * The decoding process terminates normally when tlv == last_tlv.
	 */
	while (tlv && tlv < last_tlv)
		tlv = process_ext_subevent(tlv, last_tlv);

	/* If an error occurs in decoding the subevents, hexdump the packet. */
	if (!tlv)
		packet_hexdump(data, size);
}

/* Vendor extended events with a vendor prefix. */
static const struct vendor_evt vendor_prefix_evt_table[] = {
	{ 0x03, "Extended Telemetry", intel_vendor_ext_evt },
	{ }
};

static const uint8_t intel_vendor_prefix[] = {0x87, 0x80};
#define INTEL_VENDOR_PREFIX_SIZE sizeof(intel_vendor_prefix)

/*
 * The vendor event with Intel vendor prefix.
 * Its format looks like
 *   0xff <length> <vendor_prefix> <subopcode> <data>
 *   where Intel's <vendor_prefix> is 0x8780.
 *
 *   When <subopcode> == 0x03, it is a telemetry event; and
 *   <data> is a number of tlv data.
 */
struct vendor_prefix_evt {
	uint8_t prefix_data[INTEL_VENDOR_PREFIX_SIZE];
	uint8_t subopcode;
};

static const struct vendor_evt *intel_vendor_prefix_evt(const void *data,
							int *consumed_size)
{
	unsigned int i;
	const struct vendor_prefix_evt *vnd = data;
	char prefix_string[INTEL_VENDOR_PREFIX_SIZE * 2 + 1] = { 0 };

	/* Check if the vendor prefix matches. */
	for (i = 0; i < INTEL_VENDOR_PREFIX_SIZE; i++) {
		if (vnd->prefix_data[i] != intel_vendor_prefix[i])
			return NULL;
		sprintf(prefix_string + i * 2, "%02x", vnd->prefix_data[i]);
	}
	print_field("Vendor Prefix (0x%s)", prefix_string);

	/*
	 * Handle the vendor event with a vendor prefix.
	 *   0xff <length> <vendor_prefix> <subopcode> <data>
	 * This loop checks whether the <subopcode> exists in the
	 * vendor_prefix_evt_table.
	 */
	for (i = 0; vendor_prefix_evt_table[i].str; i++) {
		if (vendor_prefix_evt_table[i].evt == vnd->subopcode) {
			*consumed_size = sizeof(struct vendor_prefix_evt);
			return &vendor_prefix_evt_table[i];
		}
	}

	return NULL;
}

const struct vendor_evt *intel_vendor_evt(const void *data, int *consumed_size)
{
	uint8_t evt = *((const uint8_t *) data);
	int i;

	/*
	 * Handle the vendor event without a vendor prefix.
	 *   0xff <length> <evt> <data>
	 * This loop checks whether the <evt> exists in the vendor_evt_table.
	 */
	for (i = 0; vendor_evt_table[i].str; i++) {
		if (vendor_evt_table[i].evt == evt)
			return &vendor_evt_table[i];
	}

	/*
	 * It is not a regular event. Check whether it is a vendor extended
	 * event that comes with a vendor prefix followed by a subopcode.
	 */
	return intel_vendor_prefix_evt(data, consumed_size);
}
