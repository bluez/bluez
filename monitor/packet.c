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

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "display.h"
#include "bt.h"
#include "l2cap.h"
#include "control.h"
#include "packet.h"

#define COLOR_INDEX_LABEL		COLOR_WHITE
#define COLOR_TIMESTAMP			COLOR_YELLOW

#define COLOR_NEW_INDEX			COLOR_GREEN
#define COLOR_DEL_INDEX			COLOR_RED

#define COLOR_HCI_COMMAND		COLOR_BLUE
#define COLOR_HCI_COMMAND_UNKNOWN	COLOR_WHITE_BG

#define COLOR_HCI_EVENT			COLOR_MAGENTA
#define COLOR_HCI_EVENT_UNKNOWN		COLOR_WHITE_BG

#define COLOR_HCI_ACLDATA		COLOR_CYAN
#define COLOR_HCI_SCODATA		COLOR_YELLOW

static time_t time_offset = ((time_t) -1);
static unsigned long filter_mask = 0;
static bool index_filter = false;
static uint16_t index_number = 0;

void packet_set_filter(unsigned long filter)
{
	filter_mask = filter;
}

void packet_add_filter(unsigned long filter)
{
	if (index_filter)
		filter &= ~PACKET_FILTER_SHOW_INDEX;

	filter_mask |= filter;
}

void packet_del_filter(unsigned long filter)
{
	filter_mask &= ~filter;
}

void packet_select_index(uint16_t index)
{
	filter_mask &= ~PACKET_FILTER_SHOW_INDEX;

	index_filter = true;
	index_number = index;
}

#define print_space(x) printf("%*c", (x), ' ');

static void print_packet(struct timeval *tv, uint16_t index, char ident,
					const char *color, const char *label,
					const char *text, const char *extra)
{
	int col = num_columns();
	char line[256], ts_str[64];
	int n, ts_len = 0, ts_pos = 0, len = 0, pos = 0;

	if (filter_mask & PACKET_FILTER_SHOW_INDEX) {
		if (use_color()) {
			n = sprintf(ts_str + ts_pos, "%s", COLOR_INDEX_LABEL);
			if (n > 0)
				ts_pos += n;
		}

		n = sprintf(ts_str + ts_pos, " [hci%d]", index);
		if (n > 0) {
			ts_pos += n;
			ts_len += n;
		}
	}

	if (tv) {
		time_t t = tv->tv_sec;
		struct tm tm;

		localtime_r(&t, &tm);

		if (use_color()) {
			n = sprintf(ts_str + ts_pos, "%s", COLOR_TIMESTAMP);
			if (n > 0)
				ts_pos += n;
		}

		if (filter_mask & PACKET_FILTER_SHOW_DATE) {
			n = sprintf(ts_str + ts_pos, " %04d-%02d-%02d",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
			if (n > 0) {
				ts_pos += n;
				ts_len += n;
			}
		}

		if (filter_mask & PACKET_FILTER_SHOW_TIME) {
			n = sprintf(ts_str + ts_pos, " %02d:%02d:%02d.%06lu",
				tm.tm_hour, tm.tm_min, tm.tm_sec, tv->tv_usec);
			if (n > 0) {
				ts_pos += n;
				ts_len += n;
			}
		}

		if (filter_mask & PACKET_FILTER_SHOW_TIME_OFFSET) {
			n = sprintf(ts_str + ts_pos, " %lu.%06lu",
					tv->tv_sec - time_offset, tv->tv_usec);
			if (n > 0) {
				ts_pos += n;
				ts_len += n;
			}
		}
	}

	if (use_color()) {
		n = sprintf(ts_str + ts_pos, "%s", COLOR_OFF);
		if (n > 0)
			ts_pos += n;
	}

	if (use_color()) {
		n = sprintf(line + pos, "%s", color);
		if (n > 0)
			pos += n;
	}

	n = sprintf(line + pos, "%c %s", ident, label);
	if (n > 0) {
		pos += n;
		len += n;
	}

	if (text) {
		int extra_len = extra ? strlen(extra) : 0;
		int max_len = col - len - extra_len - ts_len - 3;

		n = snprintf(line + pos, max_len + 1, ": %s", text);
		if (n > max_len) {
			line[pos + max_len - 1] = '.';
			line[pos + max_len - 2] = '.';
			if (line[pos + max_len - 3] == ' ')
				line[pos + max_len - 3] = '.';

			n = max_len;
		}

		if (n > 0) {
			pos += n;
			len += n;
		}
	}

	if (use_color()) {
		n = sprintf(line + pos, "%s", COLOR_OFF);
		if (n > 0)
			pos += n;
	}

	if (extra) {
		n = sprintf(line + pos, " %s", extra);
		if (n > 0) {
			pos += n;
			len += n;
		}
	}

	if (ts_len > 0) {
		printf("%s", line);
		if (len < col)
			print_space(col - len - ts_len - 1);
		printf("%s%s\n", use_color() ? COLOR_TIMESTAMP : "", ts_str);
	} else
		printf("%s\n", line);
}

static const struct {
	uint8_t error;
	const char *str;
} error2str_table[] = {
	{ 0x00, "Success"						},
	{ 0x01, "Unknown HCI Command"					},
	{ 0x02, "Unknown Connection Identifier"				},
	{ 0x03, "Hardware Failure"					},
	{ 0x04, "Page Timeout"						},
	{ 0x05, "Authentication Failure"				},
	{ 0x06, "PIN or Key Missing"					},
	{ 0x07, "Memory Capacity Exceeded"				},
	{ 0x08, "Connection Timeout"					},
	{ 0x09, "Connection Limit Exceeded"				},
	{ 0x0a, "Synchronous Connection Limit to a Device Exceeded"	},
	{ 0x0b, "ACL Connection Already Exists"				},
	{ 0x0c, "Command Disallowed"					},
	{ 0x0d, "Connection Rejected due to Limited Resources"		},
	{ 0x0e, "Connection Rejected due to Security Reasons"		},
	{ 0x0f, "Connection Rejected due to Unacceptable BD_ADDR"	},
	{ 0x10, "Connection Accept Timeout Exceeded"			},
	{ 0x11, "Unsupported Feature or Parameter Value"		},
	{ 0x12, "Invalid HCI Command Parameters"			},
	{ 0x13, "Remote User Terminated Connection"			},
	{ 0x14, "Remote Device Terminated due to Low Resources"		},
	{ 0x15, "Remote Device Terminated due to Power Off"		},
	{ 0x16, "Connection Terminated By Local Host"			},
	{ 0x17, "Repeated Attempts"					},
	{ 0x18, "Pairing Not Allowed"					},
	{ 0x19, "Unknown LMP PDU"					},
	{ 0x1a, "Unsupported Remote Feature / Unsupported LMP Feature"	},
	{ 0x1b, "SCO Offset Rejected"					},
	{ 0x1c, "SCO Interval Rejected"					},
	{ 0x1d, "SCO Air Mode Rejected"					},
	{ 0x1e, "Invalid LMP Parameters"				},
	{ 0x1f, "Unspecified Error"					},
	{ 0x20, "Unsupported LMP Parameter Value"			},
	{ 0x21, "Role Change Not Allowed"				},
	{ 0x22, "LMP Response Timeout / LL Response Timeout"		},
	{ 0x23, "LMP Error Transaction Collision"			},
	{ 0x24, "LMP PDU Not Allowed"					},
	{ 0x25, "Encryption Mode Not Acceptable"			},
	{ 0x26, "Link Key cannot be Changed"				},
	{ 0x27, "Requested QoS Not Supported"				},
	{ 0x28, "Instant Passed"					},
	{ 0x29, "Pairing With Unit Key Not Supported"			},
	{ 0x2a, "Different Transaction Collision"			},
	{ 0x2b, "Reserved"						},
	{ 0x2c, "QoS Unacceptable Parameter"				},
	{ 0x2d, "QoS Rejected"						},
	{ 0x2e, "Channel Classification Not Supported"			},
	{ 0x2f, "Insufficient Security"					},
	{ 0x30, "Parameter Out Of Manadatory Range"			},
	{ 0x31, "Reserved"						},
	{ 0x32, "Role Switch Pending"					},
	{ 0x33, "Reserved"						},
	{ 0x34, "Reserved Slot Violation"				},
	{ 0x35, "Role Switch Failed"					},
	{ 0x36, "Extended Inquiry Response Too Large"			},
	{ 0x37, "Secure Simple Pairing Not Supported By Host"		},
	{ 0x38, "Host Busy - Pairing"					},
	{ 0x39, "Connection Rejected due to No Suitable Channel Found"	},
	{ 0x3a, "Controller Busy"					},
	{ 0x3b, "Unacceptable Connection Interval"			},
	{ 0x3c, "Directed Advertising Timeout"				},
	{ 0x3d, "Connection Terminated due to MIC Failure"		},
	{ 0x3e, "Connection Failed to be Established"			},
	{ 0x3f, "MAC Connection Failed"					},
	{ }
};

static void print_error(const char *label, uint8_t error)
{
	const char *str = "Unknown";
	const char *color_on, *color_off;
	int i;

	for (i = 0; error2str_table[i].str; i++) {
		if (error2str_table[i].error == error) {
			str = error2str_table[i].str;
			break;
		}
	}

	if (use_color()) {
		if (error)
			color_on = COLOR_RED;
		else
			color_on = COLOR_GREEN;
		color_off = COLOR_OFF;
	} else {
		color_on = "";
		color_off = "";
	}

	print_field("%s: %s%s%s (0x%2.2x)", label,
				color_on, str, color_off, error);
}

static void print_status(uint8_t status)
{
	print_error("Status", status);
}

static void print_reason(uint8_t reason)
{
	print_error("Reason", reason);
}

static void print_bdaddr(const uint8_t *bdaddr)
{
	print_field("Address: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X"
					" (OUI %2.2X-%2.2X-%2.2X)",
					bdaddr[5], bdaddr[4], bdaddr[3],
					bdaddr[2], bdaddr[1], bdaddr[0],
					bdaddr[5], bdaddr[4], bdaddr[3]);
}

static void print_addr(const uint8_t *addr, uint8_t addr_type)
{
	const char *str;

	switch (addr_type) {
	case 0x00:
		print_bdaddr(addr);
		break;
	case 0x01:
		switch ((addr[5] & 0xc0) >> 6) {
		case 0x00:
			str = "Non-Resolvable";
			break;
		case 0x01:
			str = "Resolvable";
			break;
		case 0x03:
			str = "Static";
			break;
		default:
			str = "Reserved";
			break;
		}

		print_field("Address: %2.2X:%2.2X:%2.2X:%2.2X:%2.2X:%2.2X"
					" (%s)", addr[5], addr[4], addr[3],
					addr[2], addr[1], addr[0], str);
		break;
	default:
		print_field("Address: %2.2X-%2.2X-%2.2X-%2.2X-%2.2X-%2.2X",
						addr[5], addr[4], addr[3],
						addr[2], addr[1], addr[0]);
		break;
	}
}

static void print_addr_type(const char *label, uint8_t addr_type)
{
	const char *str;

	switch (addr_type) {
	case 0x00:
		str = "Public";
		break;
	case 0x01:
		str = "Random";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("%s: %s (0x%2.2x)", label, str, addr_type);
}

static void print_handle(uint16_t handle)
{
	print_field("Handle: %d", btohs(handle));
}

static void print_phy_handle(uint8_t phy_handle)
{
	print_field("Physical handle: %d", phy_handle);
}

static void print_pkt_type(uint16_t pkt_type)
{
	print_field("Packet type: 0x%4.4x", btohs(pkt_type));
}

static void print_iac(const uint8_t *lap)
{
	print_field("Access code: 0x%2.2x%2.2x%2.2x", lap[2], lap[1], lap[0]);
}

static void print_dev_class(const uint8_t *dev_class)
{
	print_field("Class: 0x%2.2x%2.2x%2.2x",
			dev_class[2], dev_class[1], dev_class[0]);
}

static void print_voice_setting(uint16_t setting)
{
	print_field("Setting: 0x%4.4x", btohs(setting));
}

static void print_retransmission_effort(uint8_t effort)
{
	const char *str;

	switch (effort) {
	case 0x00:
		str = "No retransmissions";
		break;
	case 0x01:
		str = "Optimize for power consumption";
		break;
	case 0x02:
		str = "Optimize for link quality";
		break;
	case 0xff:
		str = "Don't care";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Retransmission effort: %s (0x%2.2x)", str, effort);
}

static void print_scan_enable(uint8_t scan_enable)
{
	const char *str;

	switch (scan_enable) {
	case 0x00:
		str = "No Scans";
		break;
	case 0x01:
		str = "Inquiry Scan";
		break;
	case 0x02:
		str = "Page Scan";
		break;
	case 0x03:
		str = "Inquiry Scan + Page Scan";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Scan enable: %s (0x%2.2x)", str, scan_enable);
}

static void print_link_policy(uint16_t link_policy)
{
	print_field("Link policy: 0x%4.4x", btohs(link_policy));
}

static void print_air_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "u-law log";
		break;
	case 0x01:
		str = "A-law log";
		break;
	case 0x02:
		str = "CVSD";
		break;
	case 0x03:
		str = "Transparent";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Air mode: %s (0x%2.2x)", str, mode);
}

static void print_inquiry_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Standard Inquiry Result";
		break;
	case 0x01:
		str = "Inquiry Result with RSSI";
		break;
	case 0x02:
		str = "Inquiry Result with RSSI or Extended Inquiry Result";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_simple_pairing_mode(uint8_t mode)
{
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

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_pscan_rep_mode(uint8_t pscan_rep_mode)
{
	const char *str;

	switch (pscan_rep_mode) {
	case 0x00:
		str = "R0";
		break;
	case 0x01:
		str = "R1";
		break;
	case 0x02:
		str = "R2";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Page scan repetition mode: %s (0x%2.2x)",
						str, pscan_rep_mode);
}

static void print_pscan_period_mode(uint8_t pscan_period_mode)
{
	const char *str;

	switch (pscan_period_mode) {
	case 0x00:
		str = "P0";
		break;
	case 0x01:
		str = "P1";
		break;
	case 0x02:
		str = "P2";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Page period mode: %s (0x%2.2x)", str, pscan_period_mode);
}

static void print_pscan_mode(uint8_t pscan_mode)
{
	const char *str;

	switch (pscan_mode) {
	case 0x00:
		str = "Mandatory";
		break;
	case 0x01:
		str = "Optional I";
		break;
	case 0x02:
		str = "Optional II";
		break;
	case 0x03:
		str = "Optional III";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Page scan mode: %s (0x%2.2x)", str, pscan_mode);
}

static void print_clock_offset(uint16_t clock_offset)
{
	print_field("Clock offset: 0x%4.4x", btohs(clock_offset));
}

static void print_link_type(uint8_t link_type)
{
	const char *str;

	switch (link_type) {
	case 0x00:
		str = "SCO";
		break;
	case 0x01:
		str = "ACL";
		break;
	case 0x02:
		str = "eSCO";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Link type: %s (0x%2.2x)", str, link_type);
}

static void print_encr_mode(uint8_t encr_mode)
{
	const char *str;

	switch (encr_mode) {
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

	print_field("Encryption: %s (0x%2.2x)", str, encr_mode);
}

static void print_pin_type(uint8_t pin_type)
{
	const char *str;

	switch (pin_type) {
	case 0x00:
		str = "Variable";
		break;
	case 0x01:
		str = "Fixed";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("PIN type: %s (0x%2.2x)", str, pin_type);
}

static void print_key_flag(uint8_t key_flag)
{
	const char *str;

	switch (key_flag) {
	case 0x00:
		str = "Semi-permanent";
		break;
	case 0x01:
		str = "Temporary";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Key flag: %s (0x%2.2x)", str, key_flag);
}

static void print_key_len(uint8_t key_len)
{
	const char *str;

	switch (key_len) {
	case 32:
		str = "802.11 PAL keyLength";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Key length: %s (%d)", str, key_len);
}

static void print_key_type(uint8_t key_type)
{
	const char *str;

	switch (key_type) {
	case 0x00:
		str = "Combination key";
		break;
	case 0x01:
		str = "Local Unit key";
		break;
	case 0x02:
		str = "Remote Unit key";
		break;
	case 0x03:
		str = "Debug Combination key";
		break;
	case 0x04:
		str = "Unauthenticated Combination key";
		break;
	case 0x05:
		str = "Authenticated Combination key";
		break;
	case 0x06:
		str = "Changed Combination key";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Key type: %s (0x%2.2x)", str, key_type);
}

static void print_key_size(uint8_t key_size)
{
	print_field("Key size: %d", key_size);
}

static void print_hex_field(const char *label, const uint8_t *data,
								uint8_t len)
{
	char str[len * 2 + 1];
	uint8_t i;

	for (i = 0; i < len; i++)
		sprintf(str + (i * 2), "%2.2x", data[i]);

	print_field("%s: %s", label, str);
}

static void print_key(const char *label, const uint8_t *link_key)
{
	print_hex_field(label, link_key, 16);
}

static void print_link_key(const uint8_t *link_key)
{
	print_key("Link key", link_key);
}

static void print_pin_code(const uint8_t *pin_code)
{
	print_key("PIN code", pin_code);
}

static void print_hash(const uint8_t *hash)
{
	print_key("Hash C", hash);
}

static void print_randomizer(const uint8_t *randomizer)
{
	print_key("Randomizer R", randomizer);
}

static void print_passkey(uint32_t passkey)
{
	print_field("Passkey: %06d", btohl(passkey));
}

static void print_io_capability(uint8_t capability)
{
	const char *str;

	switch (capability) {
	case 0x00:
		str = "DisplayOnly";
		break;
	case 0x01:
		str = "DisplayYesNo";
		break;
	case 0x02:
		str = "KeyboardOnly";
		break;
	case 0x03:
		str = "NoInputNoOutput";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("IO capability: %s (0x%2.2x)", str, capability);
}

static void print_oob_data(uint8_t oob_data)
{
	const char *str;

	switch (oob_data) {
	case 0x00:
		str = "Authentication data not present";
		break;
	case 0x01:
		str = "Authentication data present";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("OOB data: %s (0x%2.2x)", str, oob_data);
}

static void print_authentication(uint8_t authentication)
{
	const char *str;

	switch (authentication) {
	case 0x00:
		str = "No Bonding - MITM not required";
		break;
	case 0x01:
		str = "No Bonding - MITM required";
		break;
	case 0x02:
		str = "Dedicated Bonding - MITM not required";
		break;
	case 0x03:
		str = "Dedicated Bonding - MITM required";
		break;
	case 0x04:
		str = "General Bonding - MITM not required";
		break;
	case 0x05:
		str = "General Bonding - MITM required";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Authentication: %s (0x%2.2x)", str, authentication);
}

static void print_flow_direction(uint8_t direction)
{
	const char *str;

	switch (direction) {
	case 0x00:
		str = "Outgoing";
		break;
	case 0x01:
		str = "Incoming";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Flow direction: %s (0x%2.2x)", str, direction);
}

static void print_service_type(uint8_t service_type)
{
	const char *str;

	switch (service_type) {
	case 0x00:
		str = "No Traffic";
		break;
	case 0x01:
		str = "Best Effort";
		break;
	case 0x02:
		str = "Guaranteed";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Service type: %s (0x%2.2x)", str, service_type);
}

static void print_short_range_mode(uint8_t mode)
{
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

	print_field("Short range mode: %s (0x%2.2x)", str, mode);
}

static void print_amp_status(uint8_t amp_status)
{
	const char *str;

	switch (amp_status) {
	case 0x00:
		str = "Present";
		break;
	case 0x01:
		str = "Bluetooth only";
		break;
	case 0x02:
		str = "No capacity";
		break;
	case 0x03:
		str = "Low capacity";
		break;
	case 0x04:
		str = "Medium capacity";
		break;
	case 0x05:
		str = "High capacity";
		break;
	case 0x06:
		str = "Full capacity";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("AMP status: %s (0x%2.2x)", str, amp_status);
}

static void print_num_resp(uint8_t num_resp)
{
	print_field("Num responses: %d", num_resp);
}

static void print_num_reports(uint8_t num_reports)
{
	print_field("Num reports: %d", num_reports);
}

static void print_rssi(int8_t rssi)
{
	print_field("RSSI: %d dBm", rssi);
}

static void print_slot_625(const char *label, uint16_t value)
{
	 print_field("%s: %.3f msec (0x%4.4x)", label,
					btohs(value) * 0.625, value);
}

static void print_slot_125(const char *label, uint16_t value)
{
	print_field("%s: %.2f msec (0x%4.4x)", label,
					btohs(value) * 1.25, value);
}

static void print_timeout(uint16_t timeout)
{
	print_slot_625("Timeout", timeout);
}

static void print_interval(uint16_t interval)
{
	print_slot_625("Interval", interval);
}

static void print_window(uint16_t window)
{
	print_slot_625("Window", window);
}

static void print_role(uint8_t role)
{
	const char *str;

	switch (role) {
	case 0x00:
		str = "Master";
		break;
	case 0x01:
		str = "Slave";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Role: %s (0x%2.2x)", str, role);
}

static void print_mode(uint8_t mode)
{
	const char *str;

	switch (mode) {
	case 0x00:
		str = "Active";
		break;
	case 0x01:
		str = "Hold";
		break;
	case 0x02:
		str = "Sniff";
		break;
	case 0x03:
		str = "Park";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Mode: %s (0x%2.2x)", str, mode);
}

static void print_name(const uint8_t *name)
{
	char str[249];

	memcpy(str, name, 248);
	str[248] = '\0';

	print_field("Name: %s", str);
}

static void print_version(const char *label, uint8_t version, uint16_t revision)
{
	print_field("%s: %d - 0x%4.4x", label, version, revision);
}

static void print_hci_version(uint8_t hci_ver, uint16_t hci_rev)
{
	print_version("HCI version", hci_ver, hci_rev);
}

static void print_lmp_version(uint8_t lmp_ver, uint16_t lmp_subver)
{
	print_version("LMP version", lmp_ver, lmp_subver);
}

static void print_manufacturer(uint16_t manufacturer)
{
	print_field("Manufacturer: %d", manufacturer);
}

static void print_commands(const uint8_t *commands)
{
	char str[129];
	int i;

	for (i = 0; i < 64; i++)
		sprintf(str + (i * 2), "%2.2x", commands[i]);

	print_field("Commands: 0x%s", str);
}

static void print_features(const uint8_t *features)
{
	char str[41];
	int i;

	for (i = 0; i < 8; i++)
		sprintf(str + (i * 5), " 0x%2.2x", features[i]);

	print_field("Features:%s", str);
}

static void print_le_states(const uint8_t *states)
{
	char str[17];
	int i;

	for (i = 0; i < 8; i++)
		sprintf(str + (i * 2), "%2.2x", states[i]);

	print_field("States: 0x%s", str);
}

static void print_le_channel_map(const uint8_t *map)
{
	char str[11];
	int i;

	for (i = 0; i < 5; i++)
		sprintf(str + (i * 2), "%2.2x", map[i]);

	print_field("Channel map: 0x%s", str);
}

static void print_random_number(const uint8_t *number)
{
	print_hex_field("Random number", number, 8);
}

static void print_event_mask(const uint8_t *mask)
{
	char str[17];
	int i;

	for (i = 0; i < 8; i++)
		sprintf(str + (i * 2), "%2.2x", mask[i]);

	print_field("Mask: 0x%s", str);
}

static void print_fec(uint8_t fec)
{
	const char *str;

	switch (fec) {
	case 0x00:
		str = "Not required";
		break;
	case 0x01:
		str = "Required";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("FEC: %s (0x%02x)", str, fec);
}

#define BT_EIR_FLAGS			0x01
#define BT_EIR_UUID16_SOME		0x02
#define BT_EIR_UUID16_ALL		0x03
#define BT_EIR_UUID32_SOME		0x04
#define BT_EIR_UUID32_ALL		0x05
#define BT_EIR_UUID128_SOME		0x06
#define BT_EIR_UUID128_ALL		0x07
#define BT_EIR_NAME_SHORT		0x08
#define BT_EIR_NAME_COMPLETE		0x09
#define BT_EIR_TX_POWER			0x0a
#define BT_EIR_CLASS_OF_DEV		0x0d
#define BT_EIR_SSP_HASH			0x0e
#define BT_EIR_SSP_RANDOMIZER		0x0f
#define BT_EIR_DEVICE_ID		0x10
#define BT_EIR_SMP_TK			0x10
#define BT_EIR_SMP_OOB_FLAGS		0x11
#define BT_EIR_SLAVE_CONN_INT		0x12
#define BT_EIR_SERVICE_UUID16		0x14
#define BT_EIR_SERVICE_UUID128		0x15
#define BT_EIR_SERVICE_DATA		0x16
#define BT_EIR_RANDOM_ADDRESS		0x17
#define BT_EIR_PUBLIC_ADDRESS		0x18
#define BT_EIR_GAP_APPEARANCE		0x19
#define BT_EIR_MANUFACTURER_DATA	0xff

static void print_uuid16_list(const char *label, const void *data,
							uint8_t data_len)
{
	const uint16_t *uuids = data;
	uint8_t count = data_len / sizeof(uint16_t);
	char str[count * 7 + 1];
	unsigned int i;

	for (i = 0; i < count; i++)
		sprintf(str + (i * 7), "0x%4.4x ", bt_get_le16(&uuids[i]));

	print_field("%s: %s", label, str);
}

static void print_uuid32_list(const char *label, const void *data,
							uint8_t data_len)
{
	const uint32_t *uuids = data;
	uint8_t count = data_len / sizeof(uint32_t);
	char str[count * 11 + 1];
	unsigned int i;

	for (i = 0; i < count; i++)
		sprintf(str + (i * 11), "0x%8.8x ", bt_get_le32(&uuids[i]));

	print_field("%s: %s", label, str);
}

static void print_uuid128_list(const char *label, const void *data,
							uint8_t data_len)
{
	uint8_t count = data_len / 16;
	char str[count * 38 + 1];
	unsigned int i;

	for (i = 0; i < count; i++) {
		const uint8_t *uuid = data + (i * 16);

		sprintf(str + (i * 38), "%.8x-%.4x-%.4x-%.4x-%.8x%.4x ",
				bt_get_le32(&uuid[12]), bt_get_le16(&uuid[10]),
				bt_get_le16(&uuid[8]), bt_get_le16(&uuid[6]),
				bt_get_le32(&uuid[2]), bt_get_le16(&uuid[0]));
	}

	print_field("%s: %s", label, str);
}

static void print_eir(const uint8_t *eir, uint8_t eir_len, bool le)
{
	uint8_t len = 0;

	if (eir_len == 0)
		return;

	while (len < eir_len - 1) {
		uint8_t field_len = eir[0];
		const uint8_t *data = &eir[2];
		uint8_t data_len;
		char name[239], label[100];
		uint32_t cls;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		len += field_len + 1;

		/* Do not continue EIR Data parsing if got incorrect length */
		if (len > eir_len) {
			len -= field_len + 1;
			break;
		}

		data_len = field_len - 1;

		switch (eir[1]) {
		case BT_EIR_FLAGS:
			print_field("Flags: 0x%2.2x", *data);
			break;

		case BT_EIR_UUID16_SOME:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs (partial)",
							data, data_len);
			break;

		case BT_EIR_UUID16_ALL:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs (complete)",
							data, data_len);
			break;

		case BT_EIR_UUID32_SOME:
			if (data_len < sizeof(uint32_t))
				break;
			print_uuid32_list("32-bit Service UUIDs (partial)",
							data, data_len);
			break;

		case BT_EIR_UUID32_ALL:
			if (data_len < sizeof(uint32_t))
				break;
			print_uuid32_list("32-bit Service UUIDs (complete)",
							data, data_len);
			break;
		case BT_EIR_UUID128_SOME:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs (partial)",
								data, data_len);
			break;

		case BT_EIR_UUID128_ALL:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs (complete)",
								data, data_len);
			break;

		case BT_EIR_NAME_SHORT:
			memset(name, 0, sizeof(name));
			memcpy(name, data, data_len);
			print_field("Name (short): %s", name);
			break;

		case BT_EIR_NAME_COMPLETE:
			memset(name, 0, sizeof(name));
			memcpy(name, data, data_len);
			print_field("Name (complete): %s", name);
			break;

		case BT_EIR_TX_POWER:
			print_field("TX power: %d dBm", (int8_t) *data);
			break;

		case BT_EIR_CLASS_OF_DEV:
			if (data_len < 3)
				break;
			cls = data[0] | (data[1] << 8) | (data[2] << 16);
			print_field("Class Of Device: 0x%6.6x", cls);
			break;

		case BT_EIR_SSP_HASH:
			print_hex_field("SSP Hash", data, data_len);
			break;

		case BT_EIR_SSP_RANDOMIZER:
			print_hex_field("SSP Rand", data, data_len);
			break;

		case BT_EIR_DEVICE_ID:
			/* SMP TK has the same value as Device ID */
			if (le)
				print_hex_field("SMP TK", data, data_len);
			else if (data_len >= 8)
				print_field("Device ID: "
						"Source 0x%4.4x "
						"Vendor 0x%4.4x "
						"Product 0x%4.4x "
						"Version 0x%4.4x",
						bt_get_le16(&data[0]),
						bt_get_le16(&data[2]),
						bt_get_le16(&data[4]),
						bt_get_le16(&data[6]));
			break;

		case BT_EIR_SMP_OOB_FLAGS:
			print_field("SMP OOB Flags: 0x%2.2x", *data);
			break;

		case BT_EIR_SLAVE_CONN_INT:
			if (data_len < 4)
				break;
			print_field("Slave Conn. Interval: 0x%4.4x - 0x%4.4x",
							bt_get_le16(&data[0]),
							bt_get_le16(&data[2]));
			break;

		case BT_EIR_SERVICE_UUID16:
			if (data_len < sizeof(uint16_t))
				break;
			print_uuid16_list("16-bit Service UUIDs",
							data, data_len);
			break;

		case BT_EIR_SERVICE_UUID128:
			if (data_len < 16)
				break;
			print_uuid128_list("128-bit Service UUIDs",
							data, data_len);
			break;

		case BT_EIR_SERVICE_DATA:
			if (data_len < 2)
				break;
			sprintf(label, "Service Data (UUID 0x%4.4x)",
							bt_get_le16(&data[0]));
			print_hex_field(label, &data[2], data_len - 2);
			break;

		case BT_EIR_RANDOM_ADDRESS:
			if (data_len < 6)
				break;
			print_addr(data, 0x01);
			break;

		case BT_EIR_PUBLIC_ADDRESS:
			if (data_len < 6)
				break;
			print_addr(data, 0x00);
			break;

		case BT_EIR_GAP_APPEARANCE:
			if (data_len < 2)
				break;
			print_field("Appearance: 0x%4.4x", bt_get_le16(data));
			break;

		case BT_EIR_MANUFACTURER_DATA:
			print_hex_field("Manufacturer Data", data, data_len);
			break;

		default:
			sprintf(label, "Unknown EIR field 0x%2.2x", eir[1]);
			print_hex_field(label, data, data_len);
			break;
		}

		eir += field_len + 1;
	}

	if (len < eir_len && eir[0] != 0)
		packet_hexdump(eir, eir_len - len);
}

void packet_hexdump(const unsigned char *buf, uint16_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	uint16_t i;

	if (!len)
		return;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 0] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 1] = hexdigits[buf[i] & 0xf];
		str[((i % 16) * 3) + 2] = ' ';
		str[(i % 16) + 49] = isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[47] = ' ';
			str[48] = ' ';
			str[65] = '\0';
			print_text(COLOR_WHITE, "%s", str);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		uint16_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 0] = ' ';
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[j + 49] = ' ';
		}
		str[47] = ' ';
		str[48] = ' ';
		str[65] = '\0';
		print_text(COLOR_WHITE, "%s", str);
	}
}

void packet_control(struct timeval *tv, uint16_t index, uint16_t opcode,
					const void *data, uint16_t size)
{
	if (index_filter && index_number != index)
		return;

	control_message(opcode, data, size);
}

#define MONITOR_NEW_INDEX	0
#define MONITOR_DEL_INDEX	1
#define MONITOR_COMMAND_PKT	2
#define MONITOR_EVENT_PKT	3
#define MONITOR_ACL_TX_PKT	4
#define MONITOR_ACL_RX_PKT	5
#define MONITOR_SCO_TX_PKT	6
#define MONITOR_SCO_RX_PKT	7

struct monitor_new_index {
	uint8_t  type;
	uint8_t  bus;
	bdaddr_t bdaddr;
	char     name[8];
} __attribute__((packed));

#define MONITOR_NEW_INDEX_SIZE 16

#define MONITOR_DEL_INDEX_SIZE 0

#define MAX_INDEX 16

struct index_data {
	bdaddr_t bdaddr;
	void *frag_buf;
	uint16_t frag_len;
};

static struct index_data index_list[MAX_INDEX];

uint32_t packet_get_flags(uint16_t opcode)
{
	switch (opcode) {
	case MONITOR_NEW_INDEX:
	case MONITOR_DEL_INDEX:
		break;
	case MONITOR_COMMAND_PKT:
		return 0x02;
	case MONITOR_EVENT_PKT:
		return 0x03;
	case MONITOR_ACL_TX_PKT:
		return 0x00;
	case MONITOR_ACL_RX_PKT:
		return 0x01;
	case MONITOR_SCO_TX_PKT:
	case MONITOR_SCO_RX_PKT:
		break;
	}

	return 0xff;
}

uint16_t packet_get_opcode(uint8_t type, uint32_t flags)
{
	switch (type) {
	case HCI_COMMAND_PKT:
		return MONITOR_COMMAND_PKT;
	case HCI_ACLDATA_PKT:
		if (flags & 0x01)
			return MONITOR_ACL_RX_PKT;
		else
			return MONITOR_ACL_TX_PKT;
	case HCI_SCODATA_PKT:
		if (flags & 0x01)
			return MONITOR_SCO_RX_PKT;
		else
			return MONITOR_SCO_TX_PKT;
	case HCI_EVENT_PKT:
		return MONITOR_EVENT_PKT;
	case 0xff:
		if (flags & 0x02) {
			if (flags & 0x01)
				return MONITOR_EVENT_PKT;
			else
				return MONITOR_COMMAND_PKT;
		} else {
			if (flags & 0x01)
				return MONITOR_ACL_RX_PKT;
			else
				return MONITOR_ACL_TX_PKT;
		}
		break;
	}

	return 0xff;
}

void packet_monitor(struct timeval *tv, uint16_t index, uint16_t opcode,
					const void *data, uint16_t size)
{
	const struct monitor_new_index *ni;
	char str[18], extra_str[24];

	if (index_filter && index_number != index)
		return;

	if (tv && time_offset == ((time_t) -1))
		time_offset = tv->tv_sec;

	switch (opcode) {
	case MONITOR_NEW_INDEX:
		ni = data;

		if (index < MAX_INDEX) {
			bacpy(&index_list[index].bdaddr, &ni->bdaddr);
			index_list[index].frag_buf = NULL;
			index_list[index].frag_len = 0;
		}

		ba2str(&ni->bdaddr, str);
		packet_new_index(tv, index, str, ni->type, ni->bus, ni->name);
		break;
	case MONITOR_DEL_INDEX:
		if (index < MAX_INDEX) {
			ba2str(&index_list[index].bdaddr, str);
			free(index_list[index].frag_buf);
		} else
			ba2str(BDADDR_ANY, str);

		packet_del_index(tv, index, str);
		break;
	case MONITOR_COMMAND_PKT:
		packet_hci_command(tv, index, data, size);
		break;
	case MONITOR_EVENT_PKT:
		packet_hci_event(tv, index, data, size);
		break;
	case MONITOR_ACL_TX_PKT:
		packet_hci_acldata(tv, index, false, data, size);
		break;
	case MONITOR_ACL_RX_PKT:
		packet_hci_acldata(tv, index, true, data, size);
		break;
	case MONITOR_SCO_TX_PKT:
		packet_hci_scodata(tv, index, false, data, size);
		break;
	case MONITOR_SCO_RX_PKT:
		packet_hci_scodata(tv, index, true, data, size);
		break;
	default:
		sprintf(extra_str, "(code %d len %d)", opcode, size);
		print_packet(tv, index, '*', COLOR_ERROR,
					"Unknown packet", NULL, extra_str);
		packet_hexdump(data, size);
		break;
	}
}

static void null_cmd(const void *data, uint8_t size)
{
}

static void status_rsp(const void *data, uint8_t size)
{
	uint8_t status = *((const uint8_t *) data);

	print_status(status);
}

static void status_bdaddr_rsp(const void *data, uint8_t size)
{
	uint8_t status = *((const uint8_t *) data);

	print_status(status);
	print_bdaddr(data + 1);
}

static void inquiry_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_inquiry *cmd = data;

	print_iac(cmd->lap);
	print_field("Length: %.2fs (0x%2.2x)",
				cmd->length * 1.28, cmd->length);
	print_num_resp(cmd->num_resp);
}

static void periodic_inquiry_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_periodic_inquiry *cmd = data;

	print_field("Max period: %.2fs (0x%2.2x)",
				cmd->max_period * 1.28, cmd->max_period);
	print_field("Min period: %.2fs (0x%2.2x)",
				cmd->min_period * 1.28, cmd->min_period);
	print_iac(cmd->lap);
	print_field("Length: %.2fs (0x%2.2x)",
				cmd->length * 1.28, cmd->length);
	print_num_resp(cmd->num_resp);
}

static void create_conn_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_create_conn *cmd = data;
	const char *str;

	print_bdaddr(cmd->bdaddr);
	print_pkt_type(cmd->pkt_type);
	print_pscan_rep_mode(cmd->pscan_rep_mode);
	print_pscan_mode(cmd->pscan_mode);
	print_clock_offset(cmd->clock_offset);

	switch (cmd->role_switch) {
	case 0x00:
		str = "Stay master";
		break;
	case 0x01:
		str = "Allow slave";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Role switch: %s (0x%2.2x)", str, cmd->role_switch);
}

static void disconnect_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_disconnect *cmd = data;

	print_handle(cmd->handle);
	print_reason(cmd->reason);
}

static void add_sco_conn_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_add_sco_conn *cmd = data;

	print_handle(cmd->handle);
	print_pkt_type(cmd->pkt_type);
}

static void create_conn_cancel_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_create_conn_cancel *cmd = data;

	print_bdaddr(cmd->bdaddr);
}

static void accept_conn_request_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_accept_conn_request *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_role(cmd->role);
}

static void reject_conn_request_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_reject_conn_request *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_reason(cmd->reason);
}

static void link_key_request_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_link_key_request_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_link_key(cmd->link_key);
}

static void link_key_request_neg_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_link_key_request_neg_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
}

static void pin_code_request_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_pin_code_request_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_field("PIN length: %d", cmd->pin_len);
	print_pin_code(cmd->pin_code);
}

static void pin_code_request_neg_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_pin_code_request_neg_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
}

static void change_conn_pkt_type_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_change_conn_pkt_type *cmd = data;

	print_handle(cmd->handle);
	print_pkt_type(cmd->pkt_type);
}

static void auth_requested_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_auth_requested *cmd = data;

	print_handle(cmd->handle);
}

static void set_conn_encrypt_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_set_conn_encrypt *cmd = data;

	print_handle(cmd->handle);
	print_encr_mode(cmd->encr_mode);
}

static void change_conn_link_key_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_change_conn_link_key *cmd = data;

	print_handle(cmd->handle);
}

static void master_link_key_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_master_link_key *cmd = data;

	print_key_flag(cmd->key_flag);
}

static void remote_name_request_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_remote_name_request *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_pscan_rep_mode(cmd->pscan_rep_mode);
	print_pscan_mode(cmd->pscan_mode);
	print_clock_offset(cmd->clock_offset);
}

static void remote_name_request_cancel_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_remote_name_request_cancel *cmd = data;

	print_bdaddr(cmd->bdaddr);
}

static void read_remote_features_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_remote_features *cmd = data;

	print_handle(cmd->handle);
}

static void read_remote_ext_features_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_remote_ext_features *cmd = data;

	print_handle(cmd->handle);
	print_field("Page: %d", cmd->page);
}

static void read_remote_version_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_remote_version *cmd = data;

	print_handle(cmd->handle);
}

static void read_clock_offset_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_clock_offset *cmd = data;

	print_handle(cmd->handle);
}

static void read_lmp_handle_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_lmp_handle *cmd = data;

	print_handle(cmd->handle);
}

static void read_lmp_handle_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_lmp_handle *rsp = data;

	print_status(rsp->status);
	print_handle(rsp->handle);
	print_field("LMP handle: %d", rsp->lmp_handle);
	print_field("Reserved: %d", btohl(rsp->reserved));
}

static void setup_sync_conn_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_setup_sync_conn *cmd = data;

	print_handle(cmd->handle);
	print_field("Transmit bandwidth: %d", btohl(cmd->tx_bandwidth));
	print_field("Receive bandwidth: %d", btohl(cmd->rx_bandwidth));
	print_field("Max latency: %d", btohs(cmd->max_latency));
	print_voice_setting(cmd->voice_setting);
	print_retransmission_effort(cmd->retrans_effort);
	print_pkt_type(cmd->pkt_type);
}

static void accept_sync_conn_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_accept_sync_conn *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_field("Transmit bandwidth: %d", btohl(cmd->tx_bandwidth));
	print_field("Receive bandwidth: %d", btohl(cmd->rx_bandwidth));
	print_field("Max latency: %d", btohs(cmd->max_latency));
	print_voice_setting(cmd->voice_setting);
	print_retransmission_effort(cmd->retrans_effort);
	print_pkt_type(cmd->pkt_type);
}

static void reject_sync_conn_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_reject_sync_conn *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_reason(cmd->reason);
}

static void io_capability_request_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_io_capability_request_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_io_capability(cmd->capability);
	print_oob_data(cmd->oob_data);
	print_authentication(cmd->authentication);
}

static void user_confirm_request_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_user_confirm_request_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
}

static void user_confirm_request_neg_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_user_confirm_request_neg_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
}

static void user_passkey_request_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_user_passkey_request_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_passkey(cmd->passkey);
}

static void user_passkey_request_neg_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_user_passkey_request_neg_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
}

static void remote_oob_data_request_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_remote_oob_data_request_reply *cmd = data;

        print_bdaddr(cmd->bdaddr);
	print_hash(cmd->hash);
	print_randomizer(cmd->randomizer);
}

static void remote_oob_data_request_neg_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_remote_oob_data_request_neg_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
}

static void io_capability_request_neg_reply_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_io_capability_request_neg_reply *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_reason(cmd->reason);
}

static void create_phy_link_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_create_phy_link *cmd = data;

	print_phy_handle(cmd->phy_handle);
	print_key_len(cmd->key_len);
	print_key_type(cmd->key_type);

	packet_hexdump(data + 3, size - 3);
}

static void accept_phy_link_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_accept_phy_link *cmd = data;

	print_phy_handle(cmd->phy_handle);
	print_key_len(cmd->key_len);
	print_key_type(cmd->key_type);

	packet_hexdump(data + 3, size - 3);
}

static void disconn_phy_link_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_disconn_phy_link *cmd = data;

	print_phy_handle(cmd->phy_handle);
	print_reason(cmd->reason);
}

static void create_logic_link_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_create_logic_link *cmd = data;

	print_phy_handle(cmd->phy_handle);

	packet_hexdump(data + 1, size - 1);
}

static void accept_logic_link_cmd(const void *data, uint8_t size)
{
        const struct bt_hci_cmd_accept_logic_link *cmd = data;

	print_phy_handle(cmd->phy_handle);

	packet_hexdump(data + 1, size - 1);
}

static void disconn_logic_link_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_disconn_logic_link *cmd = data;

	print_handle(cmd->handle);
}

static void hold_mode_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_hold_mode *cmd = data;

	print_handle(cmd->handle);
	print_slot_625("Hold max interval", cmd->max_interval);
	print_slot_625("Hold min interval", cmd->min_interval);
}

static void sniff_mode_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_sniff_mode *cmd = data;

	print_handle(cmd->handle);
	print_slot_625("Sniff max interval", cmd->max_interval);
	print_slot_625("Sniff min interval", cmd->min_interval);
	print_slot_125("Sniff attempt", cmd->attempt);
	print_slot_125("Sniff timeout", cmd->timeout);
}

static void exit_sniff_mode_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_exit_sniff_mode *cmd = data;

	print_handle(cmd->handle);
}

static void park_state_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_park_state *cmd = data;

	print_handle(cmd->handle);
	print_slot_625("Beacon max interval", cmd->max_interval);
	print_slot_625("Beacon min interval", cmd->min_interval);
}

static void exit_park_state_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_exit_park_state *cmd = data;

	print_handle(cmd->handle);
}

static void qos_setup_cmd(const void *data, uint8_t size)
{
	packet_hexdump(data, size);
}

static void role_discovery_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_role_discovery *cmd = data;

	print_handle(cmd->handle);
}

static void role_discovery_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_role_discovery *rsp = data;

	print_status(rsp->status);
	print_handle(rsp->handle);
	print_role(rsp->role);
}

static void switch_role_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_switch_role *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_role(cmd->role);
}

static void read_link_policy_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_link_policy *cmd = data;

	print_handle(cmd->handle);
}

static void read_link_policy_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_link_policy *rsp = data;

	print_status(rsp->status);
	print_handle(rsp->handle);
	print_link_policy(rsp->policy);
}

static void write_link_policy_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_link_policy *cmd = data;

	print_handle(cmd->handle);
	print_link_policy(cmd->policy);
}

static void write_link_policy_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_write_link_policy *rsp = data;

	print_status(rsp->status);
	print_handle(rsp->handle);
}

static void read_default_link_policy_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_default_link_policy *rsp = data;

	print_status(rsp->status);
	print_link_policy(rsp->policy);
}

static void write_default_link_policy_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_default_link_policy *cmd = data;

	print_link_policy(cmd->policy);
}

static void flow_spec_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_flow_spec *cmd = data;

	print_handle(cmd->handle);
	print_field("Flags: 0x%2.2x", cmd->flags);

	print_flow_direction(cmd->direction);
	print_service_type(cmd->service_type);

	print_field("Token rate: %d", btohl(cmd->token_rate));
	print_field("Token bucket size: %d", btohl(cmd->token_bucket_size));
	print_field("Peak bandwidth: %d", btohl(cmd->peak_bandwidth));
	print_field("Access latency: %d", btohl(cmd->access_latency));
}

static void sniff_subrating_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_sniff_subrating *cmd = data;

	print_handle(cmd->handle);
	print_slot_625("Max latency", cmd->max_latency);
	print_slot_625("Min remote timeout", cmd->min_remote_timeout);
	print_slot_625("Min local timeout", cmd->min_local_timeout);
}

static void sniff_subrating_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_sniff_subrating *rsp = data;

	print_status(rsp->status);
	print_handle(rsp->handle);
}

static void set_event_mask_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_set_event_mask *cmd = data;

	print_event_mask(cmd->mask);
}

static void set_event_filter_cmd(const void *data, uint8_t size)
{
	uint8_t type = *((const uint8_t *) data);

	print_field("Type: 0x%2.2x", type);

	packet_hexdump(data + 1, size - 1);
}

static void flush_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_flush *cmd = data;

	print_handle(cmd->handle);
}

static void flush_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_flush *rsp = data;

	print_status(rsp->status);
	print_handle(rsp->handle);
}

static void read_pin_type_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_pin_type *rsp = data;

	print_status(rsp->status);
	print_pin_type(rsp->pin_type);
}

static void write_pin_type_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_pin_type *cmd = data;

	print_pin_type(cmd->pin_type);
}

static void read_stored_link_key_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_stored_link_key *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_field("Read all: 0x%2.2x", cmd->read_all);
}

static void read_stored_link_key_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_stored_link_key *rsp = data;

	print_status(rsp->status);
	print_field("Max num keys: %d", btohs(rsp->max_num_keys));
	print_field("Num keys: %d", btohs(rsp->num_keys));
}

static void write_stored_link_key_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_stored_link_key *cmd = data;

	print_field("Num keys: %d", cmd->num_keys);

	packet_hexdump(data + 1, size - 1);
}

static void write_stored_link_key_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_write_stored_link_key *rsp = data;

	print_status(rsp->status);
	print_field("Num keys: %d", rsp->num_keys);
}

static void delete_stored_link_key_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_delete_stored_link_key *cmd = data;

	print_bdaddr(cmd->bdaddr);
	print_field("Delete all: 0x%2.2x", cmd->delete_all);
}

static void delete_stored_link_key_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_delete_stored_link_key *rsp = data;

	print_status(rsp->status);
	print_field("Num keys: %d", btohs(rsp->num_keys));
}

static void write_local_name_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_local_name *cmd = data;

	print_name(cmd->name);
}

static void read_local_name_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_local_name *rsp = data;

	print_status(rsp->status);
	print_name(rsp->name);
}

static void read_conn_accept_timeout_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_conn_accept_timeout *rsp = data;

	print_status(rsp->status);
	print_timeout(rsp->timeout);
}

static void write_conn_accept_timeout_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_conn_accept_timeout *cmd = data;

	print_timeout(cmd->timeout);
}

static void read_page_timeout_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_page_timeout *rsp = data;

	print_status(rsp->status);
	print_timeout(rsp->timeout);
}

static void write_page_timeout_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_page_timeout *cmd = data;

	print_timeout(cmd->timeout);
}

static void read_scan_enable_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_scan_enable *rsp = data;

	print_status(rsp->status);
	print_scan_enable(rsp->enable);
}

static void write_scan_enable_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_scan_enable *cmd = data;

	print_scan_enable(cmd->enable);
}

static void read_class_of_dev_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_class_of_dev *rsp = data;

	print_status(rsp->status);
	print_dev_class(rsp->dev_class);
}

static void write_class_of_dev_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_class_of_dev *cmd = data;

	print_dev_class(cmd->dev_class);
}

static void read_voice_setting_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_voice_setting *rsp = data;

	print_status(rsp->status);
	print_voice_setting(rsp->setting);
}

static void write_voice_setting_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_voice_setting *cmd = data;

	print_voice_setting(cmd->setting);
}

static void read_inquiry_mode_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_inquiry_mode *rsp = data;

	print_status(rsp->status);
	print_inquiry_mode(rsp->mode);
}

static void write_inquiry_mode_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_inquiry_mode *cmd = data;

	print_inquiry_mode(cmd->mode);
}

static void read_ext_inquiry_response_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_ext_inquiry_response *rsp = data;

	print_status(rsp->status);
	print_fec(rsp->fec);
	print_eir(rsp->data, sizeof(rsp->data), false);
}

static void write_ext_inquiry_response_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_ext_inquiry_response *cmd = data;

	print_fec(cmd->fec);
	print_eir(cmd->data, sizeof(cmd->data), false);
}

static void refresh_encrypt_key_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_refresh_encrypt_key *cmd = data;

	print_handle(cmd->handle);
}

static void read_simple_pairing_mode_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_simple_pairing_mode *rsp = data;

	print_status(rsp->status);
	print_simple_pairing_mode(rsp->mode);
}

static void write_simple_pairing_mode_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_simple_pairing_mode *cmd = data;

	print_simple_pairing_mode(cmd->mode);
}

static void read_inquiry_resp_tx_power_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_inquiry_resp_tx_power *rsp = data;

	print_status(rsp->status);
	print_field("TX power: %d dBm", rsp->level);
}

static void enhanced_flush_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_enhanced_flush *cmd = data;
	const char *str;

	print_handle(cmd->handle);

	switch (cmd->type) {
	case 0x00:
		str = "Automatic flushable only";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, cmd->type);
}

static void set_event_mask_page2_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_set_event_mask_page2 *cmd = data;

	print_event_mask(cmd->mask);
}

static void read_le_host_supported_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_le_host_supported *rsp = data;

	print_status(rsp->status);
	print_field("Supported: 0x%2.2x", rsp->supported);
	print_field("Simultaneous: 0x%2.2x", rsp->simultaneous);
}

static void write_le_host_supported_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_le_host_supported *cmd = data;

	print_field("Supported: 0x%2.2x", cmd->supported);
	print_field("Simultaneous: 0x%2.2x", cmd->simultaneous);
}

static void read_local_version_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_local_version *rsp = data;

	print_status(rsp->status);
	print_hci_version(rsp->hci_ver, rsp->hci_rev);
	print_lmp_version(rsp->lmp_ver, rsp->lmp_subver);
	print_manufacturer(rsp->manufacturer);
}

static void read_local_commands_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_local_commands *rsp = data;

	print_status(rsp->status);
	print_commands(rsp->commands);
}

static void read_local_features_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_local_features *rsp = data;

	print_status(rsp->status);
	print_features(rsp->features);
}

static void read_local_ext_features_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_local_ext_features *cmd = data;

	print_field("Page: %d", cmd->page);
}

static void read_local_ext_features_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_local_ext_features *rsp = data;

	print_status(rsp->status);
	print_field("Page: %d/%d", rsp->page, rsp->max_page);
	print_features(rsp->features);
}

static void read_buffer_size_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_buffer_size *rsp = data;

	print_status(rsp->status);
	print_field("ACL MTU: %-4d ACL max packet: %d",
				btohs(rsp->acl_mtu), btohs(rsp->acl_max_pkt));
	print_field("SCO MTU: %-4d SCO max packet: %d",
				rsp->sco_mtu, btohs(rsp->sco_max_pkt));
}

static void read_country_code_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_country_code *rsp = data;
	const char *str;

	print_status(rsp->status);

	switch (rsp->code) {
	case 0x00:
		str = "North America, Europe*, Japan";
		break;
	case 0x01:
		str = "France";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Country code: %s (0x%2.2x)", str, rsp->code);
}

static void read_bd_addr_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_bd_addr *rsp = data;

	print_status(rsp->status);
	print_bdaddr(rsp->bdaddr);
}

static void read_data_block_size_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_data_block_size *rsp = data;

	print_status(rsp->status);
	print_field("Max ACL length: %d", btohs(rsp->max_acl_len));
	print_field("Block length: %d", btohs(rsp->block_len));
	print_field("Num blocks: %d", btohs(rsp->num_blocks));
}

static void read_encrypt_key_size_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_encrypt_key_size *cmd = data;

	print_handle(cmd->handle);
}

static void read_encrypt_key_size_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_encrypt_key_size *rsp = data;

	print_status(rsp->status);
	print_handle(rsp->handle);
	print_key_size(rsp->key_size);
}

static void read_local_amp_info_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_local_amp_info *rsp = data;
	const char *str;

	print_status(rsp->status);
	print_amp_status(rsp->amp_status);

	print_field("Total bandwidth: %d kbps", btohl(rsp->total_bw));
	print_field("Max guaranteed bandwidth: %d kbps", btohl(rsp->max_bw));
	print_field("Min latency: %d", btohl(rsp->min_latency));
	print_field("Max PDU size: %d", btohl(rsp->max_pdu));

	switch (rsp->amp_type) {
	case 0x00:
		str = "Primary BR/EDR Controller";
		break;
	case 0x01:
		str = "802.11 AMP Controller";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Controller type: %s (0x%2.2x)", str, rsp->amp_type);

	print_field("PAL capabilities: 0x%4.4x", rsp->pal_cap);
	print_field("Max ASSOC length: %d", rsp->max_assoc_len);
	print_field("Max flush timeout: %d", rsp->max_flush_to);
	print_field("Best effort flush timeout: %d", rsp->be_flush_to);
}

static void read_local_amp_assoc_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_read_local_amp_assoc *cmd = data;

	print_phy_handle(cmd->phy_handle);
	print_field("Length so far: %d", btohs(cmd->len_so_far));
	print_field("Max ASSOC length: %d", btohs(cmd->max_assoc_len));
}

static void read_local_amp_assoc_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_read_local_amp_assoc *rsp = data;

	print_status(rsp->status);
	print_phy_handle(rsp->phy_handle);
	print_field("Remaining ASSOC length: %d", btohs(rsp->remain_assoc_len));

	packet_hexdump(data + 4, size - 4);
}

static void write_remote_amp_assoc_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_write_remote_amp_assoc *cmd = data;

	print_phy_handle(cmd->phy_handle);
	print_field("Length so far: %d", btohs(cmd->len_so_far));
	print_field("Remaining ASSOC length: %d", btohs(cmd->remain_assoc_len));

	packet_hexdump(data + 5, size - 5);
}

static void write_remote_amp_assoc_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_write_remote_amp_assoc *rsp = data;

	print_status(rsp->status);
	print_phy_handle(rsp->phy_handle);
}

static void le_set_event_mask_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_event_mask *cmd = data;

	print_event_mask(cmd->mask);
}

static void le_read_buffer_size_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_le_read_buffer_size *rsp = data;

	print_status(rsp->status);
	print_field("Data packet length: %d", btohs(rsp->le_mtu));
	print_field("Num data packets: %d", rsp->le_max_pkt);
}

static void le_read_local_features_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_le_read_local_features *rsp = data;

	print_status(rsp->status);
	print_features(rsp->features);
}

static void le_set_random_address_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_random_address *cmd = data;

	print_addr(cmd->addr, 0x01);
}

static void le_read_adv_tx_power_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_le_read_adv_tx_power *rsp = data;

	print_status(rsp->status);
	print_field("TX power: %d dBm", rsp->level);
}

static void le_set_adv_data_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_adv_data *cmd = data;

	print_field("Length: %d", cmd->len);
	print_eir(cmd->data, cmd->len, true);
}

static void le_set_scan_response_data_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_scan_response_data *cmd = data;

	print_field("Length: %d", cmd->len);
	print_eir(cmd->data, cmd->len, true);
}

static void le_set_adv_enable_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_adv_enable *cmd = data;
	const char *str;

	switch (cmd->enable) {
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

	print_field("Advertising: %s (0x%2.2x)", str, cmd->enable);
}

static void le_set_scan_parameters_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_scan_parameters *cmd = data;
	const char *str;

	switch (cmd->type) {
	case 0x00:
		str = "Passive";
		break;
	case 0x01:
		str = "Active";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%2.2x)", str, cmd->type);

	print_interval(cmd->interval);
	print_window(cmd->window);
	print_addr_type("Own address type", cmd->own_addr_type);

	switch (cmd->filter_policy) {
	case 0x00:
		str = "Accept all advertisement";
		break;
	case 0x01:
		str = "Ignore not in white list";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Filter policy: %s (0x%2.2x)", str, cmd->filter_policy);
}

static void le_set_scan_enable_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_scan_enable *cmd = data;
	const char *str;

	switch (cmd->enable) {
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

	print_field("Scanning: %s (0x%2.2x)", str, cmd->enable);

	switch (cmd->filter_dup) {
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

	print_field("Filter duplicates: %s (0x%2.2x)", str, cmd->filter_dup);
}

static void le_create_conn_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_create_conn *cmd = data;

	print_slot_625("Scan interval", cmd->scan_interval);
	print_slot_625("Scan window", cmd->scan_window);
	print_field("Filter policy: 0x%2.2x", cmd->filter_policy);
	print_addr_type("Peer address type", cmd->peer_addr_type);
	print_addr(cmd->peer_addr, cmd->peer_addr_type);
	print_addr_type("Own address type", cmd->own_addr_type);
	print_slot_125("Min connection interval", cmd->min_interval);
	print_slot_125("Max connection interval", cmd->max_interval);
	print_field("Connection latency: 0x%4.4x", btohs(cmd->latency));
	print_field("Supervision timeout: %d msec (0x%4.4x)",
		btohs(cmd->supv_timeout) * 10, btohs(cmd->supv_timeout));
	print_slot_625("Min connection length", cmd->min_length);
	print_slot_625("Max connection length", cmd->max_length);
}

static void le_conn_update_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_conn_update *cmd = data;

	print_handle(cmd->handle);
	print_slot_125("Min connection interval", cmd->min_interval);
	print_slot_125("Max connection interval", cmd->max_interval);
	print_field("Connection latency: 0x%4.4x", btohs(cmd->latency));
	print_field("Supervision timeout: %d msec (0x%4.4x)",
		btohs(cmd->supv_timeout) * 10, btohs(cmd->supv_timeout));
	print_slot_625("Min connection length", cmd->min_length);
	print_slot_625("Max connection length", cmd->max_length);
}

static void le_set_host_classification_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_set_host_classification *cmd = data;

	print_le_channel_map(cmd->map);
}

static void le_read_channel_map_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_read_channel_map *cmd = data;

	print_handle(cmd->handle);
}

static void le_read_channel_map_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_le_read_channel_map *rsp = data;

	print_status(rsp->status);
	print_handle(rsp->handle);
	print_le_channel_map(rsp->map);
}

static void le_read_remote_features_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_read_remote_features *cmd = data;

	print_handle(cmd->handle);
}

static void le_encrypt_cmd(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_encrypt *cmd = data;

	print_key("Key", cmd->key);
	print_key("Plaintext data", cmd->plaintext);
}

static void le_encrypt_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_le_encrypt *rsp = data;

	print_status(rsp->status);
	print_key("Encrypted data", rsp->data);
}

static void le_rand_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_le_rand *rsp = data;

	print_status(rsp->status);
	print_random_number(rsp->number);
}

static void le_start_encrypt(const void *data, uint8_t size)
{
	const struct bt_hci_cmd_le_start_encrypt *cmd = data;

	print_handle(cmd->handle);
	print_random_number(cmd->number);
	print_field("Encryption diversifier: 0x%4.4x",
					btohs(cmd->diversifier));
	print_key("Long term key", cmd->ltk);

}

static void le_read_supported_states_rsp(const void *data, uint8_t size)
{
	const struct bt_hci_rsp_le_read_supported_states *rsp = data;

	print_status(rsp->status);
	print_le_states(rsp->states);
}

struct opcode_data {
	uint16_t opcode;
	const char *str;
	void (*cmd_func) (const void *data, uint8_t size);
	uint8_t cmd_size;
	bool cmd_fixed;
	void (*rsp_func) (const void *data, uint8_t size);
	uint8_t rsp_size;
	bool rsp_fixed;
};

static const struct opcode_data opcode_table[] = {
	{ 0x0000, "NOP" },

	/* OGF 1 - Link Control */
	{ 0x0401, "Inquiry",
				inquiry_cmd, 5, true },
	{ 0x0402, "Inquiry Cancel",
				null_cmd, 0, true,
				status_rsp, 1, true },
	{ 0x0403, "Periodic Inquiry Mode",
				periodic_inquiry_cmd, 9, true,
				status_rsp, 1, true },
	{ 0x0404, "Exit Periodic Inquiry Mode",
				null_cmd, 0, true,
				status_rsp, 1, true },
	{ 0x0405, "Create Connection",
				create_conn_cmd, 13, true },
	{ 0x0406, "Disconnect",
				disconnect_cmd, 3, true },
	{ 0x0407, "Add SCO Connection",
				add_sco_conn_cmd, 4, true },
	{ 0x0408, "Create Connection Cancel",
				create_conn_cancel_cmd, 6, true,
				status_bdaddr_rsp, 7, true },
	{ 0x0409, "Accept Connection Request",
				accept_conn_request_cmd, 7, true },
	{ 0x040a, "Reject Connection Request",
				reject_conn_request_cmd, 7, true },
	{ 0x040b, "Link Key Request Reply",
				link_key_request_reply_cmd, 22, true,
				status_bdaddr_rsp, 7, true },
	{ 0x040c, "Link Key Request Negative Reply",
				link_key_request_neg_reply_cmd, 6, true,
				status_bdaddr_rsp, 7, true },
	{ 0x040d, "PIN Code Request Reply",
				pin_code_request_reply_cmd, 23, true,
				status_bdaddr_rsp, 7, true },
	{ 0x040e, "PIN Code Request Negative Reply",
				pin_code_request_neg_reply_cmd, 6, true,
				status_bdaddr_rsp, 7, true },
	{ 0x040f, "Change Connection Packet Type",
				change_conn_pkt_type_cmd, 4, true },
	/* reserved command */
	{ 0x0411, "Authentication Requested",
				auth_requested_cmd, 2, true },
	/* reserved command */
	{ 0x0413, "Set Connection Encryption",
				set_conn_encrypt_cmd, 3, true },
	/* reserved command */
	{ 0x0415, "Change Connection Link Key",
				change_conn_link_key_cmd, 2, true },
	/* reserved command */
	{ 0x0417, "Master Link Key",
				master_link_key_cmd, 1, true },
	/* reserved command */
	{ 0x0419, "Remote Name Request",
				remote_name_request_cmd, 10, true },
	{ 0x041a, "Remote Name Request Cancel",
				remote_name_request_cancel_cmd, 6, true,
				status_bdaddr_rsp, 7, true },
	{ 0x041b, "Read Remote Supported Features",
				read_remote_features_cmd, 2, true },
	{ 0x041c, "Read Remote Extended Features",
				read_remote_ext_features_cmd, 3, true },
	{ 0x041d, "Read Remote Version Information",
				read_remote_version_cmd, 2, true },
	/* reserved command */
	{ 0x041f, "Read Clock Offset",
				read_clock_offset_cmd, 2, true },
	{ 0x0420, "Read LMP Handle",
				read_lmp_handle_cmd, 2, true,
				read_lmp_handle_rsp, 8, true },
	/* reserved commands */
	{ 0x0428, "Setup Synchronous Connection",
				setup_sync_conn_cmd, 17, true },
	{ 0x0429, "Accept Synchronous Connection",
				accept_sync_conn_cmd, 21, true },
	{ 0x042a, "Reject Synchronous Connection",
				reject_sync_conn_cmd, 7, true },
	{ 0x042b, "IO Capability Request Reply",
				io_capability_request_reply_cmd, 9, true,
				status_bdaddr_rsp, 7, true },
	{ 0x042c, "User Confirmation Request Reply",
				user_confirm_request_reply_cmd, 6, true,
				status_bdaddr_rsp, 7, true },
	{ 0x042d, "User Confirmation Request Neg Reply",
				user_confirm_request_neg_reply_cmd, 6, true,
				status_bdaddr_rsp, 7, true },
	{ 0x042e, "User Passkey Request Reply",
				user_passkey_request_reply_cmd, 10, true,
				status_bdaddr_rsp, 7, true },
	{ 0x042f, "User Passkey Request Negative Reply",
				user_passkey_request_neg_reply_cmd, 6, true,
				status_bdaddr_rsp, 7, true },
	{ 0x0430, "Remote OOB Data Request Reply",
				remote_oob_data_request_reply_cmd, 38, true,
				status_bdaddr_rsp, 7, true },
	/* reserved commands */
	{ 0x0433, "Remote OOB Data Request Neg Reply",
				remote_oob_data_request_neg_reply_cmd, 6, true,
				status_bdaddr_rsp, 7, true },
	{ 0x0434, "IO Capability Request Negative Reply",
				io_capability_request_neg_reply_cmd, 7, true,
				status_bdaddr_rsp, 7, true },
	{ 0x0435, "Create Physical Link",
				create_phy_link_cmd, 3, false },
	{ 0x0436, "Accept Physical Link",
				accept_phy_link_cmd, 3, false },
	{ 0x0437, "Disconnect Physical Link",
				disconn_phy_link_cmd, 2, true },
	{ 0x0438, "Create Logical Link",
				create_logic_link_cmd, 33, true },
	{ 0x0439, "Accept Logical Link",
				accept_logic_link_cmd, 33, true },
	{ 0x043a, "Disconnect Logical Link",
				disconn_logic_link_cmd, 2, true },
	{ 0x043b, "Logical Link Cancel"			},
	{ 0x043c, "Flow Specifcation Modify"		},

	/* OGF 2 - Link Policy */
	{ 0x0801, "Holde Mode",
				hold_mode_cmd, 6, true },
	/* reserved command */
	{ 0x0803, "Sniff Mode",
				sniff_mode_cmd, 10, true },
	{ 0x0804, "Exit Sniff Mode",
				exit_sniff_mode_cmd, 2, true },
	{ 0x0805, "Park State",
				park_state_cmd, 6, true },
	{ 0x0806, "Exit Park State",
				exit_park_state_cmd, 2, true },
	{ 0x0807, "QoS Setup",
				qos_setup_cmd, 20, true },
	/* reserved command */
	{ 0x0809, "Role Discovery",
				role_discovery_cmd, 2, true,
				role_discovery_rsp, 4, true },
	/* reserved command */
	{ 0x080b, "Switch Role",
				switch_role_cmd, 7, true },
	{ 0x080c, "Read Link Policy Settings",
				read_link_policy_cmd, 2, true,
				read_link_policy_rsp, 5, true },
	{ 0x080d, "Write Link Policy Settings",
				write_link_policy_cmd, 2, true,
				write_link_policy_rsp, 2, true },
	{ 0x080e, "Read Default Link Policy Settings",
				null_cmd, 0, true,
				read_default_link_policy_rsp, 3, true },
	{ 0x080f, "Write Default Link Policy Settings",
				write_default_link_policy_cmd, 2, true,
				status_rsp, 1, true },
	{ 0x0810, "Flow Specification",
				flow_spec_cmd, 21, true },
	{ 0x0811, "Sniff Subrating",
				sniff_subrating_cmd, 8, true,
				sniff_subrating_rsp, 3, true },

	/* OGF 3 - Host Control */
	{ 0x0c01, "Set Event Mask",
				set_event_mask_cmd, 8, true,
				status_rsp, 1, true },
	/* reserved command */
	{ 0x0c03, "Reset",
				null_cmd, 0, true,
				status_rsp, 1, true },
	/* reserved command */
	{ 0x0c05, "Set Event Filter",
				set_event_filter_cmd, 1, false,
				status_rsp, 1, true },
	/* reserved commands */
	{ 0x0c08, "Flush",
				flush_cmd, 2, true,
				flush_rsp, 3, true },
	{ 0x0c09, "Read PIN Type",
				null_cmd, 0, true,
				read_pin_type_rsp, 2, true },
	{ 0x0c0a, "Write PIN Type",
				write_pin_type_cmd, 1, true,
				status_rsp, 1, true },
	{ 0x0c0b, "Create New Unit Key",
				null_cmd, 0, true,
				status_rsp, 1, true },
	/* reserved command */
	{ 0x0c0d, "Read Stored Link Key",
				read_stored_link_key_cmd, 8, true,
				read_stored_link_key_rsp, 5, true },
	/* reserved commands */
	{ 0x0c11, "Write Stored Link Key",
				write_stored_link_key_cmd, 1, false,
				write_stored_link_key_rsp, 2, true },
	{ 0x0c12, "Delete Stored Link Key",
				delete_stored_link_key_cmd, 7, true,
				delete_stored_link_key_rsp, 3, true },
	{ 0x0c13, "Write Local Name",
				write_local_name_cmd, 248, true,
				status_rsp, 1, true },
	{ 0x0c14, "Read Local Name",
				null_cmd, 0, true,
				read_local_name_rsp, 249, true },
	{ 0x0c15, "Read Connection Accept Timeout",
				null_cmd, 0, true,
				read_conn_accept_timeout_rsp, 3, true },
	{ 0x0c16, "Write Connection Accept Timeout",
				write_conn_accept_timeout_cmd, 2, true,
				status_rsp, 1, true },
	{ 0x0c17, "Read Page Timeout",
				null_cmd, 0, true,
				read_page_timeout_rsp, 3, true },
	{ 0x0c18, "Write Page Timeout",
				write_page_timeout_cmd, 2, true,
				status_rsp, 1, true },
	{ 0x0c19, "Read Scan Enable",
				null_cmd, 0, true,
				read_scan_enable_rsp, 2, true },
	{ 0x0c1a, "Write Scan Enable",
				write_scan_enable_cmd, 1, true,
				status_rsp, 1, true },
	{ 0x0c1b, "Read Page Scan Activity"		},
	{ 0x0c1c, "Write Page Scan Activity"		},
	{ 0x0c1d, "Read Inquiry Scan Activity"		},
	{ 0x0c1e, "Write Inquiry Scan Activity"		},
	{ 0x0c1f, "Read Authentication Enable"		},
	{ 0x0c20, "Write Authentication Enable"		},
	{ 0x0c21, "Read Encryption Mode"		},
	{ 0x0c22, "Write Encryption Mode"		},
	{ 0x0c23, "Read Class of Device",
				null_cmd, 0, true,
				read_class_of_dev_rsp, 4, true },
	{ 0x0c24, "Write Class of Device",
				write_class_of_dev_cmd, 3, true,
				status_rsp, 1, true },
	{ 0x0c25, "Read Voice Setting",
				null_cmd, 0, true,
				read_voice_setting_rsp, 3, true },
	{ 0x0c26, "Write Voice Setting",
				write_voice_setting_cmd, 2, true,
				status_rsp, 1, true },
	{ 0x0c27, "Read Automatic Flush Timeout"	},
	{ 0x0c28, "Write Automatic Flush Timeout"	},
	{ 0x0c29, "Read Num Broadcast Retransmissions"	},
	{ 0x0c2a, "Write Num Broadcast Retransmissions"	},
	{ 0x0c2b, "Read Hold Mode Activity"		},
	{ 0x0c2c, "Write Hold Mode Activity"		},
	{ 0x0c2d, "Read Transmit Power Level"		},
	{ 0x0c2e, "Read Sync Flow Control Enable"	},
	{ 0x0c2f, "Write Sync Flow Control Enable"	},
	/* reserved command */
	{ 0x0c31, "Set Host Controller To Host Flow"	},
	/* reserved command */
	{ 0x0c33, "Host Buffer Size"			},
	/* reserved command */
	{ 0x0c35, "Host Number of Completed Packets"	},
	{ 0x0c36, "Read Link Supervision Timeout"	},
	{ 0x0c37, "Write Link Supervision Timeout"	},
	{ 0x0c38, "Read Number of Supported IAC"	},
	{ 0x0c39, "Read Current IAC LAP"		},
	{ 0x0c3a, "Write Current IAC LAP"		},
	{ 0x0c3b, "Read Page Scan Period Mode"		},
	{ 0x0c3c, "Write Page Scan Period Mode"		},
	{ 0x0c3d, "Read Page Scan Mode"			},
	{ 0x0c3e, "Write Page Scan Mode"		},
	{ 0x0c3f, "Set AFH Host Channel Classification"	},
	/* reserved commands */
	{ 0x0c42, "Read Inquiry Scan Type"		},
	{ 0x0c43, "Write Inquiry Scan Type"		},
	{ 0x0c44, "Read Inquiry Mode",
				null_cmd, 0, true,
				read_inquiry_mode_rsp, 2, true },
	{ 0x0c45, "Write Inquiry Mode",
				write_inquiry_mode_cmd, 1, true,
				status_rsp, 1, true },
	{ 0x0c46, "Read Page Scan Type"			},
	{ 0x0c47, "Write Page Scan Type"		},
	{ 0x0c48, "Read AFH Channel Assessment Mode"	},
	{ 0x0c49, "Write AFH Channel Assessment Mode"	},
	/* reserved commands */
	{ 0x0c51, "Read Extended Inquiry Response",
				null_cmd, 0, true,
				read_ext_inquiry_response_rsp, 242, true },
	{ 0x0c52, "Write Extended Inquiry Response",
				write_ext_inquiry_response_cmd, 241, true,
				status_rsp, 1, true },
	{ 0x0c53, "Refresh Encryption Key",
				refresh_encrypt_key_cmd, 2, true },
	/* reserved command */
	{ 0x0c55, "Read Simple Pairing Mode",
				null_cmd, 0, true,
				read_simple_pairing_mode_rsp, 2, true },
	{ 0x0c56, "Write Simple Pairing Mode",
				write_simple_pairing_mode_cmd, 1, true,
				status_rsp, 1, true },
	{ 0x0c57, "Read Local OOB Data"			},
	{ 0x0c58, "Read Inquiry Response TX Power Level",
				null_cmd, 0, true,
				read_inquiry_resp_tx_power_rsp, 2, true },
	{ 0x0c59, "Write Inquiry Transmit Power Level"	},
	{ 0x0c5a, "Read Default Erroneous Reporting"	},
	{ 0x0c5b, "Write Default Erroneous Reporting"	},
	/* reserved commands */
	{ 0x0c5f, "Enhanced Flush",
				enhanced_flush_cmd, 3, true },
	/* reserved command */
	{ 0x0c61, "Read Logical Link Accept Timeout"	},
	{ 0x0c62, "Write Logical Link Accept Timeout"	},
	{ 0x0c63, "Set Event Mask Page 2",
				set_event_mask_page2_cmd, 8, true,
				status_rsp, 1, true },
	{ 0x0c64, "Read Location Data"			},
	{ 0x0c65, "Write Location Data"			},
	{ 0x0c66, "Read Flow Control Mode"		},
	{ 0x0c67, "Write Flow Control Mode"		},
	{ 0x0c68, "Read Enhanced Transmit Power Level"	},
	{ 0x0c69, "Read Best Effort Flush Timeout"	},
	{ 0x0c6a, "Write Best Effort Flush Timeout"	},
	{ 0x0c6b, "Short Range Mode"			},
	{ 0x0c6c, "Read LE Host Supported",
				null_cmd, 0, true,
				read_le_host_supported_rsp, 3, true },
	{ 0x0c6d, "Write LE Host Supported",
				write_le_host_supported_cmd, 2, true,
				status_rsp, 1, true },

	/* OGF 4 - Information Parameter */
	{ 0x1001, "Read Local Version Information",
				null_cmd, 0, true,
				read_local_version_rsp, 9, true },
	{ 0x1002, "Read Local Supported Commands",
				null_cmd, 0, true,
				read_local_commands_rsp, 65, true },
	{ 0x1003, "Read Local Supported Features",
				null_cmd, 0, true,
				read_local_features_rsp, 9, true },
	{ 0x1004, "Read Local Extended Features",
				read_local_ext_features_cmd, 1, true,
				read_local_ext_features_rsp, 11, true },
	{ 0x1005, "Read Buffer Size",
				null_cmd, 0, true,
				read_buffer_size_rsp, 8, true },
	/* reserved command */
	{ 0x1007, "Read Country Code",
				null_cmd, 0, true,
				read_country_code_rsp, 2, true },
	/* reserved command */
	{ 0x1009, "Read BD ADDR",
				null_cmd, 0, true,
				read_bd_addr_rsp, 7, true },
	{ 0x100a, "Read Data Block Size",
				null_cmd, 0, true,
				read_data_block_size_rsp, 7, true },

	/* OGF 5 - Status Parameter */
	{ 0x1401, "Read Failed Contact Counter"		},
	{ 0x1402, "Reset Failed Contact Counter"	},
	{ 0x1403, "Read Link Quality"			},
	/* reserved command */
	{ 0x1405, "Read RSSI"				},
	{ 0x1406, "Read AFH Channel Map"		},
	{ 0x1407, "Read Clock"				},
	{ 0x1408, "Read Encryption Key Size",
				read_encrypt_key_size_cmd, 2, true,
				read_encrypt_key_size_rsp, 4, true },
	{ 0x1409, "Read Local AMP Info",
				null_cmd, 0, true,
				read_local_amp_info_rsp, 31, true },
	{ 0x140a, "Read Local AMP ASSOC",
				read_local_amp_assoc_cmd, 5, true,
				read_local_amp_assoc_rsp, 5, false },
	{ 0x140b, "Write Remote AMP ASSOC",
				write_remote_amp_assoc_cmd, 6, false,
				write_remote_amp_assoc_rsp, 2, true },

	/* OGF 8 - LE Control */
	{ 0x2001, "LE Set Event Mask",
				le_set_event_mask_cmd, 8, true,
				status_rsp, 1, true },
	{ 0x2002, "LE Read Buffer Size",
				null_cmd, 0, true,
				le_read_buffer_size_rsp, 4, true },
	{ 0x2003, "LE Read Local Supported Features",
				null_cmd, 0, true,
				le_read_local_features_rsp, 9, true },
	/* reserved command */
	{ 0x2005, "LE Set Random Address",
				le_set_random_address_cmd, 6, true,
				status_rsp, 1, true },
	{ 0x2006, "LE Set Advertising Parameters"	},
	{ 0x2007, "LE Read Advertising Channel TX Power",
				null_cmd, 0, true,
				le_read_adv_tx_power_rsp, 2, true },
	{ 0x2008, "LE Set Advertising Data",
				le_set_adv_data_cmd, 32, true,
				status_rsp, 1, true },
	{ 0x2009, "LE Set Scan Response Data",
				le_set_scan_response_data_cmd, 32, true,
				status_rsp, 1, true },
	{ 0x200a, "LE Set Advertise Enable",
				le_set_adv_enable_cmd, 1, true,
				status_rsp, 1, true },
	{ 0x200b, "LE Set Scan Parameters",
				le_set_scan_parameters_cmd, 7, true,
				status_rsp, 1, true },
	{ 0x200c, "LE Set Scan Enable",
				le_set_scan_enable_cmd, 2, true,
				status_rsp, 1, true },
	{ 0x200d, "LE Create Connection",
				le_create_conn_cmd, 25, true },
	{ 0x200e, "LE Create Connection Cancel",
				null_cmd, 0, true,
				status_rsp, 1, true },
	{ 0x200f, "LE Read White List Size"		},
	{ 0x2010, "LE Clear White List"			},
	{ 0x2011, "LE Add Device To White List"		},
	{ 0x2012, "LE Remove Device From White List"	},
	{ 0x2013, "LE Connection Update",
				le_conn_update_cmd, 14, true },
	{ 0x2014, "LE Set Host Channel Classification",
				le_set_host_classification_cmd, 5, true,
				status_rsp, 1, true },
	{ 0x2015, "LE Read Channel Map",
				le_read_channel_map_cmd, 2, true,
				le_read_channel_map_rsp, 8, true },
	{ 0x2016, "LE Read Remote Used Features",
				le_read_remote_features_cmd, 2, true },
	{ 0x2017, "LE Encrypt",
				le_encrypt_cmd, 32, true,
				le_encrypt_rsp, 17, true },
	{ 0x2018, "LE Rand",
				null_cmd, 0, true,
				le_rand_rsp, 9, true },
	{ 0x2019, "LE Start Encryption",
				le_start_encrypt, 28, true },
	{ 0x201a, "LE Long Term Key Request Reply"	},
	{ 0x201b, "LE Long Term Key Request Neg Reply"	},
	{ 0x201c, "LE Read Supported States",
				null_cmd, 0, true,
				le_read_supported_states_rsp, 9, true },
	{ 0x201d, "LE Receiver Test"			},
	{ 0x201e, "LE Transmitter Test"			},
	{ 0x201f, "LE Test End"				},
	{ }
};

static void status_evt(const void *data, uint8_t size)
{
	uint8_t status = *((uint8_t *) data);

	print_status(status);
}

static void inquiry_result_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_inquiry_result *evt = data;

	print_num_resp(evt->num_resp);
	print_bdaddr(evt->bdaddr);
	print_pscan_rep_mode(evt->pscan_rep_mode);
	print_pscan_period_mode(evt->pscan_period_mode);
	print_pscan_mode(evt->pscan_mode);
	print_dev_class(evt->dev_class);
	print_clock_offset(evt->clock_offset);

	if (size > sizeof(*evt))
		packet_hexdump(data + sizeof(*evt), size - sizeof(*evt));
}

static void conn_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_conn_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_bdaddr(evt->bdaddr);
	print_link_type(evt->link_type);
	print_encr_mode(evt->encr_mode);
}

static void conn_request_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_conn_request *evt = data;

	print_bdaddr(evt->bdaddr);
	print_dev_class(evt->dev_class);
	print_link_type(evt->link_type);
}

static void disconnect_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_disconnect_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_reason(evt->reason);
}

static void auth_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_auth_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
}

static void remote_name_request_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_remote_name_request_complete *evt = data;

	print_status(evt->status);
	print_bdaddr(evt->bdaddr);
	print_name(evt->name);
}

static void encrypt_change_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_encrypt_change *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_encr_mode(evt->encr_mode);
}

static void change_conn_link_key_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_change_conn_link_key_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
}

static void master_link_key_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_master_link_key_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_key_flag(evt->key_flag);
}

static void remote_features_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_remote_features_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_features(evt->features);
}

static void remote_version_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_remote_version_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_lmp_version(evt->lmp_ver, evt->lmp_subver);
	print_manufacturer(evt->manufacturer);
}

static void qos_setup_complete_evt(const void *data, uint8_t size)
{
	uint8_t status = *((uint8_t *) data);

	print_status(status);

	packet_hexdump(data + 1, size - 1);
}

static void cmd_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_cmd_complete *evt = data;
	uint16_t opcode = btohs(evt->opcode);
	uint16_t ogf = cmd_opcode_ogf(opcode);
	uint16_t ocf = cmd_opcode_ocf(opcode);
	const struct opcode_data *opcode_data = NULL;
	const char *opcode_color, *opcode_str;
	int i;

	for (i = 0; opcode_table[i].str; i++) {
		if (opcode_table[i].opcode == opcode) {
			opcode_data = &opcode_table[i];
			break;
		}
	}

	if (opcode_data) {
		if (opcode_data->rsp_func)
			opcode_color = COLOR_HCI_COMMAND;
		else
			opcode_color = COLOR_HCI_COMMAND_UNKNOWN;
		opcode_str = opcode_data->str;
	} else {
		opcode_color = COLOR_HCI_COMMAND_UNKNOWN;
		opcode_str = "Unknown";
	}

	print_indent(6, opcode_color, "", opcode_str, COLOR_OFF,
			" (0x%2.2x|0x%4.4x) ncmd %d", ogf, ocf, evt->ncmd);

	if (!opcode_data->rsp_func) {
		packet_hexdump(data + 3, size - 3);
		return;
	}

	if (opcode_data->rsp_fixed) {
		if (size - 3 != opcode_data->rsp_size) {
			print_text(COLOR_ERROR, "invalid packet size");
			packet_hexdump(data + 3, size - 3);
			return;
		}
	} else {
		if (size - 3 < opcode_data->rsp_size) {
			print_text(COLOR_ERROR, "too short packet");
			packet_hexdump(data + 3, size - 3);
			return;
		}
	}

	opcode_data->rsp_func(data + 3, size - 3);
}

static void cmd_status_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_cmd_status *evt = data;
	uint16_t opcode = btohs(evt->opcode);
	uint16_t ogf = cmd_opcode_ogf(opcode);
	uint16_t ocf = cmd_opcode_ocf(opcode);
	const struct opcode_data *opcode_data = NULL;
	const char *opcode_color, *opcode_str;
	int i;

	for (i = 0; opcode_table[i].str; i++) {
		if (opcode_table[i].opcode == opcode) {
			opcode_data = &opcode_table[i];
			break;
		}
	}

	if (opcode_data) {
		opcode_color = COLOR_HCI_COMMAND;
		opcode_str = opcode_data->str;
	} else {
		opcode_color = COLOR_HCI_COMMAND_UNKNOWN;
		opcode_str = "Unknown";
	}

	print_indent(6, opcode_color, "", opcode_str, COLOR_OFF,
			" (0x%2.2x|0x%4.4x) ncmd %d", ogf, ocf, evt->ncmd);

	print_status(evt->status);
}

static void hardware_error_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_hardware_error *evt = data;

	print_field("Code: 0x%2.2x", evt->code);
}

static void flush_occurred_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_flush_occurred *evt = data;

	print_handle(evt->handle);
}

static void role_change_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_role_change *evt = data;

	print_status(evt->status);
	print_bdaddr(evt->bdaddr);
	print_role(evt->role);
}

static void num_completed_packets_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_num_completed_packets *evt = data;

	print_field("Num handles: %d", evt->num_handles);
	print_handle(evt->handle);
	print_field("Count: %d", btohs(evt->count));

	if (size > sizeof(*evt))
		packet_hexdump(data + sizeof(*evt), size - sizeof(*evt));
}

static void mode_change_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_mode_change *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_mode(evt->mode);
	print_interval(evt->interval);
}

static void return_link_keys_evt(const void *data, uint8_t size)
{
	uint8_t num_keys = *((uint8_t *) data);

	print_field("Num keys: %d", num_keys);

	packet_hexdump(data + 1, size - 1);
}

static void pin_code_request_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_pin_code_request *evt = data;

	print_bdaddr(evt->bdaddr);
}

static void link_key_request_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_link_key_request *evt = data;

	print_bdaddr(evt->bdaddr);
}

static void link_key_notify_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_link_key_notify *evt = data;

	print_bdaddr(evt->bdaddr);
	print_link_key(evt->link_key);
	print_key_type(evt->key_type);
}

static void loopback_command_evt(const void *data, uint8_t size)
{
	packet_hexdump(data, size);
}

static void data_buffer_overflow_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_data_buffer_overflow *evt = data;

	print_link_type(evt->link_type);
}

static void max_slots_change_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_max_slots_change *evt = data;

	print_handle(evt->handle);
	print_field("Max slots: %d", evt->max_slots);
}

static void clock_offset_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_clock_offset_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_clock_offset(evt->clock_offset);
}

static void conn_pkt_type_changed_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_conn_pkt_type_changed *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_pkt_type(evt->pkt_type);
}

static void qos_violation_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_qos_violation *evt = data;

	print_handle(evt->handle);
}

static void pscan_mode_change_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_pscan_mode_change *evt = data;

	print_bdaddr(evt->bdaddr);
	print_pscan_mode(evt->pscan_mode);
}

static void pscan_rep_mode_change_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_pscan_rep_mode_change *evt = data;

	print_bdaddr(evt->bdaddr);
	print_pscan_rep_mode(evt->pscan_rep_mode);
}

static void flow_spec_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_flow_spec_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_field("Flags: 0x%2.2x", evt->flags);

	print_flow_direction(evt->direction);
	print_service_type(evt->service_type);

	print_field("Token rate: %d", btohl(evt->token_rate));
	print_field("Token bucket size: %d", btohl(evt->token_bucket_size));
	print_field("Peak bandwidth: %d", btohl(evt->peak_bandwidth));
	print_field("Access latency: %d", btohl(evt->access_latency));
}

static void inquiry_result_with_rssi_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_inquiry_result_with_rssi *evt = data;

	print_num_resp(evt->num_resp);
	print_bdaddr(evt->bdaddr);
	print_pscan_rep_mode(evt->pscan_rep_mode);
	print_pscan_period_mode(evt->pscan_period_mode);
	print_dev_class(evt->dev_class);
	print_clock_offset(evt->clock_offset);
	print_rssi(evt->rssi);

	if (size > sizeof(*evt))
		packet_hexdump(data + sizeof(*evt), size - sizeof(*evt));
}

static void remote_ext_features_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_remote_ext_features_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_field("Page: %d/%d", evt->page, evt->max_page);
	print_features(evt->features);
}

static void sync_conn_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_sync_conn_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_bdaddr(evt->bdaddr);
	print_link_type(evt->link_type);
	print_field("Transmission interval: 0x%2.2x", evt->tx_interval);
	print_field("Retransmission window: 0x%2.2x", evt->retrans_window);
	print_field("RX packet length: %d", btohs(evt->rx_pkt_len));
	print_field("TX packet length: %d", btohs(evt->tx_pkt_len));
	print_air_mode(evt->air_mode);
}

static void sync_conn_changed_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_sync_conn_changed *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_field("Transmission interval: 0x%2.2x", evt->tx_interval);
	print_field("Retransmission window: 0x%2.2x", evt->retrans_window);
	print_field("RX packet length: %d", btohs(evt->rx_pkt_len));
	print_field("TX packet length: %d", btohs(evt->tx_pkt_len));
}

static void sniff_subrating_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_sniff_subrating *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_slot_625("Max transmit latency", evt->max_tx_latency);
	print_slot_625("Max receive latency", evt->max_rx_latency);
	print_slot_625("Min remote timeout", evt->min_remote_timeout);
	print_slot_625("Min local timeout", evt->min_local_timeout);
}

static void ext_inquiry_result_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_ext_inquiry_result *evt = data;

	print_num_resp(evt->num_resp);
	print_bdaddr(evt->bdaddr);
	print_pscan_rep_mode(evt->pscan_rep_mode);
	print_pscan_period_mode(evt->pscan_period_mode);
	print_dev_class(evt->dev_class);
	print_clock_offset(evt->clock_offset);
	print_rssi(evt->rssi);
	print_eir(evt->data, sizeof(evt->data), false);
}

static void encrypt_key_refresh_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_encrypt_key_refresh_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
}

static void io_capability_request_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_io_capability_request *evt = data;

	print_bdaddr(evt->bdaddr);
}

static void io_capability_response_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_io_capability_response *evt = data;

	print_bdaddr(evt->bdaddr);
	print_io_capability(evt->capability);
	print_oob_data(evt->oob_data);
	print_authentication(evt->authentication);
}

static void user_confirm_request_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_user_confirm_request *evt = data;

	print_bdaddr(evt->bdaddr);
	print_passkey(evt->passkey);
}

static void user_passkey_request_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_user_passkey_request *evt = data;

	print_bdaddr(evt->bdaddr);
}

static void remote_oob_data_request_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_remote_oob_data_request *evt = data;

	print_bdaddr(evt->bdaddr);
}

static void simple_pairing_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_simple_pairing_complete *evt = data;

	print_status(evt->status);
	print_bdaddr(evt->bdaddr);
}

static void link_supv_timeout_changed_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_link_supv_timeout_changed *evt = data;

	print_handle(evt->handle);
	print_timeout(evt->timeout);
}

static void enhanced_flush_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_enhanced_flush_complete *evt = data;

	print_handle(evt->handle);
}

static void user_passkey_notify_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_user_passkey_notify *evt = data;

	print_bdaddr(evt->bdaddr);
	print_passkey(evt->passkey);
}

static void keypress_notify_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_keypress_notify *evt = data;
	const char *str;

	print_bdaddr(evt->bdaddr);

	switch (evt->type) {
	case 0x00:
		str = "Passkey entry started";
		break;
	case 0x01:
		str = "Passkey digit entered";
		break;
	case 0x02:
		str = "Passkey digit erased";
		break;
	case 0x03:
		str = "Passkey clared";
		break;
	case 0x04:
		str = "Passkey entry completed";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Notification type: %s (0x%2.2x)", str, evt->type);
}

static void remote_host_features_notify_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_remote_host_features_notify *evt = data;

	print_bdaddr(evt->bdaddr);
	print_features(evt->features);
}

static void phy_link_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_phy_link_complete *evt = data;

	print_status(evt->status);
	print_phy_handle(evt->phy_handle);
}

static void channel_selected_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_channel_selected *evt = data;

	print_phy_handle(evt->phy_handle);
}

static void disconn_phy_link_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_disconn_phy_link_complete *evt = data;

	print_status(evt->status);
	print_phy_handle(evt->phy_handle);
	print_reason(evt->reason);
}

static void phy_link_loss_early_warning_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_phy_link_loss_early_warning *evt = data;
	const char *str;

	print_phy_handle(evt->phy_handle);

	switch (evt->reason) {
	case 0x00:
		str = "Unknown";
		break;
	case 0x01:
		str = "Range related";
		break;
	case 0x02:
		str = "Bandwidth related";
		break;
	case 0x03:
		str = "Resolving conflict";
		break;
	case 0x04:
		str = "Interference";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Reason: %s (0x%2.2x)", str, evt->reason);
}

static void phy_link_recovery_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_phy_link_recovery *evt = data;

	print_phy_handle(evt->phy_handle);
}

static void logic_link_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_logic_link_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_phy_handle(evt->phy_handle);
	print_field("TX flow spec: 0x%2.2x", evt->flow_spec);
}

static void disconn_logic_link_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_disconn_logic_link_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_reason(evt->reason);
}

static void flow_spec_modify_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_flow_spec_modify_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
}

static void num_completed_data_blocks_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_num_completed_data_blocks *evt = data;

	print_field("Total num data blocks: %d", btohs(evt->total_num_blocks));
	print_field("Num handles: %d", evt->num_handles);
	print_handle(evt->handle);
	print_field("Num packets: %d", evt->num_packets);
	print_field("Num blocks: %d", evt->num_blocks);

	if (size > sizeof(*evt))
		packet_hexdump(data + sizeof(*evt), size - sizeof(*evt));
}

static void short_range_mode_change_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_short_range_mode_change *evt = data;

	print_status(evt->status);
	print_phy_handle(evt->phy_handle);
	print_short_range_mode(evt->mode);
}

static void amp_status_change_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_amp_status_change *evt = data;

	print_status(evt->status);
	print_amp_status(evt->amp_status);
}

static void le_conn_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_le_conn_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_role(evt->role);
	print_addr_type("Peer address type", evt->peer_addr_type);
	print_addr(evt->peer_addr, evt->peer_addr_type);
	print_slot_125("Connection interval", evt->interval);
        print_slot_125("Connection latency", evt->latency);
	print_field("Supervision timeout: %d msec (0x%4.4x)",
		btohs(evt->supv_timeout) * 10, btohs(evt->supv_timeout));
	print_field("Master clock accuracy: 0x%2.2x", evt->clock_accuracy);
}

static void le_adv_report_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_le_adv_report *evt = data;
	const char *str;
	uint8_t evt_len;
	int8_t *rssi;

	print_num_reports(evt->num_reports);

	switch (evt->event_type) {
	case 0x00:
		str = "Connectable undirected - ADV_IND";
		break;
	case 0x01:
		str = "Connectable directed - ADV_DIRECT_IND";
		break;
	case 0x02:
		str = "Scannable undirected - ADV_SCAN_IND";
		break;
	case 0x03:
		str = "Non connectable undirected - ADV_NONCONN_IND";
		break;
	case 0x04:
		str = "Scan response - SCAN_RSP";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Event type: %s (0x%2.2x)", str, evt->event_type);
	print_addr_type("Address type", evt->addr_type);
	print_addr(evt->addr, evt->addr_type);
	print_field("Data length: %d", evt->data_len);
	print_eir(evt->data, evt->data_len, true);

	rssi = (int8_t *) (evt->data + evt->data_len);
	print_rssi(*rssi);

	evt_len = sizeof(*evt) + evt->data_len + 1;

	if (size > evt_len)
		packet_hexdump(data + evt_len, size - evt_len);
}

static void le_conn_update_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_le_conn_update_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_slot_125("Connection interval", evt->interval);
	print_slot_125("Connection latency", evt->latency);
	print_field("Supervision timeout: %d msec (0x%4.4x)",
		btohs(evt->supv_timeout) * 10, btohs(evt->supv_timeout));
}

static void le_remote_features_complete_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_le_remote_features_complete *evt = data;

	print_status(evt->status);
	print_handle(evt->handle);
	print_features(evt->features);
}

static void le_long_term_key_request_evt(const void *data, uint8_t size)
{
	const struct bt_hci_evt_le_long_term_key_request *evt = data;

	print_handle(evt->handle);
	print_random_number(evt->number);
	print_field("Encryption diversifier: 0x%4.4x",
					btohs(evt->diversifier));
}

struct subevent_data {
	uint8_t subevent;
	const char *str;
	void (*func) (const void *data, uint8_t size);
	uint8_t size;
	bool fixed;
};

static const struct subevent_data subevent_table[] = {
	{ 0x01, "LE Connection Complete",
				le_conn_complete_evt, 18, true },
	{ 0x02, "LE Advertising Report",
				le_adv_report_evt, 1, false },
	{ 0x03, "LE Connection Update Complete",
				le_conn_update_complete_evt, 9, true },
	{ 0x04, "LE Read Remote Used Features",
				le_remote_features_complete_evt, 11, true },
	{ 0x05, "LE Long Term Key Request",
				le_long_term_key_request_evt, 12, true },
	{ }
};

static void le_meta_event_evt(const void *data, uint8_t size)
{
	uint8_t subevent = *((const uint8_t *) data);
	const struct subevent_data *subevent_data = NULL;
	const char *subevent_color, *subevent_str;
	int i;

	for (i = 0; subevent_table[i].str; i++) {
		if (subevent_table[i].subevent == subevent) {
			subevent_data = &subevent_table[i];
			break;
		}
	}

	if (subevent_data) {
		if (subevent_data->func)
			subevent_color = COLOR_HCI_EVENT;
		else
			subevent_color = COLOR_HCI_EVENT_UNKNOWN;
		subevent_str = subevent_data->str;
	} else {
		subevent_color = COLOR_HCI_EVENT_UNKNOWN;
		subevent_str = "Unknown";
	}

	print_indent(6, subevent_color, "", subevent_str, COLOR_OFF,
						" (0x%2.2x)", subevent);

	if (!subevent_data || !subevent_data->func) {
		packet_hexdump(data + 1, size - 1);
		return;
	}

	if (subevent_data->fixed) {
		if (size - 1 != subevent_data->size) {
			print_text(COLOR_ERROR, "invalid packet size");
			packet_hexdump(data + 1, size - 1);
			return;
		}
	} else {
		if (size - 1 < subevent_data->size) {
			print_text(COLOR_ERROR, "too short packet");
			packet_hexdump(data + 1, size - 1);
			return;
		}
	}

	subevent_data->func(data + 1, size - 1);
}

struct event_data {
	uint8_t event;
	const char *str;
	void (*func) (const void *data, uint8_t size);
	uint8_t size;
	bool fixed;
};

static const struct event_data event_table[] = {
	{ 0x01, "Inquiry Complete",
				status_evt, 1, true },
	{ 0x02, "Inquiry Result",
				inquiry_result_evt, 1, false },
	{ 0x03, "Connect Complete",
				conn_complete_evt, 11, true },
	{ 0x04, "Connect Request",
				conn_request_evt, 10, true },
	{ 0x05, "Disconnect Complete",
				disconnect_complete_evt, 4, true },
	{ 0x06, "Auth Complete",
				auth_complete_evt, 3, true },
	{ 0x07, "Remote Name Req Complete",
				remote_name_request_complete_evt, 255, true },
	{ 0x08, "Encryption Change",
				encrypt_change_evt, 4, true },
	{ 0x09, "Change Connection Link Key Complete",
				change_conn_link_key_complete_evt, 3, true },
	{ 0x0a, "Master Link Key Complete",
				master_link_key_complete_evt, 4, true },
	{ 0x0b, "Read Remote Supported Features",
				remote_features_complete_evt, 11, true },
	{ 0x0c, "Read Remote Version Complete",
				remote_version_complete_evt, 8, true },
	{ 0x0d, "QoS Setup Complete",
				qos_setup_complete_evt, 21, true },
	{ 0x0e, "Command Complete",
				cmd_complete_evt, 3, false },
	{ 0x0f, "Command Status",
				cmd_status_evt, 4, true },
	{ 0x10, "Hardware Error",
				hardware_error_evt, 1, true },
	{ 0x11, "Flush Occurred",
				flush_occurred_evt, 2, true },
	{ 0x12, "Role Change",
				role_change_evt, 8, true },
	{ 0x13, "Number of Completed Packets",
				num_completed_packets_evt, 1, false },
	{ 0x14, "Mode Change",
				mode_change_evt, 6, true },
	{ 0x15, "Return Link Keys",
				return_link_keys_evt, 1, false },
	{ 0x16, "PIN Code Request",
				pin_code_request_evt, 6, true },
	{ 0x17, "Link Key Request",
				link_key_request_evt, 6, true },
	{ 0x18, "Link Key Notification",
				link_key_notify_evt, 23, true },
	{ 0x19, "Loopback Command",
				loopback_command_evt, 3, false },
	{ 0x1a, "Data Buffer Overflow",
				data_buffer_overflow_evt, 1, true },
	{ 0x1b, "Max Slots Change",
				max_slots_change_evt, 3, true },
	{ 0x1c, "Read Clock Offset Complete",
				clock_offset_complete_evt, 5, true },
	{ 0x1d, "Connection Packet Type Changed",
				conn_pkt_type_changed_evt, 5, true },
	{ 0x1e, "QoS Violation",
				qos_violation_evt, 2, true },
	{ 0x1f, "Page Scan Mode Change",
				pscan_mode_change_evt, 7, true },
	{ 0x20, "Page Scan Repetition Mode Change",
				pscan_rep_mode_change_evt, 7, true },
	{ 0x21, "Flow Specification Complete",
				flow_spec_complete_evt, 22, true },
	{ 0x22, "Inquiry Result with RSSI",
				inquiry_result_with_rssi_evt, 1, false },
	{ 0x23, "Read Remote Extended Features",
				remote_ext_features_complete_evt, 13, true },
	/* reserved events */
	{ 0x2c, "Synchronous Connect Complete",
				sync_conn_complete_evt, 17, true },
	{ 0x2d, "Synchronous Connect Changed",
				sync_conn_changed_evt, 9, true },
	{ 0x2e, "Sniff Subrating",
				sniff_subrating_evt, 11, true },
	{ 0x2f, "Extended Inquiry Result",
				ext_inquiry_result_evt, 1, false },
	{ 0x30, "Encryption Key Refresh Complete",
				encrypt_key_refresh_complete_evt, 3, true },
	{ 0x31, "IO Capability Request",
				io_capability_request_evt, 6, true },
	{ 0x32, "IO Capability Response",
				io_capability_response_evt, 9, true },
	{ 0x33, "User Confirmation Request",
				user_confirm_request_evt, 10, true },
	{ 0x34, "User Passkey Request",
				user_passkey_request_evt, 6, true },
	{ 0x35, "Remote OOB Data Request",
				remote_oob_data_request_evt, 6, true },
	{ 0x36, "Simple Pairing Complete",
				simple_pairing_complete_evt, 7, true },
	/* reserved event */
	{ 0x38, "Link Supervision Timeout Changed",
				link_supv_timeout_changed_evt, 4, true },
	{ 0x39, "Enhanced Flush Complete",
				enhanced_flush_complete_evt, 2, true },
	/* reserved event */
	{ 0x3b, "User Passkey Notification",
				user_passkey_notify_evt, 10, true },
	{ 0x3c, "Keypress Notification",
				keypress_notify_evt, 7, true },
	{ 0x3d, "Remote Host Supported Features",
				remote_host_features_notify_evt, 14, true },
	{ 0x3e, "LE Meta Event",
				le_meta_event_evt, 1, false },
	/* reserved event */
	{ 0x40, "Physical Link Complete",
				phy_link_complete_evt, 2, true },
	{ 0x41, "Channel Selected",
				channel_selected_evt, 1, true },
	{ 0x42, "Disconnect Physical Link Complete",
				disconn_phy_link_complete_evt, 3, true },
	{ 0x43, "Physical Link Loss Early Warning",
				phy_link_loss_early_warning_evt, 2, true },
	{ 0x44, "Physical Link Recovery",
				phy_link_recovery_evt, 1, true },
	{ 0x45, "Logical Link Complete",
				logic_link_complete_evt, 5, true },
	{ 0x46, "Disconnect Logical Link Complete",
				disconn_logic_link_complete_evt, 4, true },
	{ 0x47, "Flow Spec Modify Complete",
				flow_spec_modify_complete_evt, 3, true },
	{ 0x48, "Number Of Completed Data Blocks",
				num_completed_data_blocks_evt, 3, false },
	{ 0x49, "AMP Start Test"			},
	{ 0x4a, "AMP Test End"				},
	{ 0x4b, "AMP Receiver Report"			},
	{ 0x4c, "Short Range Mode Change Complete",
				short_range_mode_change_evt, 3, true },
	{ 0x4d, "AMP Status Change",
				amp_status_change_evt, 2, true },
	{ 0xfe, "Testing"				},
	{ 0xff, "Vendor"				},
	{ }
};

void packet_new_index(struct timeval *tv, uint16_t index, const char *label,
				uint8_t type, uint8_t bus, const char *name)
{
	char details[48];

	sprintf(details, "(%s,%s,%s)", hci_typetostr(type),
					hci_bustostr(bus), name);

	print_packet(tv, index, '=', COLOR_NEW_INDEX, "New Index",
							label, details);
}

void packet_del_index(struct timeval *tv, uint16_t index, const char *label)
{
	print_packet(tv, index, '=', COLOR_DEL_INDEX, "Delete Index",
							label, NULL);
}

void packet_hci_command(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	const hci_command_hdr *hdr = data;
	uint16_t opcode = btohs(hdr->opcode);
	uint16_t ogf = cmd_opcode_ogf(opcode);
	uint16_t ocf = cmd_opcode_ocf(opcode);
	const struct opcode_data *opcode_data = NULL;
	const char *opcode_color, *opcode_str;
	char extra_str[25];
	int i;

	if (size < HCI_COMMAND_HDR_SIZE) {
		sprintf(extra_str, "(len %d)", size);
		print_packet(tv, index, '*', COLOR_ERROR,
			"Malformed HCI Command packet", NULL, extra_str);
		packet_hexdump(data, size);
		return;
	}

	data += HCI_COMMAND_HDR_SIZE;
	size -= HCI_COMMAND_HDR_SIZE;

	for (i = 0; opcode_table[i].str; i++) {
		if (opcode_table[i].opcode == opcode) {
			opcode_data = &opcode_table[i];
			break;
		}
	}

	if (opcode_data) {
		if (opcode_data->cmd_func)
			opcode_color = COLOR_HCI_COMMAND;
		else
			opcode_color = COLOR_HCI_COMMAND_UNKNOWN;
		opcode_str = opcode_data->str;
	} else {
		opcode_color = COLOR_HCI_COMMAND_UNKNOWN;
		opcode_str = "Unknown";
	}

	sprintf(extra_str, "(0x%2.2x|0x%4.4x) plen %d", ogf, ocf, hdr->plen);

	print_packet(tv, index, '<', opcode_color, "HCI Command",
							opcode_str, extra_str);

	if (!opcode_data || !opcode_data->cmd_func) {
		packet_hexdump(data, size);
		return;
	}

	if (opcode_data->cmd_fixed) {
		if (hdr->plen != opcode_data->cmd_size) {
			print_text(COLOR_ERROR, "invalid packet size");
			packet_hexdump(data, size);
			return;
		}
	} else {
		if (hdr->plen < opcode_data->cmd_size) {
			print_text(COLOR_ERROR, "too short packet");
			packet_hexdump(data, size);
			return;
		}
	}

	opcode_data->cmd_func(data, hdr->plen);
}

void packet_hci_event(struct timeval *tv, uint16_t index,
					const void *data, uint16_t size)
{
	const hci_event_hdr *hdr = data;
	const struct event_data *event_data = NULL;
	const char *event_color, *event_str;
	char extra_str[25];
	int i;

	if (size < HCI_EVENT_HDR_SIZE) {
		sprintf(extra_str, "(len %d)", size);
		print_packet(tv, index, '*', COLOR_ERROR,
			"Malformed HCI Event packet", NULL, extra_str);
		packet_hexdump(data, size);
		return;
	}

	data += HCI_EVENT_HDR_SIZE;
	size -= HCI_EVENT_HDR_SIZE;

	for (i = 0; event_table[i].str; i++) {
		if (event_table[i].event == hdr->evt) {
			event_data = &event_table[i];
			break;
		}
	}

	if (event_data) {
		if (event_data->func)
			event_color = COLOR_HCI_EVENT;
		else
			event_color = COLOR_HCI_EVENT_UNKNOWN;
		event_str = event_data->str;
	} else {
		event_color = COLOR_HCI_EVENT_UNKNOWN;
		event_str = "Unknown";
	}

	sprintf(extra_str, "(0x%2.2x) plen %d", hdr->evt, hdr->plen);

	print_packet(tv, index, '>', event_color, "HCI Event",
                                                        event_str, extra_str);

	if (!event_data || !event_data->func) {
		packet_hexdump(data, size);
		return;
	}

	if (event_data->fixed) {
		if (hdr->plen != event_data->size) {
			print_text(COLOR_ERROR, "invalid packet size");
			packet_hexdump(data, size);
			return;
		}
	} else {
		if (hdr->plen < event_data->size) {
			print_text(COLOR_ERROR, "too short packet");
			packet_hexdump(data, size);
			return;
		}
	}

	event_data->func(data, hdr->plen);
}

void packet_hci_acldata(struct timeval *tv, uint16_t index, bool in,
					const void *data, uint16_t size)
{
	const hci_acl_hdr *hdr = data;
	uint16_t handle = btohs(hdr->handle);
	uint16_t dlen = btohs(hdr->dlen);
	uint8_t flags = acl_flags(handle);
	char handle_str[16], extra_str[32];

	if (size < HCI_ACL_HDR_SIZE) {
		if (in)
			print_packet(tv, index, '*', COLOR_ERROR,
				"Malformed ACL Data RX packet", NULL, NULL);
		else
			print_packet(tv, index, '*', COLOR_ERROR,
				"Malformed ACL Data TX packet", NULL, NULL);
		packet_hexdump(data, size);
		return;
	}

	data += HCI_ACL_HDR_SIZE;
	size -= HCI_ACL_HDR_SIZE;

	sprintf(handle_str, "Handle %d", acl_handle(handle));
	sprintf(extra_str, "flags 0x%2.2x dlen %d", flags, dlen);

	print_packet(tv, index, in ? '>' : '<', COLOR_HCI_ACLDATA,
				in ? "ACL Data RX" : "ACL Data TX",
						handle_str, extra_str);

	if (size != dlen) {
		print_text(COLOR_ERROR, "invalid packet size (%d != %d)",
								size, dlen);
		packet_hexdump(data, size);
		return;
	}

	if (filter_mask & PACKET_FILTER_SHOW_ACL_DATA)
		packet_hexdump(data, size);

	if (index > MAX_INDEX - 1)
		return;

	switch (flags) {
	case 0x00:	/* start of a non-automatically-flushable PDU */
	case 0x02:	/* start of an automatically-flushable PDU */
		if (index_list[index].frag_len == 0)
			l2cap_packet(acl_handle(handle), in, data, size);
		index_list[index].frag_len = 0;
		break;
	default:
		print_text(COLOR_ERROR, "invalid packet flags (0x%2.2x)",
								flags);
		packet_hexdump(data, size);
		break;
	}
}

void packet_hci_scodata(struct timeval *tv, uint16_t index, bool in,
					const void *data, uint16_t size)
{
	const hci_sco_hdr *hdr = data;
	uint16_t handle = btohs(hdr->handle);
	uint8_t flags = acl_flags(handle);
	char handle_str[16], extra_str[32];

	if (size < HCI_SCO_HDR_SIZE) {
		if (in)
			print_packet(tv, index, '*', COLOR_ERROR,
				"Malformed SCO Data RX packet", NULL, NULL);
		else
			print_packet(tv, index, '*', COLOR_ERROR,
				"Malformed SCO Data TX packet", NULL, NULL);
		packet_hexdump(data, size);
		return;
	}

	data += HCI_SCO_HDR_SIZE;
	size -= HCI_SCO_HDR_SIZE;

	sprintf(handle_str, "Handle %d", acl_handle(handle));
	sprintf(extra_str, "flags 0x%2.2x dlen %d", flags, hdr->dlen);

	print_packet(tv, index, in ? '>' : '<', COLOR_HCI_SCODATA,
				in ? "SCO Data RX" : "SCO Data TX",
						handle_str, extra_str);

	if (size != hdr->dlen) {
		print_text(COLOR_ERROR, "invalid packet size (%d != %d)",
							size, hdr->dlen);
		packet_hexdump(data, size);
		return;
	}

	if (filter_mask & PACKET_FILTER_SHOW_SCO_DATA)
		packet_hexdump(data, size);
}
