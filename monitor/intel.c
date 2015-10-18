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

#include "src/shared/util.h"
#include "display.h"
#include "packet.h"
#include "lmp.h"
#include "ll.h"
#include "vendor.h"
#include "intel.h"

static const struct vendor_ocf vendor_ocf_table[] = {
	{ 0x001, "Reset"				},
	{ 0x002, "No Operation"				},
	{ 0x005, "Read Version"				},
	{ 0x006, "Set UART Baudrate"			},
	{ 0x007, "Enable LPM"				},
	{ 0x008, "PCM Write Configuration"		},
	{ 0x009, "Secure Send"				},
	{ 0x00d, "Read Secure Boot Params"		},
	{ 0x00e, "Write Secure Boot Params"		},
	{ 0x00f, "Unlock"				},
	{ 0x010, "Change UART Baudrate"			},
	{ 0x011, "Manufacturer Mode"			},
	{ 0x012, "Read Link RSSI"			},
	{ 0x022, "Get Exception Info"			},
	{ 0x024, "Clear Exception Info"			},
	{ 0x02f, "Write BD Data"			},
	{ 0x030, "Read BD Data"				},
	{ 0x031, "Write BD Address"			},
	{ 0x032, "Flow Specification"			},
	{ 0x034, "Read Secure ID"			},
	{ 0x038, "Set Synchronous USB Interface Type"	},
	{ 0x039, "Config Synchronous Interface"		},
	{ 0x03f, "SW RF Kill"				},
	{ 0x043, "Activate Deactivate Traces"		},
	{ 0x050, "Read HW Version"			},
	{ 0x052, "Set Event Mask"			},
	{ 0x053, "Config_Link_Controller"		},
	{ 0x089, "DDC Write"				},
	{ 0x08a, "DDC Read"				},
	{ 0x08b, "DDC Config Write"			},
	{ 0x08c, "DDC Config Read"			},
	{ 0x08d, "Memory Read"				},
	{ 0x08e, "Memory Write"				},
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

static void act_deact_traces_complete_evt(const void *data, uint8_t size)
{
	uint8_t status = *((const uint8_t *) data);

	packet_print_error("Status", status);
}

static void lmp_pdu_trace_evt(const void *data, uint8_t size)
{
	uint8_t type, len, id;
	uint16_t handle, count;
	uint32_t clock;
	const char *str;

	type = *((uint8_t *) data);
	handle = get_le16(data + 2);

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
		id = *((uint8_t *) (data + 4 + len + 4));

		packet_hexdump(data + 3, 1);
		lmp_packet(data + 4, len, false);
		print_field("Clock: 0x%8.8x", clock);
		print_field("ID: 0x%2.2x", id);
		break;
	case 0x02:
		clock = get_le32(data + 3);
		id = *((uint8_t *) (data + 3 + 4));

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
		id = *((uint8_t *) (data + 3 + 2));

		print_field("Count: 0x%4.4x", count);
		print_field("ID: 0x%2.2x", id);
		packet_hexdump(data + 3 + 2 + 1, 2);
		llcp_packet(data + 8, len, false);
		break;
	case 0x05:
		count = get_le16(data + 3);
		id = *((uint8_t *) (data + 3 + 2));

		print_field("Count: 0x%4.4x", count);
		print_field("ID: 0x%2.2x", id);
		break;
	default:
		packet_hexdump(data + 3, size - 3);
		break;
	}
}

static const struct vendor_evt vendor_evt_table[] = {
	{ 0x16, "Activate Deactivate Traces Complete",
			act_deact_traces_complete_evt, 1, true },
	{ 0x17, "LMP PDU Trace",
			lmp_pdu_trace_evt, 3, false },
	{ }
};

const struct vendor_evt *intel_vendor_evt(uint8_t evt)
{
	int i;

	for (i = 0; vendor_evt_table[i].str; i++) {
		if (vendor_evt_table[i].evt == evt)
			return &vendor_evt_table[i];
	}

	return NULL;
}
