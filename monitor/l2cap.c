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

#include <bluetooth/bluetooth.h>

#include "packet.h"
#include "l2cap.h"

#define print_field(fmt, args...) printf("%-12c" fmt "\n", ' ', ## args)

struct att_opcode_data {
	uint8_t opcode;
	const char *str;
	void (*func) (const void *data, uint8_t size);
	uint8_t size;
	bool fixed;
};

static const struct att_opcode_data att_opcode_table[] = {
	{ 0x01, "Error Response"		},
	{ 0x02, "Exchange MTU Request"		},
	{ 0x03, "Exchange MTU Response"		},
	{ 0x04, "Find Information Request"	},
	{ 0x05, "Find Information Response"	},
	{ 0x06, "Find By Type Value Request"	},
	{ 0x07, "Find By Type Value Response"	},
	{ 0x08, "Read By Type Request"		},
	{ 0x09, "Read By Type Response"		},
	{ 0x0a, "Read Request"			},
	{ 0x0b, "Read Response"			},
	{ 0x0c, "Read Blob Request"		},
	{ 0x0d, "Read Blob Response"		},
	{ 0x0e, "Read Multiple Request"		},
	{ 0x0f, "Read Multiple Response"	},
	{ 0x10, "Read By Group Type Request"	},
	{ 0x11, "Read By Group Type Response"	},
	{ 0x12, "Write Request"			},
	{ 0x13, "Write Response"		},
	{ 0x16, "Prepare Write Request"		},
	{ 0x17, "Prepare Write Response"	},
	{ 0x18, "Execute Write Request"		},
	{ 0x19, "Execute Write Response"	},
	{ 0x1b, "Handle Value Notification"	},
	{ 0x1d, "Handle Value Indication"	},
	{ 0x1e, "Handle Value Confirmation"	},
	{ 0x52, "Write Command"			},
	{ 0xd2, "Signed Write Command"		},
	{ }
};

static void att_packet(const void *data, uint16_t size)
{
	uint8_t opcode = *((const uint8_t *) data);
	const struct att_opcode_data *opcode_data = NULL;
	const char *opcode_str;
	int i;

	if (size < 1) {
		print_field("malformed attribute packet");
		packet_hexdump(data, size);
		return;
	}

	for (i = 0; att_opcode_table[i].str; i++) {
		if (att_opcode_table[i].opcode == opcode) {
			opcode_data = &att_opcode_table[i];
			break;
		}
	}

	if (opcode_data)
		opcode_str = opcode_data->str;
	else
		opcode_str = "Unknown";

	print_field("ATT: %s (0x%2.2x)", opcode_str, opcode);

	packet_hexdump(data + 1, size - 1);
}

void l2cap_packet(const void *data, uint16_t size)
{
	const struct bt_l2cap_hdr *hdr = data;

	if (size < sizeof(*hdr)) {
		print_field("malformed packet");
		packet_hexdump(data, size);
		return;
	}

	if (btohs(hdr->len) != size - sizeof(*hdr)) {
		print_field("invalid packet size");
		packet_hexdump(data +  sizeof(*hdr), size - sizeof(*hdr));
		return;
	}

	switch (btohs(hdr->cid)) {
	case 0x0004:
		att_packet(data +  sizeof(*hdr), size - sizeof(*hdr));
		break;
	default:
		print_field("Channel: %d dlen %d", btohs(hdr->cid),
							btohs(hdr->len));
		packet_hexdump(data +  sizeof(*hdr), size - sizeof(*hdr));
		break;
	}
}
