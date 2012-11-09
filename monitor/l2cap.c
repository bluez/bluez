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
#include "display.h"
#include "l2cap.h"

struct sig_opcode_data {
	uint8_t opcode;
	const char *str;
	void (*func) (const void *data, uint16_t size);
	uint16_t size;
	bool fixed;
};

static const struct sig_opcode_data sig_opcode_table[] = {
	{ 0x01, "Command Reject"			},
	{ 0x02, "Connection Request"			},
	{ 0x03, "Connection Response"			},
	{ 0x04, "Configure Request"			},
	{ 0x05, "Configure Response"			},
	{ 0x06, "Disconnection Request"			},
	{ 0x07, "Disconnection Response"		},
	{ 0x08, "Echo Request"				},
	{ 0x09, "Echo Response"				},
	{ 0x0a, "Information Request"			},
	{ 0x0b, "Information Response"			},
	{ 0x0c, "Create Channel Request"		},
	{ 0x0d, "Create Channel Response"		},
	{ 0x0e, "Move Channel Request"			},
	{ 0x0f, "Move Channel Response"			},
	{ 0x10, "Move Channel Confirmation"		},
	{ 0x11, "Move Channel Confirmation Response"	},
	{ 0x12, "Connection Parameter Update Request"	},
	{ 0x13, "Connection Parameter Update Response"	},
	{ },
};

static void sig_packet(const void *data, uint16_t size)
{
	uint16_t len;
	uint8_t opcode, ident;
	const struct sig_opcode_data *opcode_data = NULL;
	const char *opcode_str;
	int i;

	if (size < 4) {
		print_text(COLOR_ERROR, "malformed signal packet");
		packet_hexdump(data, size);
		return;
	}

	opcode = *((const uint8_t *) (data));
	ident = *((const uint8_t *) (data + 1));
	len = bt_get_le16(data + 2);

	if (len != size - 4) {
		print_text(COLOR_ERROR, "invalid signal packet size");
		packet_hexdump(data, size);
		return;
	}

	for (i = 0; sig_opcode_table[i].str; i++) {
		if (sig_opcode_table[i].opcode == opcode) {
			opcode_data = &sig_opcode_table[i];
			break;
		}
	}

	if (opcode_data)
		opcode_str = opcode_data->str;
	else
		opcode_str = "Unknown";

	print_field("L2CAP: %s (0x%2.2x) ident %d len %d",
					opcode_str, opcode, ident, len);

	packet_hexdump(data + 4, size - 4);
}

struct amp_opcode_data {
	uint8_t opcode;
	const char *str;
	void (*func) (const void *data, uint16_t size);
	uint16_t size;
	bool fixed;
};

static const struct amp_opcode_data amp_opcode_table[] = {
	{ 0x01, "Command Reject"			},
	{ 0x02, "Discover Request"			},
	{ 0x03, "Discover Response"			},
	{ 0x04, "Change Notify"				},
	{ 0x05, "Change Response"			},
	{ 0x06, "Get Info Request"			},
	{ 0x07, "Get Info Response"			},
	{ 0x08, "Get Assoc Request"			},
	{ 0x09, "Get Assoc Response"			},
	{ 0x0a, "Create Physical Link Request"		},
	{ 0x0b, "Create Physical Link Response"		},
	{ 0x0c, "Disconnect Physical Link Request"	},
	{ 0x0d, "Disconnect Physical Link Response"	},
	{ },
};

static void amp_packet(const void *data, uint16_t size)
{
	uint16_t control, fcs, len;
	uint8_t opcode, ident;
	const struct amp_opcode_data *opcode_data = NULL;
	const char *opcode_str;
	int i;

	if (size < 4) {
		print_text(COLOR_ERROR, "malformed info frame packet");
		packet_hexdump(data, size);
		return;
	}

	control = bt_get_le16(data);
	fcs = bt_get_le16(data + size - 2);

	print_field("Channel: %d dlen %d control 0x%4.4x fcs 0x%4.4x",
						3, size, control, fcs);

	if (control & 0x01)
		return;

	if (size < 8) {
		print_text(COLOR_ERROR, "malformed manager packet");
		packet_hexdump(data, size);
		return;
	}

	opcode = *((const uint8_t *) (data + 2));
	ident = *((const uint8_t *) (data + 3));
	len = bt_get_le16(data + 4);

	if (len != size - 8) {
		print_text(COLOR_ERROR, "invalid manager packet size");
		packet_hexdump(data +  2, size - 4);
		return;
	}

	for (i = 0; amp_opcode_table[i].str; i++) {
		if (amp_opcode_table[i].opcode == opcode) {
			opcode_data = &amp_opcode_table[i];
			break;
		}
	}

	if (opcode_data)
		opcode_str = opcode_data->str;
	else
		opcode_str = "Unknown";

	print_field("AMP: %s (0x%2.2x) ident %d len %d",
					opcode_str, opcode, ident, len);

	packet_hexdump(data + 6, size - 8);
}

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
		print_text(COLOR_ERROR, "malformed attribute packet");
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

	print_field("ATT: %s (0x%2.2x) len %d", opcode_str, opcode, size - 1);

	packet_hexdump(data + 1, size - 1);
}

struct smp_opcode_data {
	uint8_t opcode;
	const char *str;
	void (*func) (const void *data, uint8_t size);
	uint8_t size;
	bool fixed;
};

static const struct smp_opcode_data smp_opcode_table[] = {
	{ 0x01, "Pairing Request"		},
	{ 0x02, "Pairing Response"		},
	{ 0x03, "Pairing Confirm"		},
	{ 0x04, "Pairing Random"		},
	{ 0x05, "Pairing Failed"		},
	{ 0x06, "Encryption Information"	},
	{ 0x07, "Master Identification"		},
	{ 0x08, "Identity Information"		},
	{ 0x09, "Identity Address Information"	},
	{ 0x0a, "Signing Information"		},
	{ 0x0b, "Security Request"		},
	{ }
};

static void smp_packet(const void *data, uint16_t size)
{
	uint8_t opcode = *((const uint8_t *) data);
	const struct smp_opcode_data *opcode_data = NULL;
	const char *opcode_str;
	int i;

	if (size < 1) {
		print_text(COLOR_ERROR, "malformed security packet");
		packet_hexdump(data, size);
		return;
	}

	for (i = 0; smp_opcode_table[i].str; i++) {
		if (smp_opcode_table[i].opcode == opcode) {
			opcode_data = &smp_opcode_table[i];
			break;
		}
	}

	if (opcode_data)
		opcode_str = opcode_data->str;
	else
		opcode_str = "Unknown";

	print_field("SMP: %s (0x%2.2x) len %d", opcode_str, opcode, size - 1);

	packet_hexdump(data + 1, size - 1);
}

void l2cap_packet(uint16_t handle, const void *data, uint16_t size)
{
	const struct bt_l2cap_hdr *hdr = data;

	if (size < sizeof(*hdr)) {
		print_text(COLOR_ERROR, "malformed packet");
		packet_hexdump(data, size);
		return;
	}

	if (btohs(hdr->len) != size - sizeof(*hdr)) {
		print_text(COLOR_ERROR, "invalid packet size");
		packet_hexdump(data + sizeof(*hdr), size - sizeof(*hdr));
		return;
	}

	switch (btohs(hdr->cid)) {
	case 0x0001:
	case 0x0005:
		sig_packet(data + sizeof(*hdr), size - sizeof(*hdr));
		break;
	case 0x0003:
		amp_packet(data + sizeof(*hdr), size - sizeof(*hdr));
		break;
	case 0x0004:
		att_packet(data + sizeof(*hdr), size - sizeof(*hdr));
		break;
	case 0x0006:
		smp_packet(data + sizeof(*hdr), size - sizeof(*hdr));
		break;
	default:
		print_field("Channel: %d dlen %d", btohs(hdr->cid),
							btohs(hdr->len));
		packet_hexdump(data + sizeof(*hdr), size - sizeof(*hdr));
		break;
	}
}
