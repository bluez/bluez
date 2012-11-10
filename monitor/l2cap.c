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

#include <inttypes.h>

#include <bluetooth/bluetooth.h>

#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"

static void print_psm(uint16_t psm)
{
	print_field("PSM: %d (0x%4.4x)", btohs(psm), btohs(psm));
}

static void print_cid(const char *type, uint16_t cid)
{
	print_field("%s CID: %d", type, btohs(cid));
}

static void print_reject_reason(uint16_t reason)
{
	const char *str;

	switch (btohs(reason)) {
	case 0x0000:
		str = "Command not understood";
		break;
	case 0x0001:
		str = "Signaling MTU exceeded";
		break;
	case 0x0002:
		str = "Invalid CID in request";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Reason: %s (0x%4.4x)", str, btohs(reason));
}

static void print_conn_result(uint16_t result)
{
	const char *str;

	switch (btohs(result)) {
	case 0x0000:
		str = "Connection successful";
		break;
	case 0x0001:
		str = "Connection pending";
		break;
	case 0x0002:
		str = "Connection refused - PSM not supported";
		break;
	case 0x0003:
		str = "Connection refused - security block";
		break;
	case 0x0004:
		str = "Connection refused - no resources available";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Result: %s (0x%4.4x)", str, btohs(result));
}

static void print_conn_status(uint16_t status)
{
        const char *str;

	switch (btohs(status)) {
	case 0x0000:
		str = "No further information available";
		break;
	case 0x0001:
		str = "Authentication pending";
		break;
	case 0x0002:
		str = "Authorization pending";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Status: %s (0x%4.4x)", str, btohs(status));
}

static void print_config_flags(uint16_t flags)
{
	print_field("Flags: 0x%4.4x", btohs(flags));
}

static void print_config_result(uint16_t result)
{
	const char *str;

	switch (btohs(result)) {
	case 0x0000:
		str = "Success";
		break;
	case 0x0001:
		str = "Failure - unacceptable parameters";
		break;
	case 0x0002:
		str = "Failure - rejected";
		break;
	case 0x0003:
		str = "Failure - unknown options";
		break;
	case 0x0004:
		str = "Pending";
		break;
	case 0x0005:
		str = "Failure - flow spec rejected";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Result: %s (0x%4.4x)", str, btohs(result));
}

static void print_info_type(uint16_t type)
{
	const char *str;

	switch (btohs(type)) {
	case 0x0001:
		str = "Connectionless MTU";
		break;
	case 0x0002:
		str = "Extended features supported";
		break;
	case 0x0003:
		str = "Fixed channels supported";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Type: %s (0x%4.4x)", str, btohs(type));
}

static void print_info_result(uint16_t result)
{
	const char *str;

	switch (btohs(result)) {
	case 0x0000:
		str = "Success";
		break;
	case 0x0001:
		str = "Not supported";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Result: %s (0x%4.4x)", str, btohs(result));
}

static void sig_cmd_reject(const void *data, uint16_t size)
{
	const struct bt_l2cap_pdu_cmd_reject *pdu = data;
	uint16_t mtu, scid, dcid;

	print_reject_reason(pdu->reason);

	data += sizeof(*pdu);
	size -= sizeof(*pdu);

	switch (btohs(pdu->reason)) {
	case 0x0000:
		if (size != 0) {
			print_text(COLOR_ERROR, "invalid data size");
			packet_hexdump(data, size);
			break;
		}
		break;
	case 0x0001:
		if (size != 2) {
			print_text(COLOR_ERROR, "invalid data size");
			packet_hexdump(data, size);
			break;
		}
		mtu = bt_get_le16(data);
		print_field("MTU: %d", mtu);
		break;
	case 0x0002:
		if (size != 4) {
			print_text(COLOR_ERROR, "invalid data size");
			packet_hexdump(data, size);
			break;
		}
		dcid = bt_get_le16(data);
		scid = bt_get_le16(data + 2);
		print_cid("Destination", htobs(dcid));
		print_cid("Source", htobs(scid));
		break;
	default:
		packet_hexdump(data, size);
		break;
	}
}

static void sig_conn_req(const void *data, uint16_t size)
{
	const struct bt_l2cap_pdu_conn_req *pdu = data;

	print_psm(pdu->psm);
	print_cid("Source", pdu->scid);
}

static void sig_conn_rsp(const void *data, uint16_t size)
{
	const struct bt_l2cap_pdu_conn_rsp *pdu = data;

	print_cid("Destination", pdu->dcid);
	print_cid("Source", pdu->scid);
	print_conn_result(pdu->result);
	print_conn_status(pdu->status);
}

static void sig_config_req(const void *data, uint16_t size)
{
        const struct bt_l2cap_pdu_config_rsp *pdu = data;

	print_cid("Destination", pdu->dcid);
	print_config_flags(pdu->flags);

	packet_hexdump(data + 4, size - 4);
}

static void sig_config_rsp(const void *data, uint16_t size)
{
	const struct bt_l2cap_pdu_config_rsp *pdu = data;

	print_cid("Destination", pdu->dcid);
	print_config_flags(pdu->flags);
	print_config_result(pdu->result);

	packet_hexdump(data + 6, size - 6);
}

static void sig_disconn_req(const void *data, uint16_t size)
{
	const struct bt_l2cap_pdu_disconn_req *pdu = data;

	print_cid("Destination", pdu->dcid);
	print_cid("Source", pdu->scid);
}

static void sig_disconn_rsp(const void *data, uint16_t size)
{
	const struct bt_l2cap_pdu_disconn_rsp *pdu = data;

	print_cid("Destination", pdu->dcid);
	print_cid("Source", pdu->scid);
}

static void sig_echo_req(const void *data, uint16_t size)
{
	packet_hexdump(data, size);
}

static void sig_echo_rsp(const void *data, uint16_t size)
{
	packet_hexdump(data, size);
}

static void sig_info_req(const void *data, uint16_t size)
{
	const struct bt_l2cap_pdu_info_req *pdu = data;

	print_info_type(pdu->type);
}

static void sig_info_rsp(const void *data, uint16_t size)
{
	const struct bt_l2cap_pdu_info_rsp *pdu = data;
	uint16_t mtu;
	uint32_t features;
	uint64_t channels;

	print_info_type(pdu->type);
	print_info_result(pdu->result);

	data += sizeof(*pdu);
	size -= sizeof(*pdu);

	switch (btohs(pdu->type)) {
	case 0x0001:
		if (size != 2) {
			print_text(COLOR_ERROR, "invalid data size");
			packet_hexdump(data, size);
			break;
		}

		mtu = bt_get_le16(data);
		print_field("MTU: %d", mtu);
		break;
	case 0x0002:
		if (size != 4) {
			print_text(COLOR_ERROR, "invalid data size");
			packet_hexdump(data, size);
			break;
		}
		features = bt_get_le32(data);
		print_field("Features: 0x%8.8x", features);
		break;
	case 0x0003:
		if (size != 8) {
			print_text(COLOR_ERROR, "invalid data size");
			packet_hexdump(data, size);
			break;
		}
		channels = bt_get_le64(data);
		print_field("Channels: 0x%16.16" PRIu64, channels);
		break;
	default:
		packet_hexdump(data, size);
		break;
	}
}

struct sig_opcode_data {
	uint8_t opcode;
	const char *str;
	void (*func) (const void *data, uint16_t size);
	uint16_t size;
	bool fixed;
};

static const struct sig_opcode_data sig_opcode_table[] = {
	{ 0x01, "Command Reject",
			sig_cmd_reject, 2, false },
	{ 0x02, "Connection Request",
			sig_conn_req, 4, true },
	{ 0x03, "Connection Response",
			sig_conn_rsp, 8, true },
	{ 0x04, "Configure Request",
			sig_config_req, 4, false },
	{ 0x05, "Configure Response",
			sig_config_rsp, 6, false },
	{ 0x06, "Disconnection Request",
			sig_disconn_req, 4, true },
	{ 0x07, "Disconnection Response",
			sig_disconn_rsp, 4, true },
	{ 0x08, "Echo Request",
			sig_echo_req, 0, false },
	{ 0x09, "Echo Response",
			sig_echo_rsp, 0, false },
	{ 0x0a, "Information Request",
			sig_info_req, 2, true },
	{ 0x0b, "Information Response",
			sig_info_rsp, 4, false },
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

static void sig_packet(bool in, const void *data, uint16_t size)
{
	while (size > 0) {
		uint16_t len;
		const struct bt_l2cap_hdr_sig *hdr = data;
		const struct sig_opcode_data *opcode_data = NULL;
		const char *opcode_color, *opcode_str;
		int i;

		if (size < 4) {
			print_text(COLOR_ERROR, "malformed signal packet");
			packet_hexdump(data, size);
			return;
		}

		len = btohs(hdr->len);

		data += 4;
		size -= 4;

		if (size < len) {
			print_text(COLOR_ERROR, "invalid signal packet size");
			packet_hexdump(data, size);
			return;
		}

		for (i = 0; sig_opcode_table[i].str; i++) {
			if (sig_opcode_table[i].opcode == hdr->code) {
				opcode_data = &sig_opcode_table[i];
				break;
			}
		}

		if (opcode_data) {
			if (opcode_data->func) {
				if (in)
					opcode_color = COLOR_MAGENTA;
				else
					opcode_color = COLOR_BLUE;
			} else
				opcode_color = COLOR_WHITE_BG;
			opcode_str = opcode_data->str;
		} else {
			opcode_color = COLOR_WHITE_BG;
			opcode_str = "Unknown";
		}

		print_indent(6, opcode_color, "L2CAP: ", opcode_str,
					COLOR_OFF,
					" (0x%2.2x) ident %d len %d",
					hdr->code, hdr->ident, len);

		if (!opcode_data || !opcode_data->func) {
			packet_hexdump(data, len);
			data += len;
			size -= len;
			return;
		}

		if (opcode_data->fixed) {
			if (len != opcode_data->size) {
				print_text(COLOR_ERROR, "invalid size");
				packet_hexdump(data, len);
				data += len;
				size -= len;
				continue;
			}
		} else {
			if (len < opcode_data->size) {
				print_text(COLOR_ERROR, "too short packet");
				packet_hexdump(data, size);
				data += len;
				size -= len;
				continue;
			}
		}

		opcode_data->func(data, len);

		data += len;
		size -= len;
	}

	packet_hexdump(data, size);
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

	print_indent(6, COLOR_CYAN, "AMP: ", opcode_str, COLOR_OFF,
			" (0x%2.2x) ident %d len %d", opcode, ident, len);

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

	print_indent(6, COLOR_CYAN, "ATT: ", opcode_str, COLOR_OFF,
				" (0x%2.2x) len %d", opcode, size - 1);

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

	print_indent(6, COLOR_CYAN, "SMP: ", opcode_str, COLOR_OFF,
				" (0x%2.2x) len %d", opcode, size - 1);

	packet_hexdump(data + 1, size - 1);
}

void l2cap_packet(uint16_t handle, bool in, const void *data, uint16_t size)
{
	const struct bt_l2cap_hdr *hdr = data;
	uint16_t len, cid;

	if (size < sizeof(*hdr)) {
		print_text(COLOR_ERROR, "malformed packet");
		packet_hexdump(data, size);
		return;
	}

	len = btohs(hdr->len);
	cid = btohs(hdr->cid);

	data += sizeof(*hdr);
	size -= sizeof(*hdr);

	if (len != size) {
		print_text(COLOR_ERROR, "invalid packet size");
		packet_hexdump(data, size);
		return;
	}

	switch (btohs(hdr->cid)) {
	case 0x0001:
	case 0x0005:
		sig_packet(in, data, len);
		break;
	case 0x0003:
		amp_packet(data, len);
		break;
	case 0x0004:
		att_packet(data, len);
		break;
	case 0x0006:
		smp_packet(data, len);
		break;
	default:
		print_indent(6, COLOR_CYAN, "Channel:", "", COLOR_OFF,
						" %d len %d", cid, len);
		packet_hexdump(data, len);
		break;
	}

	data += len;
	size -= len;

	packet_hexdump(data, size);
}
