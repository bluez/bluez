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
#include <stdlib.h>
#include <inttypes.h>

#include <bluetooth/bluetooth.h>

#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "sdp.h"

#define MAX_CHAN 64

struct chan_data {
	uint16_t index;
	uint16_t handle;
	uint16_t scid;
	uint16_t dcid;
	uint16_t psm;
	uint8_t  ctrlid;
	uint8_t  mode;
};

static struct chan_data chan_list[MAX_CHAN];

static void assign_scid(const struct l2cap_frame *frame,
				uint16_t scid, uint16_t psm, uint8_t ctrlid)
{
	int i, n = -1;

	for (i = 0; i < MAX_CHAN; i++) {
		if (n < 0 && chan_list[i].handle == 0x0000)
			n = i;

		if (chan_list[i].index != frame->index)
			continue;

		if (chan_list[i].handle != frame->handle)
			continue;

		if (frame->in) {
			if (chan_list[i].dcid == scid) {
				n = i;
				break;
			}
		} else {
			if (chan_list[i].scid == scid) {
				n = i;
				break;
			}
		}
	}

	if (n < 0)
		return;

	memset(&chan_list[n], 0, sizeof(chan_list[n]));
	chan_list[n].index = frame->index;
	chan_list[n].handle = frame->handle;

	if (frame->in)
		chan_list[n].dcid = scid;
	else
		chan_list[n].scid = scid;

	chan_list[n].psm = psm;
	chan_list[n].ctrlid = ctrlid;
	chan_list[n].mode = 0;
}

static void release_scid(const struct l2cap_frame *frame, uint16_t scid)
{
	int i;

	for (i = 0; i < MAX_CHAN; i++) {
		if (chan_list[i].index != frame->index)
			continue;

		if (chan_list[i].handle != frame->handle)
			continue;

		if (frame->in) {
			if (chan_list[i].scid == scid) {
				chan_list[i].handle = 0;
				break;
			}
		} else {
			if (chan_list[i].dcid == scid) {
				chan_list[i].handle = 0;
				break;
			}
		}
	}
}

static void assign_dcid(const struct l2cap_frame *frame,
					uint16_t dcid, uint16_t scid)
{
	int i;

	for (i = 0; i < MAX_CHAN; i++) {
		if (chan_list[i].index != frame->index)
			continue;

		if (chan_list[i].handle != frame->handle)
			continue;

		if (frame->in) {
			if (chan_list[i].scid == scid) {
				chan_list[i].dcid = dcid;
				break;
			}
		} else {
			if (chan_list[i].dcid == scid) {
				chan_list[i].scid = dcid;
				break;
			}
		}
	}
}

static void assign_mode(const struct l2cap_frame *frame,
					uint8_t mode, uint16_t dcid)
{
	int i;

	for (i = 0; i < MAX_CHAN; i++) {
		if (chan_list[i].index != frame->index)
			continue;

		if (chan_list[i].handle != frame->handle)
			continue;

		if (frame->in) {
			if (chan_list[i].scid == dcid) {
				chan_list[i].mode = mode;
				break;
			}
		} else {
			if (chan_list[i].dcid == dcid) {
				chan_list[i].mode = mode;
				break;
			}
		}
	}
}

static uint16_t get_psm(const struct l2cap_frame *frame)
{
	int i;

	for (i = 0; i < MAX_CHAN; i++) {
		if (chan_list[i].index != frame->index &&
					chan_list[i].ctrlid == 0)
			continue;

		if (chan_list[i].handle != frame->handle &&
					chan_list[i].ctrlid != frame->index)
			continue;

		if (frame->in) {
			if (chan_list[i].scid == frame->cid)
				return chan_list[i].psm;
		} else {
			if (chan_list[i].dcid == frame->cid)
				return chan_list[i].psm;
		}
	}

	return 0;
}

static uint8_t get_mode(const struct l2cap_frame *frame)
{
	int i;

	for (i = 0; i < MAX_CHAN; i++) {
		if (chan_list[i].index != frame->index &&
					chan_list[i].ctrlid == 0)
			continue;

		if (chan_list[i].handle != frame->handle &&
					chan_list[i].ctrlid != frame->index)
			continue;

		if (frame->in) {
			if (chan_list[i].scid == frame->cid)
				return chan_list[i].mode;
		} else {
			if (chan_list[i].dcid == frame->cid)
				return chan_list[i].mode;
		}
	}

	return 0;
}

#define MAX_INDEX 16

struct index_data {
	void *frag_buf;
	uint16_t frag_pos;
	uint16_t frag_len;
	uint16_t frag_cid;
};

static struct index_data index_list[MAX_INDEX];

static void clear_fragment_buffer(uint16_t index)
{
	free(index_list[index].frag_buf);
	index_list[index].frag_buf = NULL;
	index_list[index].frag_pos = 0;
	index_list[index].frag_len = 0;
}

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
	const char *str;

	if (btohs(flags) & 0x0001)
		str = " (continuation)";
	else
		str = "";

	print_field("Flags: 0x%4.4x%s", btohs(flags), str);
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

static struct {
	uint8_t type;
	uint8_t len;
	const char *str;
} options_table[] = {
	{ 0x01,  2, "Maximum Transmission Unit"		},
	{ 0x02,  2, "Flush Timeout"			},
	{ 0x03, 22, "Quality of Service"		},
	{ 0x04,  9, "Retransmission and Flow Control"	},
	{ 0x05,  1, "Frame Check Sequence"		},
	{ 0x06, 16, "Extended Flow Specification"	},
	{ 0x07,  2, "Extended Window Size"		},
        { }
};

static void print_config_options(const struct l2cap_frame *frame,
				uint8_t offset, uint16_t dcid, bool response)
{
	const uint8_t *data = frame->data + offset;
	uint16_t size = frame->size - offset;
	uint16_t consumed = 0;

	while (consumed < size - 2) {
		const char *str = "Unknown";
		uint8_t type = data[consumed];
		uint8_t len = data[consumed + 1];
		uint8_t expect_len = 0;
		int i;

		for (i = 0; options_table[i].str; i++) {
			if (options_table[i].type == type) {
				str = options_table[i].str;
				expect_len = options_table[i].len;
				break;
			}
		}

		print_field("Option: %s (0x%2.2x)", str, type);

		if (len != expect_len) {
			print_text(COLOR_ERROR, "wrong option size (%d != %d)",
							len, expect_len);
			break;
		}

		switch (type) {
		case 0x01:
			print_field("  MTU: %d",
					bt_get_le16(data + consumed + 2));
			break;
		case 0x02:
			print_field("  Flush timeout: %d",
					bt_get_le16(data + consumed + 2));
			break;
		case 0x03:
			switch (data[consumed + 3]) {
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
			print_field("  Flags: 0x%2.2x", data[consumed + 2]);
			print_field("  Service type: %s (0x%2.2x)",
						str, data[consumed + 3]);
			print_field("  Token rate: 0x%8.8x",
					bt_get_le32(data + consumed + 4));
			print_field("  Token bucket size: 0x%8.8x",
					bt_get_le32(data + consumed + 8));
			print_field("  Peak bandwidth: 0x%8.8x",
					bt_get_le32(data + consumed + 12));
			print_field("  Latency: 0x%8.8x",
					bt_get_le32(data + consumed + 16));
			print_field("  Delay variation: 0x%8.8x",
					bt_get_le32(data + consumed + 20));
                        break;
		case 0x04:
			if (response)
				assign_mode(frame, data[consumed + 2], dcid);

			switch (data[consumed + 2]) {
			case 0x00:
				str = "Basic";
				break;
			case 0x01:
				str = "Retransmission";
				break;
			case 0x02:
				str = "Flow control";
				break;
			case 0x03:
				str = "Enhanced retransmission";
				break;
			case 0x04:
				str = "Streaming";
				break;
			default:
				str = "Reserved";
				break;
			}
			print_field("  Mode: %s (0x%2.2x)",
						str, data[consumed + 2]);
			print_field("  TX window size: %d", data[consumed + 3]);
			print_field("  Max transmit: %d", data[consumed + 4]);
			print_field("  Retransmission timeout: %d",
					bt_get_le16(data + consumed + 5));
			print_field("  Monitor timeout: %d",
					bt_get_le16(data + consumed + 7));
			print_field("  Maximum PDU size: %d",
					bt_get_le16(data + consumed + 9));
			break;
		case 0x05:
			switch (data[consumed + 2]) {
			case 0x00:
				str = "No FCS";
				break;
			case 0x01:
				str = "16-bit FCS";
				break;
			default:
				str = "Reserved";
				break;
			}
			print_field("  FCS: %s (0x%2.2d)",
						str, data[consumed + 2]);
			break;
		case 0x06:
			switch (data[consumed + 3]) {
			case 0x00:
				str = "No traffic";
				break;
			case 0x01:
				str = "Best effort";
				break;
			case 0x02:
				str = "Guaranteed";
				break;
			default:
				str = "Reserved";
				break;
			}
			print_field("  Identifier: 0x%2.2x",
						data[consumed + 2]);
			print_field("  Service type: %s (0x%2.2x)",
						str, data[consumed + 3]);
			print_field("  Maximum SDU size: 0x%4.4x",
					bt_get_le16(data + consumed + 4));
			print_field("  SDU inter-arrival time: 0x%8.8x",
					bt_get_le32(data + consumed + 6));
			print_field("  Access latency: 0x%8.8x",
					bt_get_le32(data + consumed + 10));
			print_field("  Flush timeout: 0x%8.8x",
					bt_get_le32(data + consumed + 14));
			break;
		case 0x07:
			print_field("  Max window size: %d",
					bt_get_le16(data + consumed + 2));
			break;
		default:
			packet_hexdump(data + consumed + 2, len);
			break;
		}

		consumed += len + 2;
	}

	if (consumed < size)
		packet_hexdump(data + consumed, size - consumed);
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

static struct {
	uint8_t bit;
	const char *str;
} features_table[] = {
	{  0, "Flow control mode"			},
	{  1, "Retransmission mode"			},
	{  2, "Bi-directional QoS"			},
	{  3, "Enhanced Retransmission Mode"		},
	{  4, "Streaming Mode"				},
	{  5, "FCS Option"				},
	{  6, "Extended Flow Specification for BR/EDR"	},
	{  7, "Fixed Channels"				},
	{  8, "Extended Window Size"			},
	{  9, "Unicast Connectionless Data Reception"	},
	{ 31, "Reserved for feature mask extension"	},
	{ }
};

static void print_features(uint32_t features)
{
	uint32_t mask = features;
	int i;

	print_field("Features: 0x%8.8x", features);

	for (i = 0; features_table[i].str; i++) {
		if (features & (1 << features_table[i].bit)) {
			print_field("  %s", features_table[i].str);
			mask &= ~(1 << features_table[i].bit);
		}
	}

	if (mask)
		print_field("  Unknown features (0x%8.8x)", mask);
}

static struct {
	uint16_t cid;
	const char *str;
} channels_table[] = {
	{ 0x0000, "Null identifier"		},
	{ 0x0001, "L2CAP Signaling (BR/EDR)"	},
	{ 0x0002, "Connectionless reception"	},
	{ 0x0003, "AMP Manager Protocol"	},
	{ 0x0004, "Attribute Protocol"		},
	{ 0x0005, "L2CAP Signaling (LE)"	},
	{ 0x0006, "Security Manager"		},
	{ 0x003f, "AMP Test Manager"		},
	{ }
};

static void print_channels(uint64_t channels)
{
	uint64_t mask = channels;
	int i;

	print_field("Channels: 0x%16.16" PRIx64, channels);

	for (i = 0; channels_table[i].str; i++) {
		if (channels & (1 << channels_table[i].cid)) {
			print_field("  %s", channels_table[i].str);
			mask &= ~(1 << channels_table[i].cid);
		}
	}

	if (mask)
		print_field("  Unknown channels (0x%8.8" PRIx64 ")", mask);
}

static void print_move_result(uint16_t result)
{
	const char *str;

	switch (btohs(result)) {
	case 0x0000:
		str = "Move success";
		break;
	case 0x0001:
		str = "Move pending";
		break;
	case 0x0002:
		str = "Move refused - Controller ID not supported";
		break;
	case 0x0003:
		str = "Move refused - new Controller ID is same";
		break;
	case 0x0004:
		str = "Move refused - Configuration not supported";
		break;
	case 0x0005:
		str = "Move refused - Move Channel collision";
		break;
	case 0x0006:
		str = "Move refused - Channel not allowed to be moved";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Result: %s (0x%4.4x)", str, btohs(result));
}

static void print_move_conf_result(uint16_t result)
{
	const char *str;

	switch (btohs(result)) {
	case 0x0000:
		str = "Move success - both sides succeed";
		break;
	case 0x0001:
		str = "Move failure - one or both sides refuse";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Result: %s (0x%4.4x)", str, btohs(result));
}

static void print_conn_param_result(uint16_t result)
{
	const char *str;

	switch (btohs(result)) {
	case 0x0000:
		str = "Connection Parameters accepted";
		break;
	case 0x0001:
		str = "Connection Parameters rejected";
		break;
	default:
		str = "Reserved";
		break;
	}

	print_field("Result: %s (0x%4.4x)", str, btohs(result));
}

static void sig_cmd_reject(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_cmd_reject *pdu = frame->data;
	const void *data = frame->data;
	uint16_t size = frame->size;
	uint16_t scid, dcid;

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
		print_field("MTU: %d", bt_get_le16(data));
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

static void sig_conn_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_conn_req *pdu = frame->data;

	print_psm(pdu->psm);
	print_cid("Source", pdu->scid);

	assign_scid(frame, btohs(pdu->scid), btohs(pdu->psm), 0);
}

static void sig_conn_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_conn_rsp *pdu = frame->data;

	print_cid("Destination", pdu->dcid);
	print_cid("Source", pdu->scid);
	print_conn_result(pdu->result);
	print_conn_status(pdu->status);

	assign_dcid(frame, btohs(pdu->dcid), btohs(pdu->scid));
}

static void sig_config_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_config_rsp *pdu = frame->data;

	print_cid("Destination", pdu->dcid);
	print_config_flags(pdu->flags);
	print_config_options(frame, 4, btohs(pdu->dcid), false);
}

static void sig_config_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_config_rsp *pdu = frame->data;

	print_cid("Destination", pdu->dcid);
	print_config_flags(pdu->flags);
	print_config_result(pdu->result);
	print_config_options(frame, 6, btohs(pdu->dcid), true);
}

static void sig_disconn_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_disconn_req *pdu = frame->data;

	print_cid("Destination", pdu->dcid);
	print_cid("Source", pdu->scid);
}

static void sig_disconn_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_disconn_rsp *pdu = frame->data;

	print_cid("Destination", pdu->dcid);
	print_cid("Source", pdu->scid);

	release_scid(frame, btohs(pdu->scid));
}

static void sig_echo_req(const struct l2cap_frame *frame)
{
	packet_hexdump(frame->data, frame->size);
}

static void sig_echo_rsp(const struct l2cap_frame *frame)
{
	packet_hexdump(frame->data, frame->size);
}

static void sig_info_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_info_req *pdu = frame->data;

	print_info_type(pdu->type);
}

static void sig_info_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_info_rsp *pdu = frame->data;
	const void *data = frame->data;
	uint16_t size = frame->size;

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
		print_field("MTU: %d", bt_get_le16(data));
		break;
	case 0x0002:
		if (size != 4) {
			print_text(COLOR_ERROR, "invalid data size");
			packet_hexdump(data, size);
			break;
		}
		print_features(bt_get_le32(data));
		break;
	case 0x0003:
		if (size != 8) {
			print_text(COLOR_ERROR, "invalid data size");
			packet_hexdump(data, size);
			break;
		}
		print_channels(bt_get_le64(data));
		break;
	default:
		packet_hexdump(data, size);
		break;
	}
}

static void sig_create_chan_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_create_chan_req *pdu = frame->data;

	print_psm(pdu->psm);
	print_cid("Source", pdu->scid);
	print_field("Controller ID: %d", pdu->ctrlid);

	assign_scid(frame, btohs(pdu->scid), btohs(pdu->psm), pdu->ctrlid);
}

static void sig_create_chan_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_create_chan_rsp *pdu = frame->data;

	print_cid("Destination", pdu->dcid);
	print_cid("Source", pdu->scid);
	print_conn_result(pdu->result);
	print_conn_status(pdu->status);

	assign_dcid(frame, btohs(pdu->dcid), btohs(pdu->scid));
}

static void sig_move_chan_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_move_chan_req *pdu = frame->data;

	print_cid("Initiator", pdu->icid);
	print_field("Controller ID: %d", pdu->ctrlid);
}

static void sig_move_chan_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_move_chan_rsp *pdu = frame->data;

	print_cid("Initiator", pdu->icid);
	print_move_result(pdu->result);
}

static void sig_move_chan_conf(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_move_chan_conf *pdu = frame->data;

	print_cid("Initiator", pdu->icid);
	print_move_conf_result(pdu->result);
}

static void sig_move_chan_conf_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_move_chan_conf_rsp *pdu = frame->data;

	print_cid("Initiator", pdu->icid);
}

static void sig_conn_param_req(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_conn_param_req *pdu = frame->data;

	print_field("Min interval: %d", btohs(pdu->min_interval));
	print_field("Max interval: %d", btohs(pdu->max_interval));
	print_field("Slave latency: %d", btohs(pdu->latency));
	print_field("Timeout multiplier: %d", btohs(pdu->timeout));
}

static void sig_conn_param_rsp(const struct l2cap_frame *frame)
{
	const struct bt_l2cap_pdu_conn_param_rsp *pdu = frame->data;

	print_conn_param_result(pdu->result);
}

struct sig_opcode_data {
	uint8_t opcode;
	const char *str;
	void (*func) (const struct l2cap_frame *frame);
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
	{ 0x0c, "Create Channel Request",
			sig_create_chan_req, 5, true },
	{ 0x0d, "Create Channel Response",
			sig_create_chan_rsp, 8, true },
	{ 0x0e, "Move Channel Request",
			sig_move_chan_req, 3, true },
	{ 0x0f, "Move Channel Response",
			sig_move_chan_rsp, 4, true },
	{ 0x10, "Move Channel Confirmation",
			sig_move_chan_conf, 4, true },
	{ 0x11, "Move Channel Confirmation Response",
			sig_move_chan_conf_rsp, 2, true },
	{ 0x12, "Connection Parameter Update Request",
			sig_conn_param_req, 8, true },
	{ 0x13, "Connection Parameter Update Response",
			sig_conn_param_rsp, 2, true },
	{ },
};

static void sig_packet(uint16_t index, bool in, uint16_t handle,
			uint16_t cid, const void *data, uint16_t size)
{
	struct l2cap_frame frame;

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

		l2cap_frame_init(&frame, index, in, handle, cid, data, len);
		opcode_data->func(&frame);

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

static void l2cap_frame(uint16_t index, bool in, uint16_t handle,
			uint16_t cid, const void *data, uint16_t size)
{
	struct l2cap_frame frame;
	uint16_t psm;
	uint8_t mode;

	switch (cid) {
	case 0x0001:
	case 0x0005:
		sig_packet(index, in, handle, cid, data, size);
		break;
	case 0x0003:
		amp_packet(data, size);
		break;
	case 0x0004:
		att_packet(data, size);
		break;
	case 0x0006:
		smp_packet(data, size);
		break;
	default:
		l2cap_frame_init(&frame, index, in, handle, cid, data, size);
		psm = get_psm(&frame);
		mode = get_mode(&frame);

		print_indent(6, COLOR_CYAN, "Channel:", "", COLOR_OFF,
						" %d len %d [PSM %d mode %d]",
							cid, size, psm, mode);

		switch (psm) {
		case 0x0001:
			sdp_packet(&frame);
			break;
		default:
			packet_hexdump(data, size);
			break;
		}
		break;
	}
}

void l2cap_packet(uint16_t index, bool in, uint16_t handle, uint8_t flags,
					const void *data, uint16_t size)
{
	const struct bt_l2cap_hdr *hdr = data;
	uint16_t len, cid;

	if (index > MAX_INDEX - 1) {
		print_text(COLOR_ERROR, "controller index too large");
		packet_hexdump(data, size);
		return;
	}

	switch (flags) {
	case 0x00:	/* start of a non-automatically-flushable PDU */
	case 0x02:	/* start of an automatically-flushable PDU */
		if (index_list[index].frag_len) {
			print_text(COLOR_ERROR, "unexpected start frame");
			packet_hexdump(data, size);
			clear_fragment_buffer(index);
			return;
		}

		if (size < sizeof(*hdr)) {
			print_text(COLOR_ERROR, "frame too short");
			packet_hexdump(data, size);
			return;
		}

		len = btohs(hdr->len);
		cid = btohs(hdr->cid);

		data += sizeof(*hdr);
		size -= sizeof(*hdr);

		if (len == size) {
			/* complete frame */
			l2cap_frame(index, in, handle, cid, data, len);
			return;
		}

		if (size > len) {
			print_text(COLOR_ERROR, "frame too long");
			packet_hexdump(data, size);
			return;
		}

		index_list[index].frag_buf = malloc(len);
		if (!index_list[index].frag_buf) {
			print_text(COLOR_ERROR, "failed buffer allocation");
			packet_hexdump(data, size);
			return;
		}

		memcpy(index_list[index].frag_buf, data, size);
		index_list[index].frag_pos = size;
		index_list[index].frag_len = len - size;
		index_list[index].frag_cid = cid;
		break;

	case 0x01:	/* continuing fragment */
		if (!index_list[index].frag_len) {
			print_text(COLOR_ERROR, "unexpected continuation");
			packet_hexdump(data, size);
			return;
		}

		if (size > index_list[index].frag_len) {
			print_text(COLOR_ERROR, "fragment too long");
			packet_hexdump(data, size);
			clear_fragment_buffer(index);
			return;
		}

		memcpy(index_list[index].frag_buf +
				index_list[index].frag_pos, data, size);
		index_list[index].frag_pos += size;
		index_list[index].frag_len -= size;

		if (!index_list[index].frag_len) {
			/* complete frame */
			l2cap_frame(index, in, handle,
					index_list[index].frag_cid,
					data, index_list[index].frag_pos);
			clear_fragment_buffer(index);
			return;
		}
		break;

	case 0x03:	/* complete automatically-flushable PDU */
		if (index_list[index].frag_len) {
			print_text(COLOR_ERROR, "unexpected complete frame");
			packet_hexdump(data, size);
			clear_fragment_buffer(index);
			return;
		}

		if (size < sizeof(*hdr)) {
			print_text(COLOR_ERROR, "frame too short");
			packet_hexdump(data, size);
			return;
		}

		len = btohs(hdr->len);
		cid = btohs(hdr->cid);

		data += sizeof(*hdr);
		size -= sizeof(*hdr);

		if (len != size) {
			print_text(COLOR_ERROR, "wrong frame size");
			packet_hexdump(data, size);
			return;
		}

		/* complete frame */
		l2cap_frame(index, in, handle, cid, data, len);
		break;

	default:
		print_text(COLOR_ERROR, "invalid packet flags (0x%2.2x)",
								flags);
		packet_hexdump(data, size);
		return;
	}
}
