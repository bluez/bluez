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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/shared/util.h"
#include "bt.h"
#include "packet.h"
#include "display.h"
#include "l2cap.h"
#include "keys.h"
#include "sdp.h"
#include "rfcomm.h"
#include "obex.h"

static const char *cr_str[] = {
	"RSP",
	"CMD"
};

/* RFCOMM frame parsing macros */
#define CR_STR(type)		cr_str[GET_CR(type)]
#define GET_LEN8(length)	((length & 0xfe) >> 1)
#define GET_LEN16(length)	((length & 0xfffe) >> 1)
#define GET_CR(type)		((type & 0x02) >> 1)
#define GET_PF(ctr)		(((ctr) >> 4) & 0x1)

/* MSC macros */
#define GET_V24_FC(sigs)	((sigs & 0x02) >> 1)
#define GET_V24_RTC(sigs)	((sigs & 0x04) >> 2)
#define GET_V24_RTR(sigs)	((sigs & 0x08) >> 3)
#define GET_V24_IC(sigs)	((sigs & 0x40) >> 6)
#define GET_V24_DV(sigs)	((sigs & 0x80) >> 7)

/* RPN macros */
#define GET_RPN_DB(parity)	(parity & 0x03)
#define GET_RPN_SB(parity)	((parity & 0x04) >> 2)
#define GET_RPN_PARITY(parity)	((parity & 0x08) >> 3)
#define GET_RPN_PTYPE(parity)	((parity & 0x30) >> 4)
#define GET_RPN_XIN(io)		(io & 0x01)
#define GET_RPN_XOUT(io)	((io & 0x02) >> 1)
#define GET_RPN_RTRI(io)	((io & 0x04) >> 2)
#define GET_RPN_RTRO(io)	((io & 0x08) >> 3)
#define GET_RPN_RTCI(io)	((io & 0x10) >> 4)
#define GET_RPN_RTCO(io)	((io & 0x20) >> 5)

/* RLS macro */
#define GET_ERROR(err)		(err & 0x0f)

/* PN macros */
#define GET_FRM_TYPE(ctrl)	((ctrl & 0x0f))
#define GET_CRT_FLOW(ctrl)	((ctrl & 0xf0) >> 4)
#define GET_PRIORITY(prio)	((prio & 0x3f))
#define GET_PN_DLCI(dlci)	((dlci & 0x3f))

struct rfcomm_lhdr {
	uint8_t address;
	uint8_t control;
	uint16_t length;
	uint8_t fcs;
	uint8_t credits; /* only for UIH frame */
};

struct rfcomm_lmsc {
	uint8_t dlci;
	uint8_t v24_sig;
	uint8_t break_sig;
};

struct rfcomm_rpn {
	uint8_t dlci;
	uint8_t bit_rate;
	uint8_t parity;
	uint8_t io;
	uint8_t xon;
	uint8_t xoff;
	uint16_t pm;
};

struct rfcomm_rls {
	uint8_t dlci;
	uint8_t error;
};

struct rfcomm_nsc {
	uint8_t cmd_type;
};

struct rfcomm_lmcc {
	uint8_t type;
	uint16_t length;
};

struct rfcomm_frame {
	struct rfcomm_lhdr hdr;
	struct rfcomm_lmcc mcc;
	struct l2cap_frame l2cap_frame;
};

static void print_rfcomm_hdr(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	struct rfcomm_lhdr hdr = rfcomm_frame->hdr;

	/* Address field */
	print_field("%*cAddress: 0x%2.2x cr %d dlci 0x%2.2x", indent, ' ',
					hdr.address, GET_CR(hdr.address),
					RFCOMM_GET_DLCI(hdr.address));

	/* Control field */
	print_field("%*cControl: 0x%2.2x poll/final %d", indent, ' ',
					hdr.control, GET_PF(hdr.control));

	/* Length and FCS */
	print_field("%*cLength: %d", indent, ' ', hdr.length);
	print_field("%*cFCS: 0x%2.2x", indent, ' ', hdr.fcs);
}

static inline bool mcc_test(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	uint8_t data;

	display_printf("%*cTest Data: 0x ", indent, ' ');

	while (frame->size > 1) {
		if (!l2cap_frame_get_u8(frame, &data))
			return false;
		display_printf("%2.2x ", data);
	}

	display_printf("\n");
	return true;
}

static inline bool mcc_msc(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	struct rfcomm_lmsc msc;

	if (!l2cap_frame_get_u8(frame, &msc.dlci))
		return false;

	print_field("%*cdlci %d ", indent, ' ', RFCOMM_GET_DLCI(msc.dlci));

	if (!l2cap_frame_get_u8(frame, &msc.v24_sig))
		return false;

	/* v24 control signals */
	print_field("%*cfc %d rtc %d rtr %d ic %d dv %d", indent, ' ',
		GET_V24_FC(msc.v24_sig), GET_V24_RTC(msc.v24_sig),
		GET_V24_RTR(msc.v24_sig), GET_V24_IC(msc.v24_sig),
					GET_V24_DV(msc.v24_sig));

	if (frame->size < 2)
		goto done;

	/*
	 * TODO: Implement the break signals decoding.
	 */

	packet_hexdump(frame->data, frame->size);

done:
	return true;
}

static inline bool mcc_rpn(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	struct rfcomm_rpn rpn;

	if (!l2cap_frame_get_u8(frame, &rpn.dlci))
		return false;

	print_field("%*cdlci %d", indent, ' ', RFCOMM_GET_DLCI(rpn.dlci));

	if (frame->size < 7)
		goto done;

	/* port value octets (optional) */

	if (!l2cap_frame_get_u8(frame, &rpn.bit_rate))
		return false;

	if (!l2cap_frame_get_u8(frame, &rpn.parity))
		return false;

	if (!l2cap_frame_get_u8(frame, &rpn.io))
		return false;

	print_field("%*cbr %d db %d sb %d p %d pt %d xi %d xo %d", indent, ' ',
		rpn.bit_rate, GET_RPN_DB(rpn.parity), GET_RPN_SB(rpn.parity),
		GET_RPN_PARITY(rpn.parity), GET_RPN_PTYPE(rpn.parity),
		GET_RPN_XIN(rpn.io), GET_RPN_XOUT(rpn.io));

	if (!l2cap_frame_get_u8(frame, &rpn.xon))
		return false;

	if (!l2cap_frame_get_u8(frame, &rpn.xoff))
		return false;

	print_field("%*crtri %d rtro %d rtci %d rtco %d xon %d xoff %d",
		indent, ' ', GET_RPN_RTRI(rpn.io), GET_RPN_RTRO(rpn.io),
		GET_RPN_RTCI(rpn.io), GET_RPN_RTCO(rpn.io), rpn.xon,
		rpn.xoff);

	if (!l2cap_frame_get_le16(frame, &rpn.pm))
		return false;

	print_field("%*cpm 0x%04x", indent, ' ', rpn.pm);

done:
	return true;
}

static inline bool mcc_rls(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	struct rfcomm_rls rls;

	if (!l2cap_frame_get_u8(frame, &rls.dlci))
		return false;

	if (!l2cap_frame_get_u8(frame, &rls.error))
		return false;

	print_field("%*cdlci %d error: %d", indent, ' ',
			RFCOMM_GET_DLCI(rls.dlci), GET_ERROR(rls.error));

	return true;
}

static inline bool mcc_pn(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	struct rfcomm_pn pn;
	uint16_t mtu;

	/* rfcomm_pn struct is defined in rfcomm.h */

	if (!l2cap_frame_get_u8(frame, &pn.dlci))
		return false;

	if (!l2cap_frame_get_u8(frame, &pn.flow_ctrl))
		return false;

	if (!l2cap_frame_get_u8(frame, &pn.priority))
		return false;

	print_field("%*cdlci %d frame_type %d credit_flow %d pri %d", indent,
			' ', GET_PN_DLCI(pn.dlci), GET_FRM_TYPE(pn.flow_ctrl),
			GET_CRT_FLOW(pn.flow_ctrl), GET_PRIORITY(pn.priority));

	if (!l2cap_frame_get_u8(frame, &pn.ack_timer))
		return false;

	if (!l2cap_frame_get_le16(frame, &mtu))
		return false;

	pn.mtu = mtu;

	if (!l2cap_frame_get_u8(frame, &pn.max_retrans))
		return false;

	if (!l2cap_frame_get_u8(frame, &pn.credits))
		return false;

	print_field("%*cack_timer %d frame_size %d max_retrans %d credits %d",
			indent, ' ', pn.ack_timer, pn.mtu, pn.max_retrans,
			pn.credits);

	return true;
}

static inline bool mcc_nsc(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	struct rfcomm_nsc nsc;

	if (!l2cap_frame_get_u8(frame, &nsc.cmd_type))
		return false;

	print_field("%*ccr %d, mcc_cmd_type %x", indent, ' ',
		GET_CR(nsc.cmd_type), RFCOMM_GET_MCC_TYPE(nsc.cmd_type));

	return true;
}

struct mcc_data {
	uint8_t type;
	const char *str;
};

static const struct mcc_data mcc_table[] = {
	{ 0x08, "Test Command" },
	{ 0x28, "Flow Control On Command" },
	{ 0x18, "Flow Control Off Command" },
	{ 0x38, "Modem Status Command" },
	{ 0x24, "Remote Port Negotiation Command" },
	{ 0x14, "Remote Line Status" },
	{ 0x20, "DLC Parameter Negotiation" },
	{ 0x04, "Non Supported Command" },
	{ }
};

static inline bool mcc_frame(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	uint8_t length, ex_length, type;
	const char *type_str;
	int i;
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	struct rfcomm_lmcc mcc;
	const struct mcc_data *mcc_data = NULL;

	if (!l2cap_frame_get_u8(frame, &mcc.type) ||
			!l2cap_frame_get_u8(frame, &length))
		return false;

	if (RFCOMM_TEST_EA(length))
		mcc.length = (uint16_t) GET_LEN8(length);
	else {
		if (!l2cap_frame_get_u8(frame, &ex_length))
			return false;
		mcc.length = ((uint16_t) length << 8) | ex_length;
		mcc.length = GET_LEN16(mcc.length);
	}

	type = RFCOMM_GET_MCC_TYPE(mcc.type);

	for (i = 0; mcc_table[i].str; i++) {
		if (mcc_table[i].type == type) {
			mcc_data = &mcc_table[i];
			break;
		}
	}

	if (mcc_data)
		type_str = mcc_data->str;
	else
		type_str = "Unknown";

	print_field("%*cMCC Message type: %s %s (0x%2.2x)", indent, ' ',
				type_str, CR_STR(mcc.type), type);

	print_field("%*cLength: %d", indent+2, ' ', mcc.length);

	rfcomm_frame->mcc = mcc;

	switch (type) {
	case RFCOMM_TEST:
		return mcc_test(rfcomm_frame, indent+10);
	case RFCOMM_MSC:
		return mcc_msc(rfcomm_frame, indent+2);
	case RFCOMM_RPN:
		return mcc_rpn(rfcomm_frame, indent+2);
	case RFCOMM_RLS:
		return mcc_rls(rfcomm_frame, indent+2);
	case RFCOMM_PN:
		return mcc_pn(rfcomm_frame, indent+2);
	case RFCOMM_NSC:
		return mcc_nsc(rfcomm_frame, indent+2);
	default:
		packet_hexdump(frame->data, frame->size);
	}

	return true;
}

/* An OBEX PDU may be split across several RFCOMM UIH frames since the
 * RFCOMM MTU is typically much smaller than the maximum OBEX PDU
 * length. Information bytes are buffered per index/handle/DLCI and
 * direction until a complete PDU (3-byte opcode+length header plus
 * body) is available; complete PDUs are then decoded and any leftover
 * bytes are kept for the next frame.
 *
 * The full DLCI (server channel plus direction bit), not just the
 * server channel number, identifies the session: two connections to
 * the same server channel but opened by different initiators use
 * distinct DLCIs and must not share a reassembly buffer.
 */
#define MAX_OBEX_FRAG 64

struct obex_frag_data {
	uint16_t index;
	uint16_t handle;
	uint8_t dlci;
	bool in;
	uint8_t *buf;
	uint32_t len;
};

static struct obex_frag_data obex_frag_list[MAX_OBEX_FRAG];

static struct obex_frag_data *obex_frag_get(uint16_t index, uint16_t handle,
						uint8_t dlci, bool in)
{
	int i, n = -1;

	for (i = 0; i < MAX_OBEX_FRAG; i++) {
		if (!obex_frag_list[i].dlci) {
			if (n < 0)
				n = i;
			continue;
		}

		if (obex_frag_list[i].index == index &&
				obex_frag_list[i].handle == handle &&
				obex_frag_list[i].dlci == dlci &&
				obex_frag_list[i].in == in)
			return &obex_frag_list[i];
	}

	if (n < 0)
		return NULL;

	obex_frag_list[n].index = index;
	obex_frag_list[n].handle = handle;
	obex_frag_list[n].dlci = dlci;
	obex_frag_list[n].in = in;
	obex_frag_list[n].buf = NULL;
	obex_frag_list[n].len = 0;

	return &obex_frag_list[n];
}

static void obex_frag_reset(struct obex_frag_data *frag)
{
	free(frag->buf);
	frag->buf = NULL;
	frag->len = 0;
}

static void rfcomm_remove_channel(uint16_t index, uint16_t handle,
							uint8_t dlci)
{
	int i;

	for (i = 0; i < MAX_OBEX_FRAG; i++) {
		if (obex_frag_list[i].dlci == dlci &&
				obex_frag_list[i].index == index &&
				obex_frag_list[i].handle == handle) {
			obex_frag_reset(&obex_frag_list[i]);
			memset(&obex_frag_list[i], 0,
					sizeof(obex_frag_list[i]));
		}
	}
}

/* An ACL handle may be disconnected without an RFCOMM DISC/DM on each
 * of its channels (e.g. the link is simply dropped), which would
 * otherwise leave both directions' reassembly buffers and their slots
 * allocated. Free every fragment buffer still tracked for this handle.
 */
void rfcomm_remove_handle(uint16_t index, uint16_t handle)
{
	int i;

	for (i = 0; i < MAX_OBEX_FRAG; i++) {
		if (!obex_frag_list[i].dlci)
			continue;

		if (obex_frag_list[i].index == index &&
				obex_frag_list[i].handle == handle) {
			obex_frag_reset(&obex_frag_list[i]);
			memset(&obex_frag_list[i], 0,
					sizeof(obex_frag_list[i]));
		}
	}
}

static bool uih_frame(struct rfcomm_frame *rfcomm_frame, uint8_t indent)
{
	uint8_t credits;
	struct l2cap_frame *frame = &rfcomm_frame->l2cap_frame;
	struct rfcomm_lhdr *hdr = &rfcomm_frame->hdr;
	uint8_t channel = RFCOMM_GET_CHANNEL(hdr->address);
	uint8_t dlci = RFCOMM_GET_DLCI(hdr->address);
	struct obex_frag_data *frag;
	uint8_t *buf;
	uint32_t pos;

	if (!channel)
		return mcc_frame(rfcomm_frame, indent);

	/* fetching credits from UIH frame */
	if (GET_PF(hdr->control)) {
		if (!l2cap_frame_get_u8(frame, &credits))
			return false;
		hdr->credits = credits;
		print_field("%*cCredits: %d", indent, ' ', hdr->credits);
	}

	/* A credit-only UIH frame (credit-based flow control update)
	 * carries no information payload; nothing to decode.
	 */
	if (!frame->size)
		return true;

	/* The server channel number is only used to resolve the
	 * SDP-learned mapping; the DLCI (which also encodes which side
	 * opened the connection) is the actual session/reassembly key,
	 * since two connections can share a server channel number.
	 */
	if (!obex_channel(frame->index, frame->handle, channel, NULL)) {
		packet_hexdump(frame->data, frame->size);
		return true;
	}

	frag = obex_frag_get(frame->index, frame->handle, dlci, frame->in);
	if (!frag) {
		obex_packet(frame, dlci, frame->size);
		return true;
	}

	buf = realloc(frag->buf, frag->len + frame->size);
	if (!buf) {
		obex_frag_reset(frag);
		obex_packet(frame, dlci, frame->size);
		return true;
	}

	memcpy(buf + frag->len, frame->data, frame->size);
	frag->buf = buf;
	frag->len += frame->size;

	pos = 0;

	while (frag->len - pos >= 3) {
		struct l2cap_frame pdu_frame = *frame;
		uint16_t pdu_len = get_be16(frag->buf + pos + 1);

		if (pdu_len < 3) {
			/* Malformed declared length: hand over as much of
			 * the rest of the buffer as fits in l2cap_frame.size
			 * (uint16_t) and let obex_packet() report the error,
			 * rather than buffering indefinitely. Any excess
			 * stays buffered and is retried on the next call.
			 */
			uint32_t remaining = frag->len - pos;

			if (remaining > UINT16_MAX)
				remaining = UINT16_MAX;

			pdu_frame.data = frag->buf + pos;
			pdu_frame.size = remaining;
			obex_packet(&pdu_frame, dlci, pdu_frame.size);
			pos += remaining;
			break;
		}

		if (frag->len - pos < pdu_len)
			break;

		pdu_frame.data = frag->buf + pos;
		pdu_frame.size = pdu_len;
		obex_packet(&pdu_frame, dlci, pdu_len);

		pos += pdu_len;
	}

	if (pos == frag->len) {
		obex_frag_reset(frag);
	} else {
		/* Still waiting for more fragments: show this frame's own
		 * payload so partial OBEX data isn't silently dropped from
		 * the trace, mirroring the L2CAP SAR reassembly path.
		 */
		packet_hexdump(frame->data, frame->size);

		if (pos) {
			memmove(frag->buf, frag->buf + pos, frag->len - pos);
			frag->len -= pos;
		}
	}

	return true;
}

struct rfcomm_data {
	uint8_t frame;
	const char *str;
};

static const struct rfcomm_data rfcomm_table[] = {
	{ 0x2f, "Set Async Balance Mode (SABM)" },
	{ 0x63, "Unnumbered Ack (UA)" },
	{ 0x0f, "Disconnect Mode (DM)" },
	{ 0x43, "Disconnect (DISC)" },
	{ 0xef, "Unnumbered Info with Header Check (UIH)" },
	{ }
};

void rfcomm_packet(const struct l2cap_frame *frame)
{
	uint8_t ctype, length, ex_length, indent = 1;
	const char *frame_str, *frame_color;
	struct l2cap_frame *l2cap_frame, tmp_frame;
	struct rfcomm_frame rfcomm_frame;
	struct rfcomm_lhdr hdr;
	const struct rfcomm_data *rfcomm_data = NULL;
	uint32_t max_size;
	int i;

	l2cap_frame_pull(&rfcomm_frame.l2cap_frame, frame, 0);

	l2cap_frame = &rfcomm_frame.l2cap_frame;

	if (frame->size < 4)
		goto fail;

	memset(&hdr, 0, sizeof(hdr));
	if (!l2cap_frame_get_u8(l2cap_frame, &hdr.address) ||
			!l2cap_frame_get_u8(l2cap_frame, &hdr.control) ||
			!l2cap_frame_get_u8(l2cap_frame, &length))
		goto fail;

	/* length maybe 1 or 2 octets */
	if (RFCOMM_TEST_EA(length))
		hdr.length = (uint16_t) GET_LEN8(length);
	else {
		if (!l2cap_frame_get_u8(l2cap_frame, &ex_length))
			goto fail;
		hdr.length = ((uint16_t)ex_length << 8) | length;
		hdr.length = GET_LEN16(hdr.length);
	}

	if (!l2cap_frame->size)
		goto fail;

	l2cap_frame_pull(&tmp_frame, l2cap_frame, l2cap_frame->size-1);

	if (!l2cap_frame_get_u8(&tmp_frame, &hdr.fcs))
		goto fail;

	/* The trailing FCS byte just consumed via tmp_frame is still
	 * included in l2cap_frame's size (tmp_frame is a separate view
	 * over the same bytes). Drop it so the information payload
	 * handed to uih_frame()/mcc_frame() doesn't include it.
	 */
	l2cap_frame->size -= 1;

	/* Decoding frame type */
	ctype = RFCOMM_GET_TYPE(hdr.control);

	/* An L2CAP PDU may legally carry more than one RFCOMM frame
	 * back-to-back; bound the information payload to this frame's
	 * own declared length so trailing bytes belonging to the next
	 * multiplexed frame aren't mistaken for part of it. A UIH frame
	 * with the P/F bit set carries a leading credit octet ahead of
	 * the information field, which isn't covered by hdr.length.
	 */
	if (ctype == 0xef && GET_PF(hdr.control))
		max_size = (uint32_t) hdr.length + 1;
	else
		max_size = hdr.length;

	if (l2cap_frame->size > max_size)
		l2cap_frame->size = max_size;

	for (i = 0; rfcomm_table[i].str; i++) {
		if (rfcomm_table[i].frame == ctype) {
			rfcomm_data = &rfcomm_table[i];
			break;
		}
	}

	if (rfcomm_data) {
		if (frame->in)
			frame_color = COLOR_MAGENTA;
		else
			frame_color = COLOR_BLUE;
		frame_str = rfcomm_data->str;
	} else {
		frame_color = COLOR_WHITE_BG;
		frame_str = "Unknown";
	}

	if (!rfcomm_data) {
		packet_hexdump(frame->data, frame->size);
		return;
	}

	print_indent(6, frame_color, "RFCOMM: ", frame_str, COLOR_OFF,
						" (0x%2.2x)", ctype);

	rfcomm_frame.hdr = hdr;
	print_rfcomm_hdr(&rfcomm_frame, indent);

	/* UIH frame */
	if (ctype == 0xef) {
		if (!uih_frame(&rfcomm_frame, indent))
			goto fail;
	} else if (ctype == 0x43 || ctype == 0x0f) {
		uint8_t dlci = RFCOMM_GET_DLCI(hdr.address);

		if (!dlci) {
			/* DISC or DM on DLCI 0: the whole RFCOMM
			 * multiplexer is being torn down, taking every
			 * data channel running over it down with it, even
			 * though no per-channel DISC/DM is seen for each of
			 * them. Drop all of their OBEX state, but keep the
			 * SDP-learned channel mappings so a reconnect on
			 * the same ACL link doesn't need SDP repeated.
			 */
			obex_remove_rfcomm_sessions(frame->index,
								frame->handle);
			rfcomm_remove_handle(frame->index, frame->handle);
		} else {
			/* DISC or DM: the RFCOMM channel is being torn
			 * down, drop any OBEX state tracked for it so a
			 * later renegotiation of the same DLCI isn't
			 * misdecoded.
			 */
			obex_remove_channel(frame->index, frame->handle,
									dlci);
			rfcomm_remove_channel(frame->index, frame->handle,
									dlci);
		}
	}

	return;

fail:
	print_text(COLOR_ERROR, "Frame too short");
	packet_hexdump(frame->data, frame->size);
	return;
}
