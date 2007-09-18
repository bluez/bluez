/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2002  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2003-2007  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#include "parser.h"
#include "sdp.h"

typedef struct {
	uint16_t handle;
	struct frame frm;
} handle_info;
#define HANDLE_TABLE_SIZE 10

static handle_info handle_table[HANDLE_TABLE_SIZE];

typedef struct {
	uint16_t handle;
	uint16_t cid;
	uint16_t psm;
	uint16_t num;
	uint8_t mode;
} cid_info;
#define CID_TABLE_SIZE 20

static cid_info cid_table[2][CID_TABLE_SIZE];

#define SCID cid_table[0]
#define DCID cid_table[1]

static struct frame *add_handle(uint16_t handle)
{
	register handle_info *t = handle_table;
	register int i;

	for (i = 0; i < HANDLE_TABLE_SIZE; i++)
		if (!t[i].handle) {
			t[i].handle = handle;
			return &t[i].frm;
		}
	return NULL;
}

static struct frame *get_frame(uint16_t handle)
{
	register handle_info *t = handle_table;
	register int i;

	for (i = 0; i < HANDLE_TABLE_SIZE; i++)
		if (t[i].handle == handle)
			return &t[i].frm;

	return add_handle(handle);
}

static void add_cid(int in, uint16_t handle, uint16_t cid, uint16_t psm)
{
	register cid_info *table = cid_table[in];
	register int i, pos = -1;
	uint16_t num = 1;

	for (i = 0; i < CID_TABLE_SIZE; i++) {
		if ((pos < 0 && !table[i].cid) || table[i].cid == cid)
			pos = i;
		if (table[i].psm == psm)
			num++;
	}

	if (pos >= 0) {
		table[pos].handle = handle;
		table[pos].cid    = cid;
		table[pos].psm    = psm;
		table[pos].num    = num;
		table[pos].mode   = 0;
	}
}

static void del_cid(int in, uint16_t dcid, uint16_t scid)
{
	register int t, i;
	uint16_t cid[2];

	if (!in) {
		cid[0] = dcid;
		cid[1] = scid;
	} else {
		cid[0] = scid;
		cid[1] = dcid;
	}

	for (t = 0; t < 2; t++) {
		for (i = 0; i < CID_TABLE_SIZE; i++)
			if (cid_table[t][i].cid == cid[t]) {
				cid_table[t][i].handle = 0;
				cid_table[t][i].cid    = 0;
				cid_table[t][i].psm    = 0;
				cid_table[t][i].num    = 0;
				cid_table[t][i].mode   = 0;
				break;
			}
	}
}

static void del_handle(uint16_t handle)
{
	register int t, i;

	for (t = 0; t < 2; t++) {
		for (i = 0; i < CID_TABLE_SIZE; i++)
			if (cid_table[t][i].handle == handle) {
				cid_table[t][i].handle = 0;
				cid_table[t][i].cid    = 0;
				cid_table[t][i].psm    = 0;
				cid_table[t][i].num    = 0;
				cid_table[t][i].mode   = 0;
				break;
			}
	}
}
static uint16_t get_psm(int in, uint16_t cid)
{
	register cid_info *table = cid_table[in];
	register int i;

	for (i = 0; i < CID_TABLE_SIZE; i++)
		if (table[i].cid == cid)
			return table[i].psm;
	return parser.defpsm;
}

static uint16_t get_num(int in, uint16_t cid)
{
	register cid_info *table = cid_table[in];
	register int i;

	for (i = 0; i < CID_TABLE_SIZE; i++)
		if (table[i].cid == cid)
			return table[i].num;
	return 0;
}

static void set_mode(int in, uint16_t cid, uint8_t mode)
{
	register cid_info *table = cid_table[in];
	register int i;

	for (i = 0; i < CID_TABLE_SIZE; i++)
		if (table[i].cid == cid)
			table[i].mode = mode;
}

static uint8_t get_mode(int in, uint16_t cid)
{
	register cid_info *table = cid_table[in];
	register int i;

	for (i = 0; i < CID_TABLE_SIZE; i++)
		if (table[i].cid == cid)
			return table[i].mode;
	return 0;
}

static uint32_t get_val(uint8_t *ptr, uint8_t len)
{
	switch (len) {
	case 1:
		return *ptr;
	case 2:
		return btohs(bt_get_unaligned((uint16_t *) ptr));
	case 4:
		return btohl(bt_get_unaligned((uint32_t *) ptr));
	}
	return 0;
}

static char *reason2str(uint16_t reason)
{
	switch (reason) {
	case 0x0000:
		return "Command not understood";
	case 0x0001:
		return "Signalling MTU exceeded";
	case 0x0002:
		return "Invalid CID in request";
	default:
		return "Reserved";
	}
}

static char *connresult2str(uint16_t result)
{
	switch (result) {
	case 0x0000:
		return "Connection successful";
	case 0x0001:
		return "Connection pending";
	case 0x0002:
		return "Connection refused - PSM not supported";
	case 0x0003:
		return "Connection refused - security block";
	case 0x0004:
		return "Connection refused - no resources available";
	default:
		return "Reserved";
	}
}

static char *status2str(uint16_t status)
{
	switch (status) {
	case 0x0000:
		return "No futher information available";
	case 0x0001:
		return "Authentication pending";
	case 0x0002:
		return "Authorization pending";
	default:
		return "Reserved";
	}
}

static char *confresult2str(uint16_t result)
{
	switch (result) {
	case 0x0000:
		return "Success";
	case 0x0001:
		return "Failure - unacceptable parameters";
	case 0x0002:
		return "Failure - rejected (no reason provided)";
	case 0x0003:
		return "Failure - unknown options";
	default:
		return "Reserved";
	}
}
static char *inforesult2str(uint16_t result)
{
	switch (result) {
	case 0x0000:
		return "Success";
	case 0x0001:
		return "Not supported";
	default:
		return "Reserved";
	}
}

static char *type2str(uint8_t type)
{
	switch (type) {
	case 0x00:
		return "No traffic";
	case 0x01:
		return "Best effort";
	case 0x02:
		return "Guaranteed";
	default:
		return "Reserved";
	}
}

static char *mode2str(uint8_t mode)
{
	switch (mode) {
	case 0x00:
		return "Basic";
	case 0x01:
		return "Retransmission";
	case 0x02:
		return "Flow control";
	default:
		return "Reserved";
	}
}

static char *sar2str(uint8_t sar)
{
	switch (sar) {
	case 0x00:
		return "Unsegmented";
	case 0x01:
		return "Start";
	case 0x02:
		return "End";
	case 0x03:
		return "Continuation";
	default:
		return "Bad SAR";

	}
}

static char *supervisory2str(uint8_t supervisory)
{
	switch (supervisory) {
	case 0x00:
		return "Receiver Ready (RR)";
	case 0x01:
		return "Reject (REJ)";
	case 0x02:
	case 0x03:
		return "Reserved Supervisory";
	default:
		return "Bad Supervisory";
	}
}

static inline void command_rej(int level, struct frame *frm)
{
	l2cap_cmd_rej *h = frm->ptr;
	uint16_t reason = btohs(h->reason);
	uint32_t cid;

	printf("Command rej: reason %d", reason);

	switch (reason) {
	case 0x0001:
		printf(" mtu %d\n", get_val(frm->ptr + L2CAP_CMD_REJ_SIZE, 2));
		break;
	case 0x0002:
		cid = get_val(frm->ptr + L2CAP_CMD_REJ_SIZE, 4);
		printf(" dcid 0x%4.4x scid 0x%4.4x\n", cid & 0xffff, cid >> 16);
		break;
	default:
		printf("\n");
		break;
	}

	p_indent(level + 1, frm);
	printf("%s\n", reason2str(reason));
}

static inline void conn_req(int level, struct frame *frm)
{
	l2cap_conn_req *h = frm->ptr;
	uint16_t psm = btohs(h->psm);
	uint16_t scid = btohs(h->scid);

	add_cid(frm->in, frm->handle, scid, psm);

	if (p_filter(FILT_L2CAP))
		return;

	printf("Connect req: psm %d scid 0x%4.4x\n", psm, scid);
}

static inline void conn_rsp(int level, struct frame *frm)
{
	l2cap_conn_rsp *h = frm->ptr;
	uint16_t scid = btohs(h->scid);
	uint16_t dcid = btohs(h->dcid);
	uint16_t result = btohs(h->result);
	uint16_t status = btohs(h->status);
	uint16_t psm;

	switch (h->result) {
	case L2CAP_CR_SUCCESS:
		if ((psm = get_psm(!frm->in, scid)))
			add_cid(frm->in, frm->handle, dcid, psm);
		break;

	case L2CAP_CR_PEND:
		break;

	default:
		del_cid(frm->in, dcid, scid);
		break;
	}

	if (p_filter(FILT_L2CAP))
		return;

	printf("Connect rsp: dcid 0x%4.4x scid 0x%4.4x result %d status %d\n",
		dcid, scid, result, status);

	p_indent(level + 1, frm);
	printf("%s", connresult2str(result));

	if (result == 0x0001)
		printf(" - %s\n", status2str(status));
	else
		printf("\n");
}

static void conf_rfc(void *ptr, int len, int in, uint16_t cid)
{
	uint8_t mode;

	mode = *((uint8_t *) ptr);
	set_mode(in, cid, mode);

	printf("RFC 0x%02x (%s", mode, mode2str(mode));
	if (mode == 0x01 || mode == 0x02) {
		uint8_t txwin, maxtrans;
		uint16_t rto, mto, mps;
		txwin = *((uint8_t *) (ptr + 1));
		maxtrans = *((uint8_t *) (ptr + 2));
		rto = btohs(bt_get_unaligned((uint16_t *) (ptr + 3)));
		mto = btohs(bt_get_unaligned((uint16_t *) (ptr + 5)));
		mps = btohs(bt_get_unaligned((uint16_t *) (ptr + 7)));
		printf(", TxWin %d, MaxTx %d, RTo %d, MTo %d, MPS %d",
					txwin, maxtrans, rto, mto, mps);
	}
	printf(")");
}

static void conf_opt(int level, void *ptr, int len, int in, uint16_t cid)
{
	p_indent(level, 0);
	while (len > 0) {
		l2cap_conf_opt *h = ptr;

		ptr += L2CAP_CONF_OPT_SIZE + h->len;
		len -= L2CAP_CONF_OPT_SIZE + h->len;

		if (h->type & 0x80)
			printf("[");

		switch (h->type & 0x7f) {
		case L2CAP_CONF_MTU:
			set_mode(in, cid, 0x00);
			printf("MTU");
			if (h->len > 0)
				printf(" %d", get_val(h->val, h->len));
			break;

		case L2CAP_CONF_FLUSH_TO:
			printf("FlushTO");
			if (h->len > 0)
				printf(" %d", get_val(h->val, h->len));
			break;

		case L2CAP_CONF_QOS:
			printf("QoS");
			if (h->len > 0)
				printf(" 0x%02x (%s)", *(h->val + 1), type2str(*(h->val + 1)));
			break;

		case L2CAP_CONF_RFC:
			conf_rfc(h->val, h->len, in, cid);
			break;

		default:
			printf("Unknown (type %2.2x, len %d)", h->type & 0x7f, h->len);
			break;
		}

		if (h->type & 0x80)
			printf("] ");
		else
			printf(" ");
	}
	printf("\n");
}

static void conf_list(int level, uint8_t *list, int len)
{
	int i;

	p_indent(level, 0);
	for (i = 0; i < len; i++) {
		switch (list[i] & 0x7f) {
		case L2CAP_CONF_MTU:
			printf("MTU ");
			break;
		case L2CAP_CONF_FLUSH_TO:
			printf("FlushTo ");
			break;
		case L2CAP_CONF_QOS:
			printf("QoS ");
			break;
		case L2CAP_CONF_RFC:
			printf("RFC ");
			break;
		default:
			printf("%2.2x ", list[i] & 0x7f);
			break;
		}
	}
	printf("\n");
}

static inline void conf_req(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	l2cap_conf_req *h = frm->ptr;
	uint16_t dcid = btohs(h->dcid);
	int clen = btohs(cmd->len) - L2CAP_CONF_REQ_SIZE;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Config req: dcid 0x%4.4x flags 0x%2.2x clen %d\n",
			dcid, btohs(h->flags), clen);

	if (clen > 0)
		conf_opt(level + 1, h->data, clen, frm->in, dcid);
}

static inline void conf_rsp(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	l2cap_conf_rsp *h = frm->ptr;
	uint16_t scid = btohs(h->scid);
	uint16_t result = btohs(h->result);
	int clen = btohs(cmd->len) - L2CAP_CONF_RSP_SIZE;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Config rsp: scid 0x%4.4x flags 0x%2.2x result %d clen %d\n",
			scid, btohs(h->flags), result, clen);

	if (clen > 0) {
		if (result) {
			p_indent(level + 1, frm);
			printf("%s\n", confresult2str(result));
		}
		if (result == 0x0003)
			conf_list(level + 1, h->data, clen);
		else
			conf_opt(level + 1, h->data, clen, frm->in, scid);
	} else {
		p_indent(level + 1, frm);
		printf("%s\n", confresult2str(result));
	}
}

static inline void disconn_req(int level, struct frame *frm)
{
	l2cap_disconn_req *h = frm->ptr;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Disconn req: dcid 0x%4.4x scid 0x%4.4x\n",
			btohs(h->dcid), btohs(h->scid));
}

static inline void disconn_rsp(int level, struct frame *frm)
{
	l2cap_disconn_rsp *h = frm->ptr;
	uint16_t dcid = btohs(h->dcid);
	uint16_t scid = btohs(h->scid);

	del_cid(frm->in, dcid, scid);

	if (p_filter(FILT_L2CAP))
		return;

	printf("Disconn rsp: dcid 0x%4.4x scid 0x%4.4x\n",
			btohs(h->dcid), btohs(h->scid));
}

static inline void echo_req(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Echo req: dlen %d\n", btohs(cmd->len));
	raw_dump(level, frm);
}

static inline void echo_rsp(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Echo rsp: dlen %d\n", btohs(cmd->len));
	raw_dump(level, frm);
}

static void info_opt(int level, int type, void *ptr, int len)
{
	uint32_t mask;

	p_indent(level, 0);

	switch (type) {
	case 0x0001:
		printf("Connectionless MTU %d\n", get_val(ptr, len));
		break;
	case 0x0002:
		mask = get_val(ptr, len);
		printf("Extended feature mask 0x%4.4x\n", mask);
		if (parser.flags & DUMP_VERBOSE) {
			if (mask & 0x01) {
				p_indent(level + 1, 0);
				printf("Flow control mode\n");
			}
			if (mask & 0x02) {
				p_indent(level + 1, 0);
				printf("Retransmission mode\n");
			}
			if (mask & 0x04) {
				p_indent(level + 1, 0);
				printf("Bi-directional QoS\n");
			}
		}
		break;
	default:
		printf("Unknown (len %d)\n", len);
		break;
	}
}

static inline void info_req(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	l2cap_info_req *h = frm->ptr;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Info req: type %d\n", btohs(h->type));
}

static inline void info_rsp(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	l2cap_info_rsp *h = frm->ptr;
	uint16_t type = btohs(h->type);
	uint16_t result = btohs(h->result);
	int ilen = btohs(cmd->len) - L2CAP_INFO_RSP_SIZE;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Info rsp: type %d result %d\n", type, result);

	if (ilen > 0) {
		info_opt(level + 1, type, h->data, ilen);
	} else {
		p_indent(level + 1, frm);
		printf("%s\n", inforesult2str(result));
	}
}

static void l2cap_parse(int level, struct frame *frm)
{
	l2cap_hdr *hdr = (void *)frm->ptr;
	uint16_t dlen = btohs(hdr->len);
	uint16_t cid  = btohs(hdr->cid);
	uint16_t psm;

	frm->ptr += L2CAP_HDR_SIZE;
	frm->len -= L2CAP_HDR_SIZE;

	if (cid == 0x1) {
		/* Signaling channel */

		while (frm->len >= L2CAP_CMD_HDR_SIZE) {
			l2cap_cmd_hdr *hdr = frm->ptr;

			frm->ptr += L2CAP_CMD_HDR_SIZE;
			frm->len -= L2CAP_CMD_HDR_SIZE;

			if (!p_filter(FILT_L2CAP)) {
				p_indent(level, frm);
				printf("L2CAP(s): ");
			}

			switch (hdr->code) {
			case L2CAP_COMMAND_REJ:
				command_rej(level, frm);
				break;
			
			case L2CAP_CONN_REQ:
				conn_req(level, frm);
				break;
	
			case L2CAP_CONN_RSP:
				conn_rsp(level, frm);
				break;

			case L2CAP_CONF_REQ:
				conf_req(level, hdr, frm);
				break;

			case L2CAP_CONF_RSP:
				conf_rsp(level, hdr, frm);
				break;

			case L2CAP_DISCONN_REQ:
				disconn_req(level, frm);
				break;

			case L2CAP_DISCONN_RSP:
				disconn_rsp(level, frm);
				break;
	
			case L2CAP_ECHO_REQ:
				echo_req(level, hdr, frm);
				break;

			case L2CAP_ECHO_RSP:
				echo_rsp(level, hdr, frm);
				break;

			case L2CAP_INFO_REQ:
				info_req(level, hdr, frm);
				break;

			case L2CAP_INFO_RSP:
				info_rsp(level, hdr, frm);
				break;

			default:
				if (p_filter(FILT_L2CAP))
					break;
				printf("code 0x%2.2x ident %d len %d\n", 
					hdr->code, hdr->ident, btohs(hdr->len));
				raw_dump(level, frm);
			}

			if (frm->len > btohs(hdr->len)) {
				frm->len -= btohs(hdr->len);
				frm->ptr += btohs(hdr->len);
			} else
				frm->len = 0;
		}
	} else if (cid == 0x2) {
		/* Connectionless channel */

		if (p_filter(FILT_L2CAP))
			return;

		psm = btohs(bt_get_unaligned((uint16_t *) frm->ptr));
		frm->ptr += 2;
		frm->len -= 2;

		p_indent(level, frm);
		printf("L2CAP(c): len %d psm %d\n", dlen, psm);
		raw_dump(level, frm);
	} else {
		/* Connection oriented channel */

		uint8_t mode = get_mode(!frm->in, cid);
		uint16_t psm = get_psm(!frm->in, cid);
		uint16_t ctrl = 0, fcs = 0;
		uint32_t proto;

		frm->cid = cid;
		frm->num = get_num(!frm->in, cid);

		if (mode > 0) {
			ctrl = btohs(bt_get_unaligned((uint16_t *) frm->ptr));
			frm->ptr += 2;
			frm->len -= 4;
			fcs = btohs(bt_get_unaligned((uint16_t *) (frm->ptr + frm->len)));
		}

		if (!p_filter(FILT_L2CAP)) {
			p_indent(level, frm);
			printf("L2CAP(d): cid 0x%4.4x len %d", cid, dlen);
			if (mode > 0)
				printf(" ctrl 0x%4.4x fcs 0x%4.4x", ctrl, fcs);
			printf(" [psm %d]\n", psm);
			level++;
			if (mode > 0) {
				p_indent(level, frm);
				printf("%s:", ctrl & 0x01 ? "S-frame" : "I-frame");
				if (ctrl & 0x01) {
					printf(" %s", supervisory2str((ctrl & 0x0c) >> 2));
				} else {
					uint8_t sar = (ctrl & 0xc000) >> 14;
					printf(" %s", sar2str(sar));
					if (sar == 1) {
						uint16_t len;
						len = btohs(bt_get_unaligned((uint16_t *) frm->ptr));
						frm->ptr += 2;
						frm->len -= 2;
						printf(" (len %d)", len);
					}
					printf(" TxSeq %d", (ctrl & 0x7e) >> 1);
				}
				printf(" ReqSeq %d", (ctrl & 0x3f00) >> 8);
				if (ctrl & 0x80)
					printf(" Retransmission Disable");
				printf("\n");
			}
		}

		switch (psm) {
		case 0x01:
			if (!p_filter(FILT_SDP))
				sdp_dump(level + 1, frm);
			else
				raw_dump(level + 1, frm);
			break;

		case 0x03:
			if (!p_filter(FILT_RFCOMM))
				rfcomm_dump(level, frm);
			else
				raw_dump(level + 1, frm);
			break;

		case 0x0f:
			if (!p_filter(FILT_BNEP))
				bnep_dump(level, frm);
			else
				raw_dump(level + 1, frm);
			break;

		case 0x11:
		case 0x13:
			if (!p_filter(FILT_HIDP))
				hidp_dump(level, frm);
			else
				raw_dump(level + 1, frm);
			break;

		case 0x17:
			if (!p_filter(FILT_AVCTP))
				avctp_dump(level, frm);
			else
				raw_dump(level + 1, frm);
			break;

		case 0x19:
			if (!p_filter(FILT_AVDTP))
				avdtp_dump(level, frm);
			else
				raw_dump(level + 1, frm);
			break;

		default:
			proto = get_proto(frm->handle, psm, 0);

			switch (proto) {
			case SDP_UUID_CMTP:
				if (!p_filter(FILT_CMTP))
					cmtp_dump(level, frm);
				else
					raw_dump(level + 1, frm);
				break;

			case SDP_UUID_HARDCOPY_CONTROL_CHANNEL:
				if (!p_filter(FILT_HCRP))
					hcrp_dump(level, frm);
				else
					raw_dump(level + 1, frm);
				break;

			default:
				if (p_filter(FILT_L2CAP))
					break;

				raw_dump(level, frm);
				break;
			}
			break;
		}
	}
}

void l2cap_dump(int level, struct frame *frm)
{
	struct frame *fr;
	l2cap_hdr *hdr;
	uint16_t dlen;

	if (frm->flags & ACL_START) {
		hdr  = frm->ptr;
		dlen = btohs(hdr->len);

		if (frm->len == (dlen + L2CAP_HDR_SIZE)) {
			/* Complete frame */
			l2cap_parse(level, frm);
			return;
		}

		if (!(fr = get_frame(frm->handle))) {
			fprintf(stderr, "Not enough connection handles\n");
			raw_dump(level, frm);
			return;
		}

		if (fr->data)
			free(fr->data);

		if (!(fr->data = malloc(dlen + L2CAP_HDR_SIZE))) {
			perror("Can't allocate L2CAP reassembly buffer");
			return;
		}
		memcpy(fr->data, frm->ptr, frm->len);
		fr->data_len   = dlen + L2CAP_HDR_SIZE;
		fr->len        = frm->len;
		fr->ptr        = fr->data;
		fr->dev_id     = frm->dev_id;
		fr->in         = frm->in;
		fr->ts         = frm->ts;
		fr->handle     = frm->handle;
		fr->cid        = frm->cid;
		fr->num        = frm->num;
		fr->dlci       = frm->dlci;
		fr->channel    = frm->channel;
		fr->pppdump_fd = frm->pppdump_fd;
		fr->audio_fd   = frm->audio_fd;
	} else {
		if (!(fr = get_frame(frm->handle))) {
			fprintf(stderr, "Not enough connection handles\n");
			raw_dump(level, frm);
			return;
		}

		if (!fr->data) {
			/* Unexpected fragment */
			raw_dump(level, frm);
			return;
		}

		if (frm->len > (fr->data_len - fr->len)) {
			/* Bad fragment */
			raw_dump(level, frm);
			free(fr->data); fr->data = NULL;
			return;
		}

		memcpy(fr->data + fr->len, frm->ptr, frm->len);
		fr->len += frm->len;

		if (fr->len == fr->data_len) {
			/* Complete frame */
			l2cap_parse(level, fr);

			free(fr->data); fr->data = NULL;
			return;
		}
	}
}

void l2cap_clear(uint16_t handle)
{
	del_handle(handle);
}
