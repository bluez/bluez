/*
 *
 *  Bluetooth packet analyzer - L2CAP parser
 *
 *  Copyright (C) 2000-2002  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2003-2004  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  $Id$
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
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
	uint16_t cid;
	uint16_t psm;
	uint16_t num;
} cid_info;
#define CID_TABLE_SIZE 20

static cid_info cid_table[2][CID_TABLE_SIZE];

#define SCID cid_table[0]
#define DCID cid_table[1]

typedef struct {
	uint16_t psm;
	uint16_t num;
} psm_info;
#define PSM_TABLE_SIZE 20

static psm_info psm_table[PSM_TABLE_SIZE];

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

static void add_cid(int in, uint16_t cid, uint16_t psm)
{
	register cid_info *table = cid_table[in];
	register int i, pos = -1;
	uint16_t num = 1;

	if (in) {
		for (i = 0; i < PSM_TABLE_SIZE; i++)
			if (psm_table[i].psm == psm)
				num = psm_table[i].num;
	} else {
		for (i = 0; i < PSM_TABLE_SIZE; i++) {
			if (psm_table[i].psm == psm) {
				pos = i;
				break;
			} else if (pos < 0 && !psm_table[i].psm)
				pos = i;
		}

		if (pos >= 0) {
			psm_table[pos].psm = psm;
			psm_table[pos].num++;
			num = psm_table[pos].num;
		}
	}

	for (i = 0; i < CID_TABLE_SIZE; i++)
		if (!table[i].cid || table[i].cid == cid) {
			table[i].cid = cid;
			table[i].psm = psm;
			table[i].num = num;
			break;
		}
}

static void del_cid(int in, uint16_t dcid, uint16_t scid)
{
	register int t, i;
	uint16_t cid[2], psm = 0;

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
				psm = cid_table[t][i].psm;
				cid_table[t][i].cid = 0;
				break;
			}
	}

	for (i = 0; i < PSM_TABLE_SIZE; i++)
		if (psm_table[i].psm == psm) {
			if (psm_table[i].num < 2) {
				psm_table[i].psm = 0;
				psm_table[i].num = 0;
			} else
				psm_table[i].num--;
			break;
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

static inline void command_rej(int level, struct frame *frm)
{
	l2cap_cmd_rej *h = frm->ptr;

	printf("Command rej: reason %d\n", btohs(h->reason));
}

static inline void conn_req(int level, struct frame *frm)
{
	l2cap_conn_req *h = frm->ptr;

	add_cid(frm->in, btohs(h->scid), btohs(h->psm));

	if (p_filter(FILT_L2CAP))
		return;

	printf("Connect req: psm %d scid 0x%4.4x\n",
				btohs(h->psm), btohs(h->scid));
}

static inline void conn_rsp(int level, struct frame *frm)
{
	l2cap_conn_rsp *h = frm->ptr;
	uint16_t psm;

	if ((psm = get_psm(!frm->in, btohs(h->scid))))
		add_cid(frm->in, btohs(h->dcid), psm);

	if (p_filter(FILT_L2CAP))
		return;

	printf("Connect rsp: dcid 0x%4.4x scid 0x%4.4x result %d status %d\n",
				btohs(h->dcid), btohs(h->scid),
				btohs(h->result), btohs(h->status));
}

static void conf_opt(int level, void *ptr, int len)
{
	p_indent(level, 0);
	while (len > 0) {
		l2cap_conf_opt *h = ptr;

		ptr += L2CAP_CONF_OPT_SIZE + h->len;
		len -= L2CAP_CONF_OPT_SIZE + h->len;

		switch (h->type) {
		case L2CAP_CONF_MTU:
			printf("MTU ");
			if (h->len > 0)
				printf("%d ", get_val(h->val, h->len));
			break;
		case L2CAP_CONF_FLUSH_TO:
			printf("FlushTO ");
			if (h->len > 0)
				printf("%d ", get_val(h->val, h->len));
			break;
		case L2CAP_CONF_RFC_MODE:
			printf("Mode ");
			if (h->len > 0)
				printf("%d (%s) ", *h->val, mode2str(*h->val));
			break;
		default:
			printf("Unknown (type %2.2x, len %d) ", h->type, h->len);
			break;
		}
	}
	printf("\n");
}

static inline void conf_req(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	l2cap_conf_req *h = frm->ptr;
	int clen = btohs(cmd->len) - L2CAP_CONF_REQ_SIZE;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Config req: dcid 0x%4.4x flags 0x%4.4x clen %d\n",
			btohs(h->dcid), btohs(h->flags), clen);
	if (clen)
		conf_opt(level, h->data, clen);
}

static inline void conf_rsp(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	l2cap_conf_rsp *h = frm->ptr;
	int clen = btohs(cmd->len) - L2CAP_CONF_RSP_SIZE;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Config rsp: scid 0x%4.4x flags 0x%4.4x result %d clen %d\n",
			btohs(h->scid), btohs(h->flags), btohs(h->result), clen);
	if (clen)
		conf_opt(level, h->data, clen);
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
	del_cid(frm->in, btohs(h->dcid), btohs(h->scid));

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
	p_indent(level, 0);
	switch (type) {
	case 0x0001:
		printf("Connectionless MTU %d\n", get_val(ptr, len));
		break;
	case 0x0002:
		printf("Extended feature mask 0x%4.4x\n", get_val(ptr, len));
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
	int ilen = btohs(cmd->len) - L2CAP_INFO_RSP_SIZE;

	if (p_filter(FILT_L2CAP))
		return;

	printf("Info rsp: type %d result %d\n", btohs(h->type), btohs(h->result));
	if (ilen)
		info_opt(level, btohs(h->type), h->data, ilen);
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
			frm->ptr += btohs(hdr->len);
			frm->len -= btohs(hdr->len);
		}
	} else if (cid == 0x2) {
		/* Connectionless channel */

		if (p_filter(FILT_L2CAP))
			return;

		psm = btohs(bt_get_unaligned((uint16_t*)frm->ptr));
		frm->len -= 2;

		p_indent(level, frm);
		printf("L2CAP(c): len %d psm %d\n", dlen, psm);
		raw_dump(level, frm);
	} else {
		/* Connection oriented channel */

		uint16_t psm = get_psm(!frm->in, cid);
		uint32_t proto;

		frm->cid = cid;
		frm->num = get_num(!frm->in, cid);

		if (!p_filter(FILT_L2CAP)) {
			p_indent(level, frm);
			printf("L2CAP(d): cid 0x%4.4x len %d [psm %d]\n",
				cid, dlen, psm);
			level++;
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

		if (fr->data) free(fr->data);

		if (!(fr->data = malloc(dlen + L2CAP_HDR_SIZE))) {
			perror("Can't allocate L2CAP reassembly buffer");
			return;
		}
		memcpy(fr->data, frm->ptr, frm->len);
		fr->data_len = dlen + L2CAP_HDR_SIZE;
		fr->len = frm->len;
		fr->ptr = fr->data;
		fr->in  = frm->in;
		fr->ts  = frm->ts;
		fr->handle  = frm->handle;
		fr->cid     = frm->cid;
		fr->num     = frm->num;
		fr->channel = frm->channel;
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
