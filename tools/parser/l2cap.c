/* 
	HCIDump - HCI packet analyzer	
	Copyright (C) 2000-2001 Maxim Krasnyansky <maxk@qualcomm.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License version 2 as
	published by the Free Software Foundation;

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
	OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS.
	IN NO EVENT SHALL THE COPYRIGHT HOLDER(S) AND AUTHOR(S) BE LIABLE FOR ANY CLAIM,
	OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER
	RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
	NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
	USE OR PERFORMANCE OF THIS SOFTWARE.

	ALL LIABILITY, INCLUDING LIABILITY FOR INFRINGEMENT OF ANY PATENTS, COPYRIGHTS,
	TRADEMARKS OR OTHER RIGHTS, RELATING TO USE OF THIS SOFTWARE IS DISCLAIMED.
*/

/*
 * $Id$
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#include "parser.h"

typedef struct {
	uint16_t handle;
	struct frame frm;
} handle_info;
#define HANDLE_TABLE_SIZE 10

static handle_info handle_table[HANDLE_TABLE_SIZE];

typedef struct {
	uint16_t cid;
	uint16_t psm;
} cid_info;
#define CID_TABLE_SIZE	20

static cid_info cid_table[2][CID_TABLE_SIZE];

#define SCID cid_table[0]
#define DCID cid_table[1]

static struct frame * add_handle(uint16_t handle)
{
	register handle_info *t = handle_table;
	register int i;

	for (i=0; i<HANDLE_TABLE_SIZE; i++)
		if (!t[i].handle) {
			t[i].handle = handle;
			return &t[i].frm;
		}
	return NULL;
}

static struct frame * get_frame(uint16_t handle)
{
	register handle_info *t = handle_table;
	register int i;

	for (i=0; i<HANDLE_TABLE_SIZE; i++)
		if (t[i].handle == handle)
			return &t[i].frm;

	return add_handle(handle);
}

static void add_cid(int in, uint16_t cid, uint16_t psm)
{
	register cid_info *table = cid_table[in];
	register int i;

	for (i=0; i<CID_TABLE_SIZE; i++)
		if (!table[i].cid || table[i].cid == cid) {
			table[i].cid = cid;
			table[i].psm = psm;
			break;
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

	for (t=0; t<2; t++) {	
		for (i=0; i<CID_TABLE_SIZE; i++)
			if (cid_table[t][i].cid == cid[t]) {
				cid_table[t][i].cid = 0;
				break;
			}
	}
}

static uint16_t get_psm(int in, uint16_t cid)
{
	register cid_info *table = cid_table[in];
	register int i;
	
	for (i=0; i<CID_TABLE_SIZE; i++)
		if (table[i].cid == cid)
			return table[i].psm;
	return parser.defpsm;
}

static inline void command_rej(int level, struct frame *frm)
{
	l2cap_cmd_rej *h = frm->ptr;

	printf("Command rej: reason %d\n", 
			btohs(h->reason));
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

static uint32_t conf_opt_val(uint8_t *ptr, uint8_t len)
{
	switch (len) {
	case 1:
		return *ptr;

        case 2:
                return btohs(*(uint16_t *)ptr);

        case 4:
                return btohl(*(uint32_t *)ptr);
	}
	return 0;
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
			printf("MTU %d ", conf_opt_val(h->val, h->len));
			break;
		case L2CAP_CONF_FLUSH_TO:
			printf("FlushTO %d ", conf_opt_val(h->val, h->len));
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

	printf("Echo req: dlen %d\n", 
			btohs(cmd->len));
	raw_dump(level, frm);
}

static inline void echo_rsp(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Echo rsp: dlen %d\n", 
			btohs(cmd->len));
	raw_dump(level, frm);
}

static inline void info_req(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Info req: dlen %d\n", 
			btohs(cmd->len));
	raw_dump(level, frm);
}

static inline void info_rsp(int level, l2cap_cmd_hdr *cmd, struct frame *frm)
{
	if (p_filter(FILT_L2CAP))
		return;

	printf("Info rsp: dlen %d\n", 
			btohs(cmd->len));
	raw_dump(level, frm);
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

		psm = btohs(*(uint16_t*)frm->ptr);
		frm->len -= 2;

		p_indent(level, frm);
		printf("L2CAP(c): cid 0x%x len %d psm %d\n", cid, dlen, psm);
		raw_dump(level, frm);
	} else {
		/* Connection oriented channel */
		uint16_t psm = get_psm(!frm->in, cid);
	
		if (!p_filter(FILT_L2CAP)) {
			p_indent(level, frm);
			printf("L2CAP(d): cid 0x%x len %d [psm %d]\n", 
				cid, dlen, psm);
			level++;
		}

		switch (psm) {
		case 0x01:
			if (!p_filter(FILT_SDP))
				sdp_dump(level+1, frm);
			else
				raw_dump(level+1, frm);
			break;

		case 0x03:
			if (!p_filter(FILT_RFCOMM))
				rfcomm_dump(level, frm);
			else
				raw_dump(level+1, frm);
			break;

		case 0x0f:
			if (!p_filter(FILT_BNEP))
				bnep_dump(level, frm);
			else
				raw_dump(level+1, frm);
			break;

		case 4099:
			if (!p_filter(FILT_CMTP))
				cmtp_dump(level, frm);
			else
				raw_dump(level+1, frm);
			break;

		default:
			if (p_filter(FILT_L2CAP))
				break;

			raw_dump(level, frm);
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
			fprintf(stderr, "Not enough connetion handles\n");
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
	} else {
		if (!(fr = get_frame(frm->handle))) {
			fprintf(stderr, "Not enough connetion handles\n");
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
