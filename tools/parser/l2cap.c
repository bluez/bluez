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

#include <sys/socket.h>
#include <sys/types.h>
#include <asm/types.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/l2cap.h>

#include "parser.h"

static inline void command_rej(int level, __u8 *ptr, int len)
{
	l2cap_cmd_rej *h = (void *) ptr;
	printf("Command rej: reason %d\n", 
			btohs(h->reason));
}

static inline void conn_req(int level, __u8 *ptr, int len)
{
	l2cap_conn_req *h = (void *) ptr;
	printf("Connect req: psm %d scid 0x%4.4x\n", 
			btohs(h->psm), btohs(h->scid));
}

static inline void conn_rsp(int level, __u8 *ptr, int len)
{
	l2cap_conn_rsp *h = (void *) ptr;
	printf("Connect rsp: dcid 0x%4.4x scid 0x%4.4x result %d status %d\n",
			btohs(h->dcid), btohs(h->scid),
			btohs(h->result), btohs(h->status));
}

static __u32 conf_opt_val(__u8 *ptr, __u8 len)
{
	switch (len) {
	case 1:
		return *ptr;

        case 2:
                return btohs(*(__u16 *)ptr);

        case 4:
                return btohl(*(__u32 *)ptr);
	}
	return 0;
}

static void conf_opt(int level, __u8 *ptr, int len)
{
	indent(level);
	while (len > 0) {
		l2cap_conf_opt *h = (void *) ptr;
	
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

static inline void conf_req(int level, l2cap_cmd_hdr *cmd, __u8 *ptr, int len)
{
	l2cap_conf_req *h = (void *) ptr;
	int clen = btohs(cmd->len) - L2CAP_CONF_REQ_SIZE;
	printf("Config req: dcid 0x%4.4x flags 0x%4.4x clen %d\n",
			btohs(h->dcid), btohs(h->flags), clen);
	if (clen)
		conf_opt(level+1, h->data, clen);
}

static inline void conf_rsp(int level, l2cap_cmd_hdr *cmd, __u8 *ptr, int len)
{
	l2cap_conf_rsp *h = (void *) ptr;
	int clen = btohs(cmd->len) - L2CAP_CONF_RSP_SIZE;
	printf("Config rsp: scid 0x%4.4x flags 0x%4.4x result %d clen %d\n",
			btohs(h->scid), btohs(h->flags), btohs(h->result), clen);
	if (clen)
		conf_opt(level+1, h->data, clen);
}

static inline void disconn_req(int level, __u8 *ptr, int len)
{
	l2cap_disconn_req *h = (void *) ptr;
	printf("Disconn req: dcid 0x%4.4x scid 0x%4.4x\n", 
			btohs(h->dcid), btohs(h->scid));
}

static inline void disconn_rsp(int level, __u8 *ptr, int len)
{
	l2cap_disconn_rsp *h = (void *) ptr;
	printf("Disconn rsp: dcid 0x%4.4x scid 0x%4.4x\n",
			btohs(h->dcid), btohs(h->scid));
}

static inline void echo_req(int level, l2cap_cmd_hdr *cmd, __u8 *ptr, int len)
{
	printf("Echo req: dlen %d\n", 
			btohs(cmd->len));
	raw_dump(level, ptr, len);
}

static inline void echo_rsp(int level, l2cap_cmd_hdr *cmd, __u8 *ptr, int len)
{
	printf("Echo rsp: dlen %d\n", 
			btohs(cmd->len));
	raw_dump(level, ptr, len);
}

static inline void info_req(int level, l2cap_cmd_hdr *cmd, __u8 *ptr, int len)
{
	printf("Info req: dlen %d\n", 
			btohs(cmd->len));
	raw_dump(level, ptr, len);
}

static inline void info_rsp(int level, l2cap_cmd_hdr *cmd, __u8 *ptr, int len)
{
	printf("Info rsp: dlen %d\n", 
			btohs(cmd->len));
	raw_dump(level, ptr, len);
}

void l2cap_dump(int level, __u8 *ptr, int len, __u8 flags)
{
	l2cap_hdr *hdr = (void *) ptr;
	__u16 dlen = btohs(hdr->len);
	__u16 cid  = btohs(hdr->cid);

	ptr += L2CAP_HDR_SIZE;
	len -= L2CAP_HDR_SIZE;

	indent(level); 
	if (cid == 0x1) {
		l2cap_cmd_hdr *hdr = (void *) ptr;

		ptr += L2CAP_CMD_HDR_SIZE;
		len -= L2CAP_CMD_HDR_SIZE;

		printf("L2CAP(s): "); 

		switch (hdr->code) {
		case L2CAP_COMMAND_REJ:
			command_rej(level, ptr, len);
			break;
			
		case L2CAP_CONN_REQ:
			conn_req(level, ptr, len);
			break;
	
		case L2CAP_CONN_RSP:
			conn_rsp(level, ptr, len);
			break;

		case L2CAP_CONF_REQ:
			conf_req(level, hdr, ptr, len);		
			break;

		case L2CAP_CONF_RSP:
			conf_rsp(level, hdr, ptr, len);
			break;

		case L2CAP_DISCONN_REQ:
			disconn_req(level, ptr, len);
			break;

		case L2CAP_DISCONN_RSP:
			disconn_rsp(level, ptr, len);
			break;
	
		case L2CAP_ECHO_REQ:
			echo_req(level, hdr, ptr, len);
			break;

		case L2CAP_ECHO_RSP:
			echo_rsp(level, hdr, ptr, len);	
			break;

		case L2CAP_INFO_REQ:
			info_req(level, hdr, ptr, len);
			break;

		case L2CAP_INFO_RSP:
			info_rsp(level, hdr, ptr, len);
			break;

		default:
			printf("code 0x%2.2x ident %d len %d\n", 
				hdr->code, hdr->ident, btohs(hdr->len));
			raw_dump(level, ptr, len);
		}		
	} else {
		printf("L2CAP(d): cid 0x%x len %d\n", cid, dlen);
		raw_dump(level, ptr, len);
	}
}
