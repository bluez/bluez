/*
 *
 *  Bluetooth packet analyzer - CSR parser
 *
 *  Copyright (C) 2004-2005  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>

#include "parser.h"

#define CSR_U8(frm)  (get_u8(frm))
#define CSR_U16(frm) (btohs(htons(get_u16(frm))))
#define CSR_U32(frm) (btohl(htonl(get_u32(frm))))

static char *type2str(uint16_t type)
{
	switch (type) {
	case 0x0000:
		return "Get req";
	case 0x0001:
		return "Get rsp";
	case 0x0002:
		return "Set req";
	default:
		return "Reserved";
	}
}

static inline void bccmd_dump(int level, struct frame *frm)
{
	uint16_t type, length, seqno, varid, status;

	type   = CSR_U16(frm);
	length = CSR_U16(frm);
	seqno  = CSR_U16(frm);
	varid  = CSR_U16(frm);
	status = CSR_U16(frm);

	p_indent(level, frm);
	printf("BCCMD: %s: len %d seqno %d varid 0x%4.4x status %d\n",
			type2str(type), length, seqno, varid, status);
}

static char *cid2str(uint8_t cid)
{
	switch (cid & 0x3f) {
	case 0:
		return "BCSP Internal";
	case 1:
		return "BCSP Link";
	case 2:
		return "BCCMD";
	case 3:
		return "HQ";
	case 4:
		return "Device Mgt";
	case 5:
		return "HCI Cmd/Evt";
	case 6:
		return "HCI ACL";
	case 7:
		return "HCI SCO";
	case 8:
		return "L2CAP";
	case 9:
		return "RFCOMM";
	case 10:
		return "SDP";
	case 11:
		return "Debug";
	case 12:
		return "DFU";
	case 13:
		return "VM";
	case 14:
		return "Unused";
	case 15:
		return "Reserved";
	default:
		return "Unknown";
	}
}

static char *frag2str(uint8_t frag)
{
	switch (frag & 0xc0) {
	case 0x00:
		return " middle fragment";
	case 0x40:
		return " first fragment";
	case 0x80:
		return " last fragment";
	default:
		return "";
	}
}

void csr_dump(int level, struct frame *frm)
{
	uint8_t desc, cid, type;
	uint16_t handle, master, addr;

	desc = CSR_U8(frm);

	cid = desc & 0x3f;

	switch (cid) {
	case 2:
		bccmd_dump(level, frm);
		level++;
		break;

	case 20:
		type = CSR_U8(frm);

		if (!p_filter(FILT_LMP)) {
			switch (type) {
			case 0x0f:
				frm->handle =  ((uint8_t *) frm->ptr)[17];
				frm->master = 0;
				frm->len--;
				lmp_dump(level, frm);
				return;
			case 0x10:
				frm->handle = ((uint8_t *) frm->ptr)[17];
				frm->master = 1;
				frm->len--;
				lmp_dump(level, frm);
				return;
			case 0x12:
				handle = CSR_U16(frm);
				master = CSR_U16(frm);
				addr = CSR_U16(frm);
				p_indent(level, frm);
				printf("FHS: handle %d addr %d (%s)\n", handle,
					addr, master ? "master" : "slave");
				if (!master)
					raw_dump(level, frm);
				return;
			case 0x7b:
				p_indent(level, frm);
				printf("LMP(r): duplicate (same SEQN)\n");
				return;
			}
		}

		p_indent(level, frm);
		printf("CSR: Debug (type 0x%2.2x)\n", type);
		break;

	default:
		p_indent(level, frm);
		printf("CSR: %s (channel %d)%s\n", cid2str(cid), cid, frag2str(desc));
		break;
	}

	raw_dump(level, frm);
}
