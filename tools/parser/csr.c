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
	uint8_t desc, cid;

	desc = get_u8(frm);

	cid = desc & 0x3f;

	p_indent(level, frm);

	printf("CSR: %s (channel %d)%s\n", cid2str(cid), cid, frag2str(desc));

	raw_dump(level, frm);
}
