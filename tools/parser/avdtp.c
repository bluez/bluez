/*
 *
 *  Bluetooth packet analyzer - AVDTP parser
 *
 *  Copyright (C) 2004  Marcel Holtmann <marcel@holtmann.org>
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


static char *si2str(uint8_t si)
{
	switch (si & 0x7f) {
	case 0x01:
		return "Discover";
	case 0x02:
		return "Capabilities";
	case 0x03:
		return "Set config";
	case 0x04:
		return "Get config";
	case 0x05:
		return "Reconfigure";
	case 0x06:
		return "Open";
	case 0x07:
		return "Start";
	case 0x08:
		return "Close";
	case 0x09:
		return "Suspend";
	case 0x0a:
		return "Abort";
	case 0x0b:
		return "Security";
	default:
		return "Unknown";
	}
}

static char *pt2str(uint8_t hdr)
{
	switch (hdr & 0x0c) {
	case 0x00:
		return "Single";
	case 0x04:
		return "Start";
	case 0x08:
		return "Cont";
	case 0x0c:
		return "End";
	default:
		return "Unk";
	}
}

static char *mt2str(uint8_t hdr)
{
	switch (hdr & 0x03) {
	case 0x00:
		return "cmd";
	case 0x08:
		return "rsp";
	case 0x0c:
		return "rej";
	default:
		return "rfa";
	}
}

void avdtp_dump(int level, struct frame *frm)
{
	uint8_t hdr, sid = 0xff, nsp;

	hdr = get_u8(frm);

	nsp = (hdr & 0x0c) == 0x04 ? get_u8(frm) : 0;
	sid = hdr & 0x08 ? 0x00 : get_u8(frm);

	p_indent(level, frm);

	printf("AVDTP(s): %s %s: transaction %d\n",
		sid & 0x08 ? pt2str(hdr) : si2str(sid), mt2str(hdr), hdr >> 8);

	raw_dump(level, frm);
}
