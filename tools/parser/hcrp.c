/*
 *
 *  Bluetooth packet analyzer - HCRP parser
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


static char *pid2str(uint16_t pid)
{
	switch (pid) {
	case 0x0001:
		return "CreditGrant";
	case 0x0002:
		return "CreditRequest";
	case 0x0003:
		return "CreditReturn";
	case 0x0004:
		return "CreditQuery";
	case 0x0005:
		return "GetLPTStatus";
	case 0x0006:
		return "Get1284ID";
	case 0x0007:
		return "SoftReset";
	case 0x0008:
		return "HardRest";
	case 0x0009:
		return "RegisterNotification";
	case 0x000A:
		return "NotificationConnectionAlive";
	default:
		return "Reserved";
	}
}

static char *status2str(uint16_t status)
{
	switch (status) {
	case 0x0000:
		return "Feature unsupported";
	case 0x0001:
		return "Success";
	case 0x0002:
		return "Credit synchronization error";
	case 0xFFFF:
		return "Generic error";
	default:
		return "Unknown";
	}
}

void hcrp_dump(int level, struct frame *frm)
{
	uint16_t pid, tid, plen, status;
	uint32_t credits;

	pid = get_u16(frm);
	tid = get_u16(frm);
	plen = get_u16(frm);

	p_indent(level, frm);

	printf("HCRP %s %s: tid 0x%x plen %d",
			pid2str(pid), frm->in ? "rsp" : "cmd",  tid, plen);

	if (frm->in) {
		status = get_u16(frm);
		printf(" status %d (%s)\n", status, status2str(status));
	} else
		printf("\n");

	if (pid == 0x0001 && !frm->in) {
		credits = get_u32(frm);
		p_indent(level + 1, frm);
		printf("credits %d\n", credits);
	}

	if (pid == 0x0002 && frm->in) {
		credits = get_u32(frm);
		p_indent(level + 1, frm);
		printf("credits %d\n", credits);
	}

	raw_dump(level + 1, frm);
}
