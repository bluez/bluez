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
	HIDP parser.
	Copyright (C) 2003 Marcel Holtmann <marcel@holtmann.org>
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

#include "parser.h"

char *type2str(uint8_t head)
{
	switch (head & 0xf0) {
	case 0x00:
		return "Handshake";
	case 0x10:
		return "Control";
	case 0x40:
		return "Get report";
	case 0x50:
		return "Set report";
	case 0x60:
		return "Get protocol";
	case 0x70:
		return "Set protocol";
	case 0x80:
		return "Get idle";
	case 0x90:
		return "Set idle";
	case 0xa0:
		return "Data";
	case 0xb0:
		return "Data continuation";
	default:
		return "Reserved";
	}
}

char *result2str(uint8_t head)
{
	switch (head & 0x0f) {
	case 0x00:
		return "Successful";
	case 0x01:
		return "Not ready";
	case 0x02:
		return "Invalid report ID";
	case 0x03:
		return "Unsupported request";
	case 0x04:
		return "Invalid parameter";
	case 0x0e:
		return "Unknown";
	case 0x0f:
		return "Fatal";
	default:
		return "Reserved";
	}
}

char *operation2str(uint8_t head)
{
	switch (head & 0x0f) {
	case 0x00:
		return "No operation";
	case 0x01:
		return "Hard reset";
	case 0x02:
		return "Soft reset";
	case 0x03:
		return "Suspend";
	case 0x04:
		return "Exit suspend";
	case 0x05:
		return "Virtual cable unplug";
	default:
		return "Reserved";
	}
}

char *report2str(uint8_t head)
{
	switch (head & 0x03) {
	case 0x00:
		return "Other report";
	case 0x01:
		return "Input report";
	case 0x02:
		return "Output report";
	case 0x03:
		return "Feature report";
	default:
		return "Reserved";
	}
}

char *protocol2str(uint8_t head)
{
	switch (head & 0x01) {
	case 0x00:
		return "Report protocol";
	case 0x01:
		return "Boot protocol";
	default:
		return "Reserved";
	}
}

void hidp_dump(int level, struct frame *frm)
{
	uint8_t head;
	char *param;

	head = *(uint8_t *)frm->ptr;

	switch (head & 0xf0) {
	case 0x00:
		param = result2str(head);
		break;
	case 0x10:
		param = operation2str(head);
		break;
	case 0x60:
	case 0x70:
		param = protocol2str(head);
		break;
	case 0x40:
	case 0x50:
	case 0xa0:	
	case 0xb0:
		param = report2str(head);
		break;
	default:
		param = "";
		break;
	}

	p_indent(level, frm);

	printf("HIDP: %s: %s\n", type2str(head), param);

	frm->ptr++;
	frm->len--;

	raw_dump(level, frm);
}
