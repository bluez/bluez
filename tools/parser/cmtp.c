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
	CMTP parser.
	Copyright (C) 2002 Marcel Holtmann <marcel@holtmann.org>
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

#include "parser.h"


char *bst2str(__u8 bst)
{
	switch (bst) {
	case 0x00:
		return "complete CAPI Message";
	case 0x01:
		return "segmented CAPI Message";
	case 0x02:
		return "error";
	case 0x03:
		return "reserved";
	default:
		return "unknown";
	}
}

void cmtp_dump(int level, struct frame *frm)
{
	__u8 hdr_size;
	__u8 head;
	__u8 bst, bid, nlb;
	__u16 len;

	while (frm->len > 0) {

		head = *(__u8 *)frm->ptr;

		bst = (head & 0x03);
		bid = (head & 0x3c) >> 2;
		nlb = (head & 0xc0) >> 6;

		switch (nlb) {
		default:
		case 0x00:
		case 0x03:
			hdr_size = 1;
			len = 0;
			break;
		case 0x01:
			hdr_size = 2;
			len = *(__u8 *)(frm->ptr + 1);
			break;
		case 0x02:
			hdr_size = 3;
			len = *(__u8 *)(frm->ptr + 1) + (*(__u8 *)(frm->ptr + 2) * 256);
			break;
		}

		p_indent(level, frm);

		printf("CMTP: %s: id %d len %d\n", bst2str(bst), bid, len);

		frm->ptr += hdr_size;
		frm->len -= hdr_size;

		if (len > 0) {
			raw_ndump(level, frm, len);

			frm->ptr += len;
			frm->len -= len;
		}

	}
}
