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
	Copyright (C) 2002-2004 Marcel Holtmann <marcel@holtmann.org>
*/

/*
 * $Id$
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

#include "parser.h"


#define TABLE_SIZE 10

static struct {
	uint16_t handle;
	uint16_t cid;
	struct frame msg[16];
} table[TABLE_SIZE];

static void add_segment(uint8_t bid, struct frame *frm, int len)
{
	uint16_t handle = frm->handle, cid = frm->cid;
	struct frame *msg;
	void *data;
	int i, pos = -1;

	if (bid > 15)
		return;

	for (i = 0; i < TABLE_SIZE; i++) {
		if (table[i].handle == handle && table[i].cid == cid) {
			pos = i;
			break;
		}

		if (pos < 0 && !table[i].handle && !table[i].cid)
			pos = i;
	}

	if (pos < 0)
		return;

	table[pos].handle = handle;
	table[pos].cid    = cid;
	msg = &table[pos].msg[bid];

	data = malloc(msg->data_len + len);
	if (!data)
		return;

	if (msg->data_len > 0)
		memcpy(data, msg->data, msg->data_len);

	memcpy(data + msg->data_len, frm->ptr, len);
	free(msg->data);
	msg->data = data;
	msg->data_len += len;
	msg->ptr = msg->data;
	msg->len = msg->data_len;
	msg->in  = frm->in;
	msg->ts  = frm->ts;
	msg->handle = handle;
	msg->cid    = cid;
}

static void free_segment(uint8_t bid, struct frame *frm)
{
	uint16_t handle = frm->handle, cid = frm->cid;
	struct frame *msg;
	int i, len = 0, pos = -1;

	if (bid > 15)
		return;

	for (i = 0; i < TABLE_SIZE; i++)
		if (table[i].handle == handle && table[i].cid == cid) {
			pos = i;
			break;
		}

	if (pos < 0)
		return;

	msg = &table[pos].msg[bid];

	if (msg->data)
		free(msg->data);

	msg->data = NULL;
	msg->data_len = 0;

	for (i = 0; i < 16; i++)
		len += table[pos].msg[i].data_len;

	if (!len) {
		table[pos].handle = 0;
		table[pos].cid = 0;
	}
}

static struct frame *get_segment(uint8_t bid, struct frame *frm)
{
	uint16_t handle = frm->handle, cid = frm->cid;
	int i;

	if (bid > 15)
		return NULL;

	for (i = 0; i < TABLE_SIZE; i++)
		if (table[i].handle == handle && table[i].cid == cid)
			return &table[i].msg[bid];

	return NULL;
}

static char *bst2str(uint8_t bst)
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
	struct frame *msg;
	uint8_t hdr, bid;
	uint16_t len;

	while (frm->len > 0) {

		hdr = get_u8(frm);
		bid = (hdr & 0x3c) >> 2;

		switch ((hdr & 0xc0) >> 6) {
		case 0x01:
			len = get_u8(frm);
			break;
		case 0x02:
			len = htons(get_u16(frm));
			break;
		default:
			len = 0;
			break;
		}

		p_indent(level, frm);

		printf("CMTP: %s: id %d len %d\n", bst2str(hdr & 0x03), bid, len);

		switch (hdr & 0x03) {
		case 0x00:
			add_segment(bid, frm, len);
			msg = get_segment(bid, frm);
			if (!msg)
				break;

			if (!p_filter(FILT_CAPI))
				capi_dump(level + 1, msg);
			else
				raw_dump(level, msg);

			free_segment(bid, frm);
			break;
		case 0x01:
			add_segment(bid, frm, len);
			break;
		default:
			free_segment(bid, frm);
			break;
		}

		frm->ptr += len;
		frm->len -= len;
	}
}
