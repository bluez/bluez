/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <netinet/in.h>

#include "parser.h"

#define PPP_U8(frm)  (get_u8(frm))
#define PPP_U16(frm) (btohs(htons(get_u16(frm))))
#define PPP_U32(frm) (btohl(htonl(get_u32(frm))))

static int ppp_traffic = 0;

static unsigned char ppp_magic1[] = { 0x7e, 0xff, 0x03, 0xc0, 0x21 };
static unsigned char ppp_magic2[] = { 0x7e, 0xff, 0x7d, 0x23, 0xc0, 0x21 };
static unsigned char ppp_magic3[] = { 0x7e, 0x7d, 0xdf, 0x7d, 0x23, 0xc0, 0x21 };

static int check_for_ppp_traffic(unsigned char *data, int size)
{
	int i;

	for (i = 0; i < size - sizeof(ppp_magic1); i++)
		if (!memcmp(data + i, ppp_magic1, sizeof(ppp_magic1))) {
			ppp_traffic = 1;
			return i;
		}

	for (i = 0; i < size - sizeof(ppp_magic2); i++)
		if (!memcmp(data + i, ppp_magic2, sizeof(ppp_magic2))) {
			ppp_traffic = 1;
			return i;
		}

	for (i = 0; i < size - sizeof(ppp_magic3); i++)
		if (!memcmp(data + i, ppp_magic3, sizeof(ppp_magic3))) {
			ppp_traffic = 1;
			return i;
		}

	return -1;
}

void ppp_dump(int level, struct frame *frm)
{
	void *ptr, *end;
	int len, pos = 0;

	if (frm->pppdump_fd > fileno(stderr)) {
		unsigned char id;
		uint16_t len = htons(frm->len);
		uint32_t ts = htonl(frm->ts.tv_sec & 0xffffffff);

		id = 0x07;
		write(frm->pppdump_fd, &id, 1);
		write(frm->pppdump_fd, &ts, 4);

		id = frm->in ? 0x02 : 0x01;
		write(frm->pppdump_fd, &id, 1);
		write(frm->pppdump_fd, &len, 2);
		write(frm->pppdump_fd, frm->ptr, frm->len);
	}

	if (!ppp_traffic) {
		pos = check_for_ppp_traffic(frm->ptr, frm->len);
		if (pos < 0) {
			raw_dump(level, frm);
			return;
		}

		if (pos > 0) {
			raw_ndump(level, frm, pos);
			frm->ptr += pos;
			frm->len -= pos;
		}
	}

	frm = add_frame(frm);

	while (frm->len > 0) {
		ptr = memchr(frm->ptr, 0x7e, frm->len);
		if (!ptr)
			break;

		if (frm->ptr != ptr) {
			frm->len -= (ptr - frm->ptr);
			frm->ptr = ptr;
		}

		end = memchr(frm->ptr + 1, 0x7e, frm->len - 1);
		if (!end)
			break;

		len = end - ptr - 1;

		frm->ptr++;
		frm->len--;

		if (len > 0) {
			p_indent(level, frm);
			printf("HDLC: len %d\n", len);

			raw_ndump(level, frm, len);

			frm->ptr += len;
			frm->len -= len;
		}
	}
}
