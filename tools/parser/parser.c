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
#include <ctype.h>

#include <sys/types.h>
#include <netinet/in.h>

#include "parser.h"

struct parser_t parser;

void init_parser(unsigned long flags, unsigned long filter,
	unsigned int defpsm)
{
	if ((flags & DUMP_RAW) && !(flags & DUMP_TYPE_MASK))
		flags |= DUMP_HEX;

	parser.flags  = flags;
	parser.filter = filter;
	parser.defpsm = defpsm;
	parser.state  = 0;
}

#define PROTO_TABLE_SIZE 20

static struct {
	uint16_t handle;
	uint16_t psm;
	uint32_t proto;
} proto_table[PROTO_TABLE_SIZE];

void set_proto(uint16_t handle, uint16_t psm, uint32_t proto)
{
	int i, pos = -1;

	if (psm < 0x1000)
		return;

	for (i = 0; i < PROTO_TABLE_SIZE; i++) {
		if (proto_table[i].handle == handle && proto_table[i].psm == psm) {
			pos = i;
			break;
		}

		if (pos < 0 && !proto_table[i].handle && !proto_table[i].psm)
			pos = i;
	}

	if (pos < 0)
		return;

	proto_table[pos].handle = handle;
	proto_table[pos].psm    = psm;
	proto_table[pos].proto  = proto;
}

uint32_t get_proto(uint16_t handle, uint16_t psm)
{
	int i, pos = -1;

	for (i = 0; i < PROTO_TABLE_SIZE; i++) {
		if (proto_table[i].handle == handle && proto_table[i].psm == psm)
			return proto_table[i].proto;

		if (!proto_table[i].handle && proto_table[i].psm == psm)
			pos = i;
	}

	return (pos < 0) ? 0 : proto_table[pos].proto;
}

void hex_dump(int level, struct frame *frm, int num)
{
	unsigned char *buf = frm->ptr;
	register int i,n;

	if ((num < 0) || (num > frm->len))
		num = frm->len;

	for (i = 0, n = 1; i < num; i++, n++) {
		if (n == 1)
			p_indent(level, frm);
		printf("%2.2X ", buf[i]);
		if (n == DUMP_WIDTH) {
			printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		printf("\n");
}

void ascii_dump(int level, struct frame *frm, int num)
{
	unsigned char *buf = frm->ptr;
	register int i,n;

	if ((num < 0) || (num > frm->len))
		num = frm->len;

	for (i = 0, n = 1; i < num; i++, n++) {
		if (n == 1)
			p_indent(level, frm);
		printf("%1c ", isprint(buf[i]) ? buf[i] : '.');
		if (n == DUMP_WIDTH) {
			printf("\n");
			n = 0;
		}
	}
	if (i && n!=1)
		printf("\n");
}

void raw_ndump(int level, struct frame *frm, int num)
{
	if (!frm->len)
		return;

	switch (parser.flags & DUMP_TYPE_MASK) {
	case DUMP_ASCII:
		ascii_dump(level, frm, num);
		break;

	case DUMP_HEX:
		hex_dump(level, frm, num);
		break;

	}
}

void raw_dump(int level, struct frame *frm)
{
	raw_ndump(level, frm, -1);
}
