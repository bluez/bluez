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

#include <sys/types.h>
#include <asm/types.h>

#include "parser.h"

static long parser_flags;

void init_parser(long flags)
{
	parser_flags = flags;
}

static inline void hex_dump(int level, unsigned char *buf, int len)
{
	register unsigned char *ptr;
	register int i;
	char line[100];

	ptr = line; *ptr = 0; 
	for (i=0; i<len; i++) {
		ptr += sprintf(ptr, "%2.2X ", buf[i]);
		if (i && !((i+1)%20)) {
			indent(level); printf("%s\n", line);
			ptr = line; *ptr = 0;
		}
	}
	if (line[0])
		indent(level); printf("%s\n", line);
}

static inline void ascii_dump(int level, unsigned char *buf, int len)
{
	register unsigned char *ptr;
	register int i;
	char line[100];

	ptr = line; *ptr = 0; 
	for (i=0; i<len; i++) {
		ptr += sprintf(ptr, "%1c", buf[i]);
		if (i && !((i+1)%20)) {
			indent(level); printf("%s\n", line);
			ptr = line; *ptr = 0;
		}
	}
	if (line[0])
		indent(level); printf("%s\n", line);
}

void raw_dump(int level, unsigned char *buf, int len)
{
	switch (parser_flags & DUMP_TYPE_MASK) {
	case DUMP_HEX:
		hex_dump(level, buf, len);	
		break;

	case DUMP_ASCII:
		ascii_dump(level, buf, len);
		break;
	}
}
