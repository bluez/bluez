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

struct frame {
	void *data;
	int  data_len;
	void *ptr;
	int  len;
	int  in;
	int  handle;
	long flags;
};

/* Parser flags */
#define DUMP_WIDTH	20

#define DUMP_HEX	0x01
#define DUMP_ASCII	0x02
#define DUMP_TYPE_MASK	(DUMP_HEX | DUMP_ASCII)

/* Parser filter */
#define FILT_HCI	0x01
#define FILT_L2CAP	0x02
#define FILT_RFCOMM	0x04
#define FILT_SDP	0x08

struct parser_t {
	unsigned long flags;
	unsigned long filter;
	int state;
};

extern struct parser_t parser;

void init_parser(unsigned long flags, unsigned long filter);

static inline int p_filter(unsigned long f)
{
	return !(parser.filter & f);
}

static inline void p_indent(int level, int in)
{
	if (level < 0) {
		parser.state = 0;
		return;
	}
	
	if (!parser.state) {
		printf("%c ", (in ? '>' : '<'));
		parser.state = 1;
	} else 
		printf("  ");

	if (level)
		printf("%*c", (level*2), ' ');
}

void raw_dump(int level, struct frame *frm);
void hci_dump(int level, struct frame *frm);
void l2cap_dump(int level, struct frame *frm);
void rfcomm_dump(int level, struct frame *frm);
void sdp_dump(int level, struct frame *frm);

static inline void parse(struct frame *frm)
{
	p_indent(-1, 0);
	hci_dump(0, frm);
	fflush(stdout);
}
