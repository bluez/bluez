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
	void	*data;
	int	data_len;
	void	*ptr;
	int	len;
	int 	in;
	int	handle;
	long	flags;
	struct	timeval ts;
};

/* Parser flags */
#define DUMP_WIDTH	20

#define DUMP_HEX	0x01
#define DUMP_ASCII	0x02
#define DUMP_TYPE_MASK	(DUMP_HEX | DUMP_ASCII)
#define DUMP_TSTAMP	0x04
#define DUMP_RAW	0x08

/* Parser filter */
#define FILT_HCI	0x0001
#define FILT_L2CAP	0x0002
#define FILT_RFCOMM	0x0004
#define FILT_SDP	0x0008
#define FILT_SCO	0x0010
#define FILT_BNEP       0x0020

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

static inline void p_indent(int level, struct frame *f)
{
	if (level < 0) {
		parser.state = 0;
		return;
	}
	
	if (!parser.state) {
		if (parser.flags & DUMP_TSTAMP)
			printf("%ld.%ld ", f->ts.tv_sec, f->ts.tv_usec);
		printf("%c ", (f->in ? '>' : '<'));
		parser.state = 1;
	} else 
		printf("  ");

	if (level)
		printf("%*c", (level*2), ' ');
}

inline __u8 get_u8(struct frame *frm);
inline __u16 get_u16(struct frame *frm);
inline __u32 get_u32(struct frame *frm);
inline char* get_uuid_name(int uuid);

void raw_dump(int level, struct frame *frm);
void hci_dump(int level, struct frame *frm);
void l2cap_dump(int level, struct frame *frm);
void rfcomm_dump(int level, struct frame *frm);
void sdp_dump(int level, struct frame *frm);
void bnep_dump(int level, struct frame *frm);

static inline void parse(struct frame *frm)
{
	p_indent(-1, NULL);
	if (parser.flags & DUMP_RAW)
		raw_dump(0, frm);
	else
		hci_dump(0, frm);
	fflush(stdout);
}
