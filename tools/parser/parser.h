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
#define FILT_BNEP	0x0020
#define FILT_CMTP	0x0040
#define FILT_HIDP	0x0080

#define STRUCT_OFFSET(type, member)  ((uint8_t *)&(((type *)NULL)->member) - \
                                     (uint8_t *)((type *)NULL))

#define STRUCT_END(type, member)     (STRUCT_OFFSET(type, member) + \
                                     sizeof(((type *)NULL)->member))

struct parser_t {
	unsigned long flags;
	unsigned long filter;
	unsigned int defpsm;
	int state;
};

extern struct parser_t parser;

void init_parser(unsigned long flags, unsigned long filter, 
	unsigned int assume_psm);

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
			printf("%8lu.%06lu ", f->ts.tv_sec, f->ts.tv_usec);
		printf("%c ", (f->in ? '>' : '<'));
		parser.state = 1;
	} else 
		printf("  ");

	if (level)
		printf("%*c", (level*2), ' ');
}

/* get_uXX functions do byte swaping */

/* use memmove to prevent gcc from using builtin memcpy */
#define get_unaligned(p) \
	({ __typeof__(*(p)) t; memmove(&t, (p), sizeof(t)); t; })

static inline uint8_t get_u8(struct frame *frm)
{
	uint8_t *u8_ptr = frm->ptr;
	frm->ptr += 1;
	frm->len -= 1;
	return *u8_ptr;
}

static inline uint16_t get_u16(struct frame *frm)
{
	uint16_t *u16_ptr = frm->ptr;
	frm->ptr += 2;
	frm->len -= 2;
	return ntohs(get_unaligned(u16_ptr));
}

static inline uint32_t get_u32(struct frame *frm)
{
	uint32_t *u32_ptr = frm->ptr;
	frm->ptr += 4;
	frm->len -= 4;
	return ntohl(get_unaligned(u32_ptr));
}

static inline uint64_t get_u64(struct frame *frm)
{
	uint64_t *u64_ptr = frm->ptr;
	uint64_t u64 = get_unaligned(u64_ptr), tmp;
	frm->ptr += 8;
	frm->len -= 8;
	tmp = ntohl(u64 & 0xffffffff);
	u64 = (tmp << 32) | ntohl(u64 >> 32);
	return u64;
}

static inline void get_u128(struct frame *frm, uint64_t *l, uint64_t *h)
{
	*h = get_u64(frm);
	*l = get_u64(frm);
}

char *get_uuid_name(int uuid);

void raw_dump(int level, struct frame *frm);
void raw_ndump(int level, struct frame *frm, int num);
void hci_dump(int level, struct frame *frm);
void l2cap_dump(int level, struct frame *frm);
void rfcomm_dump(int level, struct frame *frm);
void sdp_dump(int level, struct frame *frm);
void bnep_dump(int level, struct frame *frm);
void cmtp_dump(int level, struct frame *frm);
void hidp_dump(int level, struct frame *frm);

static inline void parse(struct frame *frm)
{
	p_indent(-1, NULL);
	if (parser.flags & DUMP_RAW)
		raw_dump(0, frm);
	else
		hci_dump(0, frm);
	fflush(stdout);
}
