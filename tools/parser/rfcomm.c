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
	RFCOMM parser.
	Copyright (C) 2001 Wayne Lee <waynelee@qualcomm.com>
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

#include "rfcomm.h"
#include "parser.h"

static char *cr_str[] = {
	"RSP",
	"CMD"
};

#define CR_STR(mcc_head) cr_str[mcc_head->type.cr]

void print_rfcomm_hdr(long_frame_head* head, __u8 *ptr, int len)
{
	address_field  addr  = head->addr;
	__u8           ctr   = head->control;
	__u16          ilen  = head->length.len;
	__u8           ctr_type,pf,dlci,fcs;

	dlci     = GET_DLCI(addr);
	pf       = GET_PF(ctr);
	ctr_type = CLR_PF(ctr);
	fcs      = *(ptr + len - 1);

	printf("cr %d dlci %d pf %d ilen %d fcs 0x%x ", addr.cr, dlci, pf, ilen, fcs); 
}

void print_mcc(mcc_long_frame_head* mcc_head)
{
	printf("mcc_len %d\n", mcc_head->length.len);
}

static inline void mcc_test(int level, __u8 *ptr, int len, 
				long_frame_head *head, 
				mcc_long_frame_head *mcc_head)
{
	printf("TEST %s: ", CR_STR(mcc_head));
	print_rfcomm_hdr(head, ptr, len);
	print_mcc(mcc_head);
}
static inline void mcc_fcon(int level, __u8 *ptr, int len, 
				long_frame_head *head, 
				mcc_long_frame_head *mcc_head)
{
	printf("FCON %s: ", CR_STR(mcc_head));
	print_rfcomm_hdr(head, ptr, len);
	print_mcc(mcc_head);
}
static inline void mcc_fcoff(int level, __u8 *ptr, int len, 
				long_frame_head *head, 
				mcc_long_frame_head *mcc_head)
{
	printf("FCOFF %s: ", CR_STR(mcc_head));
	print_rfcomm_hdr(head, ptr, len);
	print_mcc(mcc_head);
}
static inline void mcc_msc(int level, __u8 *ptr, int len, 
				long_frame_head *head, 
				mcc_long_frame_head *mcc_head)
{
	msc_data *msc = (void*) ptr;

	printf("MSC %s: ", CR_STR(mcc_head));
	print_rfcomm_hdr(head, ptr, len);
	print_mcc(mcc_head);
	p_indent(level, 0); 
	printf("dlci %d fc %d rtc %d rtr %d ic %d dv %d",
		GET_DLCI(msc->addr), msc->v24_sigs.fc, msc->v24_sigs.rtc, 
		msc->v24_sigs.rtr, msc->v24_sigs.ic, msc->v24_sigs.dv );
	if (len == MSC_DATA_BREAK_SIZE)
		printf(" b1 %d b2 %d b3 %d len %d\n", msc->brk_sigs.b1,
		msc->brk_sigs.b2, msc->brk_sigs.b3, msc->brk_sigs.len);
	else
		printf("\n");
}
static inline void mcc_rpn(int level, __u8 *ptr, int len,
				long_frame_head *head, 
				mcc_long_frame_head *mcc_head)
{
	rpn_data *rpn = (void*) ptr;

	printf("RPN %s: ", CR_STR(mcc_head));
	print_rfcomm_hdr(head, ptr, len);
	print_mcc(mcc_head);
	printf("dlci %d ", GET_DLCI(rpn->addr));

	if (len == RPN_DATA_NO_RPN_SIZE) {
		printf("\n");
		return;
	}

	printf(" br: %d db: %d sb: %d p: %d pt: %d xi: %d xo: %d\n",
		rpn->rpn_val.bit_rate, rpn->rpn_val.data_bits, 
		rpn->rpn_val.stop_bit, rpn->rpn_val.parity,
		rpn->rpn_val.parity_type, rpn->rpn_val.xon_input,
		rpn->rpn_val.xon_output);
	p_indent(level, 0); 
	printf(" rtri: %d rtro: %d rtci: %d rtco: %d xon: %d xoff: %d pm: %04x",
		rpn->rpn_val.rtr_input, rpn->rpn_val.rtr_output,
		rpn->rpn_val.rtc_input, rpn->rpn_val.rtc_output,
		rpn->rpn_val.xon___u8, rpn->rpn_val.xoff___u8,
		*((__u16*)&rpn->rpn_val.pm));
}
static inline void mcc_rls(int level, __u8 *ptr, int len,
				long_frame_head *head, 
				mcc_long_frame_head *mcc_head)
{
	rls_data* rls = (void*) ptr;

	printf("RLS %s ", CR_STR(mcc_head));
	print_rfcomm_hdr(head, ptr, len);
	print_mcc(mcc_head);
	printf("dlci %d error: %d", GET_DLCI(rls->addr), rls->error);
}
static inline void mcc_pn(int level, __u8 *ptr, int len,
				long_frame_head *head, 
				mcc_long_frame_head *mcc_head)
{
	pn_data *pn = (void*) ptr;

	printf("PN %s", CR_STR(mcc_head));
	print_rfcomm_hdr(head, ptr, len);
	print_mcc(mcc_head);

	p_indent(level, 0); 
	printf("dlci %d frame_type %d conv_lay %d pri %d ack_timer %d "
		"frame_size %d max_retrans %d win_size %d\n",
		pn->dlci, pn->frame_type, pn->conv_layer, pn->pri,
		pn->ack_timer, pn->frame_size, pn->max_retrans, pn->win_size);
}

static inline void mcc_nsc(int level, __u8 *ptr, int len,
				long_frame_head *head, 
				mcc_long_frame_head *mcc_head)
{

	nsc_data *nsc = (void*) ptr;

	printf("NSC %s: ", CR_STR(mcc_head));
	print_rfcomm_hdr(head, ptr, len);
	print_mcc(mcc_head);

	p_indent(level, 0); 
	printf("cr %d, mcc_cmd_type %x\n", 
		nsc->cmd_type.cr, nsc->cmd_type.type );
}

static inline void mcc_frame(int level, struct frame *frm, long_frame_head *head)
{
        mcc_short_frame_head *mcc_short_head_p = frm->ptr;
        mcc_long_frame_head mcc_head;
        __u8 hdr_size;

        if ( mcc_short_head_p->length.ea == EA ) {
                mcc_head.type       = mcc_short_head_p->type;
                mcc_head.length.len = mcc_short_head_p->length.len;
                hdr_size = MCC_SHORT_FRAME_HEAD_SIZE;
        } else {
                mcc_head = *(mcc_long_frame_head *)frm->ptr;
                hdr_size = MCC_LONG_FRAME_HEAD_SIZE;
        }

        frm->ptr += hdr_size;
        frm->len -= hdr_size;

	p_indent(level, frm->in); 
	printf("RFCOMM(s): ");

	switch (mcc_head.type.type) {
	case TEST:
		mcc_test(level, frm->ptr, frm->len, head, &mcc_head);
		raw_dump(level, frm); 
		break;
	case FCON:
		mcc_fcon(level, frm->ptr, frm->len, head, &mcc_head);
		break;
	case FCOFF:
		mcc_fcoff(level, frm->ptr, frm->len, head, &mcc_head);
		break;
	case MSC:
		mcc_msc(level, frm->ptr, frm->len, head, &mcc_head);
		break;
	case RPN:
		mcc_test(level, frm->ptr, frm->len, head, &mcc_head);
		break;
	case RLS:
		mcc_test(level, frm->ptr, frm->len, head, &mcc_head);
		break;
	case PN:
		mcc_test(level, frm->ptr, frm->len, head, &mcc_head);
		break;
	case NSC:
		mcc_test(level, frm->ptr, frm->len, head, &mcc_head);
		break;
	default:
		printf("MCC ERR: ");
		print_rfcomm_hdr(head, frm->ptr, frm->len);
		printf("\n");
		
		frm->len--;
		raw_dump(level, frm); 
	}
}

static inline void uih_frame(int level, struct frame *frm, long_frame_head *head)
{
	if (!head->addr.server_chn) {
		mcc_frame(level, frm, head); 
	} else {
		p_indent(level, frm->in);
		printf("RFCOMM(d): UIH: ");
		print_rfcomm_hdr(head, frm->ptr, frm->len);
		printf("\n");

		frm->len--;
		raw_dump(level, frm);
	}
}

void rfcomm_dump(int level, struct frame *frm)
{
	__u8 hdr_size, ctr_type;
	short_frame_head *short_head_p = (void *) frm->ptr;
	long_frame_head head;

	if (short_head_p->length.ea == EA) {
		head.addr       = short_head_p->addr;
		head.control    = short_head_p->control;
		head.length.len = short_head_p->length.len;
		hdr_size = SHORT_FRAME_HEAD_SIZE;
	} else {
		head = *(long_frame_head *) frm->ptr;
		hdr_size = LONG_FRAME_HEAD_SIZE;
	}

	frm->ptr += hdr_size;
	frm->len -= hdr_size;

	ctr_type = CLR_PF(head.control);

	if (ctr_type == UIH) {
		uih_frame(level, frm, &head); 
	} else {
		p_indent(level, frm->in); 
		printf("RFCOMM(s): ");

		switch (ctr_type) {
		case SABM:
			printf("SABM: ");
			break;
		case UA:
			printf("UA: ");
			break;
		case DM:
			printf("DM: ");
			break;
		case DISC:
			printf("DISC: ");
			break;
		default:
			printf("ERR: ");
		}
		print_rfcomm_hdr(&head, frm->ptr, frm->len);
		printf("\n");
	}
}
