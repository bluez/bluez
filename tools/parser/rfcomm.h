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

#include <asm/byteorder.h>

#define RFCOMM_PSM 	3

#define TRUE	1
#define FALSE	0

#define RFCOMM_MAX_CONN 10
#define BT_NBR_DATAPORTS RFCOMM_MAX_CONN

#define GET_BIT(pos,bitfield) ((bitfield[(pos)/32]) & (1 << ((pos) % 32)))
#define SET_BIT(pos,bitfield) ((bitfield[(pos)/32]) |= (1 << ((pos) % 32))) 
#define CLR_BIT(pos,bitfield) ((bitfield[(pos)/32]) &= ((1 << ((pos) % 32)) ^ (~0)))
#define SET_PF(ctr) ((ctr) | (1 << 4)) 
/* Sets the P/F-bit in the control field */
#define CLR_PF(ctr) ((ctr) & 0xef)
/* clears the P/F-bit in the control field */
#define GET_PF(ctr) (((ctr) >> 4) & 0x1)
/* Returns the P/F bit */

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

/* endian-swapping macros for structs */
#define swap_long_frame(x) ((x)->h.length.val = le16_to_cpu((x)->h.length.val))
#define swap_mcc_long_frame(x) (swap_long_frame(x))

#define SHORT_CRC_CHECK 2
/* Used for uih packets */
#define LONG_CRC_CHECK 3
/* Used for all packet exepts for the uih packets */
#define SHORT_HDR 2
/* Short header for short uih packets */
#define LONG_HDR 3
/* and long header for long uih packets */

/* FIXME: Should thsi one be define here? */
#define SHORT_PAYLOAD_SIZE 127
#define EA 1
/* Used for setting the EA field in different packets,  really neccessary? */
#define FCS_SIZE 1
/* Yes the FCS size is only one byte */

#define RFCOMM_MAX_HDR_SIZE 5

#define MAX_CREDITS   30
#define START_CREDITS 7
#define MIN_CREDITS   6

#define DEF_RFCOMM_MTU 127

/* The values in the control field when sending ordinary rfcomm packets */
#define SABM 0x2f	/* set asynchronous balanced mode */
#define UA   0x63	/* unnumbered acknolodgement */
#define DM   0x0f	/* disconnected mode */
#define DISC 0x43	/* disconnect */
#define UIH  0xef	/* unnumbered information with header check (only) */
#define UI   0x03	/* unnumbered information (with all data check) */

#define SABM_SIZE 4
#define UA_SIZE   4

/* The values in the type field in a multiplexer command packet */
#define PN    (0x80 >> 2)	/* parameter negotiation */
#define PSC   (0x40 >> 2)	/* power saving control */
#define CLD   (0xc0 >> 2)	/* close down */
#define TEST  (0x20 >> 2)	/* test */
#define FCON  (0xa0 >> 2)	/* flow control on */
#define FCOFF (0x60 >> 2)	/* flow control off */
#define MSC   (0xe0 >> 2)	/* modem status command */
#define NSC   (0x10 >> 2)	/* not supported command response */
#define RPN   (0x90 >> 2)	/* remote port negotiation */
#define RLS   (0x50 >> 2)	/* remote line status */
#define SNC   (0xd0 >> 2)	/* service negotiation command */

/* Define of some V.24 signals modem control signals in RFCOMM */
#define DV  0x80	/* data valid */
#define IC  0x40	/* incoming call */
#define RTR 0x08	/* ready to receive */
#define RTC 0x04	/* ready to communicate */
#define FC  0x02	/* flow control (unable to accept frames) */

#define CTRL_CHAN 0	/* The control channel is defined as DLCI 0 in rfcomm */
#define MCC_CMD 1	 /* Multiplexer command */
#define MCC_RSP 0	 /* Multiplexer response */

/****************** TYPE DEFINITION SECTION *********************************/

#ifdef __LITTLE_ENDIAN_BITFIELD

typedef struct parameter_mask{
	__u8 bit_rate:1;
	__u8 data_bits:1;
	__u8 stop_bit:1;
	__u8 parity:1;
	__u8 parity_type:1;
	__u8 xon:1;
	__u8 xoff:1;
	__u8 res1:1;
	__u8 xon_input:1;
	__u8 xon_output:1;
	__u8 rtr_input:1;
	__u8 rtr_output:1;
	__u8 rtc_input:1;
	__u8 rtc_output:1;
	__u8 res2:2;
} __attribute__ ((packed)) parameter_mask;

typedef struct rpn_values{
	__u8 bit_rate;
	__u8 data_bits:2;
	__u8 stop_bit:1;
	__u8 parity:1;
	__u8 parity_type:2;
	__u8 res1:2;
	__u8 xon_input:1;
	__u8 xon_output:1;
	__u8 rtr_input:1;
	__u8 rtr_output:1;
	__u8 rtc_input:1;
	__u8 rtc_output:1;
	__u8 res2:2;
	__u8 xon;
	__u8 xoff;
	parameter_mask pm;
} __attribute__ ((packed)) rpn_values;

#elif defined(__BIG_ENDIAN_BITFIELD)

typedef struct parameter_mask{ 
	__u8 res1:1;
	__u8 xoff:1;
	__u8 xon:1;
	__u8 parity_type:1;
	__u8 parity:1;
	__u8 stop_bit:1;
	__u8 data_bits:1;
	__u8 bit_rate:1;

	__u8 res2:2;
	__u8 rtc_output:1;
	__u8 rtc_input:1;
	__u8 rtr_output:1;
	__u8 rtr_input:1;
	__u8 xon_output:1;
	__u8 xon_input:1;

} __attribute__ ((packed)) parameter_mask;

typedef struct rpn_values{ 
	__u8 bit_rate;

	__u8 res1:2;
	__u8 parity_type:2;
	__u8 parity:1;
	__u8 stop_bit:1;
	__u8 data_bits:2;

	__u8 res2:2;
	__u8 rtc_output:1;
	__u8 rtc_input:1;
	__u8 rtr_output:1;
	__u8 rtr_input:1;
	__u8 xon_output:1;
	__u8 xon_input:1;

	__u8 xon;
	__u8 xoff;
	parameter_mask pm;
} __attribute__ ((packed)) rpn_values;

#else  /* __XXX_BITFIELD */
#error Processor endianness unknown!
#endif

/****************************************************************************/

/****************** TYPE DEFINITION SECTION *********************************/

/* Typedefinitions of stuctures used for creating and parsing packets, for a
   further description of the structures please se the bluetooth core
   specification part F:1 and the ETSI TS 07.10 specification  */

#ifdef __LITTLE_ENDIAN_BITFIELD

typedef struct address_field {
	__u8 ea:1;
	__u8 cr:1;
	__u8 d:1;
	__u8 server_chn:5;
} __attribute__ ((packed)) address_field;

typedef struct short_length {
	__u8 ea:1;
	__u8 len:7;
} __attribute__ ((packed)) short_length;

typedef union long_length {
	struct bits {
		__u8 ea:1;
		unsigned short len:15;
	} __attribute__ ((packed)) bits ;
	__u16 val ;
} __attribute__ ((packed)) long_length;

typedef struct short_frame_head {
	address_field addr;
	__u8 control;
	short_length length;
} __attribute__ ((packed)) short_frame_head;

typedef struct short_frame {
	short_frame_head h;
	__u8 data[0]; 
} __attribute__ ((packed)) short_frame;

typedef struct long_frame_head {
	address_field addr;
	__u8 control;
	long_length length;
	__u8 data[0];
} __attribute__ ((packed)) long_frame_head;

typedef struct long_frame {
	long_frame_head h;
	__u8 data[0];
} __attribute__ ((packed)) long_frame;

/* Typedefinitions for structures used for the multiplexer commands */
typedef struct mcc_type {
	__u8 ea:1;
	__u8 cr:1;
	__u8 type:6;
} __attribute__ ((packed)) mcc_type;

typedef struct mcc_short_frame_head {
	mcc_type type;
	short_length length;
	__u8 value[0];
} __attribute__ ((packed)) mcc_short_frame_head;

typedef struct mcc_short_frame {
	mcc_short_frame_head h;
	__u8 value[0];
} __attribute__ ((packed)) mcc_short_frame;

typedef struct mcc_long_frame_head {
	mcc_type type;
	long_length length;
	__u8 value[0];
} __attribute__ ((packed)) mcc_long_frame_head;

typedef struct mcc_long_frame {
	mcc_long_frame_head h;
	__u8 value[0];
} __attribute__ ((packed)) mcc_long_frame;

/* MSC-command */
typedef struct v24_signals {
	__u8 ea:1;
	__u8 fc:1;
	__u8 rtc:1;
	__u8 rtr:1;
	__u8 reserved:2;
	__u8 ic:1;
	__u8 dv:1;
} __attribute__ ((packed)) v24_signals;

typedef struct break_signals {
	__u8 ea:1;
	__u8 b1:1;
	__u8 b2:1;
	__u8 b3:1;
	__u8 len:4;
} __attribute__ ((packed)) break_signals;

typedef struct msc_msg {
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	v24_signals v24_sigs;
	//break_signals break_sigs;
	__u8 fcs;
} __attribute__ ((packed)) msc_msg;

typedef struct rpn_msg {
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	rpn_values rpn_val;
	__u8 fcs;
} __attribute__ ((packed)) rpn_msg;

/* RLS-command */  
typedef struct rls_msg {
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	__u8 error:4;
	__u8 res:4;
	__u8 fcs;
} __attribute__ ((packed)) rls_msg;

/* PN-command */
typedef struct pn_msg {
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
/* The res1, res2 and res3 values have to be set to 0 by the sender */
	__u8 dlci:6;
	__u8 res1:2;
	__u8 frame_type:4;
	__u8 credit_flow:4;
	__u8 prior:6;
	__u8 res2:2;
	__u8 ack_timer;
	__u16 frame_size:16;
	__u8 max_nbrof_retrans;
	__u8 credits;
	__u8 fcs;
} __attribute__ ((packed)) pn_msg;

/* NSC-command */
typedef struct nsc_msg {
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	mcc_type command_type;
	__u8 fcs;
} __attribute__ ((packed)) nsc_msg;

#elif defined(__BIG_ENDIAN_BITFIELD)

typedef struct address_field {
	__u8 server_chn:5;
	__u8 d:1;
	__u8 cr:1;
	__u8 ea:1;
} __attribute__ ((packed)) address_field;

typedef struct short_length {
	__u8 len:7;
	__u8 ea:1;
} __attribute__ ((packed)) short_length;

typedef union long_length {
	struct bits {
		unsigned short len:15;
		__u8 ea:1;
	} __attribute__ ((packed)) bits;
	__u16 val;
} __attribute__ ((packed)) long_length;

typedef struct short_frame_head { 
	address_field addr;
	__u8 control;
	short_length length;
} __attribute__ ((packed)) short_frame_head;

typedef struct short_frame {
	short_frame_head h;
	__u8 data[0];
} __attribute__ ((packed)) short_frame;

typedef struct long_frame_head { 
	address_field addr;
	__u8 control;
	long_length length;
	__u8 data[0];
} __attribute__ ((packed)) long_frame_head;

typedef struct long_frame { 
	long_frame_head h;
	__u8 data[0];
} __attribute__ ((packed)) long_frame;

typedef struct mcc_type { 
	__u8 type:6;
	__u8 cr:1;
	__u8 ea:1;
} __attribute__ ((packed)) mcc_type;

typedef struct mcc_short_frame_head { 
	mcc_type type;
	short_length length;
	__u8 value[0];
} __attribute__ ((packed)) mcc_short_frame_head;

typedef struct mcc_short_frame { 
	mcc_short_frame_head h;
	__u8 value[0];
} __attribute__ ((packed)) mcc_short_frame;

typedef struct mcc_long_frame_head { 
	mcc_type type;
	long_length length;
	__u8 value[0];
} __attribute__ ((packed)) mcc_long_frame_head;

typedef struct mcc_long_frame { 
	mcc_long_frame_head h;
	__u8 value[0];
} __attribute__ ((packed)) mcc_long_frame;

typedef struct v24_signals { 
	__u8 dv:1;
	__u8 ic:1;
	__u8 reserved:2;
	__u8 rtr:1;
	__u8 rtc:1;
	__u8 fc:1;
	__u8 ea:1;
} __attribute__ ((packed)) v24_signals;

typedef struct break_signals { 
	__u8 len:4;
	__u8 b3:1;
	__u8 b2:1;
	__u8 b1:1;
	__u8 ea:1;
} __attribute__ ((packed)) break_signals;

typedef struct msc_msg { 
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	v24_signals v24_sigs;
	//break_signals break_sigs;
	__u8 fcs;
} __attribute__ ((packed)) msc_msg;

typedef struct rpn_msg { 
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	rpn_values rpn_val;
	__u8 fcs;
} __attribute__ ((packed)) rpn_msg;

typedef struct rls_msg { 
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	__u8 res:4;
	__u8 error:4;
	__u8 fcs;
} __attribute__ ((packed)) rls_msg;

typedef struct pn_msg { 
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	__u8 res1:2;
	__u8 dlci:6;
	__u8 credit_flow:4;
	__u8 frame_type:4;
	__u8 res2:2;
	__u8 prior:6;
	__u8 ack_timer;
	__u16 frame_size:16;
	__u8 max_nbrof_retrans;
	__u8 credits;
	__u8 fcs;
} __attribute__ ((packed)) pn_msg;

typedef struct nsc_msg { 
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	mcc_type command_type;
	__u8 fcs;
} __attribute__ ((packed)) nsc_msg;

#else /* __XXX_ENDIAN */
#error Processor endianness unknown!
#endif /* __XXX_ENDIAN */

/****************************************************************************/
