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
	RFCOMM frame processing engine is based on:
		Implementation of Bluetooth RFCOMM with TS 07.10, Serial Port Emulation
		Copyright (C) 2000, 2001  Axis Communications AB
		Author: Mats Friden <mats.friden@axis.com>
*/

/*
 * $Id$
 */

#include <asm/types.h>

#define GET_BIT(pos,bitfield) ((bitfield[(pos)/32]) & (1 << ((pos) % 32)))
#define SET_BIT(pos,bitfield) ((bitfield[(pos)/32]) |= (1 << ((pos) % 32))) 
#define CLR_BIT(pos,bitfield) ((bitfield[(pos)/32]) &= ((1 << ((pos) % 32)) ^ (~0)))
#define SET_PF(ctr) ((ctr) | (1 << 4)) 

/* Sets the P/F-bit in the control field */
#define CLR_PF(ctr) ((ctr) & 0xef)
/* Clears the P/F-bit in the control field */
#define GET_PF(ctr) (((ctr) >> 4) & 0x1)
/* Returns the P/F bit */

#define SHORT_CRC_CHECK 2
/* Used for uih packets */
#define LONG_CRC_CHECK 3
/* Used for all packet exepts for the uih packets */
#define SHORT_HDR 2
/* Short header for short uih packets */
#define LONG_HDR 3
/* and long header for long uih packets */

#define SHORT_PAYLOAD_SIZE 127
#define EA 1
/* Used for setting the EA field in different packets,  really neccessary? */
#define FCS_SIZE 1
/* Yes the FCS size is only one byte */

#define RFCOMM_MAX_HDR_SIZE 5

#define NBROFCREDITS 6

#define DEF_RFCOMM_MTU 127

/* The values in the control field when sending ordinary rfcomm packets */
#define SABM 0x2f
#define SABM_SIZE 4
#define UA 0x63
#define UA_SIZE 4
#define DM 0x0f
#define DISC 0x43
#define UIH 0xef

/* The values in the type field in a multiplexer command packet */
#define TEST 0x8
#define FCON 0x28
#define FCOFF 0x18
#define MSC 0x38
#define RPN 0x24
#define RLS 0x14
#define PN 0x20
#define NSC 0x4

/* Define of some V.24 signals modem control signals in RFCOMM */
#define FC 0x2
#define RTC 0x4
#define RTR 0x8
#define DV 0x80

#define PPP_DLCI 2	 /* The virtual port for ppp */
#define CTRL_CHAN 0	 /* The control channel is defined as DLCI 0 in rfcomm */
#define MCC_CMD 1	 /* Multiplexer command */
#define MCC_RSP 0	 /* Multiplexer response */

/****************** TYPE DEFINITION SECTION *********************************/

/* Typedefinitions of stuctures used for creating and parsing packets, for a
   further description of the structures please se the bluetooth core
   specification part F:1 and the ETSI TS 07.10 specification  */

typedef struct address_field {
	__u8 ea:1;
	__u8 cr:1;
	__u8 d:1;
	__u8 server_chn:5;
} __attribute__ ((packed)) address_field;

#define GET_DLCI(addr) ((addr.server_chn << 1) | (addr.d & 1))

typedef struct short_length {
	__u8  ea:1;
	__u8  len:7;
} __attribute__ ((packed)) short_length;

typedef struct long_length {
	__u16 ea:1;
	__u16 len:15;
} __attribute__ ((packed)) long_length;

typedef struct short_frame_head {
	address_field addr;
	__u8 control;
	short_length length;
} __attribute__ ((packed)) short_frame_head;
#define SHORT_FRAME_HEAD_SIZE 3

typedef struct short_frame {
	short_frame_head h;
	__u8 data[0];
} __attribute__ ((packed)) short_frame;

typedef struct long_frame_head {
	address_field addr;
	__u8 control;
	long_length length;
} __attribute__ ((packed)) long_frame_head;
#define LONG_FRAME_HEAD_SIZE 4

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
} __attribute__ ((packed)) mcc_short_frame_head;
#define MCC_SHORT_FRAME_HEAD_SIZE 2

typedef struct mcc_short_frame {
	mcc_short_frame_head h;
	__u8 value[0];
} __attribute__ ((packed)) mcc_short_frame;

typedef struct mcc_long_frame_head {
	mcc_type type;
	long_length length;
} __attribute__ ((packed)) mcc_long_frame_head;
#define MCC_LONG_FRAME_HEAD_SIZE 3

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

typedef struct brk_signals {
	__u8 ea:1;
	__u8 b1:1;
	__u8 b2:1;
	__u8 b3:1;
	__u8 len:4;
} __attribute__ ((packed)) brk_signals;

typedef struct msc_data {
	address_field addr;
	v24_signals v24_sigs;
	brk_signals brk_sigs;
	__u8 fcs;
} __attribute__ ((packed)) msc_data;
#define MSC_DATA_NO_BREAK_SIZE 2
#define MSC_DATA_BREAK_SIZE 3

typedef struct msc_msg {
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	__u8 v24_sigs;
	//brk_sigs break_signals;
	__u8 fcs;
} __attribute__ ((packed)) msc_msg;

/* RPN command */
#define B2400 0
#define B4800 1
#define B7200 2
#define B9600 3
#define B19200 4
#define B38400 5
#define B57600 6
#define B115200 7
#define D230400 8

typedef struct parameter_mask {
	__u8 bit_rate:1;
	__u8 data_bits:1;
	__u8 stop_bit:1;
	__u8 parity:1;
	__u8 parity_type:1;
	__u8 xon___u8:1;
	__u8 xoff___u8:1;
	__u8 res1:1;
	__u8 xon_input:1;
	__u8 xon_output:1;
	__u8 rtr_input:1;
	__u8 rtr_output:1;
	__u8 rtc_input:1;
	__u8 rtc_output:1;
	__u8 res2:2;
} __attribute__ ((packed)) parameter_mask;

typedef struct rpn_values {
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
	__u8 xon___u8;
	__u8 xoff___u8;
	parameter_mask pm;
} __attribute__ ((packed)) rpn_values;

typedef struct rpn_data {
	address_field addr;
	rpn_values rpn_val;
} __attribute__ ((packed)) rpn_data;
#define RPN_DATA_NO_RPN_SIZE 1
#define RPN_DATA_SIZE 8

typedef struct rpn_msg {
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	rpn_values rpn_val;
	__u8 fcs;
} __attribute__ ((packed)) rpn_msg;

/* RLS-command */  
typedef struct rls_data{
	address_field addr;
	__u8 error:4;
	__u8 res:4;
} __attribute__ ((packed)) rls_data;

typedef struct rls_msg{
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	address_field dlci;
	__u8 error:4;
	__u8 res:4;
	__u8 fcs;
} __attribute__ ((packed)) rls_msg;

/* PN-command */
typedef struct pn_data {
	__u8 dlci:6;
	__u8 res1:2;
	__u8 frame_type:4;
	__u8 conv_layer:4;
	__u8 pri:6;
	__u8 res2:2;
	__u8 ack_timer;
	__u16 frame_size;
	__u8 max_retrans;
	__u8 win_size;
} __attribute__ ((packed)) pn_data;

/* PN-command */
typedef struct pn_msg {
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	__u8 dlci:6;
	__u8 res1:2;
	__u8 frame_type:4;
	__u8 credit_flow:4;
	__u8 prior:6;
	__u8 res2:2;
	__u8 ack_timer;
	__u32 frame_size:16;
	__u8 max_nbrof_retrans;
	__u8 credits;
	__u8 fcs;
} __attribute__ ((packed)) pn_msg;

/* NSC-command */
typedef struct nsc_data{
	mcc_type cmd_type;
} __attribute__ ((packed)) nsc_data;

typedef struct nsc_msg{
	short_frame_head s_head;
	mcc_short_frame_head mcc_s_head;
	mcc_type command_type;
	__u8 fcs;
} __attribute__ ((packed)) nsc_msg;
