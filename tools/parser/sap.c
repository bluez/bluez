/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Tieto Poland
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

#include "parser.h"

#define SAP_CONNECT_REQ				0x00
#define SAP_CONNECT_RESP			0x01
#define SAP_DISCONNECT_REQ			0x02
#define SAP_DISCONNECT_RESP			0x03
#define SAP_DISCONNECT_IND			0x04
#define SAP_TRANSFER_APDU_REQ			0x05
#define SAP_TRANSFER_APDU_RESP			0x06
#define SAP_TRANSFER_ATR_REQ			0x07
#define SAP_TRANSFER_ATR_RESP			0x08
#define SAP_POWER_SIM_OFF_REQ			0x09
#define SAP_POWER_SIM_OFF_RESP			0x0A
#define SAP_POWER_SIM_ON_REQ			0x0B
#define SAP_POWER_SIM_ON_RESP			0x0C
#define SAP_RESET_SIM_REQ			0x0D
#define SAP_RESET_SIM_RESP			0x0E
#define SAP_TRANSFER_CARD_READER_STATUS_REQ	0x0F
#define SAP_TRANSFER_CARD_READER_STATUS_RESP	0x10
#define SAP_STATUS_IND				0x11
#define SAP_ERROR_RESP				0x12
#define SAP_SET_TRANSPORT_PROTOCOL_REQ		0x13
#define SAP_SET_TRANSPORT_PROTOCOL_RESP		0x14

static const char *msg2str(uint8_t msg)
{
	switch (msg) {
	case SAP_CONNECT_REQ:
		return "Connect Req";
	case SAP_CONNECT_RESP:
		return "Connect Resp";
	case SAP_DISCONNECT_REQ:
		return "Disconnect Req";
	case SAP_DISCONNECT_RESP:
		return "Disconnect Resp";
	case SAP_DISCONNECT_IND:
		return "Disconnect Ind";
	case SAP_TRANSFER_APDU_REQ:
		return "Transfer APDU Req";
	case SAP_TRANSFER_APDU_RESP:
		return "Transfer APDU Resp";
	case SAP_TRANSFER_ATR_REQ:
		return "Transfer ATR Req";
	case SAP_TRANSFER_ATR_RESP:
		return "Transfer ATR Resp";
	case SAP_POWER_SIM_OFF_REQ:
		return "Power SIM Off Req";
	case SAP_POWER_SIM_OFF_RESP:
		return "Power SIM Off Resp";
	case SAP_POWER_SIM_ON_REQ:
		return "Power SIM On Req";
	case SAP_POWER_SIM_ON_RESP:
		return "Power SIM On Resp";
	case SAP_RESET_SIM_REQ:
		return "Reset SIM Req";
	case SAP_RESET_SIM_RESP:
		return "Reset SIM Resp";
	case SAP_TRANSFER_CARD_READER_STATUS_REQ:
		return "Transfer Card Reader Status Req";
	case SAP_TRANSFER_CARD_READER_STATUS_RESP:
		return "Transfer Card Reader Status Resp";
	case SAP_STATUS_IND:
		return "Status Ind";
	case SAP_ERROR_RESP:
		return "Error Resp";
	case SAP_SET_TRANSPORT_PROTOCOL_REQ:
		return "Set Transport Protocol Req";
	case SAP_SET_TRANSPORT_PROTOCOL_RESP:
		return "Set Transport Protocol Resp";
	default:
		return "Reserved";
	}
}

void sap_dump(int level, struct frame *frm)
{
	uint8_t msg, params;

	msg = get_u8(frm);
	params = get_u8(frm);

	/* Skip reserved field */
	get_u16(frm);

	p_indent(level, frm);

	printf("SAP: %s: params %d\n", msg2str(msg), params);

	raw_dump(level, frm);
}
