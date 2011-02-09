/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  André Dieb Martins <andre.dieb@gmail.com>
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

/* Attribute Protocol Opcodes */
#define ATT_OP_ERROR			0x01
#define ATT_OP_MTU_REQ			0x02
#define ATT_OP_MTU_RESP			0x03
#define ATT_OP_FIND_INFO_REQ		0x04
#define ATT_OP_FIND_INFO_RESP		0x05
#define ATT_OP_FIND_BY_TYPE_REQ		0x06
#define ATT_OP_FIND_BY_TYPE_RESP	0x07
#define ATT_OP_READ_BY_TYPE_REQ		0x08
#define ATT_OP_READ_BY_TYPE_RESP	0x09
#define ATT_OP_READ_REQ			0x0A
#define ATT_OP_READ_RESP		0x0B
#define ATT_OP_READ_BLOB_REQ		0x0C
#define ATT_OP_READ_BLOB_RESP		0x0D
#define ATT_OP_READ_MULTI_REQ		0x0E
#define ATT_OP_READ_MULTI_RESP		0x0F
#define ATT_OP_READ_BY_GROUP_REQ	0x10
#define ATT_OP_READ_BY_GROUP_RESP	0x11
#define ATT_OP_WRITE_REQ		0x12
#define ATT_OP_WRITE_RESP		0x13
#define ATT_OP_WRITE_CMD		0x52
#define ATT_OP_PREP_WRITE_REQ		0x16
#define ATT_OP_PREP_WRITE_RESP		0x17
#define ATT_OP_EXEC_WRITE_REQ		0x18
#define ATT_OP_EXEC_WRITE_RESP		0x19
#define ATT_OP_HANDLE_NOTIFY		0x1B
#define ATT_OP_HANDLE_IND		0x1D
#define ATT_OP_HANDLE_CNF		0x1E
#define ATT_OP_SIGNED_WRITE_CMD		0xD2

/* Error codes for Error response PDU */
#define ATT_ECODE_INVALID_HANDLE		0x01
#define ATT_ECODE_READ_NOT_PERM			0x02
#define ATT_ECODE_WRITE_NOT_PERM		0x03
#define ATT_ECODE_INVALID_PDU			0x04
#define ATT_ECODE_INSUFF_AUTHEN			0x05
#define ATT_ECODE_REQ_NOT_SUPP			0x06
#define ATT_ECODE_INVALID_OFFSET		0x07
#define ATT_ECODE_INSUFF_AUTHO			0x08
#define ATT_ECODE_PREP_QUEUE_FULL		0x09
#define ATT_ECODE_ATTR_NOT_FOUND		0x0A
#define ATT_ECODE_ATTR_NOT_LONG			0x0B
#define ATT_ECODE_INSUFF_ENCR_KEY_SIZE		0x0C
#define ATT_ECODE_INVAL_ATTR_VALUE_LEN		0x0D
#define ATT_ECODE_UNLIKELY			0x0E
#define ATT_ECODE_INSUFF_ENC			0x0F
#define ATT_ECODE_UNSUPP_GRP_TYPE		0x10
#define ATT_ECODE_INSUFF_RESOURCES		0x11
#define ATT_ECODE_IO				0xFF


/* Attribute Protocol Opcodes */
static const char *attop2str(uint8_t op)
{
	switch (op) {
	case ATT_OP_ERROR:
		return "Error";
	case ATT_OP_MTU_REQ:
		return "MTU req";
	case ATT_OP_MTU_RESP:
		return "MTU resp";
	case ATT_OP_FIND_INFO_REQ:
		return "Find Information req";
	case ATT_OP_FIND_INFO_RESP:
		return "Find Information resp";
	case ATT_OP_FIND_BY_TYPE_REQ:
		return "Find By Type req";
	case ATT_OP_FIND_BY_TYPE_RESP:
		return "Find By Type resp";
	case ATT_OP_READ_BY_TYPE_REQ:
		return "Read By Type req";
	case ATT_OP_READ_BY_TYPE_RESP:
		return "Read By Type resp";
	case ATT_OP_READ_REQ:
		return "Read req";
	case ATT_OP_READ_RESP:
		return "Read resp";
	case ATT_OP_READ_BLOB_REQ:
		return "Read Blob req";
	case ATT_OP_READ_BLOB_RESP:
		return "Read Blob resp";
	case ATT_OP_READ_MULTI_REQ:
		return "Read Multi req";
	case ATT_OP_READ_MULTI_RESP:
		return "Read Multi resp";
	case ATT_OP_READ_BY_GROUP_REQ:
		return "Read By Group req";
	case ATT_OP_READ_BY_GROUP_RESP:
		return "Read By Group resp";
	case ATT_OP_WRITE_REQ:
		return "Write req";
	case ATT_OP_WRITE_RESP:
		return "Write resp";
	case ATT_OP_WRITE_CMD:
		return "Write cmd";
	case ATT_OP_PREP_WRITE_REQ:
		return "Prepare Write req";
	case ATT_OP_PREP_WRITE_RESP:
		return "Prepare Write resp";
	case ATT_OP_EXEC_WRITE_REQ:
		return "Exec Write req";
	case ATT_OP_EXEC_WRITE_RESP:
		return "Exec Write resp";
	case ATT_OP_HANDLE_NOTIFY:
		return "Handle notify";
	case ATT_OP_HANDLE_IND:
		return "Handle indicate";
	case ATT_OP_HANDLE_CNF:
		return "Handle CNF";
	case ATT_OP_SIGNED_WRITE_CMD:
		return "Signed Write Cmd";
	default:
		return "Unknown";
	}
}

static const char * atterror2str(uint8_t err)
{
	switch (err) {
	case ATT_ECODE_INVALID_HANDLE:
		return "Invalid handle";
	case ATT_ECODE_READ_NOT_PERM:
		return "Read not permitted";
	case ATT_ECODE_WRITE_NOT_PERM:
		return "Write not permitted";
	case ATT_ECODE_INVALID_PDU:
		return "Invalid PDU";
	case ATT_ECODE_INSUFF_AUTHEN:
		return "Insufficient authentication";
	case ATT_ECODE_REQ_NOT_SUPP:
		return "Request not supported";
	case ATT_ECODE_INVALID_OFFSET:
		return "Invalid offset";
	case ATT_ECODE_INSUFF_AUTHO:
		return "Insufficient authorization";
	case ATT_ECODE_PREP_QUEUE_FULL:
		return "Prepare queue full";
	case ATT_ECODE_ATTR_NOT_FOUND:
		return "Attribute not found";
	case ATT_ECODE_ATTR_NOT_LONG:
		return "Attribute not long";
	case ATT_ECODE_INSUFF_ENCR_KEY_SIZE:
		return "Insufficient encryption key size";
	case ATT_ECODE_INVAL_ATTR_VALUE_LEN:
		return "Invalid attribute value length";
	case ATT_ECODE_UNLIKELY:
		return "Unlikely error";
	case ATT_ECODE_INSUFF_ENC:
		return "Insufficient encryption";
	case ATT_ECODE_UNSUPP_GRP_TYPE:
		return "Unsupported group type";
	case ATT_ECODE_INSUFF_RESOURCES:
		return "Insufficient resources";
	case ATT_ECODE_IO:
		return "Application Error";
	default:
		return "Reserved";
	}
}

static void att_error_dump(int level, struct frame *frm)
{
	uint8_t op = get_u8(frm);
	uint16_t handle = btohs(htons(get_u16(frm)));
	uint8_t err = get_u8(frm);

	p_indent(level, frm);
	printf("Error: %s 0x%.2x\n", atterror2str(err), err);

	p_indent(level, frm);
	printf("opcode %d (%s) on handle 0x%2.2x\n", op, attop2str(op), handle);
}

static void att_mtu_req_dump(int level, struct frame *frm)
{
	uint16_t client_rx_mtu = btohs(htons(get_u16(frm)));

	p_indent(level, frm);
	printf("client rx mtu %d\n", client_rx_mtu);
}

static void att_mtu_resp_dump(int level, struct frame *frm)
{
	uint16_t server_rx_mtu = btohs(htons(get_u16(frm)));

	p_indent(level, frm);
	printf("server rx mtu %d\n", server_rx_mtu);
}

static void att_handle_notify_dump(int level, struct frame *frm)
{
	uint16_t handle = btohs(htons(get_u16(frm)));

	p_indent(level, frm);
	printf("handle 0x%2.2x\n", handle);

	p_indent(level, frm);
	printf("value ");
	while (frm->len > 0) {
		printf("0x%.2x ", get_u8(frm));
	}
	printf("\n");
}

void att_dump(int level, struct frame *frm)
{
	uint8_t op;

	op = get_u8(frm);

	p_indent(level, frm);
	printf("ATT: %s (0x%.2x)\n", attop2str(op), op);

	switch (op) {
		case ATT_OP_ERROR:
			att_error_dump(level + 1, frm);
			break;
		case ATT_OP_MTU_REQ:
			att_mtu_req_dump(level + 1, frm);
			break;
		case ATT_OP_MTU_RESP:
			att_mtu_resp_dump(level + 1, frm);
			break;
		case ATT_OP_HANDLE_NOTIFY:
			att_handle_notify_dump(level + 1, frm);
			break;

		default:
			raw_dump(level, frm);
			break;
	}
}
