/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdint.h>

#define BT_ATT_DEFAULT_LE_MTU 23

/* ATT protocol opcodes */
#define BT_ATT_OP_ERROR_RSP	      		0x01
#define BT_ATT_OP_MTU_REQ			0x02
#define BT_ATT_OP_MTU_RSP			0x03
#define BT_ATT_OP_FIND_INFO_REQ			0x04
#define BT_ATT_OP_FIND_INFO_RSP			0x05
#define BT_ATT_OP_FIND_BY_TYPE_VAL_REQ		0x06
#define BT_ATT_OP_FIND_BY_TYPE_VAL_RSP		0x07
#define BT_ATT_OP_READ_BY_TYPE_REQ		0x08
#define BT_ATT_OP_READ_BY_TYPE_RSP		0x09
#define BT_ATT_OP_READ_REQ			0x0a
#define BT_ATT_OP_READ_RSP			0x0b
#define BT_ATT_OP_READ_BLOB_REQ			0x0c
#define BT_ATT_OP_READ_BLOB_RSP			0x0d
#define BT_ATT_OP_READ_MULT_REQ			0x0e
#define BT_ATT_OP_READ_MULT_RSP			0x0f
#define BT_ATT_OP_READ_BY_GRP_TYPE_REQ		0x10
#define BT_ATT_OP_READ_BY_GRP_TYPE_RSP		0x11
#define BT_ATT_OP_WRITE_REQ			0x12
#define BT_ATT_OP_WRITE_RSP			0x13
#define BT_ATT_OP_WRITE_CMD			0x52
#define BT_ATT_OP_SIGNED_WRITE_CMD		0xD2
#define BT_ATT_OP_PREP_WRITE_REQ		0x16
#define BT_ATT_OP_PREP_WRITE_RSP		0x17
#define BT_ATT_OP_EXEC_WRITE_REQ		0x18
#define BT_ATT_OP_EXEC_WRITE_RSP		0x19
#define BT_ATT_OP_HANDLE_VAL_NOT		0x1B
#define BT_ATT_OP_HANDLE_VAL_IND		0x1D
#define BT_ATT_OP_HANDLE_VAL_CONF		0x1E

/* Error codes for Error response PDU */
#define BT_ATT_ERROR_INVALID_HANDLE			0x01
#define BT_ATT_ERROR_READ_NOT_PERMITTED			0x02
#define BT_ATT_ERROR_WRITE_NOT_PERMITTED		0x03
#define BT_ATT_ERROR_INVALID_PDU			0x04
#define BT_ATT_ERROR_AUTHENTICATION			0x05
#define BT_ATT_ERROR_REQUEST_NOT_SUPPORTED		0x06
#define BT_ATT_ERROR_INVALID_OFFSET			0x07
#define BT_ATT_ERROR_AUTHORIZATION			0x08
#define BT_ATT_ERROR_PREPARE_QUEUE_FULL			0x09
#define BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND		0x0A
#define BT_ATT_ERROR_ATTRIBUTE_NOT_LONG			0x0B
#define BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE	0x0C
#define BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN	0x0D
#define BT_ATT_ERROR_UNLIKELY				0x0E
#define BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION		0x0F
#define BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE		0x10
#define BT_ATT_ERROR_INSUFFICIENT_RESOURCES		0x11
