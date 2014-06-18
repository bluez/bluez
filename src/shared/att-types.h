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

/* Error response */
#define BT_ATT_OP_ERROR_RSP	      		0x01
struct bt_att_error_rsp_param {
	uint8_t request_opcode;
	uint16_t handle;
	uint8_t	error_code;
};

/* Exchange MTU */
#define BT_ATT_OP_MTU_REQ			0x02
struct bt_att_mtu_req_param {
	uint16_t client_rx_mtu;
};

#define BT_ATT_OP_MTU_RSP			0x03
struct bt_att_mtu_rsp_param {
	uint16_t server_rx_mtu;
};

/* Find Information */
#define BT_ATT_OP_FIND_INFO_REQ			0x04
struct bt_att_find_info_req_param {
	uint16_t start_handle;
	uint16_t end_handle;
};

#define BT_ATT_OP_FIND_INFO_RSP			0x05
struct bt_att_find_info_rsp_param {
	uint8_t format;
	const uint8_t *info_data;
	uint16_t length;
};

/* Find By Type Value */
#define BT_ATT_OP_FIND_BY_TYPE_VAL_REQ		0x06
struct bt_att_find_by_type_value_req_param {
	uint16_t start_handle;
	uint16_t end_handle;
	uint16_t type;  /* 2 octet UUID */
	const uint8_t *value;
	uint16_t length;  /* MAX length: (ATT_MTU - 7) */
};

#define BT_ATT_OP_FIND_BY_TYPE_VAL_RSP		0x07
struct bt_att_find_by_type_value_rsp_param {
	const uint8_t *handles_info_list;
	uint16_t length;
};

/* Read By Type */
#define BT_ATT_OP_READ_BY_TYPE_REQ		0x08
struct bt_att_read_by_type_req_param {
	uint16_t start_handle;
	uint16_t end_handle;
	bt_uuid_t type;  /* 2 or 16 octet UUID */
};

#define BT_ATT_OP_READ_BY_TYPE_RSP		0x09
struct bt_att_read_by_type_rsp_param {
	uint8_t length;
	const uint8_t *attr_data_list;
	uint16_t list_length;  /* Length of "attr_data_list" */
};

/* Read */
#define BT_ATT_OP_READ_REQ			0x0a
struct bt_att_read_req_param {
	uint16_t handle;
};

#define BT_ATT_OP_READ_RSP			0x0b
struct bt_att_read_rsp_param {
	const uint8_t *value;
	uint16_t length;
};

/* Read Blob */
#define BT_ATT_OP_READ_BLOB_REQ			0x0c
struct bt_att_read_blob_req_param {
	uint16_t handle;
	uint16_t offset;
};

#define BT_ATT_OP_READ_BLOB_RSP			0x0d
struct bt_att_read_blob_rsp_param {
	const uint8_t *part_value;
	uint16_t length;
};

/* Read Multiple */
#define BT_ATT_OP_READ_MULT_REQ			0x0e
struct bt_att_read_multiple_req_param {
	const uint16_t *handles;
	uint16_t num_handles;
};

#define BT_ATT_OP_READ_MULT_RSP			0x0f
struct bt_att_read_multiple_rsp_param {
	const uint8_t *values;
	uint16_t length;
};

/* Read By Group Type */
#define BT_ATT_OP_READ_BY_GRP_TYPE_REQ		0x10
struct bt_att_read_by_group_type_req_param {
	uint16_t start_handle;
	uint16_t end_handle;
	bt_uuid_t type;
};

#define BT_ATT_OP_READ_BY_GRP_TYPE_RSP		0x11
struct bt_att_read_by_group_type_rsp_param {
	uint8_t length;
	const uint8_t *attr_data_list;
	uint16_t list_length;  /* Length of "attr_data_list" */
};

/* Write Request */
#define BT_ATT_OP_WRITE_REQ			0x12
/*
 * bt_att_write_param is used for write request and signed and unsigned write
 * command.
 */
struct bt_att_write_param {
	uint16_t handle;
	const uint8_t *value;
	uint16_t length;
};

#define BT_ATT_OP_WRITE_RSP			0x13  /* No parameters */

/* Write Command */
#define BT_ATT_OP_WRITE_CMD			0x52

/* Signed Write Command */
#define BT_ATT_OP_SIGNED_WRITE_CMD		0xD2

/* Prepare Write */
#define BT_ATT_OP_PREP_WRITE_REQ		0x16
struct bt_att_prepare_write_req_param {
	uint16_t handle;
	uint16_t offset;
	const uint8_t *part_value;
	uint16_t length;
};

#define BT_ATT_OP_PREP_WRITE_RSP		0x17
struct bt_att_prepare_write_rsp_param {
	uint16_t handle;
	uint16_t offset;
	const uint8_t *part_value;
	uint16_t length;
};

/* Execute Write */
#define BT_ATT_OP_EXEC_WRITE_REQ		0x18
typedef enum {
	BT_ATT_EXEC_WRITE_FLAG_CANCEL	= 0x00,
	BT_ATT_EXEC_WRITE_FLAG_WRITE	= 0x01,
} bt_att_exec_write_flag_t;

struct bt_att_exec_write_req_param {
	bt_att_exec_write_flag_t flags;
};

#define BT_ATT_OP_EXEC_WRITE_RSP		0x19

/* Handle Value Notification/Indication */
#define BT_ATT_OP_HANDLE_VAL_NOT		0x1B
#define BT_ATT_OP_HANDLE_VAL_IND		0x1D
struct bt_att_notify_param {
	uint16_t handle;
	const uint8_t *value;
	uint16_t length;
};

/* Handle Value Confirmation */
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
