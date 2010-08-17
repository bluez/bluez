/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "att.h"

const char *att_ecode2str(uint8_t status)
{
	switch (status)  {
	case ATT_ECODE_INVALID_HANDLE:
		return "Invalid handle";
	case ATT_ECODE_READ_NOT_PERM:
		return "Atribute can't be read";
	case ATT_ECODE_WRITE_NOT_PERM:
		return "Attribute can't be written";
	case ATT_ECODE_INVALID_PDU:
		return "Attribute PDU was invalid";
	case ATT_ECODE_INSUFF_AUTHEN:
		return "Attribute requires authentication before read/write";
	case ATT_ECODE_REQ_NOT_SUPP:
		return "Server doesn't support the request received";
	case ATT_ECODE_INVALID_OFFSET:
		return "Offset past the end of the attribute";
	case ATT_ECODE_INSUFF_AUTHO:
		return "Attribute requires authorization before read/write";
	case ATT_ECODE_PREP_QUEUE_FULL:
		return "Too many prepare writes have been queued";
	case ATT_ECODE_ATTR_NOT_FOUND:
		return "No attribute found within the given range";
	case ATT_ECODE_ATTR_NOT_LONG:
		return "Attribute can't be read/written using Read Blob Req";
	case ATT_ECODE_INSUFF_ENCR_KEY_SIZE:
		return "Encryption Key Size is insufficient";
	case ATT_ECODE_INVAL_ATTR_VALUE_LEN:
		return "Attribute value length is invalid";
	case ATT_ECODE_UNLIKELY:
		return "Request attribute has encountered an unlikely error";
	case ATT_ECODE_INSUFF_ENC:
		return "Encryption required before read/write";
	case ATT_ECODE_UNSUPP_GRP_TYPE:
		return "Attribute type is not a supported grouping attribute";
	case ATT_ECODE_INSUFF_RESOURCES:
		return "Insufficient Resources to complete the request";
	case ATT_ECODE_IO:
		return "Internal application error: I/O";
	default:
		return "Unexpected error code";
	}
}

void att_data_list_free(struct att_data_list *list)
{
	int i;

	for (i = 0; i < list->num; i++)
		free(list->data[i]);

	free(list->data);
	free(list);
}

uint16_t enc_read_by_grp_req(uint16_t start, uint16_t end, uuid_t *uuid,
							uint8_t *pdu, int len)
{
	/* FIXME: UUID128 is not supported */

	if (!uuid)
		return 0;

	if (uuid->type != SDP_UUID16)
		return 0;

	if (len < 7)
		return 0;

	pdu[0] = ATT_OP_READ_BY_GROUP_REQ;
	att_put_u16(start, &pdu[1]);
	att_put_u16(end, &pdu[3]);
	att_put_u16(uuid->value.uuid16, &pdu[5]);

	return 7;
}

uint16_t dec_read_by_grp_req(const uint8_t *pdu, int len, uint16_t *start,
						uint16_t *end, uuid_t *uuid)
{
	if (pdu == NULL)
		return 0;

	if (start == NULL || end == NULL || uuid == NULL)
		return 0;

	if (pdu[0] != ATT_OP_READ_BY_GROUP_REQ)
		return 0;

	if (len < 7)
		return 0;

	*start = att_get_u16((uint16_t *) &pdu[1]);
	*end = att_get_u16((uint16_t *) &pdu[3]);
	sdp_uuid16_create(uuid, att_get_u16((uint16_t *) &pdu[5]));

	return len;
}

uint16_t enc_read_by_grp_resp(struct att_data_list *list, uint8_t *pdu, int len)
{
	int i;
	uint16_t w;
	uint8_t *ptr;

	if (list == NULL)
		return 0;

	pdu[0] = ATT_OP_READ_BY_GROUP_RESP;
	pdu[1] = list->len;

	ptr = &pdu[2];

	for (i = 0, w = 2; i < list->num && w < len; i++, w += list->len) {
		memcpy(ptr, list->data[i], list->len);
		ptr += list->len;
	}

	return w;
}

struct att_data_list *dec_read_by_grp_resp(const uint8_t *pdu, int len)
{
	struct att_data_list *list;
	const uint8_t *ptr;
	int i;

	if (pdu[0] != ATT_OP_READ_BY_GROUP_RESP)
		return NULL;

	list = malloc(sizeof(struct att_data_list));
	list->len = pdu[1];
	list->num = (len - 2) / list->len;

	list->data = malloc(sizeof(uint8_t *) * list->num);
	ptr = &pdu[2];

	for (i = 0; i < list->num; i++) {
		list->data[i] = malloc(sizeof(uint8_t) * list->len);
		memcpy(list->data[i], ptr, list->len);
		ptr += list->len;
	}

	return list;
}

uint16_t enc_find_by_type_req(uint16_t start, uint16_t end, uuid_t *uuid,
							uint8_t *pdu, int len)
{
	return 0;
}

uint16_t enc_read_by_type_req(uint16_t start, uint16_t end, uuid_t *uuid,
							uint8_t *pdu, int len)
{
	/* FIXME: UUID128 is not supported */

	if (!uuid)
		return 0;

	if (uuid->type != SDP_UUID16)
		return 0;

	if (len < 7)
		return 0;

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	att_put_u16(start, &pdu[1]);
	att_put_u16(end, &pdu[3]);
	att_put_u16(uuid->value.uuid16, &pdu[5]);

	return 7;
}

uint16_t dec_read_by_type_req(const uint8_t *pdu, int len, uint16_t *start,
						uint16_t *end, uuid_t *uuid)
{
	if (pdu == NULL)
		return 0;

	if (start == NULL || end == NULL || uuid == NULL)
		return 0;

	if (len < 7)
		return 0;

	if (pdu[0] != ATT_OP_READ_BY_TYPE_REQ)
		return 0;

	*start = att_get_u16((uint16_t *) &pdu[1]);
	*end = att_get_u16((uint16_t *) &pdu[3]);
	sdp_uuid16_create(uuid, att_get_u16((uint16_t *) &pdu[5]));

	return 7;
}

uint16_t enc_read_by_type_resp(struct att_data_list *list, uint8_t *pdu, int len)
{
	uint8_t *ptr;
	int i, w;

	if (list == NULL)
		return 0;

	if (pdu == NULL)
		return 0;

	pdu[0] = ATT_OP_READ_BY_TYPE_RESP;
	pdu[1] = list->len;
	ptr = &pdu[2];

	for (i = 0, w = 2; i < list->num && w < len; i++, w += list->len) {
		memcpy(ptr, list->data[i], list->len);
		ptr += list->len;
	}

	return w;
}

struct att_data_list *dec_read_by_type_resp(const uint8_t *pdu, int len)
{
	struct att_data_list *list;
	const uint8_t *ptr;
	int i;

	if (pdu[0] != ATT_OP_READ_BY_TYPE_RESP)
		return NULL;

	list = malloc(sizeof(struct att_data_list));
	list->len = pdu[1];
	list->num = (len - 2) / list->len;

	list->data = malloc(sizeof(uint8_t *) * list->num);
	ptr = &pdu[2];

	for (i = 0; i < list->num; i++) {
		list->data[i] = malloc(sizeof(uint8_t) * list->len);
		memcpy(list->data[i], ptr, list->len);
		ptr += list->len;
	}

	return list;
}

uint16_t enc_read_req(uint16_t handle, uint8_t *pdu, int len)
{
	if (pdu == NULL)
		return 0;

	if (len < 3)
		return 0;

	pdu[0] = ATT_OP_READ_REQ;
	att_put_u16(handle, &pdu[1]);

	return 3;
}

uint16_t dec_read_req(const uint8_t *pdu, uint16_t *handle)
{
	if (pdu == NULL)
		return 0;

	if (handle == NULL)
		return 0;

	if (pdu[0] != ATT_OP_READ_REQ)
		return 0;

	*handle = att_get_u16((uint16_t *) &pdu[1]);

	return 3;
}

uint16_t enc_read_resp(uint8_t *value, int vlen, uint8_t *pdu, int len)
{
	if (pdu == NULL)
		return 0;

	if (len < vlen + 1)
		return 0;

	pdu[0] = ATT_OP_READ_RESP;

	memcpy(pdu + 1, value, vlen);

	return vlen + 1;
}

uint16_t dec_read_resp(const uint8_t *pdu, int len, uint8_t *value, int *vlen)
{
	if (pdu == NULL)
		return 0;

	if (value == NULL || vlen == NULL)
		return 0;

	if (pdu[0] != ATT_OP_READ_RESP)
		return 0;

	memcpy(value, pdu + 1, len - 1);

	*vlen = len - 1;

	return len;
}

uint16_t enc_error_resp(uint8_t opcode, uint16_t handle, uint8_t status,
							uint8_t *pdu, int len)
{
	uint16_t u16;

	if (len < 5)
		return 0;

	u16 = htobs(handle);
	pdu[0] = ATT_OP_ERROR;
	pdu[1] = opcode;
	memcpy(&pdu[2], &u16, sizeof(u16));
	pdu[4] = status;

	return 5;
}

uint16_t enc_find_info_req(uint16_t start, uint16_t end, uint8_t *pdu, int len)
{
	if (pdu == NULL)
		return 0;

	if (len < 5)
		return 0;

	pdu[0] = ATT_OP_FIND_INFO_REQ;
	att_put_u16(start, &pdu[1]);
	att_put_u16(end, &pdu[3]);

	return 5;
}

uint16_t dec_find_info_req(const uint8_t *pdu, int len, uint16_t *start,
								uint16_t *end)
{
	if (pdu == NULL)
		return 0;

	if (len < 5)
		return 0;

	if (start == NULL || end == NULL)
		return 0;

	if (pdu[0] != ATT_OP_FIND_INFO_REQ)
		return 0;

	*start = att_get_u16((uint16_t *) &pdu[1]);
	*end = att_get_u16((uint16_t *) &pdu[3]);

	return 5;
}

uint16_t enc_find_info_resp(uint8_t format, struct att_data_list *list,
							uint8_t *pdu, int len)
{
	uint8_t *ptr;
	int i, w;

	if (pdu == NULL)
		return 0;

	if (list == NULL || len < 2)
		return 0;

	pdu[0] = ATT_OP_FIND_INFO_RESP;
	pdu[1] = format;
	ptr = (void *) &pdu[2];

	for (i = 0, w = 2; i < list->num && w < len; i++, w += list->len) {
		memcpy(ptr, list->data[i], list->len);
		ptr += list->len;
	}

	return w;
}

struct att_data_list *dec_find_info_resp(const uint8_t *pdu, int len,
							uint8_t *format)
{
	struct att_data_list *list;
	uint8_t *ptr;
	int i;

	if (pdu == NULL)
		return 0;

	if (format == NULL)
		return 0;

	if (pdu[0] != ATT_OP_FIND_INFO_RESP)
		return 0;

	*format = pdu[1];

	list = malloc(sizeof(struct att_data_list));

	if (*format == 0x01)
		list->len = 4;
	else if (*format == 0x02)
		list->len = 18;

	list->num = (len - 2) / list->len;
	list->data = malloc(sizeof(uint8_t *) * list->num);

	ptr = (void *) &pdu[2];

	for (i = 0; i < list->num; i++) {
		list->data[i] = malloc(list->len);
		memcpy(list->data[i], ptr, list->len);
		ptr += list->len;
	}

	return list;
}

uint16_t enc_notification(struct attribute *a, uint8_t *pdu, int len)
{
	if (pdu == NULL)
		return 0;

	if (len < (a->len + 3))
		return 0;

	pdu[0] = ATT_OP_HANDLE_NOTIFY;
	att_put_u16(a->handle, &pdu[1]);
	memcpy(&pdu[3], a->data, a->len);

	return a->len + 3;
}
