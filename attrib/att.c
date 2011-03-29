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
#include <bluetooth/uuid.h>

#include <glib.h>

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
	case ATT_ECODE_AUTHENTICATION:
		return "Attribute requires authentication before read/write";
	case ATT_ECODE_REQ_NOT_SUPP:
		return "Server doesn't support the request received";
	case ATT_ECODE_INVALID_OFFSET:
		return "Offset past the end of the attribute";
	case ATT_ECODE_AUTHORIZATION:
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
	if (list == NULL)
		return;

	if (list->data) {
		int i;
		for (i = 0; i < list->num; i++)
			g_free(list->data[i]);
	}

	g_free(list->data);
	g_free(list);
}

struct att_data_list *att_data_list_alloc(uint16_t num, uint16_t len)
{
	struct att_data_list *list;
	int i;

	list = g_new0(struct att_data_list, 1);
	list->len = len;
	list->num = num;

	list->data = g_malloc0(sizeof(uint8_t *) * num);

	for (i = 0; i < num; i++)
		list->data[i] = g_malloc0(sizeof(uint8_t) * len);

	return list;
}

uint16_t enc_read_by_grp_req(uint16_t start, uint16_t end, bt_uuid_t *uuid,
							uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(start) + sizeof(end);
	uint16_t length;

	if (!uuid)
		return 0;

	if (uuid->type == BT_UUID16)
		length = 2;
	else if (uuid->type == BT_UUID128)
		length = 16;
	else
		return 0;

	if (len < min_len + length)
		return 0;

	pdu[0] = ATT_OP_READ_BY_GROUP_REQ;
	att_put_u16(start, &pdu[1]);
	att_put_u16(end, &pdu[3]);

	att_put_uuid(*uuid, &pdu[5]);

	return min_len + length;
}

uint16_t dec_read_by_grp_req(const uint8_t *pdu, int len, uint16_t *start,
						uint16_t *end, bt_uuid_t *uuid)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*start) + sizeof(*end);

	if (pdu == NULL)
		return 0;

	if (start == NULL || end == NULL || uuid == NULL)
		return 0;

	if (pdu[0] != ATT_OP_READ_BY_GROUP_REQ)
		return 0;

	if (len < min_len + 2)
		return 0;

	*start = att_get_u16(&pdu[1]);
	*end = att_get_u16(&pdu[3]);
	if (len == min_len + 2)
		*uuid = att_get_uuid16(&pdu[5]);
	else
		*uuid = att_get_uuid128(&pdu[5]);

	return len;
}

uint16_t enc_read_by_grp_resp(struct att_data_list *list, uint8_t *pdu,
								int len)
{
	int i;
	uint16_t w;
	uint8_t *ptr;

	if (list == NULL)
		return 0;

	if (len < list->len + 2)
		return 0;

	pdu[0] = ATT_OP_READ_BY_GROUP_RESP;
	pdu[1] = list->len;

	ptr = &pdu[2];

	for (i = 0, w = 2; i < list->num && w + list->len <= len; i++) {
		memcpy(ptr, list->data[i], list->len);
		ptr += list->len;
		w += list->len;
	}

	return w;
}

struct att_data_list *dec_read_by_grp_resp(const uint8_t *pdu, int len)
{
	struct att_data_list *list;
	const uint8_t *ptr;
	uint16_t elen, num;
	int i;

	if (pdu[0] != ATT_OP_READ_BY_GROUP_RESP)
		return NULL;

	elen = pdu[1];
	num = (len - 2) / elen;
	list = att_data_list_alloc(num, elen);

	ptr = &pdu[2];

	for (i = 0; i < num; i++) {
		memcpy(list->data[i], ptr, list->len);
		ptr += list->len;
	}

	return list;
}

uint16_t enc_find_by_type_req(uint16_t start, uint16_t end, bt_uuid_t *uuid,
			const uint8_t *value, int vlen, uint8_t *pdu, int len)
{
	uint16_t min_len = sizeof(pdu[0]) + sizeof(start) + sizeof(end) +
							sizeof(uint16_t);

	if (pdu == NULL)
		return 0;

	if (!uuid)
		return 0;

	if (uuid->type != BT_UUID16)
		return 0;

	if (len < min_len)
		return 0;

	if (vlen > len - min_len)
		vlen = len - min_len;

	pdu[0] = ATT_OP_FIND_BY_TYPE_REQ;
	att_put_u16(start, &pdu[1]);
	att_put_u16(end, &pdu[3]);
	att_put_uuid16(*uuid, &pdu[5]);

	if (vlen > 0) {
		memcpy(&pdu[7], value, vlen);
		return min_len + vlen;
	}

	return min_len;
}

uint16_t dec_find_by_type_req(const uint8_t *pdu, int len, uint16_t *start,
		uint16_t *end, bt_uuid_t *uuid, uint8_t *value, int *vlen)
{
	int valuelen;
	uint16_t min_len = sizeof(pdu[0]) + sizeof(*start) +
						sizeof(*end) + sizeof(uint16_t);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (pdu[0] != ATT_OP_FIND_BY_TYPE_REQ)
		return 0;

	/* First requested handle number */
	if (start)
		*start = att_get_u16(&pdu[1]);

	/* Last requested handle number */
	if (end)
		*end = att_get_u16(&pdu[3]);

	/* Always UUID16 */
	if (uuid)
		*uuid = att_get_uuid16(&pdu[5]);

	valuelen = len - min_len;

	/* Attribute value to find */
	if (valuelen > 0 && value)
		memcpy(value, pdu + min_len, valuelen);

	if (vlen)
		*vlen = valuelen;

	return len;
}

uint16_t enc_find_by_type_resp(GSList *matches, uint8_t *pdu, int len)
{
	GSList *l;
	uint16_t offset;

	if (pdu == NULL || len < 5)
		return 0;

	pdu[0] = ATT_OP_FIND_BY_TYPE_RESP;

	for (l = matches, offset = 1; l && len >= (offset + 4);
					l = l->next, offset += 4) {
		struct att_range *range = l->data;

		att_put_u16(range->start, &pdu[offset]);
		att_put_u16(range->end, &pdu[offset + 2]);
	}

	return offset;
}

GSList *dec_find_by_type_resp(const uint8_t *pdu, int len)
{
	struct att_range *range;
	GSList *matches;
	int offset;

	if (pdu == NULL || len < 5)
		return NULL;

	if (pdu[0] != ATT_OP_FIND_BY_TYPE_RESP)
		return NULL;

	for (offset = 1, matches = NULL; len >= (offset + 4); offset += 4) {
		range = g_new0(struct att_range, 1);
		range->start = att_get_u16(&pdu[offset]);
		range->end = att_get_u16(&pdu[offset + 2]);

		matches = g_slist_append(matches, range);
	}

	return matches;
}

uint16_t enc_read_by_type_req(uint16_t start, uint16_t end, bt_uuid_t *uuid,
							uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(start) + sizeof(end);
	uint16_t length;

	if (!uuid)
		return 0;

	if (uuid->type == BT_UUID16)
		length = 2;
	else if (uuid->type == BT_UUID128)
		length = 16;
	else
		return 0;

	if (len < min_len + length)
		return 0;

	pdu[0] = ATT_OP_READ_BY_TYPE_REQ;
	att_put_u16(start, &pdu[1]);
	att_put_u16(end, &pdu[3]);

	att_put_uuid(*uuid, &pdu[5]);

	return min_len + length;
}

uint16_t dec_read_by_type_req(const uint8_t *pdu, int len, uint16_t *start,
						uint16_t *end, bt_uuid_t *uuid)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*start) + sizeof(*end);

	if (pdu == NULL)
		return 0;

	if (start == NULL || end == NULL || uuid == NULL)
		return 0;

	if (len < min_len + 2)
		return 0;

	if (pdu[0] != ATT_OP_READ_BY_TYPE_REQ)
		return 0;

	*start = att_get_u16(&pdu[1]);
	*end = att_get_u16(&pdu[3]);

	if (len == min_len + 2)
		*uuid = att_get_uuid16(&pdu[5]);
	else
		*uuid = att_get_uuid128(&pdu[5]);

	return len;
}

uint16_t enc_read_by_type_resp(struct att_data_list *list, uint8_t *pdu, int len)
{
	uint8_t *ptr;
	int i, w, l;

	if (list == NULL)
		return 0;

	if (pdu == NULL)
		return 0;

	l = MIN(len - 2, list->len);

	pdu[0] = ATT_OP_READ_BY_TYPE_RESP;
	pdu[1] = l;
	ptr = &pdu[2];

	for (i = 0, w = 2; i < list->num && w + l <= len; i++) {
		memcpy(ptr, list->data[i], l);
		ptr += l;
		w += l;
	}

	return w;
}

struct att_data_list *dec_read_by_type_resp(const uint8_t *pdu, int len)
{
	struct att_data_list *list;
	const uint8_t *ptr;
	uint16_t elen, num;
	int i;

	if (pdu[0] != ATT_OP_READ_BY_TYPE_RESP)
		return NULL;

	elen = pdu[1];
	num = (len - 2) / elen;
	list = att_data_list_alloc(num, elen);

	ptr = &pdu[2];

	for (i = 0; i < num; i++) {
		memcpy(list->data[i], ptr, list->len);
		ptr += list->len;
	}

	return list;
}

uint16_t enc_write_cmd(uint16_t handle, const uint8_t *value, int vlen,
							uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(handle);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (vlen > len - min_len)
		vlen = len - min_len;

	pdu[0] = ATT_OP_WRITE_CMD;
	att_put_u16(handle, &pdu[1]);

	if (vlen > 0) {
		memcpy(&pdu[3], value, vlen);
		return min_len + vlen;
	}

	return min_len;
}

uint16_t dec_write_cmd(const uint8_t *pdu, int len, uint16_t *handle,
						uint8_t *value, int *vlen)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*handle);

	if (pdu == NULL)
		return 0;

	if (value == NULL || vlen == NULL || handle == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (pdu[0] != ATT_OP_WRITE_CMD)
		return 0;

	*handle = att_get_u16(&pdu[1]);
	memcpy(value, pdu + min_len, len - min_len);
	*vlen = len - min_len;

	return len;
}

uint16_t enc_write_req(uint16_t handle, const uint8_t *value, int vlen,
							uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(handle);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (vlen > len - min_len)
		vlen = len - min_len;

	pdu[0] = ATT_OP_WRITE_REQ;
	att_put_u16(handle, &pdu[1]);

	if (vlen > 0) {
		memcpy(&pdu[3], value, vlen);
		return min_len + vlen;
	}

	return min_len;
}

uint16_t dec_write_req(const uint8_t *pdu, int len, uint16_t *handle,
						uint8_t *value, int *vlen)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*handle);

	if (pdu == NULL)
		return 0;

	if (value == NULL || vlen == NULL || handle == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (pdu[0] != ATT_OP_WRITE_REQ)
		return 0;

	*handle = att_get_u16(&pdu[1]);
	*vlen = len - min_len;
	if (*vlen > 0)
		memcpy(value, pdu + min_len, *vlen);

	return len;
}

uint16_t enc_write_resp(uint8_t *pdu, int len)
{
	if (pdu == NULL)
		return 0;

	pdu[0] = ATT_OP_WRITE_RESP;

	return sizeof(pdu[0]);
}

uint16_t dec_write_resp(const uint8_t *pdu, int len)
{
	if (pdu == NULL)
		return 0;

	if (pdu[0] != ATT_OP_WRITE_RESP)
		return 0;

	return len;
}

uint16_t enc_read_req(uint16_t handle, uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(handle);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	pdu[0] = ATT_OP_READ_REQ;
	att_put_u16(handle, &pdu[1]);

	return min_len;
}

uint16_t enc_read_blob_req(uint16_t handle, uint16_t offset, uint8_t *pdu,
									int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(handle) +
							sizeof(offset);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	pdu[0] = ATT_OP_READ_BLOB_REQ;
	att_put_u16(handle, &pdu[1]);
	att_put_u16(offset, &pdu[3]);

	return min_len;
}

uint16_t dec_read_req(const uint8_t *pdu, int len, uint16_t *handle)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*handle);

	if (pdu == NULL)
		return 0;

	if (handle == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (pdu[0] != ATT_OP_READ_REQ)
		return 0;

	*handle = att_get_u16(&pdu[1]);

	return min_len;
}

uint16_t dec_read_blob_req(const uint8_t *pdu, int len, uint16_t *handle,
							uint16_t *offset)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*handle) +
							sizeof(*offset);

	if (pdu == NULL)
		return 0;

	if (handle == NULL)
		return 0;

	if (offset == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (pdu[0] != ATT_OP_READ_BLOB_REQ)
		return 0;

	*handle = att_get_u16(&pdu[1]);
	*offset = att_get_u16(&pdu[3]);

	return min_len;
}

uint16_t enc_read_resp(uint8_t *value, int vlen, uint8_t *pdu, int len)
{
	if (pdu == NULL)
		return 0;

	/* If the attribute value length is longer than the allowed PDU size,
	 * send only the octets that fit on the PDU. The remaining octets can
	 * be requested using the Read Blob Request. */
	if (vlen > len - 1)
		vlen = len - 1;

	pdu[0] = ATT_OP_READ_RESP;

	memcpy(pdu + 1, value, vlen);

	return vlen + 1;
}

uint16_t enc_read_blob_resp(uint8_t *value, int vlen, uint16_t offset,
							uint8_t *pdu, int len)
{
	if (pdu == NULL)
		return 0;

	vlen -= offset;
	if (vlen > len - 1)
		vlen = len - 1;

	pdu[0] = ATT_OP_READ_BLOB_RESP;

	memcpy(pdu + 1, &value[offset], vlen);

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
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(opcode) +
						sizeof(handle) + sizeof(status);
	uint16_t u16;

	if (len < min_len)
		return 0;

	u16 = htobs(handle);
	pdu[0] = ATT_OP_ERROR;
	pdu[1] = opcode;
	memcpy(&pdu[2], &u16, sizeof(u16));
	pdu[4] = status;

	return min_len;
}

uint16_t enc_find_info_req(uint16_t start, uint16_t end, uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(start) + sizeof(end);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	pdu[0] = ATT_OP_FIND_INFO_REQ;
	att_put_u16(start, &pdu[1]);
	att_put_u16(end, &pdu[3]);

	return min_len;
}

uint16_t dec_find_info_req(const uint8_t *pdu, int len, uint16_t *start,
								uint16_t *end)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*start) + sizeof(*end);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (start == NULL || end == NULL)
		return 0;

	if (pdu[0] != ATT_OP_FIND_INFO_REQ)
		return 0;

	*start = att_get_u16(&pdu[1]);
	*end = att_get_u16(&pdu[3]);

	return min_len;
}

uint16_t enc_find_info_resp(uint8_t format, struct att_data_list *list,
							uint8_t *pdu, int len)
{
	uint8_t *ptr;
	int i, w;

	if (pdu == NULL)
		return 0;

	if (list == NULL)
		return 0;

	if (len < list->len + 2)
		return 0;

	pdu[0] = ATT_OP_FIND_INFO_RESP;
	pdu[1] = format;
	ptr = (void *) &pdu[2];

	for (i = 0, w = 2; i < list->num && w + list->len <= len; i++) {
		memcpy(ptr, list->data[i], list->len);
		ptr += list->len;
		w += list->len;
	}

	return w;
}

struct att_data_list *dec_find_info_resp(const uint8_t *pdu, int len,
							uint8_t *format)
{
	struct att_data_list *list;
	uint8_t *ptr;
	uint16_t elen, num;
	int i;

	if (pdu == NULL)
		return 0;

	if (format == NULL)
		return 0;

	if (pdu[0] != ATT_OP_FIND_INFO_RESP)
		return 0;

	*format = pdu[1];
	elen = sizeof(pdu[0]) + sizeof(*format);
	if (*format == 0x01)
		elen += 2;
	else if (*format == 0x02)
		elen += 16;

	num = (len - 2) / elen;

	ptr = (void *) &pdu[2];

	list = att_data_list_alloc(num, elen);

	for (i = 0; i < num; i++) {
		memcpy(list->data[i], ptr, list->len);
		ptr += list->len;
	}

	return list;
}

uint16_t enc_notification(struct attribute *a, uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(uint16_t);

	if (pdu == NULL)
		return 0;

	if (len < (a->len + min_len))
		return 0;

	pdu[0] = ATT_OP_HANDLE_NOTIFY;
	att_put_u16(a->handle, &pdu[1]);
	memcpy(&pdu[3], a->data, a->len);

	return a->len + min_len;
}

uint16_t enc_indication(struct attribute *a, uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(uint16_t);

	if (pdu == NULL)
		return 0;

	if (len < (a->len + min_len))
		return 0;

	pdu[0] = ATT_OP_HANDLE_IND;
	att_put_u16(a->handle, &pdu[1]);
	memcpy(&pdu[3], a->data, a->len);

	return a->len + min_len;
}

struct attribute *dec_indication(const uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(uint16_t);

	struct attribute *a;

	if (pdu == NULL)
		return NULL;

	if (pdu[0] != ATT_OP_HANDLE_IND)
		return NULL;

	if (len < min_len)
		return NULL;

	a = g_malloc0(sizeof(struct attribute) + len - min_len);
	a->len = len - min_len;

	a->handle = att_get_u16(&pdu[1]);
	memcpy(a->data, &pdu[3], a->len);

	return a;
}

uint16_t enc_confirmation(uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	pdu[0] = ATT_OP_HANDLE_CNF;

	return min_len;
}

uint16_t enc_mtu_req(uint16_t mtu, uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(mtu);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	pdu[0] = ATT_OP_MTU_REQ;
	att_put_u16(mtu, &pdu[1]);

	return min_len;
}

uint16_t dec_mtu_req(const uint8_t *pdu, int len, uint16_t *mtu)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*mtu);

	if (pdu == NULL)
		return 0;

	if (mtu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (pdu[0] != ATT_OP_MTU_REQ)
		return 0;

	*mtu = att_get_u16(&pdu[1]);

	return min_len;
}

uint16_t enc_mtu_resp(uint16_t mtu, uint8_t *pdu, int len)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(mtu);

	if (pdu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	pdu[0] = ATT_OP_MTU_RESP;
	att_put_u16(mtu, &pdu[1]);

	return min_len;
}

uint16_t dec_mtu_resp(const uint8_t *pdu, int len, uint16_t *mtu)
{
	const uint16_t min_len = sizeof(pdu[0]) + sizeof(*mtu);

	if (pdu == NULL)
		return 0;

	if (mtu == NULL)
		return 0;

	if (len < min_len)
		return 0;

	if (pdu[0] != ATT_OP_MTU_RESP)
		return 0;

	*mtu = att_get_u16(&pdu[1]);

	return min_len;
}
