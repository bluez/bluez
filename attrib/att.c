/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
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
	case ATT_ECODE_UNSUPP_GRP_SIZE:
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

uint16_t att_read_by_grp_type_encode(uint16_t start, uint16_t end, uuid_t *uuid,
							uint8_t *pdu, int len)
{
	uint16_t *p16;

	/* FIXME: UUID128 is not supported */

	if (!uuid)
		return 0;

	if (uuid->type != SDP_UUID16)
		return 0;

	if (len < 7)
		return 0;

	pdu[0] = ATT_OP_READ_BY_GROUP_REQ;
	p16 = (void *) &pdu[1];
	*p16 = htobs(start);
	p16++;
	*p16 = htobs(end);
	p16++;
	*p16 = htobs(uuid->value.uuid16);

	return 7;
}

struct att_data_list *att_read_by_grp_type_decode(const uint8_t *pdu, int len)
{
	struct att_data_list *list;
	const uint8_t *ptr;
	int i;

	if (pdu[0] != ATT_OP_READ_BY_GROUP_RESP)
		return NULL;

	list = malloc(sizeof(struct att_data_list));
	list->len = pdu[1];
	list->num = len / list->len;

	list->data = malloc(sizeof(uint8_t *) * list->num);
	ptr = &pdu[2];

	for (i = 0; i < list->num; i++) {
		list->data[i] = malloc(sizeof(uint8_t) * list->len);
		memcpy(list->data[i], ptr, list->len);
		ptr += list->len;
	}

	return list;
}

uint16_t att_find_by_type_encode(uint16_t start, uint16_t end, uuid_t *uuid,
							uint8_t *pdu, int len)
{
	return 0;
}
