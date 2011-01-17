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

#include <stdint.h>
#include <glib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "att.h"
#include "gattrib.h"
#include "gatt.h"

struct discover_primary {
	GAttrib *attrib;
	uuid_t uuid;
	GSList *primaries;
	gatt_cb_t cb;
	void *user_data;
};

struct discover_char {
	GAttrib *attrib;
	uuid_t uuid;
	uint16_t end;
	GSList *characteristics;
	gatt_cb_t cb;
	void *user_data;
};

static void discover_primary_free(struct discover_primary *dp)
{
	g_slist_free(dp->primaries);
	g_attrib_unref(dp->attrib);
	g_free(dp);
}

static void discover_char_free(struct discover_char *dc)
{
	g_slist_foreach(dc->characteristics, (GFunc) g_free, NULL);
	g_slist_free(dc->characteristics);
	g_attrib_unref(dc->attrib);
	g_free(dc);
}

static guint16 encode_discover_primary(uint16_t start, uint16_t end,
					uuid_t *uuid, uint8_t *pdu, size_t len)
{
	uuid_t prim;
	guint16 plen;
	uint8_t op;

	sdp_uuid16_create(&prim, GATT_PRIM_SVC_UUID);

	if (uuid == NULL) {
		/* Discover all primary services */
		op = ATT_OP_READ_BY_GROUP_REQ;
		plen = enc_read_by_grp_req(start, end, &prim, pdu, len);
	} else {
		const void *value;
		int vlen;

		/* Discover primary service by service UUID */
		op = ATT_OP_FIND_BY_TYPE_REQ;

		if (uuid->type == SDP_UUID16) {
			value = &uuid->value.uuid16;
			vlen = sizeof(uuid->value.uuid16);
		} else {
			value = &uuid->value.uuid128;
			vlen = sizeof(uuid->value.uuid128);
		}

		plen = enc_find_by_type_req(start, end, &prim, value, vlen,
								pdu, len);
	}

	return plen;
}

static void primary_by_uuid_cb(guint8 status, const guint8 *ipdu,
					guint16 iplen, gpointer user_data)

{
	struct discover_primary *dp = user_data;
	GSList *ranges, *last;
	struct att_range *range;
	uint8_t opdu[ATT_DEFAULT_MTU];
	guint16 oplen;
	int err = 0;

	if (status) {
		err = status == ATT_ECODE_ATTR_NOT_FOUND ? 0 : status;
		goto done;
	}

	ranges = dec_find_by_type_resp(ipdu, iplen);
	if (ranges == NULL)
		goto done;

	dp->primaries = g_slist_concat(dp->primaries, ranges);

	last = g_slist_last(ranges);
	g_slist_free(ranges);
	range = last->data;

	if (range->end == 0xffff)
		goto done;

	oplen = encode_discover_primary(range->end + 1, 0xffff, &dp->uuid,
							opdu, sizeof(opdu));

	if (oplen == 0)
		goto done;

	g_attrib_send(dp->attrib, 0, opdu[0], opdu, oplen, primary_by_uuid_cb,
								dp, NULL);
	return;

done:
	dp->cb(dp->primaries, err, dp->user_data);
	discover_primary_free(dp);
}

static void primary_all_cb(guint8 status, const guint8 *ipdu, guint16 iplen,
							gpointer user_data)
{
	struct discover_primary *dp = user_data;
	struct att_data_list *list;
	unsigned int i, err;
	uint16_t start, end;

	if (status) {
		err = status == ATT_ECODE_ATTR_NOT_FOUND ? 0 : status;
		goto done;
	}

	list = dec_read_by_grp_resp(ipdu, iplen);
	if (list == NULL) {
		err = ATT_ECODE_IO;
		goto done;
	}

	for (i = 0, end = 0; i < list->num; i++) {
		const uint8_t *data = list->data[i];
		struct att_primary *primary;
		uuid_t u128, u16;

		start = att_get_u16(&data[0]);
		end = att_get_u16(&data[2]);

		if (list->len == 6) {
			sdp_uuid16_create(&u16,
					att_get_u16(&data[4]));
			sdp_uuid16_to_uuid128(&u128, &u16);

		} else if (list->len == 20)
			sdp_uuid128_create(&u128, &data[4]);
		else
			/* Skipping invalid data */
			continue;

		primary = g_try_new0(struct att_primary, 1);
		if (!primary) {
			err = ATT_ECODE_INSUFF_RESOURCES;
			goto done;
		}
		primary->start = start;
		primary->end = end;
		sdp_uuid2strn(&u128, primary->uuid, sizeof(primary->uuid));
		dp->primaries = g_slist_append(dp->primaries, primary);
	}

	att_data_list_free(list);
	err = 0;

	if (end != 0xffff) {
		uint8_t opdu[ATT_DEFAULT_MTU];
		guint16 oplen = encode_discover_primary(end + 1, 0xffff, NULL,
							opdu, sizeof(opdu));

		g_attrib_send(dp->attrib, 0, opdu[0], opdu, oplen,
						primary_all_cb, dp, NULL);

		return;
	}

done:
	dp->cb(dp->primaries, err, dp->user_data);
	discover_primary_free(dp);
}

guint gatt_discover_primary(GAttrib *attrib, uuid_t *uuid, gatt_cb_t func,
							gpointer user_data)
{
	struct discover_primary *dp;
	uint8_t pdu[ATT_DEFAULT_MTU];
	GAttribResultFunc cb;
	guint16 plen;

	plen = encode_discover_primary(0x0001, 0xffff, uuid, pdu, sizeof(pdu));
	if (plen == 0)
		return 0;

	dp = g_try_new0(struct discover_primary, 1);
	if (dp == NULL)
		return 0;

	dp->attrib = g_attrib_ref(attrib);
	dp->cb = func;
	dp->user_data = user_data;

	if (uuid) {
		memcpy(&dp->uuid, uuid, sizeof(uuid_t));
		cb = primary_by_uuid_cb;
	} else
		cb = primary_all_cb;

	return g_attrib_send(attrib, 0, pdu[0], pdu, plen, cb, dp, NULL);
}

static void char_discovered_cb(guint8 status, const guint8 *ipdu, guint16 iplen,
							gpointer user_data)
{
	struct discover_char *dc = user_data;
	struct att_data_list *list;
	unsigned int i, err;
	uint8_t opdu[ATT_DEFAULT_MTU];
	guint16 oplen;
	uuid_t uuid;
	uint16_t last = 0;

	if (status) {
		err = status == ATT_ECODE_ATTR_NOT_FOUND ? 0 : status;
		goto done;
	}

	list = dec_read_by_type_resp(ipdu, iplen);
	if (list == NULL) {
		err = ATT_ECODE_IO;
		goto done;
	}

	for (i = 0; i < list->num; i++) {
		uint8_t *value = list->data[i];
		struct att_char *chars;
		uuid_t u128, u16;

		last = att_get_u16(value);

		if (list->len == 7) {
			sdp_uuid16_create(&u16, att_get_u16(&value[5]));
			sdp_uuid16_to_uuid128(&u128, &u16);
		} else
			sdp_uuid128_create(&u128, &value[5]);

		chars = g_try_new0(struct att_char, 1);
		if (!chars) {
			err = ATT_ECODE_INSUFF_RESOURCES;
			goto done;
		}

		chars->handle = last;
		chars->properties = value[2];
		chars->value_handle = att_get_u16(&value[3]);
		sdp_uuid2strn(&u128, chars->uuid, sizeof(chars->uuid));
		dc->characteristics = g_slist_append(dc->characteristics,
									chars);
	}

	att_data_list_free(list);
	err = 0;

	if (last != 0) {
		sdp_uuid16_create(&uuid, GATT_CHARAC_UUID);

		oplen = enc_read_by_type_req(last + 1, dc->end, &uuid, opdu,
								sizeof(opdu));

		if (oplen == 0)
			return;

		g_attrib_send(dc->attrib, 0, opdu[0], opdu, oplen,
						char_discovered_cb, dc, NULL);

		return;
	}

done:
	dc->cb(dc->characteristics, err, dc->user_data);
	discover_char_free(dc);
}

guint gatt_discover_char(GAttrib *attrib, uint16_t start, uint16_t end,
					gatt_cb_t func, gpointer user_data)
{
	uint8_t pdu[ATT_DEFAULT_MTU];
	struct discover_char *dc;
	guint16 plen;
	uuid_t uuid;

	sdp_uuid16_create(&uuid, GATT_CHARAC_UUID);

	plen = enc_read_by_type_req(start, end, &uuid, pdu, sizeof(pdu));
	if (plen == 0)
		return 0;

	dc = g_try_new0(struct discover_char, 1);
	if (dc == NULL)
		return 0;

	dc->attrib = g_attrib_ref(attrib);
	dc->cb = func;
	dc->user_data = user_data;
	dc->end = end;

	return g_attrib_send(attrib, 0, pdu[0], pdu, plen, char_discovered_cb,
								dc, NULL);
}

guint gatt_read_char_by_uuid(GAttrib *attrib, uint16_t start, uint16_t end,
					uuid_t *uuid, GAttribResultFunc func,
					gpointer user_data)
{
	uint8_t pdu[ATT_DEFAULT_MTU];
	guint16 plen;

	plen = enc_read_by_type_req(start, end, uuid, pdu, sizeof(pdu));
	if (plen == 0)
		return 0;

	return g_attrib_send(attrib, 0, ATT_OP_READ_BY_TYPE_REQ,
					pdu, plen, func, user_data, NULL);
}

struct read_long_data {
	GAttrib *attrib;
	GAttribResultFunc func;
	gpointer user_data;
	guint8 *buffer;
	guint16 size;
	guint16 handle;
	guint id;
	gint ref;
};

static void read_long_destroy(gpointer user_data)
{
	struct read_long_data *long_read = user_data;

	if (g_atomic_int_dec_and_test(&long_read->ref) == FALSE)
		return;

	if (long_read->buffer != NULL)
		g_free(long_read->buffer);

	g_free(long_read);
}

static void read_blob_helper(guint8 status, const guint8 *rpdu, guint16 rlen,
							gpointer user_data)
{
	struct read_long_data *long_read = user_data;
	uint8_t pdu[ATT_DEFAULT_MTU];
	guint8 *tmp;
	guint16 plen;
	guint id;

	if (status != 0 || rlen == 1) {
		status = 0;
		goto done;
	}

	tmp = g_try_realloc(long_read->buffer, long_read->size + rlen - 1);

	if (tmp == NULL) {
		status = ATT_ECODE_INSUFF_RESOURCES;
		goto done;
	}

	memcpy(&tmp[long_read->size], &rpdu[1], rlen - 1);
	long_read->buffer = tmp;
	long_read->size += rlen - 1;

	if (rlen < ATT_DEFAULT_MTU)
		goto done;

	plen = enc_read_blob_req(long_read->handle, long_read->size - 1,
							pdu, sizeof(pdu));
	id = g_attrib_send(long_read->attrib, long_read->id,
				ATT_OP_READ_BLOB_REQ, pdu, plen,
				read_blob_helper, long_read, read_long_destroy);

	if (id != 0) {
		g_atomic_int_inc(&long_read->ref);
		return;
	}

	status = ATT_ECODE_IO;

done:
	long_read->func(status, long_read->buffer, long_read->size,
							long_read->user_data);
}

static void read_char_helper(guint8 status, const guint8 *rpdu,
					guint16 rlen, gpointer user_data)
{
	struct read_long_data *long_read = user_data;
	uint8_t pdu[ATT_DEFAULT_MTU];
	guint16 plen;
	guint id;

	if (status != 0 || rlen < ATT_DEFAULT_MTU)
		goto done;

	long_read->buffer = g_malloc(rlen);

	if (long_read->buffer == NULL)
		goto done;

	memcpy(long_read->buffer, rpdu, rlen);
	long_read->size = rlen;

	plen = enc_read_blob_req(long_read->handle, rlen - 1, pdu, sizeof(pdu));
	id = g_attrib_send(long_read->attrib, long_read->id,
			ATT_OP_READ_BLOB_REQ, pdu, plen, read_blob_helper,
			long_read, read_long_destroy);

	if (id != 0) {
		g_atomic_int_inc(&long_read->ref);
		return;
	}

	status = ATT_ECODE_IO;

done:
	long_read->func(status, rpdu, rlen, long_read->user_data);
}

guint gatt_read_char(GAttrib *attrib, uint16_t handle, GAttribResultFunc func,
							gpointer user_data)
{
	uint8_t pdu[ATT_DEFAULT_MTU];
	guint16 plen;
	guint id;
	struct read_long_data *long_read;

	long_read = g_try_new0(struct read_long_data, 1);

	if (long_read == NULL)
		return 0;

	long_read->attrib = attrib;
	long_read->func = func;
	long_read->user_data = user_data;
	long_read->handle = handle;

	plen = enc_read_req(handle, pdu, sizeof(pdu));
	id = g_attrib_send(attrib, 0, ATT_OP_READ_REQ, pdu, plen,
				read_char_helper, long_read, read_long_destroy);

	if (id == 0)
		g_free(long_read);
	else {
		g_atomic_int_inc(&long_read->ref);
		long_read->id = id;
	}

	return id;
}

guint gatt_write_char(GAttrib *attrib, uint16_t handle, uint8_t *value,
			int vlen, GAttribResultFunc func, gpointer user_data)
{
	uint8_t pdu[ATT_DEFAULT_MTU];
	guint16 plen;

	plen = enc_write_req(handle, value, vlen, pdu, sizeof(pdu));
	return g_attrib_send(attrib, 0, ATT_OP_WRITE_REQ, pdu, plen, func,
							user_data, NULL);
}

guint gatt_find_info(GAttrib *attrib, uint16_t start, uint16_t end,
				GAttribResultFunc func, gpointer user_data)
{
	uint8_t pdu[ATT_DEFAULT_MTU];
	guint16 plen;

	plen = enc_find_info_req(start, end, pdu, sizeof(pdu));
	if (plen == 0)
		return 0;

	return g_attrib_send(attrib, 0, ATT_OP_FIND_INFO_REQ, pdu, plen, func,
							user_data, NULL);
}

guint gatt_write_cmd(GAttrib *attrib, uint16_t handle, uint8_t *value, int vlen,
				GDestroyNotify notify, gpointer user_data)
{
	uint8_t pdu[ATT_DEFAULT_MTU];
	guint16 plen;

	plen = enc_write_cmd(handle, value, vlen, pdu, sizeof(pdu));
	return g_attrib_send(attrib, 0, ATT_OP_WRITE_CMD, pdu, plen, NULL,
							user_data, notify);
}
