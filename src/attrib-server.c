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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "log.h"
#include "glib-helper.h"
#include "btio.h"
#include "sdpd.h"
#include "hcid.h"
#include "att.h"
#include "gattrib.h"

#include "attrib-server.h"

static GSList *database = NULL;

struct gatt_channel {
	bdaddr_t src;
	bdaddr_t dst;
	GSList *configs;
	GSList *notify;
	GSList *indicate;
	GAttrib *attrib;
	guint mtu;
	gboolean le;
	guint id;
	gboolean encrypted;
};

struct group_elem {
	uint16_t handle;
	uint16_t end;
	uint8_t *data;
	uint16_t len;
};

static GIOChannel *l2cap_io = NULL;
static GIOChannel *le_io = NULL;
static GSList *clients = NULL;
static uint32_t gatt_sdp_handle = 0;
static uint32_t gap_sdp_handle = 0;

/* GAP attribute handles */
static uint16_t name_handle = 0x0000;
static uint16_t appearance_handle = 0x0000;

static bt_uuid_t prim_uuid = {
			.type = BT_UUID16,
			.value.u16 = GATT_PRIM_SVC_UUID
};
static bt_uuid_t snd_uuid = {
			.type = BT_UUID16,
			.value.u16 = GATT_SND_SVC_UUID
};

static sdp_record_t *server_record_new(uuid_t *uuid, uint16_t start, uint16_t end)
{
	sdp_list_t *svclass_id, *apseq, *proto[2], *root, *aproto;
	uuid_t root_uuid, proto_uuid, l2cap;
	sdp_record_t *record;
	sdp_data_t *psm, *sh, *eh;
	uint16_t lp = ATT_PSM;

	if (uuid == NULL)
		return NULL;

	if (start > end)
		return NULL;

	record = sdp_record_alloc();
	if (record == NULL)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);
	sdp_list_free(root, NULL);

	svclass_id = sdp_list_append(NULL, uuid);
	sdp_set_service_classes(record, svclass_id);
	sdp_list_free(svclass_id, NULL);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto[0] = sdp_list_append(proto[0], psm);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&proto_uuid, ATT_UUID);
	proto[1] = sdp_list_append(NULL, &proto_uuid);
	sh = sdp_data_alloc(SDP_UINT16, &start);
	proto[1] = sdp_list_append(proto[1], sh);
	eh = sdp_data_alloc(SDP_UINT16, &end);
	proto[1] = sdp_list_append(proto[1], eh);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_data_free(psm);
	sdp_data_free(sh);
	sdp_data_free(eh);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);

	return record;
}

static int handle_cmp(gconstpointer a, gconstpointer b)
{
	const struct attribute *attrib = a;
	uint16_t handle = GPOINTER_TO_UINT(b);

	return attrib->handle - handle;
}

static int attribute_cmp(gconstpointer a1, gconstpointer a2)
{
	const struct attribute *attrib1 = a1;
	const struct attribute *attrib2 = a2;

	return attrib1->handle - attrib2->handle;
}

static uint8_t att_check_reqs(struct gatt_channel *channel, uint8_t opcode,
								int reqs)
{
	/* FIXME: currently, it is assumed an encrypted link is enough for
	 * authentication. This will allow to enable the SMP negotiation once
	 * it is on upstream kernel. High security level should be mapped
	 * to authentication and medium to encryption permission. */
	if (!channel->encrypted)
		channel->encrypted = g_attrib_is_encrypted(channel->attrib);
	if (reqs == ATT_AUTHENTICATION && !channel->encrypted)
		return ATT_ECODE_AUTHENTICATION;
	else if (reqs == ATT_AUTHORIZATION)
		return ATT_ECODE_AUTHORIZATION;

	switch (opcode) {
	case ATT_OP_READ_BY_GROUP_REQ:
	case ATT_OP_READ_BY_TYPE_REQ:
	case ATT_OP_READ_REQ:
	case ATT_OP_READ_BLOB_REQ:
	case ATT_OP_READ_MULTI_REQ:
		if (reqs == ATT_NOT_PERMITTED)
			return ATT_ECODE_READ_NOT_PERM;
		break;
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_WRITE_REQ:
	case ATT_OP_WRITE_CMD:
		if (reqs == ATT_NOT_PERMITTED)
			return ATT_ECODE_WRITE_NOT_PERM;
		break;
	}

	return 0;
}

static uint8_t client_set_notifications(struct attribute *attr,
							gpointer user_data)
{
	struct gatt_channel *channel = user_data;
	struct attribute *last_chr_val = NULL;
	uint16_t cfg_val;
	uint8_t props;
	bt_uuid_t uuid;
	GSList *l;

	cfg_val = att_get_u16(attr->data);

	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	for (l = database, props = 0; l != NULL; l = l->next) {
		struct attribute *a = l->data;
		static uint16_t handle = 0;

		if (a->handle >= attr->handle)
			break;

		if (bt_uuid_cmp(&a->uuid, &uuid) == 0) {
			props = att_get_u8(&a->data[0]);
			handle = att_get_u16(&a->data[1]);
			continue;
		}

		if (handle && a->handle == handle)
			last_chr_val = a;
	}

	if (last_chr_val == NULL)
		return 0;

	if ((cfg_val & 0x0001) && !(props & ATT_CHAR_PROPER_NOTIFY))
		return ATT_ECODE_WRITE_NOT_PERM;

	if ((cfg_val & 0x0002) && !(props & ATT_CHAR_PROPER_INDICATE))
		return ATT_ECODE_WRITE_NOT_PERM;

	if (cfg_val & 0x0001)
		channel->notify = g_slist_append(channel->notify, last_chr_val);
	else
		channel->notify = g_slist_remove(channel->notify, last_chr_val);

	if (cfg_val & 0x0002)
		channel->indicate = g_slist_append(channel->indicate,
								last_chr_val);
	else
		channel->indicate = g_slist_remove(channel->indicate,
								last_chr_val);

	return 0;
}

static struct attribute *client_cfg_attribute(struct gatt_channel *channel,
						struct attribute *orig_attr,
						const uint8_t *value, int vlen)
{
	guint handle = orig_attr->handle;
	bt_uuid_t uuid;
	GSList *l;

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	if (bt_uuid_cmp(&orig_attr->uuid, &uuid) != 0)
		return NULL;

	/* Value is unchanged, not need to create a private copy yet */
	if (vlen == orig_attr->len && memcmp(orig_attr->data, value, vlen) == 0)
		return orig_attr;

	l = g_slist_find_custom(channel->configs, GUINT_TO_POINTER(handle),
								handle_cmp);
	if (!l) {
		struct attribute *a;

		/* Create a private copy of the Client Characteristic
		 * Configuration attribute */
		a = g_malloc0(sizeof(*a) + vlen);
		memcpy(a, orig_attr, sizeof(*a));
		memcpy(a->data, value, vlen);
		a->write_cb = client_set_notifications;
		a->cb_user_data = channel;

		channel->configs = g_slist_insert_sorted(channel->configs, a,
								attribute_cmp);

		return a;
	}

	return l->data;
}

static uint16_t read_by_group(struct gatt_channel *channel, uint16_t start,
						uint16_t end, bt_uuid_t *uuid,
						uint8_t *pdu, int len)
{
	struct att_data_list *adl;
	struct attribute *a;
	struct group_elem *cur, *old = NULL;
	GSList *l, *groups;
	uint16_t length, last_handle, last_size = 0;
	uint8_t status;
	int i;

	if (start > end || start == 0x0000)
		return enc_error_resp(ATT_OP_READ_BY_GROUP_REQ, start,
					ATT_ECODE_INVALID_HANDLE, pdu, len);

	/*
	 * Only <<Primary Service>> and <<Secondary Service>> grouping
	 * types may be used in the Read By Group Type Request.
	 */

	if (bt_uuid_cmp(uuid, &prim_uuid) != 0 &&
		bt_uuid_cmp(uuid, &snd_uuid) != 0)
		return enc_error_resp(ATT_OP_READ_BY_GROUP_REQ, 0x0000,
					ATT_ECODE_UNSUPP_GRP_TYPE, pdu, len);

	last_handle = end;
	for (l = database, groups = NULL, cur = NULL; l; l = l->next) {
		struct attribute *client_attr;

		a = l->data;

		if (a->handle < start)
			continue;

		if (a->handle >= end)
			break;

		/* The old group ends when a new one starts */
		if (old && (bt_uuid_cmp(&a->uuid, &prim_uuid) == 0 ||
				bt_uuid_cmp(&a->uuid, &snd_uuid) == 0)) {
			old->end = last_handle;
			old = NULL;
		}

		if (bt_uuid_cmp(&a->uuid, uuid) != 0) {
			/* Still inside a service, update its last handle */
			if (old)
				last_handle = a->handle;
			continue;
		}

		if (last_size && (last_size != a->len))
			break;

		status = att_check_reqs(channel, ATT_OP_READ_BY_GROUP_REQ,
								a->read_reqs);

		client_attr = client_cfg_attribute(channel, a, a->data, a->len);
		if (client_attr)
			a = client_attr;

		if (status == 0x00 && a->read_cb)
			status = a->read_cb(a, a->cb_user_data);

		if (status) {
			g_slist_foreach(groups, (GFunc) g_free, NULL);
			g_slist_free(groups);
			return enc_error_resp(ATT_OP_READ_BY_GROUP_REQ,
						a->handle, status, pdu, len);
		}

		cur = g_new0(struct group_elem, 1);
		cur->handle = a->handle;
		cur->data = a->data;
		cur->len = a->len;

		/* Attribute Grouping Type found */
		groups = g_slist_append(groups, cur);

		last_size = a->len;
		old = cur;
		last_handle = cur->handle;
	}

	if (groups == NULL)
		return enc_error_resp(ATT_OP_READ_BY_GROUP_REQ, start,
					ATT_ECODE_ATTR_NOT_FOUND, pdu, len);

	if (l == NULL)
		cur->end = a->handle;
	else
		cur->end = last_handle;

	length = g_slist_length(groups);

	adl = att_data_list_alloc(length, last_size + 4);

	for (i = 0, l = groups; l; l = l->next, i++) {
		uint8_t *value;

		cur = l->data;

		value = (void *) adl->data[i];

		att_put_u16(cur->handle, value);
		att_put_u16(cur->end, &value[2]);
		/* Attribute Value */
		memcpy(&value[4], cur->data, cur->len);
	}

	length = enc_read_by_grp_resp(adl, pdu, len);

	att_data_list_free(adl);
	g_slist_foreach(groups, (GFunc) g_free, NULL);
	g_slist_free(groups);

	return length;
}

static uint16_t read_by_type(struct gatt_channel *channel, uint16_t start,
						uint16_t end, bt_uuid_t *uuid,
						uint8_t *pdu, int len)
{
	struct att_data_list *adl;
	GSList *l, *types;
	struct attribute *a;
	uint16_t num, length;
	uint8_t status;
	int i;

	if (start > end || start == 0x0000)
		return enc_error_resp(ATT_OP_READ_BY_TYPE_REQ, start,
					ATT_ECODE_INVALID_HANDLE, pdu, len);

	for (l = database, length = 0, types = NULL; l; l = l->next) {
		struct attribute *client_attr;

		a = l->data;

		if (a->handle < start)
			continue;

		if (a->handle > end)
			break;

		if (bt_uuid_cmp(&a->uuid, uuid)  != 0)
			continue;

		status = att_check_reqs(channel, ATT_OP_READ_BY_TYPE_REQ,
								a->read_reqs);

		client_attr = client_cfg_attribute(channel, a, a->data, a->len);
		if (client_attr)
			a = client_attr;

		if (status == 0x00 && a->read_cb)
			status = a->read_cb(a, a->cb_user_data);

		if (status) {
			g_slist_free(types);
			return enc_error_resp(ATT_OP_READ_BY_TYPE_REQ,
						a->handle, status, pdu, len);
		}

		/* All elements must have the same length */
		if (length == 0)
			length = a->len;
		else if (a->len != length)
			break;

		types = g_slist_append(types, a);
	}

	if (types == NULL)
		return enc_error_resp(ATT_OP_READ_BY_TYPE_REQ, start,
					ATT_ECODE_ATTR_NOT_FOUND, pdu, len);

	num = g_slist_length(types);

	/* Handle length plus attribute value length */
	length += 2;

	adl = att_data_list_alloc(num, length);

	for (i = 0, l = types; l; i++, l = l->next) {
		uint8_t *value;

		a = l->data;

		value = (void *) adl->data[i];

		att_put_u16(a->handle, value);

		/* Attribute Value */
		memcpy(&value[2], a->data, a->len);
	}

	length = enc_read_by_type_resp(adl, pdu, len);

	att_data_list_free(adl);
	g_slist_free(types);

	return length;
}

static int find_info(uint16_t start, uint16_t end, uint8_t *pdu, int len)
{
	struct attribute *a;
	struct att_data_list *adl;
	GSList *l, *info;
	uint8_t format, last_type = BT_UUID_UNSPEC;
	uint16_t length, num;
	int i;

	if (start > end || start == 0x0000)
		return enc_error_resp(ATT_OP_FIND_INFO_REQ, start,
					ATT_ECODE_INVALID_HANDLE, pdu, len);

	for (l = database, info = NULL, num = 0; l; l = l->next) {
		a = l->data;

		if (a->handle < start)
			continue;

		if (a->handle > end)
			break;

		if (last_type == BT_UUID_UNSPEC)
			last_type = a->uuid.type;

		if (a->uuid.type != last_type)
			break;

		info = g_slist_append(info, a);
		num++;

		last_type = a->uuid.type;
	}

	if (info == NULL)
		return enc_error_resp(ATT_OP_FIND_INFO_REQ, start,
					ATT_ECODE_ATTR_NOT_FOUND, pdu, len);

	if (last_type == BT_UUID16) {
		length = 2;
		format = 0x01;
	} else if (last_type == BT_UUID128) {
		length = 16;
		format = 0x02;
	} else {
		g_slist_free(info);
		return 0;
	}

	adl = att_data_list_alloc(num, length + 2);

	for (i = 0, l = info; l; i++, l = l->next) {
		uint8_t *value;

		a = l->data;

		value = (void *) adl->data[i];

		att_put_u16(a->handle, value);

		/* Attribute Value */
		att_put_uuid(a->uuid, &value[2]);
	}

	length = enc_find_info_resp(format, adl, pdu, len);

	att_data_list_free(adl);
	g_slist_free(info);

	return length;
}

static int find_by_type(uint16_t start, uint16_t end, bt_uuid_t *uuid,
			const uint8_t *value, int vlen, uint8_t *opdu, int mtu)
{
	struct attribute *a;
	struct att_range *range;
	GSList *l, *matches;
	int len;

	if (start > end || start == 0x0000)
		return enc_error_resp(ATT_OP_FIND_BY_TYPE_REQ, start,
					ATT_ECODE_INVALID_HANDLE, opdu, mtu);

	/* Searching first requested handle number */
	for (l = database, matches = NULL, range = NULL; l; l = l->next) {
		a = l->data;

		if (a->handle < start)
			continue;

		if (a->handle > end)
			break;

		/* Primary service? Attribute value matches? */
		if ((bt_uuid_cmp(&a->uuid, uuid) == 0) && (a->len == vlen) &&
					(memcmp(a->data, value, vlen) == 0)) {

			range = g_new0(struct att_range, 1);
			range->start = a->handle;
			/* It is allowed to have end group handle the same as
			 * start handle, for groups with only one attribute. */
			range->end = a->handle;

			matches = g_slist_append(matches, range);
		} else if (range) {
			/* Update the last found handle or reset the pointer
			 * to track that a new group started: Primary or
			 * Secondary service. */
			if (bt_uuid_cmp(&a->uuid, &prim_uuid) == 0 ||
					bt_uuid_cmp(&a->uuid, &snd_uuid) == 0)
				range = NULL;
			else
				range->end = a->handle;
		}
	}

	if (matches == NULL)
		return enc_error_resp(ATT_OP_FIND_BY_TYPE_REQ, start,
				ATT_ECODE_ATTR_NOT_FOUND, opdu, mtu);

	len = enc_find_by_type_resp(matches, opdu, mtu);

	g_slist_foreach(matches, (GFunc) g_free, NULL);
	g_slist_free(matches);

	return len;
}

static struct attribute *find_primary_range(uint16_t start, uint16_t *end)
{
	struct attribute *attrib;
	guint h = start;
	GSList *l;

	if (end == NULL)
		return NULL;

	l = g_slist_find_custom(database, GUINT_TO_POINTER(h), handle_cmp);
	if (!l)
		return NULL;

	attrib = l->data;

	if (bt_uuid_cmp(&attrib->uuid, &prim_uuid) != 0)
		return NULL;

	*end = start;

	for (l = l->next; l; l = l->next) {
		struct attribute *a = l->data;

		if (bt_uuid_cmp(&a->uuid, &prim_uuid) == 0 ||
				bt_uuid_cmp(&a->uuid, &snd_uuid) == 0)
			break;

		*end = a->handle;
	}

	return attrib;
}

static uint16_t read_value(struct gatt_channel *channel, uint16_t handle,
							uint8_t *pdu, int len)
{
	struct attribute *a, *client_attr;
	uint8_t status;
	GSList *l;
	guint h = handle;

	l = g_slist_find_custom(database, GUINT_TO_POINTER(h), handle_cmp);
	if (!l)
		return enc_error_resp(ATT_OP_READ_REQ, handle,
					ATT_ECODE_INVALID_HANDLE, pdu, len);

	a = l->data;

	status = att_check_reqs(channel, ATT_OP_READ_REQ, a->read_reqs);

	client_attr = client_cfg_attribute(channel, a, a->data, a->len);
	if (client_attr)
		a = client_attr;

	if (status == 0x00 && a->read_cb)
		status = a->read_cb(a, a->cb_user_data);

	if (status)
		return enc_error_resp(ATT_OP_READ_REQ, handle, status, pdu,
									len);

	return enc_read_resp(a->data, a->len, pdu, len);
}

static uint16_t read_blob(struct gatt_channel *channel, uint16_t handle,
					uint16_t offset, uint8_t *pdu, int len)
{
	struct attribute *a, *client_attr;
	uint8_t status;
	GSList *l;
	guint h = handle;

	l = g_slist_find_custom(database, GUINT_TO_POINTER(h), handle_cmp);
	if (!l)
		return enc_error_resp(ATT_OP_READ_BLOB_REQ, handle,
					ATT_ECODE_INVALID_HANDLE, pdu, len);

	a = l->data;

	if (a->len <= offset)
		return enc_error_resp(ATT_OP_READ_BLOB_REQ, handle,
					ATT_ECODE_INVALID_OFFSET, pdu, len);

	status = att_check_reqs(channel, ATT_OP_READ_BLOB_REQ, a->read_reqs);

	client_attr = client_cfg_attribute(channel, a, a->data, a->len);
	if (client_attr)
		a = client_attr;

	if (status == 0x00 && a->read_cb)
		status = a->read_cb(a, a->cb_user_data);

	if (status)
		return enc_error_resp(ATT_OP_READ_BLOB_REQ, handle, status,
								pdu, len);

	return enc_read_blob_resp(a->data, a->len, offset, pdu, len);
}

static uint16_t write_value(struct gatt_channel *channel, uint16_t handle,
						const uint8_t *value, int vlen,
						uint8_t *pdu, int len)
{
	struct attribute *a, *client_attr;
	uint8_t status;
	GSList *l;
	guint h = handle;

	l = g_slist_find_custom(database, GUINT_TO_POINTER(h), handle_cmp);
	if (!l)
		return enc_error_resp(ATT_OP_WRITE_REQ, handle,
				ATT_ECODE_INVALID_HANDLE, pdu, len);

	a = l->data;

	status = att_check_reqs(channel, ATT_OP_WRITE_REQ, a->write_reqs);
	if (status)
		return enc_error_resp(ATT_OP_WRITE_REQ, handle, status, pdu,
									len);

	client_attr = client_cfg_attribute(channel, a, value, vlen);
	if (client_attr)
		a = client_attr;
	else
		attrib_db_update(a->handle, NULL, value, vlen, &a);

	if (a->write_cb) {
		status = a->write_cb(a, a->cb_user_data);
		if (status)
			return enc_error_resp(ATT_OP_WRITE_REQ, handle, status,
								pdu, len);
	}

	DBG("Notifications: %d, indications: %d",
					g_slist_length(channel->notify),
					g_slist_length(channel->indicate));

	return enc_write_resp(pdu, len);
}

static uint16_t mtu_exchange(struct gatt_channel *channel, uint16_t mtu,
		uint8_t *pdu, int len)
{
	guint old_mtu = channel->mtu;

	if (mtu < ATT_DEFAULT_LE_MTU)
		channel->mtu = ATT_DEFAULT_LE_MTU;
	else
		channel->mtu = MIN(mtu, channel->mtu);

	bt_io_set(le_io, BT_IO_L2CAP, NULL,
			BT_IO_OPT_OMTU, channel->mtu,
			BT_IO_OPT_INVALID);

	return enc_mtu_resp(old_mtu, pdu, len);
}

static void channel_disconnect(void *user_data)
{
	struct gatt_channel *channel = user_data;

	g_attrib_unref(channel->attrib);
	clients = g_slist_remove(clients, channel);

	g_slist_free(channel->notify);
	g_slist_free(channel->indicate);
	g_slist_foreach(channel->configs, (GFunc) g_free, NULL);
	g_slist_free(channel->configs);

	g_free(channel);
}

static void channel_handler(const uint8_t *ipdu, uint16_t len,
							gpointer user_data)
{
	struct gatt_channel *channel = user_data;
	uint8_t opdu[ATT_MAX_MTU], value[ATT_MAX_MTU];
	uint16_t length, start, end, mtu, offset;
	bt_uuid_t uuid;
	uint8_t status = 0;
	int vlen;

	DBG("op 0x%02x", ipdu[0]);

	switch (ipdu[0]) {
	case ATT_OP_READ_BY_GROUP_REQ:
		length = dec_read_by_grp_req(ipdu, len, &start, &end, &uuid);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = read_by_group(channel, start, end, &uuid, opdu,
								channel->mtu);
		break;
	case ATT_OP_READ_BY_TYPE_REQ:
		length = dec_read_by_type_req(ipdu, len, &start, &end, &uuid);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = read_by_type(channel, start, end, &uuid, opdu,
								channel->mtu);
		break;
	case ATT_OP_READ_REQ:
		length = dec_read_req(ipdu, len, &start);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = read_value(channel, start, opdu, channel->mtu);
		break;
	case ATT_OP_READ_BLOB_REQ:
		length = dec_read_blob_req(ipdu, len, &start, &offset);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = read_blob(channel, start, offset, opdu, channel->mtu);
		break;
	case ATT_OP_MTU_REQ:
		if (!channel->le) {
			status = ATT_ECODE_REQ_NOT_SUPP;
			goto done;
		}

		length = dec_mtu_req(ipdu, len, &mtu);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = mtu_exchange(channel, mtu, opdu, channel->mtu);
		break;
	case ATT_OP_FIND_INFO_REQ:
		length = dec_find_info_req(ipdu, len, &start, &end);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = find_info(start, end, opdu, channel->mtu);
		break;
	case ATT_OP_WRITE_REQ:
		length = dec_write_req(ipdu, len, &start, value, &vlen);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = write_value(channel, start, value, vlen, opdu,
								channel->mtu);
		break;
	case ATT_OP_WRITE_CMD:
		length = dec_write_cmd(ipdu, len, &start, value, &vlen);
		if (length > 0)
			write_value(channel, start, value, vlen, opdu,
								channel->mtu);
		return;
	case ATT_OP_FIND_BY_TYPE_REQ:
		length = dec_find_by_type_req(ipdu, len, &start, &end,
							&uuid, value, &vlen);
		if (length == 0) {
			status = ATT_ECODE_INVALID_PDU;
			goto done;
		}

		length = find_by_type(start, end, &uuid, value, vlen,
							opdu, channel->mtu);
		break;
	case ATT_OP_HANDLE_CNF:
		return;
	case ATT_OP_READ_MULTI_REQ:
	case ATT_OP_PREP_WRITE_REQ:
	case ATT_OP_EXEC_WRITE_REQ:
	default:
		DBG("Unsupported request 0x%02x", ipdu[0]);
		status = ATT_ECODE_REQ_NOT_SUPP;
		goto done;
	}

	if (length == 0)
		status = ATT_ECODE_IO;

done:
	if (status)
		length = enc_error_resp(ipdu[0], 0x0000, status, opdu,
								channel->mtu);

	g_attrib_send(channel->attrib, 0, opdu[0], opdu, length,
							NULL, NULL, NULL);
}

static void connect_event(GIOChannel *io, GError *err, void *user_data)
{
	struct gatt_channel *channel;
	uint16_t cid;
	GError *gerr = NULL;

	if (err) {
		error("%s", err->message);
		return;
	}

	channel = g_new0(struct gatt_channel, 1);

	bt_io_get(io, BT_IO_L2CAP, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &channel->src,
			BT_IO_OPT_DEST_BDADDR, &channel->dst,
			BT_IO_OPT_CID, &cid,
			BT_IO_OPT_OMTU, &channel->mtu,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("bt_io_get: %s", gerr->message);
		g_error_free(gerr);
		g_free(channel);
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	if (channel->mtu > ATT_MAX_MTU)
		channel->mtu = ATT_MAX_MTU;

	if (cid != ATT_CID)
		channel->le = FALSE;
	else
		channel->le = TRUE;

	channel->attrib = g_attrib_new(io);
	g_io_channel_unref(io);

	channel->id = g_attrib_register(channel->attrib, GATTRIB_ALL_EVENTS,
				channel_handler, channel, NULL);

	g_attrib_set_disconnect_function(channel->attrib, channel_disconnect,
								channel);

	clients = g_slist_append(clients, channel);
}

static void confirm_event(GIOChannel *io, void *user_data)
{
	GError *gerr = NULL;

	if (bt_io_accept(io, connect_event, user_data, NULL, &gerr) == FALSE) {
		error("bt_io_accept: %s", gerr->message);
		g_error_free(gerr);
		g_io_channel_unref(io);
	}

	return;
}

static void attrib_notify_clients(struct attribute *attr)
{
	guint handle = attr->handle;
	GSList *l;

	for (l = clients; l; l = l->next) {
		struct gatt_channel *channel = l->data;

		/* Notification */
		if (g_slist_find_custom(channel->notify,
					GUINT_TO_POINTER(handle), handle_cmp)) {
			uint8_t pdu[ATT_MAX_MTU];
			uint16_t len;

			len = enc_notification(attr, pdu, channel->mtu);
			if (len == 0)
				continue;

			g_attrib_send(channel->attrib, 0, pdu[0], pdu, len,
							NULL, NULL, NULL);
		}

		/* Indication */
		if (g_slist_find_custom(channel->indicate,
					GUINT_TO_POINTER(handle), handle_cmp)) {
			uint8_t pdu[ATT_MAX_MTU];
			uint16_t len;

			len = enc_indication(attr, pdu, channel->mtu);
			if (len == 0)
				return;

			g_attrib_send(channel->attrib, 0, pdu[0], pdu, len,
							NULL, NULL, NULL);
		}
	}
}

static gboolean register_core_services(void)
{
	uint8_t atval[256];
	bt_uuid_t uuid;
	uint16_t appearance = 0x0000;

	/* GAP service: primary service definition */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	att_put_u16(GENERIC_ACCESS_PROFILE_ID, &atval[0]);
	attrib_db_add(0x0001, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	/* GAP service: device name characteristic */
	name_handle = 0x0006;
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(name_handle, &atval[1]);
	att_put_u16(GATT_CHARAC_DEVICE_NAME, &atval[3]);
	attrib_db_add(0x0004, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* GAP service: device name attribute */
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	attrib_db_add(name_handle, &uuid, ATT_NONE, ATT_NOT_PERMITTED,
								NULL, 0);

	/* GAP service: device appearance characteristic */
	appearance_handle = 0x0008;
	bt_uuid16_create(&uuid, GATT_CHARAC_UUID);
	atval[0] = ATT_CHAR_PROPER_READ;
	att_put_u16(appearance_handle, &atval[1]);
	att_put_u16(GATT_CHARAC_APPEARANCE, &atval[3]);
	attrib_db_add(0x0007, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 5);

	/* GAP service: device appearance attribute */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	att_put_u16(appearance, &atval[0]);
	attrib_db_add(appearance_handle, &uuid, ATT_NONE, ATT_NOT_PERMITTED,
								atval, 2);
	gap_sdp_handle = attrib_create_sdp(0x0001, "Generic Access Profile");
	if (gap_sdp_handle == 0) {
		error("Failed to register GAP service record");
		goto failed;
	}

	/* GATT service: primary service definition */
	bt_uuid16_create(&uuid, GATT_PRIM_SVC_UUID);
	att_put_u16(GENERIC_ATTRIB_PROFILE_ID, &atval[0]);
	attrib_db_add(0x0010, &uuid, ATT_NONE, ATT_NOT_PERMITTED, atval, 2);

	gatt_sdp_handle = attrib_create_sdp(0x0010,
						"Generic Attribute Profile");
	if (gatt_sdp_handle == 0) {
		error("Failed to register GATT service record");
		goto failed;
	}

	return TRUE;

failed:
	if (gap_sdp_handle)
		remove_record_from_server(gap_sdp_handle);

	return FALSE;
}

int attrib_server_init(void)
{
	GError *gerr = NULL;

	/* BR/EDR socket */
	l2cap_io = bt_io_listen(BT_IO_L2CAP, NULL, confirm_event,
					NULL, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, BDADDR_ANY,
					BT_IO_OPT_PSM, ATT_PSM,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (l2cap_io == NULL) {
		error("%s", gerr->message);
		g_error_free(gerr);
		return -1;
	}

	if (!register_core_services())
		goto failed;

	if (!main_opts.le)
		return 0;

	/* LE socket */
	le_io = bt_io_listen(BT_IO_L2CAP, NULL, confirm_event,
					&le_io, NULL, &gerr,
					BT_IO_OPT_SOURCE_BDADDR, BDADDR_ANY,
					BT_IO_OPT_CID, ATT_CID,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
					BT_IO_OPT_INVALID);
	if (le_io == NULL) {
		error("%s", gerr->message);
		g_error_free(gerr);
		/* Doesn't have LE support, continue */
	}

	return 0;

failed:
	g_io_channel_unref(l2cap_io);
	l2cap_io = NULL;

	if (le_io) {
		g_io_channel_unref(le_io);
		le_io = NULL;
	}

	return -1;
}

void attrib_server_exit(void)
{
	GSList *l;

	g_slist_foreach(database, (GFunc) g_free, NULL);
	g_slist_free(database);

	if (l2cap_io) {
		g_io_channel_unref(l2cap_io);
		g_io_channel_shutdown(l2cap_io, FALSE, NULL);
	}

	if (le_io) {
		g_io_channel_unref(le_io);
		g_io_channel_shutdown(le_io, FALSE, NULL);
	}

	for (l = clients; l; l = l->next) {
		struct gatt_channel *channel = l->data;

		g_slist_free(channel->notify);
		g_slist_free(channel->indicate);
		g_slist_foreach(channel->configs, (GFunc) g_free, NULL);
		g_slist_free(channel->configs);

		g_attrib_unref(channel->attrib);
		g_free(channel);
	}

	g_slist_free(clients);

	if (gatt_sdp_handle)
		remove_record_from_server(gatt_sdp_handle);

	if (gap_sdp_handle)
		remove_record_from_server(gap_sdp_handle);
}

uint32_t attrib_create_sdp(uint16_t handle, const char *name)
{
	sdp_record_t *record;
	struct attribute *a;
	uint16_t end = 0;
	uuid_t svc, gap_uuid;

	a = find_primary_range(handle, &end);

	if (a == NULL)
		return 0;

	if (a->len == 2)
		sdp_uuid16_create(&svc, att_get_u16(a->data));
	else if (a->len == 16)
		sdp_uuid128_create(&svc, a->data);
	else
		return 0;

	record = server_record_new(&svc, handle, end);
	if (record == NULL)
		return 0;

	if (name)
		sdp_set_info_attr(record, name, "BlueZ", NULL);

	sdp_uuid16_create(&gap_uuid, GENERIC_ACCESS_PROFILE_ID);
	if (sdp_uuid_cmp(&svc, &gap_uuid) == 0) {
		sdp_set_url_attr(record, "http://www.bluez.org/",
				"http://www.bluez.org/",
				"http://www.bluez.org/");
	}

	if (add_record_to_server(BDADDR_ANY, record) < 0)
		sdp_record_free(record);
	else
		return record->handle;

	return 0;
}

void attrib_free_sdp(uint32_t sdp_handle)
{
	remove_record_from_server(sdp_handle);
}

uint16_t attrib_db_find_avail(uint16_t nitems)
{
	uint16_t handle;
	GSList *l;

	g_assert(nitems > 0);

	for (l = database, handle = 0; l; l = l->next) {
		struct attribute *a = l->data;

		if (handle && (bt_uuid_cmp(&a->uuid, &prim_uuid) == 0 ||
				bt_uuid_cmp(&a->uuid, &snd_uuid) == 0) &&
				a->handle - handle >= nitems)
			/* Note: the range above excludes the current handle */
			return handle;

		if (a->handle == 0xffff)
			return 0;

		handle = a->handle + 1;
	}

	if (0xffff - handle + 1 >= nitems)
		return handle;

	return 0;
}

struct attribute *attrib_db_add(uint16_t handle, bt_uuid_t *uuid, int read_reqs,
				int write_reqs, const uint8_t *value, int len)
{
	struct attribute *a;
	guint h = handle;

	DBG("handle=0x%04x", handle);

	if (g_slist_find_custom(database, GUINT_TO_POINTER(h), handle_cmp))
		return NULL;

	a = g_malloc0(sizeof(struct attribute) + len);
	a->handle = handle;
	memcpy(&a->uuid, uuid, sizeof(bt_uuid_t));
	a->read_reqs = read_reqs;
	a->write_reqs = write_reqs;
	a->len = len;
	memcpy(a->data, value, len);

	database = g_slist_insert_sorted(database, a, attribute_cmp);

	return a;
}

int attrib_db_update(uint16_t handle, bt_uuid_t *uuid, const uint8_t *value,
					int len, struct attribute **attr)
{
	struct attribute *a;
	GSList *l;
	guint h = handle;

	DBG("handle=0x%04x", handle);

	l = g_slist_find_custom(database, GUINT_TO_POINTER(h), handle_cmp);
	if (!l)
		return -ENOENT;

	a = g_try_realloc(l->data, sizeof(struct attribute) + len);
	if (a == NULL)
		return -ENOMEM;

	l->data = a;
	if (uuid != NULL)
		memcpy(&a->uuid, uuid, sizeof(bt_uuid_t));
	a->len = len;
	memcpy(a->data, value, len);

	attrib_notify_clients(a);

	if (attr)
		*attr = a;

	return 0;
}

int attrib_db_del(uint16_t handle)
{
	struct attribute *a;
	GSList *l;
	guint h = handle;

	DBG("handle=0x%04x", handle);

	l = g_slist_find_custom(database, GUINT_TO_POINTER(h), handle_cmp);
	if (!l)
		return -ENOENT;

	a = l->data;
	database = g_slist_remove(database, a);
	g_free(a);

	return 0;
}

int attrib_gap_set(uint16_t uuid, const uint8_t *value, int len)
{
	uint16_t handle;

	/* FIXME: Missing Privacy and Reconnection Address */

	switch (uuid) {
	case GATT_CHARAC_DEVICE_NAME:
		handle = name_handle;
		break;
	case GATT_CHARAC_APPEARANCE:
		handle = appearance_handle;
		break;
	default:
		return -ENOSYS;
	}

	return attrib_db_update(handle, NULL, value, len, NULL);
}
