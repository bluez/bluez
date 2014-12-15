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
#include "config.h"
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <glib.h>

#include <stdio.h>

#include <bluetooth/bluetooth.h>

#include "btio/btio.h"
#include "src/log.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "attrib/gattrib.h"

struct _GAttrib {
	int ref_count;
	struct bt_att *att;
	GIOChannel *io;
	GDestroyNotify destroy;
	gpointer destroy_user_data;
	struct queue *callbacks;
	uint8_t *buf;
	int buflen;
};


struct attrib_callbacks {
	GAttribResultFunc result_func;
	GAttribNotifyFunc notify_func;
	GDestroyNotify destroy_func;
	gpointer user_data;
	GAttrib *parent;
	uint16_t notify_handle;
};

GAttrib *g_attrib_new(GIOChannel *io, guint16 mtu)
{
	gint fd;
	GAttrib *attr;

	if (!io)
		return NULL;

	fd = g_io_channel_unix_get_fd(io);
	attr = new0(GAttrib, 1);
	if (!attr)
		return NULL;

	g_io_channel_ref(io);
	attr->io = io;

	attr->att = bt_att_new(fd);
	if (!attr->att)
		goto fail;

	if (!bt_att_set_mtu(attr->att, mtu))
		goto fail;

	attr->buf = malloc0(mtu);
	attr->buflen = mtu;
	if (!attr->buf)
		goto fail;

	attr->callbacks = queue_new();
	if (!attr->callbacks)
		goto fail;

	return g_attrib_ref(attr);

fail:
	free(attr->buf);
	bt_att_unref(attr->att);
	g_io_channel_unref(io);
	free(attr);
	return NULL;
}

GAttrib *g_attrib_ref(GAttrib *attrib)
{
	if (!attrib)
		return NULL;

	__sync_fetch_and_add(&attrib->ref_count, 1);

	DBG("%p: g_attrib_ref=%d ", attrib, attrib->ref_count);

	return attrib;
}

static void attrib_callbacks_destroy(void *data)
{
	struct attrib_callbacks *cb = data;

	if (cb->destroy_func)
		cb->destroy_func(cb->user_data);

	free(data);
}

static void attrib_callbacks_remove(void *data)
{
	struct attrib_callbacks *cb = data;

	if (!data || !queue_remove(cb->parent->callbacks, data))
		return;

	attrib_callbacks_destroy(data);
}

void g_attrib_unref(GAttrib *attrib)
{
	if (!attrib)
		return;

	DBG("%p: g_attrib_unref=%d ", attrib, attrib->ref_count - 1);

	if (__sync_sub_and_fetch(&attrib->ref_count, 1))
		return;

	if (attrib->destroy)
		attrib->destroy(attrib->destroy_user_data);

	bt_att_unref(attrib->att);

	queue_destroy(attrib->callbacks, attrib_callbacks_destroy);

	free(attrib->buf);

	g_io_channel_unref(attrib->io);

	free(attrib);
}

GIOChannel *g_attrib_get_channel(GAttrib *attrib)
{
	if (!attrib)
		return NULL;

	return attrib->io;
}

struct bt_att *g_attrib_get_att(GAttrib *attrib)
{
	if (!attrib)
		return NULL;

	return attrib->att;
}

gboolean g_attrib_set_destroy_function(GAttrib *attrib, GDestroyNotify destroy,
							gpointer user_data)
{
	if (!attrib)
		return FALSE;

	attrib->destroy = destroy;
	attrib->destroy_user_data = user_data;

	return TRUE;
}


static uint8_t *construct_full_pdu(uint8_t opcode, const void *pdu,
								uint16_t length)
{
	uint8_t *buf = malloc0(length + 1);

	if (!buf)
		return NULL;

	buf[0] = opcode;
	memcpy(buf + 1, pdu, length);

	return buf;
}

static void attrib_callback_result(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	uint8_t *buf;
	struct attrib_callbacks *cb = user_data;
	guint8 status = 0;

	if (!cb)
		return;

	buf = construct_full_pdu(opcode, pdu, length);
	if (!buf)
		return;

	if (opcode == BT_ATT_OP_ERROR_RSP) {
		/* Error code is the third byte of the PDU data */
		if (length < 4)
			status = BT_ATT_ERROR_UNLIKELY;
		else
			status = ((guint8 *)pdu)[3];
	}

	if (cb->result_func)
		cb->result_func(status, buf, length + 1, cb->user_data);

	free(buf);
}

static void attrib_callback_notify(uint8_t opcode, const void *pdu,
					uint16_t length, void *user_data)
{
	uint8_t *buf;
	struct attrib_callbacks *cb = user_data;

	if (!cb || !cb->notify_func)
		return;

	if (cb->notify_handle != GATTRIB_ALL_HANDLES && length < 2)
		return;

	if (cb->notify_handle != GATTRIB_ALL_HANDLES &&
					cb->notify_handle != get_le16(pdu))
		return;

	buf = construct_full_pdu(opcode, pdu, length);
	if (!buf)
		return;

	cb->notify_func(buf, length + 1, cb->user_data);

	free(buf);
}

guint g_attrib_send(GAttrib *attrib, guint id, const guint8 *pdu, guint16 len,
				GAttribResultFunc func, gpointer user_data,
				GDestroyNotify notify)
{
	struct attrib_callbacks *cb = NULL;
	bt_att_response_func_t response_cb = NULL;
	bt_att_destroy_func_t destroy_cb = NULL;

	if (!attrib)
		return 0;

	if (!pdu || !len)
		return 0;

	if (func || notify) {
		cb = new0(struct attrib_callbacks, 1);
		if (!cb)
			return 0;
		cb->result_func = func;
		cb->user_data = user_data;
		cb->destroy_func = notify;
		cb->parent = attrib;
		queue_push_head(attrib->callbacks, cb);
		response_cb = attrib_callback_result;
		destroy_cb = attrib_callbacks_remove;
	}

	return bt_att_send(attrib->att, pdu[0], (void *)pdu + 1, len - 1,
						response_cb, cb, destroy_cb);
}

gboolean g_attrib_cancel(GAttrib *attrib, guint id)
{
	if (!attrib)
		return FALSE;

	return bt_att_cancel(attrib->att, id);
}

gboolean g_attrib_cancel_all(GAttrib *attrib)
{
	if (!attrib)
		return FALSE;

	return bt_att_cancel_all(attrib->att);
}

guint g_attrib_register(GAttrib *attrib, guint8 opcode, guint16 handle,
				GAttribNotifyFunc func, gpointer user_data,
				GDestroyNotify notify)
{
	struct attrib_callbacks *cb = NULL;

	if (!attrib)
		return 0;

	if (func || notify) {
		cb = new0(struct attrib_callbacks, 1);
		if (!cb)
			return 0;
		cb->notify_func = func;
		cb->notify_handle = handle;
		cb->user_data = user_data;
		cb->destroy_func = notify;
		cb->parent = attrib;
		queue_push_head(attrib->callbacks, cb);
	}

	if (opcode == GATTRIB_ALL_REQS)
		opcode = BT_ATT_ALL_REQUESTS;

	return bt_att_register(attrib->att, opcode, attrib_callback_notify,
						cb, attrib_callbacks_remove);
}

uint8_t *g_attrib_get_buffer(GAttrib *attrib, size_t *len)
{
	if (!attrib || !len)
		return NULL;

	*len = attrib->buflen;
	return attrib->buf;
}

gboolean g_attrib_set_mtu(GAttrib *attrib, int mtu)
{
	if (!attrib)
		return FALSE;

	/*
	 * Clients of this expect a buffer to use.
	 *
	 * Pdu encoding in sharred/att verifies if whole buffer fits the mtu,
	 * thus we should set the buflen also when mtu is reduced. But we
	 * need to reallocate the buffer only if mtu is larger.
	 */
	if (mtu > attrib->buflen)
		attrib->buf = g_realloc(attrib->buf, mtu);

	attrib->buflen = mtu;

	return bt_att_set_mtu(attrib->att, mtu);
}

gboolean g_attrib_unregister(GAttrib *attrib, guint id)
{
	if (!attrib)
		return FALSE;

	return bt_att_unregister(attrib->att, id);
}

gboolean g_attrib_unregister_all(GAttrib *attrib)
{
	if (!attrib)
		return false;

	return bt_att_unregister_all(attrib->att);
}
