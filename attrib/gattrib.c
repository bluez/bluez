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
#include <string.h>
#include <glib.h>

#include <stdio.h>

#include <bluetooth/sdp.h>

#include "att.h"
#include "gattrib.h"

struct _GAttrib {
	GIOChannel *io;
	gint refs;
	gint mtu;
	guint read_watch;
	guint write_watch;
	GQueue *queue;
	GSList *events;
	guint next_cmd_id;
	guint next_evt_id;
};

struct command {
	guint id;
	guint8 opcode;
	guint8 *pdu;
	guint16 len;
	guint8 expected;
	GAttribResultFunc func;
	gpointer user_data;
	GDestroyNotify notify;
};

struct event {
	guint id;
	guint8 expected;
	GAttribNotifyFunc func;
	gpointer user_data;
	GDestroyNotify notify;
};

static guint8 opcode2expected(guint8 opcode)
{
	/* These opcodes don't require response */
	if (opcode == ATT_OP_HANDLE_NOTIFY ||
			opcode == ATT_OP_SIGNED_WRITE_CMD)
		return 0;

	/* Nothing expected, already a response */
	if (opcode % 2)
		return 0;

	return opcode | 1;
}

static gboolean is_response(guint8 opcode)
{
	return opcode % 2 == 1;
}

GAttrib *g_attrib_ref(GAttrib *attrib)
{
	if (!attrib)
		return NULL;

	g_atomic_int_inc(&attrib->refs);

	return attrib;
}

void g_attrib_unref(GAttrib *attrib)
{
	if (!attrib)
		return;

	if (g_atomic_int_dec_and_test(&attrib->refs) == FALSE)
		return;

	g_queue_free(attrib->queue);

	if (attrib->read_watch > 0)
		g_source_remove(attrib->read_watch);

	if (attrib->write_watch > 0)
		g_source_remove(attrib->write_watch);

	g_io_channel_unref(attrib->io);

	g_free(attrib);
}

static void destroy_receiver(gpointer data)
{
	struct _GAttrib *attrib = data;

	attrib->read_watch = 0;
}

static void wake_up_sender(struct _GAttrib *attrib);

static gboolean received_data(GIOChannel *io, GIOCondition cond, gpointer data)
{
	struct _GAttrib *attrib = data;
	struct command *cmd = NULL;
	GSList *l;
	uint8_t buf[512];
	gsize len;
	guint8 status;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		return FALSE;

	memset(buf, 0, sizeof(buf));

	if (g_io_channel_read_chars(io, (gchar *) buf, sizeof(buf), &len, NULL)
							!= G_IO_STATUS_NORMAL) {
		status = ATT_ECODE_IO;
		goto done;
	}

	for (l = attrib->events; l; l = l->next) {
		struct event *evt = l->data;

		if (evt->expected == buf[0] ||
					evt->expected == GATTRIB_ALL_EVENTS)
			evt->func(buf, len, evt->user_data);
	}

	if (is_response(buf[0]) == FALSE)
		return TRUE;

	cmd = g_queue_pop_head(attrib->queue);
	if (cmd == NULL) {
		/* Keep the watch if we have events to report */
		return attrib->events != NULL;
	}

	if (buf[0] == ATT_OP_ERROR) {
		status = buf[4];
		goto done;
	}

	if (cmd->expected != buf[0]) {
		status = ATT_ECODE_IO;
		goto done;
	}

	status = 0;

done:
	if (cmd && cmd->func) {
		cmd->func(status, buf, len, cmd->user_data);

		if (cmd->notify)
			cmd->notify(cmd->user_data);

		g_free(cmd->pdu);
		g_free(cmd);
	}

	if (g_queue_is_empty(attrib->queue) == FALSE)
		wake_up_sender(attrib);

	return TRUE;
}

static gboolean can_write_data(GIOChannel *io, GIOCondition cond, gpointer data)
{
	struct _GAttrib *attrib = data;
	struct command *cmd;
	GError *gerr = NULL;
	gsize len;

	if (cond & (G_IO_HUP | G_IO_ERR | G_IO_NVAL))
		return FALSE;

	cmd = g_queue_peek_head(attrib->queue);
	if (cmd == NULL)
		return FALSE;

	if (g_io_channel_write_chars(io, (gchar *) cmd->pdu, cmd->len, &len,
						&gerr) != G_IO_STATUS_NORMAL) {
		return FALSE;
	}

	g_io_channel_flush(io, NULL);

	if (cmd->expected == 0) {
		if (cmd->notify)
			cmd->notify(cmd->user_data);

		g_queue_pop_head(attrib->queue);

		g_free(cmd->pdu);
		g_free(cmd);
		return TRUE;
	}

	return FALSE;
}


static void destroy_sender(gpointer data)
{
	struct _GAttrib *attrib = data;

	attrib->write_watch = 0;
}

static void wake_up_sender(struct _GAttrib *attrib)
{
	if (attrib->write_watch == 0)
		attrib->write_watch = g_io_add_watch_full(attrib->io,
			G_PRIORITY_DEFAULT,
			G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			can_write_data, attrib, destroy_sender);
}

GAttrib *g_attrib_new(GIOChannel *io)
{
	struct _GAttrib *attrib;

	g_io_channel_set_encoding(io, NULL, NULL);

	attrib = g_new0(struct _GAttrib, 1);
	attrib->io = g_io_channel_ref(io);
	attrib->refs = 1;
	attrib->mtu = 512;
	attrib->queue = g_queue_new();

	attrib->read_watch = g_io_add_watch_full(attrib->io,
			G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			received_data, attrib, destroy_receiver);

	return attrib;
}

guint g_attrib_send(GAttrib *attrib, guint8 opcode, const guint8 *pdu,
				guint16 len, GAttribResultFunc func,
				gpointer user_data, GDestroyNotify notify)
{
	struct command *c;

	c = g_new0(struct command, 1);
	c->opcode = opcode;
	c->expected = opcode2expected(opcode);
	c->pdu = g_malloc(len);
	memcpy(c->pdu, pdu, len);
	c->len = len;
	c->func = func;
	c->user_data = user_data;
	c->notify = notify;
	c->id = ++attrib->next_cmd_id;

	g_queue_push_tail(attrib->queue, c);

	if (g_queue_get_length(attrib->queue) == 1)
		wake_up_sender(attrib);

	return c->id;
}

gboolean g_attrib_cancel(GAttrib *attrib, guint id)
{
	return TRUE;
}

gboolean g_attrib_cancel_all(GAttrib *attrib)
{
	return TRUE;
}

gboolean g_attrib_set_debug(GAttrib *attrib,
		GAttribDebugFunc func, gpointer user_data)
{
	return TRUE;
}

guint g_attrib_register(GAttrib *attrib, guint8 opcode,
				GAttribNotifyFunc func, gpointer user_data,
				GDestroyNotify notify)
{
	struct event *event;

	event = g_new0(struct event, 1);

	event->expected = opcode;
	event->func = func;
	event->user_data = user_data;
	event->notify = notify;
	event->id = ++attrib->next_evt_id;

	attrib->events = g_slist_append(attrib->events, event);

	return event->id;
}

gboolean g_attrib_unregister(GAttrib *attrib, guint id)
{
	return TRUE;
}

gboolean g_attrib_unregister_all(GAttrib *attrib)
{
	return TRUE;
}
