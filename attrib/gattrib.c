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
	guint id;
	struct command *response;
	struct event *event;
};

struct command {
	guint8 expected;
	GAttribResultFunc func;
	gpointer user_data;
	GDestroyNotify notify;
};

struct event {
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

GAttrib *g_attrib_new(GIOChannel *io)
{
	struct _GAttrib *attrib;

	g_io_channel_set_encoding(io, NULL, NULL);

	attrib = g_new0(struct _GAttrib, 1);
	attrib->io = io;
	attrib->refs = 1;
	attrib->mtu = 512;

	return attrib;
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

	g_free(attrib->response);
	g_free(attrib->event);
	g_free(attrib);
}

static gboolean received_data(GIOChannel *io, GIOCondition cond, gpointer data)
{
	struct _GAttrib *attrib = data;
	struct command *response = attrib->response;
	struct event *event = attrib->event;
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

	if (event && (event->expected == GATTRIB_ALL_EVENTS
					|| event->expected == buf[0])) {
		event->func(buf, len, event->user_data);
		return TRUE;
	}

	if (buf[0] == ATT_OP_ERROR) {
		status = buf[4];
		goto done;
	}

	if (buf[0] != response->expected) {
		status = ATT_ECODE_IO;
		goto done;
	}

	status = 0;

done:
	if (response->func)
		response->func(status, buf, len, response->user_data);

	return TRUE;
}

static void command_destroy(gpointer user_data)
{
	struct _GAttrib *attrib = user_data;
	struct command *command = attrib->response;

	if (command->notify)
		command->notify(command->user_data);

	g_free(command);
}

static void event_destroy(gpointer user_data)
{
	struct _GAttrib *attrib = user_data;
	struct event *event = attrib->event;

	if (event->notify)
		event->notify(event->user_data);

	g_free(event);
}

guint g_attrib_send(GAttrib *attrib, guint8 opcode, const guint8 *pdu,
				guint16 len, GAttribResultFunc func,
				gpointer user_data, GDestroyNotify notify)
{
	struct command *response;
	gsize written;

	response = g_new0(struct command, 1);

	response->func = func;
	response->notify = notify;
	response->user_data = user_data;
	response->expected = opcode2expected(opcode);

	if (attrib->id == 0)
		attrib->id = g_io_add_watch_full(attrib->io,
			G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			received_data, attrib, command_destroy);

	attrib->response = response;

	g_io_channel_write(attrib->io, (gchar *) pdu, len, &written);

	return attrib->id;
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

	/* FIXME: event should be a list */

	event = g_new0(struct event, 1);

	event->expected = opcode;
	event->func = func;
	event->user_data = user_data;
	event->notify = notify;

	if (attrib->id == 0)
		attrib->id = g_io_add_watch_full(attrib->io,
			G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			received_data, attrib, event_destroy);

	attrib->event = event;

	return attrib->id;
}

gboolean g_attrib_unregister(GAttrib *attrib, guint id)
{
	return TRUE;
}

gboolean g_attrib_unregister_all(GAttrib *attrib)
{
	return TRUE;
}
