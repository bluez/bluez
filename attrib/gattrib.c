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
	struct command *command;
};

struct command {
	guint id;
	guint8 expected;
	GAttribResultFunc result;
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

	g_free(attrib->command);
	g_free(attrib);
}

static gboolean received_data(GIOChannel *io, GIOCondition cond, gpointer data)
{
	struct command *command = data;
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

	if (buf[0] == ATT_OP_ERROR) {
		status = buf[1];
		goto done;
	}

	if (buf[0] != command->expected) {
		status = ATT_ECODE_IO;
		goto done;
	}

	status = 0;

done:
	command->result(status, buf, len, command->user_data);

	return TRUE;
}

static void command_destroy(gpointer user_data)
{
	struct command *command = user_data;

	if (command->notify)
		command->notify(command->user_data);

	g_free(command);
}

guint g_attrib_send(GAttrib *attrib, guint8 opcode, const guint8 *pdu,
				guint16 len, GAttribResultFunc func,
				gpointer user_data, GDestroyNotify notify)
{
	struct command *command;
	gsize written;

	command = g_new0(struct command, 1);

	command->result = func;
	command->notify = notify;
	command->user_data = user_data;
	command->expected = opcode2expected(opcode);

	command->id = g_io_add_watch_full(attrib->io,
			G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			received_data, command, command_destroy);

	g_io_channel_write(attrib->io, (gchar *) pdu, len, &written);

	return command->id;
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
	return 0;
}

gboolean g_attrib_unregister(GAttrib *attrib, guint id)
{
	return TRUE;
}

gboolean g_attrib_unregister_all(GAttrib *attrib)
{
	return TRUE;
}
