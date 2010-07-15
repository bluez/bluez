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

#include <glib.h>

#include "gattrib.h"

struct _GAttrib {
	GIOChannel *io;
	gint refs;
};

GAttrib *g_attrib_new(GIOChannel *io)
{
	struct _GAttrib *attrib;

	attrib = g_new0(struct _GAttrib, 1);
	attrib->io = io;
	attrib->refs = 1;

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

	g_free(attrib);
}

guint g_attrib_send(GAttrib *attrib, guint8 opcode, const guint8 *pdu,
				guint16 len, GAttribResultFunc func,
				gpointer user_data, GDestroyNotify notify)
{
	return 0;
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
