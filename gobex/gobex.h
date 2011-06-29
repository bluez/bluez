/*
 *
 *  OBEX library with GLib integration
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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

#ifndef __GOBEX_H
#define __GOBEX_H

#include <glib.h>

#include <gobex/gobex-packet.h>

typedef enum {
	G_OBEX_TRANSPORT_STREAM,
	G_OBEX_TRANSPORT_PACKET,
} GObexTransportType;

typedef struct _GObex GObex;

typedef void (*GObexEventFunc) (GObex *obex, GError *err, GObexPacket *req,
							gpointer user_data);
typedef void (*GObexResponseFunc) (GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data);

gboolean g_obex_send(GObex *obex, GObexPacket *pkt, GError **err);

guint g_obex_send_req(GObex *obex, GObexPacket *req, gint timeout,
			GObexResponseFunc func, gpointer user_data,
			GError **err);
gboolean g_obex_cancel_req(GObex *obex, guint req_id);

void g_obex_set_event_function(GObex *obex, GObexEventFunc func,
							gpointer user_data);

GObex *g_obex_new(GIOChannel *io, GObexTransportType transport_type);

GObex *g_obex_ref(GObex *obex);
void g_obex_unref(GObex *obex);

#endif /* __GOBEX_H */
