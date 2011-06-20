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

#include "gobex.h"

struct _GObexRequest {
	uint8_t opcode;
	GSList *headers;
};

struct _GObex {
	gint ref_count;
	GIOChannel *io;

	GQueue *req_queue;
};

GObexRequest *g_obex_request_new(uint8_t opcode)
{
	GObexRequest *req;

	req = g_new0(GObexRequest, 1);

	req->opcode = opcode;

	return req;
}

void g_obex_request_free(GObexRequest *req)
{
	g_free(req);
}

gboolean g_obex_send(GObex *obex, GObexRequest *req)
{
	if (obex == NULL || req == NULL)
		return FALSE;

	g_queue_push_tail(obex->req_queue, req);

	return TRUE;
}

GObex *g_obex_new(GIOChannel *io)
{
	GObex *obex;

	if (io == NULL)
		return NULL;

	obex = g_new0(GObex, 1);

	obex->io = io;
	obex->ref_count = 1;
	obex->req_queue = g_queue_new();

	return obex;
}

GObex *g_obex_ref(GObex *obex)
{
	if (obex == NULL)
		return NULL;

	g_atomic_int_inc(&obex->ref_count);

	return obex;
}

void g_obex_unref(GObex *obex)
{
	gboolean last_ref;

	last_ref = g_atomic_int_dec_and_test(&obex->ref_count);

	if (!last_ref)
		return;

	g_queue_foreach(obex->req_queue, (GFunc) g_obex_request_free, NULL);
	g_queue_free(obex->req_queue);

	g_io_channel_unref(obex->io);

	g_free(obex);
}
