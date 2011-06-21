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

#include <stdint.h>
#include <glib.h>

#include <gobex/obex.h>

typedef struct _GObex GObex;
typedef struct _GObexRequest GObexRequest;
typedef struct _GObexHeader GObexHeader;

GObexHeader *g_obex_header_parse(const void *data, size_t len,
						gboolean copy, size_t *parsed);
void g_obex_header_free(GObexHeader *header);

GObexRequest *g_obex_request_new(uint8_t opcode);
void g_obex_request_free(GObexRequest *req);

gboolean g_obex_send(GObex *obex, GObexRequest *req);

GObex *g_obex_new(GIOChannel *io);

GObex *g_obex_ref(GObex *obex);
void g_obex_unref(GObex *obex);

#endif /* __GOBEX_H */
