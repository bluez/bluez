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

#ifndef __GOBEX_PACKET_H
#define __GOBEX_PACKET_H

#include <glib.h>

#include <gobex/gobex-defs.h>
#include <gobex/gobex-header.h>

/* Opcodes */
#define G_OBEX_OP_CONNECT	0x00
#define G_OBEX_OP_DISCONNECT	0x01
#define G_OBEX_OP_PUT		0x02
#define G_OBEX_OP_GET		0x03
#define G_OBEX_OP_SETPATH	0x05
#define G_OBEX_OP_SESSION	0x07
#define G_OBEX_OP_ABORT		0x7f

#define G_OBEX_PACKET_FINAL	0x80

typedef struct _GObexPacket GObexPacket;

GObexHeader *g_obex_packet_get_header(GObexPacket *pkt, guint8 id);
guint8 g_obex_packet_get_operation(GObexPacket *pkt, gboolean *final);
gboolean g_obex_packet_add_header(GObexPacket *pkt, GObexHeader *header);
gboolean g_obex_packet_set_data(GObexPacket *pkt, const void *data, gsize len,
						GObexDataPolicy data_policy);
const void *g_obex_packet_get_data(GObexPacket *pkt, gsize *len);
GObexPacket *g_obex_packet_new(guint8 opcode, gboolean final);
void g_obex_packet_free(GObexPacket *pkt);

GObexPacket *g_obex_packet_decode(const void *data, gsize len,
						gsize header_offset,
						GObexDataPolicy data_policy,
						GError **err);
gssize g_obex_packet_encode(GObexPacket *pkt, guint8 *buf, gsize len);

#endif /* __GOBEX_PACKET_H */
