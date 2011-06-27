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

/* Opcodes */
#define G_OBEX_OP_CONNECT		0x00
#define G_OBEX_OP_DISCONNECT		0x01
#define G_OBEX_OP_PUT			0x02
#define G_OBEX_OP_GET			0x03
#define G_OBEX_OP_SETPATH		0x05
#define G_OBEX_OP_SESSION		0x07
#define G_OBEX_OP_ABORT			0x7f
#define G_OBEX_FINAL			0x80

/* Header ID's */
#define G_OBEX_HDR_ID_COUNT		0xc0
#define G_OBEX_HDR_ID_NAME		0x01
#define G_OBEX_HDR_ID_TYPE		0x42
#define G_OBEX_HDR_ID_LENGTH		0xc3
#define G_OBEX_HDR_ID_TIME		0x44
#define G_OBEX_HDR_ID_DESCRIPTION	0x05
#define G_OBEX_HDR_ID_TARGET		0x46
#define G_OBEX_HDR_ID_HTTP		0x47
#define G_OBEX_HDR_ID_BODY		0x48
#define G_OBEX_HDR_ID_BODY_END		0x49
#define G_OBEX_HDR_ID_WHO		0x4a
#define G_OBEX_HDR_ID_CONNECTION	0xcb
#define G_OBEX_HDR_ID_APPARAM		0x4c
#define G_OBEX_HDR_ID_AUTHCHAL		0x4d
#define G_OBEX_HDR_ID_AUTHRESP		0x4e
#define G_OBEX_HDR_ID_CREATOR		0xcf
#define G_OBEX_HDR_ID_WANUUID		0x50
#define G_OBEX_HDR_ID_OBJECTCLASS	0x51
#define G_OBEX_HDR_ID_SESSIONPARAM	0x52
#define G_OBEX_HDR_ID_SESSIONSEQ	0x93
#define G_OBEX_HDR_ID_ACTION		0x94
#define G_OBEX_HDR_ID_DESTNAME		0x15
#define G_OBEX_HDR_ID_PERMISSIONS	0xd6
#define G_OBEX_HDR_ID_SRM		0x97
#define G_OBEX_HDR_ID_SRM_FLAGS		0x98

typedef enum {
	G_OBEX_DATA_INHERIT,
	G_OBEX_DATA_COPY,
	G_OBEX_DATA_REF,
} GObexDataPolicy;

typedef struct _GObex GObex;
typedef struct _GObexPacket GObexPacket;
typedef struct _GObexHeader GObexHeader;

GObexHeader *g_obex_header_unicode(guint8 id, const char *str);
GObexHeader *g_obex_header_bytes(guint8 id, void *data, size_t len,
						GObexDataPolicy data_policy);
GObexHeader *g_obex_header_uint8(guint8 id, guint8 val);
GObexHeader *g_obex_header_uint32(guint8 id, guint32 val);

size_t g_obex_header_encode(GObexHeader *header, void *hdr_ptr, size_t buf_len);
GObexHeader *g_obex_header_decode(const void *data, size_t len,
				GObexDataPolicy data_policy, size_t *parsed);
void g_obex_header_free(GObexHeader *header);

gboolean g_obex_packet_add_header(GObexPacket *req, GObexHeader *header);
gboolean g_obex_packet_set_data(GObexPacket *pkt, const void *data, size_t len,
						GObexDataPolicy data_policy);
GObexPacket *g_obex_packet_new(guint8 opcode, gboolean final);
void g_obex_packet_free(GObexPacket *req);

GObexPacket *g_obex_packet_decode(const void *data, size_t len,
						GObexDataPolicy data_policy);

gboolean g_obex_send(GObex *obex, GObexPacket *req);

GObex *g_obex_new(GIOChannel *io);

GObex *g_obex_ref(GObex *obex);
void g_obex_unref(GObex *obex);

#endif /* __GOBEX_H */
