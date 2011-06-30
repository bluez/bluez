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

#ifndef __GOBEX_HEADER_H
#define __GOBEX_HEADER_H

#include <glib.h>

#include <gobex/gobex-defs.h>

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

typedef struct _GObexHeader GObexHeader;

typedef guint16 (*GObexHeaderDataFunc) (GObexHeader *header, void *buf,
						gsize len, gpointer user_data);

gboolean g_obex_header_get_unicode(GObexHeader *header, const char **str);
gboolean g_obex_header_get_bytes(GObexHeader *header, const guint8 **val,
								gsize *len);
gboolean g_obex_header_get_uint8(GObexHeader *header, guint8 *val);
gboolean g_obex_header_get_uint32(GObexHeader *header, guint32 *val);

GObexHeader *g_obex_header_new_unicode(guint8 id, const char *str);
GObexHeader *g_obex_header_new_bytes(guint8 id, void *data, gsize len,
						GObexDataPolicy data_policy);
GObexHeader *g_obex_header_new_on_demand(guint8 id,
						GObexHeaderDataFunc func,
						gpointer user_data);
GObexHeader *g_obex_header_new_uint8(guint8 id, guint8 val);
GObexHeader *g_obex_header_new_uint32(guint8 id, guint32 val);

guint8 g_obex_header_get_id(GObexHeader *header);
guint16 g_obex_header_get_length(GObexHeader *header);

gsize g_obex_header_encode(GObexHeader *header, void *hdr_ptr, gsize buf_len);
GObexHeader *g_obex_header_decode(const void *data, gsize len,
				GObexDataPolicy data_policy, gsize *parsed,
				GError **err);
void g_obex_header_free(GObexHeader *header);

#endif /* __GOBEX_HEADER_H */
