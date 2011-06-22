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

#include <string.h>

#include "gobex.h"

/* Header types */
#define G_OBEX_HDR_TYPE_UNICODE	(0 << 6)
#define G_OBEX_HDR_TYPE_BYTES	(1 << 6)
#define G_OBEX_HDR_TYPE_UINT8	(2 << 6)
#define G_OBEX_HDR_TYPE_UINT32	(3 << 6)

#define G_OBEX_HDR_TYPE(id)	((id) & 0xc0)

struct _GObexHeader {
	uint8_t id;
	gboolean extdata;
	size_t vlen;
	union {
		char *string;		/* UTF-8 converted from UTF-16 */
		uint8_t *data;		/* Own buffer */
		const uint8_t *extdata;	/* Reference to external buffer */
		uint8_t u8;
		uint32_t u32;
	} v;
};

struct _GObexRequest {
	uint8_t opcode;
	GSList *headers;
};

struct _GObex {
	gint ref_count;
	GIOChannel *io;

	GQueue *req_queue;
};

GObexHeader *g_obex_header_parse(const void *data, size_t len,
						gboolean copy, size_t *parsed)
{
	GObexHeader *header;
	const char *buf = data;
	uint16_t hdr_len;
	size_t str_len;

	if (len < 2)
		return NULL;

	header = g_new0(GObexHeader, 1);

	header->id = buf[0];

	switch (G_OBEX_HDR_TYPE(header->id)) {
	case G_OBEX_HDR_TYPE_UNICODE:
		if (len < 3)
			goto failed;
		memcpy(&hdr_len, &buf[1], 2);
		hdr_len = be16toh(hdr_len);
		if (hdr_len > len || hdr_len < 5)
			goto failed;

		header->v.string = g_convert(&buf[3], hdr_len - 5,
						"UTF8", "UTF16BE",
						NULL, &str_len, NULL);
		if (header->v.string == NULL)
			goto failed;

		header->vlen = (size_t) str_len;

		*parsed = hdr_len;

		break;
	case G_OBEX_HDR_TYPE_BYTES:
		if (len < 3)
			goto failed;
		memcpy(&hdr_len, &buf[1], 2);
		hdr_len = be16toh(hdr_len);
		if (hdr_len > len)
			goto failed;

		header->vlen = hdr_len - 3;

		if (copy) {
			header->v.data = g_malloc(hdr_len);
			memcpy(header->v.data, &buf[3], header->vlen);
		} else {
			header->extdata = TRUE;
			header->v.extdata = (const uint8_t *) &buf[3];
		}

		*parsed = hdr_len;

		break;
	case G_OBEX_HDR_TYPE_UINT8:
		header->vlen = 1;
		header->v.u8 = buf[1];
		*parsed = 2;
		break;
	case G_OBEX_HDR_TYPE_UINT32:
		if (len < 5)
			goto failed;
		header->vlen = 4;
		memcpy(&header->v.u32, &buf[1], 4);
		header->v.u32 = be32toh(header->v.u32);
		*parsed = 5;
		break;
	default:
		g_assert_not_reached();
	}

	return header;

failed:
	g_obex_header_free(header);
	return NULL;
}

void g_obex_header_free(GObexHeader *header)
{
	switch (G_OBEX_HDR_TYPE(header->id)) {
	case G_OBEX_HDR_TYPE_UNICODE:
		g_free(header->v.string);
		break;
	case G_OBEX_HDR_TYPE_BYTES:
		if (!header->extdata)
			g_free(header->v.data);
		break;
	case G_OBEX_HDR_TYPE_UINT8:
	case G_OBEX_HDR_TYPE_UINT32:
		break;
	default:
		g_assert_not_reached();
	}

	g_free(header);
}

gboolean g_obex_request_add_header(GObexRequest *req, GObexHeader *header)
{
	req->headers = g_slist_append(req->headers, header);

	return TRUE;
}

GObexRequest *g_obex_request_new(uint8_t opcode)
{
	GObexRequest *req;

	req = g_new0(GObexRequest, 1);

	req->opcode = opcode;

	return req;
}

void g_obex_request_free(GObexRequest *req)
{
	g_slist_foreach(req->headers, (GFunc) g_obex_header_free, NULL);
	g_slist_free(req->headers);
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
