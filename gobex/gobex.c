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
	size_t vlen;			/* Length of value */
	size_t hlen;			/* Length of full encoded header */
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
	size_t hlen;		/* Length of all encoded headers */
	GSList *headers;
};

struct _GObex {
	gint ref_count;
	GIOChannel *io;

	GQueue *req_queue;
};

static glong utf8_to_utf16(gunichar2 **utf16, const char *utf8) {
	glong utf16_len;
	int i;

	if (*utf8 == '\0') {
		*utf16 = NULL;
		return 0;
	}

	*utf16 = g_utf8_to_utf16(utf8, -1, NULL, &utf16_len, NULL);
	if (*utf16 == NULL)
		return -1;

	/* g_utf8_to_utf16 produces host-byteorder UTF-16,
	 * but OBEX requires network byteorder (big endian) */
	for (i = 0; i < utf16_len; i++)
		(*utf16)[i] = htobe16((*utf16)[i]);

	utf16_len = (utf16_len + 1) << 1;

	return utf16_len;
}

size_t g_obex_header_encode(GObexHeader *header, void *hdr_ptr, size_t buf_len)
{
	uint8_t *buf = hdr_ptr;
	uint16_t u16;
	uint32_t u32;
	gunichar2 *utf16;
	glong utf16_len;

	if (buf_len < header->hlen)
		return 0;

	buf[0] = header->id;

	switch (G_OBEX_HDR_TYPE(header->id)) {
	case G_OBEX_HDR_TYPE_UNICODE:
		utf16_len = utf8_to_utf16(&utf16, header->v.string);
		if (utf16_len < 0 || (uint16_t) utf16_len > buf_len)
			return 0;
		u16 = htobe16(utf16_len + 3);
		memcpy(&buf[1], &u16, sizeof(u16));
		memcpy(&buf[3], utf16, utf16_len);
		g_free(utf16);
		break;
	case G_OBEX_HDR_TYPE_BYTES:
		u16 = htobe16(header->hlen);
		memcpy(&buf[1], &u16, sizeof(u16));
		if (header->extdata)
			memcpy(&buf[3], header->v.extdata, header->vlen);
		else
			memcpy(&buf[3], header->v.data, header->vlen);
		break;
	case G_OBEX_HDR_TYPE_UINT8:
		buf[1] = header->v.u8;
		break;
	case G_OBEX_HDR_TYPE_UINT32:
		u32 = htobe32(header->v.u32);
		memcpy(&buf[1], &u32, sizeof(u32));
		break;
	default:
		g_assert_not_reached();
	}

	return header->hlen;
}

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
		header->hlen = hdr_len;

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
		header->hlen = hdr_len;

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
		header->hlen = 2;
		header->v.u8 = buf[1];
		*parsed = 2;
		break;
	case G_OBEX_HDR_TYPE_UINT32:
		if (len < 5)
			goto failed;
		header->vlen = 4;
		header->hlen = 5;
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

GObexHeader *g_obex_header_unicode(uint8_t id, const char *str)
{
	GObexHeader *header;
	size_t len;

	if (G_OBEX_HDR_TYPE(id) != G_OBEX_HDR_TYPE_UNICODE)
		return NULL;

	header = g_new0(GObexHeader, 1);

	header->id = id;

	len = g_utf8_strlen(str, -1);

	header->vlen = len;
	header->hlen = 3 + ((len + 1) * 2);
	header->v.string = g_strdup(str);

	return header;
}

GObexHeader *g_obex_header_bytes(uint8_t id, void *data, size_t len,
							gboolean copy_data)
{
	GObexHeader *header;

	if (G_OBEX_HDR_TYPE(id) != G_OBEX_HDR_TYPE_BYTES)
		return NULL;

	header = g_new0(GObexHeader, 1);

	header->id = id;
	header->vlen = len;
	header->hlen = len + 3;

	if (copy_data)
		header->v.data = g_memdup(data, len);
	else {
		header->extdata = TRUE;
		header->v.extdata = data;
	}

	return header;
}

GObexHeader *g_obex_header_uint8(uint8_t id, uint8_t val)
{
	GObexHeader *header;

	if (G_OBEX_HDR_TYPE(id) != G_OBEX_HDR_TYPE_UINT8)
		return NULL;

	header = g_new0(GObexHeader, 1);

	header->id = id;
	header->vlen = 1;
	header->hlen = 2;
	header->v.u8 = val;

	return header;
}

GObexHeader *g_obex_header_uint32(uint8_t id, uint32_t val)
{
	GObexHeader *header;

	if (G_OBEX_HDR_TYPE(id) != G_OBEX_HDR_TYPE_UINT32)
		return NULL;

	header = g_new0(GObexHeader, 1);

	header->id = id;
	header->vlen = 4;
	header->hlen = 5;
	header->v.u32 = val;

	return header;
}

gboolean g_obex_request_add_header(GObexRequest *req, GObexHeader *header)
{
	req->headers = g_slist_append(req->headers, header);
	req->hlen += header->hlen;

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
