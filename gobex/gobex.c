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

#include <unistd.h>
#include <string.h>

#include "gobex.h"

/* Header types */
#define G_OBEX_HDR_TYPE_UNICODE	(0 << 6)
#define G_OBEX_HDR_TYPE_BYTES	(1 << 6)
#define G_OBEX_HDR_TYPE_UINT8	(2 << 6)
#define G_OBEX_HDR_TYPE_UINT32	(3 << 6)

#define G_OBEX_HDR_TYPE(id)	((id) & 0xc0)

struct _GObexHeader {
	guint8 id;
	gboolean extdata;
	size_t vlen;			/* Length of value */
	size_t hlen;			/* Length of full encoded header */
	union {
		char *string;		/* UTF-8 converted from UTF-16 */
		guint8 *data;		/* Own buffer */
		const guint8 *extdata;	/* Reference to external buffer */
		guint8 u8;
		guint32 u32;
	} v;
};

struct _GObexRequest {
	guint8 opcode;

	GObexDataPolicy data_policy;

	union {
		void *data;		/* Non-header data */
		const void *data_ref;	/* Reference to non-header data */
	} req;
	size_t req_data_len;

	size_t hlen;		/* Length of all encoded headers */
	GSList *headers;
};

struct _GObex {
	gint ref_count;
	GIOChannel *io;

	GQueue *req_queue;
};

struct connect_data {
	guint8 version;
	guint8 flags;
	guint16 mtu;
} __attribute__ ((packed));

struct setpath_data {
	guint8 flags;
	guint8 constants;
} __attribute__ ((packed));

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
		(*utf16)[i] = g_htons((*utf16)[i]);

	utf16_len = (utf16_len + 1) << 1;

	return utf16_len;
}

static guint8 *put_bytes(guint8 *to, const void *from, size_t count)
{
	memcpy(to, from, count);
	return (to + count);
}

static const guint8 *get_bytes(void *to, const guint8 *from, size_t count)
{
	memcpy(to, from, count);
	return (from + count);
}

size_t g_obex_header_encode(GObexHeader *header, void *buf, size_t buf_len)
{
	guint8 *ptr = buf;
	guint16 u16;
	guint32 u32;
	gunichar2 *utf16;
	glong utf16_len;

	if (buf_len < header->hlen)
		return 0;

	ptr = put_bytes(ptr, &header->id, sizeof(header->id));

	switch (G_OBEX_HDR_TYPE(header->id)) {
	case G_OBEX_HDR_TYPE_UNICODE:
		utf16_len = utf8_to_utf16(&utf16, header->v.string);
		if (utf16_len < 0 || (guint16) utf16_len > buf_len)
			return 0;
		g_assert_cmpuint(utf16_len + 3, ==, header->hlen);
		u16 = g_htons(utf16_len + 3);
		ptr = put_bytes(ptr, &u16, sizeof(u16));
		ptr = put_bytes(ptr, utf16, utf16_len);
		g_free(utf16);
		break;
	case G_OBEX_HDR_TYPE_BYTES:
		u16 = g_htons(header->hlen);
		ptr = put_bytes(ptr, &u16, sizeof(u16));
		if (header->extdata)
			ptr = put_bytes(ptr, header->v.extdata, header->vlen);
		else
			ptr = put_bytes(ptr, header->v.data, header->vlen);
		break;
	case G_OBEX_HDR_TYPE_UINT8:
		*ptr = header->v.u8;
		break;
	case G_OBEX_HDR_TYPE_UINT32:
		u32 = g_htonl(header->v.u32);
		ptr = put_bytes(ptr, &u32, sizeof(u32));
		break;
	default:
		g_assert_not_reached();
	}

	return header->hlen;
}

GObexHeader *g_obex_header_decode(const void *data, size_t len,
				GObexDataPolicy data_policy, size_t *parsed)
{
	GObexHeader *header;
	const guint8 *ptr = data;
	guint16 hdr_len;
	size_t str_len;

	if (len < 2)
		return NULL;

	header = g_new0(GObexHeader, 1);

	ptr = get_bytes(&header->id, ptr, sizeof(header->id));

	switch (G_OBEX_HDR_TYPE(header->id)) {
	case G_OBEX_HDR_TYPE_UNICODE:
		if (len < 3)
			goto failed;
		ptr = get_bytes(&hdr_len, ptr, sizeof(hdr_len));
		hdr_len = g_ntohs(hdr_len);
		if (hdr_len > len || hdr_len < 5)
			goto failed;

		header->v.string = g_convert((const char *) ptr, hdr_len - 5,
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
		ptr = get_bytes(&hdr_len, ptr, sizeof(hdr_len));
		hdr_len = g_ntohs(hdr_len);
		if (hdr_len > len)
			goto failed;

		header->vlen = hdr_len - 3;
		header->hlen = hdr_len;

		switch (data_policy) {
		case G_OBEX_DATA_COPY:
			header->v.data = g_memdup(ptr, header->vlen);
			break;
		case G_OBEX_DATA_REF:
			header->extdata = TRUE;
			header->v.extdata = ptr;
			break;
		default:
			goto failed;
		}

		*parsed = hdr_len;

		break;
	case G_OBEX_HDR_TYPE_UINT8:
		header->vlen = 1;
		header->hlen = 2;
		header->v.u8 = *ptr;
		*parsed = 2;
		break;
	case G_OBEX_HDR_TYPE_UINT32:
		if (len < 5)
			goto failed;
		header->vlen = 4;
		header->hlen = 5;
		ptr = get_bytes(&header->v.u32, ptr, sizeof(header->v.u32));
		header->v.u32 = g_ntohl(header->v.u32);
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

GObexHeader *g_obex_header_unicode(guint8 id, const char *str)
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

GObexHeader *g_obex_header_bytes(guint8 id, void *data, size_t len,
						GObexDataPolicy data_policy)
{
	GObexHeader *header;

	if (G_OBEX_HDR_TYPE(id) != G_OBEX_HDR_TYPE_BYTES)
		return NULL;

	header = g_new0(GObexHeader, 1);

	header->id = id;
	header->vlen = len;
	header->hlen = len + 3;

	switch (data_policy) {
	case G_OBEX_DATA_INHERIT:
		header->v.data = data;
		break;
	case G_OBEX_DATA_COPY:
		header->v.data = g_memdup(data, len);
		break;
	case G_OBEX_DATA_REF:
		header->extdata = TRUE;
		header->v.extdata = data;
		break;
	}

	return header;
}

GObexHeader *g_obex_header_uint8(guint8 id, guint8 val)
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

GObexHeader *g_obex_header_uint32(guint8 id, guint32 val)
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

GObexRequest *g_obex_request_new(guint8 opcode)
{
	GObexRequest *req;

	req = g_new0(GObexRequest, 1);

	req->opcode = opcode;

	req->data_policy = G_OBEX_DATA_COPY;

	return req;
}

void g_obex_request_free(GObexRequest *req)
{
	switch (req->data_policy) {
	case G_OBEX_DATA_INHERIT:
	case G_OBEX_DATA_COPY:
		g_free(req->req.data);
		break;
	case G_OBEX_DATA_REF:
		break;
	}

	g_slist_foreach(req->headers, (GFunc) g_obex_header_free, NULL);
	g_slist_free(req->headers);
	g_free(req);
}

static ssize_t get_header_offset(guint8 opcode)
{
	switch (opcode) {
	case G_OBEX_OP_CONNECT:
		return sizeof(struct connect_data);
	case G_OBEX_OP_SETPATH:
		return sizeof(struct setpath_data);
	case G_OBEX_OP_DISCONNECT:
	case G_OBEX_OP_PUT:
	case G_OBEX_OP_GET:
	case G_OBEX_OP_SESSION:
	case G_OBEX_OP_ABORT:
		return 0;
	default:
		return -1;
	}
}

static gboolean parse_headers(GObexRequest *req, const void *data, size_t len,
						GObexDataPolicy data_policy)
{
	const guint8 *buf = data;

	while (len > 0) {
		GObexHeader *header;
		size_t parsed;

		header = g_obex_header_decode(buf, len, data_policy, &parsed);
		if (header == NULL)
			return FALSE;

		req->headers = g_slist_append(req->headers, header);

		len -= parsed;
		buf += parsed;
	}

	return TRUE;
}

GObexRequest *g_obex_request_decode(const void *data, size_t len,
						GObexDataPolicy data_policy)
{
	const guint8 *buf = data;
	guint16 packet_len;
	guint8 opcode;
	ssize_t header_offset;
	GObexRequest *req;

	if (len < 3)
		return NULL;

	buf = get_bytes(&opcode, buf, sizeof(opcode));
	buf = get_bytes(&packet_len, buf, sizeof(packet_len));

	packet_len = g_ntohs(packet_len);
	if (packet_len < len)
		return NULL;

	header_offset = get_header_offset(opcode);
	if (header_offset < 0)
		return NULL;

	req = g_obex_request_new(opcode);

	req->data_policy = data_policy;

	if (header_offset == 0)
		goto headers;

	if (3 + header_offset < (ssize_t) len)
		goto failed;

	req->req_data_len = header_offset;
	switch (data_policy) {
	case G_OBEX_DATA_COPY:
		req->req.data = g_malloc(header_offset);
		buf = get_bytes(req->req.data, buf, header_offset);
		break;
	case G_OBEX_DATA_REF:
		req->req.data_ref = buf;
		buf += header_offset;
		break;
	default:
		goto failed;
	}

headers:
	if (!parse_headers(req, buf, len - (buf - (guint8 *) data),
								data_policy))
		goto failed;

	return req;

failed:
	g_obex_request_free(req);
	return NULL;
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
