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
#include <errno.h>

#include "gobex-packet.h"

#define FINAL_BIT 0x80

struct _GObexPacket {
	guint8 opcode;
	gboolean final;

	GObexDataPolicy data_policy;

	union {
		void *buf;		/* Non-header data */
		const void *buf_ref;	/* Reference to non-header data */
	} data;
	gsize data_len;

	gsize hlen;		/* Length of all encoded headers */
	GSList *headers;
};

GObexHeader *g_obex_packet_get_header(GObexPacket *pkt, guint8 id)
{
	GSList *l;

	for (l = pkt->headers; l != NULL; l = g_slist_next(l)) {
		GObexHeader *hdr = l->data;

		if (g_obex_header_get_id(hdr) == id)
			return hdr;
	}

	return NULL;
}

guint8 g_obex_packet_get_operation(GObexPacket *pkt, gboolean *final)
{
	if (final)
		*final = pkt->final;

	return pkt->opcode;
}

GObexHeader *g_obex_packet_find_header(GObexPacket *pkt, guint8 id)
{
	GSList *l;

	for (l = pkt->headers; l != NULL; l = g_slist_next(l)) {
		GObexHeader *hdr = l->data;

		if (g_obex_header_get_id(hdr) == id)
			return hdr;
	}

	return NULL;
}

gboolean g_obex_packet_prepend_header(GObexPacket *pkt, GObexHeader *header)
{
	pkt->headers = g_slist_prepend(pkt->headers, header);
	pkt->hlen += g_obex_header_get_length(header);

	return TRUE;
}

gboolean g_obex_packet_add_header(GObexPacket *pkt, GObexHeader *header)
{
	pkt->headers = g_slist_append(pkt->headers, header);
	pkt->hlen += g_obex_header_get_length(header);

	return TRUE;
}

const void *g_obex_packet_get_data(GObexPacket *pkt, gsize *len)
{
	if (pkt->data_len == 0) {
		*len = 0;
		return NULL;
	}

	*len = pkt->data_len;

	switch (pkt->data_policy) {
	case G_OBEX_DATA_INHERIT:
	case G_OBEX_DATA_COPY:
		return pkt->data.buf;
	case G_OBEX_DATA_REF:
		return pkt->data.buf_ref;
	}

	g_assert_not_reached();
}

gboolean g_obex_packet_set_data(GObexPacket *pkt, const void *data, gsize len,
						GObexDataPolicy data_policy)
{
	if (pkt->data.buf || pkt->data.buf_ref)
		return FALSE;

	pkt->data_policy = data_policy;
	pkt->data_len = len;

	switch (data_policy) {
	case G_OBEX_DATA_COPY:
		pkt->data.buf = g_memdup(data, len);
		break;
	case G_OBEX_DATA_REF:
		pkt->data.buf_ref = data;
		break;
	case G_OBEX_DATA_INHERIT:
		pkt->data.buf = (void *) data;
		break;
	}

	return TRUE;
}

GObexPacket *g_obex_packet_new(guint8 opcode, gboolean final, GSList *headers)
{
	GObexPacket *pkt;

	pkt = g_new0(GObexPacket, 1);

	pkt->opcode = opcode;
	pkt->final = final;
	pkt->headers = headers;

	pkt->data_policy = G_OBEX_DATA_COPY;

	return pkt;
}

void g_obex_packet_free(GObexPacket *pkt)
{
	switch (pkt->data_policy) {
	case G_OBEX_DATA_INHERIT:
	case G_OBEX_DATA_COPY:
		g_free(pkt->data.buf);
		break;
	case G_OBEX_DATA_REF:
		break;
	}

	g_slist_foreach(pkt->headers, (GFunc) g_obex_header_free, NULL);
	g_slist_free(pkt->headers);
	g_free(pkt);
}

static gboolean parse_headers(GObexPacket *pkt, const void *data, gsize len,
						GObexDataPolicy data_policy,
						GError **err)
{
	const guint8 *buf = data;

	while (len > 0) {
		GObexHeader *header;
		gsize parsed;

		header = g_obex_header_decode(buf, len, data_policy, &parsed,
									err);
		if (header == NULL)
			return FALSE;

		pkt->headers = g_slist_append(pkt->headers, header);
		pkt->hlen += parsed;

		len -= parsed;
		buf += parsed;
	}

	return TRUE;
}

static const guint8 *get_bytes(void *to, const guint8 *from, gsize count)
{
	memcpy(to, from, count);
	return (from + count);
}

GObexPacket *g_obex_packet_decode(const void *data, gsize len,
						gsize header_offset,
						GObexDataPolicy data_policy,
						GError **err)
{
	const guint8 *buf = data;
	guint16 packet_len;
	guint8 opcode;
	GObexPacket *pkt;
	gboolean final;

	if (data_policy == G_OBEX_DATA_INHERIT) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_INVALID_ARGS,
							"Invalid data policy");
		return NULL;
	}

	if (len < 3 + header_offset) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR,
					"Not enough data to decode packet");
		return NULL;
	}

	buf = get_bytes(&opcode, buf, sizeof(opcode));
	buf = get_bytes(&packet_len, buf, sizeof(packet_len));

	packet_len = g_ntohs(packet_len);
	if (packet_len != len) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR,
				"Incorrect packet length (%u != %zu)",
				packet_len, len);
		return NULL;
	}

	final = (opcode & FINAL_BIT) ? TRUE : FALSE;
	opcode &= ~FINAL_BIT;

	pkt = g_obex_packet_new(opcode, final, NULL);

	if (header_offset == 0)
		goto headers;

	g_obex_packet_set_data(pkt, buf, header_offset, data_policy);
	buf += header_offset;

headers:
	if (!parse_headers(pkt, buf, len - (3 + header_offset),
							data_policy, err))
		goto failed;

	return pkt;

failed:
	g_obex_packet_free(pkt);
	return NULL;
}

gssize g_obex_packet_encode(GObexPacket *pkt, guint8 *buf, gsize len)
{
	gsize count;
	guint16 u16;
	GSList *l;

	if (3 + pkt->data_len + pkt->hlen > len)
		return -ENOBUFS;

	buf[0] = pkt->opcode;
	if (pkt->final)
		buf[0] |= FINAL_BIT;

	if (pkt->data_len > 0) {
		if (pkt->data_policy == G_OBEX_DATA_REF)
			memcpy(&buf[3], pkt->data.buf_ref, pkt->data_len);
		else
			memcpy(&buf[3], pkt->data.buf, pkt->data_len);
	}

	count = 3 + pkt->data_len;

	for (l = pkt->headers; l != NULL; l = g_slist_next(l)) {
		GObexHeader *hdr = l->data;
		gssize ret;

		if (count >= len)
			return -ENOBUFS;

		ret = g_obex_header_encode(hdr, buf + count, len - count);
		if (ret < 0)
			return ret;

		/* Fix-up on-demand body header type and final bit. This
		 * breaks the layers of abstraction a bit but it's the
		 * simplest way to avoid two consecutive empty packets */
		if (g_obex_header_get_id(hdr) == G_OBEX_HDR_ID_BODY &&
								ret == 3) {
			buf[0] |= FINAL_BIT;
			buf[count] = G_OBEX_HDR_ID_BODY_END;
		}

		count += ret;
	}

	u16 = g_htons(count);
	memcpy(&buf[1], &u16, sizeof(u16));

	return count;
}
