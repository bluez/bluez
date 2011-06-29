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

#define G_OBEX_DEFAULT_MTU	4096
#define G_OBEX_MINIMUM_MTU	255
#define G_OBEX_MAXIMUM_MTU	65535

#define FINAL_BIT		0x80

struct _GObex {
	gint ref_count;
	GIOChannel *io;
	guint io_source;

	gboolean (*read) (GObex *obex);
	gboolean (*write) (GObex *obex);

	guint8 *rx_buf;
	size_t rx_data;
	guint16 rx_pkt_len;

	guint8 *tx_buf;
	size_t tx_data;
	size_t tx_sent;

	guint write_source;

	guint16 rx_mtu;
	guint16 tx_mtu;

	GQueue *tx_queue;

	GObexRequestFunc req_func;
	gpointer req_func_data;

	GObexDisconnectFunc disconn_func;
	gpointer disconn_func_data;

	struct pending_pkt *pending_req;
};

struct pending_pkt {
	guint id;
	GObexPacket *pkt;
	GObexResponseFunc rsp_func;
	gpointer rsp_data;
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

static ssize_t req_header_offset(guint8 opcode)
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

static ssize_t rsp_header_offset(guint8 opcode)
{
	switch (opcode) {
	case G_OBEX_OP_CONNECT:
		return sizeof(struct connect_data);
	case G_OBEX_OP_SETPATH:
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

static void pending_pkt_free(struct pending_pkt *p)
{
	g_obex_packet_free(p->pkt);
	g_free(p);
}

static gboolean write_stream(GObex *obex)
{
	GIOStatus status;
	gsize bytes_written;
	gchar *buf;

	buf = (gchar *) &obex->tx_buf[obex->tx_sent];
	status = g_io_channel_write_chars(obex->io, buf, obex->tx_data,
							&bytes_written, NULL);
	if (status != G_IO_STATUS_NORMAL)
		return FALSE;

	obex->tx_sent += bytes_written;
	obex->tx_data -= bytes_written;

	return TRUE;
}

static gboolean write_packet(GObex *obex)
{
	return FALSE;
}

static gboolean write_data(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GObex *obex = user_data;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR))
		goto done;

	if (obex->tx_data == 0) {
		struct pending_pkt *p = g_queue_pop_head(obex->tx_queue);
		ssize_t len;

		if (p == NULL)
			goto done;

		/* Can't send a request while there's a pending one */
		if (obex->pending_req && p->id > 0) {
			g_queue_push_head(obex->tx_queue, p);
			goto done;
		}

		len = g_obex_packet_encode(p->pkt, obex->tx_buf, obex->tx_mtu);
		if (len < 0) {
			pending_pkt_free(p);
			goto done;
		}

		if (p->id > 0)
			obex->pending_req = p;
		else
			pending_pkt_free(p);

		obex->tx_data = len;
		obex->tx_sent = 0;
	}

	if (!obex->write(obex))
		goto done;

	if (obex->tx_data > 0 || g_queue_get_length(obex->tx_queue) > 0)
		return TRUE;

done:
	obex->tx_data = 0;
	obex->write_source = 0;
	return FALSE;
}

static void enable_tx(GObex *obex)
{
	GIOCondition cond;

	if (obex->write_source > 0)
		return;

	cond = G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	obex->write_source = g_io_add_watch(obex->io, cond, write_data, obex);

	return;
}

static gboolean g_obex_send_internal(GObex *obex, struct pending_pkt *p,
								GError **err)
{

	if (obex->io == NULL) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_DISCONNECTED,
					"The transport is not connected");
		return FALSE;
	}

	g_queue_push_tail(obex->tx_queue, p);

	if (g_queue_get_length(obex->tx_queue) > 1)
		return TRUE;

	if (p->id > 0 && obex->pending_req != NULL)
		return TRUE;

	enable_tx(obex);

	return TRUE;
}

gboolean g_obex_send(GObex *obex, GObexPacket *pkt, GError **err)
{
	struct pending_pkt *p;
	gboolean ret;

	if (obex == NULL || pkt == NULL) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_INVALID_ARGS,
				"Invalid arguments");
		return FALSE;
	}

	p = g_new0(struct pending_pkt, 1);
	p->pkt = pkt;

	ret = g_obex_send_internal(obex, p, err);
	if (ret == FALSE)
		pending_pkt_free(p);

	return ret;
}

guint g_obex_send_req(GObex *obex, GObexPacket *req, GObexResponseFunc func,
					gpointer user_data, GError **err)
{
	struct pending_pkt *p;
	static guint id = 1;

	p = g_new0(struct pending_pkt, 1);

	p->pkt = req;
	p->id = id++;
	p->rsp_func = func;
	p->rsp_data = user_data;

	if (!g_obex_send_internal(obex, p, err)) {
		pending_pkt_free(p);
		return 0;
	}

	return p->id;
}

gboolean g_obex_cancel_req(GObex *obex, guint req_id)
{
	return TRUE;
}

void g_obex_set_request_function(GObex *obex, GObexRequestFunc func,
							gpointer user_data)
{
	obex->req_func = func;
	obex->req_func_data = user_data;
}

void g_obex_set_disconnect_function(GObex *obex, GObexDisconnectFunc func,
							gpointer user_data)
{
	obex->disconn_func = func;
	obex->disconn_func_data = user_data;
}

static void parse_connect_data(GObex *obex, GObexPacket *pkt)
{
	const struct connect_data *data;
	guint16 u16;
	size_t data_len;

	data = g_obex_packet_get_data(pkt, &data_len);
	if (data == NULL || data_len != sizeof(*data))
		return;

	memcpy(&u16, &data->mtu, sizeof(u16));

	obex->tx_mtu = g_ntohs(u16);
	obex->tx_buf = g_realloc(obex->tx_buf, obex->tx_mtu);
}

static void handle_response(GObex *obex, GError *err, GObexPacket *rsp)
{
	struct pending_pkt *p = obex->pending_req;

	if (rsp != NULL) {
		guint8 op = g_obex_packet_get_operation(p->pkt, NULL);
		if (op == G_OBEX_OP_CONNECT)
			parse_connect_data(obex, rsp);
	}

	if (p->rsp_func)
		p->rsp_func(obex, err, rsp, p->rsp_data);

	pending_pkt_free(p);
	obex->pending_req = NULL;

	if (g_queue_get_length(obex->tx_queue) > 0)
		enable_tx(obex);
}

static void handle_request(GObex *obex, GError *err, GObexPacket *req)
{
	if (g_obex_packet_get_operation(req, NULL) == G_OBEX_OP_CONNECT)
		parse_connect_data(obex, req);

	if (obex->req_func)
		obex->req_func(obex, req, obex->req_func_data);
}

static gboolean g_obex_handle_packet(GObex *obex, GError *err, GObexPacket *pkt)
{
	if (obex->pending_req)
		handle_response(obex, err, pkt);
	else if (pkt != NULL)
		handle_request(obex, err, pkt);

	/* FIXME: Application callback needed for err != NULL? */

	return TRUE;
}

static gboolean read_stream(GObex *obex)
{
	GIOChannel *io = obex->io;
	GIOStatus status;
	gsize rbytes, toread;
	guint16 u16;
	gchar *buf;

	if (obex->rx_data >= 3)
		goto read_body;

	rbytes = 0;
	toread = 3 - obex->rx_data;
	buf = (gchar *) &obex->rx_buf[obex->rx_data];

	status = g_io_channel_read_chars(io, buf, toread, &rbytes, NULL);
	if (status != G_IO_STATUS_NORMAL)
		return TRUE;

	obex->rx_data += rbytes;
	if (obex->rx_data < 3)
		return TRUE;

	memcpy(&u16, &buf[1], sizeof(u16));
	obex->rx_pkt_len = g_ntohs(u16);

read_body:
	if (obex->rx_data >= obex->rx_pkt_len)
		return TRUE;

	do {
		toread = obex->rx_pkt_len - obex->rx_data;
		buf = (gchar *) &obex->rx_buf[obex->rx_data];

		status = g_io_channel_read_chars(io, buf, toread, &rbytes, NULL);
		if (status != G_IO_STATUS_NORMAL)
			return TRUE;

		obex->rx_data += rbytes;
	} while (rbytes > 0 && obex->rx_data < obex->rx_pkt_len);

	return TRUE;
}

static gboolean read_packet(GObex *obex)
{
	return FALSE;
}

static gboolean incoming_data(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GObex *obex = user_data;
	GObexPacket *pkt;
	ssize_t header_offset;
	GError *err = NULL;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR))
		goto failed;

	if (!obex->read(obex))
		goto failed;

	if (obex->rx_data < 3 || obex->rx_data < obex->rx_pkt_len)
		return TRUE;

	if (obex->pending_req) {
		struct pending_pkt *p = obex->pending_req;
		guint8 opcode = g_obex_packet_get_operation(p->pkt, NULL);
		header_offset = req_header_offset(opcode);
	} else {
		guint8 opcode = obex->rx_buf[0] & ~FINAL_BIT;
		header_offset = rsp_header_offset(opcode);
	}

	if (header_offset < 0)
		goto failed;

	pkt = g_obex_packet_decode(obex->rx_buf, obex->rx_data, header_offset,
							G_OBEX_DATA_REF, &err);

	g_obex_handle_packet(obex, err, pkt);

	if (err != NULL)
		g_error_free(err);

	if (pkt != NULL)
		g_obex_packet_free(pkt);

	obex->rx_data = 0;

	return TRUE;

failed:
	g_io_channel_unref(obex->io);
	obex->io = NULL;
	obex->io_source = 0;

	if (obex->disconn_func)
		obex->disconn_func(obex, obex->disconn_func_data);

	return FALSE;
}

GObex *g_obex_new(GIOChannel *io, GObexTransportType transport_type)
{
	GObex *obex;
	GIOCondition cond;

	if (io == NULL)
		return NULL;

	obex = g_new0(GObex, 1);

	obex->io = io;
	obex->ref_count = 1;
	obex->rx_mtu = G_OBEX_DEFAULT_MTU;
	obex->tx_mtu = G_OBEX_MINIMUM_MTU;
	obex->tx_queue = g_queue_new();
	obex->rx_buf = g_malloc(obex->rx_mtu);
	obex->tx_buf = g_malloc(obex->tx_mtu);

	switch (transport_type) {
	case G_OBEX_TRANSPORT_STREAM:
		obex->read = read_stream;
		obex->write = write_stream;
		break;
	case G_OBEX_TRANSPORT_PACKET:
		obex->read = read_packet;
		obex->write = write_packet;
		break;
	}

	g_io_channel_set_encoding(io, NULL, NULL);
	g_io_channel_set_buffered(io, FALSE);
	cond = G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	obex->io_source = g_io_add_watch(io, cond, incoming_data, obex);

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

	g_queue_foreach(obex->tx_queue, (GFunc) pending_pkt_free, NULL);
	g_queue_free(obex->tx_queue);

	if (obex->io != NULL)
		g_io_channel_unref(obex->io);

	if (obex->io_source > 0)
		g_source_remove(obex->io_source);

	g_free(obex->rx_buf);
	g_free(obex->tx_buf);

	if (obex->pending_req)
		pending_pkt_free(obex->pending_req);

	g_free(obex);
}
