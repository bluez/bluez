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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "gobex.h"
#include "glib-helper.h"

#define G_OBEX_DEFAULT_MTU	4096
#define G_OBEX_MINIMUM_MTU	255
#define G_OBEX_MAXIMUM_MTU	65535

#define G_OBEX_DEFAULT_TIMEOUT	5

#define G_OBEX_OP_NONE		0xff

#define FINAL_BIT		0x80

#define CONNID_INVALID		0xffffffff

struct _GObex {
	gint ref_count;
	GIOChannel *io;
	guint io_source;

	gboolean (*read) (GObex *obex, GError **err);
	gboolean (*write) (GObex *obex, GError **err);

	guint8 *rx_buf;
	size_t rx_data;
	guint16 rx_pkt_len;
	guint8 rx_last_op;

	guint8 *tx_buf;
	size_t tx_data;
	size_t tx_sent;

	gboolean suspended;

	guint write_source;

	gssize io_rx_mtu;
	gssize io_tx_mtu;

	guint16 rx_mtu;
	guint16 tx_mtu;

	guint32 conn_id;

	GQueue *tx_queue;

	GSList *req_handlers;

	GObexFunc disconn_func;
	gpointer disconn_func_data;

	struct pending_pkt *pending_req;
};

struct pending_pkt {
	guint id;
	GObex *obex;
	GObexPacket *pkt;
	guint timeout;
	guint timeout_id;
	GObexResponseFunc rsp_func;
	gpointer rsp_data;
	gboolean cancelled;
};

struct req_handler {
	guint id;
	guint8 opcode;
	GObexRequestFunc func;
	gpointer user_data;
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
	if (p->obex != NULL)
		g_obex_unref(p->obex);

	if (p->timeout_id > 0)
		g_source_remove(p->timeout_id);

	g_obex_packet_free(p->pkt);

	g_free(p);
}

static gboolean req_timeout(gpointer user_data)
{
	GObex *obex = user_data;
	struct pending_pkt *p = obex->pending_req;

	g_assert(p != NULL);

	obex->pending_req = NULL;

	if (p->rsp_func) {
		GError *err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_TIMEOUT,
					"Timed out waiting for response");
		p->rsp_func(obex, err, NULL, p->rsp_data);
		g_error_free(err);
	}

	pending_pkt_free(p);

	return FALSE;
}

static gboolean write_stream(GObex *obex, GError **err)
{
	GIOStatus status;
	gsize bytes_written;
	gchar *buf;

	buf = (gchar *) &obex->tx_buf[obex->tx_sent];
	status = g_io_channel_write_chars(obex->io, buf, obex->tx_data,
							&bytes_written, err);
	if (status != G_IO_STATUS_NORMAL)
		return FALSE;

	obex->tx_sent += bytes_written;
	obex->tx_data -= bytes_written;

	return TRUE;
}

static gboolean write_packet(GObex *obex, GError **err)
{
	GIOStatus status;
	gsize bytes_written;
	gchar *buf;

	buf = (gchar *) &obex->tx_buf[obex->tx_sent];
	status = g_io_channel_write_chars(obex->io, buf, obex->tx_data,
							&bytes_written, err);
	if (status != G_IO_STATUS_NORMAL)
		return FALSE;

	if (bytes_written != obex->tx_data)
		return FALSE;

	obex->tx_sent += bytes_written;
	obex->tx_data -= bytes_written;

	return TRUE;
}

static gboolean write_data(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GObex *obex = user_data;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR))
		goto stop_tx;

	if (obex->tx_data == 0) {
		struct pending_pkt *p = g_queue_pop_head(obex->tx_queue);
		ssize_t len;

		if (p == NULL)
			goto stop_tx;

		/* Can't send a request while there's a pending one */
		if (obex->pending_req && p->id > 0) {
			g_queue_push_head(obex->tx_queue, p);
			goto stop_tx;
		}

		len = g_obex_packet_encode(p->pkt, obex->tx_buf, obex->tx_mtu);
		if (len == -EAGAIN) {
			g_queue_push_head(obex->tx_queue, p);
			g_obex_suspend(obex);
			goto stop_tx;
		}

		if (len < 0) {
			pending_pkt_free(p);
			goto done;
		}

		if (p->id > 0) {
			obex->pending_req = p;
			p->timeout_id = g_timeout_add_seconds(p->timeout,
							req_timeout, obex);
		} else
			pending_pkt_free(p);

		obex->tx_data = len;
		obex->tx_sent = 0;
	}

	if (obex->suspended) {
		obex->write_source = 0;
		return FALSE;
	}

	if (!obex->write(obex, NULL))
		goto stop_tx;

done:
	if (obex->tx_data > 0 || g_queue_get_length(obex->tx_queue) > 0)
		return TRUE;

stop_tx:
	obex->rx_last_op = G_OBEX_OP_NONE;
	obex->tx_data = 0;
	obex->write_source = 0;
	return FALSE;
}

static void enable_tx(GObex *obex)
{
	GIOCondition cond;

	if (obex->suspended)
		return;

	if (obex->write_source > 0)
		return;

	cond = G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL;
	obex->write_source = g_io_add_watch(obex->io, cond, write_data, obex);
}

static gboolean g_obex_send_internal(GObex *obex, struct pending_pkt *p,
								GError **err)
{

	if (obex->io == NULL) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_DISCONNECTED,
					"The transport is not connected");
		return FALSE;
	}

	if (g_obex_packet_get_operation(p->pkt, NULL) == G_OBEX_OP_ABORT)
		g_queue_push_head(obex->tx_queue, p);
	else
		g_queue_push_tail(obex->tx_queue, p);

	if (obex->pending_req == NULL || p->id == 0)
		enable_tx(obex);

	return TRUE;
}

static void init_connect_data(GObex *obex, struct connect_data *data)
{
	guint16 u16;

	memset(data, 0, sizeof(*data));

	data->version = 0x10;
	data->flags = 0;

	u16 = g_htons(obex->rx_mtu);
	memcpy(&data->mtu, &u16, sizeof(u16));
}

static void prepare_connect_rsp(GObex *obex, GObexPacket *rsp)
{
	GObexHeader *connid;
	struct connect_data data;
	static guint32 next_connid = 1;

	init_connect_data(obex, &data);
	g_obex_packet_set_data(rsp, &data, sizeof(data), G_OBEX_DATA_COPY);

	connid = g_obex_packet_find_header(rsp, G_OBEX_HDR_CONNECTION);
	if (connid != NULL) {
		g_obex_header_get_uint32(connid, &obex->conn_id);
		return;
	}

	obex->conn_id = next_connid++;

	connid = g_obex_header_new_uint32(G_OBEX_HDR_CONNECTION,
							obex->conn_id);
	g_obex_packet_prepend_header(rsp, connid);
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

	if (obex->rx_last_op == G_OBEX_OP_CONNECT)
		prepare_connect_rsp(obex, pkt);

	p = g_new0(struct pending_pkt, 1);
	p->pkt = pkt;

	ret = g_obex_send_internal(obex, p, err);
	if (ret == FALSE)
		pending_pkt_free(p);

	return ret;
}

guint g_obex_send_req(GObex *obex, GObexPacket *req, gint timeout,
			GObexResponseFunc func, gpointer user_data,
			GError **err)
{
	GObexHeader *connid;
	struct pending_pkt *p;
	static guint id = 1;

	if (obex->conn_id == CONNID_INVALID)
		goto create_pending;

	connid = g_obex_packet_find_header(req, G_OBEX_HDR_CONNECTION);
	if (connid != NULL)
		goto create_pending;

	connid = g_obex_header_new_uint32(G_OBEX_HDR_CONNECTION,
							obex->conn_id);
	g_obex_packet_prepend_header(req, connid);

create_pending:
	p = g_new0(struct pending_pkt, 1);

	p->pkt = req;
	p->id = id++;
	p->rsp_func = func;
	p->rsp_data = user_data;

	if (timeout < 0)
		p->timeout = G_OBEX_DEFAULT_TIMEOUT;
	else
		p->timeout = timeout;

	if (!g_obex_send_internal(obex, p, err)) {
		pending_pkt_free(p);
		return 0;
	}

	return p->id;
}

static gint pending_pkt_cmp(gconstpointer a, gconstpointer b)
{
	const struct pending_pkt *p = a;
	guint id = GPOINTER_TO_UINT(b);

	return (p->id - id);
}

static gboolean pending_req_abort(GObex *obex, GError **err)
{
	if (obex->pending_req->cancelled)
		return TRUE;

	obex->pending_req->cancelled = TRUE;

	return g_obex_send_rsp(obex, G_OBEX_OP_ABORT, err, G_OBEX_HDR_INVALID);
}

static gboolean cancel_complete(gpointer user_data)
{
	struct pending_pkt *p = user_data;
	GObex *obex = p->obex;
	GError *err;

	g_assert(p->rsp_func != NULL);

	err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_CANCELLED,
					"The request was cancelled");
	p->rsp_func(obex, err, NULL, p->rsp_data);

	g_error_free(err);

	pending_pkt_free(p);

	return FALSE;
}

gboolean g_obex_cancel_req(GObex *obex, guint req_id, gboolean remove_callback)
{
	GList *match;
	struct pending_pkt *p;

	if (obex->pending_req && obex->pending_req->id == req_id) {
		if (!pending_req_abort(obex, NULL)) {
			p = obex->pending_req;
			obex->pending_req = NULL;
			goto immediate_completion;
		}

		return TRUE;
	}

	match = g_queue_find_custom(obex->tx_queue, GUINT_TO_POINTER(req_id),
							pending_pkt_cmp);
	if (match == NULL)
		return FALSE;

	p = match->data;

	g_queue_delete_link(obex->tx_queue, match);

immediate_completion:
	p->cancelled = TRUE;
	p->obex = g_obex_ref(obex);

	if (remove_callback || p->rsp_func == NULL)
		pending_pkt_free(p);
	else
		g_idle_add(cancel_complete, p);

	return TRUE;
}

gboolean g_obex_send_rsp(GObex *obex, guint8 rspcode, GError **err,
						guint8 first_hdr_type, ...)
{
	GObexPacket *rsp;
	va_list args;

	va_start(args, first_hdr_type);
	rsp = g_obex_packet_new_valist(rspcode, TRUE, first_hdr_type, args);
	va_end(args);

	return g_obex_send(obex, rsp, err);
}

void g_obex_set_disconnect_function(GObex *obex, GObexFunc func,
							gpointer user_data)
{
	obex->disconn_func = func;
	obex->disconn_func_data = user_data;
}

static gint req_handler_cmpop(gconstpointer a, gconstpointer b)
{
	const struct req_handler *handler = a;
	guint opcode = GPOINTER_TO_UINT(b);

	return (gint) handler->opcode - (gint) opcode;
}

static gint req_handler_cmpid(gconstpointer a, gconstpointer b)
{
	const struct req_handler *handler = a;
	guint id = GPOINTER_TO_UINT(b);

	return (gint) handler->id - (gint) id;
}

guint g_obex_add_request_function(GObex *obex, guint8 opcode,
						GObexRequestFunc func,
						gpointer user_data)
{
	struct req_handler *handler;
	static guint next_id = 1;

	handler = g_new0(struct req_handler, 1);
	handler->id = next_id++;
	handler->opcode = opcode;
	handler->func = func;
	handler->user_data = user_data;

	obex->req_handlers = g_slist_prepend(obex->req_handlers, handler);

	return handler->id;
}

gboolean g_obex_remove_request_function(GObex *obex, guint id)
{
	struct req_handler *handler;
	GSList *match;

	match = g_slist_find_custom(obex->req_handlers, GUINT_TO_POINTER(id),
							req_handler_cmpid);
	if (match == NULL)
		return FALSE;

	handler = match->data;

	obex->req_handlers = g_slist_delete_link(obex->req_handlers, match);
	g_free(handler);

	return TRUE;
}

void g_obex_suspend(GObex *obex)
{
	if (obex->write_source > 0) {
		g_source_remove(obex->write_source);
		obex->write_source = 0;
	}

	obex->suspended = TRUE;
}

void g_obex_resume(GObex *obex)
{
	obex->suspended = FALSE;

	if (g_queue_get_length(obex->tx_queue) > 0 || obex->tx_data > 0)
		enable_tx(obex);
}

static void parse_connect_data(GObex *obex, GObexPacket *pkt)
{
	const struct connect_data *data;
	GObexHeader *connid;
	guint16 u16;
	size_t data_len;

	data = g_obex_packet_get_data(pkt, &data_len);
	if (data == NULL || data_len != sizeof(*data))
		return;

	memcpy(&u16, &data->mtu, sizeof(u16));

	obex->tx_mtu = g_ntohs(u16);
	if (obex->io_tx_mtu > 0 && obex->tx_mtu > obex->io_tx_mtu)
		obex->tx_mtu = obex->io_tx_mtu;
	obex->tx_buf = g_realloc(obex->tx_buf, obex->tx_mtu);

	connid = g_obex_packet_find_header(pkt, G_OBEX_HDR_CONNECTION);
	if (connid != NULL)
		g_obex_header_get_uint32(connid, &obex->conn_id);
}

static void handle_response(GObex *obex, GError *err, GObexPacket *rsp)
{
	struct pending_pkt *p = obex->pending_req;
	gboolean disconn = err ? TRUE : FALSE, final_rsp = TRUE;

	if (rsp != NULL) {
		guint8 opcode;

		g_obex_packet_get_operation(rsp, &final_rsp);

		opcode = g_obex_packet_get_operation(p->pkt, NULL);
		if (opcode == G_OBEX_OP_CONNECT)
			parse_connect_data(obex, rsp);
	}

	if (p->cancelled)
		err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_CANCELLED,
					"The operation was cancelled");

	if (p->rsp_func)
		p->rsp_func(obex, err, rsp, p->rsp_data);

	if (p->cancelled)
		g_error_free(err);

	if (final_rsp) {
		pending_pkt_free(p);
		obex->pending_req = NULL;
	}

	if (!disconn && g_queue_get_length(obex->tx_queue) > 0)
		enable_tx(obex);
}

static void handle_request(GObex *obex, GObexPacket *req)
{
	GSList *match;
	guint op;

	if (g_obex_packet_get_operation(req, NULL) == G_OBEX_OP_CONNECT)
		parse_connect_data(obex, req);

	op = g_obex_packet_get_operation(req, NULL);

	match = g_slist_find_custom(obex->req_handlers, GUINT_TO_POINTER(op),
							req_handler_cmpop);
	if (match) {
		struct req_handler *handler = match->data;
		handler->func(obex, req, handler->user_data);
		return;
	}

	g_obex_send_rsp(obex, G_OBEX_RSP_NOT_IMPLEMENTED, NULL,
							G_OBEX_HDR_INVALID);
}

static gboolean read_stream(GObex *obex, GError **err)
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

	if (obex->rx_pkt_len > obex->rx_mtu) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR,
				"Too big incoming packet");
		return FALSE;
	}

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

static gboolean read_packet(GObex *obex, GError **err)
{
	GIOChannel *io = obex->io;
	GError *read_err = NULL;
	GIOStatus status;
	gsize rbytes;
	guint16 u16;

	if (obex->rx_data > 0) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR,
				"RX buffer not empty before reading packet");
		return FALSE;
	}

	status = g_io_channel_read_chars(io, (gchar *) obex->rx_buf,
					obex->rx_mtu, &rbytes, &read_err);
	if (status != G_IO_STATUS_NORMAL) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR,
				"Unable to read data: %s", read_err->message);
		g_error_free(read_err);
		return FALSE;
	}

	obex->rx_data += rbytes;

	if (rbytes < 3) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR,
				"Incomplete packet received");
		return FALSE;
	}

	memcpy(&u16, &obex->rx_buf[1], sizeof(u16));
	obex->rx_pkt_len = g_ntohs(u16);

	if (obex->rx_pkt_len != rbytes) {
		g_set_error(err, G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR,
			"Data size doesn't match packet size (%zu != %u)",
			rbytes, obex->rx_pkt_len);
		return FALSE;
	}

	return TRUE;
}

static gboolean incoming_data(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	GObex *obex = user_data;
	GObexPacket *pkt;
	ssize_t header_offset;
	GError *err = NULL;
	guint8 opcode;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_DISCONNECTED,
					"Transport got disconnected");
		goto failed;
	}

	if (!obex->read(obex, &err))
		goto failed;

	if (obex->rx_data < 3 || obex->rx_data < obex->rx_pkt_len)
		return TRUE;

	if (obex->pending_req) {
		struct pending_pkt *p = obex->pending_req;
		opcode = g_obex_packet_get_operation(p->pkt, NULL);
		header_offset = rsp_header_offset(opcode);
	} else {
		opcode = obex->rx_buf[0] & ~FINAL_BIT;
		/* Unexpected response -- fail silently */
		if (opcode > 0x1f && opcode < 0xff) {
			obex->rx_data = 0;
			return TRUE;
		}
		header_offset = req_header_offset(opcode);
		obex->rx_last_op = opcode;
	}

	if (header_offset < 0) {
		err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_PARSE_ERROR,
				"Unknown header offset for opcode 0x%02x",
				opcode);
		goto failed;
	}

	pkt = g_obex_packet_decode(obex->rx_buf, obex->rx_data, header_offset,
							G_OBEX_DATA_REF, &err);
	if (pkt == NULL)
		goto failed;

	if (obex->pending_req)
		handle_response(obex, NULL, pkt);
	else
		handle_request(obex, pkt);

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
	obex->rx_data = 0;

	if (obex->pending_req)
		handle_response(obex, err, NULL);

	if (obex->disconn_func)
		obex->disconn_func(obex, err, obex->disconn_func_data);

	g_error_free(err);

	return FALSE;
}

GObex *g_obex_new(GIOChannel *io, GObexTransportType transport_type,
					gssize io_rx_mtu, gssize io_tx_mtu)
{
	GObex *obex;
	GIOCondition cond;

	if (io == NULL)
		return NULL;

	if (io_rx_mtu >= 0 && io_rx_mtu < G_OBEX_MINIMUM_MTU)
		return NULL;

	if (io_tx_mtu >= 0 && io_tx_mtu < G_OBEX_MINIMUM_MTU)
		return NULL;

	obex = g_new0(GObex, 1);

	obex->io = g_io_channel_ref(io);
	obex->ref_count = 1;
	obex->conn_id = CONNID_INVALID;
	obex->rx_last_op = G_OBEX_OP_NONE;

	obex->io_rx_mtu = io_rx_mtu;
	obex->io_tx_mtu = io_tx_mtu;

	if (io_rx_mtu > G_OBEX_MAXIMUM_MTU)
		obex->rx_mtu = G_OBEX_MAXIMUM_MTU;
	else if (io_rx_mtu < G_OBEX_MINIMUM_MTU)
		obex->rx_mtu = G_OBEX_DEFAULT_MTU;
	else
		obex->rx_mtu = io_rx_mtu;

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
	default:
		g_obex_unref(obex);
		return NULL;
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

	g_slist_free_full(obex->req_handlers, g_free);

	g_queue_foreach(obex->tx_queue, (GFunc) pending_pkt_free, NULL);
	g_queue_free(obex->tx_queue);

	if (obex->io != NULL)
		g_io_channel_unref(obex->io);

	if (obex->io_source > 0)
		g_source_remove(obex->io_source);

	if (obex->write_source > 0)
		g_source_remove(obex->write_source);

	g_free(obex->rx_buf);
	g_free(obex->tx_buf);

	if (obex->pending_req)
		pending_pkt_free(obex->pending_req);

	g_free(obex);
}

/* Higher level functions */

guint g_obex_connect(GObex *obex, GObexResponseFunc func, gpointer user_data,
					GError **err, guint8 first_hdr_id, ...)
{
	GObexPacket *req;
	struct connect_data data;
	va_list args;

	va_start(args, first_hdr_id);
	req = g_obex_packet_new_valist(G_OBEX_OP_CONNECT, TRUE,
							first_hdr_id, args);
	va_end(args);

	init_connect_data(obex, &data);
	g_obex_packet_set_data(req, &data, sizeof(data), G_OBEX_DATA_COPY);

	return g_obex_send_req(obex, req, -1, func, user_data, err);
}

guint g_obex_setpath(GObex *obex, const char *path, GObexResponseFunc func,
					gpointer user_data, GError **err)
{
	GObexPacket *req;
	struct setpath_data data;

	req = g_obex_packet_new(G_OBEX_OP_SETPATH, TRUE, G_OBEX_HDR_INVALID);

	memset(&data, 0, sizeof(data));

	if (strcmp(path, "..") == 0)
		data.flags = 0x03;
	else {
		GObexHeader *hdr;
		data.flags = 0x02;
		hdr = g_obex_header_new_unicode(G_OBEX_HDR_NAME, path);
		g_obex_packet_add_header(req, hdr);
	}

	g_obex_packet_set_data(req, &data, sizeof(data), G_OBEX_DATA_COPY);

	return g_obex_send_req(obex, req, -1, func, user_data, err);
}

guint g_obex_mkdir(GObex *obex, const char *path, GObexResponseFunc func,
					gpointer user_data, GError **err)
{
	GObexPacket *req;
	struct setpath_data data;

	req = g_obex_packet_new(G_OBEX_OP_SETPATH, TRUE, G_OBEX_HDR_NAME, path,
							G_OBEX_HDR_INVALID);

	memset(&data, 0, sizeof(data));
	g_obex_packet_set_data(req, &data, sizeof(data), G_OBEX_DATA_COPY);

	return g_obex_send_req(obex, req, -1, func, user_data, err);
}

guint g_obex_delete(GObex *obex, const char *name, GObexResponseFunc func,
					gpointer user_data, GError **err)
{
	GObexPacket *req;

	req = g_obex_packet_new(G_OBEX_OP_PUT, TRUE, G_OBEX_HDR_NAME, name,
							G_OBEX_HDR_INVALID);

	return g_obex_send_req(obex, req, -1, func, user_data, err);
}

guint g_obex_copy(GObex *obex, const char *name, const char *dest,
			GObexResponseFunc func, gpointer user_data,
			GError **err)
{
	GObexPacket *req;

	req = g_obex_packet_new(G_OBEX_OP_PUT, TRUE,
					G_OBEX_HDR_ACTION, G_OBEX_ACTION_COPY,
					G_OBEX_HDR_NAME, name,
					G_OBEX_HDR_DESTNAME, dest,
					G_OBEX_HDR_INVALID);

	return g_obex_send_req(obex, req, -1, func, user_data, err);
}

guint g_obex_move(GObex *obex, const char *name, const char *dest,
			GObexResponseFunc func, gpointer user_data,
			GError **err)
{
	GObexPacket *req;

	req = g_obex_packet_new(G_OBEX_OP_PUT, TRUE,
					G_OBEX_HDR_ACTION, G_OBEX_ACTION_MOVE,
					G_OBEX_HDR_NAME, name,
					G_OBEX_HDR_DESTNAME, dest,
					G_OBEX_HDR_INVALID);

	return g_obex_send_req(obex, req, -1, func, user_data, err);
}
