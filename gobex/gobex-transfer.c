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
#include "gobex-transfer.h"

static GSList *transfers = NULL;

struct transfer {
	guint id;
	guint8 opcode;

	GObex *obex;

	guint req_id;

	gint put_id;
	gint get_id;
	gint abort_id;

	GObexDataProducer data_producer;
	GObexDataConsumer data_consumer;
	GObexFunc complete_func;

	gpointer user_data;
};

static void transfer_free(struct transfer *transfer)
{
	transfers = g_slist_remove(transfers, transfer);

	if (transfer->req_id > 0)
		g_obex_cancel_req(transfer->obex, transfer->req_id, TRUE);

	if (transfer->put_id)
		g_obex_remove_request_function(transfer->obex,
							transfer->put_id);

	if (transfer->get_id)
		g_obex_remove_request_function(transfer->obex,
							transfer->req_id);

	if (transfer->abort_id)
		g_obex_remove_request_function(transfer->obex,
							transfer->abort_id);

	g_obex_unref(transfer->obex);
	g_free(transfer);
}

static void transfer_complete(struct transfer *transfer, GError *err)
{
	transfer->complete_func(transfer->obex, err, transfer->user_data);
	transfer_free(transfer);
}

static void transfer_abort_response(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct transfer *transfer = user_data;

	transfer->req_id = 0;

	/* Intentionally override error */
	err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_CANCELLED,
						"Operation was aborted");
	transfer_complete(transfer, err);
	g_error_free(err);
}


static gssize put_get_data(void *buf, gsize len, gpointer user_data)
{
	struct transfer *transfer = user_data;
	GObexPacket *req;
	GError *err = NULL;
	gssize ret;

	ret = transfer->data_producer(buf, len, transfer->user_data);
	if (ret >= 0)
		return ret;

	req = g_obex_packet_new(G_OBEX_OP_ABORT, TRUE, NULL);
	transfer->req_id = g_obex_send_req(transfer->obex, req, -1,
						transfer_abort_response,
						transfer, &err);
	if (err != NULL) {
		transfer_complete(transfer, err);
		g_error_free(err);
	}

	return ret;
}

static void transfer_response(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct transfer *transfer = user_data;
	GObexPacket *req;
	gboolean rspcode, final;

	transfer->req_id = 0;

	if (err != NULL) {
		transfer_complete(transfer, err);
		return;
	}

	rspcode = g_obex_packet_get_operation(rsp, &final);
	if (rspcode != G_OBEX_RSP_SUCCESS && rspcode != G_OBEX_RSP_CONTINUE) {
		GError *rsp_err;
		rsp_err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_FAILED,
					"Transfer failed (0x%02x)", rspcode);
		transfer_complete(transfer, rsp_err);
		g_error_free(rsp_err);
		return;
	}

	if (transfer->opcode == G_OBEX_OP_GET) {
		GObexHeader *body;
		body = g_obex_packet_get_header(rsp, G_OBEX_HDR_ID_BODY);
		if (body == NULL)
			body = g_obex_packet_get_header(rsp,
						G_OBEX_HDR_ID_BODY_END);
		if (body != NULL) {
			const guint8 *buf;
			gsize len;

			g_obex_header_get_bytes(body, &buf, &len);

			if (len > 0)
				transfer->data_consumer(buf, len,
							transfer->user_data);
		}
	}

	if (rspcode == G_OBEX_RSP_SUCCESS) {
		transfer_complete(transfer, NULL);
		return;
	}

	req = g_obex_packet_new(transfer->opcode, TRUE, NULL);

	if (transfer->opcode == G_OBEX_OP_PUT)
		g_obex_packet_add_body(req, put_get_data, transfer);

	transfer->req_id = g_obex_send_req(obex, req, -1, transfer_response,
							transfer, &err);
	if (err != NULL)
		transfer_complete(transfer, err);
}

static struct transfer *transfer_new(GObex *obex, guint8 opcode,
				GObexFunc complete_func, gpointer user_data)
{
	static guint next_id = 1;
	struct transfer *transfer;

	transfer = g_new0(struct transfer, 1);

	transfer->id = next_id++;
	transfer->opcode = opcode;
	transfer->obex = g_obex_ref(obex);
	transfer->complete_func = complete_func;
	transfer->user_data = user_data;

	transfers = g_slist_append(transfers, transfer);

	return transfer;
}

guint g_obex_put_req(GObex *obex, const char *type, const char *name,
			GObexDataProducer data_func,
			GObexFunc complete_func, gpointer user_data,
			GError **err)
{
	GObexPacket *req;
	GObexHeader *hdr;
	struct transfer *transfer;

	transfer = transfer_new(obex, G_OBEX_OP_PUT, complete_func, user_data);
	transfer->data_producer = data_func;

	req = g_obex_packet_new(G_OBEX_OP_PUT, TRUE, NULL);

	if (type) {
		hdr = g_obex_header_new_bytes(G_OBEX_HDR_ID_TYPE,
					(char *) type, strlen(type) + 1,
					G_OBEX_DATA_COPY);
		g_obex_packet_add_header(req, hdr);
	}

	if (name) {
		hdr = g_obex_header_new_unicode(G_OBEX_HDR_ID_NAME, name);
		g_obex_packet_add_header(req, hdr);
	}

	g_obex_packet_add_body(req, put_get_data, transfer);

	transfer->req_id = g_obex_send_req(obex, req, -1, transfer_response,
								transfer, err);
	if (transfer->req_id == 0) {
		transfer_free(transfer);
		return 0;
	}

	return transfer->id;
}

static void transfer_put_req(GObex *obex, GObexPacket *req, gpointer user_data)
{
	struct transfer *transfer = user_data;
	guint8 rspcode = G_OBEX_RSP_CONTINUE;
	GError *err = NULL;
	GObexPacket *rsp;
	GObexHeader *body;

	body = g_obex_packet_get_header(req, G_OBEX_HDR_ID_BODY);
	if (body == NULL) {
		body = g_obex_packet_get_header(req, G_OBEX_HDR_ID_BODY_END);
		rspcode = G_OBEX_RSP_SUCCESS;
	}

	if (body != NULL) {
		const guint8 *buf;
		gsize len;

		g_obex_header_get_bytes(body, &buf, &len);

		if (len > 0)
			transfer->data_consumer(buf, len, transfer->user_data);
	}

	rsp = g_obex_packet_new(rspcode, TRUE, NULL);
	if (!g_obex_send(obex, rsp, &err)) {
		transfer_complete(transfer, err);
		g_error_free(err);
	}

	if (rspcode == G_OBEX_RSP_SUCCESS)
		transfer_complete(transfer, NULL);
}

static void transfer_abort_req(GObex *obex, GObexPacket *req, gpointer user_data)
{
	struct transfer *transfer = user_data;
	GObexPacket *rsp;
	GError *err;

	err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_CANCELLED,
						"Request was aborted");
	transfer_complete(transfer, err);
	g_error_free(err);

	rsp = g_obex_packet_new(G_OBEX_RSP_SUCCESS, TRUE, NULL);
	g_obex_send(obex, rsp, NULL);
}

guint g_obex_put_rsp(GObex *obex, GObexPacket *req,
			GObexDataConsumer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err)
{
	struct transfer *transfer;
	gint id;

	transfer = transfer_new(obex, G_OBEX_OP_PUT, complete_func, user_data);
	transfer->data_consumer = data_func;

	transfer_put_req(obex, req, transfer);
	if (!g_slist_find(transfers, transfer))
		return 0;

	id = g_obex_add_request_function(obex, G_OBEX_OP_PUT, transfer_put_req,
								transfer);
	transfer->put_id = id;

	id = g_obex_add_request_function(obex, G_OBEX_OP_ABORT,
						transfer_abort_req, transfer);
	transfer->abort_id = id;

	return transfer->id;
}

guint g_obex_get_req(GObex *obex, const char *type, const char *name,
			GObexDataConsumer data_func, GObexFunc complete_func,
			gpointer user_data, GError **err)
{
	struct transfer *transfer;
	GObexPacket *req;
	GObexHeader *hdr;

	transfer = transfer_new(obex, G_OBEX_OP_GET, complete_func, user_data);
	transfer->data_consumer = data_func;

	req = g_obex_packet_new(G_OBEX_OP_GET, TRUE, NULL);

	if (type) {
		hdr = g_obex_header_new_bytes(G_OBEX_HDR_ID_TYPE,
					(char *) type, strlen(type) + 1,
					G_OBEX_DATA_COPY);
		g_obex_packet_add_header(req, hdr);
	}

	if (name) {
		hdr = g_obex_header_new_unicode(G_OBEX_HDR_ID_NAME, name);
		g_obex_packet_add_header(req, hdr);
	}

	transfer->req_id = g_obex_send_req(obex, req, -1, transfer_response,
								transfer, err);
	if (transfer->req_id == 0) {
		transfer_free(transfer);
		return 0;
	}

	return transfer->id;
}
