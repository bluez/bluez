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

#include "gobex.h"
#include "gobex-transfer.h"

static GSList *transfers = NULL;

struct transfer {
	guint id;
	guint8 opcode;

	GObex *obex;

	guint req_id;

	GObexDataProducer data_producer;
	GObexDataConsumer data_consumer;
	GObexFunc complete_func;

	gpointer user_data;
};

static void transfer_free(struct transfer *transfer)
{
	transfers = g_slist_remove(transfers, transfer);
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

	/* Intentionally override error */
	err = g_error_new(G_OBEX_ERROR, G_OBEX_ERROR_CANCELLED,
						"Operation was aborted");
	transfer_complete(transfer, err);
	g_error_free(err);
}


static gssize put_get_data(GObexHeader *header, void *buf, gsize len,
							gpointer user_data)
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
	GObexHeader *hdr;
	gboolean rspcode, final;

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

	if (rspcode == G_OBEX_RSP_SUCCESS) {
		transfer_complete(transfer, NULL);
		return;
	}

	req = g_obex_packet_new(G_OBEX_OP_PUT, TRUE, NULL);

	hdr = g_obex_header_new_on_demand(G_OBEX_HDR_ID_BODY, put_get_data,
								transfer);
	g_obex_packet_add_header(req, hdr);

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

guint g_obex_put(GObex *obex, const char *type, const char *name,
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
	hdr = g_obex_header_new_on_demand(G_OBEX_HDR_ID_BODY,
						put_get_data, transfer);
	g_obex_packet_add_header(req, hdr);

	transfer->req_id = g_obex_send_req(obex, req, -1, transfer_response,
								transfer, err);
	if (transfer->req_id == 0) {
		transfer_free(transfer);
		return 0;
	}

	return transfer->id;
}
