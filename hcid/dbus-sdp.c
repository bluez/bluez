/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <netinet/in.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "hcid.h"
#include "textfile.h"
#include "dbus-hci.h"
#include "dbus-common.h"
#include "dbus-adapter.h"
#include "dbus-error.h"
#include "dbus-sdp.h"
#include "sdp-xml.h"

#define MAX_IDENTIFIER_LEN	29	/* "XX:XX:XX:XX:XX:XX/0xYYYYYYYY\0" */
#define DEFAULT_XML_BUF_SIZE	1024

typedef struct {
	uint16_t dev_id;
	char *dst;
	void *search_data;
	get_record_cb_t *cb;
	void *data;
} get_record_data_t;

struct transaction_context {
	DBusConnection *conn;
	DBusMessage *rq;
	sdp_session_t *session;

	/* Used for internal async get remote service record implementation */
	get_record_data_t *call;
};

typedef int connect_cb_t(struct transaction_context *t);
struct pending_connect {
	DBusConnection *conn;
	DBusMessage *rq;

	char *dst;
	sdp_session_t *session;
	connect_cb_t *conn_cb;

	/* Used for internal async get remote service record implementation */
	get_record_data_t *call;
};

/* FIXME:  move to a common file */
typedef struct {
	char            *name;
	uint16_t        class;
	char            *info_name;
} sdp_service_t;

static void append_and_grow_string(void *data, const char *str)
{
	sdp_buf_t *buff = (sdp_buf_t *) data;
	int len;

	len = strlen(str);

	if (!buff->data) {
		buff->buf_size = DEFAULT_XML_BUF_SIZE;
		buff->data = realloc(buff->data, buff->buf_size);
		if (!buff->data)
			return;
	}

	/* Grow string */
	while (buff->buf_size < (buff->data_size + len + 1)) {
		/* Grow buffer by a factor of 2 */
		buff->buf_size = (buff->buf_size << 1);

		buff->data = realloc(buff->data, buff->buf_size);
		if (!buff->data)
			return;
	}

	/* Include the NULL character */
	memcpy(buff->data + buff->data_size, str, len + 1);
	buff->data_size += len;
}

/* FIXME:  move to a common file */
sdp_service_t sdp_service[] = {
	{ "vcp",	VIDEO_CONF_SVCLASS_ID,		"Video Conference"	},
	{ "map",	0,				NULL			},
	{ "pbap",	PBAP_SVCLASS_ID,		"Phone Book Access"	},
	{ "sap",	SAP_SVCLASS_ID,			"SIM Access"		},
	{ "ftp",	OBEX_FILETRANS_SVCLASS_ID,	"OBEX File Transfer"	},
	{ "bpp",	BASIC_PRINTING_SVCLASS_ID,	"Printing"		},
	{ "bip",	IMAGING_SVCLASS_ID,		"Imaging"		},
	{ "synch",	IRMC_SYNC_SVCLASS_ID,		"Synchronization"	},
	{ "dun",	DIALUP_NET_SVCLASS_ID,		"Dial-Up Networking"	},
	{ "opp",	OBEX_OBJPUSH_SVCLASS_ID,	"OBEX Object Push"	},
	{ "fax",	FAX_SVCLASS_ID,			"Fax"			},
	{ "spp",	SERIAL_PORT_SVCLASS_ID,		"Serial Port"		},
	{ "hsp",	HEADSET_SVCLASS_ID,		"Headset"		},
	{ NULL }
};

/* FIXME:  move to a common file */
uint16_t sdp_str2svclass(const char *str)
{
	sdp_service_t *s;

	for (s = sdp_service; s->name; s++) {
		if (strcasecmp(s->name, str) == 0)
			return s->class;
	}

	return 0;
}

/* list of remote and local service records */
static GSList *pending_connects  = NULL;

static struct pending_connect *pending_connect_new(DBusConnection *conn, DBusMessage *msg,
							const char *dst, connect_cb_t *cb)
{
	struct pending_connect *c;

	if (!dst)
		return NULL;

	c = malloc(sizeof(*c));
	if (!c)
		return NULL;
	memset(c, 0, sizeof(*c));

	if (dst) {
		c->dst = strdup(dst);
		if (!c->dst) {
			free(c);
			return NULL;
		}
	}

	c->conn = dbus_connection_ref(conn);
	c->rq = dbus_message_ref(msg);
	c->conn_cb = cb;

	return c;
}

static void pending_connect_free(struct pending_connect *c)
{
	if (!c)
		return;

	if (c->dst)
		free(c->dst);

	if (c->rq)
		dbus_message_unref(c->rq);

	if (c->conn)
		dbus_connection_unref(c->conn);

	free(c);
}

static struct pending_connect *find_pending_connect(const char *dst)
{
	GSList *l;

	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pending = l->data;
		if (!strcmp(dst, pending->dst))
			return pending;
	}

	return NULL;
}

static const char *get_address_from_message(DBusConnection *conn, DBusMessage *msg)
{
	struct adapter *adapter;
	const char *path;

	path = dbus_message_get_path(msg);
	if (!path)
		return NULL;

	if (dbus_connection_get_object_path_data(conn, path, (void *) &adapter) == FALSE)
		return NULL;

	return adapter->address;
}

static int sdp_store_record(const char *src, const char *dst, uint32_t handle, uint8_t *buf, size_t size)
{
	char filename[PATH_MAX + 1], key[28], *value;
	int i, err;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	snprintf(key, sizeof(key), "%s#%08X", dst, handle);

	value = malloc(size * 2 + 1);
	if (!value)
		return -ENOMEM;

	value[0] = '\0';

	for (i = 0; i < size; i++)
		sprintf(value + (i * 2), "%02X", buf[i]);

	err = textfile_put(filename, key, value);

	free(value);

	return err;
}

static void transaction_context_free(void *udata)
{
	struct transaction_context *ctxt = udata;

	if (!ctxt)
		return;

	if (ctxt->conn)
		dbus_connection_unref(ctxt->conn);

	if (ctxt->rq)
		dbus_message_unref(ctxt->rq);

	if (ctxt->session)
		sdp_close(ctxt->session);

	free(ctxt);
}

static get_record_data_t *get_record_data_new(uint16_t dev_id, const char *dst,
					void *search_data,
					get_record_cb_t *cb, void *data)
{
	get_record_data_t *n;

	n = malloc(sizeof(*n));
	if (!n)
		return NULL;

	n->dst = strdup(dst);
	if (!n->dst) {
		free(n);
		return NULL;
	}

	n->dev_id = dev_id;
	n->search_data = search_data;
	n->cb = cb;
	n->data = data;

	return n;
}

static void get_record_data_free(get_record_data_t *d)
{
	free(d->search_data);
	free(d->dst);
	free(d);
}

static inline void get_record_data_call_cb(get_record_data_t *d,
						sdp_record_t *rec, int err)
{
	d->cb(rec, d->data, err);
}

static gboolean search_process_cb(GIOChannel *chan,
				GIOCondition cond, void *udata)
{
	struct transaction_context *ctxt = udata;
	int err = 0;

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		err = EIO;
		goto failed;
	}

	if (sdp_process(ctxt->session) < 0)
		goto failed;

	return TRUE;

failed:
	if (err) {
		if (ctxt->call) {
			get_record_data_call_cb(ctxt->call, NULL, err);
			get_record_data_free(ctxt->call);
		} else
			error_failed(ctxt->conn, ctxt->rq, err);

		transaction_context_free(ctxt);
	}

	return TRUE;
}

static void remote_svc_rec_completed_cb(uint8_t type, uint16_t err, uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	sdp_record_t *rec = NULL;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	const char *src, *dst;
	int scanned;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed(ctxt->conn, ctxt->rq, EINVAL);
			goto failed;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed(ctxt->conn, ctxt->rq, sdp_err);
		goto failed;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		goto failed;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_ATTR_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed(ctxt->conn, ctxt->rq, EPROTO);
		goto failed;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID);

	src = get_address_from_message(ctxt->conn, ctxt->rq);

	reply = dbus_message_new_method_return(ctxt->rq);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_BYTE_AS_STRING, &array_iter);

	rec = sdp_extract_pdu(rsp, &scanned);
	if (rec == NULL) {
		error("SVC REC is null");
		goto done;
	}

	sdp_store_record(src, dst, rec->handle, rsp, size);

	sdp_record_free(rec);

	dbus_message_iter_append_fixed_array(&array_iter,
			DBUS_TYPE_BYTE, &rsp, size);

done:
	dbus_message_iter_close_container(&iter, &array_iter);
	send_message_and_unref(ctxt->conn, reply);

failed:
	transaction_context_free(ctxt);
}

static void remote_svc_rec_completed_xml_cb(uint8_t type, uint16_t err,
						uint8_t *rsp, size_t size,
						void *udata)
{
	struct transaction_context *ctxt = udata;
	sdp_record_t *rec = NULL;
	DBusMessage *reply;
	const char *src, *dst;
	int scanned;
	sdp_buf_t result;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed(ctxt->conn, ctxt->rq, EINVAL);
			goto failed;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed(ctxt->conn, ctxt->rq, sdp_err);
		goto failed;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		goto failed;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_ATTR_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed(ctxt->conn, ctxt->rq, EPROTO);
		goto failed;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID);

	src = get_address_from_message(ctxt->conn, ctxt->rq);

	reply = dbus_message_new_method_return(ctxt->rq);
	
	rec = sdp_extract_pdu(rsp, &scanned);
	if (rec == NULL) {
		error("SVC REC is null");
		goto done;
	}

	sdp_store_record(src, dst, rec->handle, rsp, size);

	memset(&result, 0, sizeof(sdp_buf_t));

	convert_sdp_record_to_xml(rec, &result, append_and_grow_string);

	sdp_record_free(rec);

	if (result.data) {
		dbus_message_append_args(reply,
				DBUS_TYPE_STRING, &result.data,
				DBUS_TYPE_INVALID);

		free(result.data);
	}
done:
	send_message_and_unref(ctxt->conn, reply);

failed:
	transaction_context_free(ctxt);
}

static void remote_svc_handles_completed_cb(uint8_t type, uint16_t err, uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	uint8_t *pdata;
	int csrc, tsrc;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed(ctxt->conn, ctxt->rq, EINVAL);
			goto failed;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed(ctxt->conn, ctxt->rq, sdp_err);
		goto failed;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		goto failed;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_SEARCH_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed(ctxt->conn, ctxt->rq, EPROTO);
		goto failed;
	}

	reply = dbus_message_new_method_return(ctxt->rq);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_UINT32_AS_STRING, &array_iter);

	pdata = rsp;

	tsrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (tsrc <= 0)
		goto done;

	pdata += sizeof(uint16_t);

	csrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (csrc <= 0)
		goto done;

	pdata += sizeof(uint16_t);

	do {
		uint32_t handle = ntohl(bt_get_unaligned((uint32_t*)pdata));
		pdata += sizeof(uint32_t);

		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_UINT32, &handle);
	} while (--tsrc);


done:
	dbus_message_iter_close_container(&iter, &array_iter);
	send_message_and_unref(ctxt->conn, reply);

failed:
	transaction_context_free(ctxt);
}

static gboolean sdp_client_connect_cb(GIOChannel *chan,
					GIOCondition cond, void *udata)
{
	struct pending_connect *c = udata;
	struct transaction_context *ctxt = NULL;
	int sdp_err, err = 0, sk;
	socklen_t len;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(err);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		error("getsockopt(): %s (%d)", strerror(errno), errno);
		err = errno;
		goto failed;
	}
	if (err != 0) {
		error("connect(): %s (%d)", strerror(err), err);
		goto failed;
	}

	ctxt = malloc(sizeof(*ctxt));
	if (!ctxt) {
		err = ENOMEM;
		goto failed;
	}
	memset(ctxt, 0, sizeof(*ctxt));

	ctxt->conn = dbus_connection_ref(c->conn);
	ctxt->rq = dbus_message_ref(c->rq);
	ctxt->session = c->session;
	if (c->call)
		ctxt->call = c->call;

	/* set the complete transaction callback and send the search request */
	sdp_err = c->conn_cb(ctxt);
	if (sdp_err < 0) {
		err = -sdp_err;
		error("search failed: %s (%d)", strerror(err), err);
		goto failed;
	}

	/* set the callback responsible for update the transaction data */
	g_io_add_watch(chan, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			search_process_cb, ctxt);
	goto done;

failed:
	if (c->call)
		get_record_data_call_cb(c->call, NULL, err);
	else
		error_connection_attempt_failed(c->conn, c->rq, err);

	if (c->call)
		get_record_data_free(c->call);

	if (ctxt)
		transaction_context_free(ctxt);
	else
		sdp_close(c->session);

	g_io_channel_unref(chan);

done:
	pending_connects = g_slist_remove(pending_connects, c);
	pending_connect_free(c);

	return FALSE;
}

static struct pending_connect *connect_request(DBusConnection *conn,
					DBusMessage *msg,
					uint16_t dev_id,
					const char *dst,
					connect_cb_t *cb, int *err)
{
	struct pending_connect *c;
	bdaddr_t srcba, dstba;
	GIOChannel *chan;

	c = pending_connect_new(conn, msg, dst, cb);
	if (!c) {
		if (err)
			*err = ENOMEM;
		return NULL;
	}

	hci_devba(dev_id, &srcba);
	str2ba(dst, &dstba);

	c->session = sdp_connect(&srcba, &dstba, SDP_NON_BLOCKING);
	if (!c->session) {
		if (err)
			*err = errno;
		error("sdp_connect() failed: %s (%d)", strerror(errno), errno);
		pending_connect_free(c);
		return NULL;
	}

	chan = g_io_channel_unix_new(sdp_get_socket(c->session));
	g_io_add_watch(chan, G_IO_OUT, sdp_client_connect_cb, c);
	pending_connects = g_slist_append(pending_connects, c);

	return c;
}

static int remote_svc_rec_conn_cb(struct transaction_context *ctxt)
{
	sdp_list_t *attrids = NULL;
	uint32_t range = 0x0000ffff;
	const char *dst;
	uint32_t handle;
	int err = 0;

	if (sdp_set_notify(ctxt->session, remote_svc_rec_completed_cb, ctxt) < 0) {
		err = -EINVAL;
		goto fail;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	attrids = sdp_list_append(NULL, &range);
	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_attr_async(ctxt->session, handle, SDP_ATTR_REQ_RANGE, attrids) < 0) {
		err = -sdp_get_error(ctxt->session);
		goto fail;
	}

fail:
	if (attrids)
		sdp_list_free(attrids, NULL);

	return err;
}

static int remote_svc_rec_conn_xml_cb(struct transaction_context *ctxt)
{
	sdp_list_t *attrids = NULL;
	uint32_t range = 0x0000ffff;
	const char *dst;
	uint32_t handle;
	int err = 0;

	if (sdp_set_notify(ctxt->session, remote_svc_rec_completed_xml_cb, ctxt) < 0) {
		err = -EINVAL;
		goto fail;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	attrids = sdp_list_append(NULL, &range);
	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_attr_async(ctxt->session, handle, SDP_ATTR_REQ_RANGE, attrids) < 0) {
		err = -sdp_get_error(ctxt->session);
		goto fail;
	}

fail:
	if (attrids)
		sdp_list_free(attrids, NULL);

	return err;
}

DBusHandlerResult get_remote_svc_rec(DBusConnection *conn, DBusMessage *msg, void *data, sdp_format_t format)
{
	struct adapter *adapter = data;
	const char *dst;
	uint32_t handle;
	int err = 0;
	connect_cb_t *cb;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (find_pending_connect(dst))
		return error_service_search_in_progress(conn, msg);

	cb = remote_svc_rec_conn_cb;
	if (format == SDP_FORMAT_XML)
		cb = remote_svc_rec_conn_xml_cb;

	if (!connect_request(conn, msg, adapter->dev_id,
				dst, cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return error_failed(conn, msg, err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static int remote_svc_handles_conn_cb(struct transaction_context *ctxt)
{
	sdp_list_t *search = NULL;
	const char *dst, *svc;
	uuid_t uuid;
	int err = 0;

	if (sdp_set_notify(ctxt->session, remote_svc_handles_completed_cb, ctxt) < 0) {
		err = -EINVAL;
		goto fail;
	}

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_STRING, &svc,
			DBUS_TYPE_INVALID);

	if (strlen(svc) > 0)
		str2uuid(&uuid, svc);
	else
		sdp_uuid16_create(&uuid, PUBLIC_BROWSE_GROUP);

	search = sdp_list_append(0, &uuid);

	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_search_async(ctxt->session, search, 64) < 0) {
		error("send request failed: %s (%d)", strerror(errno), errno);
		err = -sdp_get_error(ctxt->session);
		goto fail;
	}

fail:
	if (search)
		sdp_list_free(search, NULL);

	return err;
}

DBusHandlerResult get_remote_svc_handles(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	const char *dst, *svc;
	int err = 0;
	uuid_t uuid;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_STRING, &svc,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (strlen(svc) > 0) {
		/* Check if it is a service name string */
		if (str2uuid(&uuid, svc) < 0) {
			error("Invalid service class name");
			return error_invalid_arguments(conn, msg);
		}
	}

	if (find_pending_connect(dst))
		return error_service_search_in_progress(conn, msg);

	if (!connect_request(conn, msg, adapter->dev_id,
				dst, remote_svc_handles_conn_cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return error_failed(conn, msg, err);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

/*
 * Internal async get remote service record implementation
 */

static void get_rec_with_handle_comp_cb(uint8_t type, uint16_t err,
					uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	int scanned, cb_err = 0;
	sdp_record_t *rec = NULL;

	if (err == 0xffff) {
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			cb_err = EINVAL;
			goto failed;
		}
		error("search failed :%s (%d)", strerror(sdp_err), sdp_err);
		cb_err = sdp_err;
		goto failed;
	}

	if (type == SDP_ERROR_RSP || type != SDP_SVC_ATTR_RSP) {
		error("SDP error: %s(%d)", strerror(EPROTO), EPROTO);
		cb_err = EPROTO;
		goto failed;
	}

	rec = sdp_extract_pdu(rsp, &scanned);
	if (!rec) {
		error("Service record is NULL");
		cb_err = EPROTO;
		goto failed;
	}

failed:
	get_record_data_call_cb(ctxt->call, rec, cb_err);

	if (rec)
		sdp_record_free(rec);

	get_record_data_free(ctxt->call);

	transaction_context_free(ctxt);
}

static int get_rec_with_handle_conn_cb(struct transaction_context *ctxt)
{
	uint32_t range = 0x0000ffff;
	sdp_list_t *attrids = NULL;
	uint32_t handle;
	int err = 0;

	if (sdp_set_notify(ctxt->session,
				get_rec_with_handle_comp_cb, ctxt) < 0) {
		error("Invalid session data!");
		err = -EINVAL;
		goto failed;
	}

	handle = *((uint32_t *)ctxt->call->search_data);
	attrids = sdp_list_append(NULL, &range);

	if (sdp_service_attr_async(ctxt->session, handle,
					SDP_ATTR_REQ_RANGE, attrids) < 0) {
		error("send request failed: %s (%d)", strerror(errno), errno);
		err = -errno;
		goto failed;
	}

failed:
	if (attrids)
		sdp_list_free(attrids, NULL);

	return err;
}

int get_record_with_handle(DBusConnection *conn, DBusMessage *msg,
			uint16_t dev_id, const char *dst,
			uint32_t handle, get_record_cb_t *cb, void *data)
{
	struct pending_connect *c;
	get_record_data_t *d;
	uint32_t *rec_handle;
	int err;

	if (find_pending_connect(dst)) {
		error("SDP search in progress!");
		return -EINPROGRESS;
	}

	rec_handle = malloc(sizeof(uint32_t));
	if (!rec_handle)
		return -ENOMEM;

	*rec_handle = handle;

	d = get_record_data_new(dev_id, dst, rec_handle, cb, data);
	if (!d) {
		free(rec_handle);
		return -ENOMEM;
	}

	if (!(c = connect_request(conn, msg, dev_id, dst,
				get_rec_with_handle_conn_cb, &err))) {
		error("Search request failed: %s (%d)", strerror(err), err);
		get_record_data_free(d);
		return -err;
	}

	c->call = d;

	return 0;
}

static void get_rec_with_uuid_comp_cb(uint8_t type, uint16_t err,
					uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	get_record_data_t *d = ctxt->call;
	int csrc, tsrc, cb_err = 0;
	uint32_t *handle;
	uint8_t *pdata;

	if (err == 0xffff) {
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			cb_err = EINVAL;
			goto failed;
		}
		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		cb_err = sdp_err;
		goto failed;
	}

	if (type == SDP_ERROR_RSP || type != SDP_SVC_SEARCH_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		cb_err = EPROTO;
		goto failed;
	}

	pdata = rsp;
	tsrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (tsrc <= 0)
		goto failed;
	pdata += sizeof(uint16_t);

	csrc = ntohs(bt_get_unaligned((uint16_t *) pdata));
	if (csrc <= 0)
		goto failed;
	pdata += sizeof(uint16_t);

	handle = malloc(sizeof(*handle));
	if (!handle) {
		cb_err = ENOMEM;
		goto failed;
	}
	*handle = ntohl(bt_get_unaligned((uint32_t*)pdata));

	free(d->search_data);
	d->search_data = handle;

	cb_err = get_rec_with_handle_conn_cb(ctxt);
	if (cb_err)
		goto failed;

	return;

failed:
	get_record_data_call_cb(d, NULL, cb_err);

	get_record_data_free(d);

	transaction_context_free(ctxt);
}

static int get_rec_with_uuid_conn_cb(struct transaction_context *ctxt)
{
	get_record_data_t *d = ctxt->call;
	sdp_list_t *search = NULL;
	uuid_t *uuid;
	int err = 0;

	if (sdp_set_notify(ctxt->session,
			get_rec_with_uuid_comp_cb, ctxt) < 0) {
		err = -EINVAL;
		goto failed;
	}

	uuid = (uuid_t *)d->search_data;
	search = sdp_list_append(NULL, uuid);

	if (sdp_service_search_async(ctxt->session, search, 1) < 0) {
		error("send request failed: %s (%d)", strerror(errno), errno);
		err = -sdp_get_error(ctxt->session);
		goto failed;
	}

failed:
	if (search)
		sdp_list_free(search, NULL);

	return err;
}

int get_record_with_uuid(DBusConnection *conn, DBusMessage *msg,
			uint16_t dev_id, const char *dst,
			const uuid_t *uuid, get_record_cb_t *cb, void *data)
{
	struct pending_connect *c;
	get_record_data_t *d;
	int err;
	uuid_t *sdp_uuid;

	if (find_pending_connect(dst)) {
		error("SDP search in progress!");
		return -EINPROGRESS;
	}

	sdp_uuid = malloc(sizeof(uuid_t));
	if (!sdp_uuid)
		return -ENOMEM;

	memcpy(sdp_uuid, uuid, sizeof(uuid_t));

	d = get_record_data_new(dev_id, dst, sdp_uuid, cb, data);
	if (!d) {
		free(sdp_uuid);
		return -ENOMEM;
	}

	if (!(c = connect_request(conn, msg, dev_id, dst,
				get_rec_with_uuid_conn_cb, &err))) {
		error("Search request failed: %s (%d)", strerror(err), err);
		get_record_data_free(d);
		return -err;
	}

	c->call = d;

	return 0;
}
