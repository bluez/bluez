/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "hcid.h"
#include "textfile.h"
#include "adapter.h"
#include "dbus-hci.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "error.h"
#include "dbus-sdp.h"
#include "sdp-xml.h"
#include "glib-helper.h"

#define SESSION_TIMEOUT 2000
#define DEFAULT_XML_BUF_SIZE	1024

struct transaction_context {
	char		*src;
	char		*dst;
	DBusConnection	*conn;
	DBusMessage	*rq;
	sdp_session_t	*session;
	GIOChannel	*io;
	guint		io_id;
	uuid_t		uuid;
	GSList		*identifiers;
};

typedef int connect_cb_t(struct transaction_context *t);

struct pending_connect {
	DBusConnection	*conn;
	DBusMessage	*rq;
	char		*src;
	char		*dst;
	sdp_session_t	*session;
	connect_cb_t	*conn_cb;
};

struct cached_session {
	sdp_session_t *session;
	guint timeout_id;
	guint io_id;
};

static GSList *cached_sessions = NULL;

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static inline DBusMessage *in_progress(DBusMessage *msg, const char *str)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress", str);
}

static inline DBusMessage *adapter_not_ready(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotReady",
			"Adapter is not ready");
}

static inline DBusMessage *failed_strerror(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
			strerror(err));
}

static gboolean session_timeout(gpointer user_data)
{
	struct cached_session *s = user_data;

	debug("sdp session timed out. closing");

	cached_sessions = g_slist_remove(cached_sessions, s);

	g_source_remove(s->io_id);
	sdp_close(s->session);
	g_free(s);

	return FALSE;
}

gboolean idle_callback(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct cached_session *s = user_data;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP))
		debug("idle_callback: session got disconnected");

	if (cond & G_IO_IN)
		debug("got unexpected input on idle SDP socket");

	cached_sessions = g_slist_remove(cached_sessions, s);

	g_source_remove(s->timeout_id);
	sdp_close(s->session);
	g_free(s);

	return FALSE;
}

static void cache_sdp_session(sdp_session_t *sess, GIOChannel *io)
{
	struct cached_session *s;

	s = g_new0(struct cached_session, 1);

	s->session = sess;
	s->timeout_id = g_timeout_add(SESSION_TIMEOUT, session_timeout, s);
	s->io_id = g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					idle_callback, s);

	cached_sessions = g_slist_append(cached_sessions, s);

	debug("sdp session added to cache");
}

static int get_bdaddrs(int sock, bdaddr_t *sba, bdaddr_t *dba)
{
	struct sockaddr_l2 a;
	socklen_t len;

	len = sizeof(a);
	if (getsockname(sock, (struct sockaddr *) &a, &len) < 0) {
		error("getsockname: %s (%d)", strerror(errno), errno);
		return -1;
	}

	bacpy(sba, &a.l2_bdaddr);

	len = sizeof(a);
	if (getpeername(sock, (struct sockaddr *) &a, &len) < 0) {
		error("getpeername: %s (%d)", strerror(errno), errno);
		return -1;
	}

	bacpy(dba, &a.l2_bdaddr);

	return 0;
}

static struct cached_session *get_cached_session(bdaddr_t *src, bdaddr_t *dst)
{
	GSList *l;

	for (l = cached_sessions; l != NULL; l = l->next) {
		struct cached_session *s = l->data;
		int sock = sdp_get_socket(s->session);
		bdaddr_t sba, dba;

		if (get_bdaddrs(sock, &sba, &dba) < 0)
			continue;

		if (bacmp(&sba, src) || bacmp(&dba, dst))
			continue;

		debug("found matching session, removing from list");

		cached_sessions = g_slist_remove(cached_sessions, s);

		return s;
	}

	return NULL;
}

static sdp_session_t *get_sdp_session(bdaddr_t *src, bdaddr_t *dst)
{
	struct cached_session *s;
	sdp_session_t *session;

	s = get_cached_session(src, dst);
	if (!s) {
		debug("no matching session found. creating a new one");
		return sdp_connect(src, dst, SDP_NON_BLOCKING);
	}

	session = s->session;

	g_source_remove(s->timeout_id);
	g_source_remove(s->io_id);
	g_free(s);

	return session;
}

void append_and_grow_string(void *data, const char *str)
{
	sdp_buf_t *buff = data;
	int len;

	len = strlen(str);

	if (!buff->data) {
		buff->data = malloc(DEFAULT_XML_BUF_SIZE);
		if (!buff->data)
			return;
		buff->buf_size = DEFAULT_XML_BUF_SIZE;
	}

	/* Grow string */
	while (buff->buf_size < (buff->data_size + len + 1)) {
		void *tmp;
		uint32_t new_size;

		/* Grow buffer by a factor of 2 */
		new_size = (buff->buf_size << 1);

		tmp = realloc(buff->data, new_size);
		if (!tmp)
			return;

		buff->data = tmp;
		buff->buf_size = new_size;
	}

	/* Include the NULL character */
	memcpy(buff->data + buff->data_size, str, len + 1);
	buff->data_size += len;
}

/* list of remote and local service records */
static GSList *pending_connects  = NULL;

static struct pending_connect *pending_connect_new(DBusConnection *conn,
					DBusMessage *msg, const char *src,
					const char *dst, connect_cb_t *cb)
{
	struct pending_connect *c;

	if (!dst)
		return NULL;

	c = g_new0(struct pending_connect, 1);
	c->src = g_strdup(src);
	c->dst = g_strdup(dst);
	c->conn = dbus_connection_ref(conn);
	c->rq = dbus_message_ref(msg);
	c->conn_cb = cb;

	return c;
}

static void pending_connect_free(struct pending_connect *c)
{
	if (!c)
		return;

	g_free(c->src);
	g_free(c->dst);

	if (c->rq)
		dbus_message_unref(c->rq);

	if (c->conn)
		dbus_connection_unref(c->conn);

	g_free(c);
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

static int sdp_store_record(const char *src, const char *dst, uint32_t handle, uint8_t *buf, size_t size)
{
	char filename[PATH_MAX + 1], key[28], *value;
	int i, err;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	snprintf(key, sizeof(key), "%17s#%08X", dst, handle);

	value = g_malloc0(size * 2 + 1);

	for (i = 0; i < size; i++)
		sprintf(value + (i * 2), "%02X", buf[i]);

	err = textfile_put(filename, key, value);

	g_free(value);

	return err;
}

static void transaction_context_free(void *udata, gboolean cache)
{
	struct transaction_context *ctxt = udata;

	if (!ctxt)
		return;

	g_free(ctxt->src);
	g_free(ctxt->dst);

	if (ctxt->conn)
		dbus_connection_unref(ctxt->conn);

	if (ctxt->rq)
		dbus_message_unref(ctxt->rq);

	if (ctxt->session && !ctxt->io)
		sdp_close(ctxt->session);

	if (ctxt->session && ctxt->io) {
		g_source_remove(ctxt->io_id);

		if (cache)
			cache_sdp_session(ctxt->session, ctxt->io);
		else
			sdp_close(ctxt->session);

		g_io_channel_unref(ctxt->io);
	}

	if (ctxt->identifiers) {
		g_slist_foreach(ctxt->identifiers, (GFunc) g_free, NULL);
		g_slist_free(ctxt->identifiers);
	}

	g_free(ctxt);
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
		error_failed_errno(ctxt->conn, ctxt->rq, err);
		transaction_context_free(ctxt, FALSE);
	}

	return TRUE;
}

static void remote_svc_rec_completed_cb(uint8_t type, uint16_t err,
			uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	sdp_record_t *rec;
	DBusMessage *reply;
	DBusMessageIter iter, array_iter;
	int scanned;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed_errno(ctxt->conn, ctxt->rq, EINVAL);
			goto failed;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed_errno(ctxt->conn, ctxt->rq, sdp_err);
		goto failed;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		goto failed;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_ATTR_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed_errno(ctxt->conn, ctxt->rq, EPROTO);
		goto failed;
	}

	reply = dbus_message_new_method_return(ctxt->rq);
	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_BYTE_AS_STRING, &array_iter);

	rec = sdp_extract_pdu_safe(rsp, size, &scanned);
	if (rec == NULL || size != scanned) {
		error("Invalid service record!");
		goto done;
	}

	sdp_store_record(ctxt->src, ctxt->dst, rec->handle, rsp, size);

	sdp_record_free(rec);

	dbus_message_iter_append_fixed_array(&array_iter,
			DBUS_TYPE_BYTE, &rsp, size);

done:
	dbus_message_iter_close_container(&iter, &array_iter);
	dbus_connection_send(ctxt->conn, reply, NULL);
	dbus_message_unref(reply);

failed:
	transaction_context_free(ctxt, TRUE);
}

static void remote_svc_rec_completed_xml_cb(uint8_t type, uint16_t err,
						uint8_t *rsp, size_t size,
						void *udata)
{
	struct transaction_context *ctxt = udata;
	sdp_record_t *rec;
	DBusMessage *reply;
	int scanned;
	sdp_buf_t result;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed_errno(ctxt->conn, ctxt->rq, EINVAL);
			goto failed;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed_errno(ctxt->conn, ctxt->rq, sdp_err);
		goto failed;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		goto failed;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_ATTR_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed_errno(ctxt->conn, ctxt->rq, EPROTO);
		goto failed;
	}

	reply = dbus_message_new_method_return(ctxt->rq);

	rec = sdp_extract_pdu_safe(rsp, size, &scanned);
	if (rec == NULL || size != scanned) {
		error("Invalid service record!");
		goto done;
	}

	sdp_store_record(ctxt->src, ctxt->dst, rec->handle, rsp, size);

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
	dbus_connection_send(ctxt->conn, reply, NULL);
	dbus_message_unref(reply);

failed:
	transaction_context_free(ctxt, TRUE);
}

static void remote_svc_handles_completed_cb(uint8_t type, uint16_t err,
			uint8_t *rsp, size_t size, void *udata)
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
			error_failed_errno(ctxt->conn, ctxt->rq, EINVAL);
			goto failed;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed_errno(ctxt->conn, ctxt->rq, sdp_err);
		goto failed;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		goto failed;
	}

	/* check response PDU ID */
	if (type != SDP_SVC_SEARCH_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed_errno(ctxt->conn, ctxt->rq, EPROTO);
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
	dbus_connection_send(ctxt->conn, reply, NULL);
	dbus_message_unref(reply);

failed:
	transaction_context_free(ctxt, TRUE);
}

static const char *extract_service_class(sdp_data_t *d)
{
	sdp_data_t *seq;
	uuid_t *uuid;
	static char uuid_str[37];

	/* Expected sequence of UUID16 */
	if (d->attrId != SDP_ATTR_SVCLASS_ID_LIST)
		return NULL;

	if (d->dtd != SDP_SEQ8 && d->dtd != SDP_SEQ16 && d->dtd != SDP_SEQ32)
		return NULL;

	if (!d->val.dataseq)
		return NULL;

	seq = d->val.dataseq;
	if (!SDP_IS_UUID(seq->dtd))
		return NULL;

	uuid = &seq->val.uuid;
	if (uuid->type != SDP_UUID16)
		return NULL;

	sprintf(uuid_str, "0000%04x-0000-1000-8000-00805f9b34fb",
							uuid->value.uuid16);

	return uuid_str;
}

static int service_search_attr(struct transaction_context *ctxt, uint16_t uuid)
{
	sdp_list_t *attrids, *search;
	uint32_t range = 0x0000ffff;
	int ret = 0;

	sdp_uuid16_create(&ctxt->uuid, uuid);

	search = sdp_list_append(0, &ctxt->uuid);
	attrids = sdp_list_append(NULL, &range);

	/*
	 * Create/send the search request and set the
	 * callback to indicate the request completion
	 */
	if (sdp_service_search_attr_async(ctxt->session, search,
				SDP_ATTR_REQ_RANGE, attrids) < 0)
		ret = -sdp_get_error(ctxt->session);

	sdp_list_free(search, NULL);
	sdp_list_free(attrids, NULL);

	return ret;
}

static void remote_svc_identifiers_completed_cb(uint8_t type, uint16_t err,
			uint8_t *rsp, size_t size, void *udata)
{
	struct transaction_context *ctxt = udata;
	const char *puuid;
	const char *devid_uuid = "00001200-0000-1000-8000-00805f9b34fb";
	char **identifiers;
	DBusMessage *reply;
	GSList *l = NULL;
	int scanned, extracted = 0, len = 0, recsize = 0, bytesleft = size;
	uint8_t dtd = 0;

	if (!ctxt)
		return;

	if (err == 0xffff) {
		/* Check for protocol error or I/O error */
		int sdp_err = sdp_get_error(ctxt->session);
		if (sdp_err < 0) {
			error("search failed: Invalid session!");
			error_failed_errno(ctxt->conn, ctxt->rq, EINVAL);
			goto failed;
		}

		error("search failed: %s (%d)", strerror(sdp_err), sdp_err);
		error_failed_errno(ctxt->conn, ctxt->rq, sdp_err);
		goto failed;
	}

	if (type == SDP_ERROR_RSP) {
		error_sdp_failed(ctxt->conn, ctxt->rq, err);
		goto failed;
	}

	/* Check response PDU ID */
	if (type != SDP_SVC_SEARCH_ATTR_RSP) {
		error("SDP error: %s (%d)", strerror(EPROTO), EPROTO);
		error_failed_errno(ctxt->conn, ctxt->rq, EPROTO);
		goto failed;
	}

	scanned = sdp_extract_seqtype_safe(rsp, bytesleft, &dtd, &len);
	rsp += scanned;
	bytesleft -= scanned;
	for (; extracted < len; rsp += recsize, extracted += recsize, bytesleft -= recsize) {
		sdp_record_t *rec;
		sdp_data_t *d;

		recsize = 0;
		rec = sdp_extract_pdu_safe(rsp, bytesleft, &recsize);
		if (!rec)
			break;

		sdp_store_record(ctxt->src, ctxt->dst, rec->handle, rsp, recsize);

		d = sdp_data_get(rec, SDP_ATTR_SVCLASS_ID_LIST);
		if (!d) {
			sdp_record_free(rec);
			continue;
		}

		puuid = extract_service_class(d);
		sdp_record_free(rec);
		if (!puuid)
			continue;

		/* Ignore repeated identifiers */
		l = g_slist_find_custom(ctxt->identifiers,
				puuid, (GCompareFunc) strcmp);
		if (l)
			continue;

		ctxt->identifiers = g_slist_append(ctxt->identifiers,
							g_strdup(puuid));
	}

	/* If public browse response is empty: search for L2CAP */
	if (!ctxt->identifiers && ctxt->uuid.value.uuid16 == PUBLIC_BROWSE_GROUP)
		if (service_search_attr(ctxt, L2CAP_UUID) == 0)
			return; /* Wait the response */

	/* Request DeviceID if it was not returned previously */
	l = g_slist_find_custom(ctxt->identifiers,
			devid_uuid, (GCompareFunc) strcmp);
	if (!l && ctxt->uuid.value.uuid16 != PNP_INFO_SVCLASS_ID)
		if (service_search_attr(ctxt, PNP_INFO_SVCLASS_ID) == 0)
			return; /* Wait the response */

	reply = dbus_message_new_method_return(ctxt->rq);

	identifiers = g_new(char *, g_slist_length(ctxt->identifiers));

	for (l = ctxt->identifiers, len = 0; l; l = l->next, len++)
		identifiers[len] = l->data;

	dbus_message_append_args(reply,
			DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
			&identifiers, len,
			DBUS_TYPE_INVALID);

	dbus_connection_send(ctxt->conn, reply, NULL);
	dbus_message_unref(reply);

	if (len)
		g_dbus_emit_signal(ctxt->conn,
				dbus_message_get_path(ctxt->rq),
				ADAPTER_INTERFACE,
				"RemoteIdentifiersUpdated",
				DBUS_TYPE_STRING, &ctxt->dst,
				DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
				&identifiers, len,
				DBUS_TYPE_INVALID);

	if (identifiers)
		g_free(identifiers);

failed:
	transaction_context_free(ctxt, TRUE);
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

	ctxt = g_new0(struct transaction_context, 1);
	ctxt->src = g_strdup(c->src);
	ctxt->dst = g_strdup(c->dst);
	ctxt->conn = dbus_connection_ref(c->conn);
	ctxt->rq = dbus_message_ref(c->rq);
	ctxt->session = c->session;

	/* set the complete transaction callback and send the search request */
	sdp_err = c->conn_cb(ctxt);
	if (sdp_err < 0) {
		err = -sdp_err;
		error("search failed: %s (%d)", strerror(err), err);
		goto failed;
	}

	/* set the callback responsible for update the transaction data */
	ctxt->io_id = g_io_add_watch(chan,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				search_process_cb, ctxt);
	ctxt->io = g_io_channel_ref(chan);

	goto done;

failed:
	error_connection_attempt_failed(c->conn, c->rq, err);

	if (ctxt)
		transaction_context_free(ctxt, FALSE);
	else
		sdp_close(c->session);

done:
	pending_connects = g_slist_remove(pending_connects, c);
	pending_connect_free(c);

	return FALSE;
}

static struct pending_connect *connect_request(DBusConnection *conn,
					DBusMessage *msg,
					const char *src,
					const char *dst,
					connect_cb_t *cb, int *err)
{
	struct pending_connect *c;
	bdaddr_t srcba, dstba;
	GIOChannel *chan;

	c = pending_connect_new(conn, msg, src, dst, cb);
	if (!c) {
		if (err)
			*err = ENOMEM;
		return NULL;
	}

	str2ba(src, &srcba);
	str2ba(dst, &dstba);
	c->session = get_sdp_session(&srcba, &dstba);
	if (!c->session) {
		if (err)
			*err = errno;
		error("sdp_connect() failed: %s (%d)", strerror(errno), errno);
		pending_connect_free(c);
		return NULL;
	}

	chan = g_io_channel_unix_new(sdp_get_socket(c->session));
	g_io_add_watch(chan, G_IO_OUT, sdp_client_connect_cb, c);
	g_io_channel_unref(chan);
	pending_connects = g_slist_append(pending_connects, c);

	return c;
}

static int remote_svc_rec_conn_cb(struct transaction_context *ctxt)
{
	sdp_list_t *attrids;
	uint32_t range = 0x0000ffff;
	const char *dst;
	uint32_t handle;

	if (sdp_set_notify(ctxt->session, remote_svc_rec_completed_cb, ctxt) < 0)
		return -EINVAL;

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	attrids = sdp_list_append(NULL, &range);
	/*
	 * Create/send the search request and set the
	 * callback to indicate the request completion
	 */
	if (sdp_service_attr_async(ctxt->session, handle,
				SDP_ATTR_REQ_RANGE, attrids) < 0) {
		sdp_list_free(attrids, NULL);
		return -sdp_get_error(ctxt->session);
	}

	sdp_list_free(attrids, NULL);

	return 0;
}

static int remote_svc_rec_conn_xml_cb(struct transaction_context *ctxt)
{
	sdp_list_t *attrids;
	uint32_t range = 0x0000ffff;
	const char *dst;
	uint32_t handle;

	if (sdp_set_notify(ctxt->session, remote_svc_rec_completed_xml_cb, ctxt) < 0)
		return -EINVAL;

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	attrids = sdp_list_append(NULL, &range);
	/* 
	 * Create/send the search request and set the
	 * callback to indicate the request completion
	 */
	if (sdp_service_attr_async(ctxt->session, handle,
				SDP_ATTR_REQ_RANGE, attrids) < 0) {
		sdp_list_free(attrids, NULL);
		return -sdp_get_error(ctxt->session);
	}

	sdp_list_free(attrids, NULL);

	return 0;
}

DBusMessage *get_remote_svc_rec(DBusConnection *conn, DBusMessage *msg,
				void *data, sdp_format_t format)
{
	struct adapter *adapter = data;
	const char *dst;
	uint32_t handle;
	int err;
	connect_cb_t *cb;

	if (!adapter->up)
		return adapter_not_ready(msg);

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID))
		return invalid_args(msg);

	if (find_pending_connect(dst))
		return in_progress(msg, "Service search in progress");

	cb = remote_svc_rec_conn_cb;
	if (format == SDP_FORMAT_XML)
		cb = remote_svc_rec_conn_xml_cb;

	if (!connect_request(conn, msg, adapter->address,
				dst, cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return failed_strerror(msg, err);
	}

	return NULL;
}

static int remote_svc_handles_conn_cb(struct transaction_context *ctxt)
{
	sdp_list_t *search = NULL;
	const char *dst, *svc;

	if (sdp_set_notify(ctxt->session, remote_svc_handles_completed_cb, ctxt) < 0)
		return -EINVAL;

	dbus_message_get_args(ctxt->rq, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_STRING, &svc,
			DBUS_TYPE_INVALID);

	if (strlen(svc) > 0)
		bt_string2uuid(&ctxt->uuid, svc);
	else
		sdp_uuid16_create(&ctxt->uuid, PUBLIC_BROWSE_GROUP);

	search = sdp_list_append(0, &ctxt->uuid);

	/* Create/send the search request and set the callback to indicate the request completion */
	if (sdp_service_search_async(ctxt->session, search, 64) < 0) {
		error("send request failed: %s (%d)", strerror(errno), errno);
		sdp_list_free(search, NULL);
		return -sdp_get_error(ctxt->session);
	}

	sdp_list_free(search, NULL);

	return 0;
}

static int remote_svc_identifiers_conn_cb(struct transaction_context *ctxt)
{
	if (sdp_set_notify(ctxt->session,
			remote_svc_identifiers_completed_cb, ctxt) < 0)
		return -EINVAL;

	return service_search_attr(ctxt, PUBLIC_BROWSE_GROUP);
}

DBusMessage *get_remote_svc_handles(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	const char *dst, *svc;
	int err;
	uuid_t uuid;

	if (!adapter->up)
		return adapter_not_ready(msg);

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_STRING, &svc,
			DBUS_TYPE_INVALID))
		return invalid_args(msg);

	if (strlen(svc) > 0) {
		/* Check if it is a service name string */
		if (bt_string2uuid(&uuid, svc) < 0) {
			error("Invalid service class name");
			return invalid_args(msg);
		}
	}

	if (find_pending_connect(dst))
		return in_progress(msg, "Service search in progress");

	if (!connect_request(conn, msg, adapter->address,
				dst, remote_svc_handles_conn_cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return failed_strerror(msg, err);
	}

	return NULL;
}

DBusMessage *get_remote_svc_identifiers(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	const char *dst;
	int err;

	if (!adapter->up)
		return adapter_not_ready(msg);

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &dst,
			DBUS_TYPE_INVALID))
		return invalid_args(msg);

	if (find_pending_connect(dst))
		return in_progress(msg, "Service search in progress");

	if (!connect_request(conn, msg, adapter->address,
				dst, remote_svc_identifiers_conn_cb, &err)) {
		error("Search request failed: %s (%d)", strerror(err), err);
		return failed_strerror(msg, err);
	}

	return NULL;
}

DBusMessage *finish_remote_svc_transact(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct cached_session *s;
	const char *address;
	struct adapter *adapter = data;
	bdaddr_t sba, dba;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return invalid_args(msg);

	str2ba(adapter->address, &sba);
	str2ba(address, &dba);

	while ((s = get_cached_session(&sba, &dba))) {
		sdp_close(s->session);
		g_source_remove(s->timeout_id);
		g_source_remove(s->io_id);
		g_free(s);
	}

	return dbus_message_new_method_return(msg);
}
