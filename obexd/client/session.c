/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>
#include <gdbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "logging.h"
#include "pbap.h"
#include "sync.h"
#include "session.h"

#define AGENT_INTERFACE  "org.openobex.Agent"

#define TRANSFER_INTERFACE  "org.openobex.Transfer"
#define TRANSFER_BASEPATH   "/org/openobex"

#define SESSION_INTERFACE  "org.openobex.Session"
#define SESSION_BASEPATH   "/org/openobex"

#define FTP_INTERFACE  "org.openobex.FileTransfer"

#define DEFAULT_BUFFER_SIZE 4096

typedef int (*transfer_callback_t) (struct transfer_data *session, void *data);

static void finalize_transfer(struct transfer_data *transfer);

static guint64 counter = 0;

static unsigned char pcsuite_uuid[] = { 0x00, 0x00, 0x50, 0x05, 0x00, 0x00,
					0x10, 0x00, 0x80, 0x00, 0x00, 0x02,
					0xEE, 0x00, 0x00, 0x01 };

struct callback_data {
	struct session_data *session;
	sdp_session_t *sdp;
	session_callback_t func;
	void *data;
};

struct transfer_request {
	DBusPendingCall *call;
	transfer_callback_t callback;
	void *data;
};

struct transfer_params {
	const guint8 *data;
	gint size;
	session_callback_t cb;
	void *user_data;
};

static struct session_data *session_ref(struct session_data *session)
{
	g_atomic_int_inc(&session->refcount);

	debug("session_ref(%p): ref=%d", session, session->refcount);

	return session;
}

static void session_free(struct session_data *session)
{
	if (session->agent_watch)
		g_dbus_remove_watch(session->conn, session->agent_watch);

	if (session->owner_watch)
		g_dbus_remove_watch(session->conn, session->owner_watch);

	if (session->agent_name != NULL) {
		DBusMessage *message;

		message = dbus_message_new_method_call(session->agent_name,
			session->agent_path, AGENT_INTERFACE, "Release");

		dbus_message_set_no_reply(message, TRUE);

		g_dbus_send_message(session->conn, message);
	}

	if (session->obex != NULL)
		gw_obex_close(session->obex);

	if (session->sock > 2)
		close(session->sock);

	if (session->conn) {
		switch (session->uuid.value.uuid16) {
		case OBEX_FILETRANS_SVCLASS_ID:
			g_dbus_unregister_interface(session->conn,
					session->path,	FTP_INTERFACE);
			break;
		case PBAP_PSE_SVCLASS_ID:
			pbap_unregister_interface(session->conn,
					session->path, session);
			break;
		case IRMC_SYNC_SVCLASS_ID:
			sync_unregister_interface(session->conn,
					session->path, session);
		}

		g_dbus_unregister_interface(session->conn,
				session->path, SESSION_INTERFACE);

		dbus_connection_unref(session->conn);
	}

	g_free(session->path);
	g_free(session->agent_name);
	g_free(session->agent_path);
	g_free(session->owner);
	g_free(session);
}

static void session_unref(struct session_data *session)
{
	gboolean ret;

	ret = g_atomic_int_dec_and_test(&session->refcount);

	debug("session_unref(%p): ref=%d", session, session->refcount);

	if (ret == FALSE)
		return;

	session_free(session);
}

static gboolean rfcomm_callback(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct callback_data *callback = user_data;
	struct session_data *session = callback->session;
	GwObex *obex;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR))
		goto done;

	fd = g_io_channel_unix_get_fd(io);

	obex = gw_obex_setup_fd(fd, session->target,
			session->target_len, NULL, NULL);

	callback->session->sock = fd;
	callback->session->obex = obex;

done:
	callback->func(callback->session, callback->data);

	session_unref(callback->session);

	g_free(callback);

	return FALSE;
}

static int rfcomm_connect(const bdaddr_t *src,
				const bdaddr_t *dst, uint8_t channel,
					GIOFunc function, gpointer user_data)
{
	GIOChannel *io;
	struct sockaddr_rc addr;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -EIO;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -EIO;
	}

	io = g_io_channel_unix_new(sk);
	if (io == NULL) {
		close(sk);
		return -ENOMEM;
	}

	if (g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK,
						NULL) != G_IO_STATUS_NORMAL) {
		g_io_channel_unref(io);
		close(sk);
		return -EPERM;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, dst);
	addr.rc_channel = channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (errno != EAGAIN && errno != EINPROGRESS) {
			g_io_channel_unref(io);
			close(sk);
			return -EIO;
		}
	}

	g_io_add_watch(io, G_IO_OUT | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
							function, user_data);

	g_io_channel_unref(io);

	return 0;
}

static void search_callback(uint8_t type, uint16_t status,
			uint8_t *rsp, size_t size, void *user_data)
{
	struct callback_data *callback = user_data;
	unsigned int scanned, bytesleft = size;
	int seqlen = 0;
	uint8_t dataType, channel = 0;

	if (status || type != SDP_SVC_SEARCH_ATTR_RSP)
		goto failed;

	scanned = sdp_extract_seqtype(rsp, bytesleft, &dataType, &seqlen);
	if (!scanned || !seqlen)
		goto failed;

	rsp += scanned;
	bytesleft -= scanned;
	do {
		sdp_record_t *rec;
		sdp_list_t *protos;
		int recsize, ch = -1;

		recsize = 0;
		rec = sdp_extract_pdu(rsp, bytesleft, &recsize);
		if (!rec)
			break;

		if (!recsize) {
			sdp_record_free(rec);
			break;
		}

		if (!sdp_get_access_protos(rec, &protos)) {
			ch = sdp_get_proto_port(protos, RFCOMM_UUID);
			sdp_list_foreach(protos,
					(sdp_list_func_t) sdp_list_free, NULL);
			sdp_list_free(protos, NULL);
			protos = NULL;
		}

		sdp_record_free(rec);

		if (ch > 0) {
			channel = ch;
			break;
		}

		scanned += recsize;
		rsp += recsize;
		bytesleft -= recsize;
	} while (scanned < size && bytesleft > 0);

	if (channel == 0)
		goto failed;

	callback->session->channel = channel;

	if (rfcomm_connect(&callback->session->src, &callback->session->dst,
					channel, rfcomm_callback, callback) == 0) {
		sdp_close(callback->sdp);
		return;
	}

failed:
	sdp_close(callback->sdp);

	callback->func(callback->session, callback->data);
	session_unref(callback->session);
	g_free(callback);
}

static gboolean process_callback(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct callback_data *callback = user_data;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	if (sdp_process(callback->sdp) < 0)
		return FALSE;

	return TRUE;
}

static gboolean service_callback(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct callback_data *callback = user_data;
	sdp_list_t *search, *attrid;
	uint32_t range = 0x0000ffff;

	if (cond & (G_IO_NVAL | G_IO_ERR))
		goto failed;

	if (sdp_set_notify(callback->sdp, search_callback, callback) < 0)
		goto failed;

	search = sdp_list_append(NULL, &callback->session->uuid);
	attrid = sdp_list_append(NULL, &range);

	if (sdp_service_search_attr_async(callback->sdp,
				search, SDP_ATTR_REQ_RANGE, attrid) < 0) {
		sdp_list_free(attrid, NULL);
		sdp_list_free(search, NULL);
		goto failed;
	}

	sdp_list_free(attrid, NULL);
	sdp_list_free(search, NULL);

	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
						process_callback, callback);

	return FALSE;

failed:
	sdp_close(callback->sdp);

	callback->func(callback->session, callback->data);
	session_unref(callback->session);
	g_free(callback);
	return FALSE;
}

static sdp_session_t *service_connect(const bdaddr_t *src, const bdaddr_t *dst,
					GIOFunc function, gpointer user_data)
{
	sdp_session_t *sdp;
	GIOChannel *io;

	sdp = sdp_connect(src, dst, SDP_NON_BLOCKING);
	if (sdp == NULL)
		return NULL;

	io = g_io_channel_unix_new(sdp_get_socket(sdp));
	if (io == NULL) {
		sdp_close(sdp);
		return NULL;
	}

	g_io_add_watch(io, G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							function, user_data);

	g_io_channel_unref(io);

	return sdp;
}

int session_create(const char *source,
			const char *destination, const char *target,
			uint8_t channel, session_callback_t function,
			void *user_data)
{
	struct session_data *session;
	struct callback_data *callback;
	int err;

	if (destination == NULL)
		return -EINVAL;

	session = g_try_malloc0(sizeof(*session));
	if (session == NULL)
		return -ENOMEM;

	session->refcount = 1;
	session->sock = -1;
	session->channel = channel;

	session->conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (session->conn == NULL) {
		session_free(session);
		return -ENOMEM;
	}

	if (source == NULL)
		bacpy(&session->src, BDADDR_ANY);
	else
		str2ba(source, &session->src);

	str2ba(destination, &session->dst);

	if (!g_ascii_strncasecmp(target, "OPP", 3)) {
		sdp_uuid16_create(&session->uuid, OBEX_OBJPUSH_SVCLASS_ID);
	} else if (!g_ascii_strncasecmp(target, "FTP", 3)) {
		sdp_uuid16_create(&session->uuid, OBEX_FILETRANS_SVCLASS_ID);
		session->target = OBEX_FTP_UUID;
		session->target_len = OBEX_FTP_UUID_LEN;
	} else if (!g_ascii_strncasecmp(target, "PBAP", 4)) {
		sdp_uuid16_create(&session->uuid, PBAP_PSE_SVCLASS_ID);
		session->target = OBEX_PBAP_UUID;
		session->target_len = OBEX_PBAP_UUID_LEN;
	} else if (!g_ascii_strncasecmp(target, "SYNC", 4)) {
		sdp_uuid16_create(&session->uuid, IRMC_SYNC_SVCLASS_ID);
		session->target = OBEX_SYNC_UUID;
		session->target_len = OBEX_SYNC_UUID_LEN;
	} else if (!g_ascii_strncasecmp(target, "PCSUITE", 7)) {
		sdp_uuid128_create(&session->uuid, pcsuite_uuid);
	} else {
		return -EINVAL;
	}

	callback = g_try_malloc0(sizeof(*callback));
	if (callback == NULL) {
		session_free(session);
		return -ENOMEM;
	}

	callback->session = session_ref(session);
	callback->func = function;
	callback->data = user_data;

	if (session->channel > 0) {
		err = rfcomm_connect(&session->src, &session->dst,
				session->channel, rfcomm_callback, callback);
	} else {
		callback->sdp = service_connect(&session->src, &session->dst,
						service_callback, callback);
		err = (callback->sdp == NULL) ? -ENOMEM : 0;
	}

	if (err < 0) {
		session_free(session);
		g_free(callback);
		return -EINVAL;
	}

	return 0;
}

static void agent_notify_progress(DBusConnection *conn, const char *agent_name,
			const char *agent_path, const char *transfer_path,
			uint64_t transferred)
{
	DBusMessage *message;

	if (agent_name == NULL || agent_path == NULL || transfer_path == NULL)
		return;

	message = dbus_message_new_method_call(agent_name,
			agent_path, AGENT_INTERFACE, "Progress");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer_path,
			DBUS_TYPE_UINT64, &transferred,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(conn, message);
}

static void agent_notify_complete(DBusConnection *conn, const char *agent_name,
			const char *agent_path, const char *transfer_path)
{
	DBusMessage *message;

	if (agent_name == NULL || agent_path == NULL || transfer_path == NULL)
		return;

	message = dbus_message_new_method_call(agent_name,
			agent_path, AGENT_INTERFACE, "Complete");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer_path,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(conn, message);

}

static void agent_notify_error(DBusConnection *conn, const char *agent_name,
			const char *agent_path, const char *transfer_path,
			const char *error_msg)
{
	DBusMessage *message;

	if (agent_name == NULL || agent_path == NULL || transfer_path == NULL)
		return;

	message = dbus_message_new_method_call(agent_name,
			agent_path, AGENT_INTERFACE, "Error");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer_path,
			DBUS_TYPE_STRING, &error_msg,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(conn, message);
}

static void append_entry(DBusMessageIter *dict,
				const char *key, int type, void *val)
{
	DBusMessageIter entry, value;
	const char *signature;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
								NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_STRING:
		signature = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		signature = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_UINT64:
		signature = DBUS_TYPE_UINT64_AS_STRING;
		break;
	default:
		signature = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}

static DBusMessage *transfer_get_properties(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct transfer_data *transfer = user_data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	append_entry(&dict, "Name", DBUS_TYPE_STRING, &transfer->name);
	append_entry(&dict, "Size", DBUS_TYPE_UINT64, &transfer->size);
	append_entry(&dict, "Filename", DBUS_TYPE_STRING, &transfer->filename);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static void free_request(struct transfer_request *request)
{
	if (request->call)
		dbus_pending_call_unref(request->call);

	g_free(request);
}

static void free_transfer(struct transfer_data *transfer)
{
	struct session_data *session = transfer->session;

	if (transfer->xfer) {
		gw_obex_xfer_close(transfer->xfer, NULL);
		gw_obex_xfer_free(transfer->xfer);
	}

	if (transfer->fd > 0)
		close(transfer->fd);

	if (transfer->request)
		free_request(transfer->request);

	session->pending = g_slist_remove(session->pending, transfer);

	session_unref(session);

	g_free(transfer->params);
	g_free(transfer->filename);
	g_free(transfer->name);
	g_free(transfer->type);
	g_free(transfer->path);
	g_free(transfer->buffer);
	g_free(transfer);
}

static void unregister_transfer(struct transfer_data *transfer)
{
	struct session_data *session = transfer->session;

	/* Before unregistering cancel any pending call */
	if (transfer->request)
		dbus_pending_call_cancel(transfer->request->call);

	if (transfer->path) {
		g_dbus_unregister_interface(session->conn,
			transfer->path, TRANSFER_INTERFACE);

		debug("Transfer unregistered %s", transfer->path);
	}

	free_transfer(transfer);
}

static void agent_request_reply(DBusPendingCall *call, gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct transfer_request *request = transfer->request;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const char *name;
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	dbus_message_get_args(reply, NULL,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID);

	if (strlen(name)) {
		g_free(transfer->name);
		transfer->name = g_strdup(name);
	}

	if (request->callback(transfer, request->data))
		goto fail;

	free_request(request);
	transfer->request = NULL;

	return;

fail:
	finalize_transfer(transfer);
}

static void agent_request(struct transfer_data *transfer,
				transfer_callback_t cb, void *user_data)
{
	struct session_data *session = transfer->session;
	DBusMessage *message;
	DBusPendingCall *call;
	struct transfer_request *request;

	if (session->agent_name == NULL || session->agent_path == NULL ||
			transfer == NULL || transfer->path == NULL) {
		if (cb(transfer, user_data))
			goto fail;

		return;
	}

	message = dbus_message_new_method_call(session->agent_name,
			session->agent_path, AGENT_INTERFACE, "Request");

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer->path,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(session->conn, message, &call, -1)) {
		dbus_message_unref(message);
		return;
	}

	dbus_message_unref(message);

	request = g_new0(struct transfer_request, 1);
	request->call = call;
	request->callback = cb;
	request->data = user_data;
	transfer->request = request;

	dbus_pending_call_set_notify(call, agent_request_reply, transfer, NULL);

	return;

fail:
	finalize_transfer(transfer);
}

static void put_xfer_progress(GwObexXfer *xfer, gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct session_data *session = transfer->session;
	gint written;

	if (transfer->buffer_len == 0) {
		transfer->buffer_len = DEFAULT_BUFFER_SIZE;
		transfer->buffer = g_new0(char, DEFAULT_BUFFER_SIZE);
	}

	do {
		ssize_t len;

		len = read(transfer->fd, transfer->buffer + transfer->filled,
				transfer->buffer_len - transfer->filled);
		if (len < 0)
			goto failed;

		transfer->filled += len;

		if (transfer->filled == 0)
			goto complete;

		if (gw_obex_xfer_write(xfer, transfer->buffer,
					transfer->filled,
					&written, NULL) == FALSE)
			goto failed;

		transfer->filled -= written;
		transfer->transferred += written;
	} while (transfer->filled == 0);

	memmove(transfer->buffer, transfer->buffer + written, transfer->filled);

	agent_notify_progress(session->conn, session->agent_name,
			session->agent_path, transfer->path,
			transfer->transferred);
	return;

complete:
	agent_notify_complete(session->conn, session->agent_name,
				session->agent_path, transfer->path);
	goto done;

failed:
	agent_notify_error(session->conn, session->agent_name,
				session->agent_path, transfer->path,
				"Error sending object");

done:
	finalize_transfer(transfer);
}

static int session_send_reply(struct transfer_data *transfer, void *data)
{
	struct session_data *session = transfer->session;

	transfer->xfer = gw_obex_put_async(session->obex, transfer->name,
						NULL, transfer->size, -1,
						NULL);
	if (transfer->xfer == NULL)
		return -ENOTCONN;

	gw_obex_xfer_set_callback(transfer->xfer, put_xfer_progress, transfer);

	agent_notify_progress(session->conn, session->agent_name,
			session->agent_path, transfer->path, 0);

	return 0;
}

static void abort_transfer(struct transfer_data *transfer)
{
	struct session_data *session = transfer->session;

	agent_notify_error(session->conn, session->agent_name,
			session->agent_path, transfer->path,
			"The transfer was cancelled");

	if (transfer->request && transfer->request->call)
		dbus_pending_call_cancel(transfer->request->call);

	if (transfer->xfer) {
		gw_obex_xfer_abort(transfer->xfer, NULL);
		gw_obex_xfer_free(transfer->xfer);
		transfer->xfer = NULL;
	}
}

static void session_shutdown(struct session_data *session)
{
	struct transfer_data *transfer;

	transfer = session->pending ? session->pending->data : NULL;

	/* Abort active transfer */
	if (transfer)
		abort_transfer(transfer);

	/* Unregister any pending transfer */
	g_slist_foreach(session->pending, (GFunc) unregister_transfer, NULL);

	session_unref(session);
}

static void finalize_transfer(struct transfer_data *transfer)
{
	struct session_data *session = transfer->session;

	unregister_transfer(transfer);

	if (session->pending == NULL) {
		session_shutdown(session);
		return;
	}

	/* Request next transfer */
	agent_request(session->pending->data, session_send_reply, NULL);
}

static DBusMessage *transfer_cancel(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct transfer_data *transfer = user_data;
	struct session_data *session = transfer->session;
	const gchar *sender;
	DBusMessage *reply;

	sender = dbus_message_get_sender(message);
	if (g_str_equal(sender, session->agent_name) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.NotAuthorized",
				"Not Authorized");

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	abort_transfer(transfer);

	finalize_transfer(transfer);

	return reply;
}

static GDBusMethodTable transfer_methods[] = {
	{ "GetProperties", "", "a{sv}", transfer_get_properties },
	{ "Cancel", "", "", transfer_cancel },
	{ }
};

static struct transfer_data *register_transfer(struct session_data *session,
						const char *filename,
						const char *name,
						const char *type,
						struct transfer_params *params)
{
	struct transfer_data *transfer;

	transfer = g_new0(struct transfer_data, 1);
	transfer->session = session_ref(session);
	transfer->filename = g_strdup(filename);
	transfer->name = g_strdup(name);
	transfer->type = g_strdup(type);
	transfer->params = params;

	/* for OBEX specific mime types we don't need to register a transfer */
	if (type != NULL &&
			(strncmp(type, "x-obex/", 7) == 0 ||
			strncmp(type, "x-bt/", 5) == 0))
		goto done;

	transfer->path = g_strdup_printf("%s/transfer%ju",
			TRANSFER_BASEPATH, counter++);

	if (g_dbus_register_interface(session->conn, transfer->path,
				TRANSFER_INTERFACE,
				transfer_methods, NULL, NULL,
				transfer, NULL) == FALSE) {
		free_transfer(transfer);
		return NULL;
	}

	debug("Transfer registered %s", transfer->path);

done:
	session->pending = g_slist_append(session->pending, transfer);

	return transfer;
}

static void agent_disconnected(DBusConnection *connection, void *user_data)
{
	struct session_data *session = user_data;

	if (session->agent_name) {
		g_free(session->agent_name);
		session->agent_name = NULL;
	}

	if (session->agent_path) {
		g_free(session->agent_path);
		session->agent_path = NULL;
	}
}

static DBusMessage *assign_agent(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const gchar *sender;
	gchar *path;

	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments",
				"Invalid arguments in method call");

	if (session->agent_path != NULL || session->agent_name != NULL)
		return g_dbus_create_error(message,
				"org.openobex.Error.AlreadyExists",
				"Already exists");

	sender = dbus_message_get_sender(message);

	session->agent_name = g_strdup(sender);
	session->agent_path = g_strdup(path);

	session->agent_watch = g_dbus_add_disconnect_watch(connection, sender,
				agent_disconnected, session, NULL);

	return dbus_message_new_method_return(message);
}

static DBusMessage *release_agent(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const gchar *sender;
	gchar *path;

	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments",
				"Invalid arguments in method call");

	sender = dbus_message_get_sender(message);

	if (g_str_equal(sender, session->agent_name) == FALSE ||
				g_str_equal(path, session->agent_path) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.NotAuthorized",
				"Not Authorized");

	g_free(session->agent_name);
	session->agent_name = NULL;

	g_free(session->agent_path);
	session->agent_path = NULL;

	if (session->agent_watch) {
		g_dbus_remove_watch(session->conn, session->agent_watch);
		session->agent_watch = 0;
	}

	return dbus_message_new_method_return(message);
}

static DBusMessage *close_session(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const gchar *sender;

	sender = dbus_message_get_sender(message);
	if (g_str_equal(sender, session->owner) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.NotAuthorized",
				"Not Authorized");

	session_shutdown(session);

	return dbus_message_new_method_return(message);
}

static void owner_disconnected(DBusConnection *connection, void *user_data)
{
	struct session_data *session = user_data;

	session_shutdown(session);
}

static DBusMessage *session_get_properties(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	char addr[18];
	char *paddr = addr;

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	ba2str(&session->src, addr);
	append_entry(&dict, "Source", DBUS_TYPE_STRING, &paddr);

	ba2str(&session->dst, addr);
	append_entry(&dict, "Destination", DBUS_TYPE_STRING, &paddr);

	append_entry(&dict, "Channel", DBUS_TYPE_BYTE, &session->channel);

	if (session->agent_path)
		append_entry(&dict, "AgentPath", DBUS_TYPE_STRING, &session->agent_path);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable session_methods[] = {
	{ "GetProperties",	"", "a{sv}",	session_get_properties	},
	{ "AssignAgent",	"o", "",	assign_agent	},
	{ "ReleaseAgent",	"o", "",	release_agent	},
	{ "Close",		"", "",		close_session	},
	{ }
};

static void append_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter value;
	char sig[2] = { type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void dict_append_entry(DBusMessageIter *dict,
			const char *key, int type, void *val)
{
	DBusMessageIter entry;

	if (type == DBUS_TYPE_STRING) {
		const char *str = *((const char **) val);
		if (str == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

static void xml_element(GMarkupParseContext *ctxt,
			const gchar *element,
			const gchar **names,
			const gchar **values,
			gpointer user_data,
			GError **gerr)
{
	DBusMessageIter dict, *iter = user_data;
	gchar *key;
	gint i;

	if (strcasecmp("folder", element) != 0 && strcasecmp("file", element) != 0)
		return;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_entry(&dict, "Type", DBUS_TYPE_STRING, &element);

	/* FIXME: User, Group, Other permission must be reviewed */

	i = 0;
	for (key = (gchar *) names[i]; key; key = (gchar *) names[++i]) {
		key[0] = g_ascii_toupper(key[0]);
		if (g_str_equal("Size", key) == TRUE) {
			guint64 size;
			size = g_ascii_strtoll(values[i], NULL, 10);
			dict_append_entry(&dict, key, DBUS_TYPE_UINT64, &size);
		} else
			dict_append_entry(&dict, key, DBUS_TYPE_STRING, &values[i]);
	}

	dbus_message_iter_close_container(iter, &dict);
}

static const GMarkupParser parser = {
	xml_element,
	NULL,
	NULL,
	NULL,
	NULL
};

static void list_folder_callback(struct session_data *session,
					void *user_data)
{
	struct transfer_data *transfer = session->pending->data;
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	int i;

	reply = dbus_message_new_method_return(session->msg);

	if (transfer->filled == 0)
		goto done;

	for (i = transfer->filled - 1; i > 0; i--) {
		if (transfer->buffer[i] != '\0')
			break;

		transfer->filled--;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);
	ctxt = g_markup_parse_context_new(&parser, 0, &array, NULL);
	g_markup_parse_context_parse(ctxt, transfer->buffer,
					transfer->filled, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);

	transfer->filled = 0;

done:
	g_dbus_send_message(session->conn, reply);
	dbus_message_unref(session->msg);
	session->msg = NULL;
}

static void get_file_callback(struct session_data *session, void *user_data)
{

}

static void get_xfer_listing_progress(GwObexXfer *xfer,
					gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct transfer_params *params = transfer->params;
	struct session_data *session = transfer->session;
	gint bsize, bread, err = 0;

	bsize = transfer->buffer_len - transfer->filled;

	if (bsize < DEFAULT_BUFFER_SIZE) {
		transfer->buffer_len += DEFAULT_BUFFER_SIZE;
		transfer->buffer = g_realloc(transfer->buffer, transfer->buffer_len);
		bsize += DEFAULT_BUFFER_SIZE;
	}

	gw_obex_xfer_read(xfer, transfer->buffer + transfer->filled,
			bsize, &bread, &err);


	if (session->msg && err) {
		DBusMessage *reply;

		reply = g_dbus_create_error(session->msg,
				"org.openobex.Error.Failed",
				OBEX_ResponseToString(err));

		g_dbus_send_message(session->conn, reply);

		dbus_message_unref(session->msg);
		session->msg = NULL;
	}

	if (err) {
		error("gw_obex_xfer_read(): %s",
				OBEX_ResponseToString(err));
		goto complete;
	}

	transfer->filled += bread;

	if (gw_obex_xfer_object_done(xfer)) {
		if (transfer->buffer[transfer->filled - 1] == '\0')
			goto complete;

		bsize = transfer->buffer_len - transfer->filled;
		if (bsize < 1) {
			transfer->buffer_len += DEFAULT_BUFFER_SIZE;
			transfer->buffer = g_realloc(transfer->buffer, transfer->buffer_len);
		}

		transfer->buffer[transfer->filled] = '\0';
		goto complete;
	}

	return;

complete:
	if (err == 0) {
		agent_notify_progress(session->conn, session->agent_name,
				session->agent_path, transfer->path,
				transfer->filled);
		agent_notify_complete(session->conn, session->agent_name,
				session->agent_path, transfer->path);
	}

	params->cb(session, params->user_data);

	unregister_transfer(transfer);
}

static void get_xfer_progress(GwObexXfer *xfer, gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct transfer_params *params = transfer->params;
	struct session_data *session = transfer->session;
	gint bsize, bread, err = 0;
	gboolean ret;

	if (transfer->buffer_len == 0) {
		transfer->buffer_len = DEFAULT_BUFFER_SIZE;
		transfer->buffer = g_new0(char, DEFAULT_BUFFER_SIZE);
	}

	bsize = transfer->buffer_len - transfer->filled;

	ret = gw_obex_xfer_read(xfer, transfer->buffer + transfer->filled,
					bsize, &bread, &err);

	/* For GetFile reply on the first received stream */
	if (transfer->fd > 0 && session->msg) {
		DBusMessage *reply;

		if (ret == FALSE)
			reply = g_dbus_create_error(session->msg,
					"org.openobex.Error.Failed",
					OBEX_ResponseToString(err));
		else
			reply = dbus_message_new_method_return(session->msg);

		g_dbus_send_message(session->conn, reply);

		dbus_message_unref(session->msg);
		session->msg = NULL;
	}

	if (ret == FALSE) {
		error("gw_obex_xfer_read(): %s",
				OBEX_ResponseToString(err));
		goto complete;
	}

	transfer->filled += bread;
	transfer->transferred += bread;
	if (transfer->size == 0)
		transfer->size = gw_obex_xfer_object_size(xfer);

	if (transfer->fd > 0) {
		gint w;

		w = write(transfer->fd, transfer->buffer, bread);
		if (w < 0) {
			ret = FALSE;
			goto complete;
		}

		transfer->filled = 0;
	}

	if (transfer->transferred == transfer->size)
		goto complete;

	gw_obex_xfer_flush(xfer, NULL);

	agent_notify_progress(session->conn, session->agent_name,
			session->agent_path, transfer->path,
			transfer->transferred);

	return;

complete:

	if (ret == TRUE) {
		agent_notify_progress(session->conn, session->agent_name,
				session->agent_path, transfer->path,
				transfer->transferred);
		agent_notify_complete(session->conn, session->agent_name,
				session->agent_path, transfer->path);
	} else
		agent_notify_error(session->conn, session->agent_name,
				session->agent_path, transfer->path,
				"Error getting object");

	params->cb(session, params->user_data);

	unregister_transfer(transfer);
}

static int session_get_reply(struct transfer_data *transfer, void *data)
{
	struct session_data *session = transfer->session;

	transfer->xfer = gw_obex_get_async_with_apparam(session->obex,
							transfer->filename,
							transfer->type,
							transfer->params->data,
							transfer->params->size,
							NULL);
	if (transfer->xfer == NULL) {
		unregister_transfer(transfer);
		return -EIO;
	}

	if (transfer->type == NULL)
		gw_obex_xfer_set_callback(transfer->xfer, get_xfer_progress, transfer);
	else
		gw_obex_xfer_set_callback(transfer->xfer, get_xfer_listing_progress,
					transfer);

	agent_notify_progress(session->conn, session->agent_name,
			session->agent_path, transfer->path, 0);

	return 0;
}

int session_get(struct session_data *session, const char *type,
		const char *filename, const char *targetname,
		const guint8  *apparam, gint apparam_size,
		session_callback_t func)
{
	struct transfer_data *transfer;
	struct transfer_params *params;
	int err, fd = 0;

	if (session->obex == NULL)
		return -ENOTCONN;

	if (type == NULL) {
		if (targetname == NULL)
			targetname = filename;

		fd = open(targetname, O_WRONLY | O_CREAT, 0600);
		if (fd < 0) {
			err = errno;
			error("open(): %s(%d)", strerror(err), err);
			return -err;
		}
	}

	params = g_new0(struct transfer_params, 1);
	params->data = apparam;
	params->size = apparam_size;
	params->cb = func;

	transfer = register_transfer(session, filename, targetname, type,
					params);
	if (transfer == NULL) {
		if (fd)
			close(fd);

		g_free(params);
		return -EIO;
	}

	transfer->fd = fd;

	agent_request(transfer, session_get_reply, NULL);

	return 0;
}

static DBusMessage *change_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *folder;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &folder,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (gw_obex_chdir(session->obex, folder, &err) == FALSE) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				OBEX_ResponseToString(err));
	}

	return dbus_message_new_method_return(message);
}

static DBusMessage *create_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *folder;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &folder,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (gw_obex_mkdir(session->obex, folder, &err) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				OBEX_ResponseToString(err));

	return dbus_message_new_method_return(message);
}

static DBusMessage *list_folder(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;

	if (session->msg)
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");

	if (session_get(session, "x-obex/folder-listing",
				NULL, NULL, NULL, 0, list_folder_callback) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	session->msg = dbus_message_ref(message);

	return NULL;
}

static DBusMessage *get_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *target_file, *source_file;

	if (session->msg)
		return g_dbus_create_error(message,
				"org.openobex.Error.InProgress",
				"Transfer in progress");

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &target_file,
				DBUS_TYPE_STRING, &source_file,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (session_get(session, NULL, source_file,
				target_file, NULL, 0, get_file_callback) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	session->msg = dbus_message_ref(message);

	return NULL;
}

static DBusMessage *put_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	gchar *sourcefile, *targetfile;

	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_STRING, &sourcefile,
					DBUS_TYPE_STRING, &targetfile,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments",
				"Invalid arguments in method call");

	if (session_send(session, sourcefile, targetfile) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				"Failed");

	return dbus_message_new_method_return(message);
}

static DBusMessage *copy_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return dbus_message_new_method_return(message);
}

static DBusMessage *move_file(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	return dbus_message_new_method_return(message);
}

static DBusMessage *delete(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const char *file;
	int err;

	if (dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &file,
				DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	if (gw_obex_delete(session->obex, file, &err) == FALSE) {
		return g_dbus_create_error(message,
				"org.openobex.Error.Failed",
				OBEX_ResponseToString(err));
	}

	return dbus_message_new_method_return(message);
}

static GDBusMethodTable ftp_methods[] = {
	{ "ChangeFolder",	"s", "",	change_folder	},
	{ "CreateFolder",	"s", "",	create_folder	},
	{ "ListFolder",		"", "aa{sv}",	list_folder,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetFile",		"ss", "",	get_file,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "PutFile",		"ss", "",	put_file	},
	{ "CopyFile",		"ss", "",	copy_file	},
	{ "MoveFile",		"ss", "",	move_file	},
	{ "Delete",		"s", "",	delete		},
	{ }
};

int session_send(struct session_data *session, const char *filename,
				const char *targetname)
{
	struct transfer_data *transfer;
	struct stat st;
	int fd, err;

	if (session->obex == NULL)
		return -ENOTCONN;

	transfer = register_transfer(session, filename, targetname, NULL, NULL);
	if (transfer == NULL) {
		err = -EINVAL;
		goto fail;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		err = -EIO;
		goto fail;
	}

	if (fstat(fd, &st) < 0) {
		close(fd);
		err = -EIO;
		goto fail;
	}

	transfer->fd = fd;

	/* Transfer should start if it is the first in the pending list */
	if (transfer != session->pending->data)
		return 0;

	agent_request(transfer, session_send_reply, NULL);

	return 0;

fail:
	agent_notify_error(session->conn, session->agent_name,
			session->agent_path, transfer->path,
			"Could not open file for sending");

	unregister_transfer(transfer);

	return err;
}

int session_pull(struct session_data *session,
				const char *type, const char *filename,
				session_callback_t function, void *user_data)
{
	struct transfer_data *transfer;
	struct transfer_params *params;

	if (session->obex == NULL)
		return -ENOTCONN;

	transfer = register_transfer(session, NULL, NULL, type, NULL);
	if (transfer == NULL)
		return -EIO;

	params = g_try_malloc0(sizeof(*params));
	if (params == NULL) {
		unregister_transfer(transfer);
		return -ENOMEM;
	}

	params->cb = function;
	params->user_data = user_data;

	transfer->xfer = gw_obex_get_async(session->obex, NULL, type, NULL);
	if (transfer->xfer == NULL) {
		unregister_transfer(transfer);
		g_free(params);
		return -ENOTCONN;
	}

	transfer->params = params;

	gw_obex_xfer_set_callback(transfer->xfer, get_xfer_listing_progress, transfer);

	return 0;
}

int session_register(struct session_data *session)
{
	gboolean result = FALSE;

	session->path = g_strdup_printf("%s/session%ju",
						SESSION_BASEPATH, counter++);

	if (g_dbus_register_interface(session->conn, session->path,
					SESSION_INTERFACE, session_methods,
					NULL, NULL, session, NULL) == FALSE)
		return -EIO;

	switch (session->uuid.value.uuid16) {
	case OBEX_FILETRANS_SVCLASS_ID:
		result = g_dbus_register_interface(session->conn,
					session->path, FTP_INTERFACE,
					ftp_methods, NULL, NULL, session, NULL);
		break;
	case PBAP_PSE_SVCLASS_ID:
		result = pbap_register_interface(session->conn,
						session->path, session, NULL);
		break;
	case IRMC_SYNC_SVCLASS_ID:
		result = sync_register_interface(session->conn,
						session->path, session, NULL);
	}

	if (result == FALSE) {
		g_dbus_unregister_interface(session->conn,
					session->path, SESSION_INTERFACE);
		return -EIO;
	}

	session->owner_watch = g_dbus_add_disconnect_watch(session->conn,
					session->owner, owner_disconnected,
								session, NULL);

	return 0;
}

void *session_get_data(struct session_data *session)
{
	return session->priv;
}

void session_set_data(struct session_data *session, void *priv)
{
	session->priv = priv;
}

static void put_buf_xfer_progress(GwObexXfer *xfer, gpointer user_data)
{
	struct transfer_data *transfer = user_data;
	struct session_data *session = transfer->session;
	gint written;

	if (transfer->transferred == transfer->size)
		goto complete;

	if (gw_obex_xfer_write(xfer, transfer->buffer + transfer->transferred,
				transfer->size - transfer->transferred,
				&written, NULL) == FALSE)
		goto complete;

	if (gw_obex_xfer_flush(xfer, NULL) == FALSE)
		goto complete;

	transfer->transferred += written;

	agent_notify_progress(session->conn, session->agent_name,
		session->agent_path, transfer->path,
		transfer->transferred);

	return;

complete:
	if (transfer->transferred == transfer->size)
		agent_notify_complete(session->conn, session->agent_name,
			session->agent_path, transfer->path);
	else
		agent_notify_error(session->conn, session->agent_name,
			session->agent_path, transfer->path,
			"Error sending object");

	finalize_transfer(transfer);
}

static int session_put_reply(struct transfer_data *transfer, void *data)
{
	struct session_data *session = transfer->session;

	transfer->xfer = gw_obex_put_async(session->obex, transfer->name, NULL,
						transfer->size, -1, NULL);
	if (transfer->xfer == NULL)
		return -ENOTCONN;

	gw_obex_xfer_set_callback(transfer->xfer, put_buf_xfer_progress,
					transfer);

	agent_notify_progress(session->conn, session->agent_name,
		session->agent_path, transfer->path, 0);

	return 0;
}

int session_put(struct session_data *session, char *buf, const char *targetname)
{
	struct transfer_data *transfer;

	if (session->obex == NULL)
		return -ENOTCONN;

	if (session->pending != NULL)
		return -EISCONN;

	transfer = register_transfer(session, NULL, targetname, NULL, NULL);
	if (transfer == NULL)
		return -EIO;

	transfer->size = strlen(buf);
	transfer->buffer = buf;

	agent_request(transfer, session_put_reply, NULL);

	return 0;
}

int session_set_agent(struct session_data *session, const char *name,
							const char *path)
{
	if (session == NULL)
		return -EINVAL;

	if (session->agent_name != NULL || session->agent_path != NULL ||
			session->owner_watch != 0)
		return -EALREADY;

	session->agent_name = g_strdup(name);
	session->agent_path = g_strdup(path);

	session->owner_watch = g_dbus_add_disconnect_watch(session->conn,
					session->owner, owner_disconnected,
								session, NULL);

	return 0;
}
