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
#include <gw-obex.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "log.h"
#include "pbap.h"
#include "sync.h"
#include "ftp.h"
#include "transfer.h"
#include "session.h"
#include "btio.h"
#include "agent.h"

#define SESSION_INTERFACE  "org.openobex.Session"
#define SESSION_BASEPATH   "/org/openobex"

#define OBEX_IO_ERROR obex_io_error_quark()

#define BT_BUS_NAME		"org.bluez"
#define BT_PATH			"/"
#define BT_ADAPTER_IFACE	"org.bluez.Adapter"
#define BT_MANAGER_IFACE	"org.bluez.Manager"

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

struct session_callback {
	session_callback_t func;
	void *data;
};

struct pending_data {
	session_callback_t cb;
	struct session_data *session;
	struct transfer_data *transfer;
};

struct pending_req {
	DBusPendingCall *call;
	void *user_data;
};

struct session_data {
	gint refcount;
	bdaddr_t src;
	bdaddr_t dst;
	uint8_t channel;
	char *service;		/* Service friendly name */
	const char *target;	/* OBEX Target UUID */
	int target_len;
	uuid_t uuid;		/* Bluetooth Service Class */
	gchar *path;		/* Session path */
	DBusConnection *conn;
	DBusConnection *conn_system; /* system bus connection */
	DBusMessage *msg;
	GwObex *obex;
	GIOChannel *io;
	struct agent_data *agent;
	struct session_callback *callback;
	gchar *owner;		/* Session owner */
	guint watch;
	GSList *pending;
	GSList *pending_calls;
	void *priv;
	char *adapter;
};

static GSList *sessions = NULL;

static void session_prepare_put(struct session_data *session, GError *err,
								void *data);
static void session_terminate_transfer(struct session_data *session,
					struct transfer_data *transfer,
					GError *gerr);

static GQuark obex_io_error_quark(void)
{
	return g_quark_from_static_string("obex-io-error-quark");
}

struct session_data *session_ref(struct session_data *session)
{
	g_atomic_int_inc(&session->refcount);

	DBG("%p: ref=%d", session, session->refcount);

	return session;
}

static void session_unregistered(struct session_data *session)
{
	char *path;

	switch (session->uuid.value.uuid16) {
	case OBEX_FILETRANS_SVCLASS_ID:
		ftp_unregister_interface(session->conn, session->path);
		break;
	case PBAP_PSE_SVCLASS_ID:
		pbap_unregister_interface(session->conn, session->path);
		break;
	case IRMC_SYNC_SVCLASS_ID:
		sync_unregister_interface(session->conn, session->path);
	}

	path = session->path;
	session->path = NULL;

	g_dbus_unregister_interface(session->conn, path, SESSION_INTERFACE);

	DBG("Session(%p) unregistered %s", session, path);

	g_free(path);
}

static struct pending_req *find_session_request(
				const struct session_data *session,
				const DBusPendingCall *call)
{
	GSList *l;

	for (l = session->pending_calls; l; l = l->next) {
		struct pending_req *req = l->data;

		if (req->call == call)
			return req;
	}

	return NULL;
}

static void pending_req_finalize(struct pending_req *req)
{
	if (!dbus_pending_call_get_completed(req->call))
		dbus_pending_call_cancel(req->call);

	dbus_pending_call_unref(req->call);
	g_free(req);
}

static void session_free(struct session_data *session)
{
	GSList *l = session->pending_calls;

	DBG("%p", session);

	while (l) {
		struct pending_req *req = l->data;
		l = l->next;

		session->pending_calls = g_slist_remove(session->pending_calls, req);
		pending_req_finalize(req);
	}

	if (session->agent) {
		agent_release(session->agent);
		agent_free(session->agent);
	}

	if (session->watch)
		g_dbus_remove_watch(session->conn, session->watch);

	if (session->obex != NULL)
		gw_obex_close(session->obex);

	if (session->io != NULL) {
		g_io_channel_shutdown(session->io, TRUE, NULL);
		g_io_channel_unref(session->io);
	}

	if (session->path)
		session_unregistered(session);

	if (session->conn)
		dbus_connection_unref(session->conn);

	if (session->conn_system)
		dbus_connection_unref(session->conn_system);

	sessions = g_slist_remove(sessions, session);

	g_free(session->adapter);
	g_free(session->callback);
	g_free(session->path);
	g_free(session->service);
	g_free(session->owner);
	g_free(session);
}

static struct pending_req *send_method_call(DBusConnection *connection,
				const char *dest, const char *path,
				const char *interface, const char *method,
				DBusPendingCallNotifyFunction cb,
				void *user_data, int type, ...)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	va_list args;
	struct pending_req *req;

	msg = dbus_message_new_method_call(dest, path, interface, method);
	if (!msg) {
		error("Unable to allocate new D-Bus %s message", method);
		return NULL;
	}

	va_start(args, type);

	if (!dbus_message_append_args_valist(msg, type, args)) {
		dbus_message_unref(msg);
		va_end(args);
		return NULL;
	}

	va_end(args);

	if (!cb) {
		g_dbus_send_message(connection, msg);
		return 0;
	}

	if (!dbus_connection_send_with_reply(connection, msg, &call, -1)) {
		error("Sending %s failed", method);
		dbus_message_unref(msg);
		return NULL;
	}

	dbus_pending_call_set_notify(call, cb, user_data, NULL);

	req = g_new0(struct pending_req, 1);
	req->call = call;
	req->user_data = user_data;

	dbus_message_unref(msg);

	return req;
}

void session_unref(struct session_data *session)
{
	gboolean ret;

	ret = g_atomic_int_dec_and_test(&session->refcount);

	DBG("%p: ref=%d", session, session->refcount);

	if (ret == FALSE)
		return;

	send_method_call(session->conn_system,
				BT_BUS_NAME, session->adapter,
				BT_ADAPTER_IFACE, "ReleaseSession",
				NULL, NULL,
				DBUS_TYPE_INVALID);
	session_free(session);
}

static void rfcomm_callback(GIOChannel *io, GError *err, gpointer user_data)
{
	struct callback_data *callback = user_data;
	struct session_data *session = callback->session;
	GwObex *obex;
	int fd;

	DBG("");

	if (err != NULL) {
		error("%s", err->message);
		goto done;
	}

	/* do not close when gw_obex is using the fd */
	g_io_channel_set_close_on_unref(session->io, FALSE);
	g_io_channel_unref(session->io);
	session->io = NULL;

	fd = g_io_channel_unix_get_fd(io);

	obex = gw_obex_setup_fd(fd, session->target,
			session->target_len, NULL, NULL);

	session->obex = obex;

	sessions = g_slist_prepend(sessions, session);

done:
	callback->func(callback->session, err, callback->data);

	session_unref(callback->session);

	g_free(callback);
}

static GIOChannel *rfcomm_connect(const bdaddr_t *src, const bdaddr_t *dst,
					uint8_t channel, BtIOConnect function,
					gpointer user_data)
{
	GIOChannel *io;
	GError *err = NULL;

	DBG("");

	io = bt_io_connect(BT_IO_RFCOMM, function, user_data, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_DEST_BDADDR, dst,
				BT_IO_OPT_CHANNEL, channel,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (io != NULL)
		return io;

	error("%s", err->message);
	g_error_free(err);
	return NULL;
}

static void search_callback(uint8_t type, uint16_t status,
			uint8_t *rsp, size_t size, void *user_data)
{
	struct callback_data *callback = user_data;
	struct session_data *session = callback->session;
	unsigned int scanned, bytesleft = size;
	int seqlen = 0;
	uint8_t dataType, channel = 0;
	GError *gerr = NULL;

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

	session->channel = channel;

	g_io_channel_set_close_on_unref(session->io, FALSE);
	g_io_channel_unref(session->io);

	session->io = rfcomm_connect(&session->src, &session->dst, channel,
					rfcomm_callback, callback);
	if (session->io != NULL) {
		sdp_close(callback->sdp);
		return;
	}

failed:
	g_io_channel_shutdown(session->io, TRUE, NULL);
	g_io_channel_unref(session->io);
	session->io = NULL;

	g_set_error(&gerr, OBEX_IO_ERROR, -EIO,
					"Unable to find service record");
	callback->func(session, gerr, callback->data);
	g_clear_error(&gerr);

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
	struct session_data *session = callback->session;
	sdp_list_t *search, *attrid;
	uint32_t range = 0x0000ffff;
	GError *gerr = NULL;

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
	g_io_channel_shutdown(session->io, TRUE, NULL);
	g_io_channel_unref(session->io);
	session->io = NULL;

	g_set_error(&gerr, OBEX_IO_ERROR, -EIO,
					"Unable to find service record");
	callback->func(callback->session, gerr, callback->data);
	g_clear_error(&gerr);

	session_unref(callback->session);
	g_free(callback);
	return FALSE;
}

static sdp_session_t *service_connect(const bdaddr_t *src, const bdaddr_t *dst,
					GIOFunc function, gpointer user_data)
{
	struct callback_data *cb = user_data;
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

	cb->session->io = io;

	return sdp;
}

static gboolean connection_complete(gpointer data)
{
	struct callback_data *cb = data;

	cb->func(cb->session, 0, cb->data);

	session_unref(cb->session);

	g_free(cb);

	return FALSE;
}

static void owner_disconnected(DBusConnection *connection, void *user_data)
{
	struct session_data *session = user_data;

	DBG("");

	session_shutdown(session);
}

int session_set_owner(struct session_data *session, const char *name,
			GDBusWatchFunction func)
{
	if (session == NULL)
		return -EINVAL;

	if (session->watch)
		g_dbus_remove_watch(session->conn, session->watch);

	session->watch = g_dbus_add_disconnect_watch(session->conn, name, func,
							session, NULL);
	if (session->watch == 0)
		return -EINVAL;

	session->owner = g_strdup(name);

	return 0;
}

static struct session_data *session_find(const char *source,
						const char *destination,
						const char *service,
						uint8_t channel,
						const char *owner)
{
	GSList *l;

	for (l = sessions; l; l = l->next) {
		struct session_data *session = l->data;
		bdaddr_t adr;

		if (source) {
			str2ba(source, &adr);
			if (bacmp(&session->src, &adr))
				continue;
		}

		str2ba(destination, &adr);
		if (bacmp(&session->dst, &adr))
			continue;

		if (g_strcmp0(service, session->service))
			continue;

		if (channel && session->channel != channel)
			continue;

		if (g_strcmp0(owner, session->owner))
			continue;

		return session;
	}

	return NULL;
}

static int session_connect(struct session_data *session,
						struct callback_data *callback)
{
	int err;

	if (session->obex) {
		g_idle_add(connection_complete, callback);
		err = 0;
	} else if (session->channel > 0) {
		session->io = rfcomm_connect(&session->src, &session->dst,
							session->channel,
							rfcomm_callback,
							callback);
		err = (session->io == NULL) ? -EINVAL : 0;
	} else {
		callback->sdp = service_connect(&session->src, &session->dst,
						service_callback, callback);
		err = (callback->sdp == NULL) ? -ENOMEM : 0;
	}

	return err;
}

static void adapter_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	struct callback_data *callback = user_data;
	struct session_data *session = callback->session;
	struct pending_req *req = find_session_request(session, call);

	reply = dbus_pending_call_steal_reply(call);

	session->pending_calls = g_slist_remove(session->pending_calls, req);
	pending_req_finalize(req);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("manager replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);

		goto failed;
	}

	if (session_connect(session, callback) < 0)
		goto failed;

	goto proceed;

failed:
	session_unref(session);
	g_free(callback);

proceed:
	dbus_message_unref(reply);
}

static void manager_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	char *adapter;
	struct callback_data *callback = user_data;
	struct session_data *session = callback->session;
	struct pending_req *req = find_session_request(session, call);

	reply = dbus_pending_call_steal_reply(call);

	session->pending_calls = g_slist_remove(session->pending_calls, req);
	pending_req_finalize(req);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("manager replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);

		goto failed;
	}

	if (dbus_message_get_args(reply, NULL,
				DBUS_TYPE_OBJECT_PATH, &adapter,
				DBUS_TYPE_INVALID)) {
		DBG("adapter path %s", adapter);

		session->adapter = g_strdup(adapter);
		req = send_method_call(session->conn_system,
					BT_BUS_NAME, adapter,
					BT_ADAPTER_IFACE, "RequestSession",
					adapter_reply, callback,
					DBUS_TYPE_INVALID);
		if (!req)
			goto failed;

		session->pending_calls = g_slist_prepend(session->pending_calls,
									req);
	} else
		goto failed;

	goto proceed;

failed:
	session_unref(session);
	g_free(callback);

proceed:
	dbus_message_unref(reply);
}

struct session_data *session_create(const char *source,
						const char *destination,
						const char *service,
						uint8_t channel,
						const char *owner,
						session_callback_t function,
						void *user_data)
{
	struct session_data *session;
	struct callback_data *callback;
	struct pending_req *req;

	if (destination == NULL)
		return NULL;

	session = session_find(source, destination, service, channel, owner);
	if (session) {
		session_ref(session);
		goto proceed;
	}

	session = g_try_malloc0(sizeof(*session));
	if (session == NULL)
		return NULL;

	session->refcount = 1;
	session->channel = channel;

	session->conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (session->conn == NULL) {
		session_free(session);
		return NULL;
	}

	session->conn_system = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);
	if (session->conn_system == NULL) {
		session_free(session);
		return NULL;
	}

	if (source == NULL)
		bacpy(&session->src, BDADDR_ANY);
	else
		str2ba(source, &session->src);

	str2ba(destination, &session->dst);
	session->service = g_strdup(service);

	if (!g_ascii_strncasecmp(service, "OPP", 3)) {
		sdp_uuid16_create(&session->uuid, OBEX_OBJPUSH_SVCLASS_ID);
	} else if (!g_ascii_strncasecmp(service, "FTP", 3)) {
		sdp_uuid16_create(&session->uuid, OBEX_FILETRANS_SVCLASS_ID);
		session->target = OBEX_FTP_UUID;
		session->target_len = OBEX_FTP_UUID_LEN;
	} else if (!g_ascii_strncasecmp(service, "PBAP", 4)) {
		sdp_uuid16_create(&session->uuid, PBAP_PSE_SVCLASS_ID);
		session->target = OBEX_PBAP_UUID;
		session->target_len = OBEX_PBAP_UUID_LEN;
	} else if (!g_ascii_strncasecmp(service, "SYNC", 4)) {
		sdp_uuid16_create(&session->uuid, IRMC_SYNC_SVCLASS_ID);
		session->target = OBEX_SYNC_UUID;
		session->target_len = OBEX_SYNC_UUID_LEN;
	} else if (!g_ascii_strncasecmp(service, "PCSUITE", 7)) {
		sdp_uuid128_create(&session->uuid, pcsuite_uuid);
	} else {
		return NULL;
	}

proceed:
	callback = g_try_malloc0(sizeof(*callback));
	if (callback == NULL) {
		session_unref(session);
		return NULL;
	}

	callback->session = session_ref(session);
	callback->func = function;
	callback->data = user_data;

	if (source) {
		req = send_method_call(session->conn_system,
				BT_BUS_NAME, BT_PATH,
				BT_MANAGER_IFACE, "FindAdapter",
				manager_reply, callback,
				DBUS_TYPE_STRING, &source,
				DBUS_TYPE_INVALID);
	} else {
		req = send_method_call(session->conn_system,
				BT_BUS_NAME, BT_PATH,
				BT_MANAGER_IFACE, "DefaultAdapter",
				manager_reply, callback,
				DBUS_TYPE_INVALID);
	}

	if (!req) {
		session_unref(session);
		g_free(callback);
		return NULL;
	}

	session->pending_calls = g_slist_prepend(session->pending_calls, req);

	if (owner)
		session_set_owner(session, owner, owner_disconnected);

	return session;
}

void session_shutdown(struct session_data *session)
{
	DBG("%p", session);

	session_ref(session);

	/* Unregister any pending transfer */
	g_slist_foreach(session->pending, (GFunc) transfer_unregister, NULL);

	/* Unregister interfaces */
	if (session->path)
		session_unregistered(session);

	/* Shutdown io */
	if (session->io) {
		int fd = g_io_channel_unix_get_fd(session->io);
		shutdown(fd, SHUT_RDWR);
	}

	session_unref(session);
}

static DBusMessage *assign_agent(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	const gchar *sender, *path;

	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments",
				"Invalid arguments in method call");

	sender = dbus_message_get_sender(message);

	if (session_set_agent(session, sender, path) < 0)
		return g_dbus_create_error(message,
				"org.openobex.Error.AlreadyExists",
				"Already exists");

	return dbus_message_new_method_return(message);
}

static DBusMessage *release_agent(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
	struct agent_data *agent = session->agent;
	const gchar *sender;
	gchar *path;

	if (dbus_message_get_args(message, NULL,
					DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments",
				"Invalid arguments in method call");

	sender = dbus_message_get_sender(message);

	if (agent == NULL ||
			g_str_equal(sender, agent_get_name(agent)) == FALSE ||
			g_str_equal(path, agent_get_path(agent)) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.NotAuthorized",
				"Not Authorized");

	agent_free(agent);

	return dbus_message_new_method_return(message);
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

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable session_methods[] = {
	{ "GetProperties",	"", "a{sv}",	session_get_properties	},
	{ "AssignAgent",	"o", "",	assign_agent	},
	{ "ReleaseAgent",	"o", "",	release_agent	},
	{ }
};

static void session_request_reply(DBusPendingCall *call, gpointer user_data)
{
	struct pending_data *pending = user_data;
	struct session_data *session = pending->session;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const char *name;
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		GError *gerr = NULL;

		error("Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		dbus_message_unref(reply);

		g_set_error(&gerr, OBEX_IO_ERROR, -ECANCELED, "%s",
								derr.message);
		session_terminate_transfer(session, pending->transfer, gerr);
		g_clear_error(&gerr);

		return;
	}

	dbus_message_get_args(reply, NULL,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID);

	DBG("Agent.Request() reply: %s", name);

	if (strlen(name))
		transfer_set_name(pending->transfer, name);

	pending->cb(session, NULL, pending->transfer);
	dbus_message_unref(reply);

	return;
}

static gboolean session_request_proceed(gpointer data)
{
	struct pending_data *pending = data;
	struct transfer_data *transfer = pending->transfer;

	pending->cb(pending->session, NULL, transfer);
	g_free(pending);

	return FALSE;
}

static int session_request(struct session_data *session, session_callback_t cb,
				struct transfer_data *transfer)
{
	struct agent_data *agent = session->agent;
	struct pending_data *pending;
	const char *path;
	int err;

	pending = g_new0(struct pending_data, 1);
	pending->cb = cb;
	pending->session = session;
	pending->transfer = transfer;

	path = transfer_get_path(transfer);

	if (agent == NULL || path == NULL) {
		g_idle_add(session_request_proceed, pending);
		return 0;
	}

	err = agent_request(agent, path, session_request_reply, pending,
								g_free);
	if (err < 0) {
		g_free(pending);
		return err;
	}

	return 0;
}

static void session_terminate_transfer(struct session_data *session,
					struct transfer_data *transfer,
					GError *gerr)
{
	struct session_callback *callback = session->callback;

	if (callback) {
		callback->func(session, gerr, callback->data);
		return;
	}

	session_ref(session);

	transfer_unregister(transfer);

	if (session->pending)
		session_request(session, session_prepare_put,
				session->pending->data);

	session_unref(session);
}

static void session_notify_complete(struct session_data *session,
				struct transfer_data *transfer)
{
	struct agent_data *agent = session->agent;
	const char *path;

	path = transfer_get_path(transfer);

	if (agent == NULL || path == NULL)
		goto done;

	agent_notify_complete(agent, path);

done:

	DBG("Transfer(%p) complete", transfer);

	session_terminate_transfer(session, transfer, NULL);
}

static void session_notify_error(struct session_data *session,
				struct transfer_data *transfer,
				GError *err)
{
	struct agent_data *agent = session->agent;
	const char *path;

	path = transfer_get_path(transfer);
	if (agent == NULL || path == NULL)
		goto done;

	agent_notify_error(agent, path, err->message);

done:
	error("Transfer(%p) Error: %s", transfer, err->message);

	session_terminate_transfer(session, transfer, err);
}

static void session_notify_progress(struct session_data *session,
					struct transfer_data *transfer,
					gint64 transferred)
{
	struct agent_data *agent = session->agent;
	const char *path;

	path = transfer_get_path(transfer);
	if (agent == NULL || path == NULL)
		goto done;

	agent_notify_progress(agent, path, transferred);

done:
	DBG("Transfer(%p) progress: %ld bytes", transfer,
			(long int ) transferred);

	if (transferred == transfer_get_size(transfer))
		session_notify_complete(session, transfer);
}

static void transfer_progress(struct transfer_data *transfer, gint64 transferred,
				int err, void *user_data)
{
	struct session_data *session = user_data;
	GError *gerr = NULL;

	if (err != 0)
		goto fail;

	session_notify_progress(session, transfer, transferred);

	return;

fail:
	g_set_error(&gerr, OBEX_IO_ERROR, err, "%s",
			err > 0 ? OBEX_ResponseToString(err) : strerror(-err));
	session_notify_error(session, transfer, gerr);
	g_clear_error(&gerr);
}

static void session_prepare_get(struct session_data *session,
				GError *err, void *data)
{
	struct transfer_data *transfer = data;
	int ret;

	ret = transfer_get(transfer, transfer_progress, session);
	if (ret < 0) {
		GError *gerr = NULL;

		g_set_error(&gerr, OBEX_IO_ERROR, ret, "%s", strerror(-ret));
		session_notify_error(session, transfer, gerr);
		g_clear_error(&gerr);
		return;
	}

	DBG("Transfer(%p) started", transfer);
}

int session_get(struct session_data *session, const char *type,
		const char *filename, const char *targetname,
		const guint8 *apparam, gint apparam_size,
		session_callback_t func, void *user_data)
{
	struct transfer_data *transfer;
	struct transfer_params *params = NULL;
	int err;

	if (session->obex == NULL)
		return -ENOTCONN;

	if (apparam != NULL) {
		params = g_new0(struct transfer_params, 1);
		params->data = g_new(guint8, apparam_size);
		memcpy(params->data, apparam, apparam_size);
		params->size = apparam_size;
	}

	transfer = transfer_register(session->conn, filename, targetname, type,
					params, session);
	if (transfer == NULL) {
		if (params != NULL) {
			g_free(params->data);
			g_free(params);
		}
		return -EIO;
	}

	if (func != NULL) {
		struct session_callback *callback;
		callback = g_new0(struct session_callback, 1);
		callback->func = func;
		callback->data = user_data;
		session->callback = callback;
	}

	err = session_request(session, session_prepare_get, transfer);
	if (err < 0)
		return err;

	return 0;
}

int session_send(struct session_data *session, const char *filename,
				const char *targetname)
{
	struct transfer_data *transfer;
	int err;

	if (session->obex == NULL)
		return -ENOTCONN;

	transfer = transfer_register(session->conn, filename, targetname, NULL,
					NULL, session);
	if (transfer == NULL)
		return -EINVAL;

	/* Transfer should start if it is the first in the pending list */
	if (transfer != session->pending->data)
		return 0;

	err = session_request(session, session_prepare_put, transfer);
	if (err < 0)
		goto fail;

	return 0;

fail:
	transfer_unregister(transfer);

	return err;
}

int session_pull(struct session_data *session,
				const char *type, const char *filename,
				session_callback_t function, void *user_data)
{
	struct transfer_data *transfer;
	int err;

	if (session->obex == NULL)
		return -ENOTCONN;

	transfer = transfer_register(session->conn, NULL, filename, type, NULL,
								session);
	if (transfer == NULL) {
		return -EIO;
	}

	if (function != NULL) {
		struct session_callback *callback;
		callback = g_new0(struct session_callback, 1);
		callback->func = function;
		callback->data = user_data;
		session->callback = callback;
	}

	err = session_request(session, session_prepare_get, transfer);
	if (err == 0)
		return 0;

	transfer_unregister(transfer);
	return err;
}

const char *session_register(struct session_data *session,
						GDBusDestroyFunction destroy)
{
	gboolean result = FALSE;

	if (session->path)
		return session->path;

	session->path = g_strdup_printf("%s/session%ju",
						SESSION_BASEPATH, counter++);

	if (g_dbus_register_interface(session->conn, session->path,
					SESSION_INTERFACE, session_methods,
					NULL, NULL, session, destroy) == FALSE)
		goto fail;

	switch (session->uuid.value.uuid16) {
	case OBEX_FILETRANS_SVCLASS_ID:
		result = ftp_register_interface(session->conn, session->path,
								session);
		break;
	case PBAP_PSE_SVCLASS_ID:
		result = pbap_register_interface(session->conn, session->path,
								session);
		break;
	case IRMC_SYNC_SVCLASS_ID:
		result = sync_register_interface(session->conn, session->path,
								session);
	}

	if (result == FALSE) {
		g_dbus_unregister_interface(session->conn,
					session->path, SESSION_INTERFACE);
		goto fail;
	}

	DBG("Session(%p) registered %s", session, session->path);

	return session->path;

fail:
	g_free(session->path);
	session->path = NULL;
	return NULL;
}

static void session_prepare_put(struct session_data *session,
				GError *err, void *data)
{
	struct transfer_data *transfer = data;
	int ret;

	ret = transfer_put(transfer, transfer_progress, session);
	if (ret < 0) {
		GError *gerr = NULL;

		g_set_error(&gerr, OBEX_IO_ERROR, ret, "%s (%d)",
							strerror(-ret), -ret);
		session_notify_error(session, transfer, gerr);
		g_clear_error(&gerr);
		return;
	}

	DBG("Transfer(%p) started", transfer);
}

int session_put(struct session_data *session, char *buf, const char *targetname)
{
	struct transfer_data *transfer;
	int err;

	if (session->obex == NULL)
		return -ENOTCONN;

	if (session->pending != NULL)
		return -EISCONN;

	transfer = transfer_register(session->conn, NULL, targetname, NULL,
								NULL, session);
	if (transfer == NULL)
		return -EIO;

	transfer_set_buffer(transfer, buf);

	err = session_request(session, session_prepare_put, transfer);
	if (err < 0)
		return err;

	return 0;
}

static void agent_destroy(gpointer data, gpointer user_data)
{
	struct session_data *session = user_data;

	session->agent = NULL;
}

int session_set_agent(struct session_data *session, const char *name,
							const char *path)
{
	struct agent_data *agent;

	if (session == NULL)
		return -EINVAL;

	if (session->agent)
		return -EALREADY;

	agent = agent_create(session->conn, name, path, agent_destroy,
								session);

	if (session->watch == 0)
		session_set_owner(session, name, owner_disconnected);

	session->agent = agent;

	return 0;
}

const char *session_get_agent(struct session_data *session)
{
	struct agent_data *agent;

	if (session == NULL)
		return NULL;

	agent = session->agent;
	if (agent == NULL)
		return NULL;

	return agent_get_name(session->agent);
}

const char *session_get_owner(struct session_data *session)
{
	if (session == NULL)
		return NULL;

	return session->owner;
}

const char *session_get_path(struct session_data *session)
{
	return session->path;
}

const char *session_get_target(struct session_data *session)
{
	return session->target;
}

GwObex *session_get_obex(struct session_data *session)
{
	return session->obex;
}

struct transfer_data *session_get_transfer(struct session_data *session)
{
	return session->pending ? session->pending->data : NULL;
}

void session_add_transfer(struct session_data *session,
					struct transfer_data *transfer)
{
	session->pending = g_slist_append(session->pending, transfer);
}

void session_remove_transfer(struct session_data *session,
					struct transfer_data *transfer)
{
	session->pending = g_slist_remove(session->pending, transfer);
}
