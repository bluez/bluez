/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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

static struct session_data *session_ref(struct session_data *session)
{
	g_atomic_int_inc(&session->refcount);

	return session;
}

static void session_unref(struct session_data *session)
{
	if (g_atomic_int_dec_and_test(&session->refcount) == FALSE)
		return;

	if (session->agent_watch)
		g_dbus_remove_watch(session->conn, session->agent_watch);

	if (session->agent_name != NULL) {
		DBusMessage *message;

		message = dbus_message_new_method_call(session->agent_name,
			session->agent_path, AGENT_INTERFACE, "Release");

		dbus_message_set_no_reply(message, TRUE);

		g_dbus_send_message(session->conn, message);
	}

	if (session->pending != NULL)
		g_ptr_array_free(session->pending, TRUE);

	if (session->obex != NULL) {
		if (session->xfer != NULL) {
			gw_obex_xfer_close(session->xfer, NULL);
			gw_obex_xfer_free(session->xfer);
		}

		gw_obex_close(session->obex);
	}

	if (session->sock > 2)
		close(session->sock);

	if (session->conn) {
		if (session->transfer_path)
			g_dbus_unregister_interface(session->conn,
					session->transfer_path, TRANSFER_INTERFACE);

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
	g_free(session->transfer_path);
	g_free(session->name);
	g_free(session->filename);
	g_free(session->agent_name);
	g_free(session->agent_path);
	g_free(session->owner);
	g_free(session->buffer);
	g_free(session);
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

	callback->session->pending = g_ptr_array_new();

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
		session_unref(session);
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
		session_unref(session);
		return -ENOMEM;
	}

	callback->session = session;
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
		session_unref(session);
		g_free(callback);
		return -EINVAL;
	}

	return 0;
}

static void agent_request(DBusConnection *conn, const char *agent_name,
			const char *agent_path, const char *transfer_path)
{
	DBusMessage *message;

	if (agent_name == NULL || agent_path == NULL || transfer_path == NULL)
		return;

	message = dbus_message_new_method_call(agent_name,
			agent_path, AGENT_INTERFACE, "Request");

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer_path,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(conn, message);

	/* FIXME: Reply needs be handled */
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

static void abort_transfer(struct session_data *session)
{

	agent_notify_error(session->conn, session->agent_name,
			session->agent_path, session->transfer_path,
			"The transfer was cancelled");

	gw_obex_xfer_abort(session->xfer, NULL);

	gw_obex_xfer_free(session->xfer);
	session->xfer = NULL;

	g_free(session->filename);
	session->filename = NULL;

	g_free(session->name);
	session->name = NULL;

	if (session->transfer_path) {
		g_dbus_unregister_interface(session->conn,
				session->transfer_path, TRANSFER_INTERFACE);
		g_free(session->transfer_path);
		session->transfer_path = NULL;
	}

	if (session->pending->len > 0) {
		gchar *filename;
		gchar *basename;
		filename = g_ptr_array_index(session->pending, 0);
		g_ptr_array_remove(session->pending, filename);

		basename = g_path_get_basename(filename);
		session_send(session, filename, basename);
		g_free(filename);
		g_free(basename);
	}

	session_unref(session);
}

int session_set_agent(struct session_data *session, const char *name,
							const char *path)
{
	if (session == NULL)
		return -EINVAL;

	if (session->agent_name != NULL || session->agent_path != NULL)
		return -EALREADY;

	session->agent_name = g_strdup(name);
	session->agent_path = g_strdup(path);

	return 0;
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
	struct session_data *session = user_data;
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

	append_entry(&dict, "Name", DBUS_TYPE_STRING, &session->name);
	append_entry(&dict, "Size", DBUS_TYPE_UINT64, &session->size);
	append_entry(&dict, "Filename", DBUS_TYPE_STRING, &session->filename);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *transfer_cancel(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct session_data *session = user_data;
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

	abort_transfer(session);

	return reply;
}

static GDBusMethodTable transfer_methods[] = {
	{ "GetProperties", "", "a{sv}", transfer_get_properties },
	{ "Cancel", "", "", transfer_cancel },
	{ }
};

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

static void session_shutdown(struct session_data *session)
{
	if (session->transfer_path) {
		agent_notify_error(session->conn, session->agent_name,
				session->agent_path, session->transfer_path,
				"The transfer was cancelled");

		g_dbus_unregister_interface(session->conn,
				session->transfer_path, TRANSFER_INTERFACE);
		g_free(session->transfer_path);

		session->transfer_path = NULL;
	}

	if (session->xfer) {
		gw_obex_xfer_abort(session->xfer, NULL);

		gw_obex_xfer_free(session->xfer);
		session->xfer = NULL;

		g_free(session->filename);
		session->filename = NULL;

		g_free(session->name);
		session->name = NULL;

		/* the transfer was holding a session ref */
		session_unref(session);
	}

	session_unref(session);
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

	g_dbus_remove_watch(session->conn, session->owner_watch);

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

static char *register_transfer(DBusConnection *conn, void *user_data)
{
	char *path;

	path = g_strdup_printf("%s/transfer%ju",
			TRANSFER_BASEPATH, counter++);

	if (g_dbus_register_interface(conn, path,
				TRANSFER_INTERFACE,
				transfer_methods, NULL, NULL,
				user_data, NULL) == FALSE) {
		g_free(path);
		return NULL;
	}

	return path;
}

static void unregister_transfer(struct session_data *session)
{
	gw_obex_xfer_close(session->xfer, NULL);
	gw_obex_xfer_free(session->xfer);
	session->xfer = NULL;

	g_free(session->filename);
	session->filename = NULL;

	g_free(session->name);
	session->name = NULL;

	g_free(session->buffer);
	session->buffer = NULL;

	session->buffer_len = 0;
	session->filled = 0;

	if (session->transfer_path == NULL)
		return;

	g_dbus_unregister_interface(session->conn,
			session->transfer_path, TRANSFER_INTERFACE);
	g_free(session->transfer_path);
	session->transfer_path = NULL;
}

static void list_folder_callback(struct session_data *session,
					void *user_data)
{
	GMarkupParseContext *ctxt;
	DBusMessage *reply;
	DBusMessageIter iter, array;
	int i;

	reply = dbus_message_new_method_return(session->msg);

	if (session->filled == 0)
		goto done;

	for (i = session->filled - 1; i > 0; i--) {
		if (session->buffer[i] != '\0')
			break;

		session->filled--;
	}

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &array);
	ctxt = g_markup_parse_context_new(&parser, 0, &array, NULL);
	g_markup_parse_context_parse(ctxt, session->buffer,
					session->filled, NULL);
	g_markup_parse_context_free(ctxt);
	dbus_message_iter_close_container(&iter, &array);

	session->filled = 0;

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
	struct callback_data *callback = user_data;
	struct session_data *session = callback->session;
	gint bsize, bread, err = 0;

	bsize = session->buffer_len - session->filled;

	if (bsize < DEFAULT_BUFFER_SIZE) {
		session->buffer_len += DEFAULT_BUFFER_SIZE;
		session->buffer = g_realloc(session->buffer, session->buffer_len);
		bsize += DEFAULT_BUFFER_SIZE;
	}

	gw_obex_xfer_read(xfer, session->buffer + session->filled,
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
		fprintf(stderr, "gw_obex_xfer_read(): %s\n",
				OBEX_ResponseToString(err));
		goto complete;
	}

	session->filled += bread;

	if (gw_obex_xfer_object_done(xfer)) {
		if (session->buffer[session->filled - 1] == '\0')
			goto complete;

		bsize = session->buffer_len - session->filled;
		if (bsize < 1) {
			session->buffer_len += DEFAULT_BUFFER_SIZE;
			session->buffer = g_realloc(session->buffer, session->buffer_len);
		}

		session->buffer[session->filled] = '\0';
		goto complete;
	}

	return;

complete:
	if (err == 0) {
		agent_notify_progress(session->conn, session->agent_name,
				session->agent_path, session->transfer_path,
				session->filled);
		agent_notify_complete(session->conn, session->agent_name,
				session->agent_path, session->transfer_path);
	}

	callback->func(callback->session, callback->data);

	unregister_transfer(session);

	session_unref(callback->session);

	g_free(callback);
}

static void get_xfer_progress(GwObexXfer *xfer, gpointer user_data)
{
	struct callback_data *callback = user_data;
	struct session_data *session = callback->session;
	gint bsize, bread, err = 0;
	gboolean ret;

	if (session->buffer_len == 0) {
		session->buffer_len = DEFAULT_BUFFER_SIZE;
		session->buffer = g_new0(char, DEFAULT_BUFFER_SIZE);
	}

	bsize = session->buffer_len - session->filled;

	ret = gw_obex_xfer_read(xfer, session->buffer + session->filled,
					bsize, &bread, &err);

	/* For GetFile reply on the first received stream */
	if (session->fd > 0 && session->msg) {
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
		fprintf(stderr, "gw_obex_xfer_read(): %s\n",
				OBEX_ResponseToString(err));
		goto complete;
	}

	session->filled += bread;
	session->transferred += bread;
	if (session->size == 0)
		session->size = gw_obex_xfer_object_size(xfer);

	if (session->fd > 0) {
		gint w;

		w = write(session->fd, session->buffer, bread);
		if (w < 0) {
			ret = FALSE;
			goto complete;
		}

		session->filled = 0;
	}

	if (session->transferred == session->size)
		goto complete;

	gw_obex_xfer_flush(xfer, NULL);

	agent_notify_progress(session->conn, session->agent_name,
			session->agent_path, session->transfer_path,
			session->transferred);

	return;

complete:

	if (ret == TRUE) {
		agent_notify_progress(session->conn, session->agent_name,
				session->agent_path, session->transfer_path,
				session->transferred);
		agent_notify_complete(session->conn, session->agent_name,
				session->agent_path, session->transfer_path);
	} else
		agent_notify_error(session->conn, session->agent_name,
				session->agent_path, session->transfer_path,
				"Error getting object");

	callback->func(callback->session, callback->data);

	unregister_transfer(session);

	if (session->fd > 0)
		close(session->fd);

	session_unref(callback->session);

	g_free(callback);
}

int session_get(struct session_data *session, const char *type,
		const char *filename, const char *targetname,
		const guint8  *apparam, gint apparam_size,
		session_callback_t func)
{
	struct callback_data *callback;
	GwObexXfer *xfer;
	int err, fd = 0;

	if (session->obex == NULL)
		return -ENOTCONN;

	if (type == NULL) {
		if (targetname == NULL)
			targetname = filename;

		fd = open(targetname, O_WRONLY | O_CREAT, 0600);
		if (fd < 0) {
			err = errno;
			fprintf(stderr, "open(): %s(%d)\n", strerror(err), err);
			return -err;
		}
	}

	if (type == NULL || !g_str_equal(type, "x-obex/folder-listing")) {
		session->transfer_path = register_transfer(session->conn, session);
		if (session->transfer_path == NULL) {
			if (fd)
				close(fd);

			return -EIO;
		}
	}

	session->fd = fd;
	session->transferred = 0;
	session->size = 0;
	session->filename = g_strdup(filename);
	session->name = g_strdup(targetname);

	session_ref(session);

	xfer = gw_obex_get_async_with_apparam(session->obex,
				filename, type, apparam, apparam_size, NULL);
	if (xfer == NULL) {
		close(session->fd);
		session_unref(session);
		return -EIO;
	}

	callback = g_try_malloc0(sizeof(*callback));
	if (callback == NULL) {
		close(session->fd);
		session_unref(session);
		gw_obex_xfer_free(xfer);
		return -ENOMEM;
	}

	callback->session = session;
	callback->func = func;

	if (type == NULL)
		gw_obex_xfer_set_callback(xfer, get_xfer_progress, callback);
	else
		gw_obex_xfer_set_callback(xfer, get_xfer_listing_progress,
					callback);

	session->xfer = xfer;

	agent_request(session->conn, session->agent_name,
			session->agent_path, session->transfer_path);

	agent_notify_progress(session->conn, session->agent_name,
			session->agent_path, session->transfer_path, 0);

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
	session->filled = 0;

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
	session->filled = 0;

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

static void put_xfer_progress(GwObexXfer *xfer, gpointer user_data)
{
	struct session_data *session = user_data;
	ssize_t len;
	gint written;

	if (session->buffer_len == 0) {
		session->buffer_len = DEFAULT_BUFFER_SIZE;
		session->buffer = g_new0(char, DEFAULT_BUFFER_SIZE);
	}

	len = read(session->fd, session->buffer + session->filled,
				session->buffer_len - session->filled);
	if (len <= 0)
		goto complete;

	if (gw_obex_xfer_write(xfer, session->buffer, session->filled + len,
						&written, NULL) == FALSE)
		goto complete;

	if (gw_obex_xfer_flush(xfer, NULL) == FALSE)
		goto complete;

	session->filled = (session->filled + len) - written;

	memmove(session->buffer + written, session->buffer, session->filled);

	session->transferred += written;

	agent_notify_progress(session->conn, session->agent_name,
			session->agent_path, session->transfer_path,
			session->transferred);
	return;

complete:
	if (len == 0)
		agent_notify_complete(session->conn, session->agent_name,
				session->agent_path, session->transfer_path);
	else
		agent_notify_error(session->conn, session->agent_name,
				session->agent_path, session->transfer_path,
				"Error sending object");

	unregister_transfer(session);

	if (session->pending->len > 0) {
		gchar *filename = g_ptr_array_index(session->pending, 0);
		gchar *basename = g_path_get_basename(filename);

		g_ptr_array_remove(session->pending, filename);

		session_send(session, filename, basename);
		g_free(filename);
		g_free(basename);
	}

	session_unref(session);
}

int session_send(struct session_data *session, const char *filename,
				const char *targetname)
{
	GwObexXfer *xfer;
	struct stat st;
	int fd;

	if (session->obex == NULL)
		return -ENOTCONN;

	if (session->xfer != NULL) {
		g_ptr_array_add(session->pending, g_strdup(filename));
		return 0;
	}

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return -EIO;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return -EIO;
	}

	session->transfer_path = register_transfer(session->conn, session);
	if (session->transfer_path == NULL) {
		close(fd);
		return -EIO;
	}

	session->fd = fd;
	session->size = st.st_size;
	session->transferred = 0;
	session->filename = g_strdup(filename);
	session->name = g_strdup(targetname);

	session_ref(session);

	xfer = gw_obex_put_async(session->obex, session->name, NULL,
						session->size, -1, NULL);
	if (xfer == NULL)
		return -ENOTCONN;

	gw_obex_xfer_set_callback(xfer, put_xfer_progress, session);

	session->xfer = xfer;

	agent_request(session->conn, session->agent_name,
			session->agent_path, session->transfer_path);

	agent_notify_progress(session->conn, session->agent_name,
			session->agent_path, session->transfer_path, 0);

	return 0;
}

int session_pull(struct session_data *session,
				const char *type, const char *filename,
				session_callback_t function, void *user_data)
{
	struct callback_data *callback;
	GwObexXfer *xfer;

	if (session->obex == NULL)
		return -ENOTCONN;

	session_ref(session);

	callback = g_try_malloc0(sizeof(*callback));
	if (callback == NULL) {
		session_unref(session);
		return -ENOMEM;
	}

	callback->session = session;
	callback->func = function;
	callback->data = user_data;

	xfer = gw_obex_get_async(session->obex, NULL, type, NULL);
	if (xfer == NULL)
		return -ENOTCONN;

	gw_obex_xfer_set_callback(xfer, get_xfer_listing_progress, callback);

	session->xfer = xfer;

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

	session_ref(session);

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
	struct session_data *session = user_data;
	gint written;

	if (session->transferred == session->size)
		goto complete;

	if (gw_obex_xfer_write(xfer, session->buffer + session->transferred,
				session->size - session->transferred,
				&written, NULL) == FALSE)
		goto complete;

	if (gw_obex_xfer_flush(xfer, NULL) == FALSE)
		goto complete;

	session->transferred += written;

	agent_notify_progress(session->conn, session->agent_name,
		session->agent_path, session->transfer_path,
		session->transferred);

	return;

complete:
	if (session->transferred == session->size)
		agent_notify_complete(session->conn, session->agent_name,
			session->agent_path, session->transfer_path);
	else
		agent_notify_error(session->conn, session->agent_name,
			session->agent_path, session->transfer_path,
			"Error sending object");

	unregister_transfer(session);
	session_unref(session);
}

int session_put(struct session_data *session, char *buf, const char *targetname)
{
	GwObexXfer *xfer;

	if (session->obex == NULL)
		return -ENOTCONN;

	session->transfer_path = register_transfer(session->conn, session);
	if (session->transfer_path == NULL)
		return -EIO;

	session->size = strlen(buf);
	session->transferred = 0;
	session->name = g_strdup(targetname);
	session->buffer = buf;

	xfer = gw_obex_put_async(session->obex, session->name, NULL,
						session->size, -1, NULL);
	if (xfer == NULL)
		return -ENOTCONN;

	session_ref(session);

	gw_obex_xfer_set_callback(xfer, put_buf_xfer_progress, session);

	session->xfer = xfer;

	agent_request(session->conn, session->agent_name,
		session->agent_path, session->transfer_path);

	agent_notify_progress(session->conn, session->agent_name,
		session->agent_path, session->transfer_path, 0);

	return 0;
}
