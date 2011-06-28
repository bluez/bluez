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
#include "transfer.h"
#include "session.h"
#include "btio.h"

#define AGENT_INTERFACE  "org.openobex.Agent"

#define SESSION_INTERFACE  "org.openobex.Session"
#define SESSION_BASEPATH   "/org/openobex"

#define FTP_INTERFACE  "org.openobex.FileTransfer"

#define OBEX_IO_ERROR obex_io_error_quark()

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
	DBusPendingCall *call;
	session_callback_t cb;
	struct transfer_data *transfer;
};

struct agent_data {
	char *name;
	char *path;
	guint watch;
	struct pending_data *pending;
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

static void free_pending(struct pending_data *pending)
{
	if (pending->call)
		dbus_pending_call_unref(pending->call);

	g_free(pending);
}

static void agent_free(struct session_data *session)
{
	struct agent_data *agent = session->agent;

	if (agent->watch)
		g_dbus_remove_watch(session->conn, agent->watch);

	if (agent->pending) {
		dbus_pending_call_cancel(agent->pending->call);
		free_pending(agent->pending);
	}

	session->agent = NULL;

	g_free(agent->name);
	g_free(agent->path);
	g_free(agent);
}

static void agent_release(struct session_data *session)
{
	struct agent_data *agent = session->agent;
	DBusMessage *message;

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Release");

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(session->conn, message);

	agent_free(session);
}

static void session_unregistered(struct session_data *session)
{
	switch (session->uuid.value.uuid16) {
	case OBEX_FILETRANS_SVCLASS_ID:
		g_dbus_unregister_interface(session->conn, session->path,
						FTP_INTERFACE);
		break;
	case PBAP_PSE_SVCLASS_ID:
		pbap_unregister_interface(session->conn, session->path,
						session);
		break;
	case IRMC_SYNC_SVCLASS_ID:
		sync_unregister_interface(session->conn, session->path,
						session);
	}

	g_dbus_unregister_interface(session->conn, session->path,
					SESSION_INTERFACE);

	DBG("Session(%p) unregistered %s", session, session->path);

	g_free(session->path);
	session->path = NULL;
}

static void session_free(struct session_data *session)
{
	DBG("%p", session);

	if (session->agent)
		agent_release(session);

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

	g_free(session->callback);
	g_free(session->path);
	g_free(session->service);
	g_free(session->owner);
	g_free(session);
}

void session_unref(struct session_data *session)
{
	gboolean ret;

	ret = g_atomic_int_dec_and_test(&session->refcount);

	DBG("%p: ref=%d", session, session->refcount);

	if (ret == FALSE)
		return;

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
	int err;

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

	if (err < 0) {
		session_unref(session);
		g_free(callback);
		return NULL;
	}

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

static void agent_disconnected(DBusConnection *connection, void *user_data)
{
	struct session_data *session = user_data;

	session->agent->watch = 0;

	agent_free(session);
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

	if (agent == NULL || g_str_equal(sender, agent->name) == FALSE ||
				g_str_equal(path, agent->path) == FALSE)
		return g_dbus_create_error(message,
				"org.openobex.Error.NotAuthorized",
				"Not Authorized");

	agent_free(session);

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
					GError *err, void *user_data)
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

static void get_file_callback(struct session_data *session, GError *err,
							void *user_data)
{

}

static void session_request_reply(DBusPendingCall *call, gpointer user_data)
{
	struct session_data *session = user_data;
	struct agent_data *agent = session->agent;
	struct pending_data *pending = agent->pending;
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

	if (strlen(name)) {
		g_free(pending->transfer->name);
		pending->transfer->name = g_strdup(name);
	}

	agent->pending = NULL;

	pending->cb(session, NULL, pending->transfer);
	dbus_message_unref(reply);
	free_pending(pending);

	return;
}

static gboolean session_request_proceed(gpointer data)
{
	struct pending_data *pending = data;
	struct transfer_data *transfer = pending->transfer;

	pending->cb(transfer->session, NULL, transfer);
	free_pending(pending);

	return FALSE;
}

static int session_request(struct session_data *session, session_callback_t cb,
				struct transfer_data *transfer)
{
	struct agent_data *agent = session->agent;
	DBusMessage *message;
	struct pending_data *pending;

	pending = g_new0(struct pending_data, 1);
	pending->cb = cb;
	pending->transfer = transfer;

	if (agent == NULL || transfer->path == NULL) {
		g_idle_add(session_request_proceed, pending);
		return 0;
	}

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Request");

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer->path,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(session->conn, message,
						&pending->call, -1)) {
		dbus_message_unref(message);
		return -ENOMEM;
	}

	agent->pending = pending;

	dbus_message_unref(message);

	dbus_pending_call_set_notify(pending->call, session_request_reply,
					session, NULL);

	DBG("Agent.Request(\"%s\")", transfer->path);

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
	DBusMessage *message;

	if (agent == NULL || transfer->path == NULL)
		goto done;

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Complete");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer->path,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(session->conn, message);

done:

	DBG("Transfer(%p) complete", transfer);

	session_terminate_transfer(session, transfer, NULL);
}

static void session_notify_error(struct session_data *session,
				struct transfer_data *transfer,
				GError *err)
{
	struct agent_data *agent = session->agent;
	DBusMessage *message;

	if (session->msg) {
		DBusMessage *reply;

		reply = g_dbus_create_error(session->msg,
					"org.openobex.Error.Failed",
					"%s", err->message);
		g_dbus_send_message(session->conn, reply);

		dbus_message_unref(session->msg);
		session->msg = NULL;
	}

	if (agent == NULL || transfer->path == NULL)
		goto done;

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Error");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer->path,
			DBUS_TYPE_STRING, &err->message,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(session->conn, message);

done:
	error("Transfer(%p) Error: %s", transfer, err->message);

	session_terminate_transfer(session, transfer, err);
}

static void session_notify_progress(struct session_data *session,
					struct transfer_data *transfer,
					gint64 transferred)
{
	struct agent_data *agent = session->agent;
	DBusMessage *message;

	/* For GetFile reply on the first received stream */
	if (transfer->fd > 0 && session->msg) {
		DBusMessage *reply;

		reply = dbus_message_new_method_return(session->msg);
		g_dbus_send_message(session->conn, reply);

		dbus_message_unref(session->msg);
		session->msg = NULL;
	}

	if (agent == NULL || transfer->path == NULL)
		goto done;

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Progress");
	if (message == NULL)
		goto done;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &transfer->path,
			DBUS_TYPE_UINT64, &transferred,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(session->conn, message);

done:
	DBG("Transfer(%p) progress: %ld bytes", transfer,
			(long int ) transferred);

	if (transferred == transfer->size)
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
		session_callback_t func)
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

	transfer = transfer_register(session, filename, targetname, type,
					params);
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
		session->callback = callback;
	}

	err = session_request(session, session_prepare_get, transfer);
	if (err < 0)
		return err;

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
				"%s", OBEX_ResponseToString(err));
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
				"%s", OBEX_ResponseToString(err));

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
				"%s", OBEX_ResponseToString(err));
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
	int err;

	if (session->obex == NULL)
		return -ENOTCONN;

	transfer = transfer_register(session, filename, targetname, NULL,
					NULL);
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

	transfer = transfer_register(session, NULL, filename, type, NULL);
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

	DBG("Session(%p) registered %s", session, session->path);

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

	transfer = transfer_register(session, NULL, targetname, NULL, NULL);
	if (transfer == NULL)
		return -EIO;

	transfer->size = strlen(buf);
	transfer->buffer = buf;

	err = session_request(session, session_prepare_put, transfer);
	if (err < 0)
		return err;

	return 0;
}

int session_set_agent(struct session_data *session, const char *name,
							const char *path)
{
	struct agent_data *agent;

	if (session == NULL)
		return -EINVAL;

	if (session->agent)
		return -EALREADY;

	agent = g_new0(struct agent_data, 1);
	agent->name = g_strdup(name);
	agent->path = g_strdup(path);

	if (session->watch == 0)
		session_set_owner(session, name, owner_disconnected);

	agent->watch = g_dbus_add_disconnect_watch(session->conn, name,
							agent_disconnected,
							session, NULL);

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

	return agent->name;
}

const char *session_get_owner(struct session_data *session)
{
	if (session == NULL)
		return NULL;

	return session->owner;
}
