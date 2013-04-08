/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2011-2012  BMW Car IT GmbH. All rights reserved.
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <glib.h>
#include <gdbus/gdbus.h>
#include <gobex/gobex.h>

#include "dbus.h"
#include "log.h"
#include "transfer.h"
#include "session.h"
#include "driver.h"
#include "transport.h"

#define SESSION_INTERFACE "org.bluez.obex.Session1"
#define ERROR_INTERFACE "org.bluez.obex.Error"
#define SESSION_BASEPATH "/org/bluez/obex"

#define OBEX_IO_ERROR obex_io_error_quark()
#define OBEX_IO_ERROR_FIRST (0xff + 1)

enum {
	OBEX_IO_DISCONNECTED = OBEX_IO_ERROR_FIRST,
	OBEX_IO_BUSY,
};

static guint64 counter = 0;

struct callback_data {
	struct obc_session *session;
	session_callback_t func;
	void *data;
};

struct pending_request {
	guint id;
	guint req_id;
	struct obc_session *session;
	struct obc_transfer *transfer;
	session_callback_t func;
	void *data;
};

struct setpath_data {
	char **remaining;
	int index;
	session_callback_t func;
	void *user_data;
};

struct obc_session {
	guint id;
	gint refcount;
	char *source;
	char *destination;
	uint8_t channel;
	struct obc_transport *transport;
	struct obc_driver *driver;
	char *path;		/* Session path */
	DBusConnection *conn;
	GObex *obex;
	struct pending_request *p;
	char *owner;		/* Session owner */
	guint watch;
	GQueue *queue;
	guint queue_complete_id;
};

static GSList *sessions = NULL;

static void session_process_queue(struct obc_session *session);
static void session_terminate_transfer(struct obc_session *session,
					struct obc_transfer *transfer,
					GError *gerr);
static void transfer_complete(struct obc_transfer *transfer,
					GError *err, void *user_data);

static GQuark obex_io_error_quark(void)
{
	return g_quark_from_static_string("obex-io-error-quark");
}

struct obc_session *obc_session_ref(struct obc_session *session)
{
	int refs = __sync_add_and_fetch(&session->refcount, 1);

	DBG("%p: ref=%d", session, refs);

	return session;
}

static void session_unregistered(struct obc_session *session)
{
	char *path;

	if (session->driver && session->driver->remove)
		session->driver->remove(session);

	path = session->path;
	session->path = NULL;

	g_dbus_unregister_interface(session->conn, path, SESSION_INTERFACE);

	DBG("Session(%p) unregistered %s", session, path);

	g_free(path);
}

static struct pending_request *pending_request_new(struct obc_session *session,
						struct obc_transfer *transfer,
						session_callback_t func,
						void *data)
{
	struct pending_request *p;
	static guint id = 0;

	p = g_new0(struct pending_request, 1);
	p->id = ++id;
	p->session = obc_session_ref(session);
	p->transfer = transfer;
	p->func = func;
	p->data = data;

	return p;
}

static void pending_request_free(struct pending_request *p)
{
	if (p->transfer)
		obc_transfer_unregister(p->transfer);

	if (p->session)
		obc_session_unref(p->session);

	g_free(p);
}

static void session_free(struct obc_session *session)
{
	DBG("%p", session);

	if (session->queue_complete_id != 0)
		g_source_remove(session->queue_complete_id);

	if (session->queue) {
		g_queue_foreach(session->queue, (GFunc) pending_request_free,
									NULL);
		g_queue_free(session->queue);
	}

	if (session->watch)
		g_dbus_remove_watch(session->conn, session->watch);

	if (session->obex != NULL)
		g_obex_unref(session->obex);

	if (session->id > 0 && session->transport != NULL)
		session->transport->disconnect(session->id);

	if (session->path)
		session_unregistered(session);

	if (session->conn)
		dbus_connection_unref(session->conn);

	if (session->p)
		pending_request_free(session->p);

	sessions = g_slist_remove(sessions, session);

	g_free(session->path);
	g_free(session->owner);
	g_free(session->source);
	g_free(session->destination);
	g_free(session);
}

void obc_session_unref(struct obc_session *session)
{
	int refs;

	refs = __sync_sub_and_fetch(&session->refcount, 1);

	DBG("%p: ref=%d", session, refs);

	if (refs > 0)
		return;

	session_free(session);
}

static void connect_cb(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct callback_data *callback = user_data;
	GError *gerr = NULL;
	uint8_t rsp_code;

	if (err != NULL) {
		error("connect_cb: %s", err->message);
		gerr = g_error_copy(err);
		goto done;
	}

	rsp_code = g_obex_packet_get_operation(rsp, NULL);
	if (rsp_code != G_OBEX_RSP_SUCCESS)
		gerr = g_error_new(OBEX_IO_ERROR, -EIO,
				"OBEX Connect failed with 0x%02x", rsp_code);

done:
	callback->func(callback->session, NULL, gerr, callback->data);
	if (gerr != NULL)
		g_error_free(gerr);
	obc_session_unref(callback->session);
	g_free(callback);
}

static void transport_func(GIOChannel *io, GError *err, gpointer user_data)
{
	struct callback_data *callback = user_data;
	struct obc_session *session = callback->session;
	struct obc_driver *driver = session->driver;
	struct obc_transport *transport = session->transport;
	GObex *obex;
	GObexTransportType type;
	int tx_mtu = -1;
	int rx_mtu = -1;

	DBG("");

	if (err != NULL) {
		error("%s", err->message);
		goto done;
	}

	g_io_channel_set_close_on_unref(io, FALSE);

	if (transport->getpacketopt &&
			transport->getpacketopt(io, &tx_mtu, &rx_mtu) == 0)
		type = G_OBEX_TRANSPORT_PACKET;
	else
		type = G_OBEX_TRANSPORT_STREAM;

	obex = g_obex_new(io, type, tx_mtu, rx_mtu);
	if (obex == NULL)
		goto done;

	g_io_channel_set_close_on_unref(io, TRUE);

	if (driver->target != NULL)
		g_obex_connect(obex, connect_cb, callback, &err,
			G_OBEX_HDR_TARGET, driver->target, driver->target_len,
			G_OBEX_HDR_INVALID);
	else
		g_obex_connect(obex, connect_cb, callback, &err,
							G_OBEX_HDR_INVALID);

	if (err != NULL) {
		error("%s", err->message);
		g_obex_unref(obex);
		goto done;
	}

	session->obex = obex;
	sessions = g_slist_prepend(sessions, session);

	return;
done:
	callback->func(callback->session, NULL, err, callback->data);
	obc_session_unref(callback->session);
	g_free(callback);
}

static void owner_disconnected(DBusConnection *connection, void *user_data)
{
	struct obc_session *session = user_data;

	DBG("");

	obc_session_shutdown(session);
}

int obc_session_set_owner(struct obc_session *session, const char *name,
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


static struct obc_session *session_find(const char *source,
						const char *destination,
						const char *service,
						uint8_t channel,
						const char *owner)
{
	GSList *l;

	for (l = sessions; l; l = l->next) {
		struct obc_session *session = l->data;

		if (g_strcmp0(session->destination, destination))
			continue;

		if (g_strcmp0(service, session->driver->service))
			continue;

		if (source && g_strcmp0(session->source, source))
			continue;

		if (channel && session->channel != channel)
			continue;

		if (g_strcmp0(owner, session->owner))
			continue;

		return session;
	}

	return NULL;
}

static gboolean connection_complete(gpointer data)
{
	struct callback_data *cb = data;

	cb->func(cb->session, NULL, NULL, cb->data);

	obc_session_unref(cb->session);

	g_free(cb);

	return FALSE;
}

static int session_connect(struct obc_session *session,
				session_callback_t function, void *user_data)
{
	struct callback_data *callback;
	struct obc_transport *transport = session->transport;
	struct obc_driver *driver = session->driver;

	callback = g_try_malloc0(sizeof(*callback));
	if (callback == NULL)
		return -ENOMEM;

	callback->func = function;
	callback->data = user_data;
	callback->session = obc_session_ref(session);

	/* Connection completed */
	if (session->obex) {
		g_idle_add(connection_complete, callback);
		return 0;
	}

	/* Ongoing connection */
	if (session->id > 0) {
		obc_session_unref(callback->session);
		g_free(callback);
		return 0;
	}

	session->id = transport->connect(session->source, session->destination,
					driver->uuid, session->channel,
					transport_func, callback);
	if (session->id == 0) {
		obc_session_unref(callback->session);
		g_free(callback);
		return -EINVAL;
	}

	return 0;
}

struct obc_session *obc_session_create(const char *source,
						const char *destination,
						const char *service,
						uint8_t channel,
						const char *owner,
						session_callback_t function,
						void *user_data)
{
	DBusConnection *conn;
	struct obc_session *session;
	struct obc_transport *transport;
	struct obc_driver *driver;

	if (destination == NULL)
		return NULL;

	session = session_find(source, destination, service, channel, owner);
	if (session != NULL)
		goto proceed;

	/* FIXME: Do proper transport lookup when the API supports it */
	transport = obc_transport_find("Bluetooth");
	if (transport == NULL)
		return NULL;

	driver = obc_driver_find(service);
	if (driver == NULL)
		return NULL;

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (conn == NULL)
		return NULL;

	session = g_try_malloc0(sizeof(*session));
	if (session == NULL)
		return NULL;

	session->refcount = 1;
	session->transport = transport;
	session->driver = driver;
	session->conn = conn;
	session->source = g_strdup(source);
	session->destination = g_strdup(destination);
	session->channel = channel;
	session->queue = g_queue_new();

	if (owner)
		obc_session_set_owner(session, owner, owner_disconnected);

proceed:
	if (session_connect(session, function, user_data) < 0) {
		obc_session_unref(session);
		return NULL;
	}

	DBG("session %p transport %s driver %s", session,
			session->transport->name, session->driver->service);

	return session;
}

void obc_session_shutdown(struct obc_session *session)
{
	struct pending_request *p;
	GError *err;

	DBG("%p", session);

	obc_session_ref(session);

	/* Unregister any pending transfer */
	err = g_error_new(OBEX_IO_ERROR, OBEX_IO_DISCONNECTED,
						"Session closed by user");

	if (session->p != NULL && session->p->id != 0) {
		p = session->p;
		session->p = NULL;

		if (p->func)
			p->func(session, p->transfer, err, p->data);

		pending_request_free(p);
	}

	while ((p = g_queue_pop_head(session->queue))) {
		if (p->func)
			p->func(session, p->transfer, err, p->data);

		pending_request_free(p);
	}

	g_error_free(err);

	/* Unregister interfaces */
	if (session->path)
		session_unregistered(session);

	/* Disconnect transport */
	if (session->id > 0 && session->transport != NULL) {
		session->transport->disconnect(session->id);
		session->id = 0;
	}

	obc_session_unref(session);
}

static void capabilities_complete_callback(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	DBusMessage *message = user_data;
	char *contents;
	size_t size;
	int perr;

	if (err != NULL) {
		DBusMessage *error = g_dbus_create_error(message,
					ERROR_INTERFACE ".Failed",
					"%s", err->message);
		g_dbus_send_message(session->conn, error);
		goto done;
	}

	perr = obc_transfer_get_contents(transfer, &contents, &size);
	if (perr < 0) {
		DBusMessage *error = g_dbus_create_error(message,
						ERROR_INTERFACE ".Failed",
						"Error reading contents: %s",
						strerror(-perr));
		g_dbus_send_message(session->conn, error);
		goto done;
	}

	g_dbus_send_reply(session->conn, message,
						DBUS_TYPE_STRING, &contents,
						DBUS_TYPE_INVALID);
	g_free(contents);

done:
	dbus_message_unref(message);
}

static DBusMessage *get_capabilities(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct obc_session *session = user_data;
	struct obc_transfer *pull;
	DBusMessage *reply;
	GError *gerr = NULL;

	pull = obc_transfer_get("x-obex/capability", NULL, NULL, &gerr);
	if (pull == NULL)
		goto fail;

	if (!obc_session_queue(session, pull, capabilities_complete_callback,
								message, &gerr))
		goto fail;

	dbus_message_ref(message);

	return NULL;

fail:
	reply = g_dbus_create_error(message, ERROR_INTERFACE ".Failed", "%s",
								gerr->message);
	g_error_free(gerr);
	return reply;

}

static gboolean get_source(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct obc_session *session = data;

	if (session->source == NULL)
		return FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
							&session->source);

	return TRUE;
}

static gboolean source_exists(const GDBusPropertyTable *property, void *data)
{
	struct obc_session *session = data;

	return session->source != NULL;
}

static gboolean get_destination(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct obc_session *session = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
							&session->destination);

	return TRUE;
}

static gboolean get_channel(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct obc_session *session = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE,
							&session->channel);

	return TRUE;
}

static const GDBusMethodTable session_methods[] = {
	{ GDBUS_ASYNC_METHOD("GetCapabilities",
				NULL, GDBUS_ARGS({ "capabilities", "s" }),
				get_capabilities) },
	{ }
};

static const GDBusPropertyTable session_properties[] = {
	{ "Source", "s", get_source, NULL, source_exists },
	{ "Destination", "s", get_destination },
	{ "Channel", "y", get_channel },
	{ }
};

static gboolean session_queue_complete(gpointer data)
{
	struct obc_session *session = data;

	session_process_queue(session);

	session->queue_complete_id = 0;

	return FALSE;
}

guint obc_session_queue(struct obc_session *session,
				struct obc_transfer *transfer,
				session_callback_t func, void *user_data,
				GError **err)
{
	struct pending_request *p;

	if (session->obex == NULL) {
		obc_transfer_unregister(transfer);
		g_set_error(err, OBEX_IO_ERROR, -ENOTCONN,
						"Session not connected");
		return 0;
	}

	if (!obc_transfer_register(transfer, session->conn, session->path,
							session->owner, err)) {
		obc_transfer_unregister(transfer);
		return 0;
	}

	obc_transfer_set_callback(transfer, transfer_complete, session);

	p = pending_request_new(session, transfer, func, user_data);
	g_queue_push_tail(session->queue, p);

	if (session->queue_complete_id == 0)
		session->queue_complete_id = g_idle_add(
					session_queue_complete, session);

	return p->id;
}

static void session_process_queue(struct obc_session *session)
{
	struct pending_request *p;

	if (session->p != NULL)
		return;

	if (session->queue == NULL || g_queue_is_empty(session->queue))
		return;

	obc_session_ref(session);

	while ((p = g_queue_pop_head(session->queue))) {
		GError *gerr = NULL;

		DBG("Transfer(%p) started", p->transfer);

		if (obc_transfer_start(p->transfer, session->obex, &gerr)) {
			session->p = p;
			break;
		}

		if (p->func)
			p->func(session, p->transfer, gerr, p->data);

		g_clear_error(&gerr);

		pending_request_free(p);
	}

	obc_session_unref(session);
}

static gint pending_transfer_cmptransfer(gconstpointer a, gconstpointer b)
{
	const struct pending_request *p = a;
	const struct obc_transfer *transfer = b;

	if (p->transfer == transfer)
		return 0;

	return -1;
}

static void session_terminate_transfer(struct obc_session *session,
					struct obc_transfer *transfer,
					GError *gerr)
{
	struct pending_request *p = session->p;

	if (p == NULL || p->transfer != transfer) {
		GList *match;

		match = g_list_find_custom(session->queue->head, transfer,
						pending_transfer_cmptransfer);
		if (match == NULL)
			return;

		p = match->data;
		g_queue_delete_link(session->queue, match);
	} else
		session->p = NULL;

	obc_session_ref(session);

	if (p->func)
		p->func(session, p->transfer, gerr, p->data);

	pending_request_free(p);

	if (session->p == NULL)
		session_process_queue(session);

	obc_session_unref(session);
}

static void session_notify_complete(struct obc_session *session,
				struct obc_transfer *transfer)
{
	DBG("Transfer(%p) complete", transfer);

	session_terminate_transfer(session, transfer, NULL);
}

static void session_notify_error(struct obc_session *session,
				struct obc_transfer *transfer,
				GError *err)
{
	error("Transfer(%p) Error: %s", transfer, err->message);

	session_terminate_transfer(session, transfer, err);
}

static void transfer_complete(struct obc_transfer *transfer,
					GError *err, void *user_data)
{
	struct obc_session *session = user_data;

	if (err != 0)
		goto fail;

	session_notify_complete(session, transfer);

	return;

fail:
	session_notify_error(session, transfer, err);
}

const char *obc_session_register(struct obc_session *session,
						GDBusDestroyFunction destroy)
{
	if (session->path)
		return session->path;

	session->path = g_strdup_printf("%s/session%ju",
						SESSION_BASEPATH, counter++);

	if (g_dbus_register_interface(session->conn, session->path,
					SESSION_INTERFACE, session_methods,
					NULL, NULL, session, destroy) == FALSE)
		goto fail;

	if (session->driver->probe && session->driver->probe(session) < 0) {
		g_dbus_unregister_interface(session->conn, session->path,
							SESSION_INTERFACE);
		goto fail;
	}

	DBG("Session(%p) registered %s", session, session->path);

	return session->path;

fail:
	g_free(session->path);
	session->path = NULL;
	return NULL;
}

const char *obc_session_get_owner(struct obc_session *session)
{
	if (session == NULL)
		return NULL;

	return session->owner;
}

const char *obc_session_get_path(struct obc_session *session)
{
	return session->path;
}

const char *obc_session_get_target(struct obc_session *session)
{
	return session->driver->target;
}

static void setpath_complete(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	struct pending_request *p = user_data;
	struct setpath_data *data = p->data;

	if (data->func)
		data->func(session, NULL, err, data->user_data);

	g_strfreev(data->remaining);
	g_free(data);

	if (session->p == p)
		session->p = NULL;

	pending_request_free(p);

	session_process_queue(session);
}

static void setpath_cb(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct pending_request *p = user_data;
	struct setpath_data *data = p->data;
	char *next;
	guint8 code;

	p->req_id = 0;

	if (err != NULL) {
		setpath_complete(p->session, NULL, err, user_data);
		return;
	}

	code = g_obex_packet_get_operation(rsp, NULL);
	if (code != G_OBEX_RSP_SUCCESS) {
		GError *gerr = NULL;
		g_set_error(&gerr, OBEX_IO_ERROR, code, "%s",
							g_obex_strerror(code));
		setpath_complete(p->session, NULL, err, user_data);
		g_clear_error(&gerr);
		return;
	}

	/* Ignore empty folder names to avoid resetting the current path */
	while ((next = data->remaining[data->index]) && strlen(next) == 0)
		data->index++;

	if (next == NULL) {
		setpath_complete(p->session, NULL, NULL, user_data);
		return;
	}

	data->index++;

	p->req_id = g_obex_setpath(obex, next, setpath_cb, p, &err);
	if (err != NULL) {
		setpath_complete(p->session, NULL, err, data);
		g_error_free(err);
	}
}

guint obc_session_setpath(struct obc_session *session, const char *path,
				session_callback_t func, void *user_data,
				GError **err)
{
	struct setpath_data *data;
	struct pending_request *p;
	const char *first = "";

	if (session->obex == NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_DISCONNECTED,
						"Session disconnected");
		return 0;
	}

	if (session->p != NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_BUSY,
							"Session busy");
		return 0;
	}

	data = g_new0(struct setpath_data, 1);
	data->func = func;
	data->user_data = user_data;
	data->remaining = g_strsplit(strlen(path) ? path : "/", "/", 0);

	p = pending_request_new(session, NULL, setpath_complete, data);

	/* Relative path */
	if (path[0] != '/')
		first = data->remaining[data->index];

	data->index++;

	p->req_id = g_obex_setpath(session->obex, first, setpath_cb, p, err);
	if (*err != NULL)
		goto fail;

	session->p = p;

	return p->id;

fail:
	g_strfreev(data->remaining);
	g_free(data);
	pending_request_free(p);
	return 0;
}

static void async_cb(GObex *obex, GError *err, GObexPacket *rsp,
							gpointer user_data)
{
	struct pending_request *p = user_data;
	struct obc_session *session = p->session;
	GError *gerr = NULL;
	uint8_t code;

	p->req_id = 0;

	if (err != NULL) {
		if (p->func)
			p->func(p->session, NULL, err, p->data);
		goto done;
	}

	code = g_obex_packet_get_operation(rsp, NULL);
	if (code != G_OBEX_RSP_SUCCESS)
		g_set_error(&gerr, OBEX_IO_ERROR, code, "%s",
							g_obex_strerror(code));

	if (p->func)
		p->func(p->session, NULL, gerr, p->data);

	if (gerr != NULL)
		g_clear_error(&gerr);

done:
	pending_request_free(p);
	session->p = NULL;

	session_process_queue(session);
}

guint obc_session_mkdir(struct obc_session *session, const char *folder,
				session_callback_t func, void *user_data,
				GError **err)
{
	struct pending_request *p;

	if (session->obex == NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_DISCONNECTED,
						"Session disconnected");
		return 0;
	}

	if (session->p != NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_BUSY, "Session busy");
		return 0;
	}


	p = pending_request_new(session, NULL, func, user_data);

	p->req_id = g_obex_mkdir(session->obex, folder, async_cb, p, err);
	if (*err != NULL) {
		pending_request_free(p);
		return 0;
	}

	session->p = p;
	return p->id;
}

guint obc_session_copy(struct obc_session *session, const char *srcname,
				const char *destname, session_callback_t func,
				void *user_data, GError **err)
{
	struct pending_request *p;

	if (session->obex == NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_DISCONNECTED,
						"Session disconnected");
		return 0;
	}

	if (session->p != NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_BUSY, "Session busy");
		return 0;
	}

	p = pending_request_new(session, NULL, func, user_data);

	p->req_id = g_obex_copy(session->obex, srcname, destname, async_cb, p,
									err);
	if (*err != NULL) {
		pending_request_free(p);
		return 0;
	}

	session->p = p;
	return p->id;
}

guint obc_session_move(struct obc_session *session, const char *srcname,
				const char *destname, session_callback_t func,
				void *user_data, GError **err)
{
	struct pending_request *p;

	if (session->obex == NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_DISCONNECTED,
						"Session disconnected");
		return 0;
	}

	if (session->p != NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_BUSY, "Session busy");
		return 0;
	}

	p = pending_request_new(session, NULL, func, user_data);

	p->req_id = g_obex_move(session->obex, srcname, destname, async_cb, p,
									err);
	if (*err != NULL) {
		pending_request_free(p);
		return 0;
	}

	session->p = p;
	return p->id;
}

guint obc_session_delete(struct obc_session *session, const char *file,
				session_callback_t func, void *user_data,
				GError **err)
{
	struct pending_request *p;

	if (session->obex == NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_DISCONNECTED,
						"Session disconnected");
		return 0;
	}

	if (session->p != NULL) {
		g_set_error(err, OBEX_IO_ERROR, OBEX_IO_BUSY, "Session busy");
		return 0;
	}

	p = pending_request_new(session, NULL, func, user_data);

	p->req_id = g_obex_delete(session->obex, file, async_cb, p, err);
	if (*err != NULL) {
		pending_request_free(p);
		return 0;
	}

	session->p = p;
	return p->id;
}

void obc_session_cancel(struct obc_session *session, guint id,
							gboolean remove)
{
	struct pending_request *p = session->p;

	if (p == NULL || p->id != id)
		return;

	if (p->req_id == 0)
		return;

	g_obex_cancel_req(session->obex, p->req_id, remove);
	if (!remove)
		return;

	pending_request_free(p);
	session->p = NULL;

	session_process_queue(session);
}
