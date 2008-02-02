/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <glib.h>

#include <dbus/dbus.h>

#ifdef NEED_DBUS_WATCH_GET_UNIX_FD
#define dbus_watch_get_unix_fd dbus_watch_get_fd
#endif

#ifdef HAVE_DBUS_GLIB
#include <dbus/dbus-glib-lowlevel.h>
#endif

#include "dbus.h"
#include "logging.h"

#define DISPATCH_TIMEOUT	0

static int name_listener_initialized = 0;

static GSList *name_listeners = NULL;

#ifndef HAVE_DBUS_GLIB
typedef struct {
	uint32_t id;
	DBusTimeout *timeout;
} timeout_handler_t;

struct watch_info {
	guint watch_id;
	GIOChannel *io;
	DBusConnection *conn;
};

struct server_info {
	guint watch_id;
	GIOChannel *io;
	DBusServer *server;
};
#endif

struct disconnect_data {
	void (*disconnect_cb)(void *);
	void *user_data;
};

struct name_callback {
	name_cb_t func;
	void *user_data;
};

struct name_data {
	DBusConnection *connection;
	char *name;
	GSList *callbacks;
};

static struct name_data *name_data_find(DBusConnection *connection,
							const char *name)
{
	GSList *current;

	for (current = name_listeners;
			current != NULL; current = current->next) {
		struct name_data *data = current->data;

		if (name == NULL && data->name == NULL) {
			if (connection == data->connection)
				return data;
		} else {
			if (strcmp(name, data->name) == 0)
				return data;
		}
	}

	return NULL;
}

static struct name_callback *name_callback_find(GSList *callbacks,
					name_cb_t func, void *user_data)
{
	GSList *current;

	for (current = callbacks; current != NULL; current = current->next) {
		struct name_callback *cb = current->data;
		if (cb->func == func && cb->user_data == user_data)
			return cb;
	}

	return NULL;
}

static void name_data_call_and_free(struct name_data *data)
{
	GSList *l;

	for (l = data->callbacks; l != NULL; l = l->next) {
		struct name_callback *cb = l->data;
		if (cb->func)
			cb->func(data->name, cb->user_data);
		g_free(cb);
	}

	g_slist_free(data->callbacks);
	g_free(data->name);
	g_free(data);
}

static void name_data_free(struct name_data *data)
{
	GSList *l;

	for (l = data->callbacks; l != NULL; l = l->next)
		g_free(l->data);

	g_slist_free(data->callbacks);
	g_free(data->name);
	g_free(data);
}

static int name_data_add(DBusConnection *connection,
			const char *name, name_cb_t func, void *user_data)
{
	int first = 1;
	struct name_data *data = NULL;
	struct name_callback *cb = NULL;

	cb = g_new(struct name_callback, 1);

	cb->func = func;
	cb->user_data = user_data;

	data = name_data_find(connection, name);
	if (data) {
		first = 0;
		goto done;
	}

	data = g_new0(struct name_data, 1);

	data->connection = connection;
	data->name = g_strdup(name);

	name_listeners = g_slist_append(name_listeners, data);

done:
	data->callbacks = g_slist_append(data->callbacks, cb);
	return first;
}

static void name_data_remove(DBusConnection *connection,
			const char *name, name_cb_t func, void *user_data)
{
	struct name_data *data;
	struct name_callback *cb = NULL;

	data = name_data_find(connection, name);
	if (!data)
		return;

	cb = name_callback_find(data->callbacks, func, user_data);
	if (cb) {
		data->callbacks = g_slist_remove(data->callbacks, cb);
		g_free(cb);
	}

	if (!data->callbacks) {
		name_listeners = g_slist_remove(name_listeners, data);
		name_data_free(data);
	}
}

static gboolean add_match(DBusConnection *connection, const char *name)
{
	DBusError err;
	char match_string[128];

	snprintf(match_string, sizeof(match_string),
			"interface=%s,member=NameOwnerChanged,arg0=%s",
			DBUS_INTERFACE_DBUS, name);

	dbus_error_init(&err);

	dbus_bus_add_match(connection, match_string, &err);

	if (dbus_error_is_set(&err)) {
		error("Adding match rule \"%s\" failed: %s", match_string,
				err.message);
		dbus_error_free(&err);
		return FALSE;
	}

	return TRUE;
}

static gboolean remove_match(DBusConnection *connection, const char *name)
{
	DBusError err;
	char match_string[128];

	snprintf(match_string, sizeof(match_string),
			"interface=%s,member=NameOwnerChanged,arg0=%s",
			DBUS_INTERFACE_DBUS, name);

	dbus_error_init(&err);

	dbus_bus_remove_match(connection, match_string, &err);

	if (dbus_error_is_set(&err)) {
		error("Removing owner match rule for %s failed: %s",
				name, err.message);
		dbus_error_free(&err);
		return FALSE;
	}

	return TRUE;
}

static DBusHandlerResult name_exit_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	GSList *l;
	struct name_data *data;
	char *name, *old, *new;

	if (!dbus_message_is_signal(message, DBUS_INTERFACE_DBUS,
							"NameOwnerChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &old,
				DBUS_TYPE_STRING, &new,
				DBUS_TYPE_INVALID)) {
		error("Invalid arguments for NameOwnerChanged signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* We are not interested of service creations */
	if (*new != '\0')
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	data = name_data_find(connection, name);
	if (!data) {
		error("Got NameOwnerChanged signal for %s which has no listeners", name);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	for (l = data->callbacks; l != NULL; l = l->next) {
		struct name_callback *cb = l->data;
		cb->func(name, cb->user_data);
	}

	name_listeners = g_slist_remove(name_listeners, data);
	name_data_free(data);

	remove_match(connection, name);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int name_listener_add(DBusConnection *connection, const char *name,
					name_cb_t func, void *user_data)
{
	int first;

	if (!name_listener_initialized) {
		if (!dbus_connection_add_filter(connection,
					name_exit_filter, NULL, NULL)) {
			error("dbus_connection_add_filter() failed");
			return -1;
		}
		name_listener_initialized = 1;
	}

	first = name_data_add(connection, name, func, user_data);
	/* The filter is already added if this is not the first callback
	 * registration for the name */
	if (!first)
		return 0;

	if (name) {
		debug("name_listener_add(%s)", name);

		if (!add_match(connection, name)) {
			name_data_remove(connection, name, func, user_data);
			return -1;
		}
	}

	return 0;
}

int name_listener_remove(DBusConnection *connection, const char *name,
					name_cb_t func, void *user_data)
{
	struct name_data *data;
	struct name_callback *cb;

	data = name_data_find(connection, name);
	if (!data) {
		error("remove_name_listener: no listener for %s", name);
		return -1;
	}

	cb = name_callback_find(data->callbacks, func, user_data);
	if (!cb) {
		error("No matching callback found for %s", name);
		return -1;
	}

	data->callbacks = g_slist_remove(data->callbacks, cb);
	g_free(cb);

	/* Don't remove the filter if other callbacks exist */
	if (data->callbacks)
		return 0;

	if (name) {
		debug("name_listener_remove(%s)", name);

		if (!remove_match(connection, name))
			return -1;
	}

	name_data_remove(connection, name, func, user_data);

	return 0;
}

int name_listener_indicate_disconnect(DBusConnection *connection)
{
	struct name_data *data;

	data = name_data_find(connection, NULL);
	if (!data) {
		error("name_listener_indicate_disconnect: no listener found");
		return -1;
	}

	debug("name_listener_indicate_disconnect");

	name_data_call_and_free(data);

	return 0;
}

dbus_bool_t dbus_bus_get_unix_process_id(DBusConnection *conn, const char *name,
						unsigned long *pid)
{
	DBusMessage *msg, *reply;
	DBusError err;
	dbus_uint32_t pid_arg;

	msg = dbus_message_new_method_call("org.freedesktop.DBus",
						"/org/freedesktop/DBus",
						"org.freedesktop.DBus",
						"GetConnectionUnixProcessID");
	if (!msg) {
		error("Unable to allocate new message");
		return FALSE;
	}

	if (!dbus_message_append_args(msg, DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID)) {
		error("Unable to append arguments to message");
		dbus_message_unref(msg);
		return FALSE;
	}

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
	if (dbus_error_is_set(&err)) {
		error("Sending GetConnectionUnixProcessID failed: %s", err.message);
		dbus_error_free(&err);
		dbus_message_unref(msg);
		return FALSE;
	}

	dbus_error_init(&err);
	dbus_message_get_args(reply, &err, DBUS_TYPE_UINT32, &pid_arg,
					DBUS_TYPE_INVALID);
	if (dbus_error_is_set(&err)) {
		error("Getting GetConnectionUnixProcessID args failed: %s",
				err.message);
		dbus_error_free(&err);
		dbus_message_unref(msg);
		dbus_message_unref(reply);
		return FALSE;
	}

	*pid = (unsigned long) pid_arg;

	dbus_message_unref(msg);
	dbus_message_unref(reply);

	return TRUE;
}

static DBusHandlerResult disconnect_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct disconnect_data *dc_data = data;

	if (dbus_message_is_signal(msg,
			DBUS_INTERFACE_LOCAL, "Disconnected") == TRUE) {
		error("Got disconnected from the system message bus");
		dbus_connection_unref(conn);
		dc_data->disconnect_cb(dc_data->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

#ifndef HAVE_DBUS_GLIB
static dbus_int32_t server_slot = -1;

static gboolean server_func(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBusWatch *watch = data;
	int flags = 0;

	if (cond & G_IO_IN)  flags |= DBUS_WATCH_READABLE;
	if (cond & G_IO_OUT) flags |= DBUS_WATCH_WRITABLE;
	if (cond & G_IO_HUP) flags |= DBUS_WATCH_HANGUP;
	if (cond & G_IO_ERR) flags |= DBUS_WATCH_ERROR;

	dbus_watch_handle(watch, flags);

	return TRUE;
}

static dbus_bool_t add_server(DBusWatch *watch, void *data)
{
	GIOCondition cond = G_IO_HUP | G_IO_ERR;
	DBusServer *server = data;
	struct server_info *info;
	int fd, flags;

	if (!dbus_watch_get_enabled(watch))
		return TRUE;

	info = g_new(struct server_info, 1);

	fd = dbus_watch_get_unix_fd(watch);
	info->io = g_io_channel_unix_new(fd);
	info->server = dbus_server_ref(server);

	dbus_watch_set_data(watch, info, NULL);

	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) cond |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE) cond |= G_IO_OUT;

	info->watch_id = g_io_add_watch(info->io, cond, server_func, watch);

	return TRUE;
}

static void remove_server(DBusWatch *watch, void *data)
{
	struct server_info *info = dbus_watch_get_data(watch);

	dbus_watch_set_data(watch, NULL, NULL);

	if (info) {
		g_source_remove(info->watch_id);
		g_io_channel_unref(info->io);
		dbus_server_unref(info->server);
		g_free(info);
	}
}

static void server_toggled(DBusWatch *watch, void *data)
{
	/* Because we just exit on OOM, enable/disable is
	 * no different from add/remove */
	if (dbus_watch_get_enabled(watch))
		add_server(watch, data);
	else
		remove_server(watch, data);
}

static gboolean message_dispatch_cb(void *data)
{
	DBusConnection *connection = data;

	dbus_connection_ref(connection);

	/* Dispatch messages */
	while (dbus_connection_dispatch(connection) == DBUS_DISPATCH_DATA_REMAINS);

	dbus_connection_unref(connection);

	return FALSE;
}

static gboolean watch_func(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	DBusWatch *watch = data;
	struct watch_info *info = dbus_watch_get_data(watch);
	int flags = 0;

	if (cond & G_IO_IN)  flags |= DBUS_WATCH_READABLE;
	if (cond & G_IO_OUT) flags |= DBUS_WATCH_WRITABLE;
	if (cond & G_IO_HUP) flags |= DBUS_WATCH_HANGUP;
	if (cond & G_IO_ERR) flags |= DBUS_WATCH_ERROR;

	dbus_watch_handle(watch, flags);

	if (dbus_connection_get_dispatch_status(info->conn) == DBUS_DISPATCH_DATA_REMAINS)
		g_timeout_add(DISPATCH_TIMEOUT, message_dispatch_cb, info->conn);

	return TRUE;
}

static dbus_bool_t add_watch(DBusWatch *watch, void *data)
{
	GIOCondition cond = G_IO_HUP | G_IO_ERR;
	DBusConnection *conn = data;
	struct watch_info *info;
	int fd, flags;

	if (!dbus_watch_get_enabled(watch))
		return TRUE;

	info = g_new(struct watch_info, 1);

	fd = dbus_watch_get_unix_fd(watch);
	info->io = g_io_channel_unix_new(fd);
	info->conn = dbus_connection_ref(conn);

	dbus_watch_set_data(watch, info, NULL);

	flags = dbus_watch_get_flags(watch);

	if (flags & DBUS_WATCH_READABLE) cond |= G_IO_IN;
	if (flags & DBUS_WATCH_WRITABLE) cond |= G_IO_OUT;

	info->watch_id = g_io_add_watch(info->io, cond, watch_func, watch);

	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *data)
{
	struct watch_info *info = dbus_watch_get_data(watch);

	dbus_watch_set_data(watch, NULL, NULL);

	if (info) {
		g_source_remove(info->watch_id);
		g_io_channel_unref(info->io);
		dbus_connection_unref(info->conn);
		g_free(info);
	}
}

static void watch_toggled(DBusWatch *watch, void *data)
{
	/* Because we just exit on OOM, enable/disable is
	 * no different from add/remove */
	if (dbus_watch_get_enabled(watch))
		add_watch(watch, data);
	else
		remove_watch(watch, data);
}

static gboolean timeout_handler_dispatch(gpointer data)
{
	timeout_handler_t *handler = data;

	/* if not enabled should not be polled by the main loop */
	if (dbus_timeout_get_enabled(handler->timeout) != TRUE)
		return FALSE;

	dbus_timeout_handle(handler->timeout);

	return FALSE;
}

static void timeout_handler_free(void *data)
{
	timeout_handler_t *handler = data;
	if (!handler)
		return;

	g_source_remove(handler->id);
	g_free(handler);
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *data)
{
	timeout_handler_t *handler;

	if (!dbus_timeout_get_enabled(timeout))
		return TRUE;

	handler = g_new0(timeout_handler_t, 1);

	handler->timeout = timeout;
	handler->id = g_timeout_add(dbus_timeout_get_interval(timeout),
					timeout_handler_dispatch, handler);

	dbus_timeout_set_data(timeout, handler, timeout_handler_free);

	return TRUE;
}

static void remove_timeout(DBusTimeout *timeout, void *data)
{
}

static void timeout_toggled(DBusTimeout *timeout, void *data)
{
	if (dbus_timeout_get_enabled(timeout))
		add_timeout(timeout, data);
	else
		remove_timeout(timeout, data);
}

static void dispatch_status_cb(DBusConnection *conn,
				DBusDispatchStatus new_status, void *data)
{
	if (!dbus_connection_get_is_connected(conn))
		return;

	if (new_status == DBUS_DISPATCH_DATA_REMAINS)
		g_timeout_add(DISPATCH_TIMEOUT, message_dispatch_cb, data);
}
#endif

void setup_dbus_server_with_main_loop(DBusServer *server)
{
#ifdef HAVE_DBUS_GLIB
	debug("Using D-Bus GLib server setup");

	dbus_server_setup_with_g_main(server, NULL);
#else
	dbus_server_allocate_data_slot(&server_slot);
	if (server_slot < 0)
		return;

	dbus_server_set_data(server, server_slot, server, NULL);

	dbus_server_set_watch_functions(server, add_server, remove_server,
						server_toggled, server, NULL);

	dbus_server_set_timeout_functions(server, add_timeout, remove_timeout,
						timeout_toggled, server, NULL);
#endif
}

void setup_dbus_with_main_loop(DBusConnection *conn)
{
#ifdef HAVE_DBUS_GLIB
	debug("Using D-Bus GLib connection setup");

	dbus_connection_setup_with_g_main(conn, NULL);
#else
	dbus_connection_set_watch_functions(conn, add_watch, remove_watch,
						watch_toggled, conn, NULL);

	dbus_connection_set_timeout_functions(conn, add_timeout, remove_timeout,
						timeout_toggled, conn, NULL);

	dbus_connection_set_dispatch_status_function(conn, dispatch_status_cb,
								conn, NULL);
#endif
}

DBusConnection *init_dbus(const char *name,
				void (*disconnect_cb)(void *), void *user_data)
{
	struct disconnect_data *dc_data;
	DBusConnection *conn;
	DBusError err;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);

	if (dbus_error_is_set(&err)) {
		error("Can't connect to system message bus: %s", err.message);
		dbus_error_free(&err);
		return NULL;
	}

	setup_dbus_with_main_loop(conn);

	if (name) {
		dbus_error_init(&err);

		if (dbus_bus_request_name(conn, name, 0, &err) !=
				DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER ) {
			error("Could not become the primary owner of %s", name);
			dbus_connection_unref(conn);
			return NULL;
		}

		if (dbus_error_is_set(&err)) {
			error("Can't get bus name %s: %s", name, err.message);
			dbus_error_free(&err);
			dbus_connection_unref(conn);
			return NULL;
		}
	}

	if (!disconnect_cb)
		return conn;

	dc_data = g_new(struct disconnect_data, 1);

	dc_data->disconnect_cb = disconnect_cb;
	dc_data->user_data = user_data;

	dbus_connection_set_exit_on_disconnect(conn, FALSE);

	if (!dbus_connection_add_filter(conn, disconnect_filter,
				dc_data, g_free)) {
		error("Can't add D-Bus disconnect filter");
		g_free(dc_data);
		dbus_connection_unref(conn);
		return NULL;
	}

	return conn;
}

DBusConnection *init_dbus_direct(const char *address)
{
	DBusConnection *conn;
	DBusError err;

	dbus_error_init(&err);

	conn = dbus_connection_open(address, &err);

	if (dbus_error_is_set(&err)) {
		error("Can't connect to message server: %s", err.message);
		dbus_error_free(&err);
		return NULL;
	}

	setup_dbus_with_main_loop(conn);

	dbus_connection_set_exit_on_disconnect(conn, FALSE);

	return conn;
}

DBusConnection *dbus_bus_system_setup_with_main_loop(const char *name,
				void (*disconnect_cb)(void *), void *user_data)
{
	return init_dbus(name, disconnect_cb, user_data);
}

static char simple_xml[] = DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE "<node></node>";

DBusHandlerResult simple_introspect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBusMessage *reply;
	const char *path, *ptr = simple_xml;

	path = dbus_message_get_path(msg);

	info("Introspect path:%s", path);

	if (!dbus_message_has_signature(msg, DBUS_TYPE_INVALID_AS_STRING)) {
		error("Unexpected signature to introspect call");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

int set_nonblocking(int fd)
{
	long arg;

	arg = fcntl(fd, F_GETFL);
	if (arg < 0) {
		error("fcntl(F_GETFL): %s (%d)", strerror(errno), errno);
		return -errno;
	}

	/* Return if already nonblocking */
	if (arg & O_NONBLOCK)
		return 0;

	arg |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, arg) < 0) {
		error("fcntl(F_SETFL, O_NONBLOCK): %s (%d)",
				strerror(errno), errno);
		return -errno;
	}

	return 0;
}

void register_external_service(DBusConnection *conn, const char *identifier,
				const char *name, const char *description)
{
	DBusMessage *msg, *reply;

	info("Registering service");

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RegisterService");
	if (!msg) {
		error("Can't create service register method");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &identifier,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_STRING, &description, DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, NULL);
	if (!reply) {
		error("Can't register service");
		return;
	}

	dbus_message_unref(msg);
	dbus_message_unref(reply);

	dbus_connection_flush(conn);
}
