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
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <dbus/dbus.h>

#include "glib-ectomy.h"
#include "dbus.h"
#include "logging.h"
#include "list.h"

#define DISPATCH_TIMEOUT	0

static int name_listener_initialized = 0;

static struct slist *name_listeners = NULL;

typedef struct {
	uint32_t id;
	DBusTimeout *timeout;
} timeout_handler_t;

struct watch_info {
	guint watch_id;
	GIOChannel *io;
	DBusConnection *conn;
};

struct disconnect_data {
	void (*disconnect_cb)(void *);
	void *user_data;
};

struct name_callback {
	name_cb_t func;
	void *user_data;
};

struct name_data {
	char *name;
	struct slist *callbacks;
};

static struct name_data *name_data_find(const char *name)
{
	struct slist *current;

	for (current = name_listeners; current != NULL; current = current->next) {
		struct name_data *data = current->data;
		if (strcmp(name, data->name) == 0)
			return data;
	}

	return NULL;
}

static struct name_callback *name_callback_find(struct slist *callbacks,
						name_cb_t func, void *user_data)
{
	struct slist *current;

	for (current = callbacks; current != NULL; current = current->next) {
		struct name_callback *cb = current->data;
		if (cb->func == func && cb->user_data == user_data)
			return cb;
	}

	return NULL;
}

static void name_data_free(struct name_data *data)
{
	struct slist *l;

	for (l = data->callbacks; l != NULL; l = l->next)
		free(l->data);

	slist_free(data->callbacks);

	if (data->name)
		free(data->name);

	free(data);
}

static int name_data_add(const char *name, name_cb_t func, void *user_data)
{
	int first = 1;
	struct name_data *data = NULL;
	struct name_callback *cb = NULL;

	cb = malloc(sizeof(struct name_callback));
	if (!cb)
		goto failed;

	cb->func = func;
	cb->user_data = user_data;

	data = name_data_find(name);
	if (data) {
		first = 0;
		goto done;
	}

	data = malloc(sizeof(struct name_data));
	if (!data)
		goto failed;

	memset(data, 0, sizeof(struct name_data));

	data->name = strdup(name);
	if (!data->name)
		goto failed;

	name_listeners = slist_append(name_listeners, data);

done:
	data->callbacks = slist_append(data->callbacks, cb);
	return first;

failed:
	if (data)
		name_data_free(data);

	if (cb)
		free(cb);

	return 0;
}

static void name_data_remove(const char *name, name_cb_t func, void *user_data)
{
	struct name_data *data;
	struct name_callback *cb = NULL;

	data = name_data_find(name);
	if (!data)
		return;

	cb = name_callback_find(data->callbacks, func, user_data);
	if (cb) {
		data->callbacks = slist_remove(data->callbacks, cb);
		free(cb);
	}

	if (!data->callbacks) {
		name_listeners = slist_remove(name_listeners, data);
		name_data_free(data);
	}
}

static DBusHandlerResult name_exit_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct slist *l;
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

	data = name_data_find(name);
	if (!data) {
		error("Got NameOwnerChanged signal for %s which has no listeners", name);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	for (l = data->callbacks; l != NULL; l = l->next) {
		struct name_callback *cb = l->data;
		cb->func(name, cb->user_data);
	}

	name_listeners = slist_remove(name_listeners, data);
	name_data_free(data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int name_listener_add(DBusConnection *connection, const char *name,
					name_cb_t func, void *user_data)
{
	DBusError err;
	char match_string[128];
	int first;

	if (!name_listener_initialized) {
		if (!dbus_connection_add_filter(connection, name_exit_filter, NULL, NULL)) {
			error("dbus_connection_add_filter() failed");
			return -1;
		}
		name_listener_initialized = 1;
	}

	first = name_data_add(name, func, user_data);
	/* The filter is already added if this is not the first callback
	 * registration for the name */
	if (!first)
		return 0;

	debug("name_listener_add(%s)", name);

	snprintf(match_string, sizeof(match_string),
			"interface=%s,member=NameOwnerChanged,arg0=%s",
			DBUS_INTERFACE_DBUS, name);

	dbus_error_init(&err);
	dbus_bus_add_match(connection, match_string, &err);

	if (dbus_error_is_set(&err)) {
		error("Adding match rule \"%s\" failed: %s", match_string,
				err.message);
		dbus_error_free(&err);
		name_data_remove(name, func, user_data);
		return -1;
	}

	return 0;
}

int name_listener_remove(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data)
{
	struct name_data *data;
	struct name_callback *cb;
	DBusError err;
	char match_string[128];

	debug("name_listener_remove(%s)", name);

	data = name_data_find(name);
	if (!data) {
		error("remove_name_listener: no listener for %s", name);
		return -1;
	}

	cb = name_callback_find(data->callbacks, func, user_data);
	if (!cb) {
		error("No matching callback found for %s", name);
		return -1;
	}

	data->callbacks = slist_remove(data->callbacks, cb);
	free(cb);

	/* Don't remove the filter if other callbacks exist */
	if (data->callbacks)
		return 0;

	snprintf(match_string, sizeof(match_string),
			"interface=%s,member=NameOwnerChanged,arg0=%s",
			DBUS_INTERFACE_DBUS, name);

	dbus_error_init(&err);
	dbus_bus_remove_match(connection, match_string, &err);

	if (dbus_error_is_set(&err)) {
		error("Removing owner match rule for %s failed: %s",
							name, err.message);
		dbus_error_free(&err);
		return -1;
	}

	name_data_remove(name, func, user_data);

	return 0;
}

static DBusHandlerResult disconnect_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *iface,*method;
	struct disconnect_data *dc_data = data;

	if (dbus_message_get_type (msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	iface = dbus_message_get_interface(msg);
	method = dbus_message_get_member(msg);

	if ((strcmp(iface, DBUS_INTERFACE_LOCAL) == 0) &&
			(strcmp(method, "Disconnected") == 0)) {
		error("Got disconnected from the system message bus");
		dbus_connection_unref(conn);
		dc_data->disconnect_cb(dc_data->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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

	info = malloc(sizeof(struct watch_info));
	if (info == NULL)
		return FALSE;

	fd = dbus_watch_get_fd(watch);
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
		g_io_remove_watch(info->watch_id);
		g_io_channel_unref(info->io);
		dbus_connection_unref(info->conn);
		free(info);
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

	g_timeout_remove(handler->id);
	free(handler);
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *data)
{
	timeout_handler_t *handler;

	if (!dbus_timeout_get_enabled (timeout))
		return TRUE;

	handler = malloc(sizeof(timeout_handler_t));
	memset(handler, 0, sizeof(timeout_handler_t));

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
				DBusDispatchStatus new_status,
				void *data)
{
	if (!dbus_connection_get_is_connected(conn))
		return;

	if (new_status == DBUS_DISPATCH_DATA_REMAINS)
		g_timeout_add(DISPATCH_TIMEOUT, message_dispatch_cb, data);
}

DBusConnection *init_dbus(void (*disconnect_cb)(void *), void *user_data)
{
	DBusConnection *conn;
	DBusError err;
	struct disconnect_data *dc_data;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);

	if (dbus_error_is_set(&err)) {
		error("Can't open system message bus connection: %s",
				err.message);
		dbus_error_free(&err);
		return NULL;
	}

	dbus_connection_set_watch_functions(conn, add_watch, remove_watch,
						watch_toggled, conn, NULL);

	dbus_connection_set_timeout_functions(conn, add_timeout, remove_timeout,
						timeout_toggled, conn, NULL);

	dbus_connection_set_dispatch_status_function(conn, dispatch_status_cb,
							conn, NULL);

	if (!disconnect_cb)
		return conn;

	dc_data = malloc(sizeof(struct disconnect_data));
	if (!dc_data) {
		error("Allocating disconnect data failed");
		dbus_connection_unref(conn);
		return NULL;
	}

	dc_data->disconnect_cb = disconnect_cb;
	dc_data->user_data = user_data;

	dbus_connection_set_exit_on_disconnect(conn, FALSE);

	if (!dbus_connection_add_filter(conn, disconnect_filter,
				dc_data, free)) {
		error("Can't add D-Bus disconnect filter");
		free(dc_data);
		dbus_connection_unref(conn);
		return NULL;
	}

	return conn;
}

static char simple_xml[] = DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE "<node></node>";

DBusHandlerResult simple_introspect(DBusConnection *conn, DBusMessage *msg, void *data)
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

