/*
 *
 *  D-Bus helper library
 *
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdint.h>

#include <glib.h>
#include <dbus/dbus.h>

#ifdef NEED_DBUS_WATCH_GET_UNIX_FD
#define dbus_watch_get_unix_fd dbus_watch_get_fd
#endif

#include "gdbus.h"

#define DISPATCH_TIMEOUT  0

#define info(fmt...)
#define error(fmt...)
#define debug(fmt...)

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

struct disconnect_data {
	GDBusWatchFunction disconnect_cb;
	void *user_data;
};

static DBusHandlerResult disconnect_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct disconnect_data *dc_data = data;

	if (dbus_message_is_signal(msg,
			DBUS_INTERFACE_LOCAL, "Disconnected") == TRUE) {
		error("Got disconnected from the system message bus");
		dc_data->disconnect_cb(conn, dc_data->user_data);
		dbus_connection_unref(conn);
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

static void setup_dbus_with_main_loop(DBusConnection *conn)
{
	dbus_connection_set_watch_functions(conn, add_watch, remove_watch,
						watch_toggled, conn, NULL);

	dbus_connection_set_timeout_functions(conn, add_timeout, remove_timeout,
						timeout_toggled, conn, NULL);

	dbus_connection_set_dispatch_status_function(conn, dispatch_status_cb,
								conn, NULL);
}

DBusConnection *g_dbus_setup_bus(DBusBusType type, const char *name,
							DBusError *error)
{
	DBusConnection *conn;

	conn = dbus_bus_get(type, error);

	if (error != NULL) {
		if (dbus_error_is_set(error) == TRUE)
			return NULL;
	}

	if (conn == NULL)
		return NULL;

	if (name != NULL) {
		if (dbus_bus_request_name(conn, name,
				DBUS_NAME_FLAG_DO_NOT_QUEUE, error) !=
				DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER ) {
			dbus_connection_unref(conn);
			return NULL;
		}

		if (error != NULL) {
			if (dbus_error_is_set(error) == TRUE) {
				dbus_connection_unref(conn);
				return NULL;
			}
		}
	}

	setup_dbus_with_main_loop(conn);

	return conn;
}

gboolean g_dbus_request_name(DBusConnection *connection, const char *name,
							DBusError *error)
{
	return TRUE;
}

gboolean g_dbus_set_disconnect_function(DBusConnection *connection,
				GDBusWatchFunction function,
				void *user_data, DBusFreeFunction destroy)
{
	struct disconnect_data *dc_data;

	dc_data = g_new(struct disconnect_data, 1);

	dc_data->disconnect_cb = function;
	dc_data->user_data = user_data;

	dbus_connection_set_exit_on_disconnect(connection, FALSE);

	if (dbus_connection_add_filter(connection, disconnect_filter,
						dc_data, g_free) == FALSE) {
		error("Can't add D-Bus disconnect filter");
		g_free(dc_data);
		return FALSE;
	}

	return TRUE;
}
