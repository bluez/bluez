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

#include <stdio.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus.h"

#define info(fmt...)
#define error(fmt...)
#define debug(fmt...)

static DBusHandlerResult name_exit_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data);

static guint listener_id = 0;
static GSList *name_listeners = NULL;

struct name_callback {
	GDBusWatchFunction conn_func;
	GDBusWatchFunction disc_func;
	void *user_data;
	guint id;
};

struct name_data {
	DBusConnection *connection;
	char *name;
	GSList *callbacks;
	GSList *processed;
	gboolean lock;
};

static struct name_data *name_data_find(DBusConnection *connection,
							const char *name)
{
	GSList *current;

	for (current = name_listeners;
			current != NULL; current = current->next) {
		struct name_data *data = current->data;

		if (connection != data->connection)
			continue;

		if (name == NULL || g_str_equal(name, data->name))
			return data;
	}

	return NULL;
}

static struct name_callback *name_callback_find(GSList *callbacks, guint id)
{
	GSList *current;

	for (current = callbacks; current != NULL; current = current->next) {
		struct name_callback *cb = current->data;
		if (cb->id == id)
			return cb;
	}

	return NULL;
}

static void name_data_call_and_free(struct name_data *data)
{
	GSList *l;

	for (l = data->callbacks; l != NULL; l = l->next) {
		struct name_callback *cb = l->data;
		if (cb->disc_func)
			cb->disc_func(data->connection, cb->user_data);
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

static int name_data_add(DBusConnection *connection, const char *name,
						GDBusWatchFunction connect,
						GDBusWatchFunction disconnect,
						void *user_data, guint id)
{
	int first = 1;
	struct name_data *data = NULL;
	struct name_callback *cb = NULL;

	cb = g_new(struct name_callback, 1);

	cb->conn_func = connect;
	cb->disc_func = disconnect;
	cb->user_data = user_data;
	cb->id = id;

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
	if (data->lock)
		data->processed = g_slist_append(data->processed, cb);
	else
		data->callbacks = g_slist_append(data->callbacks, cb);

	return first;
}

static void name_data_remove(DBusConnection *connection,
					const char *name, guint id)
{
	struct name_data *data;
	struct name_callback *cb = NULL;

	data = name_data_find(connection, name);
	if (!data)
		return;

	cb = name_callback_find(data->callbacks, id);
	if (cb) {
		data->callbacks = g_slist_remove(data->callbacks, cb);
		g_free(cb);
	}

	if (data->callbacks)
		return;

	name_listeners = g_slist_remove(name_listeners, data);
	name_data_free(data);

	/* Remove filter if there are no listeners left for the connection */
	data = name_data_find(connection, NULL);
	if (!data)
		dbus_connection_remove_filter(connection,
						name_exit_filter,
						NULL);
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
	struct name_data *data;
	struct name_callback *cb;
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

	data = name_data_find(connection, name);
	if (!data) {
		error("Got NameOwnerChanged signal for %s which has no listeners", name);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	data->lock = TRUE;

	while (data->callbacks) {
		cb = data->callbacks->data;

		if (*new == '\0') {
			if (cb->disc_func)
				cb->disc_func(connection, cb->user_data);
		} else {
			if (cb->conn_func)
				cb->conn_func(connection, cb->user_data);
		}

		/* Check if the watch was removed/freed by the callback
		 * function */
		if (!g_slist_find(data->callbacks, cb))
			continue;

		data->callbacks = g_slist_remove(data->callbacks, cb);

		if (!cb->conn_func || !cb->disc_func) {
			g_free(cb);
			continue;
		}

		data->processed = g_slist_append(data->processed, cb);
	}

	data->callbacks = data->processed;
	data->processed = NULL;
	data->lock = FALSE;

	if (data->callbacks)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	name_listeners = g_slist_remove(name_listeners, data);
	name_data_free(data);

	/* Remove filter if there no listener left for the connection */
	data = name_data_find(connection, NULL);
	if (!data)
		dbus_connection_remove_filter(connection, name_exit_filter,
						NULL);

	remove_match(connection, name);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

struct service_data {
	DBusConnection *conn;
	GDBusWatchFunction conn_func;
	void *user_data;
};

static void service_reply(DBusPendingCall *call, void *user_data)
{
	struct service_data *data = user_data;
	DBusMessage *reply;
	DBusError error;
	dbus_bool_t has_owner;

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	dbus_error_init(&error);

	if (dbus_message_get_args(reply, &error,
					DBUS_TYPE_BOOLEAN, &has_owner,
						DBUS_TYPE_INVALID) == FALSE) {
		if (dbus_error_is_set(&error) == TRUE) {
			error("%s", error.message);
			dbus_error_free(&error);
		} else {
			error("Wrong arguments for NameHasOwner reply");
		}
		goto done;
	}

	if (has_owner && data->conn_func)
		data->conn_func(data->conn, data->user_data);

done:
	dbus_message_unref(reply);
}

static void check_service(DBusConnection *connection, const char *name,
				GDBusWatchFunction connect, void *user_data)
{
	DBusMessage *message;
	DBusPendingCall *call;
	struct service_data *data;

	data = g_try_malloc0(sizeof(*data));
	if (data == NULL) {
		error("Can't allocate data structure");
		return;
	}

	data->conn = connection;
	data->conn_func = connect;
	data->user_data = user_data;

	message = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
			DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "NameHasOwner");
	if (message == NULL) {
		error("Can't allocate new message");
		g_free(data);
		return;
	}

	dbus_message_append_args(message, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
							&call, -1) == FALSE) {
		error("Failed to execute method call");
		g_free(data);
		goto done;
	}

	if (call == NULL) {
		error("D-Bus connection not available");
		g_free(data);
		goto done;
	}

	dbus_pending_call_set_notify(call, service_reply, data, NULL);

done:
	dbus_message_unref(message);
}

guint g_dbus_add_service_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction connect,
				GDBusWatchFunction disconnect,
				void *user_data, GDBusDestroyFunction destroy)
{
	int first;

	if (!name_data_find(connection, NULL)) {
		if (!dbus_connection_add_filter(connection,
					name_exit_filter, NULL, NULL)) {
			error("dbus_connection_add_filter() failed");
			return 0;
		}
	}

	listener_id++;
	first = name_data_add(connection, name, connect, disconnect,
						user_data, listener_id);
	/* The filter is already added if this is not the first callback
	 * registration for the name */
	if (!first)
		goto done;

	if (name) {
		debug("name_listener_add(%s)", name);

		if (!add_match(connection, name)) {
			name_data_remove(connection, name, listener_id);
			return 0;
		}
	}

done:
	if (connect)
		check_service(connection, name, connect, user_data);

	return listener_id;
}

guint g_dbus_add_disconnect_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction func,
				void *user_data, GDBusDestroyFunction destroy)
{
	return g_dbus_add_service_watch(connection, name, NULL, func,
							user_data, destroy);
}

guint g_dbus_add_signal_watch(DBusConnection *connection,
				const char *rule, GDBusSignalFunction function,
				void *user_data, GDBusDestroyFunction destroy)
{
	return 0;
}

gboolean g_dbus_remove_watch(DBusConnection *connection, guint id)
{
	struct name_data *data;
	struct name_callback *cb;
	GSList *ldata, *lcb;

	if (id == 0)
		return FALSE;

	for (ldata = name_listeners; ldata; ldata = ldata->next) {
		data = ldata->data;
		for (lcb = data->callbacks; lcb; lcb = lcb->next) {
			cb = lcb->data;
			if (cb->id == id)
				goto remove;
		}
		for (lcb = data->processed; lcb; lcb = lcb->next) {
			cb = lcb->data;
			if (cb->id == id)
				goto remove;
		}
	}

	return FALSE;

remove:
	data->callbacks = g_slist_remove(data->callbacks, cb);
	data->processed = g_slist_remove(data->processed, cb);
	g_free(cb);

	/* Don't remove the filter if other callbacks exist or data is lock
	 * processing callbacks */
	if (data->callbacks || data->lock)
		return TRUE;

	if (data->name) {
		if (!remove_match(data->connection, data->name))
			return FALSE;
	}

	name_listeners = g_slist_remove(name_listeners, data);
	name_data_free(data);

	/* Remove filter if there are no listeners left for the connection */
	data = name_data_find(connection, NULL);
	if (!data)
		dbus_connection_remove_filter(connection, name_exit_filter,
						NULL);

	return TRUE;
}

void g_dbus_remove_all_watches(DBusConnection *connection)
{
	struct name_data *data;

	while ((data = name_data_find(connection, NULL))) {
		name_listeners = g_slist_remove(name_listeners, data);
		name_data_call_and_free(data);
	}

	dbus_connection_remove_filter(connection, name_exit_filter, NULL);
}
