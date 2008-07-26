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
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus.h"

#define info(fmt...)
#define error(fmt...)
#define debug(fmt...)

static guint listener_id = 0;
static GSList *name_listeners = NULL;

struct name_callback {
	GDBusWatchFunction func;
	void *user_data;
	guint id;
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
					GDBusWatchFunction func, void *user_data)
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
			cb->func(cb->user_data);
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
				GDBusWatchFunction func, void *user_data, guint id)
{
	int first = 1;
	struct name_data *data = NULL;
	struct name_callback *cb = NULL;

	cb = g_new(struct name_callback, 1);

	cb->func = func;
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
	data->callbacks = g_slist_append(data->callbacks, cb);
	return first;
}

static void name_data_remove(DBusConnection *connection,
			const char *name, GDBusWatchFunction func, void *user_data)
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
		cb->func(cb->user_data);
	}

	name_listeners = g_slist_remove(name_listeners, data);
	name_data_free(data);

	remove_match(connection, name);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

guint g_dbus_add_disconnect_watch(DBusConnection *connection,
				const char *name,
				GDBusWatchFunction func,
				void *user_data, GDBusDestroyFunction destroy)
{
	int first;

	if (!listener_id) {
		if (!dbus_connection_add_filter(connection,
					name_exit_filter, NULL, NULL)) {
			error("dbus_connection_add_filter() failed");
			return 0;
		}
	}

	listener_id++;
	first = name_data_add(connection, name, func, user_data, listener_id);
	/* The filter is already added if this is not the first callback
	 * registration for the name */
	if (!first)
		return listener_id;

	if (name) {
		debug("name_listener_add(%s)", name);

		if (!add_match(connection, name)) {
			name_data_remove(connection, name, func, user_data);
			return 0;
		}
	}

	return listener_id;
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
	}

	return FALSE;

remove:
	data->callbacks = g_slist_remove(data->callbacks, cb);
	g_free(cb);

	/* Don't remove the filter if other callbacks exist */
	if (data->callbacks)
		return TRUE;

	if (data->name) {
		if (!remove_match(data->connection, data->name))
			return FALSE;
	}

	name_listeners = g_slist_remove(name_listeners, data);
	name_data_free(data);

	return TRUE;
}

void g_dbus_remove_all_watches(DBusConnection *connection)
{
	struct name_data *data;

	data = name_data_find(connection, NULL);
	if (!data) {
		error("name_listener_indicate_disconnect: no listener found");
		return;
	}

	debug("name_listener_indicate_disconnect");

	name_data_call_and_free(data);
}
