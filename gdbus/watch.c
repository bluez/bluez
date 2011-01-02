/*
 *
 *  D-Bus helper library
 *
 *  Copyright (C) 2004-2011  Marcel Holtmann <marcel@holtmann.org>
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

static DBusHandlerResult message_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data);

static guint listener_id = 0;
static GSList *listeners = NULL;

struct service_data {
	DBusConnection *conn;
	DBusPendingCall *call;
	char *name;
	const char *owner;
	guint id;
	struct filter_callback *callback;
};

struct filter_callback {
	GDBusWatchFunction conn_func;
	GDBusWatchFunction disc_func;
	GDBusSignalFunction signal_func;
	GDBusDestroyFunction destroy_func;
	struct service_data *data;
	void *user_data;
	guint id;
};

struct filter_data {
	DBusConnection *connection;
	DBusHandleMessageFunction handle_func;
	char *name;
	char *owner;
	char *path;
	char *interface;
	char *member;
	char *argument;
	GSList *callbacks;
	GSList *processed;
	guint name_watch;
	gboolean lock;
	gboolean registered;
};

static struct filter_data *filter_data_find(DBusConnection *connection,
							const char *name,
							const char *owner,
							const char *path,
							const char *interface,
							const char *member,
							const char *argument)
{
	GSList *current;

	for (current = listeners;
			current != NULL; current = current->next) {
		struct filter_data *data = current->data;

		if (connection != data->connection)
			continue;

		if (name && data->name &&
				g_str_equal(name, data->name) == FALSE)
			continue;

		if (owner && data->owner &&
				g_str_equal(owner, data->owner) == FALSE)
			continue;

		if (path && data->path &&
				g_str_equal(path, data->path) == FALSE)
			continue;

		if (interface && data->interface &&
				g_str_equal(interface, data->interface) == FALSE)
			continue;

		if (member && data->member &&
				g_str_equal(member, data->member) == FALSE)
			continue;

		if (argument && data->argument &&
				g_str_equal(argument, data->argument) == FALSE)
			continue;

		return data;
	}

	return NULL;
}

static void format_rule(struct filter_data *data, char *rule, size_t size)
{
	const char *sender;
	int offset;

	offset = snprintf(rule, size, "type='signal'");
	sender = data->name ? : data->owner;

	if (sender)
		offset += snprintf(rule + offset, size - offset,
				",sender='%s'", sender);
	if (data->path)
		offset += snprintf(rule + offset, size - offset,
				",path='%s'", data->path);
	if (data->interface)
		offset += snprintf(rule + offset, size - offset,
				",interface='%s'", data->interface);
	if (data->member)
		offset += snprintf(rule + offset, size - offset,
				",member='%s'", data->member);
	if (data->argument)
		snprintf(rule + offset, size - offset,
				",arg0='%s'", data->argument);
}

static gboolean add_match(struct filter_data *data,
				DBusHandleMessageFunction filter)
{
	DBusError err;
	char rule[DBUS_MAXIMUM_MATCH_RULE_LENGTH];

	format_rule(data, rule, sizeof(rule));
	dbus_error_init(&err);

	dbus_bus_add_match(data->connection, rule, &err);
	if (dbus_error_is_set(&err)) {
		error("Adding match rule \"%s\" failed: %s", rule,
				err.message);
		dbus_error_free(&err);
		return FALSE;
	}

	data->handle_func = filter;
	data->registered = TRUE;

	return TRUE;
}

static gboolean remove_match(struct filter_data *data)
{
	DBusError err;
	char rule[DBUS_MAXIMUM_MATCH_RULE_LENGTH];

	format_rule(data, rule, sizeof(rule));

	dbus_error_init(&err);

	dbus_bus_remove_match(data->connection, rule, &err);
	if (dbus_error_is_set(&err)) {
		error("Removing owner match rule for %s failed: %s",
				rule, err.message);
		dbus_error_free(&err);
		return FALSE;
	}

	return TRUE;
}

static struct filter_data *filter_data_get(DBusConnection *connection,
					DBusHandleMessageFunction filter,
					const char *sender,
					const char *path,
					const char *interface,
					const char *member,
					const char *argument)
{
	struct filter_data *data;
	const char *name = NULL, *owner = NULL;

	if (filter_data_find(connection, NULL, NULL, NULL, NULL, NULL, NULL) == NULL) {
		if (!dbus_connection_add_filter(connection,
					message_filter, NULL, NULL)) {
			error("dbus_connection_add_filter() failed");
			return NULL;
		}
	}

	if (sender == NULL)
		goto proceed;

	if (sender[0] == ':')
		owner = sender;
	else
		name = sender;

proceed:
	data = filter_data_find(connection, name, owner, path, interface,
					member, argument);
	if (data)
		return data;

	data = g_new0(struct filter_data, 1);

	data->connection = dbus_connection_ref(connection);
	data->name = name ? g_strdup(name) : NULL;
	data->owner = owner ? g_strdup(owner) : NULL;
	data->path = g_strdup(path);
	data->interface = g_strdup(interface);
	data->member = g_strdup(member);
	data->argument = g_strdup(argument);

	if (!add_match(data, filter)) {
		g_free(data);
		return NULL;
	}

	listeners = g_slist_append(listeners, data);

	return data;
}

static struct filter_callback *filter_data_find_callback(
						struct filter_data *data,
						guint id)
{
	GSList *l;

	for (l = data->callbacks; l; l = l->next) {
		struct filter_callback *cb = l->data;
		if (cb->id == id)
			return cb;
	}
	for (l = data->processed; l; l = l->next) {
		struct filter_callback *cb = l->data;
		if (cb->id == id)
			return cb;
	}

	return NULL;
}

static void filter_data_free(struct filter_data *data)
{
	GSList *l;

	for (l = data->callbacks; l != NULL; l = l->next)
		g_free(l->data);

	g_slist_free(data->callbacks);
	g_dbus_remove_watch(data->connection, data->name_watch);
	g_free(data->name);
	g_free(data->owner);
	g_free(data->path);
	g_free(data->interface);
	g_free(data->member);
	g_free(data->argument);
	dbus_connection_unref(data->connection);
	g_free(data);
}

static void filter_data_call_and_free(struct filter_data *data)
{
	GSList *l;

	for (l = data->callbacks; l != NULL; l = l->next) {
		struct filter_callback *cb = l->data;
		if (cb->disc_func)
			cb->disc_func(data->connection, cb->user_data);
		if (cb->destroy_func)
			cb->destroy_func(cb->user_data);
		g_free(cb);
	}

	filter_data_free(data);
}

static struct filter_callback *filter_data_add_callback(
						struct filter_data *data,
						GDBusWatchFunction connect,
						GDBusWatchFunction disconnect,
						GDBusSignalFunction signal,
						GDBusDestroyFunction destroy,
						void *user_data)
{
	struct filter_callback *cb = NULL;

	cb = g_new0(struct filter_callback, 1);

	cb->conn_func = connect;
	cb->disc_func = disconnect;
	cb->signal_func = signal;
	cb->destroy_func = destroy;
	cb->user_data = user_data;
	cb->id = ++listener_id;

	if (data->lock)
		data->processed = g_slist_append(data->processed, cb);
	else
		data->callbacks = g_slist_append(data->callbacks, cb);

	return cb;
}

static void service_data_free(struct service_data *data)
{
	struct filter_callback *callback = data->callback;

	dbus_connection_unref(data->conn);

	if (data->call)
		dbus_pending_call_unref(data->call);

	if (data->id)
		g_source_remove(data->id);

	g_free(data->name);
	g_free(data);

	callback->data = NULL;
}

static gboolean filter_data_remove_callback(struct filter_data *data,
						struct filter_callback *cb)
{
	DBusConnection *connection;

	data->callbacks = g_slist_remove(data->callbacks, cb);
	data->processed = g_slist_remove(data->processed, cb);

	/* Cancel pending operations */
	if (cb->data) {
		if (cb->data->call)
			dbus_pending_call_cancel(cb->data->call);
		service_data_free(cb->data);
	}

	if (cb->destroy_func)
		cb->destroy_func(cb->user_data);

	g_free(cb);

	/* Don't remove the filter if other callbacks exist or data is lock
	 * processing callbacks */
	if (data->callbacks || data->lock)
		return TRUE;

	if (data->registered && !remove_match(data))
		return FALSE;

	connection = dbus_connection_ref(data->connection);
	listeners = g_slist_remove(listeners, data);
	filter_data_free(data);

	/* Remove filter if there are no listeners left for the connection */
	data = filter_data_find(connection, NULL, NULL, NULL, NULL, NULL,
					NULL);
	if (data == NULL)
		dbus_connection_remove_filter(connection, message_filter,
						NULL);

	dbus_connection_unref(connection);

	return TRUE;
}

static DBusHandlerResult signal_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct filter_data *data = user_data;
	struct filter_callback *cb;

	while (data->callbacks) {
		cb = data->callbacks->data;

		if (cb->signal_func && !cb->signal_func(connection, message,
							cb->user_data)) {
			filter_data_remove_callback(data, cb);
			continue;
		}

		/* Check if the watch was removed/freed by the callback
		 * function */
		if (!g_slist_find(data->callbacks, cb))
			continue;

		data->callbacks = g_slist_remove(data->callbacks, cb);
		data->processed = g_slist_append(data->processed, cb);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void update_name_cache(const char *name, const char *owner)
{
	GSList *l;

	for (l = listeners; l != NULL; l = l->next) {
		struct filter_data *data = l->data;

		if (g_strcmp0(data->name, name) != 0)
			continue;

		g_free(data->owner);
		data->owner = g_strdup(owner);
	}
}

static const char *check_name_cache(const char *name)
{
	GSList *l;

	for (l = listeners; l != NULL; l = l->next) {
		struct filter_data *data = l->data;

		if (g_strcmp0(data->name, name) != 0)
			continue;

		return data->owner;
	}

	return NULL;
}

static DBusHandlerResult service_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct filter_data *data = user_data;
	struct filter_callback *cb;
	char *name, *old, *new;

	if (!dbus_message_get_args(message, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &old,
				DBUS_TYPE_STRING, &new,
				DBUS_TYPE_INVALID)) {
		error("Invalid arguments for NameOwnerChanged signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	update_name_cache(name, new);

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

		/* Only auto remove if it is a bus name watch */
		if (data->argument[0] == ':' &&
				(cb->conn_func == NULL || cb->disc_func == NULL)) {
			filter_data_remove_callback(data, cb);
			continue;
		}

		data->callbacks = g_slist_remove(data->callbacks, cb);
		data->processed = g_slist_append(data->processed, cb);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


static DBusHandlerResult message_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct filter_data *data;
	const char *sender, *path, *iface, *member, *arg = NULL;

	/* Only filter signals */
	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	sender = dbus_message_get_sender(message);
	path = dbus_message_get_path(message);
	iface = dbus_message_get_interface(message);
	member = dbus_message_get_member(message);
	dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &arg, DBUS_TYPE_INVALID);

	/* Sender is always bus name */
	data = filter_data_find(connection, NULL, sender, path, iface, member,
					arg);
	if (data == NULL) {
		error("Got %s.%s signal which has no listeners", iface, member);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (data->handle_func) {
		data->lock = TRUE;

		data->handle_func(connection, message, data);

		data->callbacks = data->processed;
		data->processed = NULL;
		data->lock = FALSE;
	}

	if (data->callbacks)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	remove_match(data);

	listeners = g_slist_remove(listeners, data);
	filter_data_free(data);

	/* Remove filter if there no listener left for the connection */
	data = filter_data_find(connection, NULL, NULL, NULL, NULL, NULL,
					NULL);
	if (data == NULL)
		dbus_connection_remove_filter(connection, message_filter,
						NULL);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static gboolean update_service(void *user_data)
{
	struct service_data *data = user_data;
	struct filter_callback *cb = data->callback;

	update_name_cache(data->name, data->owner);
	if (cb->conn_func)
		cb->conn_func(data->conn, cb->user_data);

	service_data_free(data);

	return FALSE;
}

static void service_reply(DBusPendingCall *call, void *user_data)
{
	struct service_data *data = user_data;
	DBusMessage *reply;
	DBusError err;

	reply = dbus_pending_call_steal_reply(call);
	if (reply == NULL)
		return;

	dbus_error_init(&err);

	if (dbus_set_error_from_message(&err, reply))
		goto fail;

	if (dbus_message_get_args(reply, &err,
					DBUS_TYPE_STRING, &data->owner,
						DBUS_TYPE_INVALID) == FALSE)
		goto fail;

	update_service(data);

	goto done;

fail:
	error("%s", err.message);
	dbus_error_free(&err);
	service_data_free(data);
done:
	dbus_message_unref(reply);
}

static void check_service(DBusConnection *connection,
					const char *name,
					struct filter_callback *callback)
{
	DBusMessage *message;
	struct service_data *data;

	data = g_try_malloc0(sizeof(*data));
	if (data == NULL) {
		error("Can't allocate data structure");
		return;
	}

	data->conn = dbus_connection_ref(connection);
	data->name = g_strdup(name);
	data->callback = callback;
	callback->data = data;

	data->owner = check_name_cache(name);
	if (data->owner != NULL) {
		data->id = g_idle_add(update_service, data);
		return;
	}

	message = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
			DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "GetNameOwner");
	if (message == NULL) {
		error("Can't allocate new message");
		g_free(data);
		return;
	}

	dbus_message_append_args(message, DBUS_TYPE_STRING, &name,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
							&data->call, -1) == FALSE) {
		error("Failed to execute method call");
		g_free(data);
		goto done;
	}

	if (data->call == NULL) {
		error("D-Bus connection not available");
		g_free(data);
		goto done;
	}

	dbus_pending_call_set_notify(data->call, service_reply, data, NULL);

done:
	dbus_message_unref(message);
}

guint g_dbus_add_service_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction connect,
				GDBusWatchFunction disconnect,
				void *user_data, GDBusDestroyFunction destroy)
{
	struct filter_data *data;
	struct filter_callback *cb;

	if (name == NULL)
		return 0;

	data = filter_data_get(connection, service_filter, NULL, NULL,
				DBUS_INTERFACE_DBUS, "NameOwnerChanged",
				name);
	if (data == NULL)
		return 0;

	cb = filter_data_add_callback(data, connect, disconnect, NULL, NULL,
					user_data);
	if (cb == NULL)
		return 0;

	if (connect)
		check_service(connection, name, cb);

	return cb->id;
}

guint g_dbus_add_disconnect_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction func,
				void *user_data, GDBusDestroyFunction destroy)
{
	return g_dbus_add_service_watch(connection, name, NULL, func,
							user_data, destroy);
}

guint g_dbus_add_signal_watch(DBusConnection *connection,
				const char *sender, const char *path,
				const char *interface, const char *member,
				GDBusSignalFunction function, void *user_data,
				GDBusDestroyFunction destroy)
{
	struct filter_data *data;
	struct filter_callback *cb;

	data = filter_data_get(connection, signal_filter, sender, path,
				interface, member, NULL);
	if (data == NULL)
		return 0;

	cb = filter_data_add_callback(data, NULL, NULL, function, destroy,
					user_data);
	if (cb == NULL)
		return 0;

	if (data->name != NULL && data->name_watch == 0)
		data->name_watch = g_dbus_add_service_watch(connection,
							data->name, NULL,
							NULL, NULL, NULL);

	return cb->id;
}

gboolean g_dbus_remove_watch(DBusConnection *connection, guint id)
{
	struct filter_data *data;
	struct filter_callback *cb;
	GSList *ldata;

	if (id == 0)
		return FALSE;

	for (ldata = listeners; ldata; ldata = ldata->next) {
		data = ldata->data;

		cb = filter_data_find_callback(data, id);
		if (cb) {
			filter_data_remove_callback(data, cb);
			return TRUE;
		}
	}

	return FALSE;
}

void g_dbus_remove_all_watches(DBusConnection *connection)
{
	struct filter_data *data;

	while ((data = filter_data_find(connection, NULL, NULL, NULL, NULL,
					NULL, NULL))) {
		listeners = g_slist_remove(listeners, data);
		filter_data_call_and_free(data);
	}

	dbus_connection_remove_filter(connection, message_filter, NULL);
}
