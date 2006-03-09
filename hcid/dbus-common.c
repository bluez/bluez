/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2005-2006  Johan Hedberg <johan.hedberg@nokia.com>
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
#include <stdlib.h>
#include <string.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "list.h"
#include "dbus.h"

static int name_listener_initialized = 0;

struct name_callback {
	name_cb_t func;
	void *user_data;
};

struct name_data {
	char *name;
	struct slist *callbacks;
};

static struct slist *name_listeners = NULL;

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

	memset(data, sizeof(struct name_data), 0);

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
	if (!cb)
		return;

	data->callbacks = slist_remove(data->callbacks, cb);
	free(cb);

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

	debug("name_listener_add(%s)", name);

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

	snprintf(match_string, sizeof(match_string),
			"interface=%s,member=NameOwnerChanged,arg0=%s",
			DBUS_INTERFACE_DBUS, name);

	dbus_error_init(&err);
	dbus_bus_add_match(connection, match_string, &err);

	if (dbus_error_is_set(&err)) {
		error("Adding owner match rule for %s failed: %s", name, err.message);
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
