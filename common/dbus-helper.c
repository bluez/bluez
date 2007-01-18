/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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
#include <string.h>

#include <dbus/dbus.h>

#include "logging.h"

#include "dbus-helper.h"

struct generic_data {
	void *user_data;
	DBusObjectPathUnregisterFunction unregister_function;
	const char *interface;
	DBusMethodVTable *methods;
	char *introspect;
};

DBusHandlerResult dbus_connection_send_and_unref(DBusConnection *connection,
							DBusMessage *message)
{
	if (message) {
		dbus_connection_send(connection, message, NULL);
		dbus_message_unref(message);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult introspect(DBusConnection *connection,
				DBusMessage *message, struct generic_data *data)
{
	DBusMessage *reply;

	if (dbus_message_has_signature(message,
				DBUS_TYPE_INVALID_AS_STRING) == FALSE) {
		error("Unexpected signature to introspect call");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!data->introspect)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &data->introspect,
					DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(connection, reply);
}

static void generic_unregister(DBusConnection *connection, void *user_data)
{
	struct generic_data *data = user_data;

	if (data->unregister_function)
		data->unregister_function(connection, data->user_data);

	free(data);
}

static DBusHandlerResult generic_message(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	DBusMethodVTable *current;

	if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE,
							"Introspect") == TRUE)
		return introspect(connection, message, data);

	for (current = data->methods;
			current->name && current->message_function; current++) {
		if (dbus_message_is_method_call(message,
				data->interface, current->name) == FALSE)
			continue;

		if (dbus_message_has_signature(message,
				current->signature) == TRUE)
			return current->message_function(connection,
						message, data->user_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable generic_table = {
	.unregister_function	= generic_unregister,
	.message_function	= generic_message,
};

dbus_bool_t dbus_connection_create_object_path(DBusConnection *connection,
					const char *path, void *user_data,
					DBusObjectPathUnregisterFunction function)
{
	struct generic_data *data;

	data = malloc(sizeof(*data));
	if (!data)
		return FALSE;

	memset(data, 0, sizeof(*data));

	data->user_data = user_data;
	data->unregister_function = function;

	if (dbus_connection_register_object_path(connection, path,
					&generic_table, data) == FALSE) {
		free(data);
		return FALSE;
	}

	return TRUE;
}

dbus_bool_t dbus_connection_destroy_object_path(DBusConnection *connection,
							const char *path)
{
	return dbus_connection_unregister_object_path(connection, path);
}

static char simple_xml[] = DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE "<node></node>";

dbus_bool_t dbus_connection_register_interface(DBusConnection *connection,
					const char *path, const char *interface,
					DBusMethodVTable *methods,
					DBusPropertyVTable *properties)
{
	struct generic_data *data;
	DBusMethodVTable *current;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == FALSE)
		return FALSE;

	data->interface = interface;
	data->methods = methods;

	for (current = data->methods; current->name; current++) {
		debug("Adding introspection data for %s.%s",
						interface, current->name);
	}

	data->introspect = simple_xml;

	return TRUE;
}
