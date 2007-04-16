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

#include <glib.h>

#include <dbus/dbus.h>

#include "logging.h"

#include "dbus-helper.h"

struct generic_data {
	void *user_data;
	DBusObjectPathUnregisterFunction unregister_function;
	GSList *interfaces;
	char *introspect;
};

struct interface_data {
	const char *interface;
	DBusMethodVTable *methods;
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

	g_free(data);
}

static struct interface_data *find_interface(GSList *interfaces,
							const char *interface)
{
	GSList *list;

	for (list = interfaces; list; list = list->next) {
		struct interface_data *iface = list->data;
		if (!strcmp(interface, iface->interface))
			return iface;
	}

	return NULL;
}

static DBusHandlerResult generic_message(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct generic_data *data = user_data;
	struct interface_data *iface;
	DBusMethodVTable *current;
	const char *interface;

	if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE,
							"Introspect") == TRUE)
		return introspect(connection, message, data);

	interface = dbus_message_get_interface(message);

	iface = find_interface(data->interfaces, interface);
	if (!iface)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	for (current = iface->methods;
			current->name && current->message_function; current++) {
		if (dbus_message_is_method_call(message,
				iface->interface, current->name) == FALSE)
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

static char simple_xml[] = DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE "<node></node>";

dbus_bool_t dbus_connection_create_object_path(DBusConnection *connection,
					const char *path, void *user_data,
					DBusObjectPathUnregisterFunction function)
{
	struct generic_data *data;

	data = g_new0(struct generic_data, 1);

	data->user_data = user_data;
	data->unregister_function = function;

	data->interfaces = NULL;
	data->introspect = simple_xml;

	if (dbus_connection_register_object_path(connection, path,
					&generic_table, data) == FALSE) {
		g_free(data);
		return FALSE;
	}

	return TRUE;
}

dbus_bool_t dbus_connection_destroy_object_path(DBusConnection *connection,
							const char *path)
{
	return dbus_connection_unregister_object_path(connection, path);
}

dbus_bool_t dbus_connection_register_interface(DBusConnection *connection,
					const char *path, const char *interface,
					DBusMethodVTable *methods,
					DBusPropertyVTable *properties)
{
	struct generic_data *data;
	struct interface_data *iface;
	DBusMethodVTable *current;

	if (dbus_connection_get_object_path_data(connection, path,
						(void *) &data) == FALSE)
		return FALSE;

	iface = g_new0(struct interface_data, 1);

	iface->interface = interface;
	iface->methods = methods;

	for (current = iface->methods; current->name; current++) {
		debug("Adding introspection data for %s.%s",
						interface, current->name);
	}

	data->interfaces = g_slist_append(data->interfaces, iface);

	return TRUE;
}

dbus_bool_t dbus_connection_unregister_interface(DBusConnection *connection,
					const char *path, const char *interface)
{
	return TRUE;
}

void dbus_message_iter_append_dict_entry(DBusMessageIter *dict,
					const char *key, int type, void *val)
{
	DBusMessageIter entry;
	DBusMessageIter value;
	char *sig;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	switch (type) {
	case DBUS_TYPE_STRING:
		sig = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		sig = DBUS_TYPE_UINT32_AS_STRING;
		break;
	case DBUS_TYPE_BOOLEAN:
		sig = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	default:
		sig = DBUS_TYPE_VARIANT_AS_STRING;
		break;
	}

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(&entry, &value);

	dbus_message_iter_close_container(dict, &entry);
}
