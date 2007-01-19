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

#include <dbus/dbus.h>

#include "dbus-helper.h"
#include "logging.h"

#include "system.h"
#include "service.h"
#include "manager.h"

#define MANAGER_INTERFACE "org.bluez.Manager"

static DBusConnection *connection = NULL;

static DBusHandlerResult list_adapters(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter, array;
	DBusMessage *reply;
	const char path[] = "/org/bluez/hci0", *ptr = path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);

	dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &ptr);

	dbus_message_iter_close_container(&iter, &array);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult find_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char path[] = "/org/bluez/hci0", *ptr = path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult default_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char path[] = "/org/bluez/hci0", *ptr = path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult list_services(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = service_list(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult find_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = service_find(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult activate_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = service_activate(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusMethodVTable manager_table[] = {
	{ "ListAdapters", list_adapters,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_STRING_ARRAY_AS_STRING },
	{ "FindAdapter", find_adapter,
		DBUS_TYPE_STRING_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ "DefaultAdapter", default_adapter,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ "ListServices", list_services,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_STRING_ARRAY_AS_STRING },
	{ "FindService", find_service,
		DBUS_TYPE_STRING_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ "ActivateService", activate_service,
		DBUS_TYPE_STRING_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ }
};

int manager_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	info("Starting manager interface");

	if (dbus_connection_register_interface(connection, SYSTEM_PATH,
			MANAGER_INTERFACE, manager_table, NULL) == FALSE) {
		error("Manager interface registration failed");
		dbus_connection_unref(connection);
		return -1;
	}

	return 0;
}

void manager_exit(void)
{
	info("Stopping manager interface");

	dbus_connection_unregister_interface(connection,
					SYSTEM_PATH, MANAGER_INTERFACE);

	dbus_connection_unref(connection);

	connection = NULL;
}
