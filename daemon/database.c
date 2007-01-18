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
#include "database.h"

#define DATABASE_INTERFACE "org.bluez.Database"

static DBusConnection *connection = NULL;

static DBusHandlerResult add_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult remove_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusMethodVTable database_table[] = {
	{ "AddServiceRecord", add_service_record,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_UINT32_AS_STRING },
	{ "RemoveServiceRecord", remove_service_record,
		DBUS_TYPE_UINT32_AS_STRING, DBUS_TYPE_INVALID_AS_STRING },
	{ }
};

int database_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	info("Starting database interface");

	if (dbus_connection_register_interface(connection, SYSTEM_PATH,
			DATABASE_INTERFACE, database_table, NULL) == FALSE) {
		error("Database interface registration failed");
		dbus_connection_unref(connection);
		return -1;
	}

	return 0;
}

void database_exit(void)
{
	info("Stopping database interface");

	dbus_connection_unref(connection);

	connection = NULL;
}
