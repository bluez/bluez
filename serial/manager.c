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

#include <errno.h>
#include <string.h>

#include "dbus.h"
#include "logging.h"

#include "manager.h"

#define SERIAL_PATH "/org/bluez/serial"
#define SERIAL_MANAGER_INTERFACE "org.bluez.serial.Manager"
#define SERIAL_ERROR_INTERFACE "org.bluez.serial.Error"

static DBusConnection *connection = NULL;

DBusHandlerResult err_unknown_port(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				SERIAL_ERROR_INTERFACE ".UnknownPort",
				"Unknown port path"));
}

static DBusHandlerResult create_port(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult remove_port(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult list_ports(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult manager_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path, *iface, *member;

	path = dbus_message_get_path(msg);
	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Catching fallback paths */
	if (strcmp(SERIAL_PATH, path) != 0)
		return err_unknown_port(conn, msg);

	/* Accept messages from the manager interface only */
	if (strcmp(SERIAL_MANAGER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "CreatePort") == 0)
		return create_port(conn, msg, data);

	if (strcmp(member, "RemovePort") == 0)
		return remove_port(conn, msg, data);

	if (strcmp(member, "ListPorts") == 0)
		return list_ports(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void manager_unregister(DBusConnection *conn, void *data)
{
}

/* Virtual table to handle manager object path hierarchy */
static const DBusObjectPathVTable manager_table = {
	.message_function = manager_message,
	.unregister_function = manager_unregister,
};

int serial_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	/* Fallback to catch invalid serial path */
	if (dbus_connection_register_fallback(connection, SERIAL_PATH,
						&manager_table, NULL) == FALSE) {
		error("D-Bus failed to register %s path", SERIAL_PATH);
		dbus_connection_unref(connection);

		return -1;
	}

	info("Registered manager path:%s", SERIAL_PATH);

	return 0;
}

void serial_exit(void)
{
	dbus_connection_unregister_object_path(connection, SERIAL_PATH);

	dbus_connection_unref(connection);
	connection = NULL;
}
