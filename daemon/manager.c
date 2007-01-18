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

#include "logging.h"

#include "manager.h"

#define MANAGER_PATH "/org/bluez"

static DBusConnection *connection = NULL;

static DBusHandlerResult manager_handler(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable manager_table = {
	.message_function = manager_handler,
};

int manager_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	info("Starting manager interface");

	if (dbus_connection_register_object_path(connection,
			MANAGER_PATH, &manager_table, NULL) == FALSE) {
		error("Manager path registration failed");
		dbus_connection_unref(connection);
		return -1;
	}

	return 0;
}

void manager_exit(void)
{
	info("Stopping manager interface");

	dbus_connection_unregister_object_path(connection, MANAGER_PATH);

	dbus_connection_unref(connection);

	connection = NULL;
}
