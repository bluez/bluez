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

#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"

#include "system.h"
#include "adapter.h"
#include "service.h"
#include "manager.h"

#define MANAGER_INTERFACE "org.bluez.Manager"

static DBusConnection *connection = NULL;

extern DBusHandlerResult manager_list_adapters(DBusConnection *conn,
						DBusMessage *msg, void *data);

extern DBusHandlerResult manager_find_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data);

extern DBusHandlerResult manager_default_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data);

extern DBusHandlerResult manager_list_services(DBusConnection *conn,
						DBusMessage *msg, void *data);

extern DBusHandlerResult manager_find_service(DBusConnection *conn,
						DBusMessage *msg, void *data);

extern DBusHandlerResult manager_activate_service(DBusConnection *conn,
						DBusMessage *msg, void *data);

static DBusMethodVTable manager_table[] = {
	{ "ListAdapters", manager_list_adapters,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_STRING_ARRAY_AS_STRING },
	{ "FindAdapter", manager_find_adapter,
		DBUS_TYPE_STRING_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ "DefaultAdapter", manager_default_adapter,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ "ListServices", manager_list_services,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_STRING_ARRAY_AS_STRING },
	{ "FindService", manager_find_service,
		DBUS_TYPE_STRING_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ "ActivateService", manager_activate_service,
		DBUS_TYPE_STRING_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ }
};

int manager_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	info("Starting manager interface");

	if (dbus_connection_register_interface(connection, SYSTEM_PATH,
			MANAGER_INTERFACE, manager_table, NULL, NULL) == FALSE) {
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
