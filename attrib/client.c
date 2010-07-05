/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>

#include "log.h"
#include "gdbus.h"

#include "client.h"

#define CHAR_INTERFACE "org.bluez.Characteristic"

static DBusConnection *connection;

static DBusMessage *get_characteristics(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *register_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_watcher(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable char_methods[] = {
	{ "GetCharacteristics",	"",	"a{oa{sv}}", get_characteristics},
	{ "RegisterCharacteristicsWatcher",	"o", "",
						register_watcher	},
	{ "UnregisterCharacteristicsWatcher",	"o", "",
						unregister_watcher	},
	{ }
};

int attrib_client_register(const char *path)
{
	if (g_dbus_register_interface(connection, path,
				CHAR_INTERFACE,
				char_methods, NULL, NULL,
				NULL, NULL) == FALSE) {
		error("D-Bus failed to register %s interface", CHAR_INTERFACE);
		return -1;
	}

	DBG("Registered interface %s on path %s", CHAR_INTERFACE, path);

	return 0;
}

void attrib_client_unregister(const char *path)
{
	g_dbus_unregister_interface(connection, path, CHAR_INTERFACE);

	DBG("Unregistered interface %s on path %s", CHAR_INTERFACE, path);
}

int attrib_client_init(DBusConnection *conn)
{

	connection = dbus_connection_ref(conn);

	return 0;
}

void attrib_client_exit(void)
{
	dbus_connection_unref(connection);
}
