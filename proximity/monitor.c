/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <gdbus.h>

#include "log.h"

#include "monitor.h"

#define PROXIMITY_INTERFACE "org.bluez.Proximity"
#define PROXIMITY_PATH "/org/bluez/proximity"

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable monitor_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties	},
	{ "SetProperty",	"sv",	"",		set_property,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ }
};

static GDBusSignalTable monitor_signals[] = {
	{ "PropertyChanged",	"sv"	},
	{ }
};

int monitor_register(DBusConnection *conn)
{
	int ret = -1;

	if (g_dbus_register_interface(conn, PROXIMITY_PATH,
					PROXIMITY_INTERFACE,
					monitor_methods, monitor_signals,
					NULL, NULL, NULL) == TRUE) {
		DBG("Registered interface %s on path %s", PROXIMITY_INTERFACE,
							PROXIMITY_PATH);
		ret = 0;

	}

	error("D-Bus failed to register %s interface", PROXIMITY_INTERFACE);

	return ret;
}

void monitor_unregister(DBusConnection *conn)
{
	g_dbus_unregister_interface(conn, PROXIMITY_PATH, PROXIMITY_INTERFACE);
}
