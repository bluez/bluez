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


#include <errno.h>
#include <sys/types.h>

#include <bluetooth/bluetooth.h>

#include <gdbus.h>

#include "plugin.h"
#include "device.h"
#include "logging.h"
#include "manager.h"

#define SERIAL_PORT_UUID	"00001101-0000-1000-8000-00805F9B34FB"
#define DIALUP_NET_UUID		"00001103-0000-1000-8000-00805F9B34FB"

#define SERIAL_INTERFACE "org.bluez.Serial"

static DBusMessage *serial_connect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *target, *device = "/dev/rfcomm0";

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &target,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &device,
							DBUS_TYPE_INVALID);
}

static DBusMessage *serial_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *device;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &device,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable serial_methods[] = {
	{ "Connect",    "s", "s", serial_connect    },
	{ "Disconnect", "s", "",  serial_disconnect },
	{ }
};

static DBusConnection *conn;

static int serial_probe(const char *path)
{
	DBG("path %s", path);

	if (g_dbus_register_interface(conn, path, SERIAL_INTERFACE,
						serial_methods, NULL, NULL,
							NULL, NULL) == FALSE)
		return -1;

	return 0;
}

static void serial_remove(const char *path)
{
	DBG("path %s", path);

	g_dbus_unregister_interface(conn, path, SERIAL_INTERFACE);
}

static struct btd_device_driver serial_driver = {
	.name	= "serial",
	.uuids	= BTD_UUIDS(SERIAL_PORT_UUID, DIALUP_NET_UUID),
	.probe	= serial_probe,
	.remove	= serial_remove,
};

static int serial_init(void)
{
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL)
		return -EIO;

	if (serial_manager_init(conn) < 0) {
		dbus_connection_unref(conn);
		return -EIO;
	}

	btd_register_device_driver(&serial_driver);

	return 0;
}

static void serial_exit(void)
{
	btd_unregister_device_driver(&serial_driver);

	serial_manager_exit();

	dbus_connection_unref(conn);
}

BLUETOOTH_PLUGIN_DEFINE("serial", serial_init, serial_exit)
