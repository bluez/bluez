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
#include <bluetooth/sdp.h>

#include <gdbus.h>

#include "plugin.h"
#include "device.h"
#include "adapter.h"
#include "logging.h"
#include "manager.h"
#include "port.h"

#define SERIAL_PORT_UUID	"00001101-0000-1000-8000-00805F9B34FB"
#define DIALUP_NET_UUID		"00001103-0000-1000-8000-00805F9B34FB"

#define SERIAL_INTERFACE     "org.bluez.Serial"
#define ERROR_INVALID_ARGS   "org.bluez.Error.InvalidArguments"
#define ERROR_DOES_NOT_EXIST "org.bluez.Error.DoesNotExist"

static DBusMessage *serial_connect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_device *device = user_data;
	const char *target;
	char src[18], dst[18];

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &target,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	ba2str(&device->src, src);
	ba2str(&device->dst, dst);

	service_connect(conn, msg, src, dst, target);

	return NULL;
}

static DBusMessage *serial_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *device, *sender;
	int err, id;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &device,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	sender = dbus_message_get_sender(msg);

	if (sscanf(device, "/dev/rfcomm%d", &id) != 1)
		return g_dbus_create_error(msg, ERROR_INVALID_ARGS, NULL);

	err = port_remove_listener(sender, device);
	if (err < 0)
		return g_dbus_create_error(msg, ERROR_DOES_NOT_EXIST, NULL);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable serial_methods[] = {
	{ "Connect",    "s", "s", serial_connect, G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect", "s", "",  serial_disconnect },
	{ }
};

static DBusConnection *conn;

static int serial_probe(struct btd_device *device)
{
	DBG("path %s", device->path);

	if (g_dbus_register_interface(conn, device->path, SERIAL_INTERFACE,
						serial_methods, NULL, NULL,
							device, NULL) == FALSE)
		return -1;

	return 0;
}

static void serial_remove(struct btd_device *device)
{
	DBG("path %s", device->path);

	g_dbus_unregister_interface(conn, device->path, SERIAL_INTERFACE);
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
