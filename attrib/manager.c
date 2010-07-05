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

#include "../src/adapter.h"
#include "../src/device.h"

#include "manager.h"
#include "client.h"

#define GATT_UUID	"00001801-0000-1000-8000-00805f9b34fb"

static DBusConnection *connection;

static int client_probe(struct btd_device *device, GSList *uuids)
{
	const char *path = device_get_path(device);

	return attrib_client_register(path);
}

static void client_remove(struct btd_device *device)
{
	const char *path = device_get_path(device);

	attrib_client_unregister(path);
}

static struct btd_device_driver client_driver = {
	.name = "gatt-client",
	.uuids = BTD_UUIDS(GATT_UUID),
	.probe = client_probe,
	.remove = client_remove,
};

static int server_probe(struct btd_adapter *adapter)
{
	return 0;
}

static void server_remove(struct btd_adapter *adapter)
{
}

static struct btd_adapter_driver attrib_server_driver = {
	.name = "attribute-server",
	.probe = server_probe,
	.remove = server_remove,
};

int attrib_manager_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	attrib_client_init(connection);

	btd_register_adapter_driver(&attrib_server_driver);
	btd_register_device_driver(&client_driver);

	return 0;
}

void attrib_manager_exit(void)
{
	btd_unregister_adapter_driver(&attrib_server_driver);
	btd_unregister_device_driver(&client_driver);

	attrib_client_exit();
	dbus_connection_unref(connection);
}
