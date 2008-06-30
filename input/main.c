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

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include <gdbus.h>

#include "plugin.h"
#include "../hcid/device.h"
#include "logging.h"
#include "dbus-service.h"
#include "manager.h"

#define INPUT_INTERFACE "org.bluez.Input"

static DBusMessage *input_connect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *input_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *input_is_connected(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	dbus_bool_t connected = FALSE;

	return g_dbus_create_reply(msg, DBUS_TYPE_BOOLEAN, &connected,
							DBUS_TYPE_INVALID);
}

static GDBusMethodTable input_methods[] = {
	{ "Connect",     "", "",  input_connect      },
	{ "Disconnect",  "", "",  input_disconnect   },
	{ "IsConnected", "", "b", input_is_connected },
	{ }
};

static GDBusSignalTable input_signals[] = {
	{ "Connected",    "" },
	{ "Disconnected", "" },
	{ }
};

static DBusConnection *conn;

static int input_probe(struct btd_device *device)
{
	DBG("path %s", device->path);

	if (g_dbus_register_interface(conn, device->path, INPUT_INTERFACE,
					input_methods, input_signals, NULL,
							device, NULL) == FALSE)
		return -1;

	return 0;
}

static void input_remove(struct btd_device *device)
{
	DBG("path %s", device->path);

	g_dbus_unregister_interface(conn, device->path, INPUT_INTERFACE);
}

static struct btd_device_driver input_driver = {
	.name	= "input",
	.uuids	= BTD_UUIDS("00001124-0000-1000-8000-00805f9b34fb"),
	.probe	= input_probe,
	.remove	= input_remove,
};

static GKeyFile *load_config_file(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static int input_init(void)
{
	GKeyFile *config;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL)
		return -EIO;

	config = load_config_file(CONFIGDIR "/input.conf");

	if (input_manager_init(conn, config) < 0) {
		dbus_connection_unref(conn);
		return -EIO;
	}

	if (config)
		g_key_file_free(config);

	btd_register_device_driver(&input_driver);

	return 0;
}

static void input_exit(void)
{
	btd_unregister_device_driver(&input_driver);

	input_manager_exit();

	dbus_connection_unref(conn);
}

BLUETOOTH_PLUGIN_DEFINE("input", input_init, input_exit)
