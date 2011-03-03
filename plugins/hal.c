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

#include <errno.h>
#include <dbus/dbus.h>

#include <bluetooth/bluetooth.h>

#include "plugin.h"
#include "adapter.h"
#include "log.h"

static void formfactor_reply(DBusPendingCall *call, void *user_data)
{
	struct btd_adapter *adapter = user_data;
	const char *formfactor = NULL;
	DBusMessage *reply;
	uint8_t minor = 0;

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_set_error_from_message(NULL, reply) == TRUE) {
		error("Failed to access HAL");
		dbus_message_unref(reply);
		return;
	}

	if (dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &formfactor,
						DBUS_TYPE_INVALID) == FALSE) {
		error("Wrong formfactor arguments");
		dbus_message_unref(reply);
		return;
	}

	DBG("Computer is classified as %s", formfactor);

	if (formfactor != NULL) {
		if (g_str_equal(formfactor, "laptop") == TRUE)
			minor |= (1 << 2) | (1 << 3);
		else if (g_str_equal(formfactor, "desktop") == TRUE)
			minor |= 1 << 2;
		else if (g_str_equal(formfactor, "server") == TRUE)
			minor |= 1 << 3;
		else if (g_str_equal(formfactor, "handheld") == TRUE)
			minor += 1 << 4;
	}

	dbus_message_unref(reply);

	/* Computer major class */
	DBG("Setting 0x%06x for major/minor device class", (1 << 8) | minor);

	btd_adapter_set_class(adapter, 0x01, minor);
}

static DBusConnection *connection;

static int hal_probe(struct btd_adapter *adapter)
{
	const char *property = "system.formfactor";
	DBusMessage *message;
	DBusPendingCall *call;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -ENOMEM;

	message = dbus_message_new_method_call("org.freedesktop.Hal",
				"/org/freedesktop/Hal/devices/computer",
						"org.freedesktop.Hal.Device",
							"GetPropertyString");
	if (message == NULL) {
		error("Failed to create formfactor request");
		dbus_connection_unref(connection);
		return -ENOMEM;
	}

	dbus_message_append_args(message, DBUS_TYPE_STRING, &property,
							DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
						&call, -1) == FALSE) {
		error("Failed to send formfactor request");
		dbus_message_unref(message);
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, formfactor_reply, adapter, NULL);

	dbus_pending_call_unref(call);

	dbus_message_unref(message);

	return 0;
}

static void hal_remove(struct btd_adapter *adapter)
{
	dbus_connection_unref(connection);
}

static struct btd_adapter_driver hal_driver = {
	.name	= "hal",
	.probe	= hal_probe,
	.remove	= hal_remove,
};

static int hal_init(void)
{
	return btd_register_adapter_driver(&hal_driver);
}

static void hal_exit(void)
{
	btd_unregister_adapter_driver(&hal_driver);
}

BLUETOOTH_PLUGIN_DEFINE(hal, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_LOW, hal_init, hal_exit)
