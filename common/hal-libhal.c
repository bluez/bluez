/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <dbus/dbus.h>
#include <hal/libhal.h>

#include "logging.h"
#include "dbus.h"

#include "hal.h"

static LibHalContext *hal_ctx = NULL;

static DBusHandlerResult filter_function(DBusConnection *connection,
					DBusMessage *message, void *userdata)
{
	info("filter_function: sender=%s destination=%s obj_path=%s interface=%s method=%s",
	     dbus_message_get_sender (message),
	     dbus_message_get_destination (message),
	     dbus_message_get_path (message),
	     dbus_message_get_interface (message),
	     dbus_message_get_member (message));

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int hal_init(DBusConnection *conn)
{
	hal_ctx = libhal_ctx_new();
	if (!hal_ctx)
		return -ENOMEM;

	dbus_connection_add_filter(conn, filter_function, NULL, NULL);

	if (libhal_ctx_set_dbus_connection(hal_ctx, conn) == FALSE) {
		error("Failed to connect HAL via system bus");
		libhal_ctx_free(hal_ctx);
		hal_ctx = NULL;
		return -EIO;
	}

	if (libhal_ctx_init(hal_ctx, NULL) == FALSE) {
		error("Unable to init HAL context");
		libhal_ctx_free(hal_ctx);
		hal_ctx = NULL;
		return -EIO;
	}

	return 0;
}

void hal_cleanup(void)
{
	if (!hal_ctx)
		return;

	libhal_ctx_shutdown(hal_ctx, NULL);

	libhal_ctx_free(hal_ctx);

	hal_ctx = NULL;
}

int hal_create_device(struct hal_device *device)
{
	DBusError err;
	char udi[128], *dev;
	char *str = "00000000-0000-1000-8000-00805f9b34fb";

	dev = libhal_new_device(hal_ctx, NULL);

	if (libhal_device_set_property_string(hal_ctx, dev,
				"bluetooth.uuid", str, NULL) == FALSE) {
		error("Failed to add UUID property");
	}

	if (libhal_device_set_property_bool(hal_ctx, dev,
				"bluetooth.is_connected", FALSE, NULL) == FALSE) {
		error("Failed to add connected state property");
	}

	if (libhal_device_add_capability(hal_ctx, dev,
					"bluetooth", NULL) == FALSE) {
		error("Failed to add device capability");
	}

	sprintf(udi, "/org/freedesktop/Hal/devices/bluetooth_test");

	dbus_error_init(&err);
	if (libhal_device_claim_interface(hal_ctx, dev,
			"org.freedesktop.Hal.Device.MyBluetooth",
				"    <method name=\"Connect\">\n"
				"    </method>\n"
				"    <method name=\"Disconnect\">\n"
				"    </method>\n",
			&err) == FALSE) {
		error("Failed to claim to interface: ", err.message);
		dbus_error_free(&err);
	}

	if (libhal_device_commit_to_gdl(hal_ctx, dev, udi, NULL) == FALSE) {
		error("Failed to create HAL device");
	}

	free(dev);

	return 0;
}

int hal_remove_device(struct hal_device *device)
{
	char udi[128];

	sprintf(udi, "/org/freedesktop/Hal/devices/bluetooth_test");

	if (libhal_remove_device(hal_ctx, udi, NULL) == FALSE) {
		error("Failed to remove HAL device");
	}

	return 0;
}
