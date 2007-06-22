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

#include <glib.h>
#include <dbus/dbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"

#include "device.h"

void device_finish_sdp_transaction(struct device *device)
{
	char address[18], *addr_ptr = address;
	DBusMessage *msg, *reply;
	DBusError derr;

	ba2str(&device->bda, address);

	msg = dbus_message_new_method_call("org.bluez", device->adapter_path,
						"org.bluez.Adapter",
						"FinishRemoteServiceTransaction");
	if (!msg) {
		error("Unable to allocate new method call");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(device->conn, msg, -1,
								&derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) ||
			dbus_set_error_from_message(&derr, reply)) {
		error("FinishRemoteServiceTransaction(%s) failed: %s",
				address, derr.message);
		dbus_error_free(&derr);
		return;
	}

	dbus_message_unref(reply);
}

static DBusHandlerResult device_get_address(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	DBusMessage *reply;
	char address[18], *ptr = address;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	ba2str(&device->bda, address);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult device_get_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	DBusMessageIter iter, array_iter;
	struct device *device = data;
	DBusMessage *reply;
	const char *iface;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	if (device->headset &&
		headset_get_state(device->headset) >= HEADSET_STATE_CONNECTED) {
		iface = AUDIO_HEADSET_INTERFACE;
		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &iface);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusMethodVTable device_methods[] = {
	{ "GetAddress",			device_get_address,
		"",	"s"	},
	{ "GetConnectedInterfaces",	device_get_connected,
		"",	"s"	},
	{ NULL, NULL, NULL, NULL }
};

static void device_free(struct device *device)
{
	if (device->headset)
		headset_free(device);

	if (device->conn)
		dbus_connection_unref(device->conn);

	if (device->adapter_path)
		g_free(device->adapter_path);

	if (device->path)
		g_free(device->path);

	g_free(device);
}

static void device_unregister(DBusConnection *conn, void *data)
{
	struct device *device = data;

	info("Unregistered device path:%s", device->path);

	device_free(device);
}

struct device * device_register(DBusConnection *conn, const char *path, bdaddr_t *bda)
{
	struct device *device;
	bdaddr_t src;
	int dev_id;

	if (!conn || !path)
		return NULL;

	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(NULL);
	if ((dev_id < 0) ||  (hci_devba(dev_id, &src) < 0))
		return NULL;

	device = g_new0(struct device, 1);

	if (!dbus_connection_create_object_path(conn, path, device,
		device_unregister)) {
		error("D-Bus failed to register %s path", path);
		device_free(device);
		return NULL;
	}

	if (!dbus_connection_register_interface(conn,
						path,
						AUDIO_DEVICE_INTERFACE,
						device_methods, NULL, NULL)) {
		error("Failed to register %s interface to %s",
				AUDIO_DEVICE_INTERFACE, path);
		dbus_connection_destroy_object_path(conn, path);
		return NULL;
	}

	device->path = g_strdup(path);
	bacpy(&device->bda, bda);
	device->conn = dbus_connection_ref(conn);
	device->adapter_path = g_malloc0(16);
	snprintf(device->adapter_path, 16, "/org/bluez/hci%d", dev_id);

	return device;
}
