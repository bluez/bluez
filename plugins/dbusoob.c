/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  ST-Ericsson SA
 *
 *  Author: Szymon Janc <szymon.janc@tieto.com> for ST-Ericsson
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

#include <stdbool.h>

#include <errno.h>
#include <gdbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>

#include "plugin.h"
#include "log.h"
#include "adapter.h"
#include "device.h"
#include "manager.h"
#include "dbus-common.h"
#include "event.h"
#include "error.h"
#include "storage.h"

#define OOB_INTERFACE	"org.bluez.OutOfBand"

struct oob_data {
	char *addr;
	uint8_t *hash;
	uint8_t *randomizer;
	uint32_t class;
	const char *name;
};

static void read_local_data_complete(struct btd_adapter *adapter, uint8_t *hash,
				uint8_t *randomizer, void *user_data)
{
	struct DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	DBusMessage *msg = user_data;

	DBG("");

	if (!hash || !randomizer) {
		reply = btd_error_failed(msg, "Failed to read local OOB data");
		goto done;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto done;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dict_append_array(&dict, "Hash", DBUS_TYPE_BYTE, &hash, 16);
	dict_append_array(&dict, "Randomizer", DBUS_TYPE_BYTE, &randomizer, 16);

	dbus_message_iter_close_container(&iter, &dict);

done:
	dbus_message_unref(msg);

	if (!reply) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	if (!g_dbus_send_message(btd_get_dbus_connection(), reply))
		error("D-Bus send failed");
}

static DBusMessage *read_local_data(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct btd_adapter *adapter = data;
	struct oob_handler *handler;

	if (!btd_adapter_ssp_enabled(adapter))
		return btd_error_not_supported(msg);

	if (btd_adapter_check_oob_handler(adapter))
		return btd_error_in_progress(msg);

	if (btd_adapter_read_local_oob_data(adapter))
		return btd_error_failed(msg, "Request failed.");

	handler = g_new0(struct oob_handler, 1);
	handler->read_local_cb = read_local_data_complete;
	handler->user_data = dbus_message_ref(msg);

	btd_adapter_set_oob_handler(adapter, handler);

	return NULL;
}

static gboolean parse_data(DBusMessageIter *data, struct oob_data *remote_data)
{
	while (dbus_message_iter_get_arg_type(data) == DBUS_TYPE_DICT_ENTRY) {
		const char *key;
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(data, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);
		if (strcasecmp(key, "Hash") == 0) {
			DBusMessageIter array;
			int size;

			if (var != DBUS_TYPE_ARRAY)
				return FALSE;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array,
						&remote_data->hash, &size);

			if (size != 16)
				return FALSE;
		} else if (strcasecmp(key, "Randomizer") == 0) {
			DBusMessageIter array;
			int size;

			if (var != DBUS_TYPE_ARRAY)
				return FALSE;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array,
						&remote_data->randomizer,
						&size);

			if (size != 16)
				return FALSE;
		} else if (strcasecmp(key, "Class") == 0) {
			if (var != DBUS_TYPE_UINT32)
				return FALSE;

			dbus_message_iter_get_basic(&value,
							&remote_data->class);
		} else if (strcasecmp(key, "Name") == 0) {
			if (var != DBUS_TYPE_STRING)
				return FALSE;

			dbus_message_iter_get_basic(&value,
							&remote_data->name);
		}

		dbus_message_iter_next(data);
	}

	if (dbus_message_iter_get_arg_type(data) != DBUS_TYPE_INVALID)
		return FALSE;

	/* If randomizer is provided, hash also needs to be provided. */
	if (remote_data->randomizer && !remote_data->hash)
		return FALSE;

	return TRUE;
}

static gboolean store_data(struct btd_adapter *adapter, struct oob_data *data)
{
	bdaddr_t bdaddr;
	bdaddr_t local;

	str2ba(data->addr, &bdaddr);
	adapter_get_address(adapter, &local);

	if (data->hash) {
		if (btd_adapter_add_remote_oob_data(adapter, &bdaddr,
					data->hash, data->randomizer) < 0)
			return FALSE;
	}

	if (data->class)
		write_remote_class(&local, &bdaddr, data->class);

	if (data->name)
		write_device_name(&local, &bdaddr, 0, data->name);

	return TRUE;
}

static DBusMessage *add_remote_data(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct btd_adapter *adapter = user_data;
	DBusMessageIter args;
	DBusMessageIter data;
	struct oob_data remote_data;
	struct btd_device *device;

	if (!btd_adapter_ssp_enabled(adapter))
		return btd_error_not_supported(msg);

	memset(&remote_data, 0, sizeof(remote_data));

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &remote_data.addr);
	dbus_message_iter_next(&args);

	if (bachk(remote_data.addr) < 0)
		return btd_error_invalid_args(msg);

	device = adapter_find_device(adapter, remote_data.addr);
	if (device && device_is_paired(device))
		return btd_error_already_exists(msg);

	dbus_message_iter_recurse(&args, &data);

	if (!parse_data(&data, &remote_data))
		return btd_error_invalid_args(msg);

	if (!store_data(adapter, &remote_data))
		return btd_error_failed(msg, "Request failed");

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *remove_remote_data(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct btd_adapter *adapter = data;
	const char *addr;
	bdaddr_t bdaddr;

	if (!btd_adapter_ssp_enabled(adapter))
		return btd_error_not_supported(msg);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &addr,
			DBUS_TYPE_INVALID))
		return btd_error_invalid_args(msg);

	if (str2ba(addr, &bdaddr) < 0)
		return btd_error_invalid_args(msg);

	if (btd_adapter_remove_remote_oob_data(adapter, &bdaddr))
		return btd_error_failed(msg, "Request failed");

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable oob_methods[] = {
	{ GDBUS_METHOD("AddRemoteData",
			GDBUS_ARGS({ "address", "s" }, { "data", "a{sv}"}),
			NULL, add_remote_data) },
	{ GDBUS_METHOD("RemoveRemoteData",
			GDBUS_ARGS({ "address", "s" }), NULL,
			remove_remote_data) },
	{ GDBUS_ASYNC_METHOD("ReadLocalData",
			NULL, GDBUS_ARGS({ "data", "a{sv}" }),
			read_local_data) },
	{ }
};

static int oob_probe(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					path, OOB_INTERFACE,
					oob_methods, NULL, NULL,
					adapter, NULL)) {
			error("OOB interface init failed on path %s", path);
			return -EIO;
		}

	return 0;
}

static void oob_remove(struct btd_adapter *adapter)
{
	g_dbus_unregister_interface(btd_get_dbus_connection(),
				adapter_get_path(adapter), OOB_INTERFACE);
}

static struct btd_adapter_driver oob_driver = {
	.name	= "oob",
	.probe	= oob_probe,
	.remove	= oob_remove,
};

static int dbusoob_init(void)
{
	DBG("Setup dbusoob plugin");

	return btd_register_adapter_driver(&oob_driver);
}

static void dbusoob_exit(void)
{
	DBG("Cleanup dbusoob plugin");

	manager_foreach_adapter((adapter_cb) oob_remove, NULL);

	btd_unregister_adapter_driver(&oob_driver);
}

BLUETOOTH_PLUGIN_DEFINE(dbusoob, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						dbusoob_init, dbusoob_exit)
