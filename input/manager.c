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

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <gdbus.h>

#include "log.h"
#include "../src/adapter.h"
#include "../src/device.h"

#include "device.h"
#include "server.h"
#include "manager.h"

static int idle_timeout = 0;

static DBusConnection *connection = NULL;
static GSList *adapters = NULL;

static void input_remove(struct btd_device *device, const char *uuid)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	input_device_unregister(path, uuid);
}

static int hid_device_probe(struct btd_device *device, GSList *uuids)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	const sdp_record_t *rec = btd_device_get_record(device, uuids->data);
	bdaddr_t src, dst;

	DBG("path %s", path);

	if (!rec)
		return -1;

	adapter_get_address(adapter, &src);
	device_get_address(device, &dst, NULL);

	return input_device_register(connection, device, path, &src, &dst,
				HID_UUID, rec->handle, idle_timeout * 60);
}

static void hid_device_remove(struct btd_device *device)
{
	input_remove(device, HID_UUID);
}

static int headset_probe(struct btd_device *device, GSList *uuids)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	const sdp_record_t *record;
	sdp_list_t *protos;
	int ch;
	bdaddr_t src, dst;

	DBG("path %s", path);

	if (!g_slist_find_custom(uuids, HSP_HS_UUID,
					(GCompareFunc) strcasecmp))
		return -EINVAL;

	record = btd_device_get_record(device, uuids->data);

	if (!record || sdp_get_access_protos(record, &protos) < 0) {
		error("Invalid record");
		return -EINVAL;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch <= 0) {
		error("Invalid RFCOMM channel");
		return -EINVAL;
	}

	adapter_get_address(adapter, &src);
	device_get_address(device, &dst, NULL);

	return fake_input_register(connection, device, path, &src, &dst,
				HSP_HS_UUID, ch);
}

static void headset_remove(struct btd_device *device)
{
	input_remove(device, HSP_HS_UUID);
}

static int hid_server_probe(struct btd_adapter *adapter)
{
	bdaddr_t src;
	int ret;

	adapter_get_address(adapter, &src);

	ret = server_start(&src);
	if (ret < 0)
		return ret;

	adapters = g_slist_append(adapters, btd_adapter_ref(adapter));

	return 0;
}

static void hid_server_remove(struct btd_adapter *adapter)
{
	bdaddr_t src;

	adapter_get_address(adapter, &src);

	server_stop(&src);

	adapters = g_slist_remove(adapters, adapter);
	btd_adapter_unref(adapter);
}

static struct btd_device_driver input_hid_driver = {
	.name	= "input-hid",
	.uuids	= BTD_UUIDS(HID_UUID),
	.probe	= hid_device_probe,
	.remove	= hid_device_remove,
};

static struct btd_device_driver input_headset_driver = {
	.name	= "input-headset",
	.uuids	= BTD_UUIDS(HSP_HS_UUID),
	.probe	= headset_probe,
	.remove	= headset_remove,
};

static struct btd_adapter_driver input_server_driver = {
	.name   = "input-server",
	.probe  = hid_server_probe,
	.remove = hid_server_remove,
};

int input_manager_init(DBusConnection *conn, GKeyFile *config)
{
	GError *err = NULL;

	if (config) {
		idle_timeout = g_key_file_get_integer(config, "General",
						"IdleTimeout", &err);
		if (err) {
			DBG("input.conf: %s", err->message);
			g_error_free(err);
		}
	}

	connection = dbus_connection_ref(conn);

	btd_register_adapter_driver(&input_server_driver);

	btd_register_device_driver(&input_hid_driver);
	btd_register_device_driver(&input_headset_driver);

	return 0;
}

void input_manager_exit(void)
{
	btd_unregister_device_driver(&input_hid_driver);
	btd_unregister_device_driver(&input_headset_driver);

	btd_unregister_adapter_driver(&input_server_driver);

	dbus_connection_unref(connection);

	connection = NULL;
}
