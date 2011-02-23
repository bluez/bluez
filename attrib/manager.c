/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "../src/adapter.h"
#include "../src/device.h"
#include "hcid.h"

#include "manager.h"
#include "client.h"
#include "example.h"

#define GATT_UUID	"00001801-0000-1000-8000-00805f9b34fb"

static DBusConnection *connection;

static int client_probe(struct btd_device *device, GSList *uuids)
{
	const sdp_record_t *rec;
	int psm = -1;

	rec = btd_device_get_record(device, GATT_UUID);
	if (rec) {
		sdp_list_t *list;
		if (sdp_get_access_protos(rec, &list) < 0)
			return -1;

		psm = sdp_get_proto_port(list, L2CAP_UUID);

		sdp_list_foreach(list, (sdp_list_func_t) sdp_list_free, NULL);
		sdp_list_free(list, NULL);

		if (psm < 0)
			return -1;
	}

	return attrib_client_register(device, psm);
}

static void client_remove(struct btd_device *device)
{
	attrib_client_unregister(device);
}

static struct btd_device_driver client_driver = {
	.name = "gatt-client",
	.uuids = BTD_UUIDS(GATT_UUID),
	.probe = client_probe,
	.remove = client_remove,
};

int attrib_manager_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	attrib_client_init(connection);

	btd_register_device_driver(&client_driver);


	if (main_opts.attrib_server)
		return server_example_init();

	return 0;
}

void attrib_manager_exit(void)
{
	btd_unregister_device_driver(&client_driver);

	if (main_opts.attrib_server)
		server_example_exit();

	attrib_client_exit();

	dbus_connection_unref(connection);
}
