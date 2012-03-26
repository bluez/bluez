/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011 GSyC/LibreSoft, Universidad Rey Juan Carlos.
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

#include <gdbus.h>
#include <errno.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "thermometer.h"
#include "manager.h"

#define HEALTH_THERMOMETER_UUID		"00001809-0000-1000-8000-00805f9b34fb"

static DBusConnection *connection = NULL;

static gint primary_uuid_cmp(gconstpointer a, gconstpointer b)
{
	const struct gatt_primary *prim = a;
	const char *uuid = b;

	return g_strcmp0(prim->uuid, uuid);
}

static int thermometer_driver_probe(struct btd_device *device, GSList *uuids)
{
	struct gatt_primary *tattr;
	GSList *primaries, *l;

	primaries = btd_device_get_primaries(device);

	l = g_slist_find_custom(primaries, HEALTH_THERMOMETER_UUID,
							primary_uuid_cmp);
	if (l == NULL)
		return -EINVAL;

	tattr = l->data;

	return thermometer_register(connection, device, tattr);
}

static void thermometer_driver_remove(struct btd_device *device)
{
	thermometer_unregister(device);
}

static struct btd_device_driver thermometer_device_driver = {
	.name	= "thermometer-device-driver",
	.uuids	= BTD_UUIDS(HEALTH_THERMOMETER_UUID),
	.probe	= thermometer_driver_probe,
	.remove	= thermometer_driver_remove
};

int thermometer_manager_init(DBusConnection *conn)
{
	int ret;

	ret = btd_register_device_driver(&thermometer_device_driver);
	if (ret < 0)
                return ret;

	connection = dbus_connection_ref(conn);
	return 0;
}

void thermometer_manager_exit(void)
{
	btd_unregister_device_driver(&thermometer_device_driver);

	dbus_connection_unref(connection);
	connection = NULL;
}
