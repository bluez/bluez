/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *  Authors:
 *  Santiago Carot Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <btio.h>
#include <adapter.h>
#include <device.h>

#include "hdp_types.h"

#include "log.h"
#include "hdp_manager.h"
#include "hdp.h"

#include "glib-helper.h"

static DBusConnection *connection = NULL;

static int hdp_adapter_probe(struct btd_adapter *adapter)
{
	return hdp_adapter_register(connection, adapter);
}

static void hdp_adapter_remove(struct btd_adapter *adapter)
{
	hdp_adapter_unregister(adapter);
}

static struct btd_adapter_driver hdp_adapter_driver = {
	.name	= "hdp-adapter-driver",
	.probe	= hdp_adapter_probe,
	.remove	= hdp_adapter_remove,
};

static int hdp_driver_probe(struct btd_device *device, GSList *uuids)
{
	return hdp_device_register(connection, device);
}

static void hdp_driver_remove(struct btd_device *device)
{
	hdp_device_unregister(device);
}

static struct btd_device_driver hdp_device_driver = {
	.name	= "hdp-device-driver",
	.uuids	= BTD_UUIDS(HDP_UUID, HDP_SOURCE_UUID, HDP_SINK_UUID),
	.probe	= hdp_driver_probe,
	.remove	= hdp_driver_remove
};

int hdp_manager_init(DBusConnection *conn)
{
	if (hdp_manager_start(conn))
		return -1;

	connection = dbus_connection_ref(conn);
	btd_register_adapter_driver(&hdp_adapter_driver);
	btd_register_device_driver(&hdp_device_driver);

	return 0;
}

void hdp_manager_exit(void)
{
	btd_unregister_device_driver(&hdp_device_driver);
	btd_unregister_adapter_driver(&hdp_adapter_driver);
	hdp_manager_stop();

	dbus_connection_unref(connection);
	connection = NULL;
}
