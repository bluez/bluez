/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#include <bluetooth/bluetooth.h>

#include <dbus/dbus.h>
#include <glib.h>

#include "logging.h"

#include "driver.h"
#include "dbus-service.h"

static GSList *device_drivers = NULL;
static GSList *adapter_drivers = NULL;

int btd_register_device_driver(struct btd_device_driver *driver)
{
	const char **uuid;

	/* FIXME: hack to make hci to resolve service_req_auth symbol*/
	service_req_auth(NULL, NULL, NULL, NULL, NULL);
	device_drivers = g_slist_append(device_drivers, driver);

	for (uuid = driver->uuids; *uuid; uuid++) {
		debug("name %s uuid %s", driver->name, *uuid);
	}

	return 0;
}

void btd_unregister_device_driver(struct btd_device_driver *driver)
{
	device_drivers = g_slist_remove(device_drivers, driver);
}

GSList *btd_get_device_drivers()
{
	return device_drivers;
}

int btd_register_adapter_driver(struct btd_adapter_driver *driver)
{
	adapter_drivers = g_slist_append(adapter_drivers, driver);

	return 0;
}

void btd_unregister_adapter_driver(struct btd_adapter_driver *driver)
{
	adapter_drivers = g_slist_remove(adapter_drivers, driver);
}

GSList *btd_get_adapter_drivers()
{
	return adapter_drivers;
}
