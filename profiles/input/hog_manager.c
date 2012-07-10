/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia
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

#include "log.h"
#include "../src/adapter.h"
#include "../src/device.h"

#include "plugin.h"
#include "hcid.h"
#include "device.h"
#include "hog_device.h"

static int hog_device_probe(struct btd_device *device, GSList *uuids)
{
	const char *path = device_get_path(device);

	DBG("path %s", path);

	return hog_device_register(device, path);
}

static void hog_device_remove(struct btd_device *device)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	hog_device_unregister(path);
}

static struct btd_device_driver hog_driver = {
	.name	= "input-hog",
	.uuids	= BTD_UUIDS(HOG_UUID),
	.probe	= hog_device_probe,
	.remove	= hog_device_remove,
};

static int hog_manager_init(void)
{
	return btd_register_device_driver(&hog_driver);
}

static void hog_manager_exit(void)
{
	btd_unregister_device_driver(&hog_driver);
}

static int hog_init(void)
{
	if (!main_opts.gatt_enabled) {
		DBG("GATT is disabled");
		return -ENOTSUP;
	}

	return hog_manager_init();
}

static void hog_exit(void)
{
	if (!main_opts.gatt_enabled)
		return;

	hog_manager_exit();
}

BLUETOOTH_PLUGIN_DEFINE(hog, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							hog_init, hog_exit)
