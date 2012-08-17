/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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

#include <glib.h>
#include <errno.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "manager.h"

static int gatt_driver_probe(struct btd_device *device, GSList *uuids)
{
	return 0;
}

static void gatt_driver_remove(struct btd_device *device)
{
}

static struct btd_device_driver gatt_device_driver = {
	.name	= "gap-gatt-driver",
	.uuids	= BTD_UUIDS(GAP_UUID, GATT_UUID),
	.probe	= gatt_driver_probe,
	.remove	= gatt_driver_remove
};

int gatt_manager_init(void)
{
	return btd_register_device_driver(&gatt_device_driver);
}

void gatt_manager_exit(void)
{
	btd_unregister_device_driver(&gatt_device_driver);
}
