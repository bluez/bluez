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
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "gas.h"
#include "manager.h"

static gint primary_uuid_cmp(gconstpointer a, gconstpointer b)
{
	const struct gatt_primary *prim = a;
	const char *uuid = b;

	return g_strcmp0(prim->uuid, uuid);
}

static int gatt_driver_probe(struct btd_device *device, GSList *uuids)
{
	GSList *primaries, *l;
	struct gatt_primary *gap = NULL, *gatt = NULL;

	primaries = btd_device_get_primaries(device);

	l = g_slist_find_custom(primaries, GAP_UUID, primary_uuid_cmp);
	if (l)
		gap = l->data;

	l = g_slist_find_custom(primaries, GATT_UUID, primary_uuid_cmp);
	if (l)
		gatt = l->data;

	return gas_register(device, gap ? &gap->range : NULL,
				gatt ? &gatt->range : NULL);
}

static void gatt_driver_remove(struct btd_device *device)
{
	gas_unregister(device);
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
