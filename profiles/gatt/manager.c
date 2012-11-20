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
#include <stdbool.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "gas.h"
#include "log.h"
#include "manager.h"

static gint primary_uuid_cmp(gconstpointer a, gconstpointer b)
{
	const struct gatt_primary *prim = a;
	const char *uuid = b;

	return g_strcmp0(prim->uuid, uuid);
}

static int gatt_driver_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
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

	if (gap == NULL || gatt == NULL) {
		error("GAP and GATT are mandatory");
		return -EINVAL;
	}

	return gas_register(device, &gap->range, &gatt->range);
}

static void gatt_driver_remove(struct btd_profile *p,
						struct btd_device *device)
{
	gas_unregister(device);
}

static struct btd_profile gatt_profile = {
	.name		= "gap-gatt-profile",
	.remote_uuids	= BTD_UUIDS(GAP_UUID, GATT_UUID),
	.device_probe	= gatt_driver_probe,
	.device_remove	= gatt_driver_remove
};

int gatt_manager_init(void)
{
	return btd_profile_register(&gatt_profile);
}

void gatt_manager_exit(void)
{
	btd_profile_unregister(&gatt_profile);
}
