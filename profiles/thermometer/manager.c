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

#include <errno.h>
#include <stdbool.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "thermometer.h"
#include "manager.h"

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

	return thermometer_register(device, tattr);
}

static void thermometer_driver_remove(struct btd_device *device)
{
	thermometer_unregister(device);
}

static struct btd_profile thermometer_profile = {
	.name		= "thermometer-device-driver",
	.remote_uuids	= BTD_UUIDS(HEALTH_THERMOMETER_UUID),
	.device_probe	= thermometer_driver_probe,
	.device_remove	= thermometer_driver_remove
};

int thermometer_manager_init(void)
{
	int ret;

	ret = btd_profile_register(&thermometer_profile);
	if (ret < 0)
		return ret;

	return 0;
}

void thermometer_manager_exit(void)
{
	btd_profile_unregister(&thermometer_profile);
}
