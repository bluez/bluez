/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012 Tieto Poland
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
#include <stdbool.h>
#include <bluetooth/uuid.h>

#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "heartrate.h"
#include "manager.h"

static gint primary_uuid_cmp(gconstpointer a, gconstpointer b)
{
	const struct gatt_primary *prim = a;
	const char *uuid = b;

	return g_strcmp0(prim->uuid, uuid);
}

static int heartrate_adapter_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	return heartrate_adapter_register(adapter);
}

static void heartrate_adapter_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	heartrate_adapter_unregister(adapter);
}

static int heartrate_device_probe(struct btd_profile *p,
				struct btd_device *device, GSList *uuids)
{
	GSList *primaries;
	GSList *l;

	primaries = btd_device_get_primaries(device);

	l = g_slist_find_custom(primaries, HEART_RATE_UUID, primary_uuid_cmp);
	if (l == NULL)
		return -EINVAL;

	return heartrate_device_register(device, l->data);
}

static void heartrate_device_remove(struct btd_profile *p,
						struct btd_device *device)
{
	heartrate_device_unregister(device);
}

static struct btd_profile hrp_profile = {
	.name		= "Heart Rate GATT Driver",
	.remote_uuids	= BTD_UUIDS(HEART_RATE_UUID),

	.device_probe	= heartrate_device_probe,
	.device_remove	= heartrate_device_remove,

	.adapter_probe	= heartrate_adapter_probe,
	.adapter_remove	= heartrate_adapter_remove,
};

int heartrate_manager_init(void)
{
	return btd_profile_register(&hrp_profile);
}

void heartrate_manager_exit(void)
{
	btd_profile_unregister(&hrp_profile);
}
