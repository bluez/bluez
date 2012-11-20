/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Nordic Semiconductor Inc.
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
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

#include <stdbool.h>
#include <errno.h>
#include <glib.h>
#include <bluetooth/uuid.h>

#include "log.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "manager.h"
#include "scan.h"

#define SCAN_PARAMETERS_UUID	"00001813-0000-1000-8000-00805f9b34fb"

static gint primary_uuid_cmp(gconstpointer a, gconstpointer b)
{
	const struct gatt_primary *prim = a;
	const char *uuid = b;

	return g_strcmp0(prim->uuid, uuid);
}

static int scan_param_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	GSList *primaries, *l;

	DBG("Probing Scan Parameters");

	primaries = btd_device_get_primaries(device);

	l = g_slist_find_custom(primaries, SCAN_PARAMETERS_UUID,
							primary_uuid_cmp);
	if (!l)
		return -EINVAL;

	return scan_register(device, l->data);
}

static void scan_param_remove(struct btd_profile *p, struct btd_device *device)
{
	scan_unregister(device);
}

static struct btd_profile scan_profile = {
	.name = "Scan Parameters Client Driver",
	.remote_uuids = BTD_UUIDS(SCAN_PARAMETERS_UUID),
	.device_probe = scan_param_probe,
	.device_remove = scan_param_remove,
};

int scan_param_manager_init(void)
{
	return btd_profile_register(&scan_profile);

}

void scan_param_manager_exit(void)
{
	btd_profile_unregister(&scan_profile);
}
