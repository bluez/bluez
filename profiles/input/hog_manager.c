/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Nordic Semiconductor Inc.
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
#include <stdbool.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/uuid.h>

#include "log.h"
#include "../src/adapter.h"
#include "../src/device.h"
#include "../src/profile.h"

#include "plugin.h"
#include "hcid.h"
#include "device.h"
#include "suspend.h"
#include "att.h"
#include "gattrib.h"
#include "gatt.h"
#include "hog_device.h"

static gboolean suspend_supported = FALSE;
static GSList *devices = NULL;

static void set_suspend(gpointer data, gpointer user_data)
{
	struct hog_device *hogdev = data;
	gboolean suspend = GPOINTER_TO_INT(user_data);

	hog_device_set_control_point(hogdev, suspend);
}

static void suspend_callback(void)
{
	gboolean suspend = TRUE;

	DBG("Suspending ...");

	g_slist_foreach(devices, set_suspend, GINT_TO_POINTER(suspend));
}

static void resume_callback(void)
{
	gboolean suspend = FALSE;

	DBG("Resuming ...");

	g_slist_foreach(devices, set_suspend, GINT_TO_POINTER(suspend));
}

static int hog_device_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	const char *path = device_get_path(device);
	GSList *primaries, *l;

	DBG("path %s", path);

	primaries = btd_device_get_primaries(device);
	if (primaries == NULL)
		return -EINVAL;

	for (l = primaries; l; l = g_slist_next(l)) {
		struct gatt_primary *prim = l->data;
		struct hog_device *hogdev;

		if (strcmp(prim->uuid, HOG_UUID) != 0)
			continue;

		hogdev = hog_device_register(device, prim);
		if (hogdev == NULL)
			continue;

		devices = g_slist_append(devices, hogdev);
	}

	return 0;
}

static void remove_device(gpointer hogdev, gpointer b)
{
	devices = g_slist_remove(devices, hogdev);
	hog_device_unregister(hogdev);
}

static void hog_device_remove(struct btd_profile *p, struct btd_device *device)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	g_slist_foreach(devices, remove_device, NULL);
}

static struct btd_profile hog_profile = {
	.name		= "input-hog",
	.remote_uuids	= BTD_UUIDS(HOG_UUID),
	.device_probe	= hog_device_probe,
	.device_remove	= hog_device_remove,
};

static int hog_manager_init(void)
{
	int err;

	err = suspend_init(suspend_callback, resume_callback);
	if (err < 0)
		DBG("Suspend: %s(%d)", strerror(-err), -err);
	else
		suspend_supported = TRUE;

	return btd_profile_register(&hog_profile);
}

static void hog_manager_exit(void)
{
	if (suspend_supported)
		suspend_exit();

	btd_profile_register(&hog_profile);
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
