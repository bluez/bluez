/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>
#include <gdbus/gdbus.h>

#include "lib/uuid.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "monitor.h"
#include "reporter.h"
#include "manager.h"

static struct enabled enabled  = {
	.linkloss = TRUE,
	.pathloss = TRUE,
	.findme = TRUE,
};

static int monitor_device_probe(struct btd_profile *p,
				struct btd_device *device, GSList *uuids)
{
	struct gatt_primary *linkloss, *txpower, *immediate;

	immediate = btd_device_get_primary(device, IMMEDIATE_ALERT_UUID);
	txpower = btd_device_get_primary(device, TX_POWER_UUID);
	linkloss = btd_device_get_primary(device, LINK_LOSS_UUID);

	return monitor_register(device, linkloss, txpower, immediate, &enabled);
}

static void monitor_device_remove(struct btd_profile *p,
						struct btd_device *device)
{
	monitor_unregister(device);
}

static struct btd_profile pxp_monitor_profile = {
	.name		= "Proximity Monitor GATT Driver",
	.remote_uuids	= BTD_UUIDS(IMMEDIATE_ALERT_UUID,
						LINK_LOSS_UUID, TX_POWER_UUID),
	.device_probe	= monitor_device_probe,
	.device_remove	= monitor_device_remove,
};

static struct btd_profile pxp_reporter_profile = {
	.name		= "Proximity Reporter GATT Driver",
	.remote_uuids	= BTD_UUIDS(GATT_UUID),
	.device_probe	= reporter_device_probe,
	.device_remove	= reporter_device_remove,

	.adapter_probe	= reporter_adapter_probe,
	.adapter_remove	= reporter_adapter_remove,
};

static void load_config_file(GKeyFile *config)
{
	char **list;
	int i;

	if (config == NULL)
		return;

	list = g_key_file_get_string_list(config, "General", "Disable",
								NULL, NULL);
	for (i = 0; list && list[i] != NULL; i++) {
		if (g_str_equal(list[i], "FindMe"))
			enabled.findme = FALSE;
		else if (g_str_equal(list[i], "LinkLoss"))
			enabled.linkloss = FALSE;
		else if (g_str_equal(list[i], "PathLoss"))
			enabled.pathloss = FALSE;
	}

	g_strfreev(list);
}

int proximity_manager_init(GKeyFile *config)
{
	load_config_file(config);

	if (btd_profile_register(&pxp_monitor_profile) < 0)
		return -1;

	if (btd_profile_register(&pxp_reporter_profile) < 0) {
		btd_profile_unregister(&pxp_monitor_profile);
		return -1;
	}

	return 0;
}

void proximity_manager_exit(void)
{
	btd_profile_unregister(&pxp_monitor_profile);
	btd_profile_unregister(&pxp_reporter_profile);
}
