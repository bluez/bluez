// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Pauli Virtanen. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"
#include "bluetooth/sdp.h"
#include "bluetooth/uuid.h"

#include "src/dbus-common.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gmap.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

#define GMAS_UUID_STR			"00001858-0000-1000-8000-00805f9b34fb"

static void gmap_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static void service_ready(struct bt_gmap *gmap, void *user_data)
{
	struct btd_service *service = user_data;

	btd_service_connecting_complete(service, 0);
}

static struct bt_gmap *add_service(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct bt_gmap *gmap = btd_service_get_user_data(service);

	if (gmap)
		return gmap;

	gmap = bt_gmap_attach(client, service_ready, service);
	if (!gmap) {
		error("GMAP client unable to attach");
		return NULL;
	}

	bt_gmap_set_debug(gmap, gmap_debug, NULL, NULL);

	btd_service_set_user_data(service, gmap);
	return gmap;
}

static void remove_service(struct btd_service *service)
{
	struct bt_gmap *gmap = btd_service_get_user_data(service);

	if (!gmap)
		return;

	btd_service_set_user_data(service, NULL);
	bt_gmap_unref(gmap);
}

static int gmap_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gmap *gmap;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	gmap = add_service(service);
	if (!gmap)
		return -EINVAL;

	return 0;
}

static int gmap_disconnect(struct btd_service *service)
{
	remove_service(service);

	btd_service_disconnecting_complete(service, 0);
	return 0;
}

static int gmap_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);
	return 0;
}

static void gmap_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	remove_service(service);
}

static int gmap_adapter_probe(struct btd_profile *p,
				  struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bt_gmap *gmap;

	DBG("Add GMAP server %s", adapter_get_path(adapter));
	gmap = bt_gmap_add_db(btd_gatt_database_get_db(database));

	bt_gmap_set_debug(gmap, gmap_debug, NULL, NULL);
	return 0;
}

static void gmap_adapter_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bt_gmap *gmap;

	DBG("Remove GMAP server %s", adapter_get_path(adapter));
	gmap = bt_gmap_find(btd_gatt_database_get_db(database));
	bt_gmap_unref(gmap);
}

static struct btd_profile gmap_profile = {
	.name		= "gmap",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= GMAS_UUID_STR,

	.device_probe	= gmap_probe,
	.device_remove	= gmap_remove,
	.accept		= gmap_accept,
	.disconnect	= gmap_disconnect,

	.adapter_probe = gmap_adapter_probe,
	.adapter_remove = gmap_adapter_remove,

	.experimental	= true,
};

static int gmap_init(void)
{
	int err;

	err = btd_profile_register(&gmap_profile);
	if (err)
		return err;

	return 0;
}

static void gmap_exit(void)
{
	btd_profile_unregister(&gmap_profile);
}

BLUETOOTH_PLUGIN_DEFINE(gmap, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							gmap_init, gmap_exit)
