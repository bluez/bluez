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
#include "src/shared/tmap.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

#include "vcp.h"
#include "transport.h"

#define TMAS_UUID_STR			"00001855-0000-1000-8000-00805f9b34fb"

static void tmap_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static void service_ready(struct bt_tmap *tmap, void *user_data)
{
	struct btd_service *service = user_data;

	btd_service_connecting_complete(service, 0);
}

static struct bt_tmap *add_service(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct bt_tmap *tmap = btd_service_get_user_data(service);

	if (tmap)
		return tmap;

	tmap = bt_tmap_attach(client, service_ready, service);
	if (!tmap) {
		error("TMAP client unable to attach");
		return NULL;
	}

	bt_tmap_set_debug(tmap, tmap_debug, NULL, NULL);

	btd_service_set_user_data(service, tmap);
	return tmap;
}

static void remove_service(struct btd_service *service)
{
	struct bt_tmap *tmap = btd_service_get_user_data(service);

	if (!tmap)
		return;

	btd_service_set_user_data(service, NULL);
	bt_tmap_unref(tmap);
}

static int tmap_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_tmap *tmap;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	tmap = add_service(service);
	if (!tmap)
		return -EINVAL;

	return 0;
}

static int tmap_disconnect(struct btd_service *service)
{
	remove_service(service);

	btd_service_disconnecting_complete(service, 0);
	return 0;
}

static int tmap_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);
	return 0;
}

static void tmap_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	remove_service(service);
}

static int tmap_adapter_probe(struct btd_profile *p,
				  struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bt_tmap *tmap;

	DBG("Add TMAP server %s", adapter_get_path(adapter));
	tmap = bt_tmap_add_db(btd_gatt_database_get_db(database));

	bt_tmap_set_debug(tmap, tmap_debug, NULL, NULL);
	return 0;
}

static void tmap_adapter_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bt_tmap *tmap;

	DBG("Remove TMAP server %s", adapter_get_path(adapter));
	tmap = bt_tmap_find(btd_gatt_database_get_db(database));
	bt_tmap_unref(tmap);
}

static struct btd_profile tmap_profile = {
	.name		= "tmap",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= TMAS_UUID_STR,

	.device_probe	= tmap_probe,
	.device_remove	= tmap_remove,
	.accept		= tmap_accept,
	.disconnect	= tmap_disconnect,

	.adapter_probe = tmap_adapter_probe,
	.adapter_remove = tmap_adapter_remove,

	.experimental	= true,
};

static int tmap_init(void)
{
	int err;

	err = btd_profile_register(&tmap_profile);
	if (err)
		return err;

	return 0;
}

static void tmap_exit(void)
{
	btd_profile_unregister(&tmap_profile);
}

BLUETOOTH_PLUGIN_DEFINE(tmap, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							tmap_init, tmap_exit)
