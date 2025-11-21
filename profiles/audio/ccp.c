// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024  Intel Corporation. All rights reserved.
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
#include <string.h>
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
#include "src/shared/ccp.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

#define GTBS_UUID_STR "0000184C-0000-1000-8000-00805f9b34fb"

struct ccp_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_ccp *ccp;
	unsigned int state_id;
};

static void ccp_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static struct ccp_data *ccp_data_new(struct btd_device *device)
{
	struct ccp_data *data;

	data = new0(struct ccp_data, 1);
	data->device = device;

	return data;
}

static int ccp_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct ccp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (data) {
		error("Profile probed twice for the same device!");
		return -EINVAL;
	}

	data = ccp_data_new(device);
	data->service = service;

	data->ccp = bt_ccp_new(btd_gatt_database_get_db(database),
			       btd_device_get_gatt_db(device));

	bt_ccp_set_debug(data->ccp, ccp_debug, NULL, NULL);
	btd_service_set_user_data(service, data);

	return 0;
}

static void ccp_data_free(struct ccp_data *data)
{
	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_ccp_set_user_data(data->ccp, NULL);
	}

	bt_ccp_unref(data->ccp);
	free(data);
}

static void ccp_data_remove(struct ccp_data *data)
{
	DBG("data %p", data);

	ccp_data_free(data);
}

static void ccp_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct ccp_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("CCP service not handled by profile");
		return;
	}

	ccp_data_remove(data);
}

static int ccp_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct ccp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!bt_ccp_attach(data->ccp, client)) {
		error("CCP unable to attach");
		return -EINVAL;
	}

	/* TODO: register telephony operations here */

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int ccp_connect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	return 0;
}

static int ccp_disconnect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct ccp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	bt_ccp_detach(data->ccp);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static int ccp_server_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	bt_ccp_register(btd_gatt_database_get_db(database));

	return 0;
}

static void
ccp_server_remove(struct btd_profile *p,
		  struct btd_adapter *adapter)
{
	DBG("CCP remove adapter");
}

static struct btd_profile ccp_profile = {
	.name		= "ccp",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.bearer		= BTD_PROFILE_BEARER_LE,
	.remote_uuid	= GTBS_UUID_STR,
	.device_probe	= ccp_probe,
	.device_remove	= ccp_remove,
	.accept		= ccp_accept,
	.connect	= ccp_connect,
	.disconnect	= ccp_disconnect,
	.adapter_probe	= ccp_server_probe,
	.adapter_remove = ccp_server_remove,
	.testing	= true,
};

static int ccp_init(void)
{
	return btd_profile_register(&ccp_profile);
}

static void ccp_exit(void)
{
	btd_profile_unregister(&ccp_profile);
}

BLUETOOTH_PLUGIN_DEFINE(ccp, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			ccp_init, ccp_exit)
