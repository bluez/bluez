// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2023  NXP Semiconductors. All rights reserved.
 *
 *
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define	_GNU_SOURCE

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
#include "src/shared/gatt-server.h"
#include "src/shared/micp.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

#define MICS_UUID_STR	"0000184D-0000-1000-8000-00805f9b34fb"

struct micp_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_micp *micp;
	unsigned int ready_id;
};

static struct queue *sessions;

static void micp_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static int micp_disconnect(struct btd_service *service)
{
	return 0;
}

static struct micp_data *micp_data_new(struct btd_device *device)
{
	struct micp_data *data;

	data = new0(struct micp_data, 1);
	g_assert(data);
	data->device = device;

	return data;
}

static void micp_data_add(struct micp_data *data)
{
	DBG("data %p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_micp_set_debug(data->micp, micp_debug, NULL, NULL);

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service)
		btd_service_set_user_data(data->service, data);
}

static bool match_data(const void *data, const void *match_data)
{
	const struct micp_data *mdata = data;
	const struct bt_micp *micp = match_data;

	return mdata->micp == micp;
}

static void micp_data_free(struct micp_data *data)
{
	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_micp_set_user_data(data->micp, NULL);
	}

	bt_micp_ready_unregister(data->micp, data->ready_id);
	bt_micp_unref(data->micp);
	free(data);
}

static void micp_data_remove(struct micp_data *data)
{
	DBG("data %p", data);

	if (!queue_remove(sessions, data))
		return;

	micp_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

static void micp_detached(struct bt_micp *micp, void *user_data)
{
	struct micp_data *data;

	DBG("%p", micp);

	data = queue_find(sessions, match_data, micp);
	if (!data) {
		error("unable to find session");
		return;
	}

	micp_data_remove(data);
}

static void micp_ready(struct bt_micp *micp, void *user_data)
{
	DBG("micp %p\n", micp);
}

static void micp_attached(struct bt_micp *micp, void *user_data)
{
	struct micp_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", micp);

	data = queue_find(sessions, match_data, micp);
	if (data)
		return;

	att = bt_micp_get_att(micp);
	if (!att)
		return;

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("unable to find device");
		return;
	}

	data = micp_data_new(device);
	g_assert(data);
	data->micp = micp;

	micp_data_add(data);
}

static int micp_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct micp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	/*Ignore, if we probed for this device already */
	if (data) {
		error("Profile probed twice for this device");
		return -EINVAL;
	}

	data = micp_data_new(device);
	data->service = service;

	data->micp = bt_micp_new(btd_gatt_database_get_db(database),
					btd_device_get_gatt_db(device));

	if (!data->micp) {
		error("unable to create MICP instance");
		free(data);
		return -EINVAL;
	}

	micp_data_add(data);

	data->ready_id = bt_micp_ready_register(data->micp, micp_ready, service,
								NULL);

	bt_micp_set_user_data(data->micp, service);

	return 0;
}

static void micp_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct micp_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("MICP Service not handled by profile");
		return;
	}

	micp_data_remove(data);
}

static int micp_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct micp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("MICP Service not handled by profile");
		return -EINVAL;
	}

	if (!bt_micp_attach(data->micp, client)) {
		error("MICP unable to attach");
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int micp_connect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	return 0;
}

static int micp_server_probe(struct btd_profile *p,
				struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	DBG("MICP path %s", adapter_get_path(adapter));

	bt_micp_add_db(btd_gatt_database_get_db(database));

	return 0;
}

static void micp_server_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	DBG("MICP remove adapter");
}

static struct btd_profile micp_profile = {
	.name		= "micp",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= MICS_UUID_STR,

	.device_probe	= micp_probe,
	.device_remove	= micp_remove,

	.accept	= micp_accept,
	.connect	= micp_connect,
	.disconnect	= micp_disconnect,

	.adapter_probe	= micp_server_probe,
	.adapter_remove = micp_server_remove,
};

static unsigned int micp_id;

static int micp_init(void)
{
	if (!(g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL)) {
		DBG("D-Bus experimental not enabled");
		return -ENOTSUP;
	}

	btd_profile_register(&micp_profile);
	micp_id = bt_micp_register(micp_attached, micp_detached, NULL);

	return 0;
}

static void micp_exit(void)
{
	if (g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL) {
		btd_profile_unregister(&micp_profile);
		bt_micp_unregister(micp_id);
	}
}

BLUETOOTH_PLUGIN_DEFINE(micp, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							micp_init, micp_exit)
