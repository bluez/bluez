/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/gatt-database.h"
#include "attrib/gattrib.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/rap.h"
#include "attrib/att.h"
#include "src/log.h"

struct rap_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_rap *rap;
	unsigned int ready_id;
};

static struct queue *sessions;

static struct rap_data *rap_data_new(struct btd_device *device)
{
	struct rap_data *data;

	data = new0(struct rap_data, 1);
	data->device = device;

	return data;
}

static void rap_data_add(struct rap_data *data)
{
	DBG("%p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service)
		btd_service_set_user_data(data->service, data);
}

static bool match_data(const void *data, const void *match_data)
{
	const struct rap_data *mdata = data;
	const struct bt_rap *rap = match_data;

	return mdata->rap == rap;
}

static void rap_data_free(struct rap_data *data)
{
	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_rap_set_user_data(data->rap, NULL);
	}

	bt_rap_ready_unregister(data->rap, data->ready_id);
	bt_rap_unref(data->rap);
	free(data);
}

static void rap_data_remove(struct rap_data *data)
{
	DBG("%p", data);

	if (!queue_remove(sessions, data))
		return;

	rap_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

static void rap_detached(struct bt_rap *rap, void *user_data)
{
	struct rap_data *data;

	DBG("%p", rap);

	data = queue_find(sessions, match_data, rap);
	if (!data) {
		error("unable to find session");
		return;
	}

	rap_data_remove(data);
}

static void rap_ready(struct bt_rap *rap, void *user_data)
{
	DBG("%p", rap);
}

static void rap_attached(struct bt_rap *rap, void *user_data)
{
	struct rap_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", rap);

	data = queue_find(sessions, match_data, rap);
	if (data) {
		DBG("data is already present");
		return;
	}

	att = bt_rap_get_att(rap);
	if (!att) {
		error("Unable to get att");
		return;
	}

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("unable to find device");
		return;
	}

	data = rap_data_new(device);
	data->rap = rap;

	rap_data_add(data);
}

static int rap_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct rap_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	/*Ignore, if we probed for this device already */
	if (data) {
		error("Profile probed twice for this device");
		return -EINVAL;
	}

	data = rap_data_new(device);
	data->service = service;

	data->rap = bt_rap_new(btd_gatt_database_get_db(database),
				btd_device_get_gatt_db(device));

	if (!data->rap) {
		error("unable to create RAP instance");
		free(data);
		return -EINVAL;
	}

	rap_data_add(data);

	data->ready_id = bt_rap_ready_register(data->rap, rap_ready, service,
								NULL);

	bt_rap_set_user_data(data->rap, service);

	return 0;
}

static void rap_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct rap_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("RAP Service not handled by profile");
		return;
	}

	rap_data_remove(data);
}

static int rap_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct rap_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("RAP Service not handled by profile");
		return -EINVAL;
	}

	if (!bt_rap_attach(data->rap, client)) {
		error("RAP unable to attach");
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int rap_disconnect(struct btd_service *service)
{
	DBG(" ");
	btd_service_disconnecting_complete(service, 0);
	return 0;
}

static int rap_connect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	return 0;
}

static int rap_server_probe(struct btd_profile *p,
				  struct btd_adapter *adapter)
{

	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	DBG("RAP path %s", adapter_get_path(adapter));

	bt_rap_add_db(btd_gatt_database_get_db(database));

	return 0;
}

static void rap_server_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	DBG("");
}
/* Profile definition */
static struct btd_profile rap_profile = {
	.name		= "rap",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= GATT_UUID,
	.local_uuid	= RAS_UUID,

	.device_probe	= rap_probe,
	.device_remove	= rap_remove,

	.accept		= rap_accept,
	.connect	= rap_connect,
	.disconnect	= rap_disconnect,

	.adapter_probe = rap_server_probe,
	.adapter_remove = rap_server_remove,

	.experimental	= true,
};

static unsigned int rap_id;
/* Plugin init/exit */
static int rap_init(void)
{
	DBG("");
	if (!(g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL)) {
		DBG("D-Bus experimental not enabled");
		return -ENOTSUP;
	}

	btd_profile_register(&rap_profile);
	rap_id = bt_rap_register(rap_attached, rap_detached, NULL);

	return 0;
}

static void rap_exit(void)
{
	if (g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL) {
		btd_profile_unregister(&rap_profile);
		bt_rap_unregister(rap_id);
	}
}

/* Plugin definition */
BLUETOOTH_PLUGIN_DEFINE(rap, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			rap_init, rap_exit)
