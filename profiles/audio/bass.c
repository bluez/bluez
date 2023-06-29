// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2023 NXP
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "lib/bluetooth.h"
#include "lib/uuid.h"

#include "src/dbus-common.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/adapter.h"
#include "src/shared/bass.h"

#include "src/plugin.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"

#define BASS_UUID_STR "0000184f-0000-1000-8000-00805f9b34fb"

struct bass_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_bass *bass;
};

static struct queue *sessions;

static void bass_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static struct bass_data *bass_data_new(struct btd_device *device)
{
	struct bass_data *data;

	data = new0(struct bass_data, 1);
	data->device = device;

	return data;
}

static void bass_data_add(struct bass_data *data)
{
	DBG("data %p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_bass_set_debug(data->bass, bass_debug, NULL, NULL);

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service)
		btd_service_set_user_data(data->service, data);
}

static bool match_data(const void *data, const void *match_data)
{
	const struct bass_data *bdata = data;
	const struct bt_bass *bass = match_data;

	return bdata->bass == bass;
}

static void bass_data_free(struct bass_data *data)
{
	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_bass_set_user_data(data->bass, NULL);
	}

	bt_bass_unref(data->bass);
	free(data);
}

static void bass_data_remove(struct bass_data *data)
{
	DBG("data %p", data);

	if (!queue_remove(sessions, data))
		return;

	bass_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

static void bass_detached(struct bt_bass *bass, void *user_data)
{
	struct bass_data *data;

	DBG("%p", bass);

	data = queue_find(sessions, match_data, bass);
	if (!data) {
		error("Unable to find bass session");
		return;
	}

	/* If there is a service it means there is BASS thus we can keep
	 * instance allocated.
	 */
	if (data->service)
		return;

	bass_data_remove(data);
}

static void bass_attached(struct bt_bass *bass, void *user_data)
{
	struct bass_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", bass);

	data = queue_find(sessions, match_data, bass);
	if (data)
		return;

	att = bt_bass_get_att(bass);
	if (!att)
		return;

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("Unable to find device");
		return;
	}

	data = bass_data_new(device);
	data->bass = bass;

	bass_data_add(data);
}

static int bass_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct bass_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	/* Ignore, if we were probed for this device already */
	if (data) {
		error("Profile probed twice for the same device!");
		return -EINVAL;
	}

	data = bass_data_new(device);
	data->service = service;

	data->bass = bt_bass_new(btd_gatt_database_get_db(database),
					btd_device_get_gatt_db(device),
					btd_adapter_get_address(adapter));
	if (!data->bass) {
		error("Unable to create BASS instance");
		free(data);
		return -EINVAL;
	}

	bass_data_add(data);
	bt_bass_set_user_data(data->bass, service);

	return 0;
}

static void bass_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bass_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("BASS service not handled by profile");
		return;
	}

	bass_data_remove(data);
}
static int bass_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct bass_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("BASS service not handled by profile");
		return -EINVAL;
	}

	if (!bt_bass_attach(data->bass, client)) {
		error("BASS unable to attach");
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int bass_disconnect(struct btd_service *service)
{
	struct bass_data *data = btd_service_get_user_data(service);
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	bt_bass_detach(data->bass);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static int bass_server_probe(struct btd_profile *p,
				struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	DBG("BASS path %s", adapter_get_path(adapter));

	bt_bass_add_db(btd_gatt_database_get_db(database),
				btd_adapter_get_address(adapter));

	return 0;
}

static void bass_server_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	DBG("BASS remove Adapter");
}

static struct btd_profile bass_service = {
	.name		= "bass",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= BASS_UUID_STR,
	.device_probe	= bass_probe,
	.device_remove	= bass_remove,
	.accept		= bass_accept,
	.disconnect	= bass_disconnect,
	.adapter_probe	= bass_server_probe,
	.adapter_remove	= bass_server_remove,
	.experimental	= true,
};

static unsigned int bass_id;

static int bass_init(void)
{
	int err;

	err = btd_profile_register(&bass_service);
	if (err)
		return err;

	bass_id = bt_bass_register(bass_attached, bass_detached, NULL);

	return 0;
}

static void bass_exit(void)
{
	btd_profile_unregister(&bass_service);
	bt_bass_unregister(bass_id);
}

BLUETOOTH_PLUGIN_DEFINE(bass, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							bass_init, bass_exit)
