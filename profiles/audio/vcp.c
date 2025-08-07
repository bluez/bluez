// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
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
#include "src/shared/vcp.h"

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

#define VCS_UUID_STR "00001844-0000-1000-8000-00805f9b34fb"
#define MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"

struct vcp_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_vcp *vcp;
};

static struct queue *sessions;

static void vcp_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static int vcp_disconnect(struct btd_service *service)
{
	struct vcp_data *data = btd_service_get_user_data(service);
	DBG("");

	if (!data) {
		error("VCP service not handled by profile");
		return -EINVAL;
	}
	bt_vcp_detach(data->vcp);

	btd_service_disconnecting_complete(service, 0);
	return 0;
}

static struct vcp_data *vcp_data_new(struct btd_device *device)
{
	struct vcp_data *data;

	data = new0(struct vcp_data, 1);
	data->device = device;

	return data;
}

static bool match_data(const void *data, const void *match_data)
{
	const struct vcp_data *vdata = data;
	const struct bt_vcp *vcp = match_data;

	return vdata->vcp == vcp;
}

static void vcp_volume_changed(struct bt_vcp *vcp, uint8_t volume)
{
	struct vcp_data *data = queue_find(sessions, match_data, vcp);

	if (data)
		media_transport_update_device_volume(data->device, volume);
}

static void vcp_data_add(struct vcp_data *data)
{
	DBG("data %p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_vcp_set_debug(data->vcp, vcp_debug, NULL, NULL);
	bt_vcp_set_volume_callback(data->vcp, vcp_volume_changed);

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service)
		btd_service_set_user_data(data->service, data);
}

static bool match_device(const void *data, const void *match_data)
{
	const struct vcp_data *vdata = data;
	const struct btd_device *device = match_data;

	return vdata->device == device;
}

static void vcp_data_free(struct vcp_data *data)
{
	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_vcp_set_user_data(data->vcp, NULL);
	}

	bt_vcp_unref(data->vcp);
	free(data);
}

static void vcp_data_remove(struct vcp_data *data)
{
	DBG("data %p", data);

	if (!queue_remove(sessions, data))
		return;

	vcp_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

uint8_t bt_audio_vcp_get_volume(struct btd_device *device)
{
	struct vcp_data *data = queue_find(sessions, match_device, device);

	if (data)
		return bt_vcp_get_volume(data->vcp);

	return 0;
}

bool bt_audio_vcp_set_volume(struct btd_device *device, uint8_t volume)
{
	struct vcp_data *data = queue_find(sessions, match_device, device);

	if (data)
		return bt_vcp_set_volume(data->vcp, volume);

	return FALSE;
}

static void vcp_remote_client_detached(struct bt_vcp *vcp, void *user_data)
{
	struct vcp_data *data;

	DBG("%p", vcp);

	data = queue_find(sessions, match_data, vcp);
	if (!data) {
		error("Unable to find vcp session");
		return;
	}

	vcp_data_remove(data);
}

static void vcp_remote_client_attached(struct bt_vcp *vcp, void *user_data)
{
	struct vcp_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", vcp);

	data = queue_find(sessions, match_data, vcp);
	if (data)
		return;

	att = bt_vcp_get_att(vcp);
	if (!att)
		return;

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("Unable to find device");
		return;
	}

	data = vcp_data_new(device);
	data->vcp = vcp;

	vcp_data_add(data);
}

static int vcp_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct vcp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	/* Ignore, if we were probed for this device already */
	if (data) {
		error("Profile probed twice for the same device!");
		return -EINVAL;
	}

	data = vcp_data_new(device);
	data->service = service;

	data->vcp = bt_vcp_new(btd_gatt_database_get_db(database),
					btd_device_get_gatt_db(device));
	if (!data->vcp) {
		error("Unable to create VCP instance");
		free(data);
		return -EINVAL;
	}

	vcp_data_add(data);

	bt_vcp_set_user_data(data->vcp, service);

	return 0;
}

static void vcp_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct vcp_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("VCP service not handled by profile");
		return;
	}

	vcp_data_remove(data);
}

static int vcp_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct vcp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("VCP service not handled by profile");
		return -EINVAL;
	}

	if (!bt_vcp_attach(data->vcp, client)) {
		error("VCP unable to attach");
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int vcp_server_probe(struct btd_profile *p,
				  struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	DBG("VCP path %s", adapter_get_path(adapter));

	bt_vcp_add_db(btd_gatt_database_get_db(database));

	return 0;
}

static void vcp_server_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	DBG("VCP remove Adapter");
}

static struct btd_profile vcp_profile = {
	.name		= "vcp",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= VCS_UUID_STR,

	.device_probe	= vcp_probe,
	.device_remove	= vcp_remove,

	.accept		= vcp_accept,
	.disconnect	= vcp_disconnect,

	.adapter_probe = vcp_server_probe,
	.adapter_remove = vcp_server_remove,

	.experimental	= true,
};

static unsigned int vcp_id = 0;

static int vcp_init(void)
{
	int err;

	err = btd_profile_register(&vcp_profile);
	if (err)
		return err;

	vcp_id = bt_vcp_register(vcp_remote_client_attached,
					    vcp_remote_client_detached, NULL);

	return 0;
}

static void vcp_exit(void)
{
	btd_profile_unregister(&vcp_profile);
	bt_vcp_unregister(vcp_id);
}

BLUETOOTH_PLUGIN_DEFINE(vcp, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							vcp_init, vcp_exit)
