// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (C) 2022 Intel Corporation. All rights reserved.
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

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/sdp.h"
#include "lib/uuid.h"

#include "src/dbus-common.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"
#include "src/shared/csip.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"
#include "src/btd.h"

#define CSIS_UUID_STR "00001846-0000-1000-8000-00805f9b34fb"

struct csip_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_csip *csip;
	unsigned int ready_id;
};

static struct queue *sessions;

static void csip_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static struct csip_data *csip_data_new(struct btd_device *device)
{
	struct csip_data *data;

	data = new0(struct csip_data, 1);
	data->device = device;

	return data;
}

static bool csip_ltk_read(struct bt_csip *csip, uint8_t k[16], void *user_data)
{
	/* TODO: Retrieve LTK using device object */
	return false;
}

static void csip_data_add(struct csip_data *data)
{
	DBG("data %p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_csip_set_debug(data->csip, csip_debug, NULL, NULL);

	bt_csip_set_sirk(data->csip, btd_opts.csis.encrypt, btd_opts.csis.sirk,
				btd_opts.csis.size, btd_opts.csis.rank,
				csip_ltk_read, data);

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, data);

	if (data->service)
		btd_service_set_user_data(data->service, data);
}

static int csip_disconnect(struct btd_service *service)
{
	struct csip_data *data = btd_service_get_user_data(service);

	bt_csip_detach(data->csip);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static bool match_data(const void *data, const void *match_data)
{
	const struct csip_data *vdata = data;
	const struct bt_csip *csip = match_data;

	return vdata->csip == csip;
}

static void csip_data_free(struct csip_data *data)
{
	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_csip_set_user_data(data->csip, NULL);
	}

	bt_csip_ready_unregister(data->csip, data->ready_id);
	bt_csip_unref(data->csip);
	free(data);
}

static void csip_data_remove(struct csip_data *data)
{
	DBG("data %p", data);

	if (!queue_remove(sessions, data))
		return;

	csip_data_free(data);

	if (queue_isempty(sessions)) {
		queue_destroy(sessions, NULL);
		sessions = NULL;
	}
}

static void csip_detached(struct bt_csip *csip, void *user_data)
{
	struct csip_data *data;

	DBG("%p", csip);

	data = queue_find(sessions, match_data, csip);
	if (!data) {
		error("Unable to find csip session");
		return;
	}

	/* If there is a service it means there is CSIS thus we can keep
	 * instance allocated.
	 */
	if (data->service)
		return;

	csip_data_remove(data);
}

static void csip_attached(struct bt_csip *csip, void *user_data)
{
	struct csip_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", csip);

	data = queue_find(sessions, match_data, csip);
	if (data)
		return;

	att = bt_csip_get_att(csip);
	if (!att)
		return;

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("Unable to find device");
		return;
	}

	data = csip_data_new(device);
	data->csip = csip;

	csip_data_add(data);

}

static int csip_server_probe(struct btd_profile *p,
				struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	DBG("CSIP path %s", adapter_get_path(adapter));

	bt_csip_add_db(btd_gatt_database_get_db(database));

	return 0;
}

static void csip_server_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	DBG("CSIP remove Adapter");
}

static int csip_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct csip_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (!data) {
		error("CSIP service not handled by profile");
		return -EINVAL;
	}

	if (!bt_csip_attach(data->csip, client)) {
		error("CSIP unable to attach");
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static void csip_ready(struct bt_csip *csip, void *user_data)
{
	struct btd_service *service = user_data;
	struct btd_device *device = btd_service_get_device(service);
	uint8_t type, size, rank;
	uint8_t k[16];

	DBG("csip %p", csip);

	if (!bt_csip_get_sirk(csip, &type, k, &size, &rank)) {
		error("Unable to read SIRK");
		return;
	}

	btd_device_add_set(device, type == BT_CSIP_SIRK_ENCRYPT ? true : false,
								k, size, rank);
}

static int csip_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct csip_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	/* Ignore, if we were probed for this device already */
	if (data) {
		error("Profile probed twice for the same device!");
		return -EINVAL;
	}

	data = csip_data_new(device);
	data->service = service;

	data->csip = bt_csip_new(btd_gatt_database_get_db(database),
					btd_device_get_gatt_db(device));
	if (!data->csip) {
		error("Unable to create CSIP instance");
		free(data);
		return -EINVAL;
	}

	csip_data_add(data);

	data->ready_id = bt_csip_ready_register(data->csip, csip_ready, service,
								NULL);

	bt_csip_set_user_data(data->csip, service);

	return 0;
}

static void csip_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct csip_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("CSIP service not handled by profile");
		return;
	}

	csip_data_remove(data);
}

static struct btd_profile csip_profile = {
	.name		= "csip",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= CSIS_UUID_STR,

	.device_probe	= csip_probe,
	.device_remove	= csip_remove,

	.accept		= csip_accept,
	.disconnect	= csip_disconnect,

	.adapter_probe	= csip_server_probe,
	.adapter_remove	= csip_server_remove,
};

static unsigned int csip_id;

static int csip_init(void)
{
	if (!(g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL)) {
		warn("D-Bus experimental not enabled");
		return -ENOTSUP;
	}

	btd_profile_register(&csip_profile);
	csip_id = bt_csip_register(csip_attached, csip_detached, NULL);

	return 0;
}

static void csip_exit(void)
{
	if (g_dbus_get_flags() & G_DBUS_FLAG_ENABLE_EXPERIMENTAL) {
		btd_profile_unregister(&csip_profile);
		bt_csip_unregister(csip_id);
	}
}

BLUETOOTH_PLUGIN_DEFINE(csip, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						csip_init, csip_exit)
