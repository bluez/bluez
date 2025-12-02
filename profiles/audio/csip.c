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
#include "src/shared/csip.h"
#include "src/shared/crypto.h"

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

struct csis_data {
	struct btd_adapter *adapter;
	struct bt_csip *csip;
};

struct csip_data {
	struct btd_adapter *adapter;
	struct btd_device *device;
	struct btd_service *service;
	struct bt_csip *csip;
	unsigned int ready_id;
};

static struct queue *sessions;
static struct queue *servers;

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

static void csip_data_add(struct csip_data *data)
{
	DBG("data %p", data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_csip_set_debug(data->csip, csip_debug, NULL, NULL);

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
	.bearer		= BTD_PROFILE_BEARER_LE,
	.remote_uuid	= CSIS_UUID_STR,

	.device_probe	= csip_probe,
	.device_remove	= csip_remove,

	.accept		= csip_accept,
	.disconnect	= csip_disconnect,

	.experimental	= true,
};

static bool csis_encrypt(struct bt_att *att, uint8_t val[16])
{
	struct btd_device *device;
	struct bt_crypto *crypto;
	uint8_t ltk[16];
	bool ret;

	device = btd_adapter_find_device_by_fd(bt_att_get_fd(att));
	if (!device) {
		error("Unable to find device");
		return false;
	}

	if (!btd_device_get_ltk(device, ltk, NULL, NULL)) {
		error("Unable to get device LTK");
		return false;
	}

	crypto = bt_crypto_new();
	if (!crypto) {
		error("Failed to open crypto");
		return false;
	}

	ret = bt_crypto_sef(crypto, ltk, val, val);
	if (!ret)
		error("Failed to encrypt SIRK using LTK");

	bt_crypto_unref(crypto);

	return ret;
}

static void csis_data_add(struct csis_data *data)
{
	DBG("data %p", data);

	if (queue_find(servers, NULL, data)) {
		error("data %p already added", data);
		return;
	}

	bt_csip_set_debug(data->csip, csip_debug, NULL, NULL);

	bt_csip_set_sirk(data->csip, btd_opts.csis.encrypt, btd_opts.csis.sirk,
				btd_opts.csis.size, btd_opts.csis.rank,
				csis_encrypt);

	if (!servers)
		servers = queue_new();

	queue_push_tail(servers, data);
}

static struct csis_data *csis_data_new(struct btd_adapter *adapter)
{
	struct csis_data *data;

	data = new0(struct csis_data, 1);
	data->adapter = adapter;

	return data;
}

static int csis_server_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct csis_data *data;

	DBG("path %s", adapter_get_path(adapter));

	data = csis_data_new(adapter);

	data->csip = bt_csip_new(btd_gatt_database_get_db(database), NULL);
	if (!data->csip) {
		error("Unable to create CSIP instance");
		free(data);
		return -EINVAL;
	}

	csis_data_add(data);

	return 0;
}

static bool match_csis(const void *data, const void *match_data)
{
	const struct csis_data *csis = data;
	const struct btd_adapter *adapter = match_data;

	return csis->adapter == adapter;
}

static void csis_data_free(struct csis_data *data)
{
	bt_csip_unref(data->csip);
	free(data);
}

static void csis_data_remove(struct csis_data *data)
{
	DBG("data %p", data);

	csis_data_free(data);

	if (queue_isempty(servers)) {
		queue_destroy(servers, NULL);
		servers = NULL;
	}
}

static void csis_server_remove(struct btd_profile *p,
					struct btd_adapter *adapter)
{
	struct csis_data *data;

	DBG("path %s", adapter_get_path(adapter));

	data = queue_remove_if(servers, match_csis, adapter);
	if (!data)
		return;

	csis_data_remove(data);
}

static struct btd_profile csis_profile = {
	.name		= "csis",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,
	.bearer		= BTD_PROFILE_BEARER_LE,
	.local_uuid	= CSIS_UUID_STR,

	.adapter_probe	= csis_server_probe,
	.adapter_remove	= csis_server_remove,
	.experimental	= true,
};

static unsigned int csip_id;

static int csip_init(void)
{
	int err;

	err = btd_profile_register(&csis_profile);
	if (err)
		return err;

	err = btd_profile_register(&csip_profile);
	if (err)
		return err;

	csip_id = bt_csip_register(csip_attached, csip_detached, NULL);

	return 0;
}

static void csip_exit(void)
{
	btd_profile_unregister(&csis_profile);
	btd_profile_unregister(&csip_profile);
	bt_csip_unregister(csip_id);
}

BLUETOOTH_PLUGIN_DEFINE(csip, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						csip_init, csip_exit)
