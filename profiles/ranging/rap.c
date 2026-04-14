// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "bluetooth/bluetooth.h"
#include "bluetooth/l2cap.h"
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
#include "src/btd.h"

#define USE_BT_HCI_RAW_CHANNEL	1
struct rap_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_rap *rap;
	unsigned int ready_id;
#if USE_BT_HCI_RAW_CHANNEL
	struct bt_hci *hci;
#endif
};

static struct queue *sessions;

static struct rap_data *rap_data_new(struct btd_device *device)
{
	struct rap_data *data;

	data = new0(struct rap_data, 1);
	data->device = device;

	return data;
}

static void rap_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static void rap_data_add(struct rap_data *data)
{
	DBG("%p", (void *)data);

	if (queue_find(sessions, NULL, data)) {
		error("data %p already added", (void *)data);
		return;
	}

	bt_rap_set_debug(data->rap, rap_debug, NULL, NULL);

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
#if USE_BT_HCI_RAW_CHANNEL
	if (data->hci) {
		bt_rap_hci_sm_cleanup();
		bt_hci_unref(data->hci);
	}
#endif
	/* Clean up HCI connection mappings */
	bt_rap_detach_hci(data->rap);
	bt_rap_unref(data->rap);
	free(data);
}

static void rap_data_remove(struct rap_data *data)
{
	DBG("%p", (void *)data);

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

	DBG("%p", (void *)rap);

	data = queue_find(sessions, match_data, rap);
	if (!data) {
		error("unable to find session");
		return;
	}

	rap_data_remove(data);
}

static void rap_ready(struct bt_rap *rap, void *user_data)
{
	DBG("%p", (void *)rap);
}

static void rap_attached(struct bt_rap *rap, void *user_data)
{
	struct rap_data *data;
	struct bt_att *att;
	struct btd_device *device;

	DBG("%p", (void *)rap);

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
#if USE_BT_HCI_RAW_CHANNEL
	int16_t hci_index = btd_adapter_get_index(adapter);

	data->hci = bt_hci_new_raw_device(hci_index);
	if (bt_rap_attach_hci(data->rap, data->hci)) {
		DBG("HCI raw channel initialized, hci%d", hci_index);
		bt_rap_hci_set_le_bcs_options(
					btd_opts.defaults.bcs.role,
					btd_opts.defaults.bcs.cs_sync_ant_sel,
					btd_opts.defaults.bcs.max_tx_power);
	} else {
		error("HCI raw channel not available (may be in use)");
	}
#else /* USE_BT_HCI_RAW_CHANNEL */
	DBG("MGMT Events");
#endif /* USE_BT_HCI_RAW_CHANNEL */

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
	struct bt_att *att;
	const bdaddr_t *bdaddr;
	uint8_t bdaddr_type;
	uint16_t handle;
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

	/* Set up connection handle mapping for CS event routing */
	att = bt_rap_get_att(data->rap);
	bdaddr = device_get_address(device);
	bdaddr_type = device_get_le_address_type(device);

	if (att && data->hci) {
		/* Use bt_hci_get_conn_info to find the connection handle
		 * by iterating through all connections and matching bdaddr
		 */
		struct bt_hci_conn_info conn_info;
		bool found = false;

		/* Try handles from 0x0001 to 0x0EFF
		 * (valid LE connection handle range)
		 */
		for (handle = 0x0001; handle <= 0x0EFF; handle++) {
			if (bt_hci_get_conn_info(data->hci, handle,
				&conn_info)) {
				/* Check if bdaddr matches */
				if (memcmp(conn_info.bdaddr, bdaddr, 6) == 0) {
					found = true;
					DBG("Found conn handle 0x%04X", handle);
					break;
				}
			}
		}

		if (found) {
			DBG("Setting up handle mapping: handle=0x%04X", handle);
			bt_rap_set_conn_handle(data->rap, handle,
						(const uint8_t *)bdaddr,
						bdaddr_type);
		} else {
			error("Failed to find connection handle for device");
		}
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
