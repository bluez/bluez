// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Nintendo Switch 2 controller BLE plugin
 *
 *  Thin device-specific wrapper around the generic GATT-UHID bridge.
 *  Provides the GATT service UUID, characteristic discovery, and
 *  vendor/product IDs for uhid device matching.
 *
 *  This wires the BLE device(s) so that HID drivers can take over.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/plugin.h"
#include "src/log.h"
#include "src/shared/att.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-db.h"

#include "plugins/gatt-uhid.h"

/*
 * Hard facts about Nintendo and the Switch 2 controllers
 */

#define SWITCH2_SERVICE_UUID "ab7de9be-89fe-49ad-828f-118f09df7fd0"

#define NS2_VID           0x057e /* Nintendo Vendor ID */
#define NS2_PID_JOYCON_R  0x2066
#define NS2_PID_JOYCON_L  0x2067
#define NS2_PID_PROCON    0x2069
#define NS2_PID_GCCON        0x2073

#define NS2_INPUT_SIZE    63 /* Max observed on Procon2 in bytes */
#define NS2_OUTPUT_SIZE   64 /* Max observed on Procon2; no off by one */

#define NS2_MAX_NOTIFY    8 /* Max |notify characteristics in the service| */

struct switch2_ctlr_info {
	uint16_t    pid;
	const char *alias;
};

static const struct switch2_ctlr_info ctlr_table[] = {
	{ NS2_PID_PROCON,   "Nintendo Switch 2 Pro Controller" },
	{ NS2_PID_JOYCON_L, "Nintendo Switch 2 Joy-Con (L)" },
	{ NS2_PID_JOYCON_R, "Nintendo Switch 2 Joy-Con (R)" },
	{ NS2_PID_GCCON,    "Nintendo Switch 2 GameCube Controller" },
};

/* Struct representing a controller */
struct switch2_device {
	struct btd_device    *device;
	struct gatt_uhid     *bridge;
	const struct switch2_ctlr_info *info;
};

/*
 * GATT characteristic discovery
 */

/* We iterate gatt_db_foreach_service->gatt_db_service_foreach_char->inspect.
 * Collect progress in char_walk_state */
struct char_walk_state {
	uint16_t   notify_handles[NS2_MAX_NOTIFY];
	unsigned int notify_count;
};

static void inspect_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct char_walk_state *state = user_data;
	uint16_t handle, value_handle;
	uint8_t properties;

	if (!gatt_db_attribute_get_char_data(attr, &handle, &value_handle,
						&properties, NULL, NULL))
		return;

	/* Collect every characteristic that supports notification */
	if ((properties & 0x10) &&
			state->notify_count < NS2_MAX_NOTIFY) {
		state->notify_handles[state->notify_count++] = value_handle;
	}
}

static void find_chars_in_service(struct gatt_db_attribute *service,
							void *user_data)
{
	gatt_db_service_foreach_char(service, inspect_char, user_data);
}

/*
 * Plugin functions
 */

static int switch2_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	uint16_t pid = btd_device_get_product(device);
	struct switch2_device *dev;
	unsigned int c;

	DBG("switch2: probe %s", device_get_path(device));

	dev = g_new0(struct switch2_device, 1);
	dev->device = btd_device_ref(device);
	dev->info = &ctlr_table[0]; /* default to Procon 2 */

	for (c = 0; c < G_N_ELEMENTS(ctlr_table); c++) {
		if (ctlr_table[c].pid == pid) {
			dev->info = &ctlr_table[c];
			break;
		}
	}

	DBG("switch2: detected %s (pid=0x%04x)", dev->info->alias, pid);

	btd_device_set_alias(device, dev->info->alias);
	btd_device_set_skip_secondary(device, true);

	btd_service_set_user_data(service, dev);

	return 0;
}

static void switch2_remove(struct btd_service *service)
{
	struct switch2_device *dev = btd_service_get_user_data(service);

	DBG("switch2: remove %s", device_get_path(dev->device));

	btd_device_unref(dev->device);
	g_free(dev);
}

static int switch2_accept(struct btd_service *service)
{
	struct switch2_device *dev = btd_service_get_user_data(service);
	struct btd_device *device  = btd_service_get_device(service);
	struct bt_gatt_client *client;
	struct gatt_db *db;
	struct char_walk_state state;
	bt_uuid_t service_uuid;
	struct gatt_uhid_params params;

	DBG("switch2: accept %s", device_get_path(device));

	client = btd_device_get_gatt_client(device);
	if (!client) {
		error("switch2: no GATT client");
		return -EINVAL;
	}

	/* NS2 controllers reject pairing; avoid pairing */
	bt_gatt_client_set_security(client, BT_SECURITY_LOW);

	/* Low-latency connection, otherwise unplayable */
	btd_device_set_conn_param(device, 6, 6, 0, 200);

	/* Discover GATT characteristics */
	memset(&state, 0, sizeof(state));

	db = btd_device_get_gatt_db(device);
	bt_string_to_uuid(&service_uuid, SWITCH2_SERVICE_UUID);
	gatt_db_foreach_service(db, &service_uuid,
					find_chars_in_service, &state);

	if (!state.notify_count) {
		error("switch2: no notify characteristics found");
		return -ENOENT;
	}

	/* Set up the GATT-UHID bridge */
	memset(&params, 0, sizeof(params));
	/* Static info */
	params.version = 0x0001;
	params.vendor = NS2_VID;
	params.input_size = NS2_INPUT_SIZE;
	params.output_size = NS2_OUTPUT_SIZE;
	/* Our dev->info override in _probe() */
	params.name = dev->info->alias;
	params.product = dev->info->pid;
	/* Discovered handles at runtime */
	params.notify_handles = state.notify_handles;
	params.notify_count = state.notify_count;

	dev->bridge = gatt_uhid_new(client, &params);
	if (!dev->bridge) {
		error("switch2: failed to create GATT-UHID bridge");
		return -EIO;
	}

	btd_service_connecting_complete(service, 0);
	return 0;
}

static int switch2_disconnect(struct btd_service *service)
{
	struct switch2_device *dev = btd_service_get_user_data(service);

	DBG("switch2: disconnect %s", device_get_path(dev->device));

	gatt_uhid_free(dev->bridge);
	dev->bridge = NULL;

	btd_service_disconnecting_complete(service, 0);
	return 0;
}

/*
 * Plug in the plugin
 */

static struct btd_profile switch2_profile = {
	.name = "switch2",
	.bearer = BTD_PROFILE_BEARER_LE,
	.remote_uuid = SWITCH2_SERVICE_UUID,
	.device_probe = switch2_probe,
	.device_remove = switch2_remove,
	.accept = switch2_accept,
	.disconnect = switch2_disconnect,
	.auto_connect = true,
};

static int switch2_init(void)
{
	return btd_profile_register(&switch2_profile);
}

static void switch2_exit(void)
{
	btd_profile_unregister(&switch2_profile);
}

BLUETOOTH_PLUGIN_DEFINE(switch2, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						switch2_init, switch2_exit)
