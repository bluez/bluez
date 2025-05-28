// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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
#include "src/shared/mcp.h"
#include "src/shared/mcs.h"

#include "btio/btio.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/gatt-database.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "src/error.h"
#include "player.h"

#define GMCS_UUID_STR "00001849-0000-1000-8000-00805f9b34fb"

struct mcp_data {
	struct btd_device *device;
	struct btd_service *service;
	struct bt_mcp *mcp;
	unsigned int state_id;

	struct media_player *mp;
};

static void mcp_debug(const char *str, void *user_data)
{
	DBG_IDX(0xffff, "%s", str);
}

static char *name2utf8(const uint8_t *name, uint16_t len)
{
	char utf8_name[HCI_MAX_NAME_LENGTH + 2];
	int i;

	if (g_utf8_validate((const char *) name, len, NULL))
		return g_strndup((char *) name, len);

	len = MIN(len, sizeof(utf8_name) - 1);

	memset(utf8_name, 0, sizeof(utf8_name));
	strncpy(utf8_name, (char *) name, len);

	/* Assume ASCII, and replace all non-ASCII with spaces */
	for (i = 0; utf8_name[i] != '\0'; i++) {
		if (!isascii(utf8_name[i]))
			utf8_name[i] = ' ';
	}

	/* Remove leading and trailing whitespace characters */
	g_strstrip(utf8_name);

	return g_strdup(utf8_name);
}

static const char *mcp_status_val_to_string(uint8_t status)
{
	switch (status) {
	case BT_MCS_STATUS_PLAYING:
		return "playing";
	case BT_MCS_STATUS_PAUSED:
		return "paused";
	case BT_MCS_STATUS_INACTIVE:
		return "stopped";
	case BT_MCS_STATUS_SEEKING:
		/* TODO: find a way for fwd/rvs seeking, probably by storing
		 * control point operation sent before
		 */
		return "forward-seek";
	default:
		return "error";
	}
}

static struct mcp_data *mcp_data_new(struct btd_device *device)
{
	struct mcp_data *data;

	data = new0(struct mcp_data, 1);
	data->device = device;

	return data;
}

static void cb_player_name(struct bt_mcp *mcp,  const uint8_t *value,
					uint16_t length)
{
	char *name;
	struct media_player *mp = bt_mcp_get_user_data(mcp);

	name = name2utf8(value, length);
	DBG("Media Player Name %s", (const char *)name);

	media_player_set_name(mp, name);

	g_free(name);
}

static void cb_track_changed(struct bt_mcp *mcp)
{
	DBG("Track Changed");
	/* Since track changed has happened
	 * track title notification is expected
	 */
}

static void cb_track_title(struct bt_mcp *mcp, const uint8_t *value,
					uint16_t length)
{
	char *name;
	uint16_t len;
	struct media_player *mp = bt_mcp_get_user_data(mcp);

	name = name2utf8(value, length);
	len = strlen(name);

	DBG("Track Title %s", (const char *)name);

	media_player_set_metadata(mp, NULL, "Title", name, len);
	media_player_metadata_changed(mp);

	g_free(name);
}

static void cb_track_duration(struct bt_mcp *mcp, int32_t duration)
{
	struct media_player *mp = bt_mcp_get_user_data(mcp);
	unsigned char buf[10];

	/* MCP defines duration is int32 but api takes it as uint32 */
	snprintf((char *)buf, 10, "%d", duration);
	media_player_set_metadata(mp, NULL, "Duration", buf, sizeof(buf));
	media_player_metadata_changed(mp);
}

static void cb_track_position(struct bt_mcp *mcp, int32_t duration)
{
	struct media_player *mp = bt_mcp_get_user_data(mcp);

	/* MCP defines duration is int32 but api takes it as uint32 */
	media_player_set_position(mp, duration);
}

static void cb_media_state(struct bt_mcp *mcp, uint8_t status)
{
	struct media_player *mp = bt_mcp_get_user_data(mcp);

	media_player_set_status(mp, mcp_status_val_to_string(status));
}

static const struct bt_mcp_event_callback cbs = {
	.player_name			= cb_player_name,
	.track_changed			= cb_track_changed,
	.track_title			= cb_track_title,
	.track_duration			= cb_track_duration,
	.track_position			= cb_track_position,
	.media_state			= cb_media_state,
};

static int ct_play(struct media_player *mp, void *user_data)
{
	struct bt_mcp *mcp = user_data;

	return bt_mcp_play(mcp);
}

static int ct_pause(struct media_player *mp, void *user_data)
{
	struct bt_mcp *mcp = user_data;

	return bt_mcp_pause(mcp);
}

static int ct_stop(struct media_player *mp, void *user_data)
{
	struct bt_mcp *mcp = user_data;

	return bt_mcp_stop(mcp);
}

static int ct_next(struct media_player *mp, void *user_data)
{
	struct bt_mcp *mcp = user_data;

	return bt_mcp_next_track(mcp);
}

static int ct_previous(struct media_player *mp, void *user_data)
{
	struct bt_mcp *mcp = user_data;

	return bt_mcp_previous_track(mcp);
}

static const struct media_player_callback ct_cbs = {
	.play		= ct_play,
	.pause		= ct_pause,
	.stop		= ct_stop,
	.next		= ct_next,
	.previous	= ct_previous,
};

static int mcp_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct btd_adapter *adapter = device_get_adapter(device);
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct mcp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	/* Ignore, if we were probed for this device already */
	if (data) {
		error("Profile probed twice for the same device!");
		return -EINVAL;
	}

	data = mcp_data_new(device);
	data->service = service;

	data->mcp = bt_mcp_new(btd_gatt_database_get_db(database),
					btd_device_get_gatt_db(device));

	bt_mcp_set_debug(data->mcp, mcp_debug, NULL, NULL);
	btd_service_set_user_data(service, data);

	return 0;
}

static void mcp_data_free(struct mcp_data *data)
{
	DBG("");

	if (data->service) {
		btd_service_set_user_data(data->service, NULL);
		bt_mcp_set_user_data(data->mcp, NULL);
	}

	if (data->mp) {
		media_player_destroy(data->mp);
		data->mp = NULL;
	}

	bt_mcp_unref(data->mcp);
	free(data);
}

static void mcp_data_remove(struct mcp_data *data)
{
	DBG("data %p", data);

	mcp_data_free(data);
}

static void mcp_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct mcp_data *data;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	data = btd_service_get_user_data(service);
	if (!data) {
		error("MCP service not handled by profile");
		return;
	}

	mcp_data_remove(data);
}

static int mcp_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct mcp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	bt_mcp_attach(data->mcp, client);

	data->mp = media_player_controller_create(device_get_path(device),
							"mcp", 0);
	if (data->mp == NULL) {
		DBG("Unable to create Media Player");
		return -EINVAL;
	}

	media_player_set_callbacks(data->mp, &ct_cbs, data->mcp);

	bt_mcp_set_user_data(data->mcp, data->mp);
	bt_mcp_set_event_callbacks(data->mcp, &cbs, data->mp);
	btd_service_connecting_complete(service, 0);

	return 0;
}

static int mcp_connect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	return 0;
}

static int mcp_disconnect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct mcp_data *data = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	if (data->mp) {
		media_player_destroy(data->mp);
		data->mp = NULL;
	}

	bt_mcp_detach(data->mcp);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static int media_control_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);

	bt_mcp_register(btd_gatt_database_get_db(database));

	return 0;
}

static void media_control_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{

}

static struct btd_profile mcp_profile = {
	.name			= "mcp",
	.priority		= BTD_PROFILE_PRIORITY_MEDIUM,
	.remote_uuid	= GMCS_UUID_STR,
	.device_probe	= mcp_probe,
	.device_remove	= mcp_remove,
	.accept			= mcp_accept,
	.connect		= mcp_connect,
	.disconnect		= mcp_disconnect,

	.adapter_probe	= media_control_server_probe,
	.adapter_remove = media_control_server_remove,

	.experimental	= true,
};

static int mcp_init(void)
{
	return btd_profile_register(&mcp_profile);
}

static void mcp_exit(void)
{
	btd_profile_unregister(&mcp_profile);
}

BLUETOOTH_PLUGIN_DEFINE(mcp, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							mcp_init, mcp_exit)
