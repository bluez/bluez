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
#include <math.h>
#include <linux/uinput.h>

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
#include "uinput-util.h"

#define MCS_UUID_STR	"00001848-0000-1000-8000-00805f9b34fb"
#define GMCS_UUID_STR	"00001849-0000-1000-8000-00805f9b34fb"


/*
 * Remote player
 */

struct remote_player {
	struct bt_mcp *mcp;
	uint8_t ccid;
	struct media_player *mp;
	uint8_t playing_order;
};

static char *name2utf8(const uint8_t *name, uint16_t len)
{
	char *utf8_name;

	utf8_name = malloc(len + 1);
	if (!utf8_name)
		return NULL;

	if (len)
		memcpy(utf8_name, name, len);

	utf8_name[len] = 0;
	strtoutf8(utf8_name, len);

	/* Remove leading and trailing whitespace characters */
	g_strstrip(utf8_name);

	return utf8_name;
}

static const char *mcp_status_val_to_string(uint8_t status)
{
	switch (status) {
	case BT_MCS_STATE_PLAYING:
		return "playing";
	case BT_MCS_STATE_PAUSED:
		return "paused";
	case BT_MCS_STATE_INACTIVE:
		return "stopped";
	case BT_MCS_STATE_SEEKING:
		/* TODO: find a way for fwd/rvs seeking, probably by storing
		 * control point operation sent before
		 */
		return "forward-seek";
	default:
		return "error";
	}
}

static void remote_media_player_name(void *data, const uint8_t *value,
								uint16_t length)
{
	struct remote_player *remote = data;
	char *name;

	name = name2utf8(value, length);
	if (!name)
		return;

	DBG("Media Player Name %s", (const char *)name);

	media_player_set_name(remote->mp, name);

	free(name);
}

static void remote_track_changed(void *data)
{
	struct remote_player *remote = data;

	DBG("Track Changed");

	media_player_metadata_changed(remote->mp);
}

static void remote_track_title(void *data, const uint8_t *value,
								uint16_t length)
{
	struct remote_player *remote = data;
	char *name;
	uint16_t len;

	name = name2utf8(value, length);
	if (!name)
		return;

	len = strlen(name);

	DBG("Track Title %s", (const char *)name);

	media_player_set_metadata(remote->mp, NULL, "Title", name, len);
	media_player_metadata_changed(remote->mp);

	g_free(name);
}

static void remote_track_duration(void *data, int32_t duration_centisec)
{
	struct remote_player *remote = data;

	if (duration_centisec == BT_MCS_POSITION_UNAVAILABLE) {
		media_player_set_duration(remote->mp, 0);
		return;
	}

	if (duration_centisec < 0)
		duration_centisec = 0;

	media_player_set_duration(remote->mp, duration_centisec * 10);
}

static void remote_track_position(void *data, int32_t position_centisec)
{
	struct remote_player *remote = data;

	if (position_centisec == BT_MCS_POSITION_UNAVAILABLE) {
		media_player_set_position(remote->mp, 0);
		return;
	}

	if (position_centisec < 0)
		position_centisec = 0;

	media_player_set_position(remote->mp, position_centisec * 10);
}

static void remote_playback_speed(void *data, int8_t value)
{
	/* TODO */
}

static void remote_seeking_speed(void *data, int8_t speed)
{
	/* TODO */
}

static const struct {
	uint16_t basic;
	uint16_t repeat;
	bool shuffle;
	bool single;
} playing_orders[] = {
	{ BT_MCS_ORDER_SINGLE_ONCE, BT_MCS_ORDER_SINGLE_REPEAT,
	  .single = true },
	{ BT_MCS_ORDER_IN_ORDER_ONCE, BT_MCS_ORDER_IN_ORDER_REPEAT },
	{ BT_MCS_ORDER_OLDEST_ONCE, BT_MCS_ORDER_OLDEST_REPEAT },
	{ BT_MCS_ORDER_NEWEST_ONCE, BT_MCS_ORDER_NEWEST_REPEAT },
	{ BT_MCS_ORDER_SHUFFLE_ONCE, BT_MCS_ORDER_SHUFFLE_REPEAT,
	  .shuffle = true },
};

static void remote_playing_order(void *data, uint8_t order)
{
	struct remote_player *remote = data;
	const char *repeat = "off";
	unsigned int i;
	bool shuffle;

	remote->playing_order = order;

	for (i = 0; i < ARRAY_SIZE(playing_orders); ++i) {
		shuffle = playing_orders[i].shuffle;
		if (order == playing_orders[i].basic) {
			break;
		} else if (order == playing_orders[i].repeat) {
			repeat = playing_orders[i].single ? "singletrack" :
				"alltracks";
			break;
		}
	}
	if (i == ARRAY_SIZE(playing_orders))
		return;

	media_player_set_setting(remote->mp, "Repeat", repeat);
	media_player_set_setting(remote->mp, "Shuffle", shuffle ? "on" : "off");
}

static void remote_media_state(void *data, uint8_t status)
{
	struct remote_player *remote = data;

	media_player_set_status(remote->mp, mcp_status_val_to_string(status));
}

static void remote_destroy(void *data)
{
	struct remote_player *remote = data;

	media_player_destroy(remote->mp);
	free(data);
}

static const struct bt_mcp_listener_callback remote_cb = {
	.media_player_name = remote_media_player_name,
	.track_changed = remote_track_changed,
	.track_title = remote_track_title,
	.track_duration = remote_track_duration,
	.track_position = remote_track_position,
	.playback_speed = remote_playback_speed,
	.seeking_speed = remote_seeking_speed,
	.playing_order = remote_playing_order,
	.media_state = remote_media_state,
	.destroy = remote_destroy,
};

static int remote_mp_play(struct media_player *mp, void *user_data)
{
	struct remote_player *remote = user_data;

	return bt_mcp_play(remote->mcp, remote->ccid);
}

static int remote_mp_pause(struct media_player *mp, void *user_data)
{
	struct remote_player *remote = user_data;

	return bt_mcp_pause(remote->mcp, remote->ccid);
}

static int remote_mp_stop(struct media_player *mp, void *user_data)
{
	struct remote_player *remote = user_data;

	return bt_mcp_stop(remote->mcp, remote->ccid);
}

static int remote_mp_next(struct media_player *mp, void *user_data)
{
	struct remote_player *remote = user_data;

	return bt_mcp_next_track(remote->mcp, remote->ccid);
}

static int remote_mp_previous(struct media_player *mp, void *user_data)
{
	struct remote_player *remote = user_data;

	return bt_mcp_previous_track(remote->mcp, remote->ccid);
}

static bool remote_mp_set_setting(struct media_player *mp, const char *key,
					const char *value, void *user_data)
{
	struct remote_player *remote = user_data;
	unsigned int i;

	if (strcmp(key, "Repeat") == 0) {
		bool repeat = (strcmp(value, "alltracks") == 0);
		uint8_t order = remote->playing_order;

		/* Some sensible mapping, 1-to-1 not possible */
		for (i = 0; i < ARRAY_SIZE(playing_orders); ++i) {
			if (order == playing_orders[i].basic) {
				if (repeat)
					order = playing_orders[i].repeat;
				break;
			} else if (order == playing_orders[i].repeat) {
				if (!repeat)
					order = playing_orders[i].basic;
				break;
			}
		}

		if (strcmp(value, "singletrack") == 0)
			order = BT_MCS_ORDER_SINGLE_REPEAT;

		DBG("Set Repeat %s -> 0x%02x", value, order);

		if (order == remote->playing_order)
			return true;
		return bt_mcp_set_playing_order(remote->mcp, remote->ccid,
									order);
	}

	if (strcmp(key, "Shuffle") == 0) {
		bool shuffle = (strcmp(value, "off") != 0);
		uint8_t order = remote->playing_order;

		/* Some sensible mapping, 1-to-1 not possible */
		switch (order) {
		case BT_MCS_ORDER_SHUFFLE_ONCE:
			if (!shuffle)
				order = BT_MCS_ORDER_IN_ORDER_ONCE;
			break;
		case BT_MCS_ORDER_SHUFFLE_REPEAT:
			if (!shuffle)
				order = BT_MCS_ORDER_IN_ORDER_REPEAT;
			break;
		case BT_MCS_ORDER_SINGLE_ONCE:
		case BT_MCS_ORDER_IN_ORDER_ONCE:
		case BT_MCS_ORDER_OLDEST_ONCE:
		case BT_MCS_ORDER_NEWEST_ONCE:
			if (shuffle)
				order = BT_MCS_ORDER_SHUFFLE_ONCE;
			break;
		case BT_MCS_ORDER_SINGLE_REPEAT:
		case BT_MCS_ORDER_IN_ORDER_REPEAT:
		case BT_MCS_ORDER_OLDEST_REPEAT:
		case BT_MCS_ORDER_NEWEST_REPEAT:
			if (shuffle)
				order = BT_MCS_ORDER_SHUFFLE_REPEAT;
			break;
		}

		DBG("Set Shuffle %s -> 0x%02x", value, order);

		if (order == remote->playing_order)
			return true;
		return bt_mcp_set_playing_order(remote->mcp, remote->ccid,
									order);
	}

	return false;
}

static const struct media_player_callback remote_mp_cb = {
	.play		= remote_mp_play,
	.pause		= remote_mp_pause,
	.stop		= remote_mp_stop,
	.next		= remote_mp_next,
	.previous	= remote_mp_previous,
	.set_setting	= remote_mp_set_setting,
};

static void mcp_ccid(void *data, uint8_t ccid, bool gmcs)
{
	struct btd_service *service = data;
	struct btd_device *device = btd_service_get_device(service);
	struct bt_mcp *mcp = btd_service_get_user_data(service);
	struct remote_player *remote;
	struct media_player *mp;

	mp = media_player_controller_create(device_get_path(device),
					gmcs ? "mcp_gmcs" : "mcp_mcs", ccid);
	if (!mp) {
		DBG("Unable to create Media Player");
		return;
	}

	remote = new0(struct remote_player, 1);
	remote->mcp = mcp;
	remote->ccid = ccid;
	remote->mp = mp;

	media_player_set_callbacks(remote->mp, &remote_mp_cb, remote);

	if (!bt_mcp_add_listener(mcp, ccid, &remote_cb, remote)) {
		DBG("Unable to register Media Player with MCP");
		media_player_destroy(mp);
		free(remote);
		return;
	}
}

static void mcp_debug(void *data, const char *str)
{
	DBG_IDX(0xffff, "%s", str);
}

static void mcp_ready(void *data)
{
	struct btd_service *service = data;

	btd_service_connecting_complete(service, 0);
}

static const struct bt_mcp_callback mcp_cb = {
	.ccid = mcp_ccid,
	.debug = mcp_debug,
	.ready = mcp_ready,
};


/*
 * Local player
 */

struct gmcs;

struct local_player {
	struct bt_mcs *mcs;
	struct media_player *mp;
	struct gmcs *gmcs;
};

struct gmcs {
	int uinput;
	struct btd_adapter *adapter;
	struct bt_mcs *mcs;
	struct queue *players;
};

static const struct uinput_key_map key_map[] = {
	{ "Play",	BT_MCS_CMD_PLAY,		KEY_PLAYCD },
	{ "Stop",	BT_MCS_CMD_STOP,		KEY_STOPCD },
	{ "Pause",	BT_MCS_CMD_PAUSE,		KEY_PAUSECD },
	{ "Next Track",	BT_MCS_CMD_NEXT_TRACK,		KEY_NEXTSONG },
	{ "Prev Track",	BT_MCS_CMD_PREV_TRACK,		KEY_PREVIOUSSONG },
	{ NULL }
};

static struct queue *servers;

static bool gmcs_command(struct gmcs *gmcs, uint8_t cmd)
{
	unsigned int i;

	/* Emulate media key press */
	if (gmcs->uinput < 0)
		return false;

	for (i = 0; i < ARRAY_SIZE(key_map); ++i) {
		if (key_map[i].code == cmd) {
			DBG("GMCS press %s", key_map[i].name);
			uinput_send_key(gmcs->uinput, key_map[i].uinput, 1);
			uinput_send_key(gmcs->uinput, key_map[i].uinput, 0);
			break;
		}
	}

	/* We are always inactive, so command does not cause state changes and
	 * does not succeed, even though we do generate the key presses.
	 * This should be OK vs. MCP v1.0.1 p. 26
	 */
	return false;
}

static bool gmcs_play(void *data)
{
	return gmcs_command(data, BT_MCS_CMD_PLAY);
}

static bool gmcs_pause(void *data)
{
	return gmcs_command(data, BT_MCS_CMD_PAUSE);
}

static bool gmcs_stop(void *data)
{
	return gmcs_command(data, BT_MCS_CMD_STOP);
}

static bool gmcs_next_track(void *data)
{
	return gmcs_command(data, BT_MCS_CMD_NEXT_TRACK);
}

static bool gmcs_previous_track(void *data)
{
	return gmcs_command(data, BT_MCS_CMD_PREV_TRACK);
}

static void gmcs_media_player_name(void *data, struct iovec *buf, size_t size)
{
	struct gmcs *gmcs = data;
	int len;

	len = snprintf((void *)buf->iov_base, size, "%s",
					btd_adapter_get_name(gmcs->adapter));
	if (len < 0)
		len = 0;
	else if ((size_t)len > size)
		len = size;
	util_iov_push(buf, len);
}

static void gmcs_destroy(void *data)
{
	struct gmcs *gmcs = data;

	DBG_IDX(0xffff, "destroy %p", data);

	queue_remove(servers, gmcs);

	if (gmcs->uinput >= 0)
		close(gmcs->uinput);

	free(gmcs);
}

static void gmcs_debug(void *data, const char *str)
{
	DBG_IDX(0xffff, "%s", str);
}

static const struct bt_mcs_callback gmcs_cb = {
	.media_player_name = gmcs_media_player_name,
	.play = gmcs_play,
	.pause = gmcs_pause,
	.stop = gmcs_stop,
	.next_track = gmcs_next_track,
	.previous_track = gmcs_previous_track,
	.debug = gmcs_debug,
	.destroy = gmcs_destroy,
};

static struct gmcs *gmcs_new(struct btd_adapter *adapter)
{
	struct gmcs *gmcs;
	const char *name = btd_adapter_get_name(adapter);

	gmcs = new0(struct gmcs, 1);
	gmcs->adapter = adapter;
	gmcs->uinput = uinput_create(adapter, NULL, name, " (MCS)", key_map);
	if (gmcs->uinput < 0)
		error("MCS: failed to init uinput for %s", name);

	DBG_IDX(0xffff, "new %p", gmcs);

	return gmcs;
}

/*
 * Profile
 */

static struct btd_profile mcp_gmcs_profile;

static int add_service(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct bt_mcp *mcp = btd_service_get_user_data(service);
	bool gmcs;

	if (mcp)
		return -EALREADY;

	gmcs = btd_service_get_profile(service) == &mcp_gmcs_profile;

	mcp = bt_mcp_attach(client, gmcs, &mcp_cb, service);
	if (!mcp) {
		DBG("Unable to attach MCP");
		return -EINVAL;
	}

	btd_service_set_user_data(service, mcp);
	return 0;
}

static void remove_service(struct btd_service *service)
{
	struct bt_mcp *mcp = btd_service_get_user_data(service);

	btd_service_set_user_data(service, NULL);
	bt_mcp_detach(mcp);
}

static int mcp_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	return add_service(service);
}

static int mcp_connect(struct btd_service *service)
{
	return 0;
}

static int mcp_disconnect(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("%s", addr);

	remove_service(service);
	btd_service_disconnecting_complete(service, 0);
	return 0;
}

static int mcp_probe(struct btd_service *service)
{
	return 0;
}

static void mcp_remove(struct btd_service *service)
{
	remove_service(service);
}

static int gmcs_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct gatt_db *db = btd_gatt_database_get_db(database);
	struct gmcs *gmcs;

	gmcs = gmcs_new(adapter);
	if (!gmcs)
		return -EINVAL;

	gmcs->mcs = bt_mcs_register(db, true, &gmcs_cb, gmcs);
	if (!gmcs->mcs) {
		gmcs_destroy(gmcs);
		return -EINVAL;
	}

	if (!servers)
		servers = queue_new();
	queue_push_tail(servers, gmcs);

	return 0;
}

static void gmcs_remove(struct btd_profile *p, struct btd_adapter *adapter)
{
	struct btd_gatt_database *database = btd_adapter_get_database(adapter);
	struct gatt_db *db = btd_gatt_database_get_db(database);

	bt_mcs_unregister_all(db);
}

static struct btd_profile mcp_gmcs_profile = {
	.name			= "mcp-gmcs",
	.priority		= BTD_PROFILE_PRIORITY_MEDIUM,
	.bearer			= BTD_PROFILE_BEARER_LE,
	.remote_uuid		= GMCS_UUID_STR,
	.device_probe		= mcp_probe,
	.device_remove		= mcp_remove,
	.accept			= mcp_accept,
	.connect		= mcp_connect,
	.disconnect		= mcp_disconnect,

	.adapter_probe		= gmcs_probe,
	.adapter_remove		= gmcs_remove,

	.experimental = true,
};

static struct btd_profile mcp_mcs_profile = {
	.name			= "mcp-mcs",
	.priority		= BTD_PROFILE_PRIORITY_MEDIUM,
	.bearer			= BTD_PROFILE_BEARER_LE,
	.remote_uuid		= MCS_UUID_STR,
	.device_probe		= mcp_probe,
	.device_remove		= mcp_remove,
	.accept			= mcp_accept,
	.connect		= mcp_connect,
	.disconnect		= mcp_disconnect,

	.adapter_probe		= NULL,
	.adapter_remove		= NULL,

	.experimental = true,
};

static int mcp_init(void)
{
	int err;

	err = btd_profile_register(&mcp_gmcs_profile);
	if (err)
		return err;

	err = btd_profile_register(&mcp_mcs_profile);
	if (err) {
		btd_profile_unregister(&mcp_gmcs_profile);
		return err;
	}

	return err;
}

static void mcp_exit(void)
{
	btd_profile_unregister(&mcp_gmcs_profile);
	btd_profile_unregister(&mcp_mcs_profile);
}

BLUETOOTH_PLUGIN_DEFINE(mcp, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							mcp_init, mcp_exit)
