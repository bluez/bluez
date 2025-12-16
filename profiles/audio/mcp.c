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
#include <unistd.h>
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
#include "src/shared/uinput.h"

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
#include "media.h"

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

	free(name);
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

static bool get_playing_order(uint8_t order, const char **repeat,
							const char **shuffle)
{
	unsigned int i;

	*repeat = "off";
	*shuffle = "off";

	for (i = 0; i < ARRAY_SIZE(playing_orders); ++i) {
		*shuffle = playing_orders[i].shuffle ? "alltracks" : "off";
		if (order == playing_orders[i].basic) {
			break;
		} else if (order == playing_orders[i].repeat) {
			*repeat = playing_orders[i].single ? "singletrack" :
				"alltracks";
			break;
		}
	}
	if (i == ARRAY_SIZE(playing_orders))
		return false;

	return true;
}

static void remote_playing_order(void *data, uint8_t order)
{
	struct remote_player *remote = data;
	const char *repeat, *shuffle;

	remote->playing_order = order;

	if (!get_playing_order(order, &repeat, &shuffle))
		return;

	media_player_set_setting(remote->mp, "Repeat", repeat);
	media_player_set_setting(remote->mp, "Shuffle", shuffle);
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
		bool repeat = (strcasecmp(value, "alltracks") == 0);
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

		if (strcasecmp(value, "singletrack") == 0)
			order = BT_MCS_ORDER_SINGLE_REPEAT;

		DBG("Set Repeat %s -> 0x%02x", value, order);

		if (order == remote->playing_order)
			return true;
		return bt_mcp_set_playing_order(remote->mcp, remote->ccid,
									order);
	}

	if (strcmp(key, "Shuffle") == 0) {
		bool shuffle = (strcasecmp(value, "off") != 0);
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
 * Local player.
 *
 * TODO: maybe expose multiple MCS instances, as many as there are players. We'd
 * have to keep unused instances around in inactive state, so that we don't
 * consume ATT handles when players disappear/reappear.
 *
 * If an instance has no local player, for GMCS we forward key presses to
 * uinput. Other MCS instances should do nothing when inactive.
 */

struct mcs_instance;

struct player_link {
	struct local_player *lp;
	unsigned int id;
	struct mcs_instance *instance;
};

struct mcs_instance {
	struct btd_adapter *adapter;
	struct bt_mcs *mcs;
	struct queue *player_links;
	bool at_start;

	/* GMCS-specific */
	struct bt_uinput *uinput;
	unsigned int player_watch_id;
};

static const struct bt_uinput_key_map key_map[] = {
	{ "Play",	BT_MCS_CMD_PLAY,		KEY_PLAYCD },
	{ "Stop",	BT_MCS_CMD_STOP,		KEY_STOPCD },
	{ "Pause",	BT_MCS_CMD_PAUSE,		KEY_PAUSECD },
	{ "Next Track",	BT_MCS_CMD_NEXT_TRACK,		KEY_NEXTSONG },
	{ "Prev Track",	BT_MCS_CMD_PREV_TRACK,		KEY_PREVIOUSSONG },
	{ NULL }
};

static struct queue *servers;

static struct player_link *mcs_get_active(struct mcs_instance *mcs)
{
	return queue_peek_head(mcs->player_links);
}

static bool player_link_is_active(struct player_link *p)
{
	return mcs_get_active(p->instance) == p;
}

static void mcs_update_media_state(struct mcs_instance *mcs)
{
	struct player_link *p = mcs_get_active(mcs);
	const char *status = NULL;
	uint8_t state;

	mcs->at_start = false;

	if (p)
		status = local_player_get_status(p->lp);

	if (!status) {
		state = BT_MCS_STATE_INACTIVE;
	} else if (!strcasecmp(status, "playing")) {
		state = BT_MCS_STATE_PLAYING;
	} else if (!strcasecmp(status, "stopped")) {
		mcs->at_start = true;
		state = BT_MCS_STATE_PAUSED;
	} else if (!strcasecmp(status, "paused")) {
		state = BT_MCS_STATE_PAUSED;
	} else if (!strcasecmp(status, "forward-seek") ||
					!strcasecmp(status, "backward-seek")) {
		state = BT_MCS_STATE_SEEKING;
	} else {
		state = BT_MCS_STATE_INACTIVE;
	}

	bt_mcs_set_media_state(mcs->mcs, state);
	bt_mcs_changed(mcs->mcs, MCS_TRACK_POSITION_CHRC_UUID);
}

static void mcs_player_changed(struct mcs_instance *mcs)
{
	struct player_link *p = mcs_get_active(mcs);
	const char *name = p ? local_player_get_player_name(p->lp) : NULL;

	DBG("active: %p %s", p, name ? name : "");

	bt_mcs_changed(mcs->mcs, MCS_MEDIA_PLAYER_NAME_CHRC_UUID);
	mcs_update_media_state(mcs);

	bt_mcs_changed(mcs->mcs, MCS_TRACK_TITLE_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_TRACK_DURATION_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_TRACK_POSITION_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_PLAYBACK_SPEED_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_SEEKING_SPEED_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_PLAYING_ORDER_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_TRACK_CHANGED_CHRC_UUID);
}

static bool player_link_make_active(struct player_link *p)
{
	struct mcs_instance *mcs = p->instance;

	if (player_link_is_active(p))
		return false;

	queue_remove(mcs->player_links, p);
	queue_push_head(mcs->player_links, p);

	mcs_player_changed(mcs);
	return true;
}

static void lp_status_changed(void *user_data)
{
	struct player_link *p = user_data;
	struct mcs_instance *mcs = p->instance;
	const char *status = local_player_get_status(p->lp);

	/* Make the last player to start playing active */
	if (!strcasecmp(status, "playing")) {
		if (player_link_make_active(p))
			return;
	}

	if (!player_link_is_active(p))
		return;

	mcs_update_media_state(mcs);
}

static void lp_track_position(uint32_t old_ms, uint32_t new_ms, void *user_data)
{
	struct player_link *p = user_data;
	struct mcs_instance *mcs = p->instance;

	if (!player_link_is_active(p))
		return;

	bt_mcs_changed(mcs->mcs, MCS_TRACK_POSITION_CHRC_UUID);
}

static void lp_track_changed(void *user_data)
{
	struct player_link *p = user_data;
	struct mcs_instance *mcs = p->instance;

	mcs->at_start = false;

	if (!player_link_is_active(p))
		return;

	bt_mcs_changed(mcs->mcs, MCS_TRACK_TITLE_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_TRACK_POSITION_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_TRACK_DURATION_CHRC_UUID);
	bt_mcs_changed(mcs->mcs, MCS_TRACK_CHANGED_CHRC_UUID);
}

static void lp_settings_changed(const char *key, void *user_data)
{
	struct player_link *p = user_data;
	struct mcs_instance *mcs = p->instance;

	if (!player_link_is_active(p))
		return;
	if (strcasecmp(key, "Shuffle") && strcasecmp(key, "Repeat"))
		return;

	bt_mcs_changed(mcs->mcs, MCS_PLAYING_ORDER_CHRC_UUID);
}

static void lp_player_removed(void *user_data)
{
	struct player_link *p = user_data;
	struct mcs_instance *mcs = p->instance;
	bool active = player_link_is_active(p);

	DBG("%p", p);

	queue_remove(mcs->player_links, p);
	free(p);

	if (active)
		mcs_player_changed(mcs);
}

const struct local_player_callback local_player_cb = {
	.status_changed = lp_status_changed,
	.track_position = lp_track_position,
	.track_changed = lp_track_changed,
	.settings_changed = lp_settings_changed,
	.player_removed = lp_player_removed,
};

static bool mcs_command(struct mcs_instance *mcs, uint8_t cmd)
{
	unsigned int i;

	/* Emulate media key press */
	if (!mcs->uinput)
		return false;

	for (i = 0; i < ARRAY_SIZE(key_map); ++i) {
		if (key_map[i].code == cmd) {
			DBG("MCS press %s", key_map[i].name);
			bt_uinput_send_key(mcs->uinput, key_map[i].uinput, 1);
			bt_uinput_send_key(mcs->uinput, key_map[i].uinput, 0);
			break;
		}
	}

	/* We are inactive, so command does not cause state changes and
	 * does not succeed, even though we do generate the key presses.
	 * This should be OK vs. MCP v1.0.1 p. 26
	 */
	return false;
}

static bool mcs_play(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);

	if (p && local_player_play(p->lp))
		return true;
	return mcs_command(mcs, BT_MCS_CMD_PLAY);
}

static bool mcs_pause(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);

	if (p && local_player_pause(p->lp))
		return true;
	return mcs_command(mcs, BT_MCS_CMD_PAUSE);
}

static bool mcs_stop(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);

	if (p && local_player_stop(p->lp)) {
		mcs->at_start = true;
		return true;
	}
	return mcs_command(mcs, BT_MCS_CMD_STOP);
}

static bool mcs_next_track(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);

	if (p && local_player_next(p->lp)) {
		mcs->at_start = true;
		return true;
	}
	return mcs_command(data, BT_MCS_CMD_NEXT_TRACK);
}

static bool mcs_previous_track(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);

	if (p && local_player_previous(p->lp)) {
		mcs->at_start = true;
		return true;
	}
	return mcs_command(data, BT_MCS_CMD_PREV_TRACK);
}

static void mcs_media_player_name(void *data, struct iovec *buf, size_t size)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);
	const char *name = NULL;

	if (p)
		name = local_player_get_player_name(p->lp);
	if (!name)
		name = btd_adapter_get_name(mcs->adapter);

	snprintf((void *)buf->iov_base, size, "%s", name);
	util_iov_push(buf, strlen(buf->iov_base));
}

static void mcs_track_title(void *data, struct iovec *buf, size_t size)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);
	const char *name = NULL;

	if (p)
		name = local_player_get_metadata(p->lp, "Title");
	if (!name)
		name = "";

	snprintf((void *)buf->iov_base, size, "%s", name);
	util_iov_push(buf, strlen(buf->iov_base));
}

static int32_t mcs_track_duration(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);
	const char *duration = NULL;
	long duration_ms;

	if (p)
		duration = local_player_get_metadata(p->lp, "Duration");
	if (!duration)
		return BT_MCS_DURATION_UNAVAILABLE;

	duration_ms = atol(duration);
	return duration_ms / 10;
}

static int32_t mcs_track_position(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);

	if (!p)
		return BT_MCS_POSITION_UNAVAILABLE;

	if (mcs->at_start)
		return 0;

	return local_player_get_position(p->lp) / 10;
}

static uint8_t mcs_playing_order(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);
	bool shuffle, repeat, single;
	const char *shuffle_str, *repeat_str;

	if (!p)
		return BT_MCS_ORDER_IN_ORDER_ONCE;

	shuffle_str = local_player_get_setting(p->lp, "Shuffle");
	repeat_str = local_player_get_setting(p->lp, "Repeat");

	shuffle = shuffle_str && strcasecmp(shuffle_str, "off");
	repeat = repeat_str && strcasecmp(repeat_str, "off");
	single = repeat_str && !strcasecmp(repeat_str, "singletrack");
	if (single)
		return BT_MCS_ORDER_SINGLE_REPEAT;

	if (shuffle)
		return repeat ? BT_MCS_ORDER_SHUFFLE_REPEAT :
						BT_MCS_ORDER_SHUFFLE_ONCE;
	return repeat ? BT_MCS_ORDER_IN_ORDER_REPEAT :
						BT_MCS_ORDER_IN_ORDER_ONCE;
}

static uint16_t mcs_playing_order_supported(void *data)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);

	if (!p)
		return BT_MCS_ORDER_SUPPORTED_IN_ORDER_ONCE;

	return BT_MCS_ORDER_SUPPORTED_SINGLE_REPEAT |
		BT_MCS_ORDER_SUPPORTED_IN_ORDER_ONCE |
		BT_MCS_ORDER_SUPPORTED_IN_ORDER_REPEAT |
		BT_MCS_ORDER_SUPPORTED_SHUFFLE_ONCE |
		BT_MCS_ORDER_SUPPORTED_SHUFFLE_REPEAT;
}

static bool mcs_set_track_position(void *data, int32_t value)
{
	/* TODO: add support to setting position in org.bluez.MediaPlayer */
	return false;
}

static bool mcs_set_playing_order(void *data, uint8_t value)
{
	struct mcs_instance *mcs = data;
	struct player_link *p = mcs_get_active(mcs);
	const char *repeat, *shuffle;
	bool ok = true;

	if (!p)
		return false;
	if (!get_playing_order(value, &repeat, &shuffle))
		return false;

	if (local_player_set_setting(p->lp, "Shuffle", shuffle) < 0)
		ok = false;
	if (local_player_set_setting(p->lp, "Repeat", repeat) < 0)
		ok = false;

	bt_mcs_changed(mcs->mcs, MCS_PLAYING_ORDER_CHRC_UUID);
	return ok;
}

static void player_link_destroy(void *data)
{
	struct player_link *p = data;

	DBG("%p", p);

	local_player_unregister_callbacks(p->lp, p->id);
	free(p);
}

static void mcs_destroy(void *data)
{
	struct mcs_instance *mcs = data;

	DBG("destroy %p", data);

	queue_remove(servers, mcs);

	bt_uinput_destroy(mcs->uinput);

	queue_destroy(mcs->player_links, player_link_destroy);

	if (mcs->player_watch_id)
		local_player_unregister_watch(mcs->player_watch_id);

	free(mcs);
}

static void mcs_debug(void *data, const char *str)
{
	DBG_IDX(0xffff, "%s", str);
}

static const struct bt_mcs_callback gmcs_cb = {
	.media_player_name = mcs_media_player_name,
	.track_title = mcs_track_title,
	.track_duration = mcs_track_duration,
	.track_position = mcs_track_position,
	.playing_order = mcs_playing_order,
	.playing_order_supported = mcs_playing_order_supported,
	.set_track_position = mcs_set_track_position,
	.set_playing_order = mcs_set_playing_order,
	.play = mcs_play,
	.pause = mcs_pause,
	.stop = mcs_stop,
	.next_track = mcs_next_track,
	.previous_track = mcs_previous_track,
	.debug = mcs_debug,
	.destroy = mcs_destroy,
};

static void uinput_debug(const char *str, void *data)
{
	DBG_IDX(0xffff, "%s", str);
}

static void gmcs_player_added(struct local_player *lp, void *user_data)
{
	struct mcs_instance *gmcs = user_data;
	struct btd_adapter *adapter = local_player_get_adapter(lp);
	struct player_link *p;

	if (adapter != gmcs->adapter)
		return;

	p = new0(struct player_link, 1);
	p->lp = lp;
	p->id = local_player_register_callbacks(lp, &local_player_cb, p);
	p->instance = gmcs;
	if (!p->id) {
		free(p);
		return;
	}

	DBG("%p", p);

	queue_push_tail(gmcs->player_links, p);

	if (queue_length(gmcs->player_links) == 1)
		mcs_player_changed(gmcs);
}

static struct mcs_instance *gmcs_new(struct btd_adapter *adapter)
{
	struct mcs_instance *gmcs;
	const char *name = btd_adapter_get_name(adapter);
	int err;

	gmcs = new0(struct mcs_instance, 1);
	gmcs->adapter = adapter;

	gmcs->uinput = bt_uinput_new(name, " (MCS)",
			btd_adapter_get_address(adapter), NULL);
	bt_uinput_set_debug(gmcs->uinput, uinput_debug, gmcs);

	err = bt_uinput_create(gmcs->uinput, key_map);
	if (err < 0) {
		error("MCS: failed to init uinput for %s: %s", name,
								strerror(-err));
		bt_uinput_destroy(gmcs->uinput);
		gmcs->uinput = NULL;
	}

	gmcs->player_links = queue_new();
	gmcs->player_watch_id = local_player_register_watch(gmcs_player_added,
									gmcs);

	DBG("new %p", gmcs);
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
	struct mcs_instance *gmcs;

	DBG("Add GMCS server %s", adapter_get_path(adapter));

	gmcs = gmcs_new(adapter);
	if (!gmcs)
		return -EINVAL;

	gmcs->mcs = bt_mcs_register(db, true, &gmcs_cb, gmcs);
	if (!gmcs->mcs) {
		mcs_destroy(gmcs);
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

	DBG("Remove GMCS server %s", adapter_get_path(adapter));
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
