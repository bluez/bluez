// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2025 Pauli Virtanen
 *
 */

#include <stdint.h>

#include <glib.h>

#include "src/shared/util.h"
#include "src/shared/queue.h"

#include "src/adapter.h"
#include "src/device.h"
#include "src/log.h"

#include "avrcp.h"
#include "media.h"

struct player_link {
	struct local_player *lp;
	struct avrcp_player *avrcp;
	unsigned int id;
};

static unsigned int watch_id;
static struct queue *players;

static GList *lp_list_settings(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_list_settings(p->lp);
}

static const char *lp_get_setting(const char *key, void *user_data)
{
	struct player_link *p = user_data;

	return local_player_get_setting(p->lp, key);
}

static int lp_set_setting(const char *key, const char *value, void *user_data)
{
	struct player_link *p = user_data;

	return local_player_set_setting(p->lp, key, value);
}

static uint64_t lp_get_uid(void *user_data)
{
	struct player_link *p = user_data;

	if (!local_player_have_track(p->lp))
		return UINT64_MAX;

	return 0;
}

static const char *lp_get_metadata(const char *key, void *user_data)
{
	struct player_link *p = user_data;

	return local_player_get_metadata(p->lp, key);
}

static GList *lp_list_metadata(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_list_metadata(p->lp);
}

static const char *lp_get_status(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_get_status(p->lp);
}

static uint32_t lp_get_position(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_get_position(p->lp);
}

static uint32_t lp_get_duration(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_get_duration(p->lp);
}

static const char *lp_get_name(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_get_player_name(p->lp);
}

static bool lp_play(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_play(p->lp);
}

static bool lp_stop(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_stop(p->lp);
}

static bool lp_pause(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_pause(p->lp);
}

static bool lp_next(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_next(p->lp);
}

static bool lp_previous(void *user_data)
{
	struct player_link *p = user_data;

	return local_player_previous(p->lp);
}

static struct avrcp_player_cb avrcp_cb = {
	.list_settings = lp_list_settings,
	.get_setting = lp_get_setting,
	.set_setting = lp_set_setting,
	.list_metadata = lp_list_metadata,
	.get_uid = lp_get_uid,
	.get_metadata = lp_get_metadata,
	.get_position = lp_get_position,
	.get_duration = lp_get_duration,
	.get_status = lp_get_status,
	.get_name = lp_get_name,
	.play = lp_play,
	.stop = lp_stop,
	.pause = lp_pause,
	.next = lp_next,
	.previous = lp_previous,
};

static void status_changed(void *user_data)
{
	struct player_link *p = user_data;

	avrcp_player_event(p->avrcp, AVRCP_EVENT_STATUS_CHANGED,
						local_player_get_status(p->lp));
}

static void track_position(uint32_t old, uint32_t position, void *user_data)
{
	struct player_link *p = user_data;
	uint32_t duration = local_player_get_duration(p->lp);
	const char *status;

	if (position > old)
		status = "forward-seek";
	else
		status = "reverse-seek";

	if (!position) {
		avrcp_player_event(p->avrcp,
					AVRCP_EVENT_TRACK_REACHED_START, NULL);
		return;
	}

	/*
	 * If position is the maximum value allowed or greater than track's
	 * duration, we send a track-reached-end event.
	 */
	if (position == UINT32_MAX || position >= duration) {
		avrcp_player_event(p->avrcp, AVRCP_EVENT_TRACK_REACHED_END,
									NULL);
		return;
	}

	/* Send a status change to force resync the position */
	avrcp_player_event(p->avrcp, AVRCP_EVENT_STATUS_CHANGED, status);
}

static void track_changed(void *user_data)
{
	struct player_link *p = user_data;
	uint64_t uid = lp_get_uid(p->lp);

	avrcp_player_event(p->avrcp, AVRCP_EVENT_TRACK_CHANGED, &uid);
	avrcp_player_event(p->avrcp, AVRCP_EVENT_TRACK_REACHED_START, NULL);
}

static void settings_changed(const char *key, void *user_data)
{
	struct player_link *p = user_data;

	avrcp_player_event(p->avrcp, AVRCP_EVENT_SETTINGS_CHANGED, key);
}

static void player_removed(void *user_data)
{
	struct player_link *p = user_data;

	DBG("%p", p);

	avrcp_unregister_player(p->avrcp);
}

static const struct local_player_callback player_cb =  {
	.status_changed = status_changed,
	.track_position = track_position,
	.track_changed = track_changed,
	.settings_changed = settings_changed,
	.player_removed = player_removed,
};

static void player_destroy(gpointer data)
{
	struct player_link *p = data;

	DBG("%p", p);

	queue_remove(players, p);

	local_player_unregister_callbacks(p->lp, p->id);
	free(p);
}

static void player_added(struct local_player *lp, void *user_data)
{
	struct btd_adapter *adapter = local_player_get_adapter(lp);
	struct player_link *p;

	p = new0(struct player_link, 1);
	p->lp = lp;
	p->id = local_player_register_callbacks(lp, &player_cb, p);
	if (!p->id) {
		free(p);
		return;
	}

	p->avrcp = avrcp_register_player(adapter, &avrcp_cb, p, player_destroy);
	if (!p->avrcp) {
		local_player_unregister_callbacks(lp, p->id);
		free(p);
		return;
	}

	DBG("%p", p);

	queue_push_tail(players, p);
}

void avrcp_player_init(void)
{
	DBG("");

	if (watch_id)
		return;

	watch_id = local_player_register_watch(player_added, NULL);
	players = queue_new();
}

void avrcp_player_exit(void)
{
	DBG("");

	queue_destroy(players, player_removed);
	players = NULL;

	if (!watch_id)
		return;

	local_player_unregister_watch(watch_id);
	watch_id = 0;
}
