/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

struct media_endpoint;
struct local_player;

typedef void (*media_endpoint_cb_t) (struct media_endpoint *endpoint,
					void *ret, int size, void *user_data);

int media_register(struct btd_adapter *btd_adapter);
void media_unregister(struct btd_adapter *btd_adapter);

struct a2dp_sep *media_endpoint_get_sep(struct media_endpoint *endpoint);
const char *media_endpoint_get_uuid(struct media_endpoint *endpoint);
bool media_endpoint_get_delay_reporting(struct media_endpoint *endpoint);
uint8_t media_endpoint_get_codec(struct media_endpoint *endpoint);
struct btd_adapter *media_endpoint_get_btd_adapter(
					struct media_endpoint *endpoint);
bool media_endpoint_is_broadcast(struct media_endpoint *endpoint);

const struct media_endpoint *media_endpoint_get_asha(void);

/*
 * Local media player
 */
struct local_player_callback {
	void (*status_changed)(void *user_data);
	void (*track_position)(uint32_t old_ms, uint32_t new_ms,
							void *user_data);
	void (*track_changed)(void *user_data);
	void (*settings_changed)(const char *key, void *user_data);

	/* Player removed (no further callbacks) */
	void (*player_removed)(void *user_data);
};

unsigned int local_player_register_callbacks(struct local_player *lp,
		const struct local_player_callback *cb, void *user_data);
void local_player_unregister_callbacks(struct local_player *lp,
							unsigned int id);

struct btd_adapter *local_player_get_adapter(struct local_player *lp);

GList *local_player_list_settings(struct local_player *lp);
const char *local_player_get_setting(struct local_player *lp, const char *key);
int local_player_set_setting(struct local_player *lp, const char *key,
							const char *value);
const char *local_player_get_metadata(struct local_player *lp, const char *key);
GList *local_player_list_metadata(struct local_player *lp);
const char *local_player_get_status(struct local_player *lp);
uint32_t local_player_get_position(struct local_player *lp);
uint32_t local_player_get_duration(struct local_player *lp);
const char *local_player_get_player_name(struct local_player *lp);
bool local_player_have_track(struct local_player *lp);
bool local_player_play(struct local_player *lp);
bool local_player_stop(struct local_player *lp);
bool local_player_pause(struct local_player *lp);
bool local_player_next(struct local_player *lp);
bool local_player_previous(struct local_player *lp);

typedef void (*local_player_added_t)(struct local_player *lp, void *user_data);

unsigned int local_player_register_watch(local_player_added_t cb,
							void *user_data);
void local_player_unregister_watch(unsigned int id);
