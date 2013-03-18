/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2012-2012  Intel Corporation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "log.h"
#include "player.h"
#include "dbus-common.h"
#include "error.h"

#define MEDIA_PLAYER_INTERFACE "org.bluez.MediaPlayer1"
#define MEDIA_FOLDER_INTERFACE "org.bluez.MediaFolder1"
#define MEDIA_ITEM_INTERFACE "org.bluez.MediaItem1"

struct player_callback {
	const struct media_player_callback *cbs;
	void *user_data;
};

struct pending_req {
	GDBusPendingPropertySet id;
	const char *key;
	const char *value;
};

struct media_item {
	struct media_player	*player;
	char			*path;		/* Item object path */
	char			*name;		/* Item name */
	player_item_type_t	type;		/* Item type */
	player_folder_type_t	folder_type;	/* Folder type */
	bool			playable;	/* Item playable flag */
};

struct media_folder {
	struct media_item	*item;		/* Folder item */
	uint32_t		number_of_items;/* Number of items */
};

struct media_player {
	char			*device;	/* Device path */
	char			*name;		/* Player name */
	char			*type;		/* Player type */
	char			*subtype;	/* Player subtype */
	bool			browsable;	/* Player browsing feature */
	bool			searchable;	/* Player searching feature */
	struct media_folder	*folder;	/* Player current folder */
	struct media_item	*playlist;	/* Player current playlist */
	char			*path;		/* Player object path */
	GHashTable		*settings;	/* Player settings */
	GHashTable		*track;		/* Player current track */
	char			*status;
	uint32_t		position;
	GTimer			*progress;
	guint			process_id;
	struct player_callback	*cb;
	GSList			*pending;
	GSList			*folders;
};

static void append_metadata(void *key, void *value, void *user_data)
{
	DBusMessageIter *dict = user_data;

	if (strcasecmp((char *) key, "Duration") == 0 ||
			strcasecmp((char *) key, "TrackNumber") == 0 ||
			strcasecmp((char *) key, "NumberOfTracks") == 0)  {
		uint32_t num = atoi(value);
		dict_append_entry(dict, key, DBUS_TYPE_UINT32, &num);
		return;
	}

	dict_append_entry(dict, key, DBUS_TYPE_STRING, &value);
}

static struct pending_req *find_pending(struct media_player *mp,
							const char *key)
{
	GSList *l;

	for (l = mp->pending; l; l = l->next) {
		struct pending_req *p = l->data;

		if (strcasecmp(key, p->key) == 0)
			return p;
	}

	return NULL;
}

static struct pending_req *pending_new(GDBusPendingPropertySet id,
					const char *key, const char *value)
{
	struct pending_req *p;

	p = g_new0(struct pending_req, 1);
	p->id = id;
	p->key = key;
	p->value = value;

	return p;
}

static uint32_t media_player_get_position(struct media_player *mp)
{
	double timedelta;
	uint32_t sec, msec;

	if (g_strcmp0(mp->status, "playing") != 0)
		return mp->position;

	timedelta = g_timer_elapsed(mp->progress, NULL);

	sec = (uint32_t) timedelta;
	msec = (uint32_t) ((timedelta - sec) * 1000);

	return mp->position + sec * 1000 + msec;
}

static gboolean get_position(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;
	uint32_t position;

	position = media_player_get_position(mp);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &position);

	return TRUE;
}

static gboolean status_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_player *mp = data;

	return mp->status != NULL;
}

static gboolean get_status(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;

	if (mp->status == NULL)
		return FALSE;

	DBG("%s", mp->status);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &mp->status);

	return TRUE;
}

static gboolean setting_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_player *mp = data;
	const char *value;

	value = g_hash_table_lookup(mp->settings, property->name);

	return value ? TRUE : FALSE;
}

static gboolean get_setting(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;
	const char *value;

	value = g_hash_table_lookup(mp->settings, property->name);
	if (value == NULL)
		return FALSE;

	DBG("%s %s", property->name, value);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &value);

	return TRUE;
}

static void player_set_setting(struct media_player *mp,
					GDBusPendingPropertySet id,
					const char *key, const char *value)
{
	struct player_callback *cb = mp->cb;
	struct pending_req *p;

	if (cb == NULL || cb->cbs->set_setting == NULL) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".NotSupported",
					"Operation is not supported");
		return;
	}

	p = find_pending(mp, key);
	if (p != NULL) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InProgress",
					"Operation already in progress");
		return;
	}

	if (!cb->cbs->set_setting(mp, key, value, cb->user_data)) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	p = pending_new(id, key, value);

	mp->pending = g_slist_append(mp->pending, p);
}

static void set_setting(const GDBusPropertyTable *property,
			DBusMessageIter *iter, GDBusPendingPropertySet id,
			void *data)
{
	struct media_player *mp = data;
	const char *value;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
		g_dbus_pending_property_error(id,
					ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
		return;
	}

	dbus_message_iter_get_basic(iter, &value);

	player_set_setting(mp, id, property->name, value);
}

static gboolean track_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_player *mp = data;

	return g_hash_table_size(mp->track) != 0;
}

static gboolean get_track(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	g_hash_table_foreach(mp->track, append_metadata, &dict);

	dbus_message_iter_close_container(iter, &dict);

	return TRUE;
}

static gboolean get_device(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
								&mp->device);

	return TRUE;
}

static gboolean name_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_player *mp = data;

	return mp->name != NULL;
}

static gboolean get_name(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;

	if (mp->name == NULL)
		return FALSE;

	DBG("%s", mp->name);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &mp->name);

	return TRUE;
}

static gboolean type_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_player *mp = data;

	return mp->type != NULL;
}

static gboolean get_type(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;

	if (mp->type == NULL)
		return FALSE;

	DBG("%s", mp->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &mp->type);

	return TRUE;
}

static gboolean subtype_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_player *mp = data;

	return mp->subtype != NULL;
}

static gboolean get_subtype(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;

	if (mp->subtype == NULL)
		return FALSE;

	DBG("%s", mp->subtype);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &mp->subtype);

	return TRUE;
}

static gboolean browsable_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_player *mp = data;

	return mp->folder != NULL;
}

static gboolean get_browsable(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;
	dbus_bool_t value;

	if (mp->folder == NULL)
		return FALSE;

	DBG("%s", mp->browsable ? "true" : "false");

	value = mp->browsable;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static gboolean searchable_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct media_player *mp = data;

	return mp->folder != NULL;
}

static gboolean get_searchable(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;
	dbus_bool_t value;

	if (mp->folder == NULL)
		return FALSE;

	DBG("%s", mp->searchable ? "true" : "false");

	value = mp->searchable;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static gboolean playlist_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct media_player *mp = data;

	return mp->playlist != NULL;
}

static gboolean get_playlist(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;
	struct media_item *playlist = mp->playlist;

	if (playlist == NULL)
		return FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&playlist->path);

	return TRUE;
}

static DBusMessage *media_player_play(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct media_player *mp = data;
	struct player_callback *cb = mp->cb;
	int err;

	if (cb->cbs->play == NULL)
		return btd_error_not_supported(msg);

	err = cb->cbs->play(mp, cb->user_data);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *media_player_pause(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct media_player *mp = data;
	struct player_callback *cb = mp->cb;
	int err;

	if (cb->cbs->pause == NULL)
		return btd_error_not_supported(msg);

	err = cb->cbs->pause(mp, cb->user_data);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *media_player_stop(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct media_player *mp = data;
	struct player_callback *cb = mp->cb;
	int err;

	if (cb->cbs->stop == NULL)
		return btd_error_not_supported(msg);

	err = cb->cbs->stop(mp, cb->user_data);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *media_player_next(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct media_player *mp = data;
	struct player_callback *cb = mp->cb;
	int err;

	if (cb->cbs->next == NULL)
		return btd_error_not_supported(msg);

	err = cb->cbs->next(mp, cb->user_data);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *media_player_previous(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct media_player *mp = data;
	struct player_callback *cb = mp->cb;
	int err;

	if (cb->cbs->previous == NULL)
		return btd_error_not_supported(msg);

	err = cb->cbs->previous(mp, cb->user_data);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *media_player_fast_forward(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct media_player *mp = data;
	struct player_callback *cb = mp->cb;
	int err;

	if (cb->cbs->fast_forward == NULL)
		return btd_error_not_supported(msg);

	err = cb->cbs->fast_forward(mp, cb->user_data);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *media_player_rewind(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	struct media_player *mp = data;
	struct player_callback *cb = mp->cb;
	int err;

	if (cb->cbs->rewind == NULL)
		return btd_error_not_supported(msg);

	err = cb->cbs->rewind(mp, cb->user_data);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable media_player_methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("Play", NULL, NULL, media_player_play) },
	{ GDBUS_EXPERIMENTAL_METHOD("Pause", NULL, NULL, media_player_pause) },
	{ GDBUS_EXPERIMENTAL_METHOD("Stop", NULL, NULL, media_player_stop) },
	{ GDBUS_EXPERIMENTAL_METHOD("Next", NULL, NULL, media_player_next) },
	{ GDBUS_EXPERIMENTAL_METHOD("Previous", NULL, NULL,
						media_player_previous) },
	{ GDBUS_EXPERIMENTAL_METHOD("FastForward", NULL, NULL,
						media_player_fast_forward) },
	{ GDBUS_EXPERIMENTAL_METHOD("Rewind", NULL, NULL,
						media_player_rewind) },
	{ }
};

static const GDBusSignalTable media_player_signals[] = {
	{ }
};

static const GDBusPropertyTable media_player_properties[] = {
	{ "Name", "s", get_name, NULL, name_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Type", "s", get_type, NULL, type_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Subtype", "s", get_subtype, NULL, subtype_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Position", "u", get_position, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Status", "s", get_status, NULL, status_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Equalizer", "s", get_setting, set_setting, setting_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Repeat", "s", get_setting, set_setting, setting_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Shuffle", "s", get_setting, set_setting, setting_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Scan", "s", get_setting, set_setting, setting_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Track", "a{sv}", get_track, NULL, track_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Device", "o", get_device, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Browsable", "b", get_browsable, NULL, browsable_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Searchable", "b", get_searchable, NULL, searchable_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Playlist", "o", get_playlist, NULL, playlist_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static DBusMessage *media_folder_search(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return btd_error_failed(msg, strerror(ENOTSUP));
}

static DBusMessage *media_folder_list_items(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return btd_error_failed(msg, strerror(ENOTSUP));
}


static DBusMessage *media_folder_change_folder(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return btd_error_failed(msg, strerror(ENOTSUP));
}

static gboolean folder_name_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct media_player *mp = data;
	struct media_folder *folder = mp->folder;

	if (folder == NULL || folder->item == NULL)
		return FALSE;

	return folder->item->name != NULL;
}

static gboolean get_folder_name(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;
	struct media_folder *folder = mp->folder;

	if (folder == NULL || folder->item == NULL)
		return FALSE;

	DBG("%s", folder->item->name);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
							&folder->item->name);

	return TRUE;
}

static gboolean items_exists(const GDBusPropertyTable *property, void *data)
{
	struct media_player *mp = data;

	return mp->folder != NULL;
}

static gboolean get_items(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;
	struct media_folder *folder = mp->folder;

	if (folder == NULL)
		return FALSE;

	DBG("%u", folder->number_of_items);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
						&folder->number_of_items);

	return TRUE;
}

static const GDBusMethodTable media_folder_methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("Search",
			GDBUS_ARGS({ "string", "s" }, { "filter", "a{sv}" }),
			GDBUS_ARGS({ "folder", "o" }),
			media_folder_search) },
	{ GDBUS_EXPERIMENTAL_METHOD("ListItems",
			GDBUS_ARGS({ "filter", "a{sv}" }),
			GDBUS_ARGS({ "items", "a{oa{sv}}" }),
			media_folder_list_items) },
	{ GDBUS_EXPERIMENTAL_METHOD("ChangeFolder",
			GDBUS_ARGS({ "folder", "o" }), NULL,
			media_folder_change_folder) },
	{ }
};

static const GDBusPropertyTable media_folder_properties[] = {
	{ "Name", "s", get_folder_name, NULL, folder_name_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "NumberOfItems", "u", get_items, NULL, items_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static void media_item_destroy(void *data)
{
	struct media_item *item = data;

	DBG("%s", item->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(), item->path,
						MEDIA_ITEM_INTERFACE);

	g_free(item->path);
	g_free(item->name);
	g_free(item);
}

static void media_folder_destroy(struct media_folder *folder)
{
	g_free(folder);
}

void media_player_destroy(struct media_player *mp)
{
	DBG("%s", mp->path);

	g_dbus_unregister_interface(btd_get_dbus_connection(), mp->path,
						MEDIA_PLAYER_INTERFACE);

	if (mp->track)
		g_hash_table_unref(mp->track);

	if (mp->settings)
		g_hash_table_unref(mp->settings);

	if (mp->process_id > 0)
		g_source_remove(mp->process_id);

	if (mp->folder) {
		g_dbus_unregister_interface(btd_get_dbus_connection(),
						mp->path,
						MEDIA_FOLDER_INTERFACE);
		media_folder_destroy(mp->folder);
	}

	g_slist_free_full(mp->pending, g_free);
	g_slist_free_full(mp->folders, media_item_destroy);

	g_timer_destroy(mp->progress);
	g_free(mp->cb);
	g_free(mp->status);
	g_free(mp->path);
	g_free(mp->device);
	g_free(mp->subtype);
	g_free(mp->type);
	g_free(mp->name);
	g_free(mp);
}

struct media_player *media_player_controller_create(const char *path,
								uint16_t id)
{
	struct media_player *mp;

	mp = g_new0(struct media_player, 1);
	mp->device = g_strdup(path);
	mp->path = g_strdup_printf("%s/player%u", path, id);
	mp->settings = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
	mp->track = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);
	mp->progress = g_timer_new();

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					mp->path, MEDIA_PLAYER_INTERFACE,
					media_player_methods,
					media_player_signals,
					media_player_properties, mp, NULL)) {
		error("D-Bus failed to register %s path", mp->path);
		media_player_destroy(mp);
		return NULL;
	}

	DBG("%s", mp->path);

	return mp;
}

void media_player_set_duration(struct media_player *mp, uint32_t duration)
{
	char *value, *curval;

	DBG("%u", duration);

	/* Only update duration if track exists */
	if (g_hash_table_size(mp->track) == 0)
		return;

	/* Ignore if duration is already set */
	curval = g_hash_table_lookup(mp->track, "Duration");
	if (curval != NULL)
		return;

	value = g_strdup_printf("%u", duration);

	g_hash_table_replace(mp->track, g_strdup("Duration"), value);

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					mp->path, MEDIA_PLAYER_INTERFACE,
					"Track");
}

void media_player_set_position(struct media_player *mp, uint32_t position)
{
	DBG("%u", position);

	/* Only update duration if track exists */
	if (g_hash_table_size(mp->track) == 0)
		return;

	mp->position = position;
	g_timer_start(mp->progress);

	g_dbus_emit_property_changed(btd_get_dbus_connection(), mp->path,
					MEDIA_PLAYER_INTERFACE, "Position");
}

void media_player_set_setting(struct media_player *mp, const char *key,
							const char *value)
{
	char *curval;
	struct pending_req *p;

	DBG("%s: %s", key, value);

	if (strcasecmp(key, "Error") == 0) {
		p = g_slist_nth_data(mp->pending, 0);
		if (p == NULL)
			return;

		g_dbus_pending_property_error(p->id, ERROR_INTERFACE ".Failed",
									value);
		goto send;
	}

	curval = g_hash_table_lookup(mp->settings, key);
	if (g_strcmp0(curval, value) == 0)
		goto done;

	g_hash_table_replace(mp->settings, g_strdup(key), g_strdup(value));
	g_dbus_emit_property_changed(btd_get_dbus_connection(), mp->path,
					MEDIA_PLAYER_INTERFACE, key);

done:
	p = find_pending(mp, key);
	if (p == NULL)
		return;

	if (strcasecmp(value, p->value) == 0)
		g_dbus_pending_property_success(p->id);
	else
		g_dbus_pending_property_error(p->id,
					ERROR_INTERFACE ".NotSupported",
					"Operation is not supported");

send:
	mp->pending = g_slist_remove(mp->pending, p);
	g_free(p);

	return;
}

const char *media_player_get_status(struct media_player *mp)
{
	return mp->status;
}

void media_player_set_status(struct media_player *mp, const char *status)
{
	DBG("%s", status);

	if (g_strcmp0(mp->status, status) == 0)
		return;

	g_free(mp->status);
	mp->status = g_strdup(status);

	g_dbus_emit_property_changed(btd_get_dbus_connection(), mp->path,
					MEDIA_PLAYER_INTERFACE, "Status");

	mp->position = media_player_get_position(mp);
	g_timer_start(mp->progress);
}

static gboolean process_metadata_changed(void *user_data)
{
	struct media_player *mp = user_data;

	mp->process_id = 0;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					mp->path, MEDIA_PLAYER_INTERFACE,
					"Track");

	return FALSE;
}

void media_player_set_metadata(struct media_player *mp, const char *key,
						void *data, size_t len)
{
	char *value, *curval;

	value = g_strndup(data, len);

	DBG("%s: %s", key, value);

	curval = g_hash_table_lookup(mp->track, key);
	if (g_strcmp0(curval, value) == 0) {
		g_free(value);
		return;
	}

	if (mp->process_id == 0) {
		g_hash_table_remove_all(mp->track);
		mp->process_id = g_idle_add(process_metadata_changed, mp);
	}

	g_hash_table_replace(mp->track, g_strdup(key), value);
}

void media_player_set_type(struct media_player *mp, const char *type)
{
	if (g_strcmp0(mp->type, type) == 0)
		return;

	DBG("%s", type);

	mp->type = g_strdup(type);

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					mp->path, MEDIA_PLAYER_INTERFACE,
					"Type");
}

void media_player_set_subtype(struct media_player *mp, const char *subtype)
{
	if (g_strcmp0(mp->subtype, subtype) == 0)
		return;

	DBG("%s", subtype);

	mp->subtype = g_strdup(subtype);

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					mp->path, MEDIA_PLAYER_INTERFACE,
					"Subtype");
}

void media_player_set_name(struct media_player *mp, const char *name)
{
	if (g_strcmp0(mp->name, name) == 0)
		return;

	DBG("%s", name);

	mp->name = g_strdup(name);

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					mp->path, MEDIA_PLAYER_INTERFACE,
					"Name");
}

void media_player_set_browsable(struct media_player *mp, bool enabled)
{
	if (mp->browsable == enabled)
		return;

	DBG("%s", enabled ? "true" : "false");

	mp->browsable = enabled;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					mp->path, MEDIA_PLAYER_INTERFACE,
					"Browsable");
}

void media_player_set_searchable(struct media_player *mp, bool enabled)
{
	if (mp->browsable == enabled)
		return;

	DBG("%s", enabled ? "true" : "false");

	mp->searchable = enabled;

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
					mp->path, MEDIA_PLAYER_INTERFACE,
					"Searchable");
}

static void media_player_set_folder_item(struct media_player *mp,
						struct media_item *item,
						uint32_t number_of_items)
{
	struct media_folder *folder;

	folder = mp->folder;

	if (folder == NULL) {
		folder = g_new0(struct media_folder, 1);
		mp->folder = folder;

		if (!g_dbus_register_interface(btd_get_dbus_connection(),
					mp->path, MEDIA_FOLDER_INTERFACE,
					media_folder_methods,
					NULL,
					media_folder_properties, mp, NULL)) {
			error("D-Bus failed to register %s on %s path",
					MEDIA_FOLDER_INTERFACE, mp->path);
			media_folder_destroy(mp->folder);
			mp->folder = NULL;
			return;
		}
	}

	folder->item = item;
	folder->number_of_items = number_of_items;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), mp->path,
				MEDIA_FOLDER_INTERFACE, "Name");
	g_dbus_emit_property_changed(btd_get_dbus_connection(), mp->path,
				MEDIA_FOLDER_INTERFACE, "NumberOfItems");
}

static struct media_item *media_player_find_folder(struct media_player *mp,
							const char *name)
{
	GSList *l;

	for (l = mp->folders; l; l = l->next) {
		struct media_item *item = l->data;

		if (item->type != PLAYER_ITEM_TYPE_FOLDER)
			continue;

		if (g_str_equal(item->name, name))
			return item;
	}

	return NULL;
}

void media_player_set_folder(struct media_player *mp, const char *name,
						uint32_t number_of_items)
{
	struct media_item *item;

	DBG("%s number of items %u", name, number_of_items);

	item = media_player_find_folder(mp, name);
	if (item == NULL) {
		error("Unknown folder: %s", name);
		return;
	}

	media_player_set_folder_item(mp, item, number_of_items);
}

void media_player_set_playlist(struct media_player *mp, const char *name)
{
	struct media_item *item;

	DBG("%s", name);

	item = media_player_find_folder(mp, name);
	if (item == NULL) {
		error("Unknown folder: %s", name);
		return;
	}

	mp->playlist = item;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), mp->path,
					MEDIA_PLAYER_INTERFACE, "Playlist");
}

static DBusMessage *media_item_play(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	return btd_error_failed(msg, strerror(ENOTSUP));
}

static DBusMessage *media_item_add_to_nowplaying(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return btd_error_failed(msg, strerror(ENOTSUP));
}

static gboolean item_name_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct media_item *item = data;

	return item->name != NULL;
}

static gboolean get_item_name(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_item *item = data;

	if (item->name == NULL)
		return FALSE;

	DBG("%s", item->name);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &item->name);

	return TRUE;
}

static const char *type_to_string(uint8_t type)
{
	switch (type) {
	case PLAYER_ITEM_TYPE_AUDIO:
		return "audio";
	case PLAYER_ITEM_TYPE_VIDEO:
		return "video";
	case PLAYER_ITEM_TYPE_FOLDER:
		return "folder";
	}

	return NULL;
}

static gboolean get_item_type(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_item *item = data;
	const char *string;

	string = type_to_string(item->type);

	DBG("%s", string);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &string);

	return TRUE;
}

static gboolean get_playable(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_item *item = data;
	dbus_bool_t value;

	DBG("%s", item->playable ? "true" : "false");

	value = item->playable;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &value);

	return TRUE;
}

static const char *folder_type_to_string(uint8_t type)
{
	switch (type) {
	case PLAYER_FOLDER_TYPE_MIXED:
		return "mixed";
	case PLAYER_FOLDER_TYPE_TITLES:
		return "titles";
	case PLAYER_FOLDER_TYPE_ALBUMS:
		return "albums";
	case PLAYER_FOLDER_TYPE_ARTISTS:
		return "artists";
	case PLAYER_FOLDER_TYPE_GENRES:
		return "genres";
	case PLAYER_FOLDER_TYPE_PLAYLISTS:
		return "playlists";
	case PLAYER_FOLDER_TYPE_YEARS:
		return "years";
	}

	return NULL;
}

static gboolean folder_type_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct media_item *item = data;

	return folder_type_to_string(item->folder_type) != NULL;
}

static gboolean get_folder_type(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_item *item = data;
	const char *string;

	string = folder_type_to_string(item->folder_type);
	if (string == NULL)
		return FALSE;

	DBG("%s", string);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &string);

	return TRUE;
}

static const GDBusMethodTable media_item_methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("Play", NULL, NULL,
					media_item_play) },
	{ GDBUS_EXPERIMENTAL_METHOD("AddtoNowPlaying", NULL, NULL,
					media_item_add_to_nowplaying) },
	{ }
};

static const GDBusPropertyTable media_item_properties[] = {
	{ "Name", "s", get_item_name, NULL, item_name_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Type", "s", get_item_type, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "FolderType", "s", get_folder_type, NULL, folder_type_exists,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Playable", "b", get_playable, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ }
};

static struct media_item *media_player_create_item(struct media_player *mp,
						const char *name,
						player_item_type_t type)
{
	struct media_item *item;
	const char *strtype;

	strtype = type_to_string(type);
	if (strtype == NULL)
		return NULL;

	DBG("%s type %s", name, strtype);

	item = g_new0(struct media_item, 1);
	item->player = mp;
	item->path = g_strdup_printf("%s%s", mp->path, name);
	item->name = g_strdup(name);
	item->type = type;
	item->folder_type = PLAYER_FOLDER_TYPE_INVALID;

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					item->path, MEDIA_ITEM_INTERFACE,
					media_item_methods,
					NULL,
					media_item_properties, item, NULL)) {
		error("D-Bus failed to register %s on %s path",
					MEDIA_ITEM_INTERFACE, item->path);
		media_item_destroy(item);
		return NULL;
	}

	return item;
}

int media_player_create_folder(struct media_player *mp, const char *name,
						player_folder_type_t type)
{
	struct media_item *item;

	item = media_player_find_folder(mp, name);
	if (item != NULL)
		return 0;

	item = media_player_create_item(mp, name,
					PLAYER_ITEM_TYPE_FOLDER);
	if (item == NULL)
		return -EINVAL;

	item->folder_type = type;

	if (mp->folder == NULL)
		media_player_set_folder_item(mp, item, 0);

	mp->folders = g_slist_prepend(mp->folders, item);

	return 0;
}

void media_player_set_callbacks(struct media_player *mp,
				const struct media_player_callback *cbs,
				void *user_data)
{
	struct player_callback *cb;

	if (mp->cb)
		g_free(mp->cb);

	cb = g_new0(struct player_callback, 1);
	cb->cbs = cbs;
	cb->user_data = user_data;

	mp->cb = cb;
}
