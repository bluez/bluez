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

struct player_callback {
	const struct media_player_callback *cbs;
	void *user_data;
};

struct pending_req {
	GDBusPendingPropertySet id;
	const char *key;
	const char *value;
};

struct media_player {
	char			*path;		/* Player object path */
	GHashTable		*settings;	/* Player settings */
	GHashTable		*track;		/* Player current track */
	char			*status;
	uint32_t		position;
	GTimer			*progress;
	guint			process_id;
	struct player_callback	*cb;
	GSList			*pending;
};

static void append_metadata(void *key, void *value, void *user_data)
{
	DBusMessageIter *dict = user_data;

	if (strcasecmp((char *) key, "Duration") == 0 ||
			strcasecmp((char *) key, "Track") == 0 ||
			strcasecmp((char *) key, "NumberOfTracks") == 0)  {
		uint32_t num = atoi(value);
		dict_append_entry(dict, key, DBUS_TYPE_UINT32, &num);
		return;
	}

	dict_append_entry(dict, key, DBUS_TYPE_STRING, &value);
}

static DBusMessage *media_player_get_track(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct media_player *mp = data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	g_hash_table_foreach(mp->track, append_metadata, &dict);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
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

static gboolean get_position(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct media_player *mp = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &mp->position);

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

static const GDBusMethodTable media_player_methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("GetTrack",
			NULL, GDBUS_ARGS({ "metadata", "a{sv}" }),
			media_player_get_track) },
	{ }
};

static const GDBusSignalTable media_player_signals[] = {
	{ GDBUS_EXPERIMENTAL_SIGNAL("TrackChanged",
			GDBUS_ARGS({ "metadata", "a{sv}" })) },
	{ }
};

static const GDBusPropertyTable media_player_properties[] = {
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
	{ }
};

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

	g_slist_free_full(mp->pending, g_free);

	g_timer_destroy(mp->progress);
	g_free(mp->cb);
	g_free(mp->status);
	g_free(mp->path);
	g_free(mp);
}

struct media_player *media_player_controller_create(const char *path)
{
	struct media_player *mp;

	mp = g_new0(struct media_player, 1);
	mp->path = g_strdup_printf("%s/player1", path);
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

void media_player_set_position(struct media_player *mp, uint32_t position)
{
	DBG("%u", position);

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
	DBusMessage *signal;
	DBusMessageIter iter, dict;

	mp->process_id = 0;

	signal = dbus_message_new_signal(mp->path, MEDIA_PLAYER_INTERFACE,
							"TrackChanged");
	if (signal == NULL) {
		error("Unable to allocate TrackChanged signal");
		return FALSE;
	}

	dbus_message_iter_init_append(signal, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);


	g_hash_table_foreach(mp->track, append_metadata, &dict);

	dbus_message_iter_close_container(&iter, &dict);

	g_dbus_send_message(btd_get_dbus_connection(), signal);

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
