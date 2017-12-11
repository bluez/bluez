/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
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

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "gdbus/gdbus.h"
#include "src/shared/shell.h"

/* String display constants */
#define COLORED_NEW	COLOR_GREEN "NEW" COLOR_OFF
#define COLORED_CHG	COLOR_YELLOW "CHG" COLOR_OFF
#define COLORED_DEL	COLOR_RED "DEL" COLOR_OFF

#define PROMPT_ON	COLOR_BLUE "[bluetooth]" COLOR_OFF "# "
#define PROMPT_OFF	"[bluetooth]# "

#define BLUEZ_MEDIA_PLAYER_INTERFACE "org.bluez.MediaPlayer1"
#define BLUEZ_MEDIA_FOLDER_INTERFACE "org.bluez.MediaFolder1"
#define BLUEZ_MEDIA_ITEM_INTERFACE "org.bluez.MediaItem1"

static DBusConnection *dbus_conn;
static GDBusProxy *default_player;
static GSList *players = NULL;
static GSList *folders = NULL;
static GSList *items = NULL;

static void connect_handler(DBusConnection *connection, void *user_data)
{
	bt_shell_set_prompt(PROMPT_ON);
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	bt_shell_set_prompt(PROMPT_OFF);
}

static bool check_default_player(void)
{
	if (!default_player) {
		bt_shell_printf("No default player available\n");
		return FALSE;
	}

	return TRUE;
}

static void play_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to play: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("Play successful\n");
}

static GDBusProxy *find_item(const char *path)
{
	GSList *l;

	for (l = items; l; l = g_slist_next(l)) {
		GDBusProxy *proxy = l->data;

		if (strcmp(path, g_dbus_proxy_get_path(proxy)) == 0)
			return proxy;
	}

	return NULL;
}

static void cmd_play_item(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = find_item(argv[1]);
	if (proxy == NULL) {
		bt_shell_printf("Item %s not available\n", argv[1]);
		return;
	}

	if (g_dbus_proxy_method_call(proxy, "Play", NULL, play_reply,
							NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to play\n");
		return;
	}

	bt_shell_printf("Attempting to play %s\n", argv[1]);
}

static void cmd_play(int argc, char *argv[])
{
	if (argc > 1)
		return cmd_play_item(argc, argv);

	if (!check_default_player())
		return;

	if (g_dbus_proxy_method_call(default_player, "Play", NULL, play_reply,
							NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to play\n");
		return;
	}

	bt_shell_printf("Attempting to play\n");
}

static void pause_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to pause: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("Pause successful\n");
}

static void cmd_pause(int argc, char *argv[])
{
	if (!check_default_player())
		return;

	if (g_dbus_proxy_method_call(default_player, "Pause", NULL,
					pause_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to play\n");
		return;
	}

	bt_shell_printf("Attempting to pause\n");
}

static void stop_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to stop: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("Stop successful\n");
}

static void cmd_stop(int argc, char *argv[])
{
	if (!check_default_player())
		return;

	if (g_dbus_proxy_method_call(default_player, "Stop", NULL, stop_reply,
							NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to stop\n");
		return;
	}

	bt_shell_printf("Attempting to stop\n");
}

static void next_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to jump to next: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("Next successful\n");
}

static void cmd_next(int argc, char *argv[])
{
	if (!check_default_player())
		return;

	if (g_dbus_proxy_method_call(default_player, "Next", NULL, next_reply,
							NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to jump to next\n");
		return;
	}

	bt_shell_printf("Attempting to jump to next\n");
}

static void previous_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to jump to previous: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("Previous successful\n");
}

static void cmd_previous(int argc, char *argv[])
{
	if (!check_default_player())
		return;

	if (g_dbus_proxy_method_call(default_player, "Previous", NULL,
					previous_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to jump to previous\n");
		return;
	}

	bt_shell_printf("Attempting to jump to previous\n");
}

static void fast_forward_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to fast forward: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("FastForward successful\n");
}

static void cmd_fast_forward(int argc, char *argv[])
{
	if (!check_default_player())
		return;

	if (g_dbus_proxy_method_call(default_player, "FastForward", NULL,
				fast_forward_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to jump to previous\n");
		return;
	}

	bt_shell_printf("Fast forward playback\n");
}

static void rewind_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to rewind: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("Rewind successful\n");
}

static void cmd_rewind(int argc, char *argv[])
{
	if (!check_default_player())
		return;

	if (g_dbus_proxy_method_call(default_player, "Rewind", NULL,
					rewind_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to rewind\n");
		return;
	}

	bt_shell_printf("Rewind playback\n");
}

static void generic_callback(const DBusError *error, void *user_data)
{
	char *str = user_data;

	if (dbus_error_is_set(error))
		bt_shell_printf("Failed to set %s: %s\n", str, error->name);
	else
		bt_shell_printf("Changing %s succeeded\n", str);
}

static void cmd_equalizer(int argc, char *argv[])
{
	char *value;
	DBusMessageIter iter;

	if (!check_default_player())
		return;

	if (!g_dbus_proxy_get_property(default_player, "Equalizer", &iter)) {
		bt_shell_printf("Operation not supported\n");
		return;
	}

	value = g_strdup(argv[1]);

	if (g_dbus_proxy_set_property_basic(default_player, "Equalizer",
						DBUS_TYPE_STRING, &value,
						generic_callback, value,
						g_free) == FALSE) {
		bt_shell_printf("Failed to setting equalizer\n");
		g_free(value);
		return;
	}

	bt_shell_printf("Attempting to set equalizer\n");
}

static void cmd_repeat(int argc, char *argv[])
{
	char *value;
	DBusMessageIter iter;

	if (!check_default_player())
		return;


	if (!g_dbus_proxy_get_property(default_player, "Repeat", &iter)) {
		bt_shell_printf("Operation not supported\n");
		return;
	}

	value = g_strdup(argv[1]);

	if (g_dbus_proxy_set_property_basic(default_player, "Repeat",
						DBUS_TYPE_STRING, &value,
						generic_callback, value,
						g_free) == FALSE) {
		bt_shell_printf("Failed to set repeat\n");
		g_free(value);
		return;
	}

	bt_shell_printf("Attempting to set repeat\n");
}

static void cmd_shuffle(int argc, char *argv[])
{
	char *value;
	DBusMessageIter iter;

	if (!check_default_player())
		return;

	if (!g_dbus_proxy_get_property(default_player, "Shuffle", &iter)) {
		bt_shell_printf("Operation not supported\n");
		return;
	}

	value = g_strdup(argv[1]);

	if (g_dbus_proxy_set_property_basic(default_player, "Shuffle",
						DBUS_TYPE_STRING, &value,
						generic_callback, value,
						g_free) == FALSE) {
		bt_shell_printf("Failed to set shuffle\n");
		g_free(value);
		return;
	}

	bt_shell_printf("Attempting to set shuffle\n");
}

static void cmd_scan(int argc, char *argv[])
{
	char *value;
	DBusMessageIter iter;

	if (!check_default_player())
		return;

	if (!g_dbus_proxy_get_property(default_player, "Shuffle", &iter)) {
		bt_shell_printf("Operation not supported\n");
		return;
	}

	value = g_strdup(argv[1]);

	if (g_dbus_proxy_set_property_basic(default_player, "Shuffle",
						DBUS_TYPE_STRING, &value,
						generic_callback, value,
						g_free) == FALSE) {
		bt_shell_printf("Failed to set scan\n");
		g_free(value);
		return;
	}

	bt_shell_printf("Attempting to set scan\n");
}

static char *proxy_description(GDBusProxy *proxy, const char *title,
						const char *description)
{
	const char *path;

	path = g_dbus_proxy_get_path(proxy);

	return g_strdup_printf("%s%s%s%s %s ",
					description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					title, path);
}

static void print_player(GDBusProxy *proxy, const char *description)
{
	char *str;

	str = proxy_description(proxy, "Player", description);

	bt_shell_printf("%s%s\n", str, default_player == proxy ? "[default]" : "");

	g_free(str);
}

static void cmd_list(int argc, char *arg[])
{
	GSList *l;

	for (l = players; l; l = g_slist_next(l)) {
		GDBusProxy *proxy = l->data;
		print_player(proxy, NULL);
	}
}

static GDBusProxy *find_player(const char *path)
{
	GSList *l;

	for (l = players; l; l = g_slist_next(l)) {
		GDBusProxy *proxy = l->data;

		if (strcmp(path, g_dbus_proxy_get_path(proxy)) == 0)
			return proxy;
	}

	return NULL;
}

static void print_iter(const char *label, const char *name,
						DBusMessageIter *iter)
{
	dbus_bool_t valbool;
	dbus_uint32_t valu32;
	dbus_uint16_t valu16;
	dbus_int16_t vals16;
	const char *valstr;
	DBusMessageIter subiter;

	if (iter == NULL) {
		bt_shell_printf("%s%s is nil\n", label, name);
		return;
	}

	switch (dbus_message_iter_get_arg_type(iter)) {
	case DBUS_TYPE_INVALID:
		bt_shell_printf("%s%s is invalid\n", label, name);
		break;
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		dbus_message_iter_get_basic(iter, &valstr);
		bt_shell_printf("%s%s: %s\n", label, name, valstr);
		break;
	case DBUS_TYPE_BOOLEAN:
		dbus_message_iter_get_basic(iter, &valbool);
		bt_shell_printf("%s%s: %s\n", label, name,
					valbool == TRUE ? "yes" : "no");
		break;
	case DBUS_TYPE_UINT32:
		dbus_message_iter_get_basic(iter, &valu32);
		bt_shell_printf("%s%s: 0x%06x\n", label, name, valu32);
		break;
	case DBUS_TYPE_UINT16:
		dbus_message_iter_get_basic(iter, &valu16);
		bt_shell_printf("%s%s: 0x%04x\n", label, name, valu16);
		break;
	case DBUS_TYPE_INT16:
		dbus_message_iter_get_basic(iter, &vals16);
		bt_shell_printf("%s%s: %d\n", label, name, vals16);
		break;
	case DBUS_TYPE_VARIANT:
		dbus_message_iter_recurse(iter, &subiter);
		print_iter(label, name, &subiter);
		break;
	case DBUS_TYPE_ARRAY:
		dbus_message_iter_recurse(iter, &subiter);
		while (dbus_message_iter_get_arg_type(&subiter) !=
							DBUS_TYPE_INVALID) {
			print_iter(label, name, &subiter);
			dbus_message_iter_next(&subiter);
		}
		break;
	case DBUS_TYPE_DICT_ENTRY:
		dbus_message_iter_recurse(iter, &subiter);
		dbus_message_iter_get_basic(&subiter, &valstr);
		dbus_message_iter_next(&subiter);
		print_iter(label, valstr, &subiter);
		break;
	default:
		bt_shell_printf("%s%s has unsupported type\n", label, name);
		break;
	}
}

static void print_property(GDBusProxy *proxy, const char *name)
{
	DBusMessageIter iter;

	if (g_dbus_proxy_get_property(proxy, name, &iter) == FALSE)
		return;

	print_iter("\t", name, &iter);
}

static GDBusProxy *find_folder(const char *path)
{
	GSList *l;

	for (l = folders; l; l = g_slist_next(l)) {
		GDBusProxy *proxy = l->data;

		if (strcmp(path, g_dbus_proxy_get_path(proxy)) == 0)
			return proxy;
	}

	return NULL;
}

static void cmd_show_item(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = find_item(argv[1]);
	if (!proxy) {
		bt_shell_printf("Item %s not available\n", argv[1]);
		return;
	}

	bt_shell_printf("Item %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "Player");
	print_property(proxy, "Name");
	print_property(proxy, "Type");
	print_property(proxy, "FolderType");
	print_property(proxy, "Playable");
	print_property(proxy, "Metadata");
}

static void cmd_show(int argc, char *argv[])
{
	GDBusProxy *proxy;
	GDBusProxy *folder;
	GDBusProxy *item;
	DBusMessageIter iter;
	const char *path;

	if (argc < 2) {
		if (check_default_player() == FALSE)
			return;

		proxy = default_player;
	} else {
		proxy = find_player(argv[1]);
		if (!proxy) {
			bt_shell_printf("Player %s not available\n", argv[1]);
			return;
		}
	}

	bt_shell_printf("Player %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "Name");
	print_property(proxy, "Repeat");
	print_property(proxy, "Equalizer");
	print_property(proxy, "Shuffle");
	print_property(proxy, "Scan");
	print_property(proxy, "Status");
	print_property(proxy, "Position");
	print_property(proxy, "Track");

	folder = find_folder(g_dbus_proxy_get_path(proxy));
	if (folder == NULL)
		return;

	bt_shell_printf("Folder %s\n", g_dbus_proxy_get_path(proxy));

	print_property(folder, "Name");
	print_property(folder, "NumberOfItems");

	if (!g_dbus_proxy_get_property(proxy, "Playlist", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &path);

	item = find_item(path);
	if (item == NULL)
		return;

	bt_shell_printf("Playlist %s\n", path);

	print_property(item, "Name");
}

static void cmd_select(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = find_player(argv[1]);
	if (proxy == NULL) {
		bt_shell_printf("Player %s not available\n", argv[1]);
		return;
	}

	if (default_player == proxy)
		return;

	default_player = proxy,
	print_player(proxy, NULL);
}

static void change_folder_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to change folder: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("ChangeFolder successful\n");
}

static void change_folder_setup(DBusMessageIter *iter, void *user_data)
{
	const char *path = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void cmd_change_folder(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (dbus_validate_path(argv[1], NULL) == FALSE) {
		bt_shell_printf("Not a valid path\n");
		return;
	}

	if (check_default_player() == FALSE)
		return;

	proxy = find_folder(g_dbus_proxy_get_path(default_player));
	if (proxy == NULL) {
		bt_shell_printf("Operation not supported\n");
		return;
	}

	if (g_dbus_proxy_method_call(proxy, "ChangeFolder", change_folder_setup,
				change_folder_reply, argv[1], NULL) == FALSE) {
		bt_shell_printf("Failed to change current folder\n");
		return;
	}

	bt_shell_printf("Attempting to change folder\n");
}

static void append_variant(DBusMessageIter *iter, int type, void *val)
{
	DBusMessageIter value;
	char sig[2] = { type, '\0' };

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void dict_append_entry(DBusMessageIter *dict,
			const char *key, int type, void *val)
{
	DBusMessageIter entry;

	if (type == DBUS_TYPE_STRING) {
		const char *str = *((const char **) val);
		if (str == NULL)
			return;
	}

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

struct list_items_args {
	int start;
	int end;
};

static void list_items_setup(DBusMessageIter *iter, void *user_data)
{
	struct list_items_args *args = user_data;
	DBusMessageIter dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	if (args->start < 0)
		goto done;

	dict_append_entry(&dict, "Start", DBUS_TYPE_UINT32, &args->start);

	if (args->end < 0)
		goto done;

	dict_append_entry(&dict, "End", DBUS_TYPE_UINT32, &args->end);

done:
	dbus_message_iter_close_container(iter, &dict);
}

static void list_items_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to list items: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("ListItems successful\n");
}

static void cmd_list_items(int argc, char *argv[])
{
	GDBusProxy *proxy;
	struct list_items_args *args;

	if (check_default_player() == FALSE)
		return;

	proxy = find_folder(g_dbus_proxy_get_path(default_player));
	if (proxy == NULL) {
		bt_shell_printf("Operation not supported\n");
		return;
	}

	args = g_new0(struct list_items_args, 1);
	args->start = -1;
	args->end = -1;

	if (argc < 2)
		goto done;

	errno = 0;
	args->start = strtol(argv[1], NULL, 10);
	if (errno != 0) {
		bt_shell_printf("%s(%d)\n", strerror(errno), errno);
		g_free(args);
		return;
	}

	if (argc < 3)
		goto done;

	errno = 0;
	args->end = strtol(argv[2], NULL, 10);
	if (errno != 0) {
		bt_shell_printf("%s(%d)\n", strerror(errno), errno);
		g_free(args);
		return;
	}

done:
	if (g_dbus_proxy_method_call(proxy, "ListItems", list_items_setup,
				list_items_reply, args, g_free) == FALSE) {
		bt_shell_printf("Failed to change current folder\n");
		g_free(args);
		return;
	}

	bt_shell_printf("Attempting to list items\n");
}

static void search_setup(DBusMessageIter *iter, void *user_data)
{
	char *string = user_data;
	DBusMessageIter dict;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &string);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_STRING_AS_STRING
					DBUS_TYPE_VARIANT_AS_STRING
					DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
					&dict);

	dbus_message_iter_close_container(iter, &dict);
}

static void search_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to search: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("Search successful\n");
}

static void cmd_search(int argc, char *argv[])
{
	GDBusProxy *proxy;
	char *string;

	if (check_default_player() == FALSE)
		return;

	proxy = find_folder(g_dbus_proxy_get_path(default_player));
	if (proxy == NULL) {
		bt_shell_printf("Operation not supported\n");
		return;
	}

	string = g_strdup(argv[1]);

	if (g_dbus_proxy_method_call(proxy, "Search", search_setup,
				search_reply, string, g_free) == FALSE) {
		bt_shell_printf("Failed to search\n");
		g_free(string);
		return;
	}

	bt_shell_printf("Attempting to search\n");
}

static void add_to_nowplaying_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to queue: %s\n", error.name);
		dbus_error_free(&error);
		return;
	}

	bt_shell_printf("AddToNowPlaying successful\n");
}

static void cmd_queue(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = find_item(argv[1]);
	if (proxy == NULL) {
		bt_shell_printf("Item %s not available\n", argv[1]);
		return;
	}

	if (g_dbus_proxy_method_call(proxy, "AddtoNowPlaying", NULL,
					add_to_nowplaying_reply, NULL,
					NULL) == FALSE) {
		bt_shell_printf("Failed to play\n");
		return;
	}

	bt_shell_printf("Attempting to queue %s\n", argv[1]);
}

static const struct bt_shell_menu main_menu = {
	.name = "main",
	.entries = {
	{ "list",         NULL,       cmd_list, "List available players" },
	{ "show",         "[player]", cmd_show, "Player information" },
	{ "select",       "<player>", cmd_select, "Select default player" },
	{ "play",         "[item]",   cmd_play, "Start playback" },
	{ "pause",        NULL,       cmd_pause, "Pause playback" },
	{ "stop",         NULL,       cmd_stop, "Stop playback" },
	{ "next",         NULL,       cmd_next, "Jump to next item" },
	{ "previous",     NULL,       cmd_previous, "Jump to previous item" },
	{ "fast-forward", NULL,       cmd_fast_forward,
						"Fast forward playback" },
	{ "rewind",       NULL,       cmd_rewind, "Rewind playback" },
	{ "equalizer",    "<on/off>", cmd_equalizer,
						"Enable/Disable equalizer"},
	{ "repeat",       "<singletrack/alltrack/group/off>", cmd_repeat,
						"Set repeat mode"},
	{ "shuffle",      "<alltracks/group/off>", cmd_shuffle,
						"Set shuffle mode"},
	{ "scan",         "<alltracks/group/off>", cmd_scan,
						"Set scan mode"},
	{ "change-folder", "<item>",  cmd_change_folder,
						"Change current folder" },
	{ "list-items", "[start] [end]",  cmd_list_items,
					"List items of current folder" },
	{ "search",     "<string>",   cmd_search,
					"Search items containing string" },
	{ "queue",       "<item>",    cmd_queue, "Add item to playlist queue" },
	{ "show-item",   "<item>",    cmd_show_item, "Show item information" },
	{} },
};

static void player_added(GDBusProxy *proxy)
{
	players = g_slist_append(players, proxy);

	if (default_player == NULL)
		default_player = proxy;

	print_player(proxy, COLORED_NEW);
}

static void print_folder(GDBusProxy *proxy, const char *description)
{
	const char *path;

	path = g_dbus_proxy_get_path(proxy);

	bt_shell_printf("%s%s%sFolder %s\n", description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					path);
}

static void folder_added(GDBusProxy *proxy)
{
	folders = g_slist_append(folders, proxy);

	print_folder(proxy, COLORED_NEW);
}

static void print_item(GDBusProxy *proxy, const char *description)
{
	const char *path, *name;
	DBusMessageIter iter;

	path = g_dbus_proxy_get_path(proxy);

	if (g_dbus_proxy_get_property(proxy, "Name", &iter))
		dbus_message_iter_get_basic(&iter, &name);
	else
		name = "<unknown>";

	bt_shell_printf("%s%s%sItem %s %s\n", description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					path, name);
}

static void item_added(GDBusProxy *proxy)
{
	items = g_slist_append(items, proxy);

	print_item(proxy, COLORED_NEW);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_MEDIA_PLAYER_INTERFACE))
		player_added(proxy);
	else if (!strcmp(interface, BLUEZ_MEDIA_FOLDER_INTERFACE))
		folder_added(proxy);
	else if (!strcmp(interface, BLUEZ_MEDIA_ITEM_INTERFACE))
		item_added(proxy);
}

static void player_removed(GDBusProxy *proxy)
{
	print_player(proxy, COLORED_DEL);

	if (default_player == proxy)
		default_player = NULL;

	players = g_slist_remove(players, proxy);
}

static void folder_removed(GDBusProxy *proxy)
{
	folders = g_slist_remove(folders, proxy);

	print_folder(proxy, COLORED_DEL);
}

static void item_removed(GDBusProxy *proxy)
{
	items = g_slist_remove(items, proxy);

	print_item(proxy, COLORED_DEL);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_MEDIA_PLAYER_INTERFACE))
		player_removed(proxy);
	if (!strcmp(interface, BLUEZ_MEDIA_FOLDER_INTERFACE))
		folder_removed(proxy);
	if (!strcmp(interface, BLUEZ_MEDIA_ITEM_INTERFACE))
		item_removed(proxy);
}

static void player_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Player", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static void folder_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Folder", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static void item_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Item", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_MEDIA_PLAYER_INTERFACE))
		player_property_changed(proxy, name, iter);
	else if (!strcmp(interface, BLUEZ_MEDIA_FOLDER_INTERFACE))
		folder_property_changed(proxy, name, iter);
	else if (!strcmp(interface, BLUEZ_MEDIA_ITEM_INTERFACE))
		item_property_changed(proxy, name, iter);
}

int main(int argc, char *argv[])
{
	GDBusClient *client;

	bt_shell_init(argc, argv, NULL);
	bt_shell_set_menu(&main_menu);
	bt_shell_set_prompt(PROMPT_OFF);
	bt_shell_attach(fileno(stdin));

	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);

	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							property_changed, NULL);

	bt_shell_run();

	g_dbus_client_unref(client);

	dbus_connection_unref(dbus_conn);

	return 0;
}
