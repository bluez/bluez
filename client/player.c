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
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <wordexp.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "lib/bluetooth.h"
#include "lib/uuid.h"

#include "profiles/audio/a2dp-codecs.h"
#include "src/shared/lc3.h"

#include "src/shared/util.h"
#include "src/shared/shell.h"
#include "src/shared/io.h"
#include "src/shared/queue.h"
#include "player.h"

/* String display constants */
#define COLORED_NEW	COLOR_GREEN "NEW" COLOR_OFF
#define COLORED_CHG	COLOR_YELLOW "CHG" COLOR_OFF
#define COLORED_DEL	COLOR_RED "DEL" COLOR_OFF

#define BLUEZ_MEDIA_INTERFACE "org.bluez.Media1"
#define BLUEZ_MEDIA_PLAYER_INTERFACE "org.bluez.MediaPlayer1"
#define BLUEZ_MEDIA_FOLDER_INTERFACE "org.bluez.MediaFolder1"
#define BLUEZ_MEDIA_ITEM_INTERFACE "org.bluez.MediaItem1"
#define BLUEZ_MEDIA_ENDPOINT_INTERFACE "org.bluez.MediaEndpoint1"
#define BLUEZ_MEDIA_TRANSPORT_INTERFACE "org.bluez.MediaTransport1"

#define BLUEZ_MEDIA_ENDPOINT_PATH "/local/endpoint"

#define NSEC_USEC(_t) (_t / 1000L)
#define SEC_USEC(_t)  (_t  * 1000000L)
#define TS_USEC(_ts)  (SEC_USEC((_ts)->tv_sec) + NSEC_USEC((_ts)->tv_nsec))

struct endpoint {
	char *path;
	char *uuid;
	uint8_t codec;
	struct iovec *caps;
	bool auto_accept;
	bool acquiring;
	uint8_t cig;
	uint8_t cis;
	char *transport;
	DBusMessage *msg;
};

static DBusConnection *dbus_conn;
static GDBusProxy *default_player;
static GList *medias = NULL;
static GList *players = NULL;
static GList *folders = NULL;
static GList *items = NULL;
static GList *endpoints = NULL;
static GList *local_endpoints = NULL;
static GList *transports = NULL;
static struct queue *ios = NULL;

struct transport {
	GDBusProxy *proxy;
	int sk;
	uint16_t mtu[2];
	char *filename;
	int fd;
	struct io *io;
	uint32_t seq;
};

static void endpoint_unregister(void *data)
{
	struct endpoint *ep = data;

	bt_shell_printf("Endpoint %s unregistered\n", ep->path);
	g_dbus_unregister_interface(dbus_conn, ep->path,
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	g_list_free_full(local_endpoints, endpoint_unregister);
	local_endpoints = NULL;
}

static bool check_default_player(void)
{
	if (!default_player) {
		bt_shell_printf("No default player available\n");
		return FALSE;
	}

	return TRUE;
}

static char *generic_generator(const char *text, int state, GList *source)
{
	static int index = 0;

	if (!source)
		return NULL;

	if (!state)
		index = 0;

	return g_dbus_proxy_path_lookup(source, &index, text);
}

static char *player_generator(const char *text, int state)
{
	return generic_generator(text, state, players);
}

static char *item_generator(const char *text, int state)
{
	return generic_generator(text, state, items);
}

static void play_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to play: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Play successful\n");

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_play(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc > 1) {
		proxy = g_dbus_proxy_lookup(items, NULL, argv[1],
						BLUEZ_MEDIA_ITEM_INTERFACE);
		if (proxy == NULL) {
			bt_shell_printf("Item %s not available\n", argv[1]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	} else {
		if (!check_default_player())
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		proxy = default_player;
	}

	if (g_dbus_proxy_method_call(proxy, "Play", NULL, play_reply,
							NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to play\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to play %s\n", argv[1] ? : "");
}

static void pause_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to pause: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Pause successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_pause(int argc, char *argv[])
{
	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (g_dbus_proxy_method_call(default_player, "Pause", NULL,
					pause_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to play\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
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
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Stop successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_stop(int argc, char *argv[])
{
	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (g_dbus_proxy_method_call(default_player, "Stop", NULL, stop_reply,
							NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to stop\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
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
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Next successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_next(int argc, char *argv[])
{
	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (g_dbus_proxy_method_call(default_player, "Next", NULL, next_reply,
							NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to jump to next\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
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
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Previous successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_previous(int argc, char *argv[])
{
	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (g_dbus_proxy_method_call(default_player, "Previous", NULL,
					previous_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to jump to previous\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to jump to previous\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void fast_forward_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to fast forward: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("FastForward successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_fast_forward(int argc, char *argv[])
{
	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (g_dbus_proxy_method_call(default_player, "FastForward", NULL,
				fast_forward_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to jump to previous\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Fast forward playback\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void rewind_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to rewind: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Rewind successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_rewind(int argc, char *argv[])
{
	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (g_dbus_proxy_method_call(default_player, "Rewind", NULL,
					rewind_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to rewind\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Rewind playback\n");
}

static void generic_callback(const DBusError *error, void *user_data)
{
	char *str = user_data;

	if (dbus_error_is_set(error)) {
		bt_shell_printf("Failed to set %s: %s\n", str, error->name);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	} else {
		bt_shell_printf("Changing %s succeeded\n", str);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}
}

static void cmd_equalizer(int argc, char *argv[])
{
	char *value;
	DBusMessageIter iter;

	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!g_dbus_proxy_get_property(default_player, "Equalizer", &iter)) {
		bt_shell_printf("Operation not supported\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	value = g_strdup(argv[1]);

	if (g_dbus_proxy_set_property_basic(default_player, "Equalizer",
						DBUS_TYPE_STRING, &value,
						generic_callback, value,
						g_free) == FALSE) {
		bt_shell_printf("Failed to setting equalizer\n");
		g_free(value);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to set equalizer\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_repeat(int argc, char *argv[])
{
	char *value;
	DBusMessageIter iter;

	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!g_dbus_proxy_get_property(default_player, "Repeat", &iter)) {
		bt_shell_printf("Operation not supported\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	value = g_strdup(argv[1]);

	if (g_dbus_proxy_set_property_basic(default_player, "Repeat",
						DBUS_TYPE_STRING, &value,
						generic_callback, value,
						g_free) == FALSE) {
		bt_shell_printf("Failed to set repeat\n");
		g_free(value);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to set repeat\n");
}

static void cmd_shuffle(int argc, char *argv[])
{
	char *value;
	DBusMessageIter iter;

	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!g_dbus_proxy_get_property(default_player, "Shuffle", &iter)) {
		bt_shell_printf("Operation not supported\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	value = g_strdup(argv[1]);

	if (g_dbus_proxy_set_property_basic(default_player, "Shuffle",
						DBUS_TYPE_STRING, &value,
						generic_callback, value,
						g_free) == FALSE) {
		bt_shell_printf("Failed to set shuffle\n");
		g_free(value);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to set shuffle\n");
}

static void cmd_scan(int argc, char *argv[])
{
	char *value;
	DBusMessageIter iter;

	if (!check_default_player())
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (!g_dbus_proxy_get_property(default_player, "Shuffle", &iter)) {
		bt_shell_printf("Operation not supported\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	value = g_strdup(argv[1]);

	if (g_dbus_proxy_set_property_basic(default_player, "Shuffle",
						DBUS_TYPE_STRING, &value,
						generic_callback, value,
						g_free) == FALSE) {
		bt_shell_printf("Failed to set scan\n");
		g_free(value);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
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

static void print_iter(const char *label, const char *name,
						DBusMessageIter *iter)
{
	dbus_bool_t valbool;
	dbus_uint32_t valu32;
	dbus_uint16_t valu16;
	dbus_int16_t vals16;
	unsigned char byte;
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
		bt_shell_printf("%s%s: 0x%08x (%u)\n", label, name, valu32,
								valu32);
		break;
	case DBUS_TYPE_UINT16:
		dbus_message_iter_get_basic(iter, &valu16);
		bt_shell_printf("%s%s: 0x%04x (%u)\n", label, name, valu16,
								valu16);
		break;
	case DBUS_TYPE_INT16:
		dbus_message_iter_get_basic(iter, &vals16);
		bt_shell_printf("%s%s: %d\n", label, name, vals16);
		break;
	case DBUS_TYPE_BYTE:
		dbus_message_iter_get_basic(iter, &byte);
		bt_shell_printf("%s%s: 0x%02x (%d)\n", label, name, byte, byte);
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

static void print_media(GDBusProxy *proxy, const char *description)
{
	char *str;

	str = proxy_description(proxy, "Media", description);

	bt_shell_printf("%s\n", str);
	print_property(proxy, "SupportedUUIDs");

	g_free(str);
}

static void print_player(void *data, void *user_data)
{
	GDBusProxy *proxy = data;
	const char *description = user_data;
	char *str;

	str = proxy_description(proxy, "Player", description);

	bt_shell_printf("%s%s\n", str,
			default_player == proxy ? "[default]" : "");

	g_free(str);
}

static void cmd_list(int argc, char *arg[])
{
	g_list_foreach(players, print_player, NULL);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_show_item(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_lookup(items, NULL, argv[1],
						BLUEZ_MEDIA_ITEM_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Item %s not available\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	bt_shell_printf("Item %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "Player");
	print_property(proxy, "Name");
	print_property(proxy, "Type");
	print_property(proxy, "FolderType");
	print_property(proxy, "Playable");
	print_property(proxy, "Metadata");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
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
			return bt_shell_noninteractive_quit(EXIT_FAILURE);

		proxy = default_player;
	} else {
		proxy = g_dbus_proxy_lookup(players, NULL, argv[1],
						BLUEZ_MEDIA_PLAYER_INTERFACE);
		if (!proxy) {
			bt_shell_printf("Player %s not available\n", argv[1]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
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

	folder = g_dbus_proxy_lookup(folders, NULL,
					g_dbus_proxy_get_path(proxy),
					BLUEZ_MEDIA_FOLDER_INTERFACE);
	if (folder == NULL)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	bt_shell_printf("Folder %s\n", g_dbus_proxy_get_path(proxy));

	print_property(folder, "Name");
	print_property(folder, "NumberOfItems");

	if (!g_dbus_proxy_get_property(proxy, "Playlist", &iter))
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	dbus_message_iter_get_basic(&iter, &path);

	item = g_dbus_proxy_lookup(items, NULL, path,
					BLUEZ_MEDIA_ITEM_INTERFACE);
	if (item == NULL)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	bt_shell_printf("Playlist %s\n", path);

	print_property(item, "Name");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_select(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_lookup(players, NULL, argv[1],
						BLUEZ_MEDIA_PLAYER_INTERFACE);
	if (proxy == NULL) {
		bt_shell_printf("Player %s not available\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (default_player == proxy)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	default_player = proxy;
	print_player(proxy, NULL);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void change_folder_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to change folder: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("ChangeFolder successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
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
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (check_default_player() == FALSE)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	proxy = g_dbus_proxy_lookup(folders, NULL,
					g_dbus_proxy_get_path(default_player),
					BLUEZ_MEDIA_FOLDER_INTERFACE);
	if (proxy == NULL) {
		bt_shell_printf("Operation not supported\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (g_dbus_proxy_method_call(proxy, "ChangeFolder", change_folder_setup,
				change_folder_reply, argv[1], NULL) == FALSE) {
		bt_shell_printf("Failed to change current folder\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to change folder\n");
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

	g_dbus_dict_append_entry(&dict, "Start",
					DBUS_TYPE_UINT32, &args->start);

	if (args->end < 0)
		goto done;

	g_dbus_dict_append_entry(&dict, "End", DBUS_TYPE_UINT32, &args->end);

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
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("ListItems successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_list_items(int argc, char *argv[])
{
	GDBusProxy *proxy;
	struct list_items_args *args;

	if (check_default_player() == FALSE)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	proxy = g_dbus_proxy_lookup(folders, NULL,
					g_dbus_proxy_get_path(default_player),
					BLUEZ_MEDIA_FOLDER_INTERFACE);
	if (proxy == NULL) {
		bt_shell_printf("Operation not supported\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
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
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (argc < 3)
		goto done;

	errno = 0;
	args->end = strtol(argv[2], NULL, 10);
	if (errno != 0) {
		bt_shell_printf("%s(%d)\n", strerror(errno), errno);
		g_free(args);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

done:
	if (g_dbus_proxy_method_call(proxy, "ListItems", list_items_setup,
				list_items_reply, args, g_free) == FALSE) {
		bt_shell_printf("Failed to change current folder\n");
		g_free(args);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
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
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Search successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_search(int argc, char *argv[])
{
	GDBusProxy *proxy;
	char *string;

	if (check_default_player() == FALSE)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	proxy = g_dbus_proxy_lookup(folders, NULL,
					g_dbus_proxy_get_path(default_player),
					BLUEZ_MEDIA_FOLDER_INTERFACE);
	if (proxy == NULL) {
		bt_shell_printf("Operation not supported\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	string = g_strdup(argv[1]);

	if (g_dbus_proxy_method_call(proxy, "Search", search_setup,
				search_reply, string, g_free) == FALSE) {
		bt_shell_printf("Failed to search\n");
		g_free(string);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
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
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("AddToNowPlaying successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_queue(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_lookup(items, NULL, argv[1],
						BLUEZ_MEDIA_ITEM_INTERFACE);
	if (proxy == NULL) {
		bt_shell_printf("Item %s not available\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (g_dbus_proxy_method_call(proxy, "AddtoNowPlaying", NULL,
					add_to_nowplaying_reply, NULL,
					NULL) == FALSE) {
		bt_shell_printf("Failed to play\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to queue %s\n", argv[1]);
}

static const struct bt_shell_menu player_menu = {
	.name = "player",
	.desc = "Media Player Submenu",
	.entries = {
	{ "list",         NULL,       cmd_list, "List available players" },
	{ "show",         "[player]", cmd_show, "Player information",
							player_generator},
	{ "select",       "<player>", cmd_select, "Select default player",
							player_generator},
	{ "play",         "[item]",   cmd_play, "Start playback",
							item_generator},
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
						"Change current folder",
							item_generator},
	{ "list-items", "[start] [end]",  cmd_list_items,
					"List items of current folder" },
	{ "search",     "<string>",   cmd_search,
					"Search items containing string" },
	{ "queue",       "<item>",    cmd_queue, "Add item to playlist queue",
							item_generator},
	{ "show-item",   "<item>",    cmd_show_item, "Show item information",
							item_generator},
	{} },
};

static char *endpoint_generator(const char *text, int state)
{
	return generic_generator(text, state, endpoints);
}

static char *local_endpoint_generator(const char *text, int state)
{
	int len = strlen(text);
	GList *l;
	static int index = 0;

	if (!state)
		index = 0;

	for (l = g_list_nth(local_endpoints, index); l; l = g_list_next(l)) {
		struct endpoint *ep = l->data;

		index++;

		if (!strncasecmp(ep->path, text, len))
			return strdup(ep->path);
	}

	return NULL;
}

static void print_endpoint(void *data, void *user_data)
{
	GDBusProxy *proxy = data;
	const char *description = user_data;
	char *str;

	str = proxy_description(proxy, "Endpoint", description);

	bt_shell_printf("%s\n", str);

	g_free(str);
}

static void cmd_list_endpoints(int argc, char *argv[])
{
	GList *l;

	if (argc > 1) {
		if (strcmp("local", argv[1])) {
			bt_shell_printf("Endpoint list %s not available\n",
					argv[1]);
			return bt_shell_noninteractive_quit(EXIT_SUCCESS);
		}

		for (l = local_endpoints; l; l = g_list_next(l)) {
			struct endpoint *ep = l->data;

			bt_shell_printf("%s\n", ep->path);
		}

		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	for (l = endpoints; l; l = g_list_next(l)) {
		GDBusProxy *proxy = l->data;
		print_endpoint(proxy, NULL);
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void confirm_response(const char *input, void *user_data)
{
	DBusMessage *msg = user_data;

	if (!strcasecmp(input, "y") || !strcasecmp(input, "yes"))
		g_dbus_send_reply(dbus_conn, msg, DBUS_TYPE_INVALID);
	else if (!strcasecmp(input, "n") || !strcmp(input, "no"))
		g_dbus_send_error(dbus_conn, msg, "org.bluez.Error.Rejected",
									NULL);
	else
		g_dbus_send_error(dbus_conn, msg, "org.bluez.Error.Canceled",
									NULL);
}

static DBusMessage *endpoint_set_configuration(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct endpoint *ep = user_data;
	DBusMessageIter args, props;
	const char *path;

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);
	dbus_message_iter_next(&args);

	dbus_message_iter_recurse(&args, &props);
	if (dbus_message_iter_get_arg_type(&props) != DBUS_TYPE_DICT_ENTRY)
		return g_dbus_create_error(msg,
					 "org.bluez.Error.InvalidArguments",
					 NULL);

	bt_shell_printf("Endpoint: SetConfiguration\n");
	bt_shell_printf("\tTransport %s\n", path);
	print_iter("\t", "Properties", &props);

	free(ep->transport);
	ep->transport = strdup(path);

	if (ep->auto_accept) {
		bt_shell_printf("Auto Accepting...\n");
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	bt_shell_prompt_input("Endpoint", "Accept (yes/no):", confirm_response,
							dbus_message_ref(msg));

	return NULL;
}

struct codec_capabilities {
	uint8_t len;
	uint8_t type;
	uint8_t data[UINT8_MAX];
};

#define data(args...) ((const unsigned char[]) { args })

#define CODEC_DATA(args...) \
	{ \
		.iov_base = (void *)data(args), \
		.iov_len = sizeof(data(args)), \
	}

#define CODEC_CAPABILITIES(_uuid, _codec_id, _data) \
	{ \
		.uuid = _uuid, \
		.codec_id = _codec_id, \
		.data = _data, \
	}

#define LC3_DATA(_freq, _duration, _chan_count, _len_min, _len_max) \
	CODEC_DATA(0x03, LC3_FREQ, _freq, _freq >> 8, \
		   0x02, LC3_DURATION, _duration, \
		   0x02, LC3_CHAN_COUNT, _chan_count, \
		   0x05, LC3_FRAME_LEN, _len_min, _len_min >> 8, _len_max, \
		   _len_max >> 8)

static const struct capabilities {
	const char *uuid;
	uint8_t codec_id;
	struct iovec data;
} caps[] = {
	/* A2DP SBC Source:
	 *
	 * Channel Modes: Mono DualChannel Stereo JointStereo
	 * Frequencies: 16Khz 32Khz 44.1Khz 48Khz
	 * Subbands: 4 8
	 * Blocks: 4 8 12 16
	 * Bitpool Range: 2-64
	 */
	CODEC_CAPABILITIES(A2DP_SOURCE_UUID, A2DP_CODEC_SBC,
					CODEC_DATA(0xff, 0xff, 2, 64)),
	/* A2DP SBC Sink:
	 *
	 * Channel Modes: Mono DualChannel Stereo JointStereo
	 * Frequencies: 16Khz 32Khz 44.1Khz 48Khz
	 * Subbands: 4 8
	 * Blocks: 4 8 12 16
	 * Bitpool Range: 2-64
	 */
	CODEC_CAPABILITIES(A2DP_SINK_UUID, A2DP_CODEC_SBC,
					CODEC_DATA(0xff, 0xff, 2, 64)),
	/* PAC LC3 Sink:
	 *
	 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
	 * Duration: 7.5 ms 10 ms
	 * Channel count: 3
	 * Frame length: 30-240
	 */
	CODEC_CAPABILITIES(PAC_SINK_UUID, LC3_ID,
					LC3_DATA(LC3_FREQ_ANY, LC3_DURATION_ANY,
						3u, 30, 240)),
	/* PAC LC3 Source:
	 *
	 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
	 * Duration: 7.5 ms 10 ms
	 * Channel count: 3
	 * Frame length: 30-240
	 */
	CODEC_CAPABILITIES(PAC_SOURCE_UUID, LC3_ID,
					LC3_DATA(LC3_FREQ_ANY, LC3_DURATION_ANY,
						3u, 30, 240)),
};

struct codec_qos {
	uint32_t interval;
	uint8_t  framing;
	char *phy;
	uint16_t sdu;
	uint8_t  rtn;
	uint16_t latency;
	uint32_t delay;
};

struct codec_preset {
	const char *name;
	const struct iovec data;
	const struct codec_qos qos;
	bool is_default;
	uint8_t latency;
};

#define SBC_PRESET(_name, _data) \
	{ \
		.name = _name, \
		.data = _data, \
	}

#define SBC_DEFAULT_PRESET(_name, _data) \
	{ \
		.name = _name, \
		.data = _data, \
		.is_default = true, \
	}

static struct codec_preset sbc_presets[] = {
	/* Table 4.7: Recommended sets of SBC parameters in the SRC device
	 * Other settings: Block length = 16, Allocation method = Loudness,
	 * Subbands = 8.
	 * A2DP spec sets maximum bitrates as follows:
	 * This profile limits the available maximum bit rate to 320kb/s for
	 * mono, and 512kb/s for two-channel modes.
	 */
	SBC_PRESET("MQ_MONO_44_1",
		CODEC_DATA(0x28, 0x15, 2, SBC_BITPOOL_MQ_MONO_44100)),
	SBC_PRESET("MQ_MONO_48",
		CODEC_DATA(0x18, 0x15, 2, SBC_BITPOOL_MQ_MONO_48000)),
	SBC_PRESET("MQ_STEREO_44_1",
		CODEC_DATA(0x21, 0x15, 2, SBC_BITPOOL_MQ_JOINT_STEREO_44100)),
	SBC_PRESET("MQ_STEREO_48",
		CODEC_DATA(0x11, 0x15, 2, SBC_BITPOOL_MQ_JOINT_STEREO_48000)),
	SBC_PRESET("HQ_MONO_44_1",
		CODEC_DATA(0x28, 0x15, 2, SBC_BITPOOL_HQ_MONO_44100)),
	SBC_PRESET("HQ_MONO_48",
		CODEC_DATA(0x18, 0x15, 2, SBC_BITPOOL_HQ_MONO_48000)),
	SBC_DEFAULT_PRESET("HQ_STEREO_44_1",
		CODEC_DATA(0x21, 0x15, 2, SBC_BITPOOL_HQ_JOINT_STEREO_44100)),
	SBC_PRESET("HQ_STEREO_48",
		CODEC_DATA(0x11, 0x15, 2, SBC_BITPOOL_HQ_JOINT_STEREO_48000)),
	/* Higher bitrates not recommended by A2DP spec, it dual channel to
	 * avoid going above 53 bitpool:
	 *
	 * https://habr.com/en/post/456476/
	 * https://gitlab.freedesktop.org/pulseaudio/pulseaudio/-/issues/1092
	 */
	SBC_PRESET("XQ_DUAL_44_1", CODEC_DATA(0x24, 0x15, 2, 43)),
	SBC_PRESET("XQ_DUAL_48", CODEC_DATA(0x14, 0x15, 2, 39)),
	/* Ultra high bitpool that fits in 512 kbps mandatory bitrate */
	SBC_PRESET("UQ_STEREO_44_1", CODEC_DATA(0x21, 0x15, 2, 64)),
	SBC_PRESET("UQ_STEREO_48", CODEC_DATA(0x11, 0x15, 2, 58)),
};

#define QOS_CONFIG(_interval, _framing, _phy, _sdu, _rtn, _latency, _delay) \
	{ \
		.interval = _interval, \
		.framing = _framing, \
		.phy = _phy, \
		.sdu = _sdu, \
		.rtn = _rtn, \
		.latency = _latency, \
		.delay = _delay, \
	}

#define QOS_UNFRAMED(_interval, _phy, _sdu, _rtn, _latency, _delay) \
	QOS_CONFIG(_interval, 0x00, _phy, _sdu, _rtn, _latency, _delay)

#define QOS_FRAMED(_interval, _phy, _sdu, _rtn, _latency, _delay) \
	QOS_CONFIG(_interval, 0x01, _phy, _sdu, _rtn, _latency, _delay)

#define QOS_UNFRAMED_1M(_interval, _sdu, _rtn, _latency, _delay) \
	QOS_UNFRAMED(_interval, "1M", _sdu, _rtn, _latency, _delay) \

#define QOS_FRAMED_1M(_interval, _sdu, _rtn, _latency, _delay) \
	QOS_FRAMED(_interval, "1M", _sdu, _rtn, _latency, _delay) \

#define QOS_UNFRAMED_2M(_interval, _sdu, _rtn, _latency, _delay) \
	QOS_UNFRAMED(_interval, "2M", _sdu, _rtn, _latency, _delay) \

#define QOS_FRAMED_2M(_interval, _sdu, _rtn, _latency, _delay) \
	QOS_FRAMED(_interval, "2M", _sdu, _rtn, _latency, _delay) \

#define LC3_7_5_UNFRAMED(_sdu, _rtn, _latency, _delay) \
	QOS_UNFRAMED(7500u, "2M", _sdu, _rtn, _latency, _delay)

#define LC3_7_5_FRAMED(_sdu, _rtn, _latency, _delay) \
	QOS_FRAMED(7500u, "2M", _sdu, _rtn, _latency, _delay)

#define LC3_10_UNFRAMED(_sdu, _rtn, _latency, _delay) \
	QOS_UNFRAMED_2M(10000u, _sdu, _rtn, _latency, _delay)

#define LC3_10_FRAMED(_sdu, _rtn, _latency, _delay) \
	QOS_FRAMED_2M(10000u, _sdu, _rtn, _latency, _delay)

#define LC3_PRESET_DATA(_freq, _duration, _len) \
	CODEC_DATA(0x02, LC3_CONFIG_FREQ, _freq, \
		   0x02, LC3_CONFIG_DURATION, _duration, \
		   0x03, LC3_CONFIG_FRAME_LEN, _len, _len >> 8)

#define LC3_PRESET_8KHZ(_duration, _len) \
	LC3_PRESET_DATA(LC3_CONFIG_FREQ_8KHZ, _duration, _len)

#define LC3_PRESET_11KHZ(_duration, _len) \
	LC3_PRESET_DATA(LC3_CONFIG_FREQ_11KHZ, _duration, _len)

#define LC3_PRESET_16KHZ(_duration, _len) \
	LC3_PRESET_DATA(LC3_CONFIG_FREQ_16KHZ, _duration, _len)

#define LC3_PRESET_22KHZ(_duration, _len) \
	LC3_PRESET_DATA(LC3_CONFIG_FREQ_22KHZ, _duration, _len)

#define LC3_PRESET_24KHZ(_duration, _len) \
	LC3_PRESET_DATA(LC3_CONFIG_FREQ_24KHZ, _duration, _len)

#define LC3_PRESET_32KHZ(_duration, _len) \
	LC3_PRESET_DATA(LC3_CONFIG_FREQ_32KHZ, _duration, _len)

#define LC3_PRESET_44KHZ(_duration, _len) \
	LC3_PRESET_DATA(LC3_CONFIG_FREQ_44KHZ, _duration, _len)

#define LC3_PRESET_48KHZ(_duration, _len) \
	LC3_PRESET_DATA(LC3_CONFIG_FREQ_48KHZ, _duration, _len)

#define LC3_PRESET_LL(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.latency = 0x01, \
	}

#define LC3_PRESET(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.latency = 0x02, \
	}

#define LC3_PRESET_HR(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.latency = 0x03, \
	}

#define LC3_DEFAULT_PRESET(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.is_default = true, \
		.qos = _qos, \
		.latency = 0x02, \
	}

static struct codec_preset lc3_presets[] = {
	/* Table 4.43: QoS configuration support setting requirements */
	LC3_PRESET("8_1_1",
			LC3_PRESET_8KHZ(LC3_CONFIG_DURATION_7_5, 26u),
			LC3_7_5_UNFRAMED(26u, 2u, 8u, 40000u)),
	LC3_PRESET("8_2_1",
			LC3_PRESET_8KHZ(LC3_CONFIG_DURATION_10, 30u),
			LC3_10_UNFRAMED(30u, 2u, 10u, 40000u)),
	LC3_PRESET("16_1_1",
			LC3_PRESET_16KHZ(LC3_CONFIG_DURATION_7_5, 30u),
			LC3_7_5_UNFRAMED(30u, 2u, 8u, 40000u)),
	LC3_DEFAULT_PRESET("16_2_1",
			LC3_PRESET_16KHZ(LC3_CONFIG_DURATION_10, 40u),
			LC3_10_UNFRAMED(40u, 2u, 10u, 40000u)),
	LC3_PRESET("24_1_1",
			LC3_PRESET_24KHZ(LC3_CONFIG_DURATION_7_5, 45u),
			LC3_7_5_UNFRAMED(45u, 2u, 8u, 40000u)),
	LC3_PRESET("24_2_1",
			LC3_PRESET_24KHZ(LC3_CONFIG_DURATION_10, 60u),
			LC3_10_UNFRAMED(60u, 2u, 10u, 40000u)),
	LC3_PRESET("32_1_1",
			LC3_PRESET_32KHZ(LC3_CONFIG_DURATION_7_5, 60u),
			LC3_7_5_UNFRAMED(60u, 2u, 8u, 40000u)),
	LC3_PRESET("32_2_1",
			LC3_PRESET_32KHZ(LC3_CONFIG_DURATION_10, 80u),
			LC3_10_UNFRAMED(80u, 2u, 10u, 40000u)),
	LC3_PRESET("44_1_1",
			LC3_PRESET_44KHZ(LC3_CONFIG_DURATION_7_5, 98u),
			QOS_FRAMED_2M(8163u, 98u, 5u, 24u, 40000u)),
	LC3_PRESET("44_2_1",
			LC3_PRESET_44KHZ(LC3_CONFIG_DURATION_10, 130u),
			QOS_FRAMED_2M(10884u, 130u, 5u, 31u, 40000u)),
	LC3_PRESET("48_1_1",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_7_5, 75u),
			LC3_7_5_UNFRAMED(75u, 5u, 15u, 40000u)),
	LC3_PRESET("48_2_1",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_10, 100u),
			LC3_10_UNFRAMED(100u, 5u, 20u, 40000u)),
	LC3_PRESET("48_3_1",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_7_5, 90u),
			LC3_7_5_UNFRAMED(90u, 5u, 15u, 40000u)),
	LC3_PRESET("48_4_1",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_10, 120u),
			LC3_10_UNFRAMED(120u, 5u, 20u, 40000u)),
	LC3_PRESET("48_5_1",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_7_5, 117u),
			LC3_7_5_UNFRAMED(117u, 5u, 15u, 40000u)),
	LC3_PRESET("48_6_1",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_10, 155u),
			LC3_10_UNFRAMED(155u, 5u, 20u, 40000u)),
	/* QoS Configuration settings for high reliability audio data */
	LC3_PRESET_HR("44_1_2",
			LC3_PRESET_44KHZ(LC3_CONFIG_DURATION_7_5, 98u),
			QOS_FRAMED_2M(8163u, 98u, 23u, 54u, 40000u)),
	LC3_PRESET_HR("44_2_2",
			LC3_PRESET_44KHZ(LC3_CONFIG_DURATION_10, 130u),
			QOS_FRAMED_2M(10884u, 130u, 23u, 71u, 40000u)),
	LC3_PRESET_HR("48_1_2",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_7_5, 75u),
			LC3_7_5_UNFRAMED(75u, 23u, 45u, 40000u)),
	LC3_PRESET_HR("48_2_2",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_10, 100u),
			LC3_10_UNFRAMED(100u, 23u, 60u, 40000u)),
	LC3_PRESET_HR("48_3_2",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_7_5, 90u),
			LC3_7_5_UNFRAMED(90u, 23u, 45u, 40000u)),
	LC3_PRESET_HR("48_4_2",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_10, 120u),
			LC3_10_UNFRAMED(120u, 23u, 60u, 40000u)),
	LC3_PRESET_HR("48_5_2",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_7_5, 117u),
			LC3_7_5_UNFRAMED(117u, 23u, 45u, 40000u)),
	LC3_PRESET_HR("48_6_2",
			LC3_PRESET_48KHZ(LC3_CONFIG_DURATION_10, 155u),
			LC3_10_UNFRAMED(155u, 23u, 60u, 40000u)),
};

#define PRESET(_uuid, _presets) \
	{ \
		.uuid = _uuid, \
		.presets = _presets, \
		.num_presets = ARRAY_SIZE(_presets), \
	}

static const struct preset {
	const char *uuid;
	struct codec_preset *presets;
	size_t num_presets;
} presets[] = {
	PRESET(A2DP_SOURCE_UUID, sbc_presets),
	PRESET(A2DP_SINK_UUID, sbc_presets),
	PRESET(PAC_SINK_UUID, lc3_presets),
	PRESET(PAC_SOURCE_UUID, lc3_presets),
};

static struct codec_preset *find_preset(const char *uuid, const char *name)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(presets); i++) {
		const struct preset *preset = &presets[i];

		if (!strcasecmp(preset->uuid, uuid)) {
			size_t j;

			for (j = 0; j < preset->num_presets; j++) {
				struct codec_preset *p;

				p = &preset->presets[j];

				if (!name) {
					if (p->is_default)
						return p;
				} else if (!strcmp(p->name, name))
					return p;
			}
		}
	}

	return NULL;
}

static DBusMessage *endpoint_select_config_reply(DBusMessage *msg,
						 uint8_t *data, size_t len)
{
	DBusMessage *reply;
	DBusMessageIter args, array;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &args);

	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY,
						DBUS_TYPE_BYTE_AS_STRING,
						&array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE, &data,
								len);

	dbus_message_iter_close_container(&args, &array);

	return reply;
}

static uint8_t *str2bytearray(char *arg, size_t *val_len)
{
	uint8_t value[UINT8_MAX];
	char *entry;
	unsigned int i;

	for (i = 0; (entry = strsep(&arg, " \t")) != NULL; i++) {
		long val;
		char *endptr = NULL;

		if (*entry == '\0')
			continue;

		if (i >= G_N_ELEMENTS(value)) {
			bt_shell_printf("Too much data\n");
			return NULL;
		}

		val = strtol(entry, &endptr, 0);
		if (!endptr || *endptr != '\0' || val > UINT8_MAX) {
			bt_shell_printf("Invalid value at index %d\n", i);
			return NULL;
		}

		value[i] = val;
	}

	*val_len = i;

	return util_memdup(value, i);
}

static void select_config_response(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	struct codec_preset *p;
	DBusMessage *reply;
	uint8_t *data;
	size_t len;

	p = find_preset(ep->uuid, input);
	if (p) {
		data = p->data.iov_base;
		len = p->data.iov_len;
		goto done;
	}

	data = str2bytearray((void *) input, &len);
	if (!data) {
		g_dbus_send_error(dbus_conn, ep->msg,
				  "org.bluez.Error.Rejected", NULL);
		ep->msg = NULL;
		return;
	}

done:
	reply = endpoint_select_config_reply(ep->msg, data, len);
	if (!reply)
		return;

	if (!p)
		free(data);

	g_dbus_send_message(dbus_conn, reply);
	dbus_message_unref(ep->msg);
	ep->msg = NULL;
}

static DBusMessage *endpoint_select_configuration(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct endpoint *ep = user_data;
	struct codec_preset *p;
	DBusMessageIter args;
	DBusMessage *reply;

	dbus_message_iter_init(msg, &args);

	bt_shell_printf("Endpoint: SelectConfiguration\n");
	print_iter("\t", "Capabilities", &args);

	if (!ep->auto_accept) {
		ep->msg = dbus_message_ref(msg);
		bt_shell_prompt_input("Endpoint", "Enter preset/configuration:",
					select_config_response, ep);
		return NULL;
	}

	p = find_preset(ep->uuid, NULL);
	if (!p) {
		reply = g_dbus_create_error(msg, "org.bluez.Error.Rejected",
								NULL);
		return reply;
	}

	reply = endpoint_select_config_reply(msg, p->data.iov_base,
						p->data.iov_len);
	if (!reply)
		return NULL;

	bt_shell_printf("Auto Accepting using %s...\n", p->name);

	return reply;
}

struct endpoint_config {
	GDBusProxy *proxy;
	struct endpoint *ep;
	struct iovec *caps;
	uint8_t target_latency;
	const struct codec_qos *qos;
};

static void append_properties(DBusMessageIter *iter,
						struct endpoint_config *cfg)
{
	DBusMessageIter dict;
	struct codec_qos *qos = (void *)cfg->qos;
	const char *key = "Capabilities";

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	bt_shell_printf("Capabilities: ");
	bt_shell_hexdump(cfg->caps->iov_base, cfg->caps->iov_len);

	g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &key,
					DBUS_TYPE_BYTE, &cfg->caps->iov_base,
					cfg->caps->iov_len);

	if (!qos)
		goto done;

	if (cfg->target_latency) {
		bt_shell_printf("TargetLatency 0x%02x\n", qos->interval);
		g_dbus_dict_append_entry(&dict, "TargetLatency",
					DBUS_TYPE_BYTE, &cfg->target_latency);
	}

	if (cfg->ep->cig != BT_ISO_QOS_CIG_UNSET) {
		bt_shell_printf("CIG 0x%2.2x\n", cfg->ep->cig);
		g_dbus_dict_append_entry(&dict, "CIG", DBUS_TYPE_BYTE,
							&cfg->ep->cig);
	}

	if (cfg->ep->cis != BT_ISO_QOS_CIS_UNSET) {
		bt_shell_printf("CIS 0x%2.2x\n", cfg->ep->cis);
		g_dbus_dict_append_entry(&dict, "CIS", DBUS_TYPE_BYTE,
							&cfg->ep->cis);
	}

	bt_shell_printf("Interval %u\n", qos->interval);

	g_dbus_dict_append_entry(&dict, "Interval", DBUS_TYPE_UINT32,
						&qos->interval);

	bt_shell_printf("Framing %s\n", qos->framing ? "true" : "false");

	g_dbus_dict_append_entry(&dict, "Framing", DBUS_TYPE_BOOLEAN,
						&qos->framing);

	bt_shell_printf("PHY %s\n", qos->phy);

	g_dbus_dict_append_entry(&dict, "PHY", DBUS_TYPE_STRING, &qos->phy);

	bt_shell_printf("SDU %u\n", cfg->qos->sdu);

	g_dbus_dict_append_entry(&dict, "SDU", DBUS_TYPE_UINT16, &qos->sdu);

	bt_shell_printf("Retransmissions %u\n", qos->rtn);

	g_dbus_dict_append_entry(&dict, "Retransmissions", DBUS_TYPE_BYTE,
						&qos->rtn);

	bt_shell_printf("Latency %u\n", qos->latency);

	g_dbus_dict_append_entry(&dict, "Latency", DBUS_TYPE_UINT16,
						&qos->latency);

	bt_shell_printf("Delay %u\n", qos->delay);

	g_dbus_dict_append_entry(&dict, "Delay", DBUS_TYPE_UINT32,
						&qos->delay);

done:
	dbus_message_iter_close_container(iter, &dict);
}

static struct iovec *iov_append(struct iovec **iov, const void *data,
							size_t len)
{
	if (!*iov) {
		*iov = new0(struct iovec, 1);
		(*iov)->iov_base = new0(uint8_t, UINT8_MAX);
	}

	if (data && len) {
		memcpy((*iov)->iov_base + (*iov)->iov_len, data, len);
		(*iov)->iov_len += len;
	}

	return *iov;
}

static DBusMessage *endpoint_select_properties_reply(struct endpoint *ep,
						DBusMessage *msg,
						struct codec_preset *preset)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	struct endpoint_config *cfg;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	cfg = new0(struct endpoint_config, 1);
	cfg->ep = ep;

	/* Copy capabilities */
	iov_append(&cfg->caps, preset->data.iov_base, preset->data.iov_len);
	cfg->target_latency = preset->latency;

	if (preset->qos.phy)
		/* Set QoS parameters */
		cfg->qos = &preset->qos;

	dbus_message_iter_init_append(reply, &iter);

	append_properties(&iter, cfg);

	free(cfg);

	return reply;
}

static void select_properties_response(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	struct codec_preset *p;
	DBusMessage *reply;

	p = find_preset(ep->uuid, input);
	if (p) {
		reply = endpoint_select_properties_reply(ep, ep->msg, p);
		goto done;
	}

	bt_shell_printf("Preset %s not found\n", input);
	reply = g_dbus_create_error(ep->msg, "org.bluez.Error.Rejected", NULL);

done:
	g_dbus_send_message(dbus_conn, reply);
	dbus_message_unref(ep->msg);
	ep->msg = NULL;
}

static DBusMessage *endpoint_select_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct endpoint *ep = user_data;
	struct codec_preset *p;
	DBusMessageIter args;
	DBusMessage *reply;

	dbus_message_iter_init(msg, &args);

	bt_shell_printf("Endpoint: SelectProperties\n");
	print_iter("\t", "Properties", &args);

	if (!ep->auto_accept) {
		ep->msg = dbus_message_ref(msg);
		bt_shell_prompt_input("Endpoint", "Enter preset/configuration:",
					select_properties_response, ep);
		return NULL;
	}

	p = find_preset(ep->uuid, NULL);
	if (!p)
		NULL;

	reply = endpoint_select_properties_reply(ep, msg, p);
	if (!reply)
		return NULL;

	bt_shell_printf("Auto Accepting using %s...\n", p->name);

	return reply;
}

static DBusMessage *endpoint_clear_configuration(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct endpoint *ep = user_data;

	free(ep->transport);
	ep->transport = NULL;

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static struct endpoint *endpoint_find(const char *pattern)
{
	GList *l;

	for (l = local_endpoints; l; l = g_list_next(l)) {
		struct endpoint *ep = l->data;

		/* match object path */
		if (!strcmp(ep->path, pattern))
			return ep;

		/* match UUID */
		if (!strcmp(ep->uuid, pattern))
			return ep;
	}

	return NULL;
}

static void cmd_show_endpoint(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_lookup(endpoints, NULL, argv[1],
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Endpoint %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	bt_shell_printf("Endpoint %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "UUID");
	print_property(proxy, "Codec");
	print_property(proxy, "Capabilities");
	print_property(proxy, "Device");
	print_property(proxy, "DelayReporting");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static const GDBusMethodTable endpoint_methods[] = {
	{ GDBUS_ASYNC_METHOD("SetConfiguration",
					GDBUS_ARGS({ "endpoint", "o" },
						{ "properties", "a{sv}" } ),
					NULL, endpoint_set_configuration) },
	{ GDBUS_ASYNC_METHOD("SelectConfiguration",
					GDBUS_ARGS({ "caps", "ay" } ),
					GDBUS_ARGS({ "cfg", "ay" } ),
					endpoint_select_configuration) },
	{ GDBUS_ASYNC_METHOD("SelectProperties",
					GDBUS_ARGS({ "properties", "a{sv}" } ),
					GDBUS_ARGS({ "properties", "a{sv}" } ),
					endpoint_select_properties) },
	{ GDBUS_ASYNC_METHOD("ClearConfiguration",
					GDBUS_ARGS({ "transport", "o" } ),
					NULL, endpoint_clear_configuration) },
	{ },
};

static void endpoint_free(void *data)
{
	struct endpoint *ep = data;

	if (ep->caps) {
		g_free(ep->caps->iov_base);
		g_free(ep->caps);
	}

	if (ep->msg)
		dbus_message_unref(ep->msg);

	g_free(ep->path);
	g_free(ep->uuid);
	g_free(ep);
}

static gboolean endpoint_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct endpoint *ep = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &ep->uuid);

	return TRUE;
}

static gboolean endpoint_get_codec(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct endpoint *ep = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE, &ep->codec);

	return TRUE;
}

static gboolean endpoint_get_capabilities(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct endpoint *ep = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
					     &ep->caps->iov_base,
					     ep->caps->iov_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static const GDBusPropertyTable endpoint_properties[] = {
	{ "UUID", "s", endpoint_get_uuid, NULL, NULL },
	{ "Codec", "y", endpoint_get_codec, NULL, NULL },
	{ "Capabilities", "ay", endpoint_get_capabilities, NULL, NULL },
	{ }
};

static void register_endpoint_setup(DBusMessageIter *iter, void *user_data)
{
	struct endpoint *ep = user_data;
	DBusMessageIter dict;
	const char *key = "Capabilities";

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &ep->path);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	g_dbus_dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING, &ep->uuid);

	g_dbus_dict_append_entry(&dict, "Codec", DBUS_TYPE_BYTE, &ep->codec);

	g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &key,
					DBUS_TYPE_BYTE, &ep->caps->iov_base,
					ep->caps->iov_len);

	bt_shell_printf("Capabilities:\n");
	bt_shell_hexdump(ep->caps->iov_base, ep->caps->iov_len);

	dbus_message_iter_close_container(iter, &dict);
}

static void register_endpoint_reply(DBusMessage *message, void *user_data)
{
	struct endpoint *ep = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("Failed to register endpoint: %s\n",
				error.name);
		dbus_error_free(&error);
		local_endpoints = g_list_remove(local_endpoints, ep);
		g_dbus_unregister_interface(dbus_conn, ep->path,
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Endpoint %s registered\n", ep->path);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void endpoint_register(struct endpoint *ep)
{
	GList *l;

	if (!g_dbus_register_interface(dbus_conn, ep->path,
					BLUEZ_MEDIA_ENDPOINT_INTERFACE,
					endpoint_methods, NULL,
					endpoint_properties, ep,
					endpoint_free)) {
		goto fail;
	}

	for (l = medias; l; l = g_list_next(l)) {
		if (!g_dbus_proxy_method_call(l->data, "RegisterEndpoint",
						register_endpoint_setup,
						register_endpoint_reply,
						ep, NULL)) {
			g_dbus_unregister_interface(dbus_conn, ep->path,
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
			goto fail;
		}
	}

	return;

fail:
	bt_shell_printf("Failed register endpoint\n");
	local_endpoints = g_list_remove(local_endpoints, ep);
	return bt_shell_noninteractive_quit(EXIT_FAILURE);

}

static void endpoint_cis(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	char *endptr = NULL;
	int value;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		ep->cis = BT_ISO_QOS_CIS_UNSET;
	} else {
		value = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0' || value > UINT8_MAX) {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		ep->cis = value;
	}

	endpoint_register(ep);
}

static void endpoint_cig(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	char *endptr = NULL;
	int value;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		ep->cig = BT_ISO_QOS_CIG_UNSET;
	} else {
		value = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0' || value > UINT8_MAX) {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		ep->cig = value;
	}

	bt_shell_prompt_input(ep->path, "CIS (auto/value):", endpoint_cis, ep);
}

static void endpoint_auto_accept(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;

	if (!strcasecmp(input, "y") || !strcasecmp(input, "yes")) {
		ep->auto_accept = true;
	} else if (!strcasecmp(input, "n") || !strcasecmp(input, "no")) {
		ep->auto_accept = false;
	} else {
		bt_shell_printf("Invalid input for Auto Accept\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_prompt_input(ep->path, "CIG (auto/value):", endpoint_cig, ep);
}

static void endpoint_set_capabilities(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;

	if (ep->caps)
		g_free(ep->caps->iov_base);
	else
		ep->caps = g_new0(struct iovec, 1);

	ep->caps->iov_base = str2bytearray((char *) input, &ep->caps->iov_len);

	bt_shell_prompt_input(ep->path, "Auto Accept (yes/no):",
						endpoint_auto_accept, ep);
}

static char *uuid_generator(const char *text, int state)
{
	int len = strlen(text);
	static int index = 0;
	size_t i;

	if (!state) {
		index = 0;
	}

	for (i = index; i < ARRAY_SIZE(caps); i++) {
		const struct capabilities *cap = &caps[i];

		index++;

		if (!strncasecmp(cap->uuid, text, len))
			return strdup(cap->uuid);
	}

	return NULL;
}

static const struct capabilities *find_capabilities(const char *uuid,
							uint8_t codec_id)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(caps); i++) {
		const struct capabilities *cap = &caps[i];

		if (strcasecmp(cap->uuid, uuid))
			continue;

		if (cap->codec_id == codec_id)
			return cap;
	}

	return NULL;
}

static void cmd_register_endpoint(int argc, char *argv[])
{
	struct endpoint *ep;
	char *endptr = NULL;

	ep = g_new0(struct endpoint, 1);
	ep->uuid = g_strdup(argv[1]);
	ep->codec = strtol(argv[2], &endptr, 0);
	ep->path = g_strdup_printf("%s/ep%u", BLUEZ_MEDIA_ENDPOINT_PATH,
					g_list_length(local_endpoints));
	local_endpoints = g_list_append(local_endpoints, ep);

	if (argc > 3)
		endpoint_set_capabilities(argv[3], ep);
	else {
		const struct capabilities *cap;

		cap = find_capabilities(ep->uuid, ep->codec);
		if (cap) {
			if (ep->caps)
				ep->caps->iov_len = 0;

			/* Copy capabilities */
			iov_append(&ep->caps, cap->data.iov_base,
							cap->data.iov_len);

			bt_shell_prompt_input(ep->path, "Auto Accept (yes/no):",
						endpoint_auto_accept, ep);
		} else
			bt_shell_prompt_input(ep->path, "Enter capabilities:",
						endpoint_set_capabilities, ep);
	}
}

static void unregister_endpoint_setup(DBusMessageIter *iter, void *user_data)
{
	struct endpoint *ep = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &ep->path);
}

static void unregister_endpoint_reply(DBusMessage *message, void *user_data)
{
	struct endpoint *ep = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("Failed to unregister endpoint: %s\n",
				error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Endpoint %s unregistered\n", ep->path);

	local_endpoints = g_list_remove(local_endpoints, ep);
	g_dbus_unregister_interface(dbus_conn, ep->path,
					BLUEZ_MEDIA_ENDPOINT_INTERFACE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_unregister_endpoint(int argc, char *argv[])
{
	struct endpoint *ep;
	GList *l;

	ep = endpoint_find(argv[1]);
	if (!ep) {
		bt_shell_printf("Unable to find endpoint object: %s\n",
								argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	for (l = medias; l; l = g_list_next(l)) {
		if (!g_dbus_proxy_method_call(l->data, "UnregisterEndpoint",
						unregister_endpoint_setup,
						unregister_endpoint_reply,
						ep, NULL)) {
			bt_shell_printf("Failed unregister endpoint\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void config_endpoint_setup(DBusMessageIter *iter, void *user_data)
{
	struct endpoint_config *cfg = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
					&cfg->ep->path);

	append_properties(iter, cfg);
}

static void config_endpoint_reply(DBusMessage *message, void *user_data)
{
	struct endpoint_config *cfg = user_data;
	struct endpoint *ep = cfg->ep;
	DBusError error;

	free(cfg->caps->iov_base);
	free(cfg->caps);
	free(cfg);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("Failed to config endpoint: %s\n",
				error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Endpoint %s configured\n", ep->path);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void endpoint_set_config(struct endpoint_config *cfg)
{
	if (!g_dbus_proxy_method_call(cfg->proxy, "SetConfiguration",
						config_endpoint_setup,
						config_endpoint_reply,
						cfg, NULL)) {
		bt_shell_printf("Failed to config endpoint\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static void endpoint_config(const char *input, void *user_data)
{
	struct endpoint_config *cfg = user_data;
	uint8_t *data;
	size_t len = 0;

	data = str2bytearray((char *) input, &len);

	iov_append(&cfg->caps, data, len);
	free(data);

	endpoint_set_config(cfg);
}

static void cmd_config_endpoint(int argc, char *argv[])
{
	struct endpoint_config *cfg;
	const struct codec_preset *preset;

	cfg = new0(struct endpoint_config, 1);

	cfg->proxy = g_dbus_proxy_lookup(endpoints, NULL, argv[1],
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
	if (!cfg->proxy) {
		bt_shell_printf("Endpoint %s not found\n", argv[1]);
		goto fail;
	}

	cfg->ep = endpoint_find(argv[2]);
	if (!cfg->ep) {
		bt_shell_printf("Local Endpoint %s not found\n", argv[2]);
		goto fail;
	}

	if (argc > 3) {
		preset = find_preset(cfg->ep->uuid, argv[3]);
		if (!preset) {
			bt_shell_printf("Preset %s not found\n", argv[3]);
			goto fail;
		}

		/* Copy capabilities */
		iov_append(&cfg->caps, preset->data.iov_base,
						preset->data.iov_len);

		/* Set QoS parameters */
		cfg->qos = &preset->qos;

		endpoint_set_config(cfg);
		return;
	}

	bt_shell_prompt_input(cfg->ep->path, "Enter configuration:",
					endpoint_config, cfg);

	return;

fail:
	g_free(cfg);
	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_presets_endpoint(int argc, char *argv[])
{
	size_t i;
	struct codec_preset *default_preset = NULL;

	if (argc > 2) {
		default_preset = find_preset(argv[1], argv[2]);
		if (!default_preset) {
			bt_shell_printf("Preset %s not found\n", argv[2]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		default_preset->is_default = true;
	}

	for (i = 0; i < ARRAY_SIZE(presets); i++) {
		const struct preset *preset = &presets[i];

		if (!strcasecmp(preset->uuid, argv[1])) {
			size_t j;

			for (j = 0; j < preset->num_presets; j++) {
				struct codec_preset *p;

				p = &preset->presets[j];

				if (default_preset && p != default_preset)
					p->is_default = false;

				if (p->is_default)
					bt_shell_printf("*%s\n", p->name);
				else
					bt_shell_printf("%s\n", p->name);
			}
		}
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static const struct bt_shell_menu endpoint_menu = {
	.name = "endpoint",
	.desc = "Media Endpoint Submenu",
	.entries = {
	{ "list",         "[local]",    cmd_list_endpoints,
						"List available endpoints" },
	{ "show",         "<endpoint>", cmd_show_endpoint,
						"Endpoint information",
						endpoint_generator },
	{ "register",     "<UUID> <codec> [capabilities...]",
						cmd_register_endpoint,
						"Register Endpoint",
						uuid_generator },
	{ "unregister",   "<UUID/object>", cmd_unregister_endpoint,
						"Register Endpoint",
						local_endpoint_generator },
	{ "config",       "<endpoint> <local endpoint> [preset]",
						cmd_config_endpoint,
						"Configure Endpoint",
						endpoint_generator },
	{ "presets",      "<UUID> [default]", cmd_presets_endpoint,
						"List available presets",
						uuid_generator },
	{} },
};

static struct endpoint *endpoint_new(const struct capabilities *cap)
{
	struct endpoint *ep;

	ep = new0(struct endpoint, 1);
	ep->uuid = g_strdup(cap->uuid);
	ep->codec = cap->codec_id;
	ep->path = g_strdup_printf("%s/ep%u", BLUEZ_MEDIA_ENDPOINT_PATH,
					g_list_length(local_endpoints));
	/* Copy capabilities */
	iov_append(&ep->caps, cap->data.iov_base, cap->data.iov_len);
	local_endpoints = g_list_append(local_endpoints, ep);

	return ep;
}

static void register_endpoints(GDBusProxy *proxy)
{
	struct endpoint *ep;
	DBusMessageIter iter, array;

	if (!g_dbus_proxy_get_property(proxy, "SupportedUUIDs", &iter))
		return;

	dbus_message_iter_recurse(&iter, &array);
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		const char *uuid;
		size_t i;

		dbus_message_iter_get_basic(&array, &uuid);

		for (i = 0; i < ARRAY_SIZE(caps); i++) {
			const struct capabilities *cap = &caps[i];

			if (strcasecmp(cap->uuid, uuid))
				continue;

			ep = endpoint_new(cap);
			ep->auto_accept = true;
			ep->cig = BT_ISO_QOS_CIG_UNSET;
			ep->cis = BT_ISO_QOS_CIS_UNSET;
			endpoint_register(ep);
		}

		dbus_message_iter_next(&array);
	}
}

static void media_added(GDBusProxy *proxy)
{
	medias = g_list_append(medias, proxy);

	print_media(proxy, COLORED_NEW);

	if (bt_shell_get_env("AUTO_REGISTER_ENDPOINT"))
		register_endpoints(proxy);
}

static void player_added(GDBusProxy *proxy)
{
	players = g_list_append(players, proxy);

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
	folders = g_list_append(folders, proxy);

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
	items = g_list_append(items, proxy);

	print_item(proxy, COLORED_NEW);
}

static void endpoint_added(GDBusProxy *proxy)
{
	endpoints = g_list_append(endpoints, proxy);

	print_endpoint(proxy, COLORED_NEW);
}

static void print_transport(void *data, void *user_data)
{
	GDBusProxy *proxy = data;
	const char *description = user_data;
	char *str;

	str = proxy_description(proxy, "Transport", description);

	bt_shell_printf("%s\n", str);

	g_free(str);
}

static void transport_added(GDBusProxy *proxy)
{
	transports = g_list_append(transports, proxy);

	print_transport(proxy, COLORED_NEW);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_MEDIA_INTERFACE))
		media_added(proxy);
	else if (!strcmp(interface, BLUEZ_MEDIA_PLAYER_INTERFACE))
		player_added(proxy);
	else if (!strcmp(interface, BLUEZ_MEDIA_FOLDER_INTERFACE))
		folder_added(proxy);
	else if (!strcmp(interface, BLUEZ_MEDIA_ITEM_INTERFACE))
		item_added(proxy);
	else if (!strcmp(interface, BLUEZ_MEDIA_ENDPOINT_INTERFACE))
		endpoint_added(proxy);
	else if (!strcmp(interface, BLUEZ_MEDIA_TRANSPORT_INTERFACE))
		transport_added(proxy);
}

static void media_removed(GDBusProxy *proxy)
{
	print_media(proxy, COLORED_DEL);

	medias = g_list_remove(medias, proxy);
}

static void player_removed(GDBusProxy *proxy)
{
	print_player(proxy, COLORED_DEL);

	if (default_player == proxy)
		default_player = NULL;

	players = g_list_remove(players, proxy);
}

static void folder_removed(GDBusProxy *proxy)
{
	folders = g_list_remove(folders, proxy);

	print_folder(proxy, COLORED_DEL);
}

static void item_removed(GDBusProxy *proxy)
{
	items = g_list_remove(items, proxy);

	print_item(proxy, COLORED_DEL);
}

static void endpoint_removed(GDBusProxy *proxy)
{
	endpoints = g_list_remove(endpoints, proxy);

	print_endpoint(proxy, COLORED_DEL);
}

static void transport_removed(GDBusProxy *proxy)
{
	transports = g_list_remove(transports, proxy);

	print_transport(proxy, COLORED_DEL);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_MEDIA_INTERFACE))
		media_removed(proxy);
	if (!strcmp(interface, BLUEZ_MEDIA_PLAYER_INTERFACE))
		player_removed(proxy);
	if (!strcmp(interface, BLUEZ_MEDIA_FOLDER_INTERFACE))
		folder_removed(proxy);
	if (!strcmp(interface, BLUEZ_MEDIA_ITEM_INTERFACE))
		item_removed(proxy);
	if (!strcmp(interface, BLUEZ_MEDIA_ENDPOINT_INTERFACE))
		endpoint_removed(proxy);
	if (!strcmp(interface, BLUEZ_MEDIA_TRANSPORT_INTERFACE))
		transport_removed(proxy);
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

static void endpoint_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Endpoint", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static struct endpoint *find_ep_by_transport(const char *path)
{
	GList *l;

	for (l = local_endpoints; l; l = g_list_next(l)) {
		struct endpoint *ep = l->data;

		if (ep->transport && !strcmp(ep->transport, path))
			return ep;
	}

	return NULL;
}

static struct endpoint *find_link_by_proxy(GDBusProxy *proxy)
{
	DBusMessageIter iter, array;

	if (!g_dbus_proxy_get_property(proxy, "Links", &iter))
		return NULL;

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) ==
				DBUS_TYPE_OBJECT_PATH) {
		const char *transport;
		struct endpoint *link;

		dbus_message_iter_get_basic(&array, &transport);

		link = find_ep_by_transport(transport);
		if (link)
			return link;
	}

	return NULL;
}

static void transport_close(struct transport *transport)
{
	if (transport->fd < 0)
		return;

	close(transport->fd);
	free(transport->filename);
}

static void transport_free(void *data)
{
	struct transport *transport = data;

	io_destroy(transport->io);
	free(transport);
}

static bool transport_disconnected(struct io *io, void *user_data)
{
	struct transport *transport = user_data;

	bt_shell_printf("Transport fd disconnected\n");

	if (queue_remove(ios, transport))
		transport_free(transport);

	return false;
}

static bool transport_recv(struct io *io, void *user_data)
{
	struct transport *transport = user_data;
	uint8_t buf[1024];
	int ret, len;

	ret = read(io_get_fd(io), buf, sizeof(buf));
	if (ret < 0) {
		bt_shell_printf("Failed to read: %s (%d)\n", strerror(errno),
								-errno);
		return true;
	}

	bt_shell_printf("[seq %d] recv: %u bytes\n", transport->seq, ret);

	transport->seq++;

	if (transport->fd) {
		len = write(transport->fd, buf, ret);
		if (len < 0)
			bt_shell_printf("Unable to write: %s (%d)",
						strerror(errno), -errno);
	}

	return true;
}

static void transport_new(GDBusProxy *proxy, int sk, uint16_t mtu[2])
{
	struct transport *transport;

	transport = new0(struct transport, 1);
	transport->proxy = proxy;
	transport->sk = sk;
	transport->mtu[0] = mtu[0];
	transport->mtu[1] = mtu[1];
	transport->io = io_new(sk);
	transport->fd = -1;

	io_set_disconnect_handler(transport->io, transport_disconnected,
							transport, NULL);
	io_set_read_handler(transport->io, transport_recv, transport, NULL);

	if (!ios)
		ios = queue_new();

	queue_push_tail(ios, transport);
}

static void acquire_reply(DBusMessage *message, void *user_data)
{
	GDBusProxy *proxy = user_data;
	struct endpoint *ep, *link;
	DBusError error;
	int sk;
	uint16_t mtu[2];

	ep = find_ep_by_transport(g_dbus_proxy_get_path(proxy));
	if (ep) {
		ep->acquiring = false;
		link = find_link_by_proxy(proxy);
		if (link)
			link->acquiring = false;
	}

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to acquire: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!dbus_message_get_args(message, &error,
				   DBUS_TYPE_UNIX_FD, &sk,
				   DBUS_TYPE_UINT16, &mtu[0],
				   DBUS_TYPE_UINT16, &mtu[1],
				   DBUS_TYPE_INVALID)) {
		bt_shell_printf("Failed to parse Acquire() reply: %s",
							error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Acquire successful: fd %d MTU %u:%u\n", sk, mtu[0],
								mtu[1]);

	transport_new(proxy, sk, mtu);

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void transport_acquire(const char *input, void *user_data)
{
	GDBusProxy *proxy = user_data;
	struct endpoint *ep, *link;

	if (!strcasecmp(input, "y") || !strcasecmp(input, "yes")) {
		if (g_dbus_proxy_method_call(proxy, "Acquire", NULL,
						acquire_reply, proxy, NULL))
			return;
		bt_shell_printf("Failed acquire transport\n");
	}

	/* Reset acquiring */
	ep = find_ep_by_transport(g_dbus_proxy_get_path(proxy));
	if (ep) {
		ep->acquiring = false;
		link = find_link_by_proxy(proxy);
		if (link)
			link->acquiring = false;
	}
}

static void transport_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;
	struct endpoint *ep, *link;

	str = proxy_description(proxy, "Transport", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);

	if (strcmp(name, "State"))
		return;

	dbus_message_iter_get_basic(iter, &str);

	if (strcmp(str, "pending"))
		return;

	/* Only attempt to acquire if transport is configured with a local
	 * endpoint.
	 */
	ep = find_ep_by_transport(g_dbus_proxy_get_path(proxy));
	if (!ep || ep->acquiring)
		return;

	ep->acquiring = true;

	link = find_link_by_proxy(proxy);
	if (link) {
		bt_shell_printf("Link %s found\n", link->transport);
		/* If link already acquiring wait it to be complete */
		if (link->acquiring)
			return;
		link->acquiring = true;
	}

	if (ep->auto_accept) {
		bt_shell_printf("Auto Acquiring...\n");
		if (!g_dbus_proxy_method_call(proxy, "Acquire", NULL,
						acquire_reply, proxy, NULL)) {
			bt_shell_printf("Failed acquire transport\n");
			ep->acquiring = false;
			if (link)
				link->acquiring = false;
		}
		return;
	}

	bt_shell_prompt_input(g_dbus_proxy_get_path(proxy), "Acquire (yes/no):",
					transport_acquire, proxy);
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
	else if (!strcmp(interface, BLUEZ_MEDIA_ENDPOINT_INTERFACE))
		endpoint_property_changed(proxy, name, iter);
	else if (!strcmp(interface, BLUEZ_MEDIA_TRANSPORT_INTERFACE))
		transport_property_changed(proxy, name, iter);
}

static char *transport_generator(const char *text, int state)
{
	return generic_generator(text, state, transports);
}

static void cmd_list_transport(int argc, char *argv[])
{
	GList *l;

	for (l = transports; l; l = g_list_next(l)) {
		GDBusProxy *proxy = l->data;
		print_transport(proxy, NULL);
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_show_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_lookup(transports, NULL, argv[1],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Transport %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Transport %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "UUID");
	print_property(proxy, "Codec");
	print_property(proxy, "Configuration");
	print_property(proxy, "Device");
	print_property(proxy, "State");
	print_property(proxy, "Delay");
	print_property(proxy, "Volume");
	print_property(proxy, "Endpoint");

	print_property(proxy, "Interval");
	print_property(proxy, "Framing");
	print_property(proxy, "SDU");
	print_property(proxy, "Retransmissions");
	print_property(proxy, "Latency");
	print_property(proxy, "Location");
	print_property(proxy, "Metadata");
	print_property(proxy, "Links");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static bool match_proxy(const void *data, const void *user_data)
{
	const struct transport *transport = data;
	const GDBusProxy *proxy = user_data;

	return transport->proxy == proxy;
}

static struct transport *find_transport(GDBusProxy *proxy)
{
	return queue_find(ios, match_proxy, proxy);
}

static void cmd_acquire_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;
	int i;

	for (i = 1; i < argc; i++) {
		proxy = g_dbus_proxy_lookup(transports, NULL, argv[i],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
		if (!proxy) {
			bt_shell_printf("Transport %s not found\n", argv[i]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		if (find_transport(proxy)) {
			bt_shell_printf("Transport %s already acquired\n",
					argv[i]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		if (!g_dbus_proxy_method_call(proxy, "Acquire", NULL,
						acquire_reply, proxy, NULL)) {
			bt_shell_printf("Failed acquire transport\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void release_reply(DBusMessage *message, void *user_data)
{
	struct transport *transport = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to release: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (queue_remove(ios, transport))
		transport_free(transport);

	bt_shell_printf("Release successful\n");

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_release_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;
	int i;

	for (i = 1; i < argc; i++) {
		struct transport *transport;

		proxy = g_dbus_proxy_lookup(transports, NULL, argv[i],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
		if (!proxy) {
			bt_shell_printf("Transport %s not found\n", argv[1]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		transport = find_transport(proxy);
		if (!transport) {
			bt_shell_printf("Transport %s not acquired\n", argv[i]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		if (!g_dbus_proxy_method_call(proxy, "Release", NULL,
					release_reply, transport, NULL)) {
			bt_shell_printf("Failed release transport\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static int open_file(const char *filename, int flags)
{
	int fd = -1;

	bt_shell_printf("Opening %s ...\n", filename);

	if (flags & O_CREAT)
		fd = open(filename, flags, 0755);
	else
		fd = open(filename, flags);

	if (fd <= 0)
		bt_shell_printf("Can't open file %s: %s\n", filename,
						strerror(errno));

	return fd;
}

#define NSEC_USEC(_t) (_t / 1000L)
#define SEC_USEC(_t)  (_t  * 1000000L)
#define TS_USEC(_ts)  (SEC_USEC((_ts)->tv_sec) + NSEC_USEC((_ts)->tv_nsec))

static void send_wait(struct timespec *t_start, uint32_t us)
{
	struct timespec t_now;
	struct timespec t_diff;
	int64_t delta_us;

	/* Skip sleep at start */
	if (!us)
		return;

	if (clock_gettime(CLOCK_MONOTONIC, &t_now) < 0) {
		bt_shell_printf("clock_gettime: %s (%d)", strerror(errno),
								errno);
		return;
	}

	t_diff.tv_sec = t_now.tv_sec - t_start->tv_sec;
	t_diff.tv_nsec = t_now.tv_nsec - t_start->tv_nsec;

	delta_us = us - TS_USEC(&t_diff);

	if (delta_us < 0) {
		bt_shell_printf("Send is behind: %" PRId64 " us - skip sleep",
							delta_us);
		delta_us = 1000;
	}

	usleep(delta_us);

	if (clock_gettime(CLOCK_MONOTONIC, t_start) < 0)
		bt_shell_printf("clock_gettime: %s (%d)", strerror(errno),
								errno);
}

static int transport_send(struct transport *transport, int fd,
					struct bt_iso_qos *qos)
{
	struct timespec t_start;
	uint8_t *buf;
	uint32_t num = 0;

	if (qos && clock_gettime(CLOCK_MONOTONIC, &t_start) < 0) {
		bt_shell_printf("clock_gettime: %s (%d)", strerror(errno),
								errno);
		return -errno;
	}

	buf = malloc(transport->mtu[1]);
	if (!buf) {
		bt_shell_printf("malloc: %s (%d)", strerror(errno), errno);
		return -ENOMEM;
	}

	/* num of packets = latency (ms) / interval (us) */
	if (qos)
		num = (qos->out.latency * 1000 / qos->out.interval);

	for (transport->seq = 0; ; transport->seq++) {
		ssize_t ret;
		int queued;

		ret = read(fd, buf, transport->mtu[1]);
		if (ret <= 0) {
			if (ret < 0)
				bt_shell_printf("read failed: %s (%d)",
						strerror(errno), errno);
			close(fd);
			return ret;
		}

		ret = send(transport->sk, buf, ret, 0);
		if (ret <= 0) {
			bt_shell_printf("Send failed: %s (%d)",
							strerror(errno), errno);
			return -errno;
		}

		ioctl(transport->sk, TIOCOUTQ, &queued);

		bt_shell_printf("[seq %d] send: %zd bytes "
				"(TIOCOUTQ %d bytes)\n",
				transport->seq, ret, queued);

		if (qos) {
			if (transport->seq && !((transport->seq + 1) % num))
				send_wait(&t_start, num * qos->out.interval);
		}
	}

	free(buf);
}

static void cmd_send_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;
	struct transport *transport;
	int fd, err;
	struct bt_iso_qos qos;
	socklen_t len;

	proxy = g_dbus_proxy_lookup(transports, NULL, argv[1],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Transport %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	transport = find_transport(proxy);
	if (!transport) {
		bt_shell_printf("Transport %s not acquired\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (transport->sk < 0) {
		bt_shell_printf("No Transport Socked found\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	fd = open_file(argv[2], O_RDONLY);

	bt_shell_printf("Sending ...\n");

	/* Read QoS if available */
	memset(&qos, 0, sizeof(qos));
	len = sizeof(qos);
	if (getsockopt(transport->sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos,
							&len) < 0)
		err = transport_send(transport, fd, NULL);
	else
		err = transport_send(transport, fd, &qos);

	close(fd);

	if (err < 0)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}


static void cmd_receive_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;
	struct transport *transport;

	proxy = g_dbus_proxy_lookup(transports, NULL, argv[1],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Transport %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	transport = find_transport(proxy);
	if (!transport) {
		bt_shell_printf("Transport %s not acquired\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (transport->sk < 0) {
		bt_shell_printf("No Transport Socked found\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	transport_close(transport);

	transport->fd = open_file(argv[2], O_RDWR | O_CREAT);
	if (transport->fd < 0)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	transport->filename = strdup(argv[2]);

	bt_shell_printf("Filename: %s\n", transport->filename);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void volume_callback(const DBusError *error, void *user_data)
{
	if (dbus_error_is_set(error)) {
		bt_shell_printf("Failed to set Volume: %s\n", error->name);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Changing Volume succeeded\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_volume_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;
	char *endptr = NULL;
	int volume;

	proxy = g_dbus_proxy_lookup(transports, NULL, argv[1],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Transport %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}


	if (argc == 2) {
		print_property(proxy, "Volume");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	volume = strtol(argv[2], &endptr, 0);
	if (!endptr || *endptr != '\0' || volume > UINT16_MAX) {
		bt_shell_printf("Invalid argument: %s\n", argv[2]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!g_dbus_proxy_set_property_basic(proxy, "Volume", DBUS_TYPE_UINT16,
						&volume, volume_callback,
						NULL, NULL)) {
		bt_shell_printf("Failed release transport\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static const struct bt_shell_menu transport_menu = {
	.name = "transport",
	.desc = "Media Transport Submenu",
	.entries = {
	{ "list",         NULL,    cmd_list_transport,
						"List available transports" },
	{ "show",        "<transport>", cmd_show_transport,
						"Transport information",
						transport_generator },
	{ "acquire",     "<transport> [transport1...]", cmd_acquire_transport,
						"Acquire Transport",
						transport_generator },
	{ "release",     "<transport> [transport1...]", cmd_release_transport,
						"Release Transport",
						transport_generator },
	{ "send",        "<transport> <filename>", cmd_send_transport,
						"Send contents of a file" },
	{ "receive",     "<transport> [filename]", cmd_receive_transport,
						"Get/Set file to receive" },
	{ "volume",      "<transport> [value]",	cmd_volume_transport,
						"Get/Set transport volume",
						transport_generator },
	{} },
};

static GDBusClient *client;

void player_add_submenu(void)
{
	bt_shell_add_submenu(&player_menu);
	bt_shell_add_submenu(&endpoint_menu);
	bt_shell_add_submenu(&transport_menu);

	dbus_conn = bt_shell_get_env("DBUS_CONNECTION");
	if (!dbus_conn || client)
		return;

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							property_changed, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);
}

void player_remove_submenu(void)
{
	g_dbus_client_unref(client);
	queue_destroy(ios, transport_free);
}
