// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
 *  Copyright 2023-2025 NXP
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
#include <sys/timerfd.h>
#include <sys/stat.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "bluetooth/iso.h"

#include "profiles/audio/a2dp-codecs.h"
#include "src/shared/lc3.h"

#include "src/shared/util.h"
#include "src/shared/shell.h"
#include "src/shared/io.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"
#include "src/shared/bap-debug.h"
#include "print.h"
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
#define ROUND_CLOSEST(_x, _y) (((_x) + (_y / 2)) / (_y))

#define EP_SRC_LOCATIONS 0x00000003
#define EP_SNK_LOCATIONS 0x00000003

#define EP_SRC_CTXT 0x000f
#define EP_SUPPORTED_SRC_CTXT EP_SRC_CTXT
#define EP_SNK_CTXT 0x0fff
#define EP_SUPPORTED_SNK_CTXT EP_SNK_CTXT

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct avdtp_media_codec_capability {
	uint8_t rfa0:4;
	uint8_t media_type:4;
	uint8_t media_codec_type;
	uint8_t data[0];
} __attribute__ ((packed));

#elif __BYTE_ORDER == __BIG_ENDIAN

struct avdtp_media_codec_capability {
	uint8_t media_type:4;
	uint8_t rfa0:4;
	uint8_t media_codec_type;
	uint8_t data[0];
} __attribute__ ((packed));

#else
#error "Unknown byte order"
#endif

#define BCAST_CODE {0x01, 0x02, 0x68, 0x05, 0x53, 0xf1, 0x41, 0x5a, \
				0xa2, 0x65, 0xbb, 0xaf, 0xc6, 0xea, 0x03, 0xb8}

struct endpoint {
	char *path;
	char *uuid;
	uint8_t codec;
	uint16_t cid;
	uint16_t vid;
	struct iovec *caps;
	struct iovec *meta;
	uint32_t locations;
	uint16_t supported_context;
	uint16_t context;
	bool auto_accept;
	bool auto_acquire;
	uint8_t max_transports;
	uint8_t iso_group;
	uint8_t iso_stream;
	struct queue *acquiring;
	struct queue *auto_acquiring;
	unsigned int auto_acquiring_id;
	struct queue *selecting;
	unsigned int selecting_id;
	struct queue *transports;
	DBusMessage *msg;
	struct preset *preset;
	struct codec_preset *codec_preset;
	bool broadcast;
	struct iovec *bcode;
	unsigned int refcount;
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
static uint8_t bcast_code[] = BCAST_CODE;
static bool auto_acquire = false;
static bool auto_select = false;

struct transport {
	GDBusProxy *proxy;
	int sk;
	uint16_t mtu[2];
	char *filename;
	int fd;
	struct stat stat;
	struct io *io;
	uint32_t seq;
	struct io *timer_io;
	int num;
};

struct transport_select_args {
	GDBusProxy *proxy;
	struct queue *links;
	struct queue *selecting;
};

static void player_menu_pre_run(const struct bt_shell_menu *menu);
static void transport_set_links(struct transport_select_args *args);
static void transport_select(struct transport_select_args *args);

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

static char *endpoint_generator(const char *text, int state)
{
	char *ret;

	ret = generic_generator(text, state, endpoints);
	if (ret)
		return ret;

	return local_endpoint_generator(text, state);
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

static bool ep_selecting_process(void *user_data)
{
	struct endpoint *ep = user_data;
	struct transport_select_args *args;
	const struct queue_entry *entry;

	if (queue_isempty(ep->selecting))
		return true;

	args = g_new0(struct transport_select_args, 1);

	for (entry = queue_get_entries(ep->selecting); entry;
					entry = entry->next) {
		GDBusProxy *link;

		link = g_dbus_proxy_lookup(transports, NULL, entry->data,
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
		if (!link)
			continue;

		if (find_transport(link))
			continue;

		if (!args->proxy) {
			args->proxy = link;
			continue;
		}

		if (!args->links)
			args->links = queue_new();

		/* Enqueue all links */
		queue_push_tail(args->links, link);
	}

	queue_destroy(ep->selecting, NULL);
	ep->selecting = NULL;

	transport_set_links(args);

	return true;
}

static void ep_set_selecting(struct endpoint *ep, const char *path)
{
	bt_shell_printf("Transport %s selecting\n", path);

	if (!ep->selecting)
		ep->selecting = queue_new();

	queue_push_tail(ep->selecting, strdup(path));

	if (!ep->selecting_id)
		ep->selecting_id = timeout_add(1000, ep_selecting_process, ep,
						NULL);
}

static void transport_acquire(GDBusProxy *proxy, bool prompt);

static bool ep_auto_acquiring_process(void *user_data)
{
	struct endpoint *ep = user_data;
	const struct queue_entry *entry;

	ep->auto_acquiring_id = 0;

	if (queue_isempty(ep->auto_acquiring))
		return true;

	for (entry = queue_get_entries(ep->auto_acquiring); entry;
					entry = entry->next) {
		GDBusProxy *proxy;

		proxy = g_dbus_proxy_lookup(transports, NULL, entry->data,
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
		if (!proxy)
			continue;

		transport_acquire(proxy, false);
	}

	queue_destroy(ep->auto_acquiring, NULL);
	ep->auto_acquiring = NULL;

	return true;
}

static void ep_set_auto_acquiring(struct endpoint *ep, const char *path)
{
	bt_shell_printf("Transport %s auto acquiring\n", path);

	if (!ep->auto_acquiring)
		ep->auto_acquiring = queue_new();

	queue_push_tail(ep->auto_acquiring, strdup(path));

	if (!ep->auto_acquiring_id)
		ep->auto_acquiring_id = timeout_add(1000,
						ep_auto_acquiring_process,
						ep, NULL);
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

	if (!ep->max_transports) {
		bt_shell_printf("Maximum transports reached: rejecting\n");
		return g_dbus_create_error(msg,
					 "org.bluez.Error.Rejected",
					 "Maximum transports reached");
	}

	ep->max_transports--;

	if (!ep->transports)
		ep->transports = queue_new();

	queue_push_tail(ep->transports, strdup(path));

	if (ep->auto_accept) {
		if (auto_select && ep->broadcast)
			ep_set_selecting(ep, path);
		else if (ep->auto_acquire && !ep->broadcast)
			ep_set_auto_acquiring(ep, path);

		bt_shell_printf("Auto Accepting...\n");
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	bt_shell_prompt_input("Endpoint", "Accept (yes/no):", confirm_response,
							dbus_message_ref(msg));

	return NULL;
}

#define CODEC_CAPABILITIES(_name, _uuid, _codec_id, _data, _meta) \
	{ \
		.name = _name, \
		.uuid = _uuid, \
		.codec_id = _codec_id, \
		.data = _data, \
		.meta = _meta, \
	}

#define LC3_DATA(_freq, _duration, _len_min, _len_max) \
	UTIL_IOV_INIT(0x03, LC3_FREQ, _freq, _freq >> 8, \
			0x02, LC3_DURATION, _duration, \
			0x05, LC3_FRAME_LEN, _len_min, _len_min >> 8, \
			_len_max, _len_max >> 8)

static const struct capabilities {
	const char *name;
	const char *uuid;
	uint8_t codec_id;
	struct iovec data;
	struct iovec meta;
} caps[] = {
	/* A2DP SBC Source:
	 *
	 * Channel Modes: Mono DualChannel Stereo JointStereo
	 * Frequencies: 16Khz 32Khz 44.1Khz 48Khz
	 * Subbands: 4 8
	 * Blocks: 4 8 12 16
	 * Bitpool Range: 2-64
	 */
	CODEC_CAPABILITIES("a2dp_src/sbc", A2DP_SOURCE_UUID, A2DP_CODEC_SBC,
				UTIL_IOV_INIT(0xff, 0xff, 2, 64),
				UTIL_IOV_INIT()),

	/* A2DP SBC Sink:
	 *
	 * Channel Modes: Mono DualChannel Stereo JointStereo
	 * Frequencies: 16Khz 32Khz 44.1Khz 48Khz
	 * Subbands: 4 8
	 * Blocks: 4 8 12 16
	 * Bitpool Range: 2-64
	 */
	CODEC_CAPABILITIES("a2dp_snk/sbc", A2DP_SINK_UUID, A2DP_CODEC_SBC,
				UTIL_IOV_INIT(0xff, 0xff, 2, 64),
				UTIL_IOV_INIT()),

	/* PAC LC3 Sink:
	 *
	 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
	 * Duration: 7.5 ms 10 ms
	 * Frame length: 26-240
	 */
	CODEC_CAPABILITIES("pac_snk/lc3", PAC_SINK_UUID, LC3_ID,
				LC3_DATA(LC3_FREQ_ANY, LC3_DURATION_ANY, 26,
					240),
				UTIL_IOV_INIT()),

	/* PAC LC3 Source:
	 *
	 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
	 * Duration: 7.5 ms 10 ms
	 * Channel count: 3
	 * Frame length: 26-240
	 */
	CODEC_CAPABILITIES("pac_src/lc3", PAC_SOURCE_UUID, LC3_ID,
				LC3_DATA(LC3_FREQ_ANY, LC3_DURATION_ANY, 26,
					240),
				UTIL_IOV_INIT()),

	/* Broadcast LC3 Source:
	 *
	 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
	 * Duration: 7.5 ms 10 ms
	 * Channel count: 3
	 * Frame length: 26-240
	 */
	CODEC_CAPABILITIES("bcaa/lc3", BCAA_SERVICE_UUID, LC3_ID,
				LC3_DATA(LC3_FREQ_ANY, LC3_DURATION_ANY, 26,
					240),
				UTIL_IOV_INIT()),

	/* Broadcast LC3 Sink:
	 *
	 * Frequencies: 8Khz 11Khz 16Khz 22Khz 24Khz 32Khz 44.1Khz 48Khz
	 * Duration: 7.5 ms 10 ms
	 * Channel count: 3
	 * Frame length: 26-240
	 */
	CODEC_CAPABILITIES("baa/lc3", BAA_SERVICE_UUID, LC3_ID,
				LC3_DATA(LC3_FREQ_ANY, LC3_DURATION_ANY, 26,
					240),
				UTIL_IOV_INIT()),
};

struct codec_preset {
	char *name;
	const struct iovec data;
	const struct iovec meta;
	struct bt_bap_qos qos;
	uint8_t target_latency;
	uint32_t chan_alloc;
	bool custom;
	bool alt;
	struct codec_preset *alt_preset;
};

#define SBC_PRESET(_name, _data) \
	{ \
		.name = _name, \
		.data = _data, \
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
		UTIL_IOV_INIT(0x28, 0x15, 2, SBC_BITPOOL_MQ_MONO_44100)),
	SBC_PRESET("MQ_MONO_48",
		UTIL_IOV_INIT(0x18, 0x15, 2, SBC_BITPOOL_MQ_MONO_48000)),
	SBC_PRESET("MQ_STEREO_44_1",
		UTIL_IOV_INIT(0x21, 0x15, 2,
				SBC_BITPOOL_MQ_JOINT_STEREO_44100)),
	SBC_PRESET("MQ_STEREO_48",
		UTIL_IOV_INIT(0x11, 0x15, 2,
				SBC_BITPOOL_MQ_JOINT_STEREO_48000)),
	SBC_PRESET("HQ_MONO_44_1",
		UTIL_IOV_INIT(0x28, 0x15, 2, SBC_BITPOOL_HQ_MONO_44100)),
	SBC_PRESET("HQ_MONO_48",
		UTIL_IOV_INIT(0x18, 0x15, 2, SBC_BITPOOL_HQ_MONO_48000)),
	SBC_PRESET("HQ_STEREO_44_1",
		UTIL_IOV_INIT(0x21, 0x15, 2,
				SBC_BITPOOL_HQ_JOINT_STEREO_44100)),
	SBC_PRESET("HQ_STEREO_48",
		UTIL_IOV_INIT(0x11, 0x15, 2,
			      SBC_BITPOOL_HQ_JOINT_STEREO_48000)),
	/* Higher bitrates not recommended by A2DP spec, it dual channel to
	 * avoid going above 53 bitpool:
	 *
	 * https://habr.com/en/post/456476/
	 * https://gitlab.freedesktop.org/pulseaudio/pulseaudio/-/issues/1092
	 */
	SBC_PRESET("XQ_DUAL_44_1", UTIL_IOV_INIT(0x24, 0x15, 2, 43)),
	SBC_PRESET("XQ_DUAL_48", UTIL_IOV_INIT(0x14, 0x15, 2, 39)),
	/* Ultra high bitpool that fits in 512 kbps mandatory bitrate */
	SBC_PRESET("UQ_STEREO_44_1", UTIL_IOV_INIT(0x21, 0x15, 2, 64)),
	SBC_PRESET("UQ_STEREO_48", UTIL_IOV_INIT(0x11, 0x15, 2, 58)),
};

#define LC3_PRESET_LL(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.target_latency = 0x01, \
	}

#define LC3_PRESET(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.target_latency = 0x02, \
	}

#define LC3_PRESET_HR(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.target_latency = 0x03, \
	}

#define LC3_PRESET_B(_name, _data, _qos) \
	{ \
		.name = _name, \
		.data = _data, \
		.qos = _qos, \
		.target_latency = 0x00, \
	}

static struct codec_preset lc3_ucast_presets[] = {
	/* Table 4.43: QoS configuration support setting requirements */
	LC3_PRESET("8_1_1", LC3_CONFIG_8_1, LC3_QOS_8_1_1),
	LC3_PRESET("8_2_1", LC3_CONFIG_8_2, LC3_QOS_8_2_1),
	LC3_PRESET("16_1_1", LC3_CONFIG_16_1, LC3_QOS_16_1_1),
	LC3_PRESET("16_2_1", LC3_CONFIG_16_2, LC3_QOS_16_2_1),
	LC3_PRESET("24_1_1", LC3_CONFIG_24_1, LC3_QOS_24_1_1),
	LC3_PRESET("24_2_1", LC3_CONFIG_24_2, LC3_QOS_24_2_1),
	LC3_PRESET("32_1_1", LC3_CONFIG_32_1, LC3_QOS_32_1_1),
	LC3_PRESET("32_2_1", LC3_CONFIG_32_2, LC3_QOS_32_2_1),
	LC3_PRESET("44_1_1", LC3_CONFIG_44_1, LC3_QOS_44_1_1),
	LC3_PRESET("44_2_1", LC3_CONFIG_44_2, LC3_QOS_44_2_1),
	LC3_PRESET("48_1_1", LC3_CONFIG_48_1, LC3_QOS_48_1_1),
	LC3_PRESET("48_2_1", LC3_CONFIG_48_2, LC3_QOS_48_2_1),
	LC3_PRESET("48_3_1", LC3_CONFIG_48_3, LC3_QOS_48_3_1),
	LC3_PRESET("48_4_1", LC3_CONFIG_48_4, LC3_QOS_48_4_1),
	LC3_PRESET("48_5_1", LC3_CONFIG_48_5, LC3_QOS_48_5_1),
	LC3_PRESET("48_6_1", LC3_CONFIG_48_6, LC3_QOS_48_6_1),
	/* QoS Configuration settings for high reliability audio data */
	LC3_PRESET_HR("8_1_2", LC3_CONFIG_8_1, LC3_QOS_8_1_2),
	LC3_PRESET_HR("8_2_2", LC3_CONFIG_8_2, LC3_QOS_8_2_2),
	LC3_PRESET_HR("16_1_2", LC3_CONFIG_16_1, LC3_QOS_16_1_2),
	LC3_PRESET_HR("16_2_2", LC3_CONFIG_16_2, LC3_QOS_16_2_2),
	LC3_PRESET_HR("24_1_2", LC3_CONFIG_24_1, LC3_QOS_24_1_2),
	LC3_PRESET_HR("24_2_2", LC3_CONFIG_24_2, LC3_QOS_24_2_2),
	LC3_PRESET_HR("32_1_2", LC3_CONFIG_32_1, LC3_QOS_32_1_2),
	LC3_PRESET_HR("32_2_2", LC3_CONFIG_32_2, LC3_QOS_32_2_2),
	LC3_PRESET_HR("44_1_2", LC3_CONFIG_44_1, LC3_QOS_44_1_2),
	LC3_PRESET_HR("44_2_2", LC3_CONFIG_44_2, LC3_QOS_44_2_2),
	LC3_PRESET_HR("48_1_2", LC3_CONFIG_48_1, LC3_QOS_48_1_2),
	LC3_PRESET_HR("48_2_2", LC3_CONFIG_48_2, LC3_QOS_48_2_2),
	LC3_PRESET_HR("48_3_2", LC3_CONFIG_48_3, LC3_QOS_48_3_2),
	LC3_PRESET_HR("48_4_2", LC3_CONFIG_48_4, LC3_QOS_48_4_2),
	LC3_PRESET_HR("48_5_2", LC3_CONFIG_48_5, LC3_QOS_48_5_2),
	LC3_PRESET_HR("48_6_2", LC3_CONFIG_48_6, LC3_QOS_48_6_2),
	/* QoS configuration support setting requirements for the UGG and UGT */
	LC3_PRESET_LL("16_1_gs", LC3_CONFIG_16_1, LC3_QOS_16_1_GS),
	LC3_PRESET_LL("16_2_gs", LC3_CONFIG_16_2, LC3_QOS_16_2_GS),
	LC3_PRESET_LL("32_1_gs", LC3_CONFIG_32_1, LC3_QOS_32_1_GS),
	LC3_PRESET_LL("32_2_gs", LC3_CONFIG_32_2, LC3_QOS_32_2_GS),
	LC3_PRESET_LL("48_1_gs", LC3_CONFIG_48_1, LC3_QOS_48_1_GS),
	LC3_PRESET_LL("48_2_gs", LC3_CONFIG_48_2, LC3_QOS_48_2_GS),
	LC3_PRESET_LL("32_1_gr", LC3_CONFIG_32_1, LC3_QOS_32_1_GR),
	LC3_PRESET_LL("32_2_gr", LC3_CONFIG_32_2, LC3_QOS_32_2_GR),
	LC3_PRESET_LL("48_1_gr", LC3_CONFIG_48_1, LC3_QOS_48_1_GR),
	LC3_PRESET_LL("48_2_gr", LC3_CONFIG_48_2, LC3_QOS_48_2_GR),
	LC3_PRESET_LL("48_3_gr", LC3_CONFIG_48_3, LC3_QOS_48_3_GR),
	LC3_PRESET_LL("48_4_gr", LC3_CONFIG_48_4, LC3_QOS_48_4_GR),
	LC3_PRESET_LL("32_1_gr_l+r", LC3_CONFIG_32_1_AC(2),
				LC3_QOS_32_1_GR_AC(2)),
	LC3_PRESET_LL("32_2_gr_l+r", LC3_CONFIG_32_2_AC(2),
				LC3_QOS_32_2_GR_AC(2)),
	LC3_PRESET_LL("48_1_gr_l+r", LC3_CONFIG_48_1_AC(2),
				LC3_QOS_48_1_GR_AC(2)),
	LC3_PRESET_LL("48_2_gr_l+r", LC3_CONFIG_48_2_AC(2),
				LC3_QOS_48_2_GR_AC(2)),
	LC3_PRESET_LL("48_3_gr_l+r", LC3_CONFIG_48_3_AC(2),
				LC3_QOS_48_3_GR_AC(2)),
	LC3_PRESET_LL("48_4_gr_l+r", LC3_CONFIG_48_4_AC(2),
				LC3_QOS_48_4_GR_AC(2)),
};

static struct codec_preset lc3_bcast_presets[] = {
	/* Table 6.4: Broadcast Audio Stream configuration support requirements
	 * for the Broadcast Source and Broadcast Sink
	 */
	LC3_PRESET_B("8_1_1", LC3_CONFIG_8_1, LC3_QOS_8_1_1_B),
	LC3_PRESET_B("8_2_1", LC3_CONFIG_8_2, LC3_QOS_8_2_1_B),
	LC3_PRESET_B("16_1_1", LC3_CONFIG_16_1, LC3_QOS_16_1_1_B),
	LC3_PRESET_B("16_2_1", LC3_CONFIG_16_2, LC3_QOS_16_2_1_B),
	LC3_PRESET_B("24_1_1", LC3_CONFIG_24_1, LC3_QOS_24_1_1_B),
	LC3_PRESET_B("24_2_1", LC3_CONFIG_24_2, LC3_QOS_24_2_1_B),
	LC3_PRESET_B("32_1_1", LC3_CONFIG_32_1, LC3_QOS_32_1_1_B),
	LC3_PRESET_B("32_2_1", LC3_CONFIG_32_2, LC3_QOS_32_2_1_B),
	LC3_PRESET_B("44_1_1", LC3_CONFIG_44_1, LC3_QOS_44_1_1_B),
	LC3_PRESET_B("44_2_1", LC3_CONFIG_44_2, LC3_QOS_44_2_1_B),
	LC3_PRESET_B("48_1_1", LC3_CONFIG_48_1, LC3_QOS_48_1_1_B),
	LC3_PRESET_B("48_2_1", LC3_CONFIG_48_2, LC3_QOS_48_2_1_B),
	LC3_PRESET_B("48_3_1", LC3_CONFIG_48_3, LC3_QOS_48_3_1_B),
	LC3_PRESET_B("48_4_1", LC3_CONFIG_48_4, LC3_QOS_48_4_1_B),
	LC3_PRESET_B("48_5_1", LC3_CONFIG_48_5, LC3_QOS_48_5_1_B),
	LC3_PRESET_B("48_6_1", LC3_CONFIG_48_6, LC3_QOS_48_6_1_B),
	/* Broadcast Audio Stream configuration settings for high-reliability
	 * audio data.
	 */
	LC3_PRESET_B("8_1_2", LC3_CONFIG_8_1, LC3_QOS_8_1_1_B),
	LC3_PRESET_B("8_2_2", LC3_CONFIG_8_2, LC3_QOS_8_2_2_B),
	LC3_PRESET_B("16_1_2", LC3_CONFIG_16_1, LC3_QOS_16_1_2_B),
	LC3_PRESET_B("16_2_2", LC3_CONFIG_16_2, LC3_QOS_16_2_2_B),
	LC3_PRESET_B("24_1_2", LC3_CONFIG_24_1, LC3_QOS_24_1_2_B),
	LC3_PRESET_B("24_2_2", LC3_CONFIG_24_2, LC3_QOS_24_2_2_B),
	LC3_PRESET_B("32_1_2", LC3_CONFIG_32_1, LC3_QOS_32_1_2_B),
	LC3_PRESET_B("32_2_2", LC3_CONFIG_32_2, LC3_QOS_32_2_2_B),
	LC3_PRESET_B("44_1_2", LC3_CONFIG_44_1, LC3_QOS_44_1_2_B),
	LC3_PRESET_B("44_2_2", LC3_CONFIG_44_2, LC3_QOS_44_2_2_B),
	LC3_PRESET_B("48_1_2", LC3_CONFIG_48_1, LC3_QOS_48_1_2_B),
	LC3_PRESET_B("48_2_2", LC3_CONFIG_48_2, LC3_QOS_48_2_2_B),
	LC3_PRESET_B("48_3_2", LC3_CONFIG_48_3, LC3_QOS_48_3_2_B),
	LC3_PRESET_B("48_4_2", LC3_CONFIG_48_4, LC3_QOS_48_4_2_B),
	LC3_PRESET_B("48_5_2", LC3_CONFIG_48_5, LC3_QOS_48_5_2_B),
	LC3_PRESET_B("48_6_2", LC3_CONFIG_48_6, LC3_QOS_48_6_2_B),
};

static void print_ltv(const char *str, void *user_data)
{
	const char *label = user_data;

	bt_shell_printf("\t%s.%s\n", label, str);
}

static void print_lc3_caps(uint8_t *data, int len)
{
	const char *label = "Capabilities";

	bt_bap_debug_caps(data, len, print_ltv, (void *)label);
}

static void print_lc3_cfg(void *data, int len)
{
	const char *label = "Configuration";

	bt_bap_debug_config(data, len, print_ltv, (void *)label);
}

static void print_lc3_meta(void *data, int len)
{
	const char *label = "Metadata";

	bt_bap_debug_metadata(data, len, print_ltv, (void *)label);
}

#define PRESET(_uuid, _codec, _presets, _default_index) \
	{ \
		.uuid = _uuid, \
		.codec = _codec, \
		.default_preset = &_presets[_default_index], \
		.presets = _presets, \
		.num_presets = ARRAY_SIZE(_presets), \
	}

static struct preset {
	const char *uuid;
	uint8_t codec;
	uint16_t cid;
	uint16_t vid;
	struct queue *custom;
	struct codec_preset *default_preset;
	struct codec_preset *presets;
	size_t num_presets;
} presets[] = {
	PRESET(A2DP_SOURCE_UUID, A2DP_CODEC_SBC, sbc_presets, 6),
	PRESET(A2DP_SINK_UUID, A2DP_CODEC_SBC, sbc_presets, 6),
	PRESET(PAC_SINK_UUID, LC3_ID, lc3_ucast_presets, 3),
	PRESET(PAC_SOURCE_UUID, LC3_ID, lc3_ucast_presets, 3),
	PRESET(BCAA_SERVICE_UUID,  LC3_ID, lc3_bcast_presets, 3),
	PRESET(BAA_SERVICE_UUID,  LC3_ID, lc3_bcast_presets, 3),
};

static void parse_vendor_codec(const char *codec, uint16_t *vid, uint16_t *cid)
{
	char **list;
	char *endptr = NULL;

	if (!codec)
		return;

	list = g_strsplit(codec, ":", 2);

	if (vid)
		*vid = strtol(list[0], &endptr, 0);

	if (cid)
		*cid = strtol(list[1], &endptr, 0);

	g_strfreev(list);
}

static struct preset *find_presets(const char *uuid, uint8_t codec,
					uint16_t vid, uint16_t cid)
{
	size_t i;

	if (codec == 0xff) {
		GList *l;

		for (l = local_endpoints; l; l = g_list_next(l)) {
			struct endpoint *ep = l->data;

			if (strcasecmp(ep->uuid, uuid) || ep->codec != codec)
				continue;

			if (ep->codec == 0xff && (ep->vid != vid ||
							ep->cid != cid))
				continue;

			return ep->preset;
		}

		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(presets); i++) {
		struct preset *preset = &presets[i];

		if (preset->codec != codec)
			continue;

		if (!strcasecmp(preset->uuid, uuid))
			return preset;
	}

	return NULL;
}

static struct preset *find_vendor_presets(const char *uuid, const char *codec)
{
	uint16_t cid;
	uint16_t vid;

	if (!uuid || !codec)
		return NULL;

	parse_vendor_codec(codec, &vid, &cid);

	return find_presets(uuid, 0xff, vid, cid);
}

static struct preset *find_presets_name(const char *uuid, const char *codec)
{
	uint8_t id;
	char *endptr = NULL;

	if (!uuid || !codec)
		return NULL;

	if (strrchr(codec, ':'))
		return find_vendor_presets(uuid, codec);

	id = strtol(codec, &endptr, 0);

	return find_presets(uuid, id, 0x0000, 0x0000);
}

static bool match_custom_name(const void *data, const void *match_data)
{
	const struct codec_preset *preset = data;
	const char *name = match_data;

	return !strcmp(preset->name, name);
}

static struct codec_preset *preset_find_name(struct preset *preset,
						const char *name)
{
	size_t i;

	if (!preset)
		return NULL;

	if (!name)
		return preset->default_preset;

	for (i = 0; i < preset->num_presets; i++) {
		struct codec_preset *p;

		p = &preset->presets[i];

		if (!strcmp(p->name, name))
			return p;
	}

	return queue_find(preset->custom, match_custom_name, name);
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

	p = preset_find_name(ep->preset, input);
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

	if (!ep->max_transports) {
		bt_shell_printf("Maximum transports reached: rejecting\n");
		return g_dbus_create_error(msg,
					 "org.bluez.Error.Rejected",
					 "Maximum transports reached");
	}

	if (!ep->auto_accept) {
		ep->msg = dbus_message_ref(msg);
		bt_shell_prompt_input("Endpoint", "Enter preset/configuration:",
					select_config_response, ep);
		return NULL;
	}

	p = preset_find_name(ep->preset, NULL);
	if (!p) {
		reply = g_dbus_create_error(msg, "org.bluez.Error.Rejected",
								NULL);
		return reply;
	}

	reply = endpoint_select_config_reply(msg, p->data.iov_base,
						p->data.iov_len);
	if (!reply) {
		reply = g_dbus_create_error(msg, "org.bluez.Error.Rejected",
								NULL);
		return reply;
	}

	bt_shell_printf("Auto Accepting using %s...\n", p->name);

	/* Mark auto_acquire if set so the transport is acquired upon
	 * SetConfiguration.
	 */
	ep->auto_acquire = auto_acquire;

	return reply;
}

struct endpoint_config {
	GDBusProxy *proxy;
	struct endpoint *ep;
	struct iovec *caps;		/* Codec Specific Configuration LTVs */
	struct iovec *meta;		/* Metadata LTVs*/
	uint8_t target_latency;
	struct bt_bap_qos qos;		/* BAP QOS configuration parameters */
};

static void append_io_qos(DBusMessageIter *iter, struct bt_bap_io_qos *qos)
{
	bt_shell_printf("Interval %u\n", qos->interval);

	g_dbus_dict_append_entry(iter, "Interval", DBUS_TYPE_UINT32,
						&qos->interval);

	bt_shell_printf("PHY 0x%02x\n", qos->phy);

	g_dbus_dict_append_entry(iter, "PHY", DBUS_TYPE_BYTE, &qos->phy);

	bt_shell_printf("SDU %u\n", qos->sdu);

	g_dbus_dict_append_entry(iter, "SDU", DBUS_TYPE_UINT16, &qos->sdu);

	bt_shell_printf("Retransmissions %u\n", qos->rtn);

	g_dbus_dict_append_entry(iter, "Retransmissions", DBUS_TYPE_BYTE,
						&qos->rtn);

	bt_shell_printf("Latency %u\n", qos->latency);

	g_dbus_dict_append_entry(iter, "Latency", DBUS_TYPE_UINT16,
						&qos->latency);
}

static void append_ucast_qos(DBusMessageIter *iter, struct endpoint_config *cfg)
{
	struct bt_bap_ucast_qos *qos = &cfg->qos.ucast;

	if (cfg->ep->iso_group != BT_ISO_QOS_GROUP_UNSET) {
		bt_shell_printf("CIG 0x%2.2x\n", cfg->ep->iso_group);
		g_dbus_dict_append_entry(iter, "CIG", DBUS_TYPE_BYTE,
							&cfg->ep->iso_group);
	}

	if (cfg->ep->iso_stream != BT_ISO_QOS_STREAM_UNSET) {
		bt_shell_printf("CIS 0x%2.2x\n", cfg->ep->iso_stream);
		g_dbus_dict_append_entry(iter, "CIS", DBUS_TYPE_BYTE,
							&cfg->ep->iso_stream);
	}

	bt_shell_printf("Framing 0x%02x\n", qos->framing);

	g_dbus_dict_append_entry(iter, "Framing", DBUS_TYPE_BYTE,
					&qos->framing);

	bt_shell_printf("PresentationDelay %u\n", qos->delay);

	g_dbus_dict_append_entry(iter, "PresentationDelay",
					DBUS_TYPE_UINT32, &qos->delay);

	if (cfg->target_latency) {
		bt_shell_printf("TargetLatency 0x%02x\n", cfg->target_latency);
		g_dbus_dict_append_entry(iter, "TargetLatency", DBUS_TYPE_BYTE,
					&cfg->target_latency);
	}

	append_io_qos(iter, &qos->io_qos);
}

static void append_bcast_qos(DBusMessageIter *iter, struct endpoint_config *cfg)
{
	struct bt_bap_bcast_qos *qos = &cfg->qos.bcast;

	if (cfg->ep->iso_group != BT_ISO_QOS_BIG_UNSET) {
		bt_shell_printf("BIG 0x%2.2x\n", cfg->ep->iso_group);
		g_dbus_dict_append_entry(iter, "BIG", DBUS_TYPE_BYTE,
							&cfg->ep->iso_group);
	}

	if (cfg->ep->iso_stream != BT_ISO_QOS_BIS_UNSET) {
		bt_shell_printf("BIS 0x%2.2x\n", cfg->ep->iso_stream);
		g_dbus_dict_append_entry(iter, "BIS", DBUS_TYPE_BYTE,
							&cfg->ep->iso_stream);
	}

	if (qos->sync_factor) {
		bt_shell_printf("SyncFactor %u\n", qos->sync_factor);
		g_dbus_dict_append_entry(iter, "SyncFactor", DBUS_TYPE_BYTE,
						&qos->sync_factor);
	}

	if (qos->options) {
		bt_shell_printf("Options %u\n", qos->options);
		g_dbus_dict_append_entry(iter, "Options", DBUS_TYPE_BYTE,
						&qos->options);
	}

	if (qos->skip) {
		bt_shell_printf("Skip %u\n", qos->skip);
		g_dbus_dict_append_entry(iter, "Skip", DBUS_TYPE_UINT16,
						&qos->skip);
	}

	if (qos->sync_timeout) {
		bt_shell_printf("SyncTimeout %u\n", qos->sync_timeout);
		g_dbus_dict_append_entry(iter, "SyncTimeout", DBUS_TYPE_UINT16,
						&qos->sync_timeout);
	}

	if (qos->sync_cte_type) {
		bt_shell_printf("SyncCteType %u\n", qos->sync_cte_type);
		g_dbus_dict_append_entry(iter, "SyncCteType", DBUS_TYPE_BYTE,
					&qos->sync_cte_type);
	}

	if (qos->mse) {
		bt_shell_printf("MSE %u\n", qos->mse);
		g_dbus_dict_append_entry(iter, "MSE", DBUS_TYPE_BYTE,
						&qos->mse);
	}

	if (qos->timeout) {
		bt_shell_printf("Timeout %u\n", qos->timeout);
		g_dbus_dict_append_entry(iter, "Timeout", DBUS_TYPE_UINT16,
						&qos->timeout);
	}

	if (cfg->ep->bcode->iov_len != 0) {
		const char *key = "BCode";
		uint8_t encryption = 0x01;

		g_dbus_dict_append_entry(iter, "Encryption", DBUS_TYPE_BYTE,
						&encryption);

		bt_shell_printf("BCode:\n");
		bt_shell_hexdump(cfg->ep->bcode->iov_base,
				cfg->ep->bcode->iov_len);

		g_dbus_dict_append_basic_array(iter, DBUS_TYPE_STRING,
						&key, DBUS_TYPE_BYTE,
						&cfg->ep->bcode->iov_base,
						cfg->ep->bcode->iov_len);
	}

	bt_shell_printf("Framing 0x%02x\n", qos->framing);

	g_dbus_dict_append_entry(iter, "Framing", DBUS_TYPE_BYTE,
					&qos->framing);

	bt_shell_printf("PresentationDelay %u\n", qos->delay);

	g_dbus_dict_append_entry(iter, "PresentationDelay",
					DBUS_TYPE_UINT32, &qos->delay);

	/* Add BAP codec QOS configuration */
	append_io_qos(iter, &qos->io_qos);
}

static void append_qos(DBusMessageIter *iter, struct endpoint_config *cfg)
{
	DBusMessageIter entry, var, dict;
	const char *key = "QoS";

	dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						"a{sv}", &var);

	dbus_message_iter_open_container(&var, DBUS_TYPE_ARRAY, "{sv}",
					&dict);

	if (cfg->ep->broadcast)
		append_bcast_qos(&dict, cfg);
	else
		append_ucast_qos(&dict, cfg);

	dbus_message_iter_close_container(&var, &dict);
	dbus_message_iter_close_container(&entry, &var);
	dbus_message_iter_close_container(iter, &entry);
}

static void append_properties(DBusMessageIter *iter,
						struct endpoint_config *cfg)
{
	DBusMessageIter dict;
	const char *key = "Capabilities";

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	if (cfg->ep->codec == LC3_ID) {
		print_lc3_cfg(cfg->caps->iov_base, cfg->caps->iov_len);
	} else {
		bt_shell_printf("Capabilities: ");
		bt_shell_hexdump(cfg->caps->iov_base, cfg->caps->iov_len);
	}

	g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &key,
					DBUS_TYPE_BYTE, &cfg->caps->iov_base,
					cfg->caps->iov_len);

	if (cfg->meta && cfg->meta->iov_len) {
		const char *meta = "Metadata";

		g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &meta,
				DBUS_TYPE_BYTE, &cfg->meta->iov_base,
				cfg->meta->iov_len);

		if (cfg->ep->codec == LC3_ID) {
			print_lc3_meta(cfg->meta->iov_base, cfg->meta->iov_len);
		} else {
			bt_shell_printf("Metadata:\n");
			bt_shell_hexdump(cfg->meta->iov_base,
						cfg->meta->iov_len);
		}
	}

	append_qos(&dict, cfg);

	dbus_message_iter_close_container(iter, &dict);
}

static int parse_chan_alloc(DBusMessageIter *iter, uint32_t *location,
						uint8_t *channels)
{
	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_DICT_ENTRY) {
		const char *key;
		DBusMessageIter value, entry;
		int var;

		dbus_message_iter_recurse(iter, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);

		if (!strcasecmp(key, "ChannelAllocation")) {
			if (var != DBUS_TYPE_UINT32)
				return -EINVAL;
			dbus_message_iter_get_basic(&value, location);
			if (*channels)
				*channels = __builtin_popcount(*location);
			return 0;
		} else if (!strcasecmp(key, "Locations")) {
			uint32_t tmp;

			if (var != DBUS_TYPE_UINT32)
				return -EINVAL;

			dbus_message_iter_get_basic(&value, &tmp);
			*location &= tmp;

			if (*channels)
				*channels = __builtin_popcount(*location);
		}

		dbus_message_iter_next(iter);
	}

	return *location ? 0 : -EINVAL;
}

static void ltv_find(size_t i, uint8_t l, uint8_t t, uint8_t *v,
					void *user_data)
{
	bool *found = user_data;

	*found = true;
}

static DBusMessage *endpoint_select_properties_reply(struct endpoint *ep,
						DBusMessage *msg,
						struct codec_preset *preset)
{
	DBusMessage *reply;
	DBusMessageIter iter, props;
	struct endpoint_config *cfg;
	struct bt_bap_io_qos *qos;
	uint32_t location = ep->locations;
	uint8_t channels = 1;

	if (!preset)
		return NULL;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	cfg = new0(struct endpoint_config, 1);
	cfg->ep = ep;

	/* Copy capabilities */
	cfg->caps = util_iov_dup(&preset->data, 1);
	cfg->target_latency = preset->target_latency;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &props);

	if (!parse_chan_alloc(&props, &location, &channels)) {
		uint32_t chan_alloc = 0;
		uint8_t type = LC3_CONFIG_CHAN_ALLOC;
		bool found = false;

		if (preset->chan_alloc & location)
			chan_alloc = preset->chan_alloc & location;
		else if (preset->alt_preset &&
					preset->alt_preset->chan_alloc &
					location) {
			chan_alloc = preset->alt_preset->chan_alloc & location;
			preset = preset->alt_preset;

			/* Copy alternate capabilities */
			util_iov_free(cfg->caps, 1);
			cfg->caps = util_iov_dup(&preset->data, 1);
			cfg->target_latency = preset->target_latency;
		} else
			chan_alloc = location;

		/* Check if Channel Allocation is present in caps */
		util_ltv_foreach(cfg->caps->iov_base, cfg->caps->iov_len,
					&type, ltv_find, &found);

		/* If Channel Allocation has not been set directly via
		 * preset->data then attempt to set it if chan_alloc has been
		 * set.
		 */
		if (!found && chan_alloc) {
			uint8_t chan_alloc_ltv[] = {
				0x05, LC3_CONFIG_CHAN_ALLOC, chan_alloc & 0xff,
				chan_alloc >> 8, chan_alloc >> 16,
				chan_alloc >> 24
			};

			put_le32(chan_alloc, &chan_alloc_ltv[2]);
			util_iov_append(cfg->caps, &chan_alloc_ltv,
						sizeof(chan_alloc_ltv));
		}
	}

	/* Copy metadata */
	if (preset->meta.iov_len)
		cfg->meta = util_iov_dup(&preset->meta, 1);
	else
		cfg->meta = util_iov_dup(ep->meta, 1);

	if (ep->broadcast)
		qos = &preset->qos.bcast.io_qos;
	else
		qos = &preset->qos.ucast.io_qos;

	if (qos->phy) {
		/* Set QoS parameters */
		cfg->qos = preset->qos;
		/* Adjust the SDU size based on the number of
		 * locations/channels that is being requested.
		 */
		if (channels > 1) {
			if (ep->broadcast)
				cfg->qos.bcast.io_qos.sdu *= channels;
			else
				cfg->qos.ucast.io_qos.sdu *= channels;
		}
	}

	dbus_message_iter_init_append(reply, &iter);

	bt_shell_printf("selecting %s...\n", preset->name);

	append_properties(&iter, cfg);

	free(cfg);

	return reply;
}

static struct codec_preset *endpoint_find_codec_preset(struct endpoint *ep,
							const char *name)
{
	if (ep->codec_preset &&
			(!name || !strcmp(ep->codec_preset->name, name)))
		return ep->codec_preset;

	return preset_find_name(ep->preset, name);
}

static void select_properties_response(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	struct codec_preset *p;
	DBusMessage *reply;

	p = endpoint_find_codec_preset(ep, input);
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

	if (!ep->max_transports) {
		bt_shell_printf("Maximum transports reached: rejecting\n");
		return g_dbus_create_error(msg,
					 "org.bluez.Error.Rejected",
					 "Maximum transports reached");
	}

	if (!ep->auto_accept) {
		ep->msg = dbus_message_ref(msg);
		bt_shell_prompt_input("Endpoint", "Enter preset/configuration:",
					select_properties_response, ep);
		return NULL;
	}

	p = endpoint_find_codec_preset(ep, NULL);
	if (!p)
		return NULL;

	reply = endpoint_select_properties_reply(ep, msg, p);
	if (!reply)
		return NULL;

	/* Mark auto_acquire if set so the transport is acquired upon
	 * SetConfiguration.
	 */
	ep->auto_acquire = auto_acquire;

	return reply;
}

static bool match_str(const void *data, const void *user_data)
{
	return !strcmp(data, user_data);
}

static DBusMessage *endpoint_clear_configuration(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct endpoint *ep = user_data;
	DBusMessageIter args;
	const char *path;

	dbus_message_iter_init(msg, &args);

	dbus_message_iter_get_basic(&args, &path);

	if (ep->max_transports != UINT8_MAX)
		ep->max_transports++;

	queue_remove_if(ep->transports, match_str, (void *)path);

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

static void print_aptx_common(a2dp_aptx_t *aptx)
{
	bt_shell_printf("\n\t\tFrequencies: ");
	if (aptx->frequency & APTX_SAMPLING_FREQ_16000)
		bt_shell_printf("16kHz ");
	if (aptx->frequency & APTX_SAMPLING_FREQ_32000)
		bt_shell_printf("32kHz ");
	if (aptx->frequency & APTX_SAMPLING_FREQ_44100)
		bt_shell_printf("44.1kHz ");
	if (aptx->frequency & APTX_SAMPLING_FREQ_48000)
		bt_shell_printf("48kHz ");

	bt_shell_printf("\n\t\tChannel modes: ");
	if (aptx->channel_mode & APTX_CHANNEL_MODE_MONO)
		bt_shell_printf("Mono ");
	if (aptx->channel_mode & APTX_CHANNEL_MODE_STEREO)
		bt_shell_printf("Stereo ");
}

static void print_aptx(a2dp_aptx_t *aptx, uint8_t size)
{
	bt_shell_printf("\t\tVendor Specific Value (aptX)");

	if (size < sizeof(*aptx)) {
		bt_shell_printf(" (broken)\n");
		return;
	}

	print_aptx_common(aptx);

	bt_shell_printf("\n");
}

static void print_faststream(a2dp_faststream_t *faststream, uint8_t size)
{
	bt_shell_printf("\t\tVendor Specific Value (FastStream)");

	if (size < sizeof(*faststream)) {
		bt_shell_printf(" (broken)\n");
		return;
	}

	bt_shell_printf("\n\t\tDirections: ");
	if (faststream->direction & FASTSTREAM_DIRECTION_SINK)
		bt_shell_printf("sink ");
	if (faststream->direction & FASTSTREAM_DIRECTION_SOURCE)
		bt_shell_printf("source ");

	if (faststream->direction & FASTSTREAM_DIRECTION_SINK) {
		bt_shell_printf("\n\t\tSink Frequencies: ");
		if (faststream->sink_frequency &
				FASTSTREAM_SINK_SAMPLING_FREQ_44100)
			bt_shell_printf("44.1kHz ");
		if (faststream->sink_frequency &
				FASTSTREAM_SINK_SAMPLING_FREQ_48000)
			bt_shell_printf("48kHz ");
	}

	if (faststream->direction & FASTSTREAM_DIRECTION_SOURCE) {
		bt_shell_printf("\n\t\tSource Frequencies: ");
		if (faststream->source_frequency &
				FASTSTREAM_SOURCE_SAMPLING_FREQ_16000)
			bt_shell_printf("16kHz ");
	}

	bt_shell_printf("\n");
}

static void print_aptx_ll(a2dp_aptx_ll_t *aptx_ll, uint8_t size)
{
	a2dp_aptx_ll_new_caps_t *aptx_ll_new;

	bt_shell_printf("\t\tVendor Specific Value (aptX Low Latency)");

	if (size < sizeof(*aptx_ll)) {
		bt_shell_printf(" (broken)\n");
		return;
	}

	print_aptx_common(&aptx_ll->aptx);

	bt_shell_printf("\n\tBidirectional link: %s",
			aptx_ll->bidirect_link ? "Yes" : "No");

	aptx_ll_new = &aptx_ll->new_caps[0];
	if (aptx_ll->has_new_caps &&
	    size >= sizeof(*aptx_ll) + sizeof(*aptx_ll_new)) {
		bt_shell_printf("\n\tTarget codec buffer level: %u",
			(unsigned int)aptx_ll_new->target_level2 |
			((unsigned int)(aptx_ll_new->target_level1) << 8));
		bt_shell_printf("\n\tInitial codec buffer level: %u",
			(unsigned int)aptx_ll_new->initial_level2 |
			((unsigned int)(aptx_ll_new->initial_level1) << 8));
		bt_shell_printf("\n\tSRA max rate: %g",
			aptx_ll_new->sra_max_rate / 10000.0);
		bt_shell_printf("\n\tSRA averaging time: %us",
			(unsigned int)aptx_ll_new->sra_avg_time);
		bt_shell_printf("\n\tGood working codec buffer level: %u",
			(unsigned int)aptx_ll_new->good_working_level2 |
			((unsigned int)(aptx_ll_new->good_working_level1) << 8)
			);
	}

	bt_shell_printf("\n");
}

static void print_aptx_hd(a2dp_aptx_hd_t *aptx_hd, uint8_t size)
{
	bt_shell_printf("\t\tVendor Specific Value (aptX HD)");

	if (size < sizeof(*aptx_hd)) {
		bt_shell_printf(" (broken)\n");
		return;
	}

	print_aptx_common(&aptx_hd->aptx);

	bt_shell_printf("\n");
}

static void print_ldac(a2dp_ldac_t *ldac, uint8_t size)
{
	bt_shell_printf("\t\tVendor Specific Value (LDAC)");

	if (size < sizeof(*ldac)) {
		bt_shell_printf(" (broken)\n");
		return;
	}

	bt_shell_printf("\n\t\tFrequencies: ");
	if (ldac->frequency & LDAC_SAMPLING_FREQ_44100)
		bt_shell_printf("44.1kHz ");
	if (ldac->frequency & LDAC_SAMPLING_FREQ_48000)
		bt_shell_printf("48kHz ");
	if (ldac->frequency & LDAC_SAMPLING_FREQ_88200)
		bt_shell_printf("88.2kHz ");
	if (ldac->frequency & LDAC_SAMPLING_FREQ_96000)
		bt_shell_printf("96kHz ");
	if (ldac->frequency & LDAC_SAMPLING_FREQ_176400)
		bt_shell_printf("176.4kHz ");
	if (ldac->frequency & LDAC_SAMPLING_FREQ_192000)
		bt_shell_printf("192kHz ");

	bt_shell_printf("\n\t\tChannel modes: ");
	if (ldac->channel_mode & LDAC_CHANNEL_MODE_MONO)
		bt_shell_printf("Mono ");
	if (ldac->channel_mode & LDAC_CHANNEL_MODE_DUAL)
		bt_shell_printf("Dual ");
	if (ldac->channel_mode & LDAC_CHANNEL_MODE_STEREO)
		bt_shell_printf("Stereo ");

	bt_shell_printf("\n");
}

static void print_opus_g(a2dp_opus_g_t *opus, uint8_t size)
{
	bt_shell_printf("\t\tVendor Specific Value (Opus [Google])");

	if (size < sizeof(*opus)) {
		bt_shell_printf(" (broken)\n");
		return;
	}

	bt_shell_printf("\n\t\tFrequencies: ");
	if (opus->data & OPUS_G_FREQUENCY_48000)
		bt_shell_printf("48kHz ");

	bt_shell_printf("\n\t\tChannel modes: ");
	if (opus->data & OPUS_G_CHANNELS_MONO)
		bt_shell_printf("Mono ");
	if (opus->data & OPUS_G_CHANNELS_STEREO)
		bt_shell_printf("Stereo ");
	if (opus->data & OPUS_G_CHANNELS_DUAL)
		bt_shell_printf("Dual Mono ");

	bt_shell_printf("\n\t\tFrame durations: ");
	if (opus->data & OPUS_G_DURATION_100)
		bt_shell_printf("10 ms ");
	if (opus->data & OPUS_G_DURATION_200)
		bt_shell_printf("20 ms ");

	bt_shell_printf("\n");
}

static void print_vendor(a2dp_vendor_codec_t *vendor, uint8_t size)
{
	uint32_t vendor_id;
	uint16_t codec_id;
	int i;

	if (size < sizeof(*vendor)) {
		bt_shell_printf("\tMedia Codec: Vendor Specific A2DP Codec "
				"(broken)");
		return;
	}

	vendor_id = A2DP_GET_VENDOR_ID(*vendor);
	codec_id = A2DP_GET_CODEC_ID(*vendor);

	bt_shell_printf("\tMedia Codec: Vendor Specific A2DP Codec");

	bt_shell_printf("\n\tVendor ID 0x%08x", vendor_id);

	bt_shell_printf("\n\tVendor Specific Codec ID 0x%04x", codec_id);

	bt_shell_printf("\n\tVendor Specific Data:");
	for (i = 6; i < size; ++i)
		bt_shell_printf(" 0x%.02x", ((unsigned char *)vendor)[i]);
	bt_shell_printf("\n");

	if (vendor_id == APTX_VENDOR_ID && codec_id == APTX_CODEC_ID)
		print_aptx((void *) vendor, size);
	else if (vendor_id == FASTSTREAM_VENDOR_ID &&
			codec_id == FASTSTREAM_CODEC_ID)
		print_faststream((void *) vendor, size);
	else if (vendor_id == APTX_LL_VENDOR_ID && codec_id == APTX_LL_CODEC_ID)
		print_aptx_ll((void *) vendor, size);
	else if (vendor_id == APTX_HD_VENDOR_ID && codec_id == APTX_HD_CODEC_ID)
		print_aptx_hd((void *) vendor, size);
	else if (vendor_id == LDAC_VENDOR_ID && codec_id == LDAC_CODEC_ID)
		print_ldac((void *) vendor, size);
	else if (vendor_id == OPUS_G_VENDOR_ID && codec_id == OPUS_G_CODEC_ID)
		print_opus_g((void *) vendor, size);
}

static void print_mpeg24(a2dp_aac_t *aac, uint8_t size)
{
	unsigned int freq, bitrate;

	if (size < sizeof(*aac)) {
		bt_shell_printf("\tMedia Codec: MPEG24 (broken)\n");
		return;
	}

	freq = AAC_GET_FREQUENCY(*aac);
	bitrate = AAC_GET_BITRATE(*aac);

	bt_shell_printf("\tMedia Codec: MPEG24\n\tObject Types: ");

	if (aac->object_type & AAC_OBJECT_TYPE_MPEG2_AAC_LC)
		bt_shell_printf("MPEG-2 AAC LC ");
	if (aac->object_type & AAC_OBJECT_TYPE_MPEG4_AAC_LC)
		bt_shell_printf("MPEG-4 AAC LC ");
	if (aac->object_type & AAC_OBJECT_TYPE_MPEG4_AAC_LTP)
		bt_shell_printf("MPEG-4 AAC LTP ");
	if (aac->object_type & AAC_OBJECT_TYPE_MPEG4_AAC_SCA)
		bt_shell_printf("MPEG-4 AAC scalable ");

	bt_shell_printf("\n\tFrequencies: ");
	if (freq & AAC_SAMPLING_FREQ_8000)
		bt_shell_printf("8kHz ");
	if (freq & AAC_SAMPLING_FREQ_11025)
		bt_shell_printf("11.025kHz ");
	if (freq & AAC_SAMPLING_FREQ_12000)
		bt_shell_printf("12kHz ");
	if (freq & AAC_SAMPLING_FREQ_16000)
		bt_shell_printf("16kHz ");
	if (freq & AAC_SAMPLING_FREQ_22050)
		bt_shell_printf("22.05kHz ");
	if (freq & AAC_SAMPLING_FREQ_24000)
		bt_shell_printf("24kHz ");
	if (freq & AAC_SAMPLING_FREQ_32000)
		bt_shell_printf("32kHz ");
	if (freq & AAC_SAMPLING_FREQ_44100)
		bt_shell_printf("44.1kHz ");
	if (freq & AAC_SAMPLING_FREQ_48000)
		bt_shell_printf("48kHz ");
	if (freq & AAC_SAMPLING_FREQ_64000)
		bt_shell_printf("64kHz ");
	if (freq & AAC_SAMPLING_FREQ_88200)
		bt_shell_printf("88.2kHz ");
	if (freq & AAC_SAMPLING_FREQ_96000)
		bt_shell_printf("96kHz ");

	bt_shell_printf("\n\tChannels: ");
	if (aac->channels & AAC_CHANNELS_1)
		bt_shell_printf("1 ");
	if (aac->channels & AAC_CHANNELS_2)
		bt_shell_printf("2 ");

	bt_shell_printf("\n\tBitrate: %u", bitrate);

	bt_shell_printf("\n\tVBR: %s", aac->vbr ? "Yes\n" : "No\n");
}

static void print_mpeg12(a2dp_mpeg_t *mpeg, uint8_t size)
{
	uint16_t bitrate;

	if (size < sizeof(*mpeg)) {
		bt_shell_printf("\tMedia Codec: MPEG12 (broken)\n");
		return;
	}

	bitrate = MPEG_GET_BITRATE(*mpeg);

	bt_shell_printf("\tMedia Codec: MPEG12\n\tChannel Modes: ");

	if (mpeg->channel_mode & MPEG_CHANNEL_MODE_MONO)
		bt_shell_printf("Mono ");
	if (mpeg->channel_mode & MPEG_CHANNEL_MODE_DUAL_CHANNEL)
		bt_shell_printf("DualChannel ");
	if (mpeg->channel_mode & MPEG_CHANNEL_MODE_STEREO)
		bt_shell_printf("Stereo ");
	if (mpeg->channel_mode & MPEG_CHANNEL_MODE_JOINT_STEREO)
		bt_shell_printf("JointStereo");

	bt_shell_printf("\n\tFrequencies: ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_16000)
		bt_shell_printf("16Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_22050)
		bt_shell_printf("22.05Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_24000)
		bt_shell_printf("24Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_32000)
		bt_shell_printf("32Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_44100)
		bt_shell_printf("44.1Khz ");
	if (mpeg->frequency & MPEG_SAMPLING_FREQ_48000)
		bt_shell_printf("48Khz ");

	bt_shell_printf("\n\tCRC: %s", mpeg->crc ? "Yes" : "No");

	bt_shell_printf("\n\tLayer: ");
	if (mpeg->layer & MPEG_LAYER_MP1)
		bt_shell_printf("1 ");
	if (mpeg->layer & MPEG_LAYER_MP2)
		bt_shell_printf("2 ");
	if (mpeg->layer & MPEG_LAYER_MP3)
		bt_shell_printf("3 ");

	if (bitrate & MPEG_BIT_RATE_FREE) {
		bt_shell_printf("\n\tBit Rate: Free format");
	} else {
		if (mpeg->layer & MPEG_LAYER_MP1) {
			bt_shell_printf("\n\tLayer 1 Bit Rate: ");
			if (bitrate & MPEG_MP1_BIT_RATE_32000)
				bt_shell_printf("32kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_64000)
				bt_shell_printf("64kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_96000)
				bt_shell_printf("96kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_128000)
				bt_shell_printf("128kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_160000)
				bt_shell_printf("160kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_192000)
				bt_shell_printf("192kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_224000)
				bt_shell_printf("224kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_256000)
				bt_shell_printf("256kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_320000)
				bt_shell_printf("320kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_352000)
				bt_shell_printf("352kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_384000)
				bt_shell_printf("384kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_416000)
				bt_shell_printf("416kbps ");
			if (bitrate & MPEG_MP1_BIT_RATE_448000)
				bt_shell_printf("448kbps ");
		}

		if (mpeg->layer & MPEG_LAYER_MP2) {
			bt_shell_printf("\n\tLayer 2 Bit Rate: ");
			if (bitrate & MPEG_MP2_BIT_RATE_32000)
				bt_shell_printf("32kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_48000)
				bt_shell_printf("48kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_56000)
				bt_shell_printf("56kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_64000)
				bt_shell_printf("64kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_80000)
				bt_shell_printf("80kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_96000)
				bt_shell_printf("96kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_112000)
				bt_shell_printf("112kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_128000)
				bt_shell_printf("128kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_160000)
				bt_shell_printf("160kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_192000)
				bt_shell_printf("192kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_224000)
				bt_shell_printf("224kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_256000)
				bt_shell_printf("256kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_320000)
				bt_shell_printf("320kbps ");
			if (bitrate & MPEG_MP2_BIT_RATE_384000)
				bt_shell_printf("384kbps ");
		}

		if (mpeg->layer & MPEG_LAYER_MP3) {
			bt_shell_printf("\n\tLayer 3 Bit Rate: ");
			if (bitrate & MPEG_MP3_BIT_RATE_32000)
				bt_shell_printf("32kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_40000)
				bt_shell_printf("40kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_48000)
				bt_shell_printf("48kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_56000)
				bt_shell_printf("56kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_64000)
				bt_shell_printf("64kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_80000)
				bt_shell_printf("80kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_96000)
				bt_shell_printf("96kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_112000)
				bt_shell_printf("112kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_128000)
				bt_shell_printf("128kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_160000)
				bt_shell_printf("160kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_192000)
				bt_shell_printf("192kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_224000)
				bt_shell_printf("224kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_256000)
				bt_shell_printf("256kbps ");
			if (bitrate & MPEG_MP3_BIT_RATE_320000)
				bt_shell_printf("320kbps ");
		}
	}

	bt_shell_printf("\n\tVBR: %s", mpeg->vbr ? "Yes" : "No");

	bt_shell_printf("\n\tPayload Format: ");
	if (mpeg->mpf)
		bt_shell_printf("RFC-2250 RFC-3119\n");
	else
		bt_shell_printf("RFC-2250\n");
}

static void print_sbc(a2dp_sbc_t *sbc, uint8_t size)
{
	if (size < sizeof(*sbc)) {
		bt_shell_printf("\tMedia Codec: SBC (broken)\n");
		return;
	}

	bt_shell_printf("\tMedia Codec: SBC\n\tChannel Modes: ");

	if (sbc->channel_mode & SBC_CHANNEL_MODE_MONO)
		bt_shell_printf("Mono ");
	if (sbc->channel_mode & SBC_CHANNEL_MODE_DUAL_CHANNEL)
		bt_shell_printf("DualChannel ");
	if (sbc->channel_mode & SBC_CHANNEL_MODE_STEREO)
		bt_shell_printf("Stereo ");
	if (sbc->channel_mode & SBC_CHANNEL_MODE_JOINT_STEREO)
		bt_shell_printf("JointStereo");

	bt_shell_printf("\n\tFrequencies: ");
	if (sbc->frequency & SBC_SAMPLING_FREQ_16000)
		bt_shell_printf("16Khz ");
	if (sbc->frequency & SBC_SAMPLING_FREQ_32000)
		bt_shell_printf("32Khz ");
	if (sbc->frequency & SBC_SAMPLING_FREQ_44100)
		bt_shell_printf("44.1Khz ");
	if (sbc->frequency & SBC_SAMPLING_FREQ_48000)
		bt_shell_printf("48Khz ");

	bt_shell_printf("\n\tSubbands: ");
	if (sbc->allocation_method & SBC_SUBBANDS_4)
		bt_shell_printf("4 ");
	if (sbc->allocation_method & SBC_SUBBANDS_8)
		bt_shell_printf("8");

	bt_shell_printf("\n\tBlocks: ");
	if (sbc->block_length & SBC_BLOCK_LENGTH_4)
		bt_shell_printf("4 ");
	if (sbc->block_length & SBC_BLOCK_LENGTH_8)
		bt_shell_printf("8 ");
	if (sbc->block_length & SBC_BLOCK_LENGTH_12)
		bt_shell_printf("12 ");
	if (sbc->block_length & SBC_BLOCK_LENGTH_16)
		bt_shell_printf("16 ");

	bt_shell_printf("\n\tBitpool Range: %d-%d\n",
				sbc->min_bitpool, sbc->max_bitpool);
}

static int print_a2dp_codec(uint8_t codec, void *data, uint8_t size)
{
	int i;

	switch (codec) {
	case A2DP_CODEC_SBC:
		print_sbc(data, size);
		break;
	case A2DP_CODEC_MPEG12:
		print_mpeg12(data, size);
		break;
	case A2DP_CODEC_MPEG24:
		print_mpeg24(data, size);
		break;
	case A2DP_CODEC_VENDOR:
		print_vendor(data, size);
		break;
	default:
		bt_shell_printf("\tMedia Codec: Unknown\n");
		bt_shell_printf("\t\tCodec Data:");
		for (i = 0; i < size - 2; ++i)
			bt_shell_printf(" 0x%.02x", ((unsigned char *)data)[i]);
		bt_shell_printf("\n");
	}

	return 0;
}

static void print_hexdump(const char *label, struct iovec *iov)
{
	if (!iov)
		return;

	bt_shell_printf("%s:\n", label);
	bt_shell_hexdump(iov->iov_base, iov->iov_len);
}

static void print_codec(const char *uuid, uint8_t codec, struct iovec *caps,
						struct iovec *meta)
{
	if (!strcasecmp(uuid, A2DP_SINK_UUID) ||
			!strcasecmp(uuid, A2DP_SOURCE_UUID)) {
		print_a2dp_codec(codec, caps->iov_base, caps->iov_len);
		return;
	}

	if (codec != LC3_ID) {
		print_hexdump("Capabilities", caps);
		print_hexdump("Metadata", meta);
		return;
	}

	print_lc3_caps(caps->iov_base, caps->iov_len);

	if (!meta)
		return;

	print_lc3_meta(meta->iov_base, meta->iov_len);
}

static void print_capabilities(GDBusProxy *proxy)
{
	DBusMessageIter iter, subiter;
	const char *uuid;
	uint8_t codec;
	struct iovec caps, meta;

	if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (!g_dbus_proxy_get_property(proxy, "Codec", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &codec);

	if (!g_dbus_proxy_get_property(proxy, "Capabilities", &iter))
		return;

	dbus_message_iter_recurse(&iter, &subiter);

	dbus_message_iter_get_fixed_array(&subiter, &caps.iov_base,
						(int *)&caps.iov_len);

	if (g_dbus_proxy_get_property(proxy, "Metadata", &iter)) {
		dbus_message_iter_recurse(&iter, &subiter);
		dbus_message_iter_get_fixed_array(&subiter, &meta.iov_base,
						  (int *)&meta.iov_len);
	} else {
		meta.iov_base = NULL;
		meta.iov_len = 0;
	}

	print_codec(uuid, codec, &caps, &meta);
}

static void print_preset(struct codec_preset *codec, uint8_t codec_id)
{
	bt_shell_printf("\tPreset %s\n", codec->name);

	if (codec_id == LC3_ID)
		print_lc3_cfg(codec->data.iov_base, codec->data.iov_len);
}

static void print_local_endpoint(struct endpoint *ep)
{
	bt_shell_printf("Endpoint %s\n", ep->path);
	bt_shell_printf("\tUUID %s\n", ep->uuid);
	bt_shell_printf("\tCodec 0x%02x (%u)\n", ep->codec, ep->codec);

	if (ep->caps)
		print_codec(ep->uuid, ep->codec, ep->caps, ep->meta);

	if (ep->codec_preset)
		print_preset(ep->codec_preset, ep->codec);

	if (ep->locations)
		bt_shell_printf("\tLocations 0x%08x (%u)\n", ep->locations,
				ep->locations);
	if (ep->supported_context)
		bt_shell_printf("\tSupportedContext 0x%08x (%u)\n",
				ep->supported_context, ep->supported_context);
	if (ep->context)
		bt_shell_printf("\tContext 0x%08x (%u)\n", ep->context,
				ep->context);
}

static void print_endpoint_properties(GDBusProxy *proxy)
{
	bt_shell_printf("Endpoint %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "UUID");
	print_property(proxy, "Codec");
	print_capabilities(proxy);
	print_property(proxy, "Device");
	print_property(proxy, "DelayReporting");
	print_property(proxy, "Locations");
	print_property(proxy, "SupportedContext");
	print_property(proxy, "Context");
	print_property(proxy, "QoS");
	print_property(proxy, "SupportedFeatures");
}

static void print_endpoints(void *data, void *user_data)
{
	print_endpoint_properties(data);
}

static void print_local_endpoints(void *data, void *user_data)
{
	print_local_endpoint(data);
}

static void cmd_show_endpoint(int argc, char *argv[])
{
	GDBusProxy *proxy;

	/* Show all endpoints if no argument is given */
	if (argc != 2) {
		g_list_foreach(endpoints, print_endpoints, NULL);
		g_list_foreach(local_endpoints, print_local_endpoints, NULL);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	proxy = g_dbus_proxy_lookup(endpoints, NULL, argv[1],
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
	if (!proxy) {
		struct endpoint *ep;

		ep = endpoint_find(argv[1]);
		if (ep)
			return print_local_endpoint(ep);

		bt_shell_printf("Endpoint %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	print_endpoint_properties(proxy);

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

	util_iov_free(ep->caps, 1);
	util_iov_free(ep->meta, 1);

	if (ep->msg)
		dbus_message_unref(ep->msg);

	queue_destroy(ep->preset->custom, free);
	ep->preset->custom = NULL;

	if (ep->codec == 0xff)
		free(ep->preset);

	timeout_remove(ep->selecting_id);
	timeout_remove(ep->auto_acquiring_id);

	queue_destroy(ep->acquiring, NULL);
	queue_destroy(ep->auto_acquiring, free);
	queue_destroy(ep->selecting, free);
	queue_destroy(ep->transports, free);

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

struct vendor {
	uint16_t cid;
	uint16_t vid;
} __packed;

static gboolean endpoint_get_vendor(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct endpoint *ep = data;
	struct vendor vendor = { ep->cid, ep->vid };

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &vendor);

	return TRUE;
}

static gboolean endpoint_vendor_exists(const GDBusPropertyTable *property,
							void *data)
{
	struct endpoint *ep = data;

	return ep->cid && ep->vid;
}

static gboolean endpoint_get_metadata(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct endpoint *ep = data;
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
				&ep->meta->iov_base,
				ep->meta->iov_len);

	dbus_message_iter_close_container(iter, &array);

	return TRUE;
}

static gboolean endpoint_metadata_exists(const GDBusPropertyTable *property,
							void *data)
{
	struct endpoint *ep = data;

	return ep->meta ? TRUE : FALSE;
}

static gboolean endpoint_get_locations(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct endpoint *ep = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &ep->locations);

	return TRUE;
}

static gboolean endpoint_locations_exists(const GDBusPropertyTable *property,
							void *data)
{
	struct endpoint *ep = data;

	return ep->supported_context ? TRUE : FALSE;
}

static gboolean
endpoint_get_supported_context(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct endpoint *ep = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16,
					&ep->supported_context);

	return TRUE;
}

static gboolean
endpoint_supported_context_exists(const GDBusPropertyTable *property,
							void *data)
{
	struct endpoint *ep = data;

	return ep->supported_context ? TRUE : FALSE;
}

static gboolean endpoint_get_context(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct endpoint *ep = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &ep->context);

	return TRUE;
}

static gboolean endpoint_context_exists(const GDBusPropertyTable *property,
							void *data)
{
	struct endpoint *ep = data;

	return ep->context ? TRUE : FALSE;
}

static const GDBusPropertyTable endpoint_properties[] = {
	{ "UUID", "s", endpoint_get_uuid, NULL, NULL },
	{ "Codec", "y", endpoint_get_codec, NULL, NULL },
	{ "Capabilities", "ay", endpoint_get_capabilities, NULL, NULL },
	{ "Metadata", "ay", endpoint_get_metadata, NULL,
				endpoint_metadata_exists },
	{ "Vendor", "u", endpoint_get_vendor, NULL, endpoint_vendor_exists },
	{ "Locations", "u", endpoint_get_locations, NULL,
				endpoint_locations_exists },
	{ "SupportedContext", "q", endpoint_get_supported_context, NULL,
				endpoint_supported_context_exists },
	{ "Context", "q", endpoint_get_context, NULL, endpoint_context_exists },
	{ }
};

static void register_endpoint_setup(DBusMessageIter *iter, void *user_data)
{
	struct endpoint *ep = user_data;
	DBusMessageIter dict;
	const char *key = "Capabilities";
	const char *meta = "Metadata";

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &ep->path);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	g_dbus_dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING, &ep->uuid);

	g_dbus_dict_append_entry(&dict, "Codec", DBUS_TYPE_BYTE, &ep->codec);

	if (ep->cid && ep->vid) {
		struct vendor vendor = { ep->cid, ep->vid };

		g_dbus_dict_append_entry(&dict, "Vendor", DBUS_TYPE_UINT32,
						 &vendor);
	}

	if (ep->caps) {
		g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &key,
					DBUS_TYPE_BYTE, &ep->caps->iov_base,
					ep->caps->iov_len);

		bt_shell_printf("Capabilities:\n");
		bt_shell_hexdump(ep->caps->iov_base, ep->caps->iov_len);
	}

	if (ep->meta) {
		g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &meta,
				DBUS_TYPE_BYTE, &ep->meta->iov_base,
				ep->meta->iov_len);

		bt_shell_printf("Metadata:\n");
		bt_shell_hexdump(ep->meta->iov_base, ep->meta->iov_len);
	}

	if (ep->locations)
		g_dbus_dict_append_entry(&dict, "Locations", DBUS_TYPE_UINT32,
						&ep->locations);

	if (ep->supported_context)
		g_dbus_dict_append_entry(&dict, "SupportedContext",
						DBUS_TYPE_UINT16,
						&ep->supported_context);

	if (ep->context)
		g_dbus_dict_append_entry(&dict, "Context", DBUS_TYPE_UINT16,
						&ep->context);

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
		if (g_list_find(local_endpoints, ep)) {
			local_endpoints = g_list_remove(local_endpoints, ep);
			g_dbus_unregister_interface(dbus_conn, ep->path,
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
		}
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Endpoint %s registered\n", ep->path);
	ep->refcount++;

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static bool media_supports_uuid(GDBusProxy *proxy, const char *uuid)
{
	DBusMessageIter iter, array;

	if (!g_dbus_proxy_get_property(proxy, "SupportedUUIDs", &iter))
		return false;

	dbus_message_iter_recurse(&iter, &array);
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		const char *support_uuid;

		dbus_message_iter_get_basic(&array, &support_uuid);

		if (!strcasecmp(uuid, support_uuid))
			return true;

		dbus_message_iter_next(&array);
	}

	return false;
}

static void endpoint_register(struct endpoint *ep)
{
	GList *l;
	int registered = 0;

	if (!g_dbus_register_interface(dbus_conn, ep->path,
					BLUEZ_MEDIA_ENDPOINT_INTERFACE,
					endpoint_methods, NULL,
					endpoint_properties, ep,
					endpoint_free)) {
		goto fail;
	}

	for (l = medias; l; l = g_list_next(l)) {
		if (!media_supports_uuid(l->data, ep->uuid))
			continue;

		if (!g_dbus_proxy_method_call(l->data, "RegisterEndpoint",
						register_endpoint_setup,
						register_endpoint_reply,
						ep, NULL)) {
			g_dbus_unregister_interface(dbus_conn, ep->path,
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
			goto fail;
		}

		registered++;
	}

	if (!registered)
		goto fail;

	return;

fail:
	bt_shell_printf("Failed register endpoint\n");
	local_endpoints = g_list_remove(local_endpoints, ep);
	return bt_shell_noninteractive_quit(EXIT_FAILURE);

}

static void endpoint_iso_stream(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	char *endptr = NULL;
	int value;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		ep->iso_stream = BT_ISO_QOS_STREAM_UNSET;
	} else {
		value = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0' || value > UINT8_MAX) {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		ep->iso_stream = value;
	}

	endpoint_register(ep);
}

static void endpoint_iso_group(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	char *endptr = NULL;
	int value;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		ep->iso_group = BT_ISO_QOS_GROUP_UNSET;
	} else {
		value = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0' || value > UINT8_MAX) {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		ep->iso_group = value;
	}

	bt_shell_prompt_input(ep->path, "CIS (auto/value):",
		endpoint_iso_stream, ep);
}

static void endpoint_context(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	char *endptr = NULL;
	int value;

	value = strtol(input, &endptr, 0);

	if (!endptr || *endptr != '\0' || value > UINT16_MAX) {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	ep->context = value;

	bt_shell_prompt_input(ep->path, "CIG (auto/value):",
		endpoint_iso_group, ep);
}

static void endpoint_supported_context(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	char *endptr = NULL;
	int value;

	value = strtol(input, &endptr, 0);

	if (!endptr || *endptr != '\0' || value > UINT16_MAX) {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	ep->supported_context = value;

	if (ep->broadcast) {
		endpoint_register(ep);
		return;
	}

	bt_shell_prompt_input(ep->path, "Context (value):", endpoint_context,
									ep);
}

static void endpoint_locations(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	char *endptr = NULL;
	int value;
	uint8_t channels;

	value = strtol(input, &endptr, 0);

	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	ep->locations = value;

	channels = __builtin_popcount(value);
	/* Automatically set LC3_CHAN_COUNT if only 1 location is supported */
	if (channels == 1)
		util_ltv_push(ep->caps, sizeof(channels), LC3_CHAN_COUNT,
				&channels);

	bt_shell_prompt_input(ep->path, "Supported Context (value):",
				endpoint_supported_context, ep);
}

static void endpoint_max_transports(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	char *endptr = NULL;
	int value;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		ep->max_transports = UINT8_MAX;
	} else {
		value = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0' || value > UINT8_MAX) {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		ep->max_transports = value;
	}

	bt_shell_prompt_input(ep->path, "Locations:", endpoint_locations, ep);
}

static void endpoint_auto_accept(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;

	if (!strcasecmp(input, "y") || !strcasecmp(input, "yes")) {
		ep->auto_accept = true;
		bt_shell_prompt_input(ep->path, "Max Transports (auto/value):",
						endpoint_max_transports, ep);
		return;
	} else if (!strcasecmp(input, "n") || !strcasecmp(input, "no")) {
		ep->auto_accept = false;
		bt_shell_prompt_input(ep->path, "Max Transports (auto/value):",
						endpoint_max_transports, ep);
		return;
	} else {
		bt_shell_printf("Invalid input for Auto Accept\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static void endpoint_set_metadata(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	struct iovec iov;

	if (!strcasecmp(input, "n") || !strcasecmp(input, "no")) {
		util_iov_free(ep->meta, 1);
		ep->meta = NULL;
		goto done;
	}

	iov.iov_base = str2bytearray((char *) input, &iov.iov_len);
	if (iov.iov_base) {
		util_iov_free(ep->meta, 1);
		ep->meta = util_iov_dup(&iov, 1);
	}

done:
	bt_shell_prompt_input(ep->path, "Auto Accept (yes/no):",
					endpoint_auto_accept, ep);
}

static void endpoint_set_capabilities(const char *input, void *user_data)
{
	struct endpoint *ep = user_data;
	struct iovec iov;

	if (!strcasecmp(input, "n") || !strcasecmp(input, "no")) {
		util_iov_free(ep->caps, 1);
		ep->caps = NULL;
		goto done;
	}

	iov.iov_base = str2bytearray((char *) input, &iov.iov_len);
	if (iov.iov_base) {
		util_iov_free(ep->caps, 1);
		ep->caps = util_iov_dup(&iov, 1);
	}

done:
	bt_shell_prompt_input(ep->path, "Enter Metadata (value/no):",
					endpoint_set_metadata, ep);
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

static struct codec_preset *codec_preset_new(const char *name)
{
	struct codec_preset *codec;

	codec = new0(struct codec_preset, 1);
	codec->name = strdup(name);
	codec->custom = true;

	return codec;
}

static struct codec_preset *codec_preset_add(struct preset *preset,
						const char *name)
{
	struct codec_preset *codec;

	codec = preset_find_name(preset, name);
	if (codec)
		return codec;

	codec = codec_preset_new(name);

	if (!preset->custom)
		preset->custom = queue_new();

	queue_push_tail(preset->custom, codec);

	return codec;
}

static void cmd_register_endpoint(int argc, char *argv[])
{
	struct endpoint *ep;
	char *endptr = NULL;

	ep = g_new0(struct endpoint, 1);
	ep->uuid = g_strdup(argv[1]);
	ep->codec = strtol(argv[2], &endptr, 0);
	ep->cid = 0x0000;
	ep->vid = 0x0000;
	ep->path = g_strdup_printf("%s/ep%u", BLUEZ_MEDIA_ENDPOINT_PATH,
					g_list_length(local_endpoints));
	local_endpoints = g_list_append(local_endpoints, ep);

	if (!strcmp(ep->uuid, BCAA_SERVICE_UUID) ||
		!strcmp(ep->uuid, BAA_SERVICE_UUID)) {
		ep->broadcast = true;
	} else {
		ep->broadcast = false;
	}

	if (strrchr(argv[2], ':')) {
		ep->codec = 0xff;
		parse_vendor_codec(argv[2], &ep->vid, &ep->cid);
		ep->preset = new0(struct preset, 1);
		ep->preset->default_preset = codec_preset_add(ep->preset,
								"custom");
	} else {
		ep->preset = find_presets_name(ep->uuid, argv[2]);
	}

	if (argc > 3)
		endpoint_set_capabilities(argv[3], ep);
	else {
		const struct capabilities *cap;

		cap = find_capabilities(ep->uuid, ep->codec);
		if (cap) {
			/* Copy capabilities */
			util_iov_free(ep->caps, 1);
			ep->caps = util_iov_dup(&cap->data, 1);

			/* Copy metadata */
			util_iov_free(ep->meta, 1);
			ep->meta = util_iov_dup(&cap->meta, 1);

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

	ep->refcount--;

	if (ep->refcount == 0) {
		local_endpoints = g_list_remove(local_endpoints, ep);
		g_dbus_unregister_interface(dbus_conn, ep->path,
					    BLUEZ_MEDIA_ENDPOINT_INTERFACE);
	}

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

	util_iov_append(cfg->caps, data, len);
	free(data);

	endpoint_set_config(cfg);
}

static struct endpoint *endpoint_new(const struct capabilities *cap);

static void endpoint_set_metadata_cfg(const char *input, void *user_data)
{
	struct endpoint_config *cfg = user_data;

	if (!strcasecmp(input, "n") || !strcasecmp(input, "no"))
		goto done;

	if (!cfg->meta)
		cfg->meta = g_new0(struct iovec, 1);

	cfg->meta->iov_base = str2bytearray((char *) input,
				&cfg->meta->iov_len);
	if (!cfg->meta->iov_base) {
		free(cfg->meta);
		cfg->meta = NULL;
	}

done:
	endpoint_set_config(cfg);
}

static void config_endpoint_channel_location(const char *input, void *user_data)
{
	struct endpoint_config *cfg = user_data;
	char *endptr = NULL;
	uint32_t location;
	uint8_t channels = 1;

	if (!strcasecmp(input, "n") || !strcasecmp(input, "no"))
		goto add_meta;

	location = strtol(input, &endptr, 0);

	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	/* Add Channel Allocation LTV in capabilities */
	location = cpu_to_le32(location);
	util_ltv_push(cfg->caps, LC3_CONFIG_CHAN_ALLOC_LEN - 1,
			LC3_CONFIG_CHAN_ALLOC, &location);

	/* Adjust the SDU size based on the number of
	 * locations/channels that is being requested.
	 */
	channels = __builtin_popcount(location);
	if (channels > 1)
		cfg->qos.bcast.io_qos.sdu *= channels;

add_meta:
	/* Add metadata */
	bt_shell_prompt_input(cfg->ep->path, "Enter Metadata (value/no):",
			endpoint_set_metadata_cfg, cfg);
}

static void config_endpoint_sync_factor(const char *input, void *user_data)
{
	struct endpoint_config *cfg = user_data;
	char *endptr = NULL;
	int value;
	uint8_t type = LC3_CONFIG_CHAN_ALLOC;
	bool found = false;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		cfg->qos.bcast.sync_factor = BT_ISO_SYNC_FACTOR;
	} else {
		value = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0' || value > UINT8_MAX) {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		cfg->qos.bcast.sync_factor = value;
	}

	/* Check if Channel Allocation is present in caps */
	util_ltv_foreach(cfg->caps->iov_base,
			cfg->caps->iov_len, &type,
			ltv_find, &found);

	/* Add Channel Allocation if it is not present in caps */
	if (!found) {
		bt_shell_prompt_input(cfg->ep->path,
				"Enter channel location (value/no):",
				config_endpoint_channel_location, cfg);
	} else {
		/* Add metadata */
		bt_shell_prompt_input(cfg->ep->path,
				"Enter Metadata (value/no):",
				endpoint_set_metadata_cfg, cfg);
	}
}

static void config_endpoint_iso_stream(const char *input, void *user_data)
{
	struct endpoint_config *cfg = user_data;
	char *endptr = NULL;
	int value;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		cfg->ep->iso_stream = BT_ISO_QOS_STREAM_UNSET;
	} else {
		value = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0' || value > UINT8_MAX) {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		cfg->ep->iso_stream = value;
	}

	bt_shell_prompt_input(cfg->ep->path,
			"Enter sync factor (value/auto):",
			config_endpoint_sync_factor, cfg);
}

static void config_endpoint_iso_group(const char *input, void *user_data)
{
	struct endpoint_config *cfg = user_data;
	char *endptr = NULL;
	int value;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		cfg->ep->iso_group = BT_ISO_QOS_GROUP_UNSET;
	} else {
		value = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0' || value > UINT8_MAX) {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		cfg->ep->iso_group = value;
	}

	bt_shell_prompt_input(cfg->ep->path,
		"BIS (auto/value):",
		config_endpoint_iso_stream, cfg);
}

static void endpoint_set_config_bcast(struct endpoint_config *cfg)
{
	cfg->ep->bcode = g_new0(struct iovec, 1);
	util_iov_append(cfg->ep->bcode, bcast_code,
			sizeof(bcast_code));

	if ((strcmp(cfg->ep->uuid, BAA_SERVICE_UUID) == 0)) {
		/* A broadcast sink endpoint config does not need
		 * user input.
		 */
		endpoint_set_config(cfg);
		return;
	}

	bt_shell_prompt_input(cfg->ep->path,
		"BIG (auto/value):",
		config_endpoint_iso_group, cfg);
}

static void cmd_config_endpoint(int argc, char *argv[])
{
	struct endpoint_config *cfg;
	const struct codec_preset *preset;

	cfg = new0(struct endpoint_config, 1);

	/* Search for the remote endpoint name on DBUS */
	cfg->proxy = g_dbus_proxy_lookup(endpoints, NULL, argv[1],
						BLUEZ_MEDIA_ENDPOINT_INTERFACE);
	if (!cfg->proxy) {
		bt_shell_printf("Endpoint %s not found\n", argv[1]);
		goto fail;
	}

	/* Search for the local endpoint */
	cfg->ep = endpoint_find(argv[2]);
	if (!cfg->ep) {
		bt_shell_printf("Local Endpoint %s not found\n", argv[2]);
		goto fail;
	}

	if (argc > 3) {
		preset = preset_find_name(cfg->ep->preset, argv[3]);
		if (!preset) {
			bt_shell_printf("Preset %s not found\n", argv[3]);
			goto fail;
		}

		cfg->caps = g_new0(struct iovec, 1);
		/* Copy capabilities */
		util_iov_append(cfg->caps, preset->data.iov_base,
				preset->data.iov_len);
		cfg->target_latency = preset->target_latency;

		/* Set QoS parameters */
		cfg->qos = preset->qos;

		if (cfg->ep->broadcast)
			endpoint_set_config_bcast(cfg);
		else
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

static void custom_metadata(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct iovec *meta = (void *)&p->meta;

	if (!strcasecmp(input, "n") || !strcasecmp(input, "no"))
		goto done;

	meta->iov_base = str2bytearray((void *)input, &meta->iov_len);
	if (!meta->iov_base) {
		bt_shell_printf("Invalid metadata %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

done:
	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void custom_delay(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct bt_bap_qos *qos = (void *)&p->qos;
	char *endptr = NULL;

	if (!p->target_latency)
		qos->bcast.delay = strtol(input, &endptr, 0);
	else
		qos->ucast.delay = strtol(input, &endptr, 0);

	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_prompt_input("Metadata", "Enter Metadata (value/no):",
				custom_metadata, user_data);
}

static void custom_latency(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct bt_bap_qos *qos = (void *)&p->qos;
	char *endptr = NULL;

	if (!p->target_latency)
		qos->bcast.io_qos.latency = strtol(input, &endptr, 0);
	else
		qos->ucast.io_qos.latency = strtol(input, &endptr, 0);

	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_prompt_input("QoS", "Enter Presentation Delay (us):",
					custom_delay, user_data);
}

static void custom_rtn(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct bt_bap_qos *qos = (void *)&p->qos;
	char *endptr = NULL;

	if (!p->target_latency)
		qos->bcast.io_qos.rtn = strtol(input, &endptr, 0);
	else
		qos->ucast.io_qos.rtn = strtol(input, &endptr, 0);

	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_prompt_input("QoS", "Enter Max Transport Latency (ms):",
					custom_latency, user_data);
}

static void custom_sdu(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct bt_bap_qos *qos = (void *)&p->qos;
	char *endptr = NULL;

	if (!p->target_latency)
		qos->bcast.io_qos.sdu = strtol(input, &endptr, 0);
	else
		qos->ucast.io_qos.sdu = strtol(input, &endptr, 0);

	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_prompt_input("QoS", "Enter RTN:", custom_rtn, user_data);
}

static void custom_phy(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct bt_bap_io_qos *qos;

	if (!p->target_latency)
		qos = &p->qos.bcast.io_qos;
	else
		qos = &p->qos.ucast.io_qos;

	if (!strcmp(input, "1M"))
		qos->phy = 0x01;
	else if (!strcmp(input, "2M"))
		qos->phy = 0x02;
	else {
		char *endptr = NULL;
		uint8_t phy = strtol(input, &endptr, 0);

		if (!endptr || *endptr != '\0') {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		switch (phy) {
		case 0x01:
		case 0x02:
			qos->phy = phy;
			break;
		default:
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	bt_shell_prompt_input("QoS", "Enter Max SDU:", custom_sdu, user_data);
}

static void custom_framing(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	uint8_t *framing;

	if (!p->target_latency)
		framing = &p->qos.bcast.framing;
	else
		framing = &p->qos.ucast.framing;

	if (!strcasecmp(input, "Unframed"))
		*framing = 0x00;
	else if (!strcasecmp(input, "Framed"))
		*framing = 0x01;
	else {
		char *endptr = NULL;

		*framing = strtol(input, &endptr, 0);
		if (!endptr || *endptr != '\0') {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	bt_shell_prompt_input("QoS", "Enter PHY (1M, 2M):", custom_phy,
							user_data);
}

static void custom_interval(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	char *endptr = NULL;
	struct bt_bap_io_qos *qos;

	if (!p->target_latency)
		qos = &p->qos.bcast.io_qos;
	else
		qos = &p->qos.ucast.io_qos;

	qos->interval = strtol(input, &endptr, 0);
	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_prompt_input("QoS", "Enter Framing (Unframed, Framed):",
				custom_framing, user_data);
}

static void custom_target_latency(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;

	if (!strcasecmp(input, "Low"))
		p->target_latency = 0x01;
	else if (!strcasecmp(input, "Balance"))
		p->target_latency = 0x02;
	else if (!strcasecmp(input, "High"))
		p->target_latency = 0x03;
	else {
		char *endptr = NULL;

		p->target_latency = strtol(input, &endptr, 0);
		if (!endptr || *endptr != '\0') {
			bt_shell_printf("Invalid argument: %s\n", input);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	bt_shell_prompt_input("QoS", "Enter SDU Interval (us):",
					custom_interval, user_data);
}

static void custom_length(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct iovec *iov = (void *)&p->data;
	uint8_t ltv[4] = { 0x03, LC3_CONFIG_FRAME_LEN };
	uint16_t len;
	char *endptr = NULL;

	len = strtol(input, &endptr, 0);
	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	ltv[2] = len;
	ltv[3] = len >> 8;

	util_iov_append(iov, ltv, sizeof(ltv));

	bt_shell_prompt_input("QoS", "Enter Target Latency "
				"(Low, Balance, High):",
				custom_target_latency, user_data);
}

static void custom_location(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct iovec *iov = (void *)&p->data;
	uint32_t location;
	char *endptr = NULL;

	location = strtol(input, &endptr, 0);
	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	/* Only add Channel Allocation if set */
	if (location) {
		uint8_t ltv[6] = { 0x05, LC3_CONFIG_CHAN_ALLOC };

		location = cpu_to_le32(location);
		memcpy(&ltv[2], &location, sizeof(location));
		util_iov_append(iov, ltv, sizeof(ltv));
	}

	bt_shell_prompt_input("Codec", "Enter frame length:",
					custom_length, user_data);
}

static uint8_t val2duration(uint32_t val)
{
	switch (val) {
	case 7:
		return 0x00;
	case 10:
		return 0x01;
	default:
		return 0xff;
	}
}

static void custom_duration(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct iovec *iov = (void *)&p->data;
	uint8_t ltv[3] = { 0x02, LC3_CONFIG_DURATION, 0x00 };
	char *endptr = NULL;
	uint32_t val;

	val = strtol(input, &endptr, 0);
	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (strncmp(input, "0x", 2))
		ltv[2] = val2duration(val);
	else
		ltv[2] = val;

	if (ltv[2] == 0xff) {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	util_iov_append(iov, ltv, sizeof(ltv));

	bt_shell_prompt_input("Codec", "Enter channel allocation:",
					custom_location, user_data);
}

static uint8_t val2freq(uint32_t val)
{
	switch (val) {
	case 8:
		return 0x01;
	case 11:
		return 0x02;
	case 16:
		return 0x03;
	case 22:
		return 0x04;
	case 24:
		return 0x05;
	case 32:
		return 0x06;
	case 44:
		return 0x07;
	case 48:
		return 0x08;
	case 88:
		return 0x09;
	case 96:
		return 0x0a;
	case 174:
		return 0x0b;
	case 192:
		return 0x0c;
	case 384:
		return 0x0d;
	default:
		return 0x00;
	}
}

static void custom_frequency(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	struct iovec *iov = (void *)&p->data;
	uint8_t ltv[3] = { 0x02, LC3_CONFIG_FREQ, 0x00 };
	uint32_t val;
	char *endptr = NULL;

	val = strtol(input, &endptr, 0);
	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (strncmp(input, "0x", 2))
		ltv[2] = val2freq(val);
	else
		ltv[2] = val;

	if (!ltv[2]) {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	/* Reset iov to start over the codec configuration */
	free(iov->iov_base);
	iov->iov_base = NULL;
	iov->iov_len = 0;
	util_iov_append(iov, ltv, sizeof(ltv));

	bt_shell_prompt_input("Codec", "Enter frame duration (ms):",
				custom_duration, user_data);
}

static void foreach_custom_preset_print(void *data, void *user_data)
{
	struct codec_preset *p = data;
	struct preset *preset = user_data;

	bt_shell_printf("%s%s\n", p == preset->default_preset ? "*" : "",
				p->name);
}

static void print_presets(struct preset *preset)
{
	size_t i;
	struct codec_preset *p;

	for (i = 0; i < preset->num_presets; i++) {
		p = &preset->presets[i];

		if (p == preset->default_preset)
			bt_shell_printf("*%s\n", p->name);
		else if (preset->default_preset &&
					p == preset->default_preset->alt_preset)
			bt_shell_printf("**%s\n", p->name);
		else
			bt_shell_printf("%s\n", p->name);
	}

	queue_foreach(preset->custom, foreach_custom_preset_print, preset);
}

static void custom_chan_alloc(const char *input, void *user_data)
{
	struct codec_preset *p = user_data;
	char *endptr = NULL;

	p->chan_alloc = strtol(input, &endptr, 0);
	if (!endptr || *endptr != '\0') {
		bt_shell_printf("Invalid argument: %s\n", input);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (p->alt_preset)
		bt_shell_prompt_input(p->alt_preset->name,
					"Enter Channel Allocation: ",
					custom_chan_alloc, p->alt_preset);
	else
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_presets_endpoint(int argc, char *argv[])
{
	struct preset *preset;
	struct codec_preset *default_preset = NULL;
	struct endpoint *ep = NULL;

	preset = find_presets_name(argv[1], argv[2]);
	if (!preset) {
		ep = endpoint_find(argv[1]);
		if (!ep) {
			bt_shell_printf("No preset found\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
		preset = ep->preset;
		argv++;
		argc--;
	} else {
		argv += 2;
		argc -= 2;
	}

	if (argc > 1) {
		default_preset = codec_preset_add(preset, argv[1]);
		if (!default_preset) {
			bt_shell_printf("Preset %s not found\n", argv[1]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		if (ep)
			ep->codec_preset = default_preset;
		else
			preset->default_preset = default_preset;

		if (argc > 2) {
			struct codec_preset *alt_preset;
			struct iovec *caps = (void *)&default_preset->data;
			struct iovec *meta = (void *)&default_preset->meta;

			/* Check if and alternative preset was given */
			alt_preset = preset_find_name(preset, argv[2]);
			if (alt_preset) {
				default_preset->alt_preset = alt_preset;
				bt_shell_prompt_input(default_preset->name,
						"Enter Channel Allocation: ",
						custom_chan_alloc,
						default_preset);
				return;
			}

			/* Check if Codec Configuration was entered */
			if (strlen(argv[2])) {
				caps->iov_base = str2bytearray(argv[2],
							      &caps->iov_len);
				if (!caps->iov_base) {
					bt_shell_printf("Invalid configuration "
								"%s\n",
								argv[2]);
					return bt_shell_noninteractive_quit(
								EXIT_FAILURE);
				}
			}

			/* Check if metadata was entered */
			if (argc > 3) {
				meta->iov_base = str2bytearray(argv[3],
								&meta->iov_len);
				if (!meta->iov_base) {
					bt_shell_printf("Invalid metadata %s\n",
							argv[5]);
					return bt_shell_noninteractive_quit(
								EXIT_FAILURE);
				}
			}

			/* If configuration was left empty then ask the
			 * parameters.
			 */
			if (!caps->iov_base || !caps->iov_len)
				goto enter_cc;

			bt_shell_prompt_input("QoS", "Enter Target Latency "
						"(Low, Balance, High):",
						custom_target_latency,
						default_preset);

			return;
		}
	} else if (ep && (ep->codec_preset))
		print_preset(ep->codec_preset, ep->codec);
	else
		print_presets(preset);

enter_cc:
	if (default_preset && default_preset->custom) {
		bt_shell_prompt_input("Codec", "Enter frequency (Khz):",
					custom_frequency, default_preset);
		return;
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static const struct bt_shell_menu endpoint_menu = {
	.name = "endpoint",
	.desc = "Media Endpoint Submenu",
	.entries = {
	{ "list",         "[local]",    cmd_list_endpoints,
						"List available endpoints" },
	{ "show",         "[endpoint]", cmd_show_endpoint,
						"Endpoint information",
						endpoint_generator },
	{ "register",     "<UUID> <codec[:company]> [capabilities...]",
						cmd_register_endpoint,
						"Register Endpoint",
						uuid_generator },
	{ "unregister",   "<UUID/object>", cmd_unregister_endpoint,
						"Register Endpoint",
						local_endpoint_generator },
	{ "config",       "<endpoint> [local endpoint] [preset]",
						cmd_config_endpoint,
						"Configure Endpoint",
						endpoint_generator },
	{ "presets",      "<endpoint>/<UUID> [codec[:company]] [preset] "
						"[codec config] [metadata]",
						cmd_presets_endpoint,
						"List or add presets",
						uuid_generator },
	{} },
};

static void endpoint_init_bcast(struct endpoint *ep)
{
	if (!strcmp(ep->uuid, BAA_SERVICE_UUID)) {
		ep->locations = EP_SNK_LOCATIONS;
		ep->supported_context = EP_SUPPORTED_SNK_CTXT;
	} else {
		ep->locations = EP_SRC_LOCATIONS;
		ep->supported_context = EP_SUPPORTED_SRC_CTXT;
	}
}

static void endpoint_init_ucast(struct endpoint *ep)
{
	if (!strcmp(ep->uuid, PAC_SINK_UUID)) {
		ep->locations = EP_SNK_LOCATIONS;
		ep->supported_context = EP_SUPPORTED_SNK_CTXT;
		ep->context = EP_SNK_CTXT;
	} else if (!strcmp(ep->uuid, PAC_SOURCE_UUID)) {
		ep->locations = EP_SRC_LOCATIONS;
		ep->supported_context = EP_SUPPORTED_SRC_CTXT;
		ep->context = EP_SRC_CTXT;
	}
}

static void endpoint_init_defaults(struct endpoint *ep)
{
	ep->preset = find_presets(ep->uuid, ep->codec, ep->vid, ep->cid);
	ep->max_transports = UINT8_MAX;
	ep->auto_accept = true;

	if (!strcmp(ep->uuid, A2DP_SOURCE_UUID) ||
			!strcmp(ep->uuid, A2DP_SOURCE_UUID))
		return;

	ep->iso_group = BT_ISO_QOS_GROUP_UNSET;
	ep->iso_stream = BT_ISO_QOS_STREAM_UNSET;

	ep->broadcast = (strcmp(ep->uuid, BCAA_SERVICE_UUID) &&
			strcmp(ep->uuid, BAA_SERVICE_UUID)) ? false : true;

	if (ep->broadcast)
		endpoint_init_bcast(ep);
	else
		endpoint_init_ucast(ep);
}

static struct endpoint *endpoint_new(const struct capabilities *cap)
{
	struct endpoint *ep;

	ep = new0(struct endpoint, 1);
	ep->uuid = g_strdup(cap->uuid);
	ep->codec = cap->codec_id;
	ep->path = g_strdup_printf("%s/%s", BLUEZ_MEDIA_ENDPOINT_PATH,
				cap->name);
	/* Copy capabilities */
	ep->caps = util_iov_dup(&cap->data, 1);
	/* Copy metadata */
	ep->meta = util_iov_dup(&cap->meta, 1);

	local_endpoints = g_list_append(local_endpoints, ep);

	return ep;
}

static void register_endpoints(GDBusProxy *proxy)
{
	struct endpoint *ep;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(caps); i++) {
		const struct capabilities *cap = &caps[i];

		if (!media_supports_uuid(proxy, cap->uuid))
			continue;

		ep = endpoint_new(cap);
		endpoint_init_defaults(ep);
		endpoint_register(ep);
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

		if (queue_find(ep->transports, match_str, path))
			return ep;
	}

	return NULL;
}

static GDBusProxy *find_link_by_proxy(GDBusProxy *proxy)
{
	DBusMessageIter iter, array;

	if (!g_dbus_proxy_get_property(proxy, "Links", &iter))
		return NULL;

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) ==
				DBUS_TYPE_OBJECT_PATH) {
		const char *transport;

		dbus_message_iter_get_basic(&array, &transport);

		proxy = g_dbus_proxy_lookup(transports, NULL, transport,
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
		if (proxy)
			return proxy;
	}

	return NULL;
}

static void transport_close(struct transport *transport)
{
	if (transport->fd < 0)
		return;

	close(transport->fd);
	transport->fd = -1;

	free(transport->filename);
}

static void transport_free(void *data)
{
	struct transport *transport = data;

	io_destroy(transport->timer_io);
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

	ret = io_get_fd(io);
	if (ret < 0) {
		bt_shell_printf("io_get_fd() returned %d\n", ret);
		return true;
	}

	ret = read(ret, buf, sizeof(buf));
	if (ret < 0) {
		bt_shell_printf("Failed to read: %s (%d)\n", strerror(errno),
								-errno);
		return true;
	}

	bt_shell_echo("[seq %d] recv: %u bytes", transport->seq, ret);

	transport->seq++;

	if (transport->filename) {
		len = write(transport->fd, buf, ret);
		if (len < 0)
			bt_shell_printf("Unable to write: %s (%d)\n",
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

static void ep_set_acquiring(struct endpoint *ep, GDBusProxy *proxy, bool value)
{
	bt_shell_printf("Transport %s %s\n", g_dbus_proxy_get_path(proxy),
			value ? "acquiring" : "acquiring complete");

	if (value && !ep->acquiring)
		ep->acquiring = queue_new();

	if (value)
		queue_push_tail(ep->acquiring, proxy);
	else
		queue_remove(ep->acquiring, proxy);
}

static void transport_set_acquiring(GDBusProxy *proxy, bool value)
{
	struct endpoint *ep;
	GDBusProxy *link;

	ep = find_ep_by_transport(g_dbus_proxy_get_path(proxy));
	if (!ep)
		return;

	ep_set_acquiring(ep, proxy, value);

	if (!ep->broadcast) {
		link = find_link_by_proxy(proxy);
		if (link) {
			ep = find_ep_by_transport(g_dbus_proxy_get_path(link));
			if (!ep)
				return;

			ep_set_acquiring(ep, link, value);
		}
	}
}

static void acquire_reply(DBusMessage *message, void *user_data)
{
	GDBusProxy *proxy = user_data;
	DBusError error;
	int sk;
	uint16_t mtu[2];

	transport_set_acquiring(proxy, false);

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

static void free_transport_select_args(struct transport_select_args *args)
{
	queue_destroy(args->links, NULL);
	queue_destroy(args->selecting, NULL);
	g_free(args);
}

static void select_reply(DBusMessage *message, void *user_data)
{
	DBusError error;
	struct transport_select_args *args = user_data;
	GDBusProxy *link;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to select: %s\n", error.name);
		dbus_error_free(&error);
		free_transport_select_args(args);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Select successful\n");

	/* Select next link */
	link = queue_pop_head(args->selecting);
	if (link) {
		args->proxy = link;
		transport_select(args);
	} else {
		free_transport_select_args(args);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}
}

static void unselect_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to unselect: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Unselect successful\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}


static void prompt_acquire(const char *input, void *user_data)
{
	GDBusProxy *proxy = user_data;

	if (!strcasecmp(input, "y") || !strcasecmp(input, "yes")) {
		if (g_dbus_proxy_method_call(proxy, "Acquire", NULL,
						acquire_reply, proxy, NULL)) {
			transport_set_acquiring(proxy, true);
			return;
		}
		bt_shell_printf("Failed acquire transport\n");
	}
}

static void transport_acquire(GDBusProxy *proxy, bool prompt)
{
	struct endpoint *ep;
	GDBusProxy *link;

	/* only attempt to acquire if transport is configured with a local
	 * endpoint.
	 */
	ep = find_ep_by_transport(g_dbus_proxy_get_path(proxy));
	if (!ep) {
		bt_shell_printf("transport endpoint not found\n");
		return;
	}

	if (queue_find(ep->acquiring, NULL, proxy)) {
		bt_shell_printf("acquire already in progress\n");
		return;
	}

	if (!ep->broadcast) {
		link = find_link_by_proxy(proxy);
		if (link) {
			ep = find_ep_by_transport(g_dbus_proxy_get_path(link));
			/* if link already acquiring wait it to be complete */
			if (!ep || queue_find(ep->acquiring, NULL, link))
				return;
		}
	}

	if (ep->auto_accept || !prompt) {
		if (!prompt)
			bt_shell_printf("auto acquiring...\n");
		if (!g_dbus_proxy_method_call(proxy, "Acquire", NULL,
						acquire_reply, proxy, NULL)) {
			bt_shell_printf("failed acquire transport\n");
			return;
		}

		transport_set_acquiring(proxy, true);
		return;
	}

	bt_shell_prompt_input(g_dbus_proxy_get_path(proxy), "acquire (yes/no):",
					prompt_acquire, proxy);
}

static void transport_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Transport", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);

	if (strcmp(name, "State"))
		return;

	dbus_message_iter_get_basic(iter, &str);

	if (!strcmp(str, "pending") || !strcmp(str, "broadcasting"))
		transport_acquire(proxy, !auto_acquire);
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

static void print_configuration(GDBusProxy *proxy)
{
	DBusMessageIter iter, subiter;
	const char *uuid;
	uint8_t codec;
	uint8_t *data;
	int len;

	if (!g_dbus_proxy_get_property(proxy, "UUID", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &uuid);

	if (!g_dbus_proxy_get_property(proxy, "Codec", &iter))
		return;

	dbus_message_iter_get_basic(&iter, &codec);

	if (!g_dbus_proxy_get_property(proxy, "Configuration", &iter))
		return;

	dbus_message_iter_recurse(&iter, &subiter);

	dbus_message_iter_get_fixed_array(&subiter, &data, &len);

	if (!strcasecmp(uuid, A2DP_SINK_UUID) ||
			!strcasecmp(uuid, A2DP_SOURCE_UUID)) {
		print_a2dp_codec(codec, (void *)data, len);
		return;
	}

	if (codec != LC3_ID) {
		print_property(proxy, "Configuration");
		return;
	}

	print_lc3_cfg(data, len);

	if (!g_dbus_proxy_get_property(proxy, "Metadata", &iter))
		return;

	dbus_message_iter_recurse(&iter, &subiter);

	dbus_message_iter_get_fixed_array(&subiter, &data, &len);

	print_lc3_meta(data, len);
}

static void print_transport_properties(GDBusProxy *proxy)
{
	bt_shell_printf("Transport %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "UUID");
	print_property(proxy, "Codec");
	print_configuration(proxy);
	print_property(proxy, "Device");
	print_property(proxy, "State");
	print_property(proxy, "Delay");
	print_property(proxy, "Volume");
	print_property(proxy, "Endpoint");
	print_property(proxy, "QoS");
	print_property(proxy, "Location");
	print_property(proxy, "Links");
}

static void print_transports(void *data, void *user_data)
{
	print_transport_properties(data);
}

static void cmd_show_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;

	/* Show all transports if no argument is given */
	if (argc != 2) {
		g_list_foreach(transports, print_transports, NULL);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	proxy = g_dbus_proxy_lookup(transports, NULL, argv[1],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Transport %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	print_transport_properties(proxy);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_acquire_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;
	int i;

	if (argc == 2 && !strcmp(argv[1], "auto")) {
		auto_acquire = true;
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

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

		transport_acquire(proxy, false);
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void set_bcode_cb(const DBusError *error, void *user_data)
{
	struct transport_select_args *args = user_data;

	if (dbus_error_is_set(error)) {
		bt_shell_printf("Failed to set broadcast code: %s\n",
								error->name);
		free_transport_select_args(args);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Setting broadcast code succeeded\n");

	transport_select(args);
}

static void set_bcode(const char *input, void *user_data)
{
	struct transport_select_args *args = user_data;
	uint8_t *bcode = NULL;
	size_t len = 0;

	if (!strcasecmp(input, "n") || !strcasecmp(input, "no"))
		bcode = g_new0(uint8_t, 16);
	else {
		bcode = str2bytearray((char *) input, &len);
		/* If the input is not 16 bytes, perhaps it was entered as
		 * string so just use it instead.
		 */
		if (len != 16) {
			bcode = (uint8_t *)strdup(input);
			len = strlen(input);
		}
	}

	if (g_dbus_proxy_set_property_dict(args->proxy, "QoS",
				set_bcode_cb, user_data,
				NULL, "BCode", DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				len, bcode, NULL) == FALSE) {
		bt_shell_printf("Setting broadcast code failed\n");
		g_free(bcode);
		free_transport_select_args(args);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	g_free(bcode);
}

static void transport_select(struct transport_select_args *args)
{
	if (!g_dbus_proxy_method_call(args->proxy, "Select", NULL,
					select_reply, args, NULL)) {
		bt_shell_printf("Failed select transport\n");
		free_transport_select_args(args);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static void transport_set_bcode(struct transport_select_args *args)
{
	DBusMessageIter iter, array;
	unsigned char encryption = 0;
	const char *key;
	uint8_t *bcode, zeroed_bcode[16] = {};
	int bcode_len = 0;

	if (g_dbus_proxy_get_property(args->proxy, "QoS", &iter) == FALSE) {
		free_transport_select_args(args);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) !=
						DBUS_TYPE_INVALID) {
		DBusMessageIter entry, value, array_value;
		int var;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		var = dbus_message_iter_get_arg_type(&value);

		if (!strcasecmp(key, "Encryption")) {
			if (var != DBUS_TYPE_BYTE)
				break;

			dbus_message_iter_get_basic(&value, &encryption);
		} else if (!strcasecmp(key, "BCode")) {
			if (var != DBUS_TYPE_ARRAY)
				break;

			dbus_message_iter_recurse(&value, &array_value);
			dbus_message_iter_get_fixed_array(&array_value, &bcode,
								&bcode_len);

			if (bcode_len != 16 || !memcmp(bcode, zeroed_bcode, 16))
				bcode_len = 0;
		}

		dbus_message_iter_next(&array);
	}

	/* Only attempt to set bcode if encryption is enabled and
	 * bcode is not already set.
	 */
	if (encryption == 1 && !bcode_len) {
		const char *path = g_dbus_proxy_get_path(args->proxy);

		bt_shell_prompt_input(path, "Enter bcode[value/no]:",
					set_bcode, args);
		return;
	}

	/* Go straight to selecting transport, if Broadcast Code
	 * is not required.
	 */
	transport_select(args);
}

static void transport_unselect(GDBusProxy *proxy, bool prompt)
{
	if (!g_dbus_proxy_method_call(proxy, "Unselect", NULL,
					unselect_reply, proxy, NULL)) {
		bt_shell_printf("Failed unselect transport\n");
		return;
	}
}

static void set_links_cb(const DBusError *error, void *user_data)
{
	struct transport_select_args *args = user_data;
	GDBusProxy *link;

	link = queue_pop_head(args->links);

	if (queue_isempty(args->links)) {
		queue_destroy(args->links, NULL);
		args->links = NULL;
	}

	if (dbus_error_is_set(error)) {
		bt_shell_printf("Failed to set link %s: %s\n",
						g_dbus_proxy_get_path(link),
						error->name);
		free_transport_select_args(args);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Successfully linked transport %s\n",
						g_dbus_proxy_get_path(link));

	if (!args->selecting)
		args->selecting = queue_new();

	/* Enqueue link to mark that it is ready to be selected */
	queue_push_tail(args->selecting, link);

	/* Continue setting the remaining links */
	transport_set_links(args);
}

static void transport_set_links(struct transport_select_args *args)
{
	GDBusProxy *link;
	const char *path;

	link = queue_peek_head(args->links);
	if (link) {
		path = g_dbus_proxy_get_path(link);

		if (g_dbus_proxy_set_property_array(args->proxy, "Links",
					DBUS_TYPE_OBJECT_PATH,
					&path, 1, set_links_cb,
					args, NULL) == FALSE) {
			bt_shell_printf("Linking transport %s failed\n", path);
			free_transport_select_args(args);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		return;
	}

	/* If all links have been set, check is transport requires the
	 * user to provide a Broadcast Code.
	 */
	transport_set_bcode(args);
}

static void cmd_select_transport(int argc, char *argv[])
{
	GDBusProxy *link = NULL;
	struct transport_select_args *args;
	int i;

	if (argc == 2 && !strcmp(argv[1], "auto")) {
		auto_select = true;
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	args = g_new0(struct transport_select_args, 1);

	for (i = 1; i < argc; i++) {
		link = g_dbus_proxy_lookup(transports, NULL, argv[i],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
		if (!link) {
			bt_shell_printf("Transport %s not found\n", argv[i]);
			goto fail;
		}

		if (find_transport(link)) {
			bt_shell_printf("Transport %s already acquired\n",
					argv[i]);
			goto fail;
		}

		if (!args->proxy) {
			args->proxy = link;
			continue;
		}

		if (!args->links)
			args->links = queue_new();

		/* Enqueue all links */
		queue_push_tail(args->links, link);
	}

	/* Link streams before selecting one by one */
	transport_set_links(args);

	return;

fail:
	free_transport_select_args(args);
	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_unselect_transport(int argc, char *argv[])
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

		transport_unselect(proxy, false);
	}
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

static int elapsed_time(bool reset, int *secs, int *nsecs)
{
	static struct timespec start;
	struct timespec curr;

	if (reset) {
		if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
			bt_shell_printf("clock_gettime: %s (%d)",
						strerror(errno), errno);
			return -errno;
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &curr) < 0) {
		bt_shell_printf("clock_gettime: %s (%d)", strerror(errno),
						errno);
		return -errno;
	}

	*secs = curr.tv_sec - start.tv_sec;
	*nsecs = curr.tv_nsec - start.tv_nsec;
	if (*nsecs < 0) {
		(*secs)--;
		*nsecs += 1000000000;
	}

	return 0;
}

static int transport_send_seq(struct transport *transport, int fd, uint32_t num)
{
	uint8_t *buf;
	uint32_t i;

	if (!num)
		return 0;

	buf = malloc(transport->mtu[1]);
	if (!buf)
		return -ENOMEM;

	for (i = 0; i < num; i++, transport->seq++) {
		ssize_t ret;
		int secs = 0, nsecs = 0;
		off_t offset;

		ret = read(fd, buf, transport->mtu[1]);
		if (ret <= 0) {
			if (ret < 0)
				bt_shell_printf("read failed: %s (%d)",
						strerror(errno), errno);
			free(buf);
			return ret;
		}

		ret = send(transport->sk, buf, ret, 0);
		if (ret <= 0) {
			bt_shell_printf("send failed: %s (%d)",
							strerror(errno), errno);
			free(buf);
			return -errno;
		}

		elapsed_time(!transport->seq, &secs, &nsecs);

		if (!transport->seq && fstat(fd, &transport->stat) < 0) {
			bt_shell_printf("fstat failed: %s (%d)",
							strerror(errno), errno);
			free(buf);
			return -errno;
		}

		offset = lseek(fd, 0, SEEK_CUR);

		bt_shell_echo("[seq %d %d.%03ds] send: %lld/%lld bytes",
				transport->seq, secs,
				(nsecs + 500000) / 1000000,
				(long long)offset,
				(long long)transport->stat.st_size);
	}

	free(buf);

	return i;
}

static bool transport_timer_read(struct io *io, void *user_data)
{
	struct transport *transport = user_data;
	struct bt_iso_qos qos;
	socklen_t len;
	int ret, fd;
	uint64_t exp;

	if (transport->fd < 0)
		return false;

	fd = io_get_fd(io);
	if (fd < 0) {
		bt_shell_printf("io_get_fd() returned %d\n", fd);
		return false;
	}

	ret = read(fd, &exp, sizeof(exp));
	if (ret < 0) {
		bt_shell_printf("Failed to read: %s (%d)\n", strerror(errno),
								-errno);
		return false;
	}

	/* Read QoS if available */
	memset(&qos, 0, sizeof(qos));
	len = sizeof(qos);
	if (getsockopt(transport->sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos,
							&len) < 0) {
		bt_shell_printf("Failed to getsockopt(BT_ISO_QOS): %s (%d)\n",
					strerror(errno), -errno);
		return false;
	}

	ret = transport_send_seq(transport, transport->fd, transport->num);
	if (ret < 0) {
		bt_shell_printf("Unable to send: %s (%d)\n",
					strerror(-ret), ret);
		return false;
	}

	if (!ret) {
		transport_close(transport);
		return false;
	}

	return true;
}

static int transport_send(struct transport *transport, int fd,
					struct bt_iso_io_qos *qos)
{
	struct itimerspec ts;
	int timer_fd;

	transport->seq = 0;

	if (!qos)
		return transport_send_seq(transport, fd, UINT32_MAX);

	if (transport->fd >= 0)
		return -EALREADY;

	timer_fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (timer_fd < 0)
		return -errno;

	/* Send data in bursts of
	 * num = ROUND_CLOSEST(Transport_Latency (ms) / SDU_Interval (us))
	 * with average data rate = 1 packet / SDU_Interval
	 */
	transport->num = ROUND_CLOSEST(qos->latency * 1000, qos->interval);
	if (!transport->num)
		transport->num = 1;

	memset(&ts, 0, sizeof(ts));
	ts.it_value.tv_nsec = 1;
	ts.it_interval.tv_nsec = transport->num * qos->interval * 1000;

	if (timerfd_settime(timer_fd, TFD_TIMER_ABSTIME, &ts, NULL) < 0) {
		close(timer_fd);
		return -errno;
	}

	transport->fd = fd;
	transport->timer_io = io_new(timer_fd);

	io_set_read_handler(transport->timer_io, transport_timer_read,
						transport, NULL);

	/* One extra packet to buffers immediately */
	return transport_send_seq(transport, fd, 1);
}

static void cmd_send_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;
	struct transport *transport;
	int fd = -1, err;
	struct bt_iso_qos qos;
	socklen_t len;
	int i;

	for (i = 1; i < argc; i++) {
		proxy = g_dbus_proxy_lookup(transports, NULL, argv[i],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
		if (!proxy) {
			bt_shell_printf("Transport %s not found\n", argv[i]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		transport = find_transport(proxy);
		if (!transport) {
			bt_shell_printf("Transport %s not acquired\n", argv[i]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		if (transport->sk < 0) {
			bt_shell_printf("No Transport Socked found\n");
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}

		if (i + 1 < argc) {
			fd = open_file(argv[++i], O_RDONLY);
			if (fd < 0)
				return bt_shell_noninteractive_quit(
								EXIT_FAILURE);
		}

		bt_shell_printf("Sending ...\n");

		/* Read QoS if available */
		memset(&qos, 0, sizeof(qos));
		len = sizeof(qos);
		if (getsockopt(transport->sk, SOL_BLUETOOTH, BT_ISO_QOS, &qos,
							&len) < 0) {
			bt_shell_printf("Unable to getsockopt(BT_ISO_QOS): %s",
							strerror(errno));
			err = transport_send(transport, fd, NULL);
		} else {
			struct sockaddr_iso addr;
			socklen_t optlen = sizeof(addr);

			err = getpeername(transport->sk,
					(struct sockaddr *)&addr, &optlen);
			if (!err) {
				if (!(bacmp(&addr.iso_bdaddr, BDADDR_ANY)))
					err = transport_send(transport, fd,
							     &qos.bcast.out);
				else
					err = transport_send(transport, fd,
							     &qos.ucast.out);
			}
		}

		if (err < 0) {
			bt_shell_printf("Unable to send: %s (%d)\n",
						strerror(-err), -err);
			close(fd);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

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

static void set_metadata_cb(const DBusError *error, void *user_data)
{
	if (dbus_error_is_set(error)) {
		bt_shell_printf("Failed to set Metadata: %s\n", error->name);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Changing Metadata succeeded\n");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_metadata_transport(int argc, char *argv[])
{
	GDBusProxy *proxy;
	struct iovec iov;

	proxy = g_dbus_proxy_lookup(transports, NULL, argv[1],
					BLUEZ_MEDIA_TRANSPORT_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Transport %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}


	if (argc == 2) {
		print_property(proxy, "Metadata");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	iov.iov_base = str2bytearray((char *) argv[2], &iov.iov_len);
	if (!iov.iov_base) {
		bt_shell_printf("Invalid argument: %s\n", argv[2]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (!g_dbus_proxy_set_property_array(proxy, "Metadata", DBUS_TYPE_BYTE,
						iov.iov_base, iov.iov_len,
						set_metadata_cb,
						NULL, NULL)) {
		bt_shell_printf("Failed release transport\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static const struct bt_shell_menu transport_menu = {
	.name = "transport",
	.desc = "Media Transport Submenu",
	.pre_run = player_menu_pre_run,
	.entries = {
	{ "list",         NULL,    cmd_list_transport,
						"List available transports" },
	{ "show",        "[transport]", cmd_show_transport,
						"Transport information",
						transport_generator },
	{ "acquire",     "<transport> [transport1...]", cmd_acquire_transport,
						"Acquire Transport",
						transport_generator },
	{ "release",     "<transport> [transport1...]", cmd_release_transport,
						"Release Transport",
						transport_generator },
	{ "send",        "<transport> <filename> [transport1...]",
						cmd_send_transport,
						"Send contents of a file",
						transport_generator },
	{ "receive",     "<transport> [filename]", cmd_receive_transport,
						"Get/Set file to receive",
						transport_generator },
	{ "volume",      "<transport> [value]",	cmd_volume_transport,
						"Get/Set transport volume",
						transport_generator },
	{ "select",      "<transport> [transport1...]", cmd_select_transport,
						"Select Transport",
						transport_generator },
	{ "unselect",    "<transport> [transport1...]", cmd_unselect_transport,
						"Unselect Transport",
						transport_generator },
	{ "metadata",    "<transport> [value...]", cmd_metadata_transport,
						"Get/Set Transport Metadata",
						transport_generator },
	{} },
};

static GDBusClient *client;

void player_add_submenu(void)
{
	bt_shell_add_submenu(&player_menu);
	bt_shell_add_submenu(&endpoint_menu);
	bt_shell_add_submenu(&transport_menu);
}

static void player_menu_pre_run(const struct bt_shell_menu *menu)
{
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
