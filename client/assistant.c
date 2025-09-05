// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2024 NXP
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

#include <glib.h>

#include "gdbus/gdbus.h"

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/shared/util.h"
#include "src/shared/shell.h"
#include "src/shared/io.h"
#include "src/shared/queue.h"
#include "print.h"
#include "assistant.h"

/* String display constants */
#define COLORED_NEW	COLOR_GREEN "NEW" COLOR_OFF
#define COLORED_CHG	COLOR_YELLOW "CHG" COLOR_OFF
#define COLORED_DEL	COLOR_RED "DEL" COLOR_OFF

#define MEDIA_ASSISTANT_INTERFACE "org.bluez.MediaAssistant1"

#define BCODE_LEN		16

struct assistant_config {
	GDBusProxy *proxy;	/* DBus object reference */
	struct iovec *meta;	/* Stream metadata LTVs */
	struct bt_iso_qos qos;	/* Stream QoS parameters */
};

static DBusConnection *dbus_conn;

static GList *assistants;

static void assistant_menu_pre_run(const struct bt_shell_menu *menu);

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

static void print_assistant(GDBusProxy *proxy, const char *description)
{
	char *str;

	str = proxy_description(proxy, "Assistant", description);

	bt_shell_printf("%s\n", str);

	g_free(str);
}

static void assistant_added(GDBusProxy *proxy)
{
	assistants = g_list_append(assistants, proxy);

	print_assistant(proxy, COLORED_NEW);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, MEDIA_ASSISTANT_INTERFACE))
		assistant_added(proxy);
}

static void assistant_removed(GDBusProxy *proxy)
{
	assistants = g_list_remove(assistants, proxy);

	print_assistant(proxy, COLORED_DEL);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, MEDIA_ASSISTANT_INTERFACE))
		assistant_removed(proxy);
}

static void assistant_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Assistant", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, MEDIA_ASSISTANT_INTERFACE))
		assistant_property_changed(proxy, name, iter);
}

static void assistant_unregister(void *data)
{
	GDBusProxy *proxy = data;

	bt_shell_printf("Assistant %s unregistered\n",
				g_dbus_proxy_get_path(proxy));
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	g_list_free_full(assistants, assistant_unregister);
	assistants = NULL;
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

static void append_qos(DBusMessageIter *iter, struct assistant_config *cfg)
{
	DBusMessageIter entry, var, dict;
	const char *key = "QoS";
	const char *bcode_key = "BCode";
	uint8_t *bcode = cfg->qos.bcast.bcode;

	dbus_message_iter_open_container(iter, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
						"a{sv}", &var);

	dbus_message_iter_open_container(&var, DBUS_TYPE_ARRAY, "{sv}",
					&dict);

	g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING,
					&bcode_key, DBUS_TYPE_BYTE,
					&bcode, BCODE_LEN);

	dbus_message_iter_close_container(&var, &dict);
	dbus_message_iter_close_container(&entry, &var);
	dbus_message_iter_close_container(iter, &entry);
}

static void push_setup(DBusMessageIter *iter, void *user_data)
{
	struct assistant_config *cfg = user_data;
	DBusMessageIter dict;
	const char *meta = "Metadata";

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

	if (cfg->meta)
		g_dbus_dict_append_basic_array(&dict, DBUS_TYPE_STRING, &meta,
				DBUS_TYPE_BYTE, &cfg->meta->iov_base,
				cfg->meta->iov_len);

	if (cfg->qos.bcast.encryption)
		append_qos(&dict, cfg);

	dbus_message_iter_close_container(iter, &dict);
}

static void push_reply(DBusMessage *message, void *user_data)
{
	struct assistant_config *cfg = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("Failed to push assistant: %s\n",
				error.name);

		dbus_error_free(&error);

		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Assistant %s pushed\n",
				g_dbus_proxy_get_path(cfg->proxy));

	free(cfg->meta);
	g_free(cfg);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void assistant_set_bcode_cfg(const char *input, void *user_data)
{
	struct assistant_config *cfg = user_data;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto")) {
		memset(cfg->qos.bcast.bcode, 0, BCODE_LEN);
	} else {
		if (strnlen(input, BCODE_LEN + 1) > BCODE_LEN) {
			bt_shell_printf("Input string too long %s\n", input);
			goto fail;
		}

		memcpy(cfg->qos.bcast.bcode, input, strlen(input));
	}

	if (!g_dbus_proxy_method_call(cfg->proxy, "Push",
					push_setup, push_reply,
					cfg, NULL)) {
		bt_shell_printf("Failed to push assistant\n");
		goto fail;
	}

	return;

fail:
	free(cfg->meta);
	g_free(cfg);

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void assistant_set_metadata_cfg(const char *input, void *user_data)
{
	struct assistant_config *cfg = user_data;
	DBusMessageIter iter, dict, entry, value;
	const char *key;

	if (!strcasecmp(input, "a") || !strcasecmp(input, "auto"))
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
	/* Get QoS property to check if the stream is encrypted */
	if (!g_dbus_proxy_get_property(cfg->proxy, "QoS", &iter))
		goto fail;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		goto fail;

	dbus_message_iter_recurse(&iter, &dict);

	if (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_DICT_ENTRY)
		goto fail;

	dbus_message_iter_recurse(&dict, &entry);
	dbus_message_iter_get_basic(&entry, &key);

	if (strcasecmp(key, "Encryption") != 0)
		goto fail;

	dbus_message_iter_next(&entry);
	dbus_message_iter_recurse(&entry, &value);

	if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_BYTE)
		goto fail;

	dbus_message_iter_get_basic(&value, &cfg->qos.bcast.encryption);

	if (cfg->qos.bcast.encryption)
		/* Prompt user to enter the Broadcast Code to decrypt
		 * the stream
		 */
		bt_shell_prompt_input("Assistant",
				"Enter Broadcast Code (auto/value):",
				assistant_set_bcode_cfg, cfg);
	else
		if (!g_dbus_proxy_method_call(cfg->proxy, "Push",
						push_setup, push_reply,
						cfg, NULL)) {
			bt_shell_printf("Failed to push assistant\n");
			goto fail;
		}

	return;

fail:
	free(cfg->meta);
	g_free(cfg);

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_push_assistant(int argc, char *argv[])
{
	struct assistant_config *cfg;

	cfg = new0(struct assistant_config, 1);
	if (!cfg)
		goto fail;

	/* Search for DBus object */
	cfg->proxy = g_dbus_proxy_lookup(assistants, NULL, argv[1],
						MEDIA_ASSISTANT_INTERFACE);
	if (!cfg->proxy) {
		bt_shell_printf("Assistant %s not found\n", argv[1]);
		goto fail;
	}

	/* Prompt user to enter metadata */
	bt_shell_prompt_input("Assistant",
			"Enter Metadata (auto/value):",
			assistant_set_metadata_cfg, cfg);

	return;

fail:
	g_free(cfg);
	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_list_assistant(int argc, char *argv[])
{
	GList *l;

	for (l = assistants; l; l = g_list_next(l)) {
		GDBusProxy *proxy = l->data;
		print_assistant(proxy, NULL);
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void print_assistant_properties(GDBusProxy *proxy)
{
	bt_shell_printf("Transport %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "State");
	print_property(proxy, "Metadata");
	print_property(proxy, "QoS");
}

static void print_assistants(void *data, void *user_data)
{
	print_assistant_properties(data);
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

static char *assistant_generator(const char *text, int state)
{
	return generic_generator(text, state, assistants);
}

static void cmd_show_assistant(int argc, char *argv[])
{
	GDBusProxy *proxy;

	/* Show all transports if no argument is given */
	if (argc != 2) {
		g_list_foreach(assistants, print_assistants, NULL);
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	proxy = g_dbus_proxy_lookup(assistants, NULL, argv[1],
					MEDIA_ASSISTANT_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Assistant %s not found\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	print_assistant_properties(proxy);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static const struct bt_shell_menu assistant_menu = {
	.name = "assistant",
	.desc = "Media Assistant Submenu",
	.pre_run = assistant_menu_pre_run,
	.entries = {
	{ "list", NULL, cmd_list_assistant, "List available assistants" },
	{ "show", "[assistant]", cmd_show_assistant,
					"Assistant information",
					assistant_generator },
	{ "push", "<assistant>", cmd_push_assistant,
					"Send stream information to peer",
					assistant_generator },
	{} },
};

static GDBusClient * client;

void assistant_add_submenu(void)
{
	bt_shell_add_submenu(&assistant_menu);
}

static void assistant_menu_pre_run(const struct bt_shell_menu *menu)
{
	dbus_conn = bt_shell_get_env("DBUS_CONNECTION");
	if (!dbus_conn || client)
		return;

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							property_changed, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);
}

void assistant_remove_submenu(void)
{
	g_dbus_client_unref(client);
	client = NULL;
}

