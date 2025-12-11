// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright © 2025 Collabora Ltd.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdlib.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "src/shared/shell.h"
#include "print.h"
#include "telephony.h"

/* String display constants */
#define COLORED_NEW	COLOR_GREEN "NEW" COLOR_OFF
#define COLORED_CHG	COLOR_YELLOW "CHG" COLOR_OFF
#define COLORED_DEL	COLOR_RED "DEL" COLOR_OFF

#define BLUEZ_TELEPHONY_INTERFACE "org.bluez.Telephony1"
#define BLUEZ_TELEPHONY_CALL_INTERFACE "org.bluez.Call1"

static DBusConnection *dbus_conn;
static GDBusProxy *default_ag;
static GList *ags;
static GList *calls;

static GDBusClient *client;

static bool check_default_ag(void)
{
	if (!default_ag) {
		bt_shell_printf("No default audio gateway available\n");
		return FALSE;
	}

	return TRUE;
}

static char *generic_generator(const char *text, int state, GList *source)
{
	static int index;

	if (!source)
		return NULL;

	if (!state)
		index = 0;

	return g_dbus_proxy_path_lookup(source, &index, text);
}

static char *ag_generator(const char *text, int state)
{
	return generic_generator(text, state, ags);
}

static char *call_generator(const char *text, int state)
{
	return generic_generator(text, state, calls);
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

static void print_ag(void *data, void *user_data)
{
	GDBusProxy *proxy = data;
	const char *description = user_data;
	char *str;

	str = proxy_description(proxy, "Telephony", description);

	bt_shell_printf("%s%s\n", str,
			default_ag == proxy ? "[default]" : "");

	g_free(str);
}

static void print_call(void *data, void *user_data)
{
	GDBusProxy *proxy = data;
	const char *description = user_data;
	const char *path, *line_id;
	DBusMessageIter iter;

	path = g_dbus_proxy_get_path(proxy);

	if (g_dbus_proxy_get_property(proxy, "LineIdentification", &iter))
		dbus_message_iter_get_basic(&iter, &line_id);
	else
		line_id = "<unknown>";

	bt_shell_printf("%s%s%sCall %s %s\n", description ? "[" : "",
					description ? : "",
					description ? "] " : "",
					path, line_id);
}

static void cmd_list(int argc, char *arg[])
{
	g_list_foreach(ags, print_ag, NULL);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_show(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc < 2) {
		if (check_default_ag() == FALSE)
			return bt_shell_noninteractive_quit(EXIT_FAILURE);

		proxy = default_ag;
	} else {
		proxy = g_dbus_proxy_lookup(ags, NULL, argv[1],
						BLUEZ_TELEPHONY_INTERFACE);
		if (!proxy) {
			bt_shell_printf("Audio gateway %s not available\n",
								argv[1]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	bt_shell_printf("Audio gateway %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "UUID");
	print_property(proxy, "SupportedURISchemes");
	print_property(proxy, "State");
	print_property(proxy, "Service");
	print_property(proxy, "Signal");
	print_property(proxy, "Roaming");
	print_property(proxy, "BattChg");
	print_property(proxy, "OperatorName");
	print_property(proxy, "InbandRingtone");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_select(int argc, char *argv[])
{
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_lookup(ags, NULL, argv[1],
						BLUEZ_TELEPHONY_INTERFACE);
	if (proxy == NULL) {
		bt_shell_printf("Audio gateway %s not available\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (default_ag == proxy)
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);

	default_ag = proxy;
	print_ag(proxy, NULL);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void dial_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to answer: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Dial successful\n");

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void dial_setup(DBusMessageIter *iter, void *user_data)
{
	const char *number = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &number);
}

static void cmd_dial(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc < 3) {
		if (check_default_ag() == FALSE)
			return bt_shell_noninteractive_quit(EXIT_FAILURE);

		proxy = default_ag;
	} else {
		proxy = g_dbus_proxy_lookup(ags, NULL, argv[2],
						BLUEZ_TELEPHONY_INTERFACE);
		if (!proxy) {
			bt_shell_printf("Audio gateway %s not available\n",
							argv[1]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	if (g_dbus_proxy_method_call(proxy, "Dial", dial_setup,
				dial_reply, argv[1], NULL) == FALSE) {
		bt_shell_printf("Failed to dial\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to dial\n");
}

static void hangupall_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to answer: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Hangup all successful\n");

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_hangupall(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc < 2) {
		if (check_default_ag() == FALSE)
			return bt_shell_noninteractive_quit(EXIT_FAILURE);

		proxy = default_ag;
	} else {
		proxy = g_dbus_proxy_lookup(ags, NULL, argv[1],
						BLUEZ_TELEPHONY_INTERFACE);
		if (!proxy) {
			bt_shell_printf("Audio gateway %s not available\n",
							argv[1]);
			return bt_shell_noninteractive_quit(EXIT_FAILURE);
		}
	}

	if (g_dbus_proxy_method_call(proxy, "HangupAll", NULL,
				hangupall_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to hangup all calls\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to hangup all calls\n");
}

static void cmd_list_calls(int argc, char *arg[])
{
	g_list_foreach(calls, print_call, NULL);

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void cmd_show_call(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc < 2)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	proxy = g_dbus_proxy_lookup(calls, NULL, argv[1],
				BLUEZ_TELEPHONY_CALL_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Call %s not available\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Call %s\n", g_dbus_proxy_get_path(proxy));

	print_property(proxy, "LineIdentification");
	print_property(proxy, "IncomingLine");
	print_property(proxy, "Name");
	print_property(proxy, "Multiparty");
	print_property(proxy, "State");

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

static void answer_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to answer: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Answer successful\n");

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_answer_call(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc < 2)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	proxy = g_dbus_proxy_lookup(calls, NULL, argv[1],
				BLUEZ_TELEPHONY_CALL_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Call %s not available\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (g_dbus_proxy_method_call(proxy, "Answer", NULL,
				answer_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to answer call\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to answer\n");
}

static void hangup_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == TRUE) {
		bt_shell_printf("Failed to answer: %s\n", error.name);
		dbus_error_free(&error);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Hangup successful\n");

	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void cmd_hangup_call(int argc, char *argv[])
{
	GDBusProxy *proxy;

	if (argc < 2)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	proxy = g_dbus_proxy_lookup(calls, NULL, argv[1],
			BLUEZ_TELEPHONY_CALL_INTERFACE);
	if (!proxy) {
		bt_shell_printf("Call %s not available\n", argv[1]);
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (g_dbus_proxy_method_call(proxy, "Hangup", NULL,
				hangup_reply, NULL, NULL) == FALSE) {
		bt_shell_printf("Failed to hangup call\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Attempting to hangup\n");
}

static void ag_added(GDBusProxy *proxy)
{
	ags = g_list_append(ags, proxy);

	if (default_ag == NULL)
		default_ag = proxy;

	print_ag(proxy, COLORED_NEW);
}

static void call_added(GDBusProxy *proxy)
{
	calls = g_list_append(calls, proxy);

	print_call(proxy, COLORED_NEW);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_TELEPHONY_INTERFACE))
		ag_added(proxy);
	else if (!strcmp(interface, BLUEZ_TELEPHONY_CALL_INTERFACE))
		call_added(proxy);
}

static void ag_removed(GDBusProxy *proxy)
{
	print_ag(proxy, COLORED_DEL);

	if (default_ag == proxy)
		default_ag = NULL;

	ags = g_list_remove(ags, proxy);
}

static void call_removed(GDBusProxy *proxy)
{
	calls = g_list_remove(calls, proxy);

	print_call(proxy, COLORED_DEL);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_TELEPHONY_INTERFACE))
		ag_removed(proxy);
	else if (!strcmp(interface, BLUEZ_TELEPHONY_CALL_INTERFACE))
		call_removed(proxy);
}

static void ag_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Telephony", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static void call_property_changed(GDBusProxy *proxy, const char *name,
						DBusMessageIter *iter)
{
	char *str;

	str = proxy_description(proxy, "Call", COLORED_CHG);
	print_iter(str, name, iter);
	g_free(str);
}

static void property_changed(GDBusProxy *proxy, const char *name,
					DBusMessageIter *iter, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, BLUEZ_TELEPHONY_INTERFACE))
		ag_property_changed(proxy, name, iter);
	else if (!strcmp(interface, BLUEZ_TELEPHONY_CALL_INTERFACE))
		call_property_changed(proxy, name, iter);
}

static void telephony_menu_pre_run(const struct bt_shell_menu *menu)
{
	dbus_conn = bt_shell_get_env("DBUS_CONNECTION");
	if (!dbus_conn || client)
		return;

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							property_changed, NULL);
}

static const struct bt_shell_menu telephony_menu = {
	.name = "telephony",
	.desc = "Telephony Submenu",
	.pre_run = telephony_menu_pre_run,
	.entries = {
	{ "list",         NULL, cmd_list, "List available audio gateway" },
	{ "show",         "[telephony]", cmd_show, "Audio gateway information",
						ag_generator},
	{ "select",       "<telephony>", cmd_select,
						"Select default audio gateway",
						ag_generator},
	{ "dial",         "<number> [telephony]", cmd_dial, "Dial number",
						ag_generator},
	{ "hangup-all",   "[telephony]", cmd_hangupall, "Hangup all calls",
						ag_generator},
	{ "list-calls",   NULL, cmd_list_calls, "List calls" },
	{ "show-call",    "<call>", cmd_show_call, "Show call information",
						call_generator},
	{ "answer",       "<call>", cmd_answer_call, "Answer call",
						call_generator},
	{ "hangup",       "<call>", cmd_hangup_call, "Hangup call",
						call_generator},
	{} },
};

void telephony_add_submenu(void)
{
	bt_shell_add_submenu(&telephony_menu);
}

void telephony_remove_submenu(void)
{
	g_dbus_client_unref(client);
}
