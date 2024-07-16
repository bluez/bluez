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

#include "lib/bluetooth.h"
#include "lib/uuid.h"

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

static DBusConnection *dbus_conn;

static GList *assistants;

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

static GDBusClient * client;

void assistant_add_submenu(void)
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

