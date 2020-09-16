/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020 Google LLC
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "gdbus/gdbus.h"
#include "src/shared/util.h"
#include "src/shared/shell.h"
#include "adv_monitor.h"

#define ADV_MONITOR_APP_PATH	"/org/bluez/adv_monitor_app"
#define ADV_MONITOR_INTERFACE	"org.bluez.AdvertisementMonitor1"

static struct adv_monitor_manager {
	GSList *supported_types;
	GSList *supported_features;
	GDBusProxy *proxy;
	gboolean app_registered;
} manager = { NULL, NULL, NULL, FALSE };

static void set_supported_list(GSList **list, DBusMessageIter *iter)
{
	char *str;
	DBusMessageIter subiter;

	dbus_message_iter_recurse(iter, &subiter);
	while (dbus_message_iter_get_arg_type(&subiter) ==
						DBUS_TYPE_STRING) {
		dbus_message_iter_get_basic(&subiter, &str);
		*list = g_slist_append(*list, str);
		dbus_message_iter_next(&subiter);
	}
}

void adv_monitor_add_manager(DBusConnection *conn, GDBusProxy *proxy)
{
	DBusMessageIter iter;

	if (manager.proxy != NULL || manager.supported_types != NULL ||
					manager.supported_features != NULL) {
		bt_shell_printf("advertisement monitor manager already "
				"added\n");
		return;
	}

	manager.proxy = proxy;

	if (g_dbus_proxy_get_property(proxy, "SupportedMonitorTypes", &iter))
		set_supported_list(&(manager.supported_types), &iter);

	if (g_dbus_proxy_get_property(proxy, "SupportedFeatures", &iter))
		set_supported_list(&(manager.supported_features), &iter);

}

void adv_monitor_remove_manager(DBusConnection *conn)
{
	if (manager.supported_types != NULL)
		g_slist_free(g_steal_pointer(&(manager.supported_types)));
	if (manager.supported_features != NULL)
		g_slist_free(g_steal_pointer(&(manager.supported_features)));
	manager.proxy = NULL;
	manager.app_registered = FALSE;
}

static void register_setup(DBusMessageIter *iter, void *user_data)
{
	const char *path = ADV_MONITOR_APP_PATH;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void register_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (!dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("AdvertisementMonitor path registered\n");
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	bt_shell_printf("Failed to register path: %s\n", error.name);
	dbus_error_free(&error);
	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void unregister_setup(DBusMessageIter *iter, void *user_data)
{
	const char *path = ADV_MONITOR_APP_PATH;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void unregister_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (!dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("AdvertisementMonitor path unregistered\n");
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	bt_shell_printf("Failed to unregister Advertisement Monitor:"
			" %s\n", error.name);
	dbus_error_free(&error);
	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

void adv_monitor_register_app(DBusConnection *conn)
{
	if (manager.app_registered) {
		bt_shell_printf("Advertisement Monitor already registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	} else if (manager.supported_types == NULL ||
		!g_dbus_proxy_method_call(manager.proxy, "RegisterMonitor",
					register_setup, register_reply,
					NULL, NULL)) {
		bt_shell_printf("Failed to register Advertisement Monitor\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
	manager.app_registered = TRUE;
}

void adv_monitor_unregister_app(DBusConnection *conn)
{
	if (!manager.app_registered) {
		bt_shell_printf("Advertisement Monitor not registered\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	} else if (!g_dbus_proxy_method_call(manager.proxy, "UnregisterMonitor",
					unregister_setup, unregister_reply,
					NULL, NULL)) {
		bt_shell_printf("Failed to unregister Advertisement Monitor\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
	manager.app_registered = FALSE;
}
