// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021 Google LLC
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "bluetooth/bluetooth.h"
#include "gdbus/gdbus.h"
#include "src/shared/shell.h"

#include "admin.h"
#define _GNU_SOURCE

static DBusConnection *dbus_conn;
static GList *set_proxies;
static GList *status_proxies;

static void admin_menu_pre_run(const struct bt_shell_menu *menu);

static GDBusProxy *admin_policy_find_proxy(GList *proxies,
						const char *path)
{
	GList *list;

	for (list = g_list_first(proxies); list; list = g_list_next(list)) {
		GDBusProxy *proxy = list->data;

		if (!strcmp(g_dbus_proxy_get_path(proxy), path))
			return proxy;
	}

	return NULL;
}

static GDBusProxy *admin_policy_get_status_proxy(const char *controller_path)
{
	if (!controller_path)
		return NULL;

	return admin_policy_find_proxy(status_proxies, controller_path);
}

static GDBusProxy *admin_policy_get_set_proxy(const char *controller_path)
{
	if (!controller_path)
		return NULL;

	return admin_policy_find_proxy(set_proxies, controller_path);
}

static GDBusProxy *admin_policy_get_controller(int argc, char *argv[],
						int *arg_index)
{
	GDBusProxy *controller;

	*arg_index = 1;

	if (argc > 1 && strlen(argv[1])) {
		controller = bluetoothctl_find_controller(argv[1]);
		if (controller) {
			*arg_index = 2;
			return controller;
		}

		if (bachk(argv[1]) == 0) {
			bt_shell_printf("Controller %s not available\n",
								argv[1]);
			return NULL;
		}
	}

	controller = bluetoothctl_get_default_controller();
	if (controller)
		return controller;

	bt_shell_printf("No default controller available\n");
	return NULL;
}

static void admin_policy_read_service_allowlist(GDBusProxy *controller)
{
	DBusMessageIter iter, subiter;
	GDBusProxy *status_proxy;
	char *uuid = NULL;
	const char *controller_path = g_dbus_proxy_get_path(controller);

	status_proxy = admin_policy_get_status_proxy(controller_path);
	if (!status_proxy || !g_dbus_proxy_get_property(status_proxy,
						"ServiceAllowList", &iter)) {
		bt_shell_printf("Failed to get property\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		bt_shell_printf("Unexpected return type\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	bt_shell_printf("Service AllowedList:\n");
	dbus_message_iter_recurse(&iter, &subiter);
	while (dbus_message_iter_get_arg_type(&subiter) ==
						DBUS_TYPE_STRING) {
		dbus_message_iter_get_basic(&subiter, &uuid);
		bt_shell_printf("\t%s\n", uuid);
		dbus_message_iter_next(&subiter);
	}

	return bt_shell_noninteractive_quit(EXIT_SUCCESS);
}

struct uuid_list_data {
	char **uuid_list;
	size_t num;
};

static void set_service_setup(DBusMessageIter *iter, void *user_data)
{
	struct uuid_list_data *data = user_data;
	DBusMessageIter arr_iter;
	size_t i;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_STRING_AS_STRING,
						&arr_iter);

	for (i = 0; i < data->num; i++) {
		dbus_message_iter_append_basic(&arr_iter, DBUS_TYPE_STRING,
							&data->uuid_list[i]);
	}

	dbus_message_iter_close_container(iter, &arr_iter);
}

static void set_service_reply(DBusMessage *message, void *user_data)
{
	DBusError error;

	dbus_error_init(&error);

	if (!dbus_set_error_from_message(&error, message)) {
		bt_shell_printf("Set allowed service successfully\n");
		return bt_shell_noninteractive_quit(EXIT_SUCCESS);
	}

	bt_shell_printf("Failed to set service allowed list: %s\n", error.name);
	dbus_error_free(&error);
	return bt_shell_noninteractive_quit(EXIT_FAILURE);
}

static void admin_policy_set_service_allowlist(GDBusProxy *controller,
						int argc, char *argv[])
{
	struct uuid_list_data data;
	GDBusProxy *set_proxy;
	const char *controller_path = g_dbus_proxy_get_path(controller);

	set_proxy = admin_policy_get_set_proxy(controller_path);
	if (!set_proxy) {
		bt_shell_printf("Set proxy not ready\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	data.uuid_list = argv;
	data.num = argc;

	if (!g_dbus_proxy_method_call(set_proxy, "SetServiceAllowList",
					set_service_setup, set_service_reply,
					&data, NULL)) {
		bt_shell_printf("Failed to call method\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}
}

static void cmd_admin_allow(int argc, char *argv[])
{
	GDBusProxy *controller;
	int arg_index;

	controller = admin_policy_get_controller(argc, argv, &arg_index);
	if (!controller)
		return bt_shell_noninteractive_quit(EXIT_FAILURE);

	if (argc <= arg_index) {
		admin_policy_read_service_allowlist(controller);
		return;
	}

	if (strcmp(argv[arg_index], "clear") == 0)
		arg_index++;

	admin_policy_set_service_allowlist(controller, argc - arg_index,
						argv + arg_index);
}

static const struct bt_shell_menu admin_menu = {
	.name = "admin",
	.desc = "Admin Policy Submenu",
	.pre_run = admin_menu_pre_run,
	.entries = {
	{ "allow", "[ctrl] [clear/uuid1 uuid2 ...]", cmd_admin_allow,
				"Allow service UUIDs and block rest of them",
				bluetoothctl_controller_generator},
	{} },
};

static void admin_policy_status_added(GDBusProxy *proxy)
{
	status_proxies = g_list_append(status_proxies, proxy);
}

static void proxy_added(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.AdminPolicySet1"))
		set_proxies = g_list_append(set_proxies, proxy);
	else if (!strcmp(interface, "org.bluez.AdminPolicyStatus1"))
		admin_policy_status_added(proxy);
}

static void admin_policy_status_removed(GDBusProxy *proxy)
{
	status_proxies = g_list_remove(status_proxies, proxy);
}

static void proxy_removed(GDBusProxy *proxy, void *user_data)
{
	const char *interface;

	interface = g_dbus_proxy_get_interface(proxy);

	if (!strcmp(interface, "org.bluez.AdminPolicySet1"))
		set_proxies = g_list_remove(set_proxies, proxy);
	else if (!strcmp(interface, "org.bluez.AdminPolicyStatus1"))
		admin_policy_status_removed(proxy);
}

static GDBusClient *client;

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	g_list_free_full(set_proxies, NULL);
	set_proxies = NULL;
	g_list_free_full(status_proxies, NULL);
	status_proxies = NULL;
}

void admin_add_submenu(void)
{
	bt_shell_add_submenu(&admin_menu);
}

static void admin_menu_pre_run(const struct bt_shell_menu *menu)
{
	dbus_conn = bt_shell_get_env("DBUS_CONNECTION");
	if (!dbus_conn || client)
		return;

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");
	g_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							NULL, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);
}

void admin_remove_submenu(void)
{
	g_dbus_client_unref(client);
	client = NULL;
}
