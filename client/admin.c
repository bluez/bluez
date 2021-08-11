/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021 Google LLC
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "gdbus/gdbus.h"
#include "src/shared/shell.h"

#include "admin.h"
#define _GNU_SOURCE

static GDBusProxy *set_proxy;
static GDBusProxy *status_proxy;

void admin_policy_set_set_proxy(GDBusProxy *proxy)
{
	set_proxy = proxy;
}

void admin_policy_set_status_proxy(GDBusProxy *proxy)
{
	status_proxy = proxy;
}

void admin_policy_read_service_allowlist(DBusConnection *dbus_conn)
{
	DBusMessageIter iter, subiter;
	char *uuid = NULL;

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

void admin_policy_set_service_allowlist(DBusConnection *dbus_connd,
							int argc, char *argv[])
{
	struct uuid_list_data data;

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
