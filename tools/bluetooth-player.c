// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/uio.h>

#include <glib.h>

#include "gdbus/gdbus.h"
#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/shared/util.h"
#include "src/shared/shell.h"
#include "client/player.h"

#define PROMPT	"[bluetooth-player]> "

static DBusConnection *dbus_conn;

static void connect_handler(DBusConnection *connection, void *user_data)
{
	bt_shell_attach(fileno(stdin));
	bt_shell_set_prompt(PROMPT, COLOR_BLUE);
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	bt_shell_detach();
	bt_shell_set_prompt(PROMPT, NULL);
}

int main(int argc, char *argv[])
{
	GDBusClient *client;
	int status;

	bt_shell_init(argc, argv, NULL);
	bt_shell_set_prompt(PROMPT, NULL);

	dbus_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);

	bt_shell_set_env("DBUS_CONNECTION", dbus_conn);

	player_add_submenu();

	client = g_dbus_client_new(dbus_conn, "org.bluez", "/org/bluez");

	g_dbus_client_set_connect_watch(client, connect_handler, NULL);
	g_dbus_client_set_disconnect_watch(client, disconnect_handler, NULL);

	status = bt_shell_run();

	player_remove_submenu();

	g_dbus_client_unref(client);

	dbus_connection_unref(dbus_conn);

	return status;
}
