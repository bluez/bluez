/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Intel Corporation
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

#include <glib.h>
#include <gdbus.h>

#define SERVICE_NAME "org.bluez.unit.test-gdbus-client"
#define SERVICE_PATH "/org/bluez/unit/test_gdbus_client"

static GMainLoop *main_loop;
static DBusConnection *dbus_conn;
static GDBusClient *dbus_client;
static guint timeout_source;

static const GDBusMethodTable methods[] = {
	{ }
};

static const GDBusSignalTable signals[] = {
	{ }
};

static const GDBusPropertyTable properties[] = {
	{ }
};

static gboolean timeout_handler(gpointer data)
{
	timeout_source = 0;

	g_dbus_client_unref(dbus_client);

	return FALSE;
}

static void connect_handler(DBusConnection *connection, void *user_data)
{
	g_dbus_client_unref(dbus_client);
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	g_main_loop_quit(main_loop);
}

static void client_connect_disconnect(void)
{
	main_loop = g_main_loop_new(NULL, FALSE);
	dbus_conn = g_dbus_setup_private(DBUS_BUS_SESSION, SERVICE_NAME, NULL);

	if (dbus_conn == NULL)
		return;

	g_dbus_register_interface(dbus_conn, SERVICE_PATH, SERVICE_NAME,
				methods, signals, properties, NULL, NULL);

	dbus_client = g_dbus_client_new(dbus_conn, SERVICE_NAME, SERVICE_PATH);

	g_dbus_client_set_connect_watch(dbus_client, connect_handler, NULL);
	g_dbus_client_set_disconnect_watch(dbus_client,
						disconnect_handler, NULL);

	timeout_source = g_timeout_add_seconds(10, timeout_handler, NULL);

	g_main_loop_run(main_loop);

	if (timeout_source > 0)
		g_source_remove(timeout_source);

	g_dbus_unregister_interface(dbus_conn, SERVICE_PATH, SERVICE_NAME);

	dbus_connection_unref(dbus_conn);
	g_main_loop_unref(main_loop);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/gdbus/client_connect_disconnect",
						client_connect_disconnect);

	return g_test_run();
}
