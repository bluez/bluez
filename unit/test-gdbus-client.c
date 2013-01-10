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

struct context {
	GMainLoop *main_loop;
	DBusConnection *dbus_conn;
	GDBusClient *dbus_client;
	guint timeout_source;
};

static const GDBusMethodTable methods[] = {
	{ }
};

static const GDBusSignalTable signals[] = {
	{ }
};

static const GDBusPropertyTable properties[] = {
	{ }
};

static struct context *create_context(void)
{
	struct context *context = g_new0(struct context, 1);
	DBusError err;

	context->main_loop = g_main_loop_new(NULL, FALSE);
	if (context->main_loop == NULL) {
		g_free(context);
		return NULL;
	}

	dbus_error_init(&err);

	context->dbus_conn = g_dbus_setup_private(DBUS_BUS_SESSION,
							SERVICE_NAME, &err);
	if (context->dbus_conn == NULL) {
		if (dbus_error_is_set(&err)) {
			if (g_test_verbose())
				g_printerr("D-Bus setup failed: %s\n",
								err.message);
			dbus_error_free(&err);
		}

		g_main_loop_unref(context->main_loop);
		g_free(context);
		return NULL;
	}

	/* Avoid D-Bus library calling _exit() before next test finishes. */
	dbus_connection_set_exit_on_disconnect(context->dbus_conn, FALSE);

	return context;
}

static void destroy_context(struct context *context)
{
	if (context == NULL)
		return;

	dbus_connection_flush(context->dbus_conn);
	dbus_connection_close(context->dbus_conn);

	g_main_loop_unref(context->main_loop);

	g_free(context);
}

static gboolean timeout_handler(gpointer user_data)
{
	struct context *context = user_data;

	if (g_test_verbose())
		g_print("timeout triggered\n");

	context->timeout_source = 0;

	g_dbus_client_unref(context->dbus_client);

	return FALSE;
}

static void connect_handler(DBusConnection *connection, void *user_data)
{
	struct context *context = user_data;

	if (g_test_verbose())
		g_print("service connected\n");

	g_dbus_client_unref(context->dbus_client);
}

static void disconnect_handler(DBusConnection *connection, void *user_data)
{
	struct context *context = user_data;

	if (g_test_verbose())
		g_print("service disconnected\n");

	g_main_loop_quit(context->main_loop);
}

static void simple_client(void)
{
	struct context *context = create_context();

	if (context == NULL)
		return;

	context->dbus_client = g_dbus_client_new(context->dbus_conn,
						SERVICE_NAME, SERVICE_PATH);

	g_dbus_client_set_connect_watch(context->dbus_client,
						connect_handler, context);
	g_dbus_client_set_disconnect_watch(context->dbus_client,
						disconnect_handler, context);

	g_main_loop_run(context->main_loop);

	destroy_context(context);
}

static void client_connect_disconnect(void)
{
	struct context *context = create_context();

	if (context == NULL)
		return;

	g_dbus_register_interface(context->dbus_conn,
				SERVICE_PATH, SERVICE_NAME,
				methods, signals, properties, NULL, NULL);

	context->dbus_client = g_dbus_client_new(context->dbus_conn,
						SERVICE_NAME, SERVICE_PATH);

	g_dbus_client_set_connect_watch(context->dbus_client,
						connect_handler, context);
	g_dbus_client_set_disconnect_watch(context->dbus_client,
						disconnect_handler, context);

	context->timeout_source = g_timeout_add_seconds(10, timeout_handler,
								context);

	g_main_loop_run(context->main_loop);

	if (context->timeout_source > 0)
		g_source_remove(context->timeout_source);

	g_dbus_unregister_interface(context->dbus_conn,
					SERVICE_PATH, SERVICE_NAME);

	destroy_context(context);
}

int main(int argc, char *argv[])
{
	g_test_init(&argc, &argv, NULL);

	g_test_add_func("/gdbus/simple_client", simple_client);

	g_test_add_func("/gdbus/client_connect_disconnect",
						client_connect_disconnect);

	return g_test_run();
}
