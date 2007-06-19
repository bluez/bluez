/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <dbus.h>

#include "logging.h"
#include "server.h"

static DBusHandlerResult message_handler(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	debug("Incoming message %p", conn);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static void unregister_handler(DBusConnection *conn, void *data)
{
	debug("Unregister local connection %p", conn);
}

static void handle_connection(DBusServer *server, DBusConnection *conn, void *data)
{
	DBusObjectPathVTable vtable = { &unregister_handler, &message_handler,
							NULL, NULL, NULL, NULL};

	debug("New local connection %p", conn);

	//dbus_connection_add_filter(conn, filter_function, NULL, NULL);

	dbus_connection_register_fallback(conn, "/org/bluez", &vtable, NULL);

	dbus_connection_ref(conn);

	//dbus_connection_setup_with_g_main(conn, NULL);
	setup_dbus_with_main_loop(conn);
}

static DBusServer *server = NULL;

char *get_local_server_address(void)
{
	return dbus_server_get_address(server);
}

void init_local_server(void)
{
	DBusError err;
	char *address;

	dbus_error_init(&err);

	server = dbus_server_listen("unix:tmpdir=/var/run", &err);
	if (server == NULL) {
		error("Can't create local D-Bus server");
		dbus_error_free(&err);
		return;
	}

	address = dbus_server_get_address(server);

	info("Created local server at %s", address);

	dbus_free(address);

	//dbus_server_setup_with_g_main(server, NULL);
	setup_dbus_server_with_main_loop(server);

	dbus_server_set_new_connection_function(server, handle_connection,
								NULL, NULL);
}

void shutdown_local_server(void)
{
	if (server == NULL)
		return;

	info("Shutting down local server");

	dbus_server_disconnect(server);

	dbus_server_unref(server);

	server = NULL;
}
