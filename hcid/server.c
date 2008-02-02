/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include <dbus.h>

#include "dbus-database.h"

#include "logging.h"
#include "server.h"

static DBusHandlerResult filter_function(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	if (dbus_message_is_signal(msg, DBUS_INTERFACE_LOCAL, "Disconnected") &&
			strcmp(dbus_message_get_path(msg), DBUS_PATH_LOCAL) == 0) {
		debug("Received local disconnected signal");
		name_listener_indicate_disconnect(conn);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult message_handler(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	if (strcmp(dbus_message_get_interface(msg), DATABASE_INTERFACE) == 0)
		return database_message(conn, msg, data);

	debug("%s -> %s.%s", dbus_message_get_path(msg),
		dbus_message_get_interface(msg), dbus_message_get_member(msg));

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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

	dbus_connection_add_filter(conn, filter_function, NULL, NULL);

	if (dbus_connection_register_object_path(conn, "/org/bluez",
						&vtable, NULL) == FALSE) {
		error("Can't register local object path");
		return;
	}

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
	const char *ext_only[] = { "EXTERNAL", NULL };
	char *address;
	DBusError err;
	int fd, len;

	dbus_error_init(&err);

	server = dbus_server_listen("unix:tmpdir=/var/run", &err);
	if (server == NULL) {
		error("Can't create local D-Bus server");
		dbus_error_free(&err);
		return;
	}

	address = dbus_server_get_address(server);

	info("Created local server at %s", address);

	fd = open("/var/run/bluetoothd_address",
				O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR);
	if (fd < 0) {
		error("Can't create server address file");
	} else {
		len = write(fd, address, strlen(address));
		close(fd);
	}

	dbus_free(address);

	//dbus_server_setup_with_g_main(server, NULL);
	setup_dbus_server_with_main_loop(server);

	dbus_server_set_new_connection_function(server, handle_connection,
								NULL, NULL);

	dbus_server_set_auth_mechanisms(server, ext_only);
}

void shutdown_local_server(void)
{
	if (server == NULL)
		return;

	info("Shutting down local server");

	if (unlink("/var/run/bluetoothd_address") < 0)
		error("Can't remove server address file");

	dbus_server_disconnect(server);

	dbus_server_unref(server);

	server = NULL;
}
