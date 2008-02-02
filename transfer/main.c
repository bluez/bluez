/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "logging.h"
#include "dbus.h"

#include "server.h"
#include "session.h"

#define SERVICE_PATH "/org/bluez/transfer"

static GMainLoop *main_loop;

static DBusConnection *system_bus;

static DBusHandlerResult error_reply(DBusConnection *conn,
					DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, "org.bluez.transfer.Error", str));
}

static DBusHandlerResult push_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *address, *pathname, *identifier;
	struct session_data *session;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &pathname, DBUS_TYPE_INVALID) == FALSE)
		return error_reply(conn, msg, "Invalid arguments");

	debug("Requesting push of %s to %s", pathname, address);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	session = session_create(conn, msg);
	if (!session) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	identifier = session_connect(session, address, pathname);
	if (!identifier) {
		session_destroy(session);
		dbus_message_unref(reply);
		return error_reply(conn, msg, "Unable to connect session");
	}

	debug("Created new session at %s", identifier);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &identifier,
							DBUS_TYPE_INVALID);

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult manager_handler(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	if (dbus_message_is_method_call(msg, "org.bluez.transfer.Manager", "Push"))
		return push_message(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable manager_table = {
	.message_function = manager_handler,
};

static int setup_manager(void)
{
	if (dbus_connection_register_object_path(system_bus,
			SERVICE_PATH, &manager_table, NULL) == FALSE) {
		error("Service path registration failed");
		return -1;
	}

	return 0;
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void sig_hup(int sig)
{
}

static void sig_debug(int sig)
{
	toggle_debug();
}

int main(int argc, char *argv[])
{
	struct sigaction sa;

	start_logging("transfer", "Bluetooth transfer service ver %s", VERSION);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = sig_debug;
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	enable_debug();

	main_loop = g_main_loop_new(NULL, FALSE);

	system_bus = init_dbus(NULL, NULL, NULL);
	if (!system_bus) {
		g_main_loop_unref(main_loop);
		exit(1);
	}

	if (setup_manager() < 0) {
		dbus_connection_unref(system_bus);
		g_main_loop_unref(main_loop);
		exit(1);
	}

	start_server(9);

	g_main_loop_run(main_loop);

	stop_server();

	dbus_connection_unregister_object_path(system_bus, SERVICE_PATH);

	dbus_connection_unref(system_bus);

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
