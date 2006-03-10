/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2006  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include <dbus/dbus.h>

static const char *agent_path = "/org/bluez/passkey-agent/";

static char *passkey = "0000";

static volatile sig_atomic_t __io_canceled = 0;

static void sig_term(int sig)
{
	__io_canceled = 1;
}

DBusHandlerResult agent_message(DBusConnection *conn, DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	char *path, *address;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &path);
	dbus_message_iter_get_basic(&iter, &address);

	reply = dbus_message_new_method_return(msg);

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &passkey);

	dbus_connection_send(conn, reply, NULL);

	dbus_connection_flush(conn);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static const DBusObjectPathVTable agent_table = {
	.message_function = agent_message,
};

int main(int argc, char **argv)
{
	struct sigaction sa;
	DBusConnection* conn;
	DBusMessage *msg, *reply;
	DBusMessageIter iter;
	DBusError err;

	dbus_error_init(&err);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);

	if (dbus_error_is_set(&err)) {
		fprintf(stderr, "Can't get on system bus");
		dbus_error_free(&err);
		exit(1);
	}

	dbus_connection_register_object_path(conn, agent_path,
							&agent_table, NULL);

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez/Manager",
			"org.bluez.Security", "RegisterDefaultPasskeyAgent");

	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		exit(1);
	}

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &agent_path);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr, "Can't register passkey agent\n");
		exit(1);
	}

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags   = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	while (!__io_canceled) {
		if (dbus_connection_read_write_dispatch(conn, 100) != TRUE)
			break;
	}

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez/Manager",
			"org.bluez.Security", "UnregisterDefaultPasskeyAgent");

	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		exit(1);
	}

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &agent_path);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	dbus_connection_close(conn);

	return 0;
}
