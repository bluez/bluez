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

#include <string.h>
#include <signal.h>

#include "dbus.h"
#include "logging.h"

#include <dbus/dbus.h>

#define INPUT_PATH "/org/bluez/input"

static int started = 0;

static DBusConnection *connection = NULL;

static DBusHandlerResult start_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	info("Starting input service");

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		error("Can't create reply message");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	started = 1;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult stop_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	info("Stopping input service");

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		error("Can't create reply message");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	started = 0;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult release_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		error("Can't create reply message");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	info("Got Release method. Exiting.");

	raise(SIGTERM);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult input_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *interface;
	const char *member;

	interface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (strcmp(interface, "org.bluez.ServiceAgent") == 0) {
		if (strcmp(member, "Start") == 0)
			return start_message(conn, msg, data);
		if (strcmp(member, "Stop") == 0)
			return stop_message(conn, msg, data);
		if (strcmp(member, "Release") == 0)
			return release_message(conn, msg, data);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (strcmp(interface, "org.bluez.Input") != 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	/* Handle Input interface methods here */

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable input_table = {
	.message_function = input_message,
};

static void register_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Registering failed: %s", err.message);
		dbus_error_free(&err);
		raise(SIGTERM);
	}
	else 
		debug("Successfully registered");

	dbus_message_unref(reply);
}

int input_dbus_init(void)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	const char *name = "Input service";
	const char *description = "A service for input devices";
	const char *input_path = INPUT_PATH;

	connection = init_dbus("org.bluez.input", NULL, NULL);
	if (!connection)
		return -1;

	if (!dbus_connection_register_object_path(connection, input_path,
						&input_table, NULL)) {
		error("D-Bus failed to register %s path", INPUT_PATH);
		return -1;
	}

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
					"org.bluez.Manager", "RegisterService");
	if (!msg) {
		error("Can't allocate new method call");
		return -1;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &input_path,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_STRING, &description,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending Register method call failed");
		dbus_message_unref(msg);
		return -1;
	}

	dbus_pending_call_set_notify(pending, register_reply, NULL, NULL);
	dbus_message_unref(msg);

	return 0;
}

