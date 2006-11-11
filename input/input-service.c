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

#include <signal.h>

#include "dbus.h"
#include "logging.h"

#include <dbus/dbus.h>

#define INPUT_PATH "/org/bluez/input"

static DBusConnection *connection = NULL;

static DBusHandlerResult start_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	info("Starting example service");

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		error("Can't create reply message");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult stop_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	info("Stopping example service");

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		error("Can't create reply message");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

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
	if (dbus_message_is_method_call(msg, "org.bluez.ServiceAgent", "Start"))
		return start_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.ServiceAgent", "Stop"))
		return stop_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.ServiceAgent", "Release"))
		return release_message(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


static const DBusObjectPathVTable input_table = {
	.message_function = input_message,
};

int input_dbus_init(void)
{
	DBusError err;
	DBusMessage *msg, *reply;
	const char *name = "Input service";
	const char *description = "A service for input devices";
	const char *input_path = INPUT_PATH;

	connection = init_dbus(NULL, NULL);
	if (!connection)
		return -1;

	dbus_error_init(&err);

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

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1,
								&err);

	dbus_message_unref(msg);

	if (!reply) {
		error("Can't register service agent");
		if (dbus_error_is_set(&err)) {
			error("%s", err.message);
			dbus_error_free(&err);
		}
		return -1;
	}

	return 0;
}

