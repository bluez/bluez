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

#include "error.h"
#include "logging.h"

#define AUDIO_ERROR_INTERFACE "org.bluez.audio.Error"

/* FIXME: Remove these once global error functions exist */
static DBusHandlerResult error_reply(DBusConnection *conn, DBusMessage *msg,
					const char *name, const char *descr)
{
	DBusMessage *derr;

	if (!conn || !msg)
		return DBUS_HANDLER_RESULT_HANDLED;

	derr = dbus_message_new_error(msg, name, descr);
	if (!derr) {
		error("Unable to allocate new error return");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	return send_message_and_unref(conn, derr);
}

DBusHandlerResult err_invalid_args(DBusConnection *conn, DBusMessage *msg,
						const char *descr)
{
	return error_reply(conn, msg, AUDIO_ERROR_INTERFACE ".InvalidArguments",
			descr ? descr : "Invalid arguments in method call");
}

DBusHandlerResult err_already_connected(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, AUDIO_ERROR_INTERFACE ".AlreadyConnected",
				"Already connected to a device");
}

DBusHandlerResult err_not_connected(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, AUDIO_ERROR_INTERFACE ".NotConnected",
				"Not connected to any device");
}

DBusHandlerResult err_not_supported(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, AUDIO_ERROR_INTERFACE ".NotSupported",
			"The service is not supported by the remote device");
}

DBusHandlerResult err_connect_failed(DBusConnection *conn,
					DBusMessage *msg, const char *err)
{
	return error_reply(conn, msg, AUDIO_ERROR_INTERFACE ".ConnectFailed",
				err);
}

DBusHandlerResult err_does_not_exist(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, AUDIO_ERROR_INTERFACE ".DoesNotExist",
				"Does not exist");
}

DBusHandlerResult err_not_available(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, ".NotAvailable",
				"Not available");
}

DBusHandlerResult err_failed(DBusConnection *conn, DBusMessage *msg,
				const char *dsc)
{
	return error_reply(conn, msg, AUDIO_ERROR_INTERFACE ".Failed", dsc);
}
