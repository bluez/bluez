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

#define NETWORK_ERROR_INTERFACE "org.bluez.Error"

DBusHandlerResult err_unknown_connection(DBusConnection *conn,
						DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				NETWORK_ERROR_INTERFACE ".UnknownConnection",
				"Unknown connection path"));
}

DBusHandlerResult err_does_not_exist(DBusConnection *conn, DBusMessage *msg,
					const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				NETWORK_ERROR_INTERFACE ".DoesNotExist", str));
}

DBusHandlerResult err_failed(DBusConnection *conn, DBusMessage *msg,
				const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				NETWORK_ERROR_INTERFACE ".Failed", str));
}

DBusHandlerResult err_invalid_args(DBusConnection *conn,
					DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				NETWORK_ERROR_INTERFACE ".InvalidArguments", str));
}
