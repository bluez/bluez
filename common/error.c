/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2007-2008  Fabien Chevalier <fabchevalier@free.fr>
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
#include <string.h>
#include <errno.h>

#include <gdbus.h>

#include "error.h"

DBusMessage *create_errno_message(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
							strerror(err));
}

/**
  org.bluez.Error.ConnectionAttemptFailed:

  An unexpected error (other than DeviceUnreachable) error has occured while
  attempting a connection to a device
*/
DBusHandlerResult error_connection_attempt_failed(DBusConnection *conn, DBusMessage *msg, int err)
{
	return error_common_reply(conn, msg,
			ERROR_INTERFACE ".ConnectionAttemptFailed",
			err > 0 ? strerror(err) : "Connection attempt failed");
}

/**
  org.bluez.Error.NotSupported:

  The remote device does not support the expected feature.
  Examples of use: trying to connect to audio device while audio is not
  declared in device sdp record.
*/
DBusHandlerResult error_not_supported(DBusConnection *conn, DBusMessage *msg)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".NotSupported",
							"Not supported");
}

/**
  org.bluez.Error.Canceled:

  The operation was canceled.
  Examples of use : autorization process canceled, connection canceled
*/
DBusHandlerResult error_canceled(DBusConnection *conn, DBusMessage *msg,
					const char *str)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".Canceled", str);
}

/**
  org.bluez.Error.Failed:

  This is a the most generic error.
  desc filed is MANDATORY
*/
DBusHandlerResult error_failed(DBusConnection *conn, DBusMessage *msg,
				const char * desc)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".Failed", desc);
}

/**
  org.bluez.Error.Failed:

  This is a the most generic error, instantiated form a UNIX errno number.
*/
DBusHandlerResult error_failed_errno(DBusConnection *conn, DBusMessage *msg,
					int err)
{
	const char *desc = strerror(err);

	return error_failed(conn, msg, desc);
}

/* Helper function - internal use only */
DBusHandlerResult error_common_reply(DBusConnection *conn, DBusMessage *msg,
					const char *name, const char *descr)
{
	DBusMessage *derr;
	dbus_bool_t ret;

	if (!conn || !msg)
		return DBUS_HANDLER_RESULT_HANDLED;

	derr = dbus_message_new_error(msg, name, descr);
	if (!derr)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	ret = dbus_connection_send(conn, derr, NULL);

	dbus_message_unref(derr);

	return DBUS_HANDLER_RESULT_HANDLED;
}
