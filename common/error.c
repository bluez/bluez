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

#include <string.h>
#include <errno.h>

#include "dbus-helper.h"
#include "error.h"

/**
  org.bluez.Error.DeviceUnreachable:

  The remote device is either powered down or out of range.
*/
DBusHandlerResult error_device_unreachable(DBusConnection *conn, DBusMessage *msg)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".DeviceUnreachable",
							"Device Unreachable");
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
				err ? strerror(err) : "Connection attempt failed");
}

/**
  org.bluez.Error.AlreadyConnected:

  A connection request has been received on an already connected device.
*/
DBusHandlerResult error_already_connected(DBusConnection *conn, DBusMessage *msg)
{
	return error_common_reply(conn, msg,
				ERROR_INTERFACE ".AlreadyConnected",
				"Already connected to a device");
}

/**
  org.bluez.Error.InProgress:

  Error returned if an operation is in progress. Since
  this is a generic error that can be used in various
  situations, the error message should be more clear
  about what is in progress. For example "Bonding in
  progress".
  */
DBusHandlerResult error_in_progress(DBusConnection *conn, DBusMessage *msg,
						const char *str)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".InProgress", str);
}

/**
  org.bluez.Error.InvalidArguments:

  The DBUS request does not contain the right number of
  arguments with the right type, or the arguments are there but
  their value is wrong, or does not makes sense in the current context.
*/
DBusHandlerResult error_invalid_arguments(DBusConnection *conn, DBusMessage *msg,
						const char *descr)
{
	return error_common_reply(conn, msg,
				ERROR_INTERFACE ".InvalidArguments",
				descr ? descr : "Invalid arguments in method call");
}

/**
  org.bluez.Error.OutOfMemory:

  Not enough memory to execute the request.
  Error returned when a memory allocation via malloc()
  fails. This error is similar to ENOMEM.
*/
DBusHandlerResult error_out_of_memory(DBusConnection *conn, DBusMessage *msg)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".OutOfMemory",
							"Out of memory");
}

/**
  org.bluez.Error.NotAvailable:

  The requested information is not there.
  Examples of use: Adapter object when remote info is not available, or Database
  object record is not found
*/
DBusHandlerResult error_not_available(DBusConnection *conn, DBusMessage *msg)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".NotAvailable",
							"Not available");
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
  org.bluez.Error.NotConnected:

  The remote device is not connected, while the method call
  would expect it to be, or is not in the expected state to
  perform the action
*/
DBusHandlerResult error_not_connected(DBusConnection *conn, DBusMessage *msg)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".NotConnected",
							"Not connected");
}

/**
  org.bluez.Error.AlreadyExists:

  One of the requested elements already exists
  Examples of use: Bonding, record, passkey agent, auth agent,
  hid device ... already exists
*/
DBusHandlerResult error_already_exists(DBusConnection *conn, DBusMessage *msg,
					const char *str)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".AlreadyExists", str);
}

/**
  org.bluez.Error.DoesNotExist:

  One of the requested elements does not exist
  Examples of use: Bonding, record, passkey agent, auth agent, bluetooth device
  ... does not exist.
*/
DBusHandlerResult error_does_not_exist(DBusConnection *conn, DBusMessage *msg,
					const char *str)
{
	return error_common_reply(conn, msg, ERROR_INTERFACE ".DoesNotExist", str);
}

/**
  org.bluez.Error.DoesNotExist:

  Same as error_does_not_exist, but with device error message
*/
DBusHandlerResult error_device_does_not_exist(DBusConnection *conn,
						DBusMessage *msg)
{
	return error_does_not_exist(conn, msg, "Device does not exist");
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

	if (!conn || !msg)
		return DBUS_HANDLER_RESULT_HANDLED;

	derr = dbus_message_new_error(msg, name, descr);
	if (!derr)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return dbus_connection_send_and_unref(conn, derr);
}
