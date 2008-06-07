/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#include <stdio.h>
#include <errno.h>

#include <bluetooth/sdp.h>

#include <dbus/dbus.h>
#include <gdbus.h>

#include "hcid.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "error.h"

static inline DBusHandlerResult send_message_and_unref(DBusConnection *conn,
							DBusMessage *msg)
{
	if (msg) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult error_no_such_adapter(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NoSuchAdapter",
							"No such adapter"));
}

DBusHandlerResult error_authentication_canceled(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
				    dbus_message_new_error(msg, ERROR_INTERFACE ".AuthenticationCanceled",
							   "Authentication Canceled"));
}

static const char *strsdperror(int err)
{
	switch (err) {
	case SDP_INVALID_VERSION:
		return "Invalid/unsupported SDP version";
	case SDP_INVALID_RECORD_HANDLE:
		return "Invalid Service Record Handle";
	case SDP_INVALID_SYNTAX:
		return "Invalid request syntax";
	case SDP_INVALID_PDU_SIZE:
		return "Invalid PDU size";
	case SDP_INVALID_CSTATE:
		return "Invalid Continuation State";
	default:
		return "Undefined error";
	}
}

DBusHandlerResult error_sdp_failed(DBusConnection *conn, DBusMessage *msg, int err)
{
	const char *str = strsdperror(err);

	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".Failed", str));
}
