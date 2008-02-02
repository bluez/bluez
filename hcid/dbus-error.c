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

#include <dbus/dbus.h>

#include <bluetooth/sdp.h>

#include "hcid.h"
#include "dbus.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "error.h"

DBusHandlerResult error_not_ready(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NotReady", "Adapter is not ready"));
}

DBusHandlerResult error_unknown_method(DBusConnection *conn, DBusMessage *msg)
{
	char error[128];
	const char *signature = dbus_message_get_signature(msg);
	const char *method = dbus_message_get_member(msg);
	const char *interface = dbus_message_get_interface(msg);

	snprintf(error, 128, "Method \"%s\" with signature \"%s\" on interface \"%s\" doesn't exist",
			method, signature, interface);

	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".UnknownMethod",
							error));
}

DBusHandlerResult error_not_authorized(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NotAuthorized",
							"Not authorized"));
}

DBusHandlerResult error_rejected(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".Rejected",
							"Rejected"));
}

DBusHandlerResult error_no_such_adapter(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NoSuchAdapter",
							"No such adapter"));
}

DBusHandlerResult error_no_such_service(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NoSuchService",
							"No such service"));
}

DBusHandlerResult error_request_deferred(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".RequestDeferred",
							"Request Deferred"));
}

DBusHandlerResult error_unsupported_major_class(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".UnsupportedMajorClass",
							"Unsupported Major Class"));
}

DBusHandlerResult error_not_in_progress(DBusConnection *conn, DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
		dbus_message_new_error(msg, ERROR_INTERFACE ".NotInProgress", str));
}

DBusHandlerResult error_bonding_already_exists(DBusConnection *conn, DBusMessage *msg)
{
	return error_already_exists(conn, msg, "Bonding already exists");
}

DBusHandlerResult error_bonding_does_not_exist(DBusConnection *conn, DBusMessage *msg)
{
	return error_does_not_exist(conn, msg, "Bonding does not exist");
}

DBusHandlerResult error_bonding_in_progress(DBusConnection *conn, DBusMessage *msg)
{
	return error_in_progress(conn, msg, "Bonding in progress");
}

DBusHandlerResult error_bonding_not_in_progress(DBusConnection *conn, DBusMessage *msg)
{
	return error_not_in_progress(conn, msg, "Bonding is not in progress");
}

DBusHandlerResult error_authentication_canceled(DBusConnection *conn, DBusMessage *msg)
{
	return send_message_and_unref(conn,
				    dbus_message_new_error(msg, ERROR_INTERFACE ".AuthenticationCanceled",
							   "Authentication Canceled"));
}

DBusHandlerResult error_discover_in_progress(DBusConnection *conn, DBusMessage *msg)
{
	return error_in_progress(conn, msg, "Discover in progress");
}

DBusHandlerResult error_record_does_not_exist(DBusConnection *conn, DBusMessage *msg)
{
	return error_does_not_exist(conn, msg, "Record does not exist");
}

DBusHandlerResult error_passkey_agent_already_exists(DBusConnection *conn, DBusMessage *msg)
{
	return error_already_exists(conn, msg, "Passkey agent already exists");
}

DBusHandlerResult error_passkey_agent_does_not_exist(DBusConnection *conn, DBusMessage *msg)
{
	return error_does_not_exist(conn, msg, "Passkey agent does not exist");
}

DBusHandlerResult error_auth_agent_already_exists(DBusConnection *conn, DBusMessage *msg)
{
	return error_already_exists(conn, msg, "Authorization agent already exists");
}

DBusHandlerResult error_auth_agent_does_not_exist(DBusConnection *conn, DBusMessage *msg)
{
	return error_does_not_exist(conn, msg, "Authorization agent does not exist");
}

DBusHandlerResult error_service_does_not_exist(DBusConnection *conn, DBusMessage *msg)
{
	return error_does_not_exist(conn, msg, "Service does not exist");
}

DBusHandlerResult error_service_search_in_progress(DBusConnection *conn, DBusMessage *msg)
{
	return error_in_progress(conn, msg, "Service search in progress");
}

DBusHandlerResult error_audit_already_exists(DBusConnection *conn, DBusMessage *msg)
{
	return error_already_exists(conn, msg, "Audit already performed");
}

DBusHandlerResult error_disconnect_in_progress(DBusConnection *conn, DBusMessage *msg)
{
	return error_in_progress(conn, msg, "Disconnection in progress");
}

DBusHandlerResult error_service_start_in_progress(DBusConnection *conn,
							DBusMessage *msg)
{
	return error_in_progress(conn, msg, "Service start in progress");
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
