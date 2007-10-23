/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#define ERROR_INTERFACE "org.bluez.Error"

DBusHandlerResult error_failed(DBusConnection *conn, DBusMessage *msg, int err);
DBusHandlerResult error_not_ready(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_invalid_arguments(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_unknown_method(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_authorized(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_rejected(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_out_of_memory(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_no_such_adapter(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_no_such_service(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_available(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_supported(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_request_deferred(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_not_connected(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_does_not_exist(DBusConnection *conn, DBusMessage *msg, const char *str);
DBusHandlerResult error_canceled(DBusConnection *conn, DBusMessage *msg, const char *str);
DBusHandlerResult error_not_in_progress(DBusConnection *conn, DBusMessage *msg, const char *str);
DBusHandlerResult error_unsupported_major_class(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_connection_attempt_failed(DBusConnection *conn, DBusMessage *msg, int err);
DBusHandlerResult error_bonding_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_bonding_not_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_authentication_canceled(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_discover_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_connect_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_connect_not_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_record_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_passkey_agent_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_passkey_agent_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_auth_agent_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_auth_agent_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_binding_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_service_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_service_does_not_exist(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_service_search_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_connect_canceled(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_sdp_failed(DBusConnection *conn, DBusMessage *msg, int err);
DBusHandlerResult error_audit_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_trusted_device_already_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_trusted_device_does_not_exists(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_disconnect_in_progress(DBusConnection *conn, DBusMessage *msg);
DBusHandlerResult error_service_start_in_progress(DBusConnection *conn, DBusMessage *msg);
