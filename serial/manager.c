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

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "dbus.h"
#include "logging.h"

#include "manager.h"

#define SERIAL_MANAGER_PATH		"/org/bluez/serial"
#define SERIAL_MANAGER_INTERFACE	"org.bluez.serial.Manager"
#define SERIAL_ERROR_INTERFACE		"org.bluez.serial.Error"

#define PATH_LENGTH		32
#define BASE_UUID			"00000000-0000-1000-8000-00805F9B34FB"

struct pending_connection {
	DBusConnection	*conn;
	DBusMessage	*msg;
	bdaddr_t	src;		/* Source address */
	char		*addr;		/* Destination address */
	char		*adapter_path;	/* Adapter D-Bus path */
};

static DBusConnection *connection = NULL;

static void pending_connection_free(struct pending_connection *pc)
{
	if (pc->conn)
		dbus_connection_unref(pc->conn);
	if (pc->msg)
		dbus_message_unref(pc->msg);
	if (pc->addr)
		g_free(pc->addr);
	if (pc->adapter_path)
		g_free(pc->adapter_path);
}

static DBusHandlerResult err_connection_failed(DBusConnection *conn,
					DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
			SERIAL_ERROR_INTERFACE".ConnectionAttemptFailed", str));
}

static DBusHandlerResult err_failed(DBusConnection *conn,
				DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				SERIAL_ERROR_INTERFACE ".Failed", str));
}

static DBusHandlerResult err_invalid_args(DBusConnection *conn,
					DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				SERIAL_ERROR_INTERFACE ".InvalidArguments", str));
}

static DBusHandlerResult err_not_supported(DBusConnection *conn,
							DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
			SERIAL_ERROR_INTERFACE ".NotSupported",
			"The service is not supported by the remote device"));
}

static void record_reply(DBusPendingCall *call, void *data)
{
	struct pending_connection *pc = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	sdp_record_t *rec;
	const uint8_t *rec_bin;
	sdp_list_t *protos;
	DBusError derr;
	int len, scanned, ch;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
				"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pc->conn, pc->msg, derr.message);
		else
			err_not_supported(pc->conn, pc->msg);

		error("GetRemoteServiceRecord: %s(%s)",
					derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pc->conn, pc->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pc->conn, pc->msg);
		error("Invalid service record length");
		goto fail;
	}

	rec = sdp_extract_pdu(rec_bin, &scanned);
	if (!rec) {
		error("Can't extract SDP record.");
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	if (len != scanned || (sdp_get_access_protos(rec, &protos) < 0)) {
		sdp_record_free(rec);
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch < 1 || ch > 30) {
		error("Channel out of range: %d", ch);
		sdp_record_free(rec);
		err_not_supported(pc->conn, pc->msg);
	}

	/* FIXME: Check if there is a pending connection */

fail:
	dbus_message_unref(reply);
	dbus_error_free(&derr);
	pending_connection_free(pc);
}

static int get_record(struct pending_connection *pc, uint32_t handle,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", pc->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceRecord");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pc->addr,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pc->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pc, NULL);
	dbus_message_unref(msg);
	dbus_pending_call_unref(pending);

	return 0;
}

static void handles_reply(DBusPendingCall *call, void *data)
{
	struct pending_connection *pc = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
				"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pc->conn, pc->msg, derr.message);
		else
			err_not_supported(pc->conn, pc->msg);

		error("GetRemoteServiceHandles: %s(%s)",
					derr.name, derr.message);
		goto fail;
	}
	
	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle,
				&len, DBUS_TYPE_INVALID)) {
		err_not_supported(pc->conn, pc->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	if (get_record(pc, *phandle, record_reply) < 0) {
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	dbus_message_unref(reply);
	return;
fail:
	dbus_message_unref(reply);
	dbus_error_free(&derr);
	pending_connection_free(pc);
}

static int get_handles(struct pending_connection *pc, const char *uuid,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", pc->adapter_path,
				"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pc->addr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pc->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pc, NULL);
	dbus_message_unref(msg);
	dbus_pending_call_unref(pending);

	return 0;
}

static DBusHandlerResult connect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusError derr;
	bdaddr_t src;
	struct pending_connection *pc;
	const char *addr, *pattern;
	char *endptr;
	long val;
	int dev_id;

	/* FIXME: Check if it already exist or if there is pending connect */

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dev_id = hci_get_route(NULL);
	if ((dev_id < 0) ||  (hci_devba(dev_id, &src) < 0))
		return err_failed(conn, msg, "Adapter not available");

	pc = g_new0(struct pending_connection, 1);
	pc->conn = dbus_connection_ref(conn);
	pc->msg = dbus_message_ref(msg);
	bacpy(&pc->src, &src);
	pc->addr = g_strdup(addr);
	pc->adapter_path = g_malloc0(16);
	snprintf(pc->adapter_path, 16, "/org/bluez/hci%d", dev_id);

	/* UUID 128*/
	if (strlen(pattern) == 36) {
		char tmp[37];

		strcpy(tmp, pattern);
		tmp[4] = '0';
		tmp[5] = '0';
		tmp[6] = '0';
		tmp[7] = '0';

		if (strcasecmp(BASE_UUID, tmp) != 0) {
			pending_connection_free(pc);
			return err_invalid_args(conn, msg, "invalid UUID");
		}

		if (get_handles(pc, pattern, handles_reply) < 0) {
			pending_connection_free(pc);
			return err_not_supported(conn, msg);
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	errno = 0;
	val = strtol(pattern, &endptr, 0);
	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
			(errno != 0 && val == 0) || (pattern == endptr)) {
		pending_connection_free(pc);
		return err_invalid_args(conn, msg, "Invalid pattern");
	}

	/* Record handle: starts at 0x10000 */
	if (strncasecmp("0x", pattern, 2) == 0) {
		if (val < 0x10000) {
			pending_connection_free(pc);
			return err_invalid_args(conn, msg,
					"invalid record handle");
		}

		if (get_record(pc, val, record_reply) < 0) {
			pending_connection_free(pc);
			return err_not_supported(conn, msg);
	
		}
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* RFCOMM Channel range: 1 - 30 */
	if (val < 1 || val > 30) {
		pending_connection_free(pc);
		return err_invalid_args(conn, msg,
				"invalid RFCOMM channel");
	}

	/* FIXME: Connect */
	info("Connecting to channel: %d", val);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult cancel_connect_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult manager_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *iface, *member;

	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Accept messages from the manager interface only */
	if (strcmp(SERIAL_MANAGER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "ConnectService") == 0)
		return connect_service(conn, msg, data);

	if (strcmp(member, "DisconnectService") == 0)
		return disconnect_service(conn, msg, data);

	if (strcmp(member, "CancelConnectService") == 0)
		return cancel_connect_service(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void manager_unregister(DBusConnection *conn, void *data)
{

}

/* Virtual table to handle manager object path hierarchy */
static const DBusObjectPathVTable manager_table = {
	.message_function	= manager_message,
	.unregister_function	= manager_unregister,
};

int serial_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	if (dbus_connection_register_object_path(connection,
			SERIAL_MANAGER_PATH, &manager_table, NULL) == FALSE) {
		error("D-Bus failed to register %s path", SERIAL_MANAGER_PATH);
		dbus_connection_unref(connection);

		return -1;
	}

	info("Registered manager path:%s", SERIAL_MANAGER_PATH);

	return 0;
}

void serial_exit(void)
{
	dbus_connection_unregister_object_path(connection, SERIAL_MANAGER_PATH);

	dbus_connection_unref(connection);
	connection = NULL;
}
