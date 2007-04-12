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

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "logging.h"
#include "dbus.h"

#define NETWORK_PATH "/org/bluez/network"
#define NETWORK_MANAGER_INTERFACE "org.bluez.network.Manager"

#include "error.h"
#include "bridge.h"
#include "manager.h"
#include "server.h"
#include "connection.h"
#include "common.h"

static GSList *server_paths = NULL;	/* Network registered servers paths */
static GSList *connection_paths = NULL;	/* Network registered connections paths */

struct pending_reply {
	DBusConnection	*conn;
	DBusMessage	*msg;
	char		*addr;
	char		*path;
	char		*adapter_path;
	uint16_t	id;
};

static DBusConnection *connection = NULL;

static void pending_reply_free(struct pending_reply *pr)
{
	if (pr->addr)
		g_free(pr->addr);
	if (pr->path)
		g_free(pr->path);
	if (pr->adapter_path)
		g_free(pr->adapter_path);
	if (pr->msg)
		dbus_message_unref(pr->msg);
	if (pr->conn)
		dbus_connection_unref(pr->conn);
}

static DBusHandlerResult create_path(DBusConnection *conn,
					DBusMessage *msg, const char *path,
					const char *sname)
{
	DBusMessage *reply, *signal;

	/* emit signal when it is a new path */
	if (sname) {
		signal = dbus_message_new_signal(NETWORK_PATH,
			NETWORK_MANAGER_INTERFACE, sname);

		dbus_message_append_args(signal,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

		send_message_and_unref(conn, signal);
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_paths(DBusConnection *conn, DBusMessage *msg,
					GSList *list)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (; list; list = list->next) {
		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING,
						&list->data);
	}
	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult remove_path(DBusConnection *conn,
					DBusMessage *msg, GSList **list,
					const char *sname)
{
	const char *path;
	DBusMessage *reply, *signal;
	DBusError derr;
	GSList *l;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	l = g_slist_find_custom(*list, path, (GCompareFunc) strcmp);
	if (!l)
		return err_does_not_exist(conn, msg, "Path doesn't exist");

	g_free(l->data);
	*list = g_slist_remove(*list, l->data);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (!dbus_connection_unregister_object_path(conn, path))
		error("Network path unregister failed");

	signal = dbus_message_new_signal(NETWORK_PATH,
			NETWORK_MANAGER_INTERFACE, sname);

	dbus_message_append_args(signal,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	send_message_and_unref(conn, signal);

	return send_message_and_unref(conn, reply);
}

static void pan_record_reply(DBusPendingCall *call, void *data)
{
	struct pending_reply *pr = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	int len, scanned;
	uint8_t *rec_bin;
	sdp_record_t *rec = NULL;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
				"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceRecord failed: %s(%s)", derr.name,
			derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pr->conn, pr->msg);
		error("Invalid PAN service record length");
		goto fail;
	}

	rec = sdp_extract_pdu(rec_bin, &scanned);

	if (connection_register(pr->conn, pr->path, pr->addr, pr->id,
				rec) == -1) {
		err_failed(pr->conn, pr->msg, "D-Bus path registration failed");
		goto fail;
	}

	connection_paths = g_slist_append(connection_paths, g_strdup(pr->path));

	create_path(pr->conn, pr->msg, pr->path, "ConnectionCreated");
fail:
	sdp_record_free(rec);
	dbus_error_free(&derr);
	pending_reply_free(pr);
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static int get_record(struct pending_reply *pr, uint32_t handle,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceRecord");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pr->addr,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
}

static void pan_handle_reply(DBusPendingCall *call, void *data)
{
	struct pending_reply *pr = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
				"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pr->conn, pr->msg, derr.message);
		else
			err_not_supported(pr->conn, pr->msg);

		error("GetRemoteServiceHandles: %s(%s)", derr.name,
				derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle,
				&len, DBUS_TYPE_INVALID)) {
		err_not_supported(pr->conn, pr->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (!len) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	if (get_record(pr, *phandle, pan_record_reply) < 0) {
		err_not_supported(pr->conn, pr->msg);
		goto fail;
	}

	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	return;
fail:
	dbus_error_free(&derr);
	pending_reply_free(pr);
}

static int get_handles(struct pending_reply *pr,
			DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	const char *uuid;

	msg = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	uuid = bnep_uuid(pr->id);
	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pr->addr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
}

static void get_address_reply(DBusPendingCall *call, void *data)
{
	struct pending_reply *pr = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	const char *address;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetAddress: %s(%s)", derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID)) {
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (server_register(pr->conn, address, pr->path, pr->id) < 0) {
		err_failed(pr->conn, pr->msg, "D-Bus path registration failed");
		goto fail;
	}

	server_paths = g_slist_append(server_paths, g_strdup(pr->path));

	create_path(pr->conn, pr->msg, pr->path, "ServerCreated");
fail:
	dbus_error_free(&derr);
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	return;
}

static int get_address(struct pending_reply *pr,
			DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", pr->adapter_path,
			"org.bluez.Adapter", "GetAddress");
	if (!msg)
		return -1;

	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
}

static void default_adapter_reply(DBusPendingCall *call, void *data)
{
	struct pending_reply *pr = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	const char *adapter;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		err_connection_failed(pr->conn, pr->msg, derr.message);
		error("DefaultAdapter: %s(%s)", derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_STRING, &adapter,
				DBUS_TYPE_INVALID)) {
		err_connection_failed(pr->conn, pr->msg, derr.message);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	pr->adapter_path = g_strdup(adapter);

	if (pr->addr) {
		if (get_handles(pr, pan_handle_reply) < 0) {
			err_failed(pr->conn, pr->msg, "D-Bus path registration failed");
			goto fail;
		}
	} else if (get_address(pr, get_address_reply) < 0) {
		err_failed(pr->conn, pr->msg, "D-Bus path registration failed");
		goto fail;
	}

	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	return;
fail:
	dbus_error_free(&derr);
	pending_reply_free(pr);
}

static int get_default_adapter(struct pending_reply *pr,
		DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
			"org.bluez.Manager", "DefaultAdapter");
	if (!msg)
		return -1;

	if (dbus_connection_send_with_reply(pr->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pr, NULL);
	dbus_message_unref(msg);

	return 0;
}

static DBusHandlerResult list_servers(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return list_paths(conn, msg, server_paths);
}

static DBusHandlerResult create_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct pending_reply *pr;
	DBusError derr;
	const char *str;
	int id;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &str,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	id = bnep_service_id(str);
	if ((id != BNEP_SVC_GN) && (id != BNEP_SVC_NAP))
		return err_invalid_args(conn, msg, "Not supported");

	pr = g_new0(struct pending_reply, 1);
	pr->conn = dbus_connection_ref(conn);;
	pr->msg = dbus_message_ref(msg);
	pr->addr = NULL;
	pr->id = id;
	pr->path = g_new0(char, 32);
	snprintf(pr->path, 32, NETWORK_PATH "/server/%s", bnep_name(id));

	if (g_slist_find_custom(server_paths, pr->path,
				(GCompareFunc) strcmp)) {
		err_already_exists(conn, msg, "Server Already exists");
		pending_reply_free(pr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (get_default_adapter(pr, default_adapter_reply) < 0) {
		err_failed(conn, msg, "D-Bus path registration failed");
		pending_reply_free(pr);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult remove_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return remove_path(conn, msg, &server_paths, "ServerRemoved");
}

static DBusHandlerResult list_connections(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return list_paths(conn, msg, connection_paths);
}

static DBusHandlerResult create_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct pending_reply *pr;
	static int uid = 0;
	DBusError derr;
	const char *addr;
	const char *str;
	uint16_t id;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_STRING, &str,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	id = bnep_service_id(str);
	if ((id != BNEP_SVC_GN) && (id != BNEP_SVC_NAP))
		return err_invalid_args(conn, msg, "Not supported");

	pr = g_new0(struct pending_reply, 1);
	pr->conn = dbus_connection_ref(conn);
	pr->msg = dbus_message_ref(msg);
	pr->addr = g_strdup(addr);
	pr->id = id;
	pr->path = g_new0(char, 48);
	snprintf(pr->path, 48, NETWORK_PATH "/connection%d", uid++);

	if (get_default_adapter(pr, default_adapter_reply) < 0) {
		err_failed(conn, msg, "D-Bus path registration failed");
		pending_reply_free(pr);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult remove_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return remove_path(conn, msg, &connection_paths, "ConnectionRemoved");
}

static DBusHandlerResult manager_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path, *iface, *member;

	path = dbus_message_get_path(msg);
	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Catching fallback paths */
	if (strcmp(NETWORK_PATH, path) != 0)
		return err_unknown_connection(conn, msg);

	/* Accept messages from the manager interface only */
	if (strcmp(NETWORK_MANAGER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "ListServers") == 0)
		return list_servers(conn, msg, data);

	if (strcmp(member, "CreateServer") == 0)
		return create_server(conn, msg, data);

	if (strcmp(member, "RemoveServer") == 0)
		return remove_server(conn, msg, data);

	if (strcmp(member, "ListConnections") == 0)
		return list_connections(conn, msg, data);

	if (strcmp(member, "CreateConnection") == 0)
		return create_connection(conn, msg, data);

	if (strcmp(member, "RemoveConnection") == 0)
		return remove_connection(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	info("Unregistered manager path");

	if (server_paths) {
		g_slist_foreach(server_paths, (GFunc)g_free, NULL);
		g_slist_free(server_paths);
		server_paths = NULL;
	}

	if (connection_paths) {
		g_slist_foreach(connection_paths, (GFunc)g_free, NULL);
		g_slist_free(connection_paths);
		connection_paths = NULL;
	}

	bnep_kill_all_connections();
}

/* Virtual table to handle manager object path hierarchy */
static const DBusObjectPathVTable manager_table = {
	.message_function = manager_message,
	.unregister_function = manager_unregister,
};

int network_init(DBusConnection *conn)
{
	if (bridge_init() < 0) {
		error("Can't init bridge module");
		return -1;
	}

	if (bridge_create("pan0") < 0) {
		error("Can't create bridge");
		return -1;
	}

	if (bnep_init()) {
		error("Can't init bnep module");
		return -1;
	}

	connection = dbus_connection_ref(conn);

	/* Fallback to catch invalid network path */
	if (dbus_connection_register_fallback(connection, NETWORK_PATH,
						&manager_table, NULL) == FALSE) {
		error("D-Bus failed to register %s path", NETWORK_PATH);
		dbus_connection_unref(connection);

		return -1;
	}

	info("Registered manager path:%s", NETWORK_PATH);

	/* FIXME: Missing register stored servers */

	return 0;
}

void network_exit(void)
{
	dbus_connection_unregister_object_path(connection, NETWORK_PATH);

	dbus_connection_unref(connection);

	connection = NULL;

	if (bridge_remove("pan0") < 0)
		error("Can't remove bridge");

	bnep_cleanup();
	bridge_cleanup();
}
