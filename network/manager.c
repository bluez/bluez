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

struct manager {
	bdaddr_t src;		/* Local adapter BT address */
	GSList *servers;	/* Network registered servers paths */
	GSList *connections;	/* Network registered connections paths */
};

static DBusConnection *connection = NULL;

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

static DBusHandlerResult list_servers(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct manager *mgr = data;

	return list_paths(conn, msg, mgr->servers);
}

static DBusHandlerResult create_path(DBusConnection *conn,
					DBusMessage *msg, char *path,
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

	g_free(path);
	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult create_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct manager *mgr = data;
	DBusError derr;
	const char *str;
	char *path;
	uint16_t id;

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

	path = g_new0(char, 32);
	snprintf(path, 32, NETWORK_PATH "/server/%s", bnep_name(id));

	/* Path already registered */
	if (g_slist_find_custom(mgr->servers, path, (GCompareFunc) strcmp))
		return create_path(conn, msg, path, NULL); /* Return already exist error */

	if (server_register(conn, path, id) == -1) {
		err_failed(conn, msg, "D-Bus path registration failed");
		g_free(path);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	mgr->servers = g_slist_append(mgr->servers, g_strdup(path));

	return create_path(conn, msg, path, "ServerCreated");
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

static DBusHandlerResult remove_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct manager *mgr = data;

	return remove_path(conn, msg, &mgr->servers, "ServerRemoved");
}

static DBusHandlerResult list_connections(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct manager *mgr = data;

	return list_paths(conn, msg, mgr->connections);
}

static DBusHandlerResult create_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct manager *mgr = data;
	static int uid = 0;
	DBusError derr;
	const char *addr;
	const char *str;
	char *path;
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

	path = g_new0(char, 32);
	snprintf(path, 32, NETWORK_PATH "/connection%d", uid++);

	if (connection_register(conn, path, addr, id) == -1) {
		err_failed(conn, msg, "D-Bus path registration failed");
		g_free(path);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	mgr->connections = g_slist_append(mgr->connections, g_strdup(path));

	return create_path(conn, msg, path, "ConnectionCreated");
}

static DBusHandlerResult remove_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct manager *mgr = data;

	return remove_path(conn, msg, &mgr->connections, "ConnectionRemoved");
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

static void manager_free(struct manager *mgr)
{
	if (!mgr)
		return;

	if (mgr->servers)
		g_slist_free(mgr->servers);

	if (mgr->connections)
		g_slist_free(mgr->connections);

	g_free (mgr);
	bnep_kill_all_connections();
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	struct manager *mgr = data;

	info("Unregistered manager path");

	manager_free(mgr);
}

/* Virtual table to handle manager object path hierarchy */
static const DBusObjectPathVTable manager_table = {
	.message_function = manager_message,
	.unregister_function = manager_unregister,
};

int network_dbus_init(void)
{
	struct manager *mgr;
	bdaddr_t src;
	int dev_id;

	connection = init_dbus(NULL, NULL, NULL);
	if (!connection)
		return -1;

	dbus_connection_set_exit_on_disconnect(connection, TRUE);

	mgr = g_new0(struct manager, 1);

	/* Fallback to catch invalid network path */
	if (!dbus_connection_register_fallback(connection, NETWORK_PATH,
						&manager_table, mgr)) {
		error("D-Bus failed to register %s path", NETWORK_PATH);
		goto fail;
	}

	info("Registered manager path:%s", NETWORK_PATH);

	/* Set the default adapter */
	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(&src);
	if (dev_id < 0) {
		error("Bluetooth device not available");
		goto fail;
	}

	if (hci_devba(dev_id, &src) < 0) {
		error("Can't get local adapter device info");
		goto fail;
	}

	bacpy(&mgr->src, &src);

	return 0;

fail:
	manager_free(mgr);

	return -1;
}

void network_dbus_exit(void)
{
	dbus_connection_unregister_object_path(connection, NETWORK_PATH);

	dbus_connection_unref(connection);
}

void internal_service(const char *identifier)
{
	DBusMessage *msg, *reply;
	const char *name = "Network service", *desc = "";

	info("Registering service");

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RegisterService");
	if (!msg) {
		error("Can't create service register method");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &identifier,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &desc, DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1,
							  NULL);
	if (!reply) {
		error("Can't register service");
		return;
	}

	dbus_message_unref(msg);
	dbus_message_unref(reply);

	dbus_connection_flush(connection);
}

int network_init(void)
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

	return network_dbus_init();
}

void network_exit(void)
{
	network_dbus_exit();

	if (bridge_remove("pan0") < 0)
		error("Can't remove bridge");

	bnep_cleanup();
	bridge_cleanup();
}
