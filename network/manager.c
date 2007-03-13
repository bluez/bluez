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

#include <glib.h>

#include "logging.h"
#include "dbus.h"

#define NETWORK_PATH "/org/bluez/network"
#define NETWORK_MANAGER_INTERFACE "org.bluez.network.Manager"
#define NETWORK_ERROR_INTERFACE "org.bluez.Error"

#include "manager.h"

struct manager {
	bdaddr_t src;		/* Local adapter BT address */
	GSList *servers;	/* Network registered servers paths */
};

static DBusConnection *connection = NULL;

static DBusHandlerResult err_unknown_connection(DBusConnection *conn,
							DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				NETWORK_ERROR_INTERFACE ".UnknownConnection",
				"Unknown connection path"));
}

static DBusHandlerResult list_servers(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult create_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult remove_server(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult list_connections(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult create_connection(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult remove_connections(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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

	if (strcmp(member, "RemoveConnections") == 0)
		return remove_connections(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void manager_free(struct manager *mgr)
{
	if (!mgr)
		return;

	g_free (mgr);
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

	/* Fallback to catch invalid device path */
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

	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, NULL);
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
	network_dbus_init();
	return 0;
}

void network_exit(void)
{
	network_dbus_exit();
}
