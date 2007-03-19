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

#include <glib.h>

#include "logging.h"
#include "dbus.h"
#include "error.h"

#define NETWORK_CONNECTION_INTERFACE "org.bluez.network.Manager"

#include "connection.h"

struct network_conn {
	char *path;
};

static DBusHandlerResult get_address(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_uuid(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_name(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_descriptor(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_interface(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult connect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult is_connected(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult connection_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *iface, *member;

	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (strcmp(NETWORK_CONNECTION_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "GetAddress") == 0)
		return get_address(conn, msg, data);

	if (strcmp(member, "GetUUID") == 0)
		return get_uuid(conn, msg, data);

	if (strcmp(member, "GetName") == 0)
		return get_name(conn, msg, data);

	if (strcmp(member, "GetDescription") == 0)
		return get_descriptor(conn, msg, data);

	if (strcmp(member, "GetInterface") == 0)
		return get_interface(conn, msg, data);

	if (strcmp(member, "Connect") == 0)
		return connect(conn, msg, data);

	if (strcmp(member, "Disconnect") == 0)
		return disconnect(conn, msg, data);

	if (strcmp(member, "IsConnected") == 0)
		return is_connected(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void connection_free(struct network_conn *nc)
{
	if (!nc)
		return;

	if (nc->path)
		g_free(nc->path);

	g_free(nc);
}

static void connection_unregister(DBusConnection *conn, void *data)
{
	struct network_conn *nc = data;

	info("Unregistered connection path %s", nc->path);

	connection_free(nc);
}

/* Virtual table to handle connection object path hierarchy */
static const DBusObjectPathVTable connection_table = {
	.message_function = connection_message,
	.unregister_function = connection_unregister,
};

int connection_register(DBusConnection *conn, const char *path)
{
	struct network_conn *nc;

	if (!conn)
		return -1;

	nc = g_new0(struct network_conn, 1);

	/* register path */
	if (!dbus_connection_register_object_path(conn, path,
						&connection_table, nc)) {
		error("D-Bus failed to register %s path", path);
		goto fail;
	}

	nc->path = g_strdup(path);
	info("Registered connection path:%s", path);

	return 0;
fail:
	connection_free(nc);
	return -1;
}
