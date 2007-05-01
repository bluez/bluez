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
#include <string.h>
#include <glib.h>

#include "dbus.h"
#include "logging.h"

#include "manager.h"

#define SERIAL_MANAGER_PATH "/org/bluez/serial"
#define SERIAL_PORT_PATH "/org/bluez/serial/port"
#define SERIAL_MANAGER_INTERFACE "org.bluez.serial.Manager"
#define SERIAL_PORT_INTERFACE "org.bluez.serial.Port"
#define SERIAL_ERROR_INTERFACE "org.bluez.serial.Error"

#define PATH_LENGTH		32

static DBusConnection *connection = NULL;
static GSList *port_paths = NULL;
static unsigned int next_id = 0;

struct serial_port {
	char		*owner;
	int16_t		id;		/* Device id */
};

static void serial_port_free(struct serial_port *sp)
{
	if (!sp)
		return;
	if (sp->owner)
		g_free(sp->owner);
	g_free(sp);
}

static DBusHandlerResult err_does_not_exist(DBusConnection *conn,
							DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				SERIAL_ERROR_INTERFACE ".DoesNotExist",
				"Port doesn't exist"));
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

static DBusHandlerResult err_unknown_port(DBusConnection *conn,
						DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				SERIAL_ERROR_INTERFACE ".UnknownPort",
				"Unknown port path"));
}

static DBusHandlerResult port_connect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult port_disconnect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult port_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *iface, *member;

	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Accept messages from the port interface only */
	if (strcmp(SERIAL_PORT_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "Connect") == 0)
		return port_connect(conn, msg, data);

	if (strcmp(member, "Disconnect") == 0)
		return port_disconnect(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void port_handler_unregister(DBusConnection *conn, void *data)
{
	/* FIXME: Disconnect if applied */
	serial_port_free(data);
}

/* Virtual table to handle port object path hierarchy */
static const DBusObjectPathVTable port_table = {
	.message_function	= port_message,
	.unregister_function	= port_handler_unregister,
};

static int port_register(DBusConnection *conn,
				const char *path, const char *owner)
{
	struct serial_port *sp;
	DBusMessage *signal;

	if (!conn || !owner)
		return -EINVAL;

	sp = g_new0(struct serial_port, 1);

	/* FIXME: Create the RFCOMM device node */
	sp->id		= -1;
	sp->owner	= g_strdup(owner);

	/* Register path */
	if (!dbus_connection_register_object_path(conn, path,
						&port_table, sp)) {
		serial_port_free(sp);
		return -1;
	}

	signal = dbus_message_new_signal(SERIAL_MANAGER_PATH,
				SERIAL_MANAGER_INTERFACE, "PortCreated");

	dbus_message_append_args(signal,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	send_message_and_unref(conn, signal);

	info("Registered serial port path:%s", path);

	return 0;
}

static int port_unregister(DBusConnection *conn,
				const char *path, const char *owner)
{
	struct serial_port *sp;

	if (!conn || !owner)
		return -EINVAL;

	if (!dbus_connection_get_object_path_data(conn, path, (void *) &sp) || !sp)
		return -ENOENT;

	if (strcmp(sp->owner, owner) != 0)
		return -EACCES;

	/* FIXME: If it is connected return EPERM or disconnect */

	dbus_connection_unregister_object_path(conn, path);

	return 0;
}

static DBusHandlerResult create_port(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	char port_path[PATH_LENGTH];
	DBusMessage *reply;
	DBusError derr;
	const char *addr;
	const char *pattern;
	const char *ppath = port_path;

	/* FIXME: Check if it already exist */

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Pattern can be a service or a channel */

	/* FIXME: Missing SDP search */

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	snprintf(port_path, PATH_LENGTH, SERIAL_PORT_PATH"%d", next_id++);

	if (port_register(conn, port_path, dbus_message_get_sender(msg)) < 0) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, "D-Bus path registration failed");
	}

	port_paths = g_slist_append(port_paths, g_strdup(port_path));

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult remove_port(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusError derr;
	const char *path;
	GSList *l;
	int err;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	l = g_slist_find_custom(port_paths, path, (GCompareFunc) strcmp);
	if (!l)
		return err_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	err = port_unregister(conn, path, dbus_message_get_sender(msg));
	if (err < 0) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, strerror(-err));
	}

	g_free(l->data);
	port_paths = g_slist_remove(port_paths, l->data);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_ports(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	GSList *l;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (l = port_paths; l; l= l->next) {
		dbus_message_iter_append_basic(&array_iter,
				DBUS_TYPE_STRING, &l->data);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult manager_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path, *iface, *member;

	path = dbus_message_get_path(msg);
	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Catching fallback paths */
	if (strcmp(SERIAL_MANAGER_PATH, path) != 0)
		return err_unknown_port(conn, msg);

	/* Accept messages from the manager interface only */
	if (strcmp(SERIAL_MANAGER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "CreatePort") == 0)
		return create_port(conn, msg, data);

	if (strcmp(member, "RemovePort") == 0)
		return remove_port(conn, msg, data);

	if (strcmp(member, "ListPorts") == 0)
		return list_ports(conn, msg, data);

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

	/* Fallback to catch invalid serial path */
	if (dbus_connection_register_fallback(connection, SERIAL_MANAGER_PATH,
						&manager_table, NULL) == FALSE) {
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
