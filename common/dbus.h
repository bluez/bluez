/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#ifndef __H_BLUEZ_DBUS_H__
#define __H_BLUEZ_DBUS_H__

#include <dbus/dbus.h>

void setup_dbus_server_with_main_loop(DBusServer *server);
void setup_dbus_with_main_loop(DBusConnection *conn);

DBusConnection *init_dbus(const char *name,
				void (*disconnect_cb)(void *), void *user_data);

DBusConnection *init_dbus_direct(const char *address);

DBusConnection *dbus_bus_system_setup_with_main_loop(const char *name,
				void (*disconnect_cb)(void *), void *user_data);

DBusHandlerResult simple_introspect(DBusConnection *conn,
					DBusMessage *msg, void *user_data);

typedef void (*name_cb_t)(const char *name, void *user_data);

int name_listener_add(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);
int name_listener_remove(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);
int name_listener_indicate_disconnect(DBusConnection *connection);

dbus_bool_t dbus_bus_get_unix_process_id(DBusConnection *conn, const char *name,
						unsigned long *pid);

static inline DBusHandlerResult send_message_and_unref(DBusConnection *conn, DBusMessage *msg)
{
	if (msg) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

int set_nonblocking(int fd);

void register_external_service(DBusConnection *conn, const char *identifier,
				const char *name, const char *description);

#endif /* __H_BLUEZ_DBUS_H__ */
