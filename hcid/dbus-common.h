/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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

#ifndef __BLUEZ_DBUS_COMMON_H
#define __BLUEZ_DBUS_COMMON_H

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#define BASE_PATH		"/org/bluez"

#define MAX_PATH_LENGTH 64

typedef DBusHandlerResult (*service_handler_func_t) (DBusConnection *conn,
							DBusMessage *msg,
							void *user_data);

struct service_data {
	const char		*name;
	service_handler_func_t	handler_func;
};

typedef void (*name_cb_t)(const char *name, void *user_data);

int name_listener_add(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);
int name_listener_remove(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);

DBusHandlerResult simple_introspect(DBusConnection *conn, DBusMessage *msg, void *data);

service_handler_func_t find_service_handler(struct service_data *services, DBusMessage *msg);

int str2uuid(uuid_t *uuid, const char *string);

int l2raw_connect(const char *local, const bdaddr_t *remote);

int check_address(const char *addr);

static inline DBusHandlerResult send_message_and_unref(DBusConnection *conn, DBusMessage *msg)
{
	if (msg) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

DBusHandlerResult handle_method_call(DBusConnection *conn, DBusMessage *msg, void *data);

#endif /* __BLUEZ_DBUS_COMMON_H */
