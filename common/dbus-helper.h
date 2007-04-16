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

#define DBUS_TYPE_STRING_ARRAY_AS_STRING (DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING)
#define DBUS_TYPE_BYTE_ARRAY_AS_STRING   (DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING)

DBusHandlerResult dbus_connection_send_and_unref(DBusConnection *connection,
							DBusMessage *message);

dbus_bool_t dbus_connection_create_object_path(DBusConnection *connection,
					const char *path, void *user_data,
					DBusObjectPathUnregisterFunction function);

dbus_bool_t dbus_connection_destroy_object_path(DBusConnection *connection,
							const char *path);

typedef struct DBusMethodVTable DBusMethodVTable;

struct DBusMethodVTable {
	const char *name;
	DBusObjectPathMessageFunction message_function;
	const char *signature;
	const char *reply;
};

typedef struct DBusPropertyVTable DBusPropertyVTable;

struct DBusPropertyVTable {
};

dbus_bool_t dbus_connection_register_interface(DBusConnection *connection,
					const char *path, const char *interface,
					DBusMethodVTable *methods,
					DBusPropertyVTable *properties);

dbus_bool_t dbus_connection_unregister_interface(DBusConnection *connection,
					const char *path, const char *interface);
void dbus_message_iter_append_dict_entry(DBusMessageIter *dict,
					const char *key, int type, void *val);

