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
#include <stdarg.h>
#include <dbus.h>

#define DBUS_TYPE_STRING_ARRAY_AS_STRING (DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING)
#define DBUS_TYPE_BYTE_ARRAY_AS_STRING   (DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_BYTE_AS_STRING)

DBusHandlerResult dbus_connection_send_and_unref(DBusConnection *connection,
							DBusMessage *message);

dbus_bool_t dbus_connection_create_object_path(DBusConnection *connection,
					const char *path, void *user_data,
					DBusObjectPathUnregisterFunction function);

dbus_bool_t dbus_connection_destroy_object_path(DBusConnection *connection,
							const char *path);

dbus_bool_t dbus_connection_get_object_user_data(DBusConnection *connection,
							const char *path,
							void **data_p);

typedef struct DBusMethodVTable DBusMethodVTable;

struct DBusMethodVTable {
	const char *name;
	DBusObjectPathMessageFunction message_function;
	const char *signature;
	const char *reply;
};

typedef struct DBusSignalVTable DBusSignalVTable;

struct DBusSignalVTable {
	const char *name;
	const char *signature;
};

typedef struct DBusPropertyVTable DBusPropertyVTable;

struct DBusPropertyVTable {
	const char *name;
};

dbus_bool_t dbus_connection_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					DBusMethodVTable *methods,
					DBusSignalVTable *signals,
					DBusPropertyVTable *properties);

dbus_bool_t dbus_connection_unregister_interface(DBusConnection *connection,
					const char *path, const char *name);
void dbus_message_iter_append_dict_entry(DBusMessageIter *dict,
					const char *key, int type, void *val);

dbus_bool_t dbus_connection_emit_signal(DBusConnection *conn, const char *path,
					const char *interface, const char *name,
					int first, ...);

dbus_bool_t dbus_connection_emit_signal_valist(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name,
						int first,
						va_list var_args);
