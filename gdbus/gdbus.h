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

#ifndef __GDBUS_H
#define __GDBUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dbus/dbus.h>
#include <glib.h>

typedef void (* GDBusDisconnectFunction) (void *user_data);

DBusConnection *g_dbus_setup_bus(DBusBusType type, const char *name,
							DBusError *error);

gboolean g_dbus_set_disconnect_function(DBusConnection *connection,
				GDBusDisconnectFunction function,
				void *user_data, DBusFreeFunction destroy);

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
void dbus_message_iter_append_variant(DBusMessageIter *iter, int type, void *val);
void dbus_message_iter_append_dict_entry(DBusMessageIter *dict,
					const char *key, int type, void *val);
void dbus_message_iter_append_dict_valist(DBusMessageIter *iter,
					const char *first_key,
					va_list var_args);
void dbus_message_iter_append_dict(DBusMessageIter *iter,
					const char *first_key, ...);
dbus_bool_t dbus_connection_emit_signal(DBusConnection *conn, const char *path,
					const char *interface, const char *name,
					int first, ...);

dbus_bool_t dbus_connection_emit_signal_valist(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name,
						int first,
						va_list var_args);
dbus_bool_t dbus_connection_emit_property_changed(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name,
						int type, void *value);

static inline DBusHandlerResult send_message_and_unref(DBusConnection *conn,
							DBusMessage *msg)
{
	if (msg) {
		dbus_connection_send(conn, msg, NULL);
		dbus_message_unref(msg);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

typedef void (* GDBusDestroyFunction) (void *user_data);

typedef DBusMessage * (* GDBusMethodFunction) (DBusConnection *connection,
					DBusMessage *message, void *user_data);

typedef enum {
	G_DBUS_METHOD_FLAG_DEPRECATED = (1 << 0),
	G_DBUS_METHOD_FLAG_NOREPLY    = (1 << 1),
	G_DBUS_METHOD_FLAG_ASYNC      = (1 << 2),
} GDBusMethodFlags;

typedef enum {
	G_DBUS_SIGNAL_FLAG_DEPRECATED = (1 << 0),
} GDBusSignalFlags;

typedef enum {
	G_DBUS_PROPERTY_FLAG_DEPRECATED = (1 << 0),
} GDBusPropertyFlags;

typedef struct {
	const char *name;
	const char *signature;
	const char *reply;
	GDBusMethodFunction function;
	GDBusMethodFlags flags;
} GDBusMethodTable;

typedef struct {
	const char *name;
	const char *signature;
	GDBusSignalFlags flags;
} GDBusSignalTable;

typedef struct {
	const char *name;
	const char *type;
	GDBusPropertyFlags flags;
} GDBusPropertyTable;

gboolean g_dbus_register_interface(DBusConnection *connection,
					const char *path, const char *name,
					GDBusMethodTable *methods,
					GDBusSignalTable *signals,
					GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy);
gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name);

DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args);
DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...);
DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...);
DBusMessage *g_dbus_create_reply_valist(DBusMessage *message,
						int type, va_list args);

gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message);
gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...);
gboolean g_dbus_send_reply_valist(DBusConnection *connection,
				DBusMessage *message, int type, va_list args);

typedef void (*name_cb_t)(const char *name, void *user_data);

guint name_listener_add(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);
int name_listener_remove(DBusConnection *connection, const char *name,
				name_cb_t func, void *user_data);
gboolean name_listener_id_remove(guint id);
int name_listener_indicate_disconnect(DBusConnection *connection);

#ifdef __cplusplus
}
#endif

#endif /* __GDBUS_H */
