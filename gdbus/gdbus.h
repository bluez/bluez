/*
 *
 *  D-Bus helper library
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

typedef void (* GDBusWatchFunction) (DBusConnection *connection,
							void *user_data);

typedef gboolean (* GDBusSignalFunction) (DBusConnection *connection,
					DBusMessage *message, void *user_data);

DBusConnection *g_dbus_setup_bus(DBusBusType type, const char *name,
							DBusError *error);

DBusConnection *g_dbus_setup_private(DBusBusType type, const char *name,
							DBusError *error);

gboolean g_dbus_request_name(DBusConnection *connection, const char *name,
							DBusError *error);

gboolean g_dbus_set_disconnect_function(DBusConnection *connection,
				GDBusWatchFunction function,
				void *user_data, DBusFreeFunction destroy);

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
					const GDBusMethodTable *methods,
					const GDBusSignalTable *signals,
					const GDBusPropertyTable *properties,
					void *user_data,
					GDBusDestroyFunction destroy);
gboolean g_dbus_unregister_interface(DBusConnection *connection,
					const char *path, const char *name);

DBusMessage *g_dbus_create_error(DBusMessage *message, const char *name,
						const char *format, ...);
DBusMessage *g_dbus_create_error_valist(DBusMessage *message, const char *name,
					const char *format, va_list args);
DBusMessage *g_dbus_create_reply(DBusMessage *message, int type, ...);
DBusMessage *g_dbus_create_reply_valist(DBusMessage *message,
						int type, va_list args);

gboolean g_dbus_send_message(DBusConnection *connection, DBusMessage *message);
gboolean g_dbus_send_reply(DBusConnection *connection,
				DBusMessage *message, int type, ...);
gboolean g_dbus_send_reply_valist(DBusConnection *connection,
				DBusMessage *message, int type, va_list args);

gboolean g_dbus_emit_signal(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name, int type, ...);
gboolean g_dbus_emit_signal_valist(DBusConnection *connection,
				const char *path, const char *interface,
				const char *name, int type, va_list args);

guint g_dbus_add_service_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction connect,
				GDBusWatchFunction disconnect,
				void *user_data, GDBusDestroyFunction destroy);
guint g_dbus_add_disconnect_watch(DBusConnection *connection, const char *name,
				GDBusWatchFunction function,
				void *user_data, GDBusDestroyFunction destroy);
guint g_dbus_add_signal_watch(DBusConnection *connection,
				const char *sender, const char *path,
				const char *interface, const char *member,
				GDBusSignalFunction function, void *user_data,
				GDBusDestroyFunction destroy);
gboolean g_dbus_remove_watch(DBusConnection *connection, guint tag);
void g_dbus_remove_all_watches(DBusConnection *connection);

#ifdef __cplusplus
}
#endif

#endif /* __GDBUS_H */
