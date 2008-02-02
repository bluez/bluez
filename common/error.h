/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2007-2008  Fabien Chevalier <fabchevalier@free.fr>
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

#include <dbus/dbus.h>

#define ERROR_INTERFACE "org.bluez.Error"

DBusHandlerResult error_device_unreachable(DBusConnection *conn,
						DBusMessage *msg);

DBusHandlerResult error_connection_attempt_failed(DBusConnection *conn,
							DBusMessage *msg,
							int err);

DBusHandlerResult error_already_connected(DBusConnection *conn,
						DBusMessage *msg);

DBusHandlerResult error_not_connected(DBusConnection *conn, DBusMessage *msg);

DBusHandlerResult error_in_progress(DBusConnection *conn, DBusMessage *msg,
					const char *str);

DBusHandlerResult error_invalid_arguments(DBusConnection *conn,
						DBusMessage *msg,
						const char *str);

DBusHandlerResult error_out_of_memory(DBusConnection *conn, DBusMessage *msg);

DBusHandlerResult error_not_available(DBusConnection *conn, DBusMessage *msg);

DBusHandlerResult error_not_supported(DBusConnection *conn,
						DBusMessage *msg);

DBusHandlerResult error_already_exists(DBusConnection *conn, DBusMessage *msg,
						const char *str);

DBusHandlerResult error_does_not_exist(DBusConnection *conn, DBusMessage *msg,
						const char *str);

DBusHandlerResult error_device_does_not_exist(DBusConnection *conn,
						DBusMessage *msg);

DBusHandlerResult error_canceled(DBusConnection *conn, DBusMessage *msg,
						const char *str);

DBusHandlerResult error_failed(DBusConnection *conn, DBusMessage *msg,
					const char *desc);

DBusHandlerResult error_failed_errno(DBusConnection *conn, DBusMessage *msg,
					int err);

DBusHandlerResult error_common_reply(DBusConnection *conn, DBusMessage *msg,
					const char *name, const char *descr);

