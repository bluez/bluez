/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#define DATABASE_INTERFACE "org.bluez.Database"

dbus_bool_t database_init(DBusConnection *conn, const char *path);
void database_cleanup(DBusConnection *conn, const char *path);

int add_xml_record(DBusConnection *conn, const char *sender, bdaddr_t *src,
				const char *record, dbus_uint32_t *handle);
DBusMessage *update_xml_record(DBusConnection *conn,
				DBusMessage *msg, bdaddr_t *src);
int remove_record(DBusConnection *conn, const char *sender,
						dbus_uint32_t handle);
