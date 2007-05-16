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

int connection_register(DBusConnection *conn, const char *path, bdaddr_t *src,
		bdaddr_t *dst, uint16_t id, const char *name, const char *desc);
int connection_store(DBusConnection *conn, const char *path);
int connection_remove_stored(DBusConnection *conn, const char *path);
int connection_find_data(DBusConnection *conn, const char *path,
			const char *pattern);
gboolean connection_has_pending(DBusConnection *conn, const char *path);
