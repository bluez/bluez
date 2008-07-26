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

#define NETWORK_CONNECTION_INTERFACE "org.bluez.network.Connection"

int connection_init(DBusConnection *conn, const char *iface_prefix);
void connection_exit();
int connection_register(const char *path, bdaddr_t *src, bdaddr_t *dst,
			uint16_t id, const char *name, const char *desc);
int connection_store(const char *path, gboolean default_path);
int connection_remove_stored(const char *path);
int connection_find_data(const char *path, const char *pattern);
gboolean connection_has_pending(const char *path);
gboolean connection_is_connected(const char *path);
