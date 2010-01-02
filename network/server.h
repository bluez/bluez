/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
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

int server_init(DBusConnection *conn, const char *iface_prefix,
		gboolean secure);
void server_exit();
int server_register(struct btd_adapter *adapter, uint16_t id);
int server_unregister(struct btd_adapter *adapter, uint16_t id);
int server_register_from_file(const char *path, const bdaddr_t *src,
		uint16_t id, const char *filename);

int server_store(const char *path);

int server_find_data(const char *path, const char *pattern);
