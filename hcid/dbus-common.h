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

#define BASE_PATH		"/org/bluez"
#define ADAPTER_PATH_INDEX	10

#define MAX_PATH_LENGTH 64

int str2uuid(uuid_t *uuid, const char *string);

int l2raw_connect(const char *local, const bdaddr_t *remote);

#define check_address(address) bachk(address)

void hcid_dbus_exit(void);
int hcid_dbus_init(void);
void hcid_dbus_unregister(void);

void dbus_message_iter_append_dict_entry(DBusMessageIter *dict,
					const char *key, int type, void *val);

dbus_bool_t dbus_connection_emit_property_changed(DBusConnection *conn,
						const char *path,
						const char *interface,
						const char *name,
						int type, void *value);
