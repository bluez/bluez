/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
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

#include <bluetooth/bluetooth.h>
#include <dbus/dbus.h>

#define MANAGER_INTERFACE "org.bluez.Manager"

dbus_bool_t manager_init(DBusConnection *conn, const char *path);
void manager_cleanup(DBusConnection *conn, const char *path);

const char *manager_get_base_path(void);
struct btd_adapter *manager_find_adapter(const bdaddr_t *sba);
struct btd_adapter *manager_find_adapter_by_address(const char *address);
struct btd_adapter *manager_find_adapter_by_path(const char *path);
struct btd_adapter *manager_find_adapter_by_id(int id);
GSList *manager_get_adapters(void);
int manager_register_adapter(int id, gboolean devup);
int manager_unregister_adapter(int id);
int manager_start_adapter(int id);
int manager_stop_adapter(int id);
void manager_add_adapter(const char *path);
int manager_get_default_adapter();
void manager_set_default_adapter(int id);
void manager_update_svc(struct btd_adapter *adapter, uint8_t svc);
void btd_manager_set_offline(gboolean offline);
