/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021 Google LLC
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
 */

void admin_policy_set_set_proxy(GDBusProxy *proxy);
void admin_policy_set_status_proxy(GDBusProxy *proxy);

void admin_policy_read_service_allowlist(DBusConnection *dbus_conn);
void admin_policy_set_service_allowlist(DBusConnection *dbus_conn,
							int argc, char *argv[]);
