/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020 Google LLC
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

#define RSSI_DEFAULT_HIGH_THRESHOLD -50
#define RSSI_DEFAULT_LOW_THRESHOLD -70
#define RSSI_DEFAULT_HIGH_TIMEOUT 10
#define RSSI_DEFAULT_LOW_TIMEOUT 5

void adv_monitor_add_manager(DBusConnection *conn, GDBusProxy *proxy);
void adv_monitor_remove_manager(DBusConnection *conn);
void adv_monitor_register_app(DBusConnection *conn);
void adv_monitor_unregister_app(DBusConnection *conn);
void adv_monitor_add_monitor(DBusConnection *conn, char *type,
				gboolean rssi_enabled, int argc, char *argv[]);
void adv_monitor_print_monitor(DBusConnection *conn, int monitor_idx);
void adv_monitor_remove_monitor(DBusConnection *conn, int monitor_idx);
void adv_monitor_get_supported_info(void);
