/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020 Google LLC
 *
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
