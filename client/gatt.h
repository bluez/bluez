/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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

void gatt_add_service(GDBusProxy *proxy);
void gatt_remove_service(GDBusProxy *proxy);

void gatt_add_characteristic(GDBusProxy *proxy);
void gatt_remove_characteristic(GDBusProxy *proxy);

void gatt_add_descriptor(GDBusProxy *proxy);
void gatt_remove_descriptor(GDBusProxy *proxy);

void gatt_list_attributes(const char *device);
GDBusProxy *gatt_select_attribute(GDBusProxy *parent, const char *path);
char *gatt_attribute_generator(const char *text, int state);

void gatt_read_attribute(GDBusProxy *proxy, int argc, char *argv[]);
void gatt_write_attribute(GDBusProxy *proxy, int argc, char *argv[]);
void gatt_notify_attribute(GDBusProxy *proxy, bool enable);

void gatt_acquire_write(GDBusProxy *proxy, const char *arg);
void gatt_release_write(GDBusProxy *proxy, const char *arg);

void gatt_acquire_notify(GDBusProxy *proxy, const char *arg);
void gatt_release_notify(GDBusProxy *proxy, const char *arg);

void gatt_add_manager(GDBusProxy *proxy);
void gatt_remove_manager(GDBusProxy *proxy);

void gatt_register_app(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[]);
void gatt_unregister_app(DBusConnection *conn, GDBusProxy *proxy);

void gatt_register_service(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[]);
void gatt_unregister_service(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[]);

void gatt_register_chrc(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[]);
void gatt_unregister_chrc(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[]);

void gatt_register_desc(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[]);
void gatt_unregister_desc(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[]);

void gatt_register_include(DBusConnection *conn, GDBusProxy *proxy,
					int argc, char *argv[]);
void gatt_unregister_include(DBusConnection *conn, GDBusProxy *proxy,
						int argc, char *argv[]);
