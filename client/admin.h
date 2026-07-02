// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021 Google LLC
 *
 *
 */

void admin_add_submenu(void);
void admin_remove_submenu(void);

GDBusProxy *bluetoothctl_get_default_controller(void);
GDBusProxy *bluetoothctl_find_controller(const char *address);
char *bluetoothctl_controller_generator(const char *text, int state);
