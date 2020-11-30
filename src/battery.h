/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Google LLC
 *
 *
 */

struct btd_battery;

struct btd_battery *btd_battery_register(const char *path);
bool btd_battery_unregister(struct btd_battery *battery);
bool btd_battery_update(struct btd_battery *battery, uint8_t percentage);
