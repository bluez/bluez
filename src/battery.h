/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Google LLC
 *
 *
 */

struct btd_adapter;
struct btd_battery;
struct btd_battery_provider_manager;

struct btd_battery *btd_battery_register(const char *path, const char *source,
					 const char *provider_path);
struct btd_battery *btd_battery_register_component(const char *device_path,
					 const char *identifier,
					 const char *source);
bool btd_battery_unregister(struct btd_battery *battery);

/* Pass UINT8_MAX as percentage to mark the level as unknown, which
 * invalidates the Percentage property instead of setting it.
 */
bool btd_battery_update(struct btd_battery *battery, uint8_t percentage);

/* charging is 0 or 1 when known, or -1 to mark the state as unknown, which
 * invalidates the Charging property instead of setting it.
 */
bool btd_battery_update_charging(struct btd_battery *battery, int charging);

struct btd_battery_provider_manager *
btd_battery_provider_manager_create(struct btd_adapter *adapter);
void btd_battery_provider_manager_destroy(
	struct btd_battery_provider_manager *manager);
