// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Open Mobile Platform LLC <community@omp.ru>
 *
 *
 */

#include <stdint.h>

#define LAST_CHARGES_SIZE 8
#define MAX_CHARGE_STEP 5

struct bt_battery;

struct bt_battery *bt_battery_new(void);
void bt_battery_free(struct bt_battery *battery);

uint8_t bt_battery_charge(struct bt_battery *battery, uint8_t percentage);
