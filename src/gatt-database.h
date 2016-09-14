/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  Google Inc.
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

struct btd_gatt_database;

struct btd_gatt_database *btd_gatt_database_new(struct btd_adapter *adapter);
void btd_gatt_database_destroy(struct btd_gatt_database *database);

struct gatt_db *btd_gatt_database_get_db(struct btd_gatt_database *database);
