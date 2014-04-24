/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdbool.h>

#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"

struct gatt_db {
	uint16_t next_handle;
	struct queue *services;
};

struct gatt_db_attribute {
};

struct gatt_db_service {
	uint16_t num_handles;
	struct gatt_db_attribute **attributes;
};

struct gatt_db *gatt_db_new(void)
{
	struct gatt_db *db;

	db = new0(struct gatt_db, 1);
	if (!db)
		return NULL;

	db->services = queue_new();
	if (!db->services) {
		free(db);
		return NULL;
	}

	db->next_handle = 0x0001;

	return db;
}

static void gatt_db_service_destroy(void *data)
{
	struct gatt_db_service *service = data;
	int i;

	for (i = 0; i < service->num_handles; i++)
		free(service->attributes[i]);

	free(service->attributes);
	free(service);
}

void gatt_db_destroy(struct gatt_db *db)
{
	queue_destroy(db->services, gatt_db_service_destroy);
	free(db);
}
