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

#include "lib/uuid.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"

static const bt_uuid_t primary_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_PRIM_SVC_UUID };
static const bt_uuid_t secondary_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_SND_SVC_UUID };

struct gatt_db {
	uint16_t next_handle;
	struct queue *services;
};

struct gatt_db_attribute {
	uint16_t handle;
	bt_uuid_t uuid;
	uint16_t val_len;
	uint8_t value[0];
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

static struct gatt_db_attribute *new_attribute(const bt_uuid_t *type,
							const uint8_t *val,
							uint16_t len)
{
	struct gatt_db_attribute *attribute;

	attribute = malloc0(sizeof(struct gatt_db_attribute) + len);
	if (!attribute)
		return NULL;

	attribute->uuid = *type;
	memcpy(&attribute->value, val, len);
	attribute->val_len = len;

	return attribute;
}

static int uuid_to_le(const bt_uuid_t *uuid, uint8_t *dst)
{
	switch (uuid->type) {
	case BT_UUID16:
		put_le16(uuid->value.u16, dst);
		break;
	case BT_UUID32:
		put_le32(uuid->value.u32, dst);
		break;
	default:
		bswap_128(&uuid->value.u128, dst);
		break;
	}

	return bt_uuid_len(uuid);
}

uint16_t gatt_db_add_service(struct gatt_db *db, const bt_uuid_t *uuid,
					bool primary, uint16_t num_handles)
{
	struct gatt_db_service *service;
	const bt_uuid_t *type;
	uint8_t value[16];
	uint16_t len;

	if (num_handles < 1)
		return 0;

	service = new0(struct gatt_db_service, 1);
	if (!service)
		return 0;

	service->attributes = new0(struct gatt_db_attribute *, num_handles);
	if (!service->attributes) {
		free(service);
		return 0;
	}

	if (primary)
		type = &primary_service_uuid;
	else
		type = &secondary_service_uuid;

	len = uuid_to_le(uuid, value);

	service->attributes[0] = new_attribute(type, value, len);
	if (!service->attributes[0]) {
		gatt_db_service_destroy(service);
		return 0;
	}

	if (!queue_push_tail(db->services, service)) {
		gatt_db_service_destroy(service);
		return 0;
	}

	/* TODO now we get next handle from database. We should first look
	 * for 'holes' between existing services first, and assign next_handle
	 * only if enough space was not found.
	 */
	service->attributes[0]->handle = db->next_handle;
	db->next_handle += num_handles;
	service->num_handles = num_handles;

	return service->attributes[0]->handle;
}
