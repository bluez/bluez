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

#define MAX_CHAR_DECL_VALUE_LEN 19

static const bt_uuid_t primary_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_PRIM_SVC_UUID };
static const bt_uuid_t secondary_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_SND_SVC_UUID };
static const bt_uuid_t characteristic_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_CHARAC_UUID };

struct gatt_db {
	uint16_t next_handle;
	struct queue *services;
};

struct gatt_db_attribute {
	uint16_t handle;
	bt_uuid_t uuid;
	uint8_t permissions;
	gatt_db_read_t read_func;
	gatt_db_write_t write_func;
	void *user_data;
	uint16_t val_len;
	uint8_t value[0];
};

struct gatt_db_service {
	uint16_t num_handles;
	struct gatt_db_attribute **attributes;
};

static bool match_service_by_handle(const void *data, const void *user_data)
{
	const struct gatt_db_service *service = data;

	return service->attributes[0]->handle == PTR_TO_INT(user_data);
}

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

bool gatt_db_remove_service(struct gatt_db *db, uint16_t handle)
{
	struct gatt_db_service *service;

	service = queue_remove_if(db->services, match_service_by_handle,
							INT_TO_PTR(handle));
	if (!service)
		return false;

	gatt_db_service_destroy(service);

	return true;
}

static uint16_t get_attribute_index(struct gatt_db_service *service,
							int end_offset)
{
	int i = 0;

	/* Here we look for first free attribute index with given offset */
	while (i < (service->num_handles - end_offset) &&
						service->attributes[i])
		i++;

	return i == (service->num_handles - end_offset) ? 0 : i;
}

static uint16_t get_handle_at_index(struct gatt_db_service *service,
								int index)
{
	return service->attributes[index]->handle;
}

static uint16_t update_attribute_handle(struct gatt_db_service *service,
								int index)
{
	uint16_t previous_handle;

	/* We call this function with index > 0, because index 0 is reserved
	 * for service declaration, and is set in add_service()
	 */
	previous_handle = service->attributes[index - 1]->handle;
	service->attributes[index]->handle = previous_handle + 1;

	return service->attributes[index]->handle;
}

static void set_attribute_data(struct gatt_db_attribute *attribute,
						gatt_db_read_t read_func,
						gatt_db_write_t write_func,
						uint8_t permissions,
						void *user_data)
{
	attribute->permissions = permissions;
	attribute->read_func = read_func;
	attribute->write_func = write_func;
	attribute->user_data = user_data;
}

uint16_t gatt_db_add_characteristic(struct gatt_db *db, uint16_t handle,
						const bt_uuid_t *uuid,
						uint8_t permissions,
						uint8_t properties,
						gatt_db_read_t read_func,
						gatt_db_write_t write_func,
						void *user_data)
{
	uint8_t value[MAX_CHAR_DECL_VALUE_LEN];
	struct gatt_db_service *service;
	uint16_t len = 0;
	int i;

	service = queue_find(db->services, match_service_by_handle,
							INT_TO_PTR(handle));
	if (!service)
		return 0;

	i = get_attribute_index(service, 1);
	if (!i)
		return 0;

	value[0] = properties;
	len += sizeof(properties);
	/* We set handle of characteristic value, which will be added next */
	put_le16(get_handle_at_index(service, i - 1) + 2, &value[1]);
	len += sizeof(uint16_t);
	len += uuid_to_le(uuid, &value[3]);

	service->attributes[i] = new_attribute(&characteristic_uuid, value,
									len);
	if (!service->attributes[i])
		return 0;

	update_attribute_handle(service, i++);

	service->attributes[i] = new_attribute(uuid, NULL, 0);
	if (!service->attributes[i]) {
		free(service->attributes[i - 1]);
		return 0;
	}

	set_attribute_data(service->attributes[i], read_func, write_func,
							permissions, user_data);

	return update_attribute_handle(service, i);
}

uint16_t gatt_db_add_char_descriptor(struct gatt_db *db, uint16_t handle,
						const bt_uuid_t *uuid,
						uint8_t permissions,
						gatt_db_read_t read_func,
						gatt_db_write_t write_func,
						void *user_data)
{
	struct gatt_db_service *service;
	int i;

	service = queue_find(db->services, match_service_by_handle,
							INT_TO_PTR(handle));
	if (!service)
		return 0;

	i = get_attribute_index(service, 0);
	if (!i)
		return 0;

	service->attributes[i] = new_attribute(uuid, NULL, 0);
	if (!service->attributes[i])
		return 0;

	set_attribute_data(service->attributes[i], read_func, write_func,
							permissions, user_data);

	return update_attribute_handle(service, i);
}
