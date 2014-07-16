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
#define MAX_INCLUDED_VALUE_LEN 6

static const bt_uuid_t primary_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_PRIM_SVC_UUID };
static const bt_uuid_t secondary_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_SND_SVC_UUID };
static const bt_uuid_t characteristic_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_CHARAC_UUID };
static const bt_uuid_t included_service_uuid = { .type = BT_UUID16,
					.value.u16 = GATT_INCLUDE_UUID };

struct gatt_db {
	uint16_t next_handle;
	struct queue *services;
};

struct gatt_db_attribute {
	uint16_t handle;
	bt_uuid_t uuid;
	uint32_t permissions;
	uint16_t value_len;
	uint8_t *value;

	gatt_db_read_t read_func;
	gatt_db_write_t write_func;
	void *user_data;
};

struct gatt_db_service {
	bool active;
	uint16_t num_handles;
	struct gatt_db_attribute **attributes;
};

static bool match_service_by_handle(const void *data, const void *user_data)
{
	const struct gatt_db_service *service = data;

	return service->attributes[0]->handle == PTR_TO_INT(user_data);
}

static struct gatt_db_attribute *new_attribute(const bt_uuid_t *type,
							const uint8_t *val,
							uint16_t len)
{
	struct gatt_db_attribute *attribute;

	attribute = new0(struct gatt_db_attribute, 1);
	if (!attribute)
		return NULL;

	attribute->uuid = *type;
	attribute->value_len = len;
	if (len) {
		attribute->value = malloc0(len);
		if (!attribute->value) {
			free(attribute);
			return NULL;
		}

		memcpy(attribute->value, val, len);
	}

	return attribute;
}

static void attribute_destroy(struct gatt_db_attribute *attribute)
{
	/* Attribute was not initialized by user */
	if (!attribute)
		return;

	free(attribute->value);
	free(attribute);
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
		attribute_destroy(service->attributes[i]);

	free(service->attributes);
	free(service);
}

void gatt_db_destroy(struct gatt_db *db)
{
	if (!db)
		return;

	queue_destroy(db->services, gatt_db_service_destroy);
	free(db);
}

static int uuid_to_le(const bt_uuid_t *uuid, uint8_t *dst)
{
	bt_uuid_t uuid128;

	if (uuid->type == BT_UUID16) {
		put_le16(uuid->value.u16, dst);
		return bt_uuid_len(uuid);
	}

	bt_uuid_to_uuid128(uuid, &uuid128);
	bswap_128(&uuid128.value.u128, dst);
	return bt_uuid_len(&uuid128);
}

uint16_t gatt_db_add_service(struct gatt_db *db, const bt_uuid_t *uuid,
					bool primary, uint16_t num_handles)
{
	struct gatt_db_service *service;
	const bt_uuid_t *type;
	uint8_t value[16];
	uint16_t len;

	if (num_handles < 1 || (num_handles + db->next_handle) > UINT16_MAX)
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
						uint32_t permissions,
						void *user_data)
{
	attribute->permissions = permissions;
	attribute->read_func = read_func;
	attribute->write_func = write_func;
	attribute->user_data = user_data;
}

uint16_t gatt_db_add_characteristic(struct gatt_db *db, uint16_t handle,
						const bt_uuid_t *uuid,
						uint32_t permissions,
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
						uint32_t permissions,
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

uint16_t gatt_db_add_included_service(struct gatt_db *db, uint16_t handle,
						uint16_t included_handle)
{
	struct gatt_db_service *included_service;
	uint8_t value[MAX_INCLUDED_VALUE_LEN];
	uint16_t len = 0;
	struct gatt_db_service *service;
	int index;

	service = queue_find(db->services, match_service_by_handle,
							INT_TO_PTR(handle));
	if (!service)
		return 0;

	included_service = queue_find(db->services, match_service_by_handle,
						INT_TO_PTR(included_handle));

	if (!included_service)
		return 0;

	put_le16(included_handle, &value[len]);
	len += sizeof(uint16_t);

	put_le16(included_handle + included_service->num_handles - 1,
								&value[len]);
	len += sizeof(uint16_t);

	/* The Service UUID shall only be present when the UUID is a 16-bit
	 * Bluetooth UUID. Vol 2. Part G. 3.2
	 */
	if (included_service->attributes[0]->value_len == sizeof(uint16_t)) {
		memcpy(&value[len], included_service->attributes[0]->value,
				included_service->attributes[0]->value_len);
		len += included_service->attributes[0]->value_len;
	}

	index = get_attribute_index(service, 0);
	if (!index)
		return 0;

	service->attributes[index] = new_attribute(&included_service_uuid,
								value, len);
	if (!service->attributes[index])
		return 0;

	/* The Attribute Permissions shall be read only and not require
	 * authentication or authorization. Vol 2. Part G. 3.2
	 *
	 * TODO handle permissions
	 */
	set_attribute_data(service->attributes[index], NULL, NULL, 0, NULL);

	return update_attribute_handle(service, index);
}

bool gatt_db_service_set_active(struct gatt_db *db, uint16_t handle,
								bool active)
{
	struct gatt_db_service *service;

	service = queue_find(db->services, match_service_by_handle,
							INT_TO_PTR(handle));
	if (!service)
		return false;

	service->active = active;

	return true;
}

struct read_by_group_type_data {
	struct queue *queue;
	bt_uuid_t uuid;
	uint16_t start_handle;
	uint16_t end_handle;
	uint16_t uuid_size;
	bool stop_search;
};

static void read_by_group_type(void *data, void *user_data)
{
	struct read_by_group_type_data *search_data = user_data;
	struct gatt_db_service *service = data;

	if (!service->active)
		return;

	/* Don't want more results as they have different size */
	if (search_data->stop_search)
		return;

	if (bt_uuid_cmp(&search_data->uuid, &service->attributes[0]->uuid))
		return;

	if (service->attributes[0]->handle < search_data->start_handle)
		return;

	/* Remember size of uuid */
	if (!search_data->uuid_size) {
		search_data->uuid_size = service->attributes[0]->value_len;
	} else if (search_data->uuid_size !=
					service->attributes[0]->value_len) {
		/* Don't want more results. This is last */
		search_data->stop_search = true;
		return;
	}

	queue_push_tail(search_data->queue,
			UINT_TO_PTR(service->attributes[0]->handle));
}

void gatt_db_read_by_group_type(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							const bt_uuid_t type,
							struct queue *queue)
{
	struct read_by_group_type_data data;

	data.uuid = type;
	data.start_handle = start_handle;
	data.end_handle = end_handle;
	data.queue = queue;
	data.uuid_size = 0;
	data.stop_search = false;

	queue_foreach(db->services, read_by_group_type, &data);
}

struct find_by_type_value_data {
	struct queue *queue;
	bt_uuid_t uuid;
	uint16_t start_handle;
	uint16_t end_handle;
};

static void find_by_type(void *data, void *user_data)
{
	struct find_by_type_value_data *search_data = user_data;
	struct gatt_db_service *service = data;
	struct gatt_db_attribute *attribute;
	int i;

	if (!service->active)
		return;

	for (i = 0; i < service->num_handles; i++) {
		attribute = service->attributes[i];

		if (!attribute)
			continue;

		if ((attribute->handle < search_data->start_handle) ||
				(attribute->handle > search_data->end_handle))
			continue;

		if (bt_uuid_cmp(&search_data->uuid, &attribute->uuid))
			continue;

		queue_push_tail(search_data->queue,
						UINT_TO_PTR(attribute->handle));
	}
}

void gatt_db_find_by_type(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							const bt_uuid_t *type,
							struct queue *queue)
{
	struct find_by_type_value_data data;

	data.uuid = *type;
	data.start_handle = start_handle;
	data.end_handle = end_handle;
	data.queue = queue;

	queue_foreach(db->services, find_by_type, &data);
}

struct read_by_type_data {
	struct queue *queue;
	bt_uuid_t uuid;
	uint16_t start_handle;
	uint16_t end_handle;
};

static void read_by_type(void *data, void *user_data)
{
	struct read_by_type_data *search_data = user_data;
	struct gatt_db_service *service = data;
	struct gatt_db_attribute *attribute;
	int i;

	if (!service->active)
		return;

	for (i = 0; i < service->num_handles; i++) {
		attribute = service->attributes[i];
		if (!attribute)
			continue;

		if (attribute->handle < search_data->start_handle)
			continue;

		if (attribute->handle > search_data->end_handle)
			return;

		if (bt_uuid_cmp(&search_data->uuid, &attribute->uuid))
			continue;

		queue_push_tail(search_data->queue,
						UINT_TO_PTR(attribute->handle));
	}
}

void gatt_db_read_by_type(struct gatt_db *db, uint16_t start_handle,
						uint16_t end_handle,
						const bt_uuid_t type,
						struct queue *queue)
{
	struct read_by_type_data data;
	data.uuid = type;
	data.start_handle = start_handle;
	data.end_handle = end_handle;
	data.queue = queue;

	queue_foreach(db->services, read_by_type, &data);
}


struct find_information_data {
	struct queue *queue;
	uint16_t start_handle;
	uint16_t end_handle;
};

static void find_information(void *data, void *user_data)
{
	struct find_information_data *search_data = user_data;
	struct gatt_db_service *service = data;
	struct gatt_db_attribute *attribute;
	int i;

	if (!service->active)
		return;

	/* Check if service is in range */
	if ((service->attributes[0]->handle + service->num_handles - 1) <
						search_data->start_handle)
		return;

	for (i = 0; i < service->num_handles; i++) {
		attribute = service->attributes[i];
		if (!attribute)
			continue;

		if (attribute->handle < search_data->start_handle)
			continue;

		if (attribute->handle > search_data->end_handle)
			return;

		queue_push_tail(search_data->queue,
						UINT_TO_PTR(attribute->handle));
	}
}

void gatt_db_find_information(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							struct queue *queue)
{
	struct find_information_data data;

	data.start_handle = start_handle;
	data.end_handle = end_handle;
	data.queue = queue;

	queue_foreach(db->services, find_information, &data);
}

static bool find_service_for_handle(const void *data, const void *user_data)
{
	const struct gatt_db_service *service = data;
	uint16_t handle = PTR_TO_INT(user_data);
	uint16_t start, end;

	start = service->attributes[0]->handle;
	end = start + service->num_handles;

	return (start <= handle) && (handle < end);
}

bool gatt_db_read(struct gatt_db *db, uint16_t handle, uint16_t offset,
				uint8_t att_opcode, bdaddr_t *bdaddr,
				uint8_t **value, int *length)
{
	struct gatt_db_service *service;
	uint16_t service_handle;
	struct gatt_db_attribute *a;

	if (!value || !length)
		return false;

	service = queue_find(db->services, find_service_for_handle,
						INT_TO_PTR(handle));
	if (!service)
		return false;

	service_handle = service->attributes[0]->handle;

	a = service->attributes[handle - service_handle];
	if (!a)
		return false;

	/*
	 * We call callback, and set length to -1, to notify user that callback
	 * has been called. Otherwise we set length to value length in database.
	 */
	if (a->read_func) {
		*value = NULL;
		*length = -1;
		a->read_func(handle, offset, att_opcode, bdaddr, a->user_data);
	} else {
		if (offset > a->value_len)
			return false;

		*value = &a->value[offset];
		*length = a->value_len - offset;
	}

	return true;
}

bool gatt_db_write(struct gatt_db *db, uint16_t handle, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t att_opcode, bdaddr_t *bdaddr)
{
	struct gatt_db_service *service;
	uint16_t service_handle;
	struct gatt_db_attribute *a;

	service = queue_find(db->services, find_service_for_handle,
						INT_TO_PTR(handle));
	if (!service)
		return false;

	service_handle = service->attributes[0]->handle;

	a = service->attributes[handle - service_handle];
	if (!a || !a->write_func)
		return false;

	a->write_func(handle, offset, value, len, att_opcode, bdaddr,
								a->user_data);

	return true;
}

const bt_uuid_t *gatt_db_get_attribute_type(struct gatt_db *db,
							uint16_t handle)
{
	struct gatt_db_service *service;
	struct gatt_db_attribute *attribute;
	uint16_t service_handle;

	service = queue_find(db->services, find_service_for_handle,
						INT_TO_PTR(handle));
	if (!service)
		return NULL;

	service_handle = service->attributes[0]->handle;

	attribute = service->attributes[handle - service_handle];
	if (!attribute)
		return NULL;

	return &attribute->uuid;
}

uint16_t gatt_db_get_end_handle(struct gatt_db *db, uint16_t handle)
{
	struct gatt_db_service *service;

	service = queue_find(db->services, find_service_for_handle,
						INT_TO_PTR(handle));
	if (!service)
		return 0;

	return service->attributes[0]->handle + service->num_handles - 1;
}

bool gatt_db_get_service_uuid(struct gatt_db *db, uint16_t handle,
								bt_uuid_t *uuid)
{
	struct gatt_db_service *service;

	service = queue_find(db->services, find_service_for_handle,
						INT_TO_PTR(handle));
	if (!service)
		return false;

	if (service->attributes[0]->value_len == 2) {
		uint16_t value;

		value = get_le16(service->attributes[0]->value);
		bt_uuid16_create(uuid, value);

		return true;
	}

	if (service->attributes[0]->value_len == 16) {
		uint128_t value;

		bswap_128(service->attributes[0]->value, &value);
		bt_uuid128_create(uuid, value);

		return true;
	}

	return false;
}

bool gatt_db_get_attribute_permissions(struct gatt_db *db, uint16_t handle,
							uint32_t *permissions)
{
	struct gatt_db_attribute *attribute;
	struct gatt_db_service *service;
	uint16_t service_handle;

	service = queue_find(db->services, find_service_for_handle,
							INT_TO_PTR(handle));
	if (!service)
		return false;

	service_handle = service->attributes[0]->handle;

	/*
	 * We can safely get attribute from attributes array with offset,
	 * because find_service_for_handle() check if given handle is
	 * in service range.
	 */
	attribute = service->attributes[handle - service_handle];
	if (!attribute)
		return false;

	*permissions = attribute->permissions;
	return true;

}
