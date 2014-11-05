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

struct pending_read {
	unsigned int id;
	gatt_db_attribute_read_t func;
	void *user_data;
};

struct pending_write {
	unsigned int id;
	gatt_db_attribute_write_t func;
	void *user_data;
};

struct gatt_db_attribute {
	struct gatt_db_service *service;
	uint16_t handle;
	bt_uuid_t uuid;
	uint32_t permissions;
	uint16_t value_len;
	uint8_t *value;

	gatt_db_read_t read_func;
	gatt_db_write_t write_func;
	void *user_data;

	unsigned int read_id;
	struct queue *pending_reads;

	unsigned int write_id;
	struct queue *pending_writes;
};

struct gatt_db_service {
	bool active;
	uint16_t num_handles;
	struct gatt_db_attribute **attributes;
};

static void attribute_destroy(struct gatt_db_attribute *attribute)
{
	/* Attribute was not initialized by user */
	if (!attribute)
		return;

	queue_destroy(attribute->pending_reads, free);
	queue_destroy(attribute->pending_writes, free);

	free(attribute->value);
	free(attribute);
}

static struct gatt_db_attribute *new_attribute(struct gatt_db_service *service,
							const bt_uuid_t *type,
							const uint8_t *val,
							uint16_t len)
{
	struct gatt_db_attribute *attribute;

	attribute = new0(struct gatt_db_attribute, 1);
	if (!attribute)
		return NULL;

	attribute->service = service;
	attribute->uuid = *type;
	attribute->value_len = len;
	if (len) {
		attribute->value = malloc0(len);
		if (!attribute->value)
			goto failed;

		memcpy(attribute->value, val, len);
	}

	attribute->pending_reads = queue_new();
	if (!attribute->pending_reads)
		goto failed;

	attribute->pending_writes = queue_new();
	if (!attribute->pending_reads)
		goto failed;

	return attribute;

failed:
	attribute_destroy(attribute);
	return NULL;
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

struct gatt_db_attribute *gatt_db_add_service(struct gatt_db *db,
						const bt_uuid_t *uuid,
						bool primary,
						uint16_t num_handles)
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

	service->attributes[0] = new_attribute(service, type, value, len);
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

	return service->attributes[0];
}

bool gatt_db_remove_service(struct gatt_db *db,
					struct gatt_db_attribute *attrib)
{
	struct gatt_db_service *service;

	if (!db || !attrib)
		return false;

	service = attrib->service;

	queue_remove(db->services, service);

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

static struct gatt_db_attribute *
attribute_update(struct gatt_db_service *service, int index)
{
	uint16_t previous_handle;

	/* We call this function with index > 0, because index 0 is reserved
	 * for service declaration, and is set in add_service()
	 */
	previous_handle = service->attributes[index - 1]->handle;
	service->attributes[index]->handle = previous_handle + 1;

	return service->attributes[index];
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

struct gatt_db_attribute *
gatt_db_service_add_characteristic(struct gatt_db_attribute *attrib,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					uint8_t properties,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	struct gatt_db_service *service;
	uint8_t value[MAX_CHAR_DECL_VALUE_LEN];
	uint16_t len = 0;
	int i;

	if (!attrib)
		return NULL;

	service = attrib->service;

	i = get_attribute_index(service, 1);
	if (!i)
		return NULL;

	value[0] = properties;
	len += sizeof(properties);
	/* We set handle of characteristic value, which will be added next */
	put_le16(get_handle_at_index(service, i - 1) + 2, &value[1]);
	len += sizeof(uint16_t);
	len += uuid_to_le(uuid, &value[3]);

	service->attributes[i] = new_attribute(service, &characteristic_uuid,
								value, len);
	if (!service->attributes[i])
		return NULL;

	attribute_update(service, i++);

	service->attributes[i] = new_attribute(service, uuid, NULL, 0);
	if (!service->attributes[i]) {
		free(service->attributes[i - 1]);
		return NULL;
	}

	set_attribute_data(service->attributes[i], read_func, write_func,
							permissions, user_data);

	return attribute_update(service, i);
}

struct gatt_db_attribute *
gatt_db_service_add_descriptor(struct gatt_db_attribute *attrib,
					const bt_uuid_t *uuid,
					uint32_t permissions,
					gatt_db_read_t read_func,
					gatt_db_write_t write_func,
					void *user_data)
{
	struct gatt_db_service *service;
	int i;

	if (!attrib)
		return false;

	service = attrib->service;

	i = get_attribute_index(service, 0);
	if (!i)
		return NULL;

	service->attributes[i] = new_attribute(service, uuid, NULL, 0);
	if (!service->attributes[i])
		return NULL;

	set_attribute_data(service->attributes[i], read_func, write_func,
							permissions, user_data);

	return attribute_update(service, i);
}

struct gatt_db_attribute *
gatt_db_service_add_included(struct gatt_db_attribute *attrib,
					struct gatt_db_attribute *include)
{
	struct gatt_db_service *service, *included;
	uint8_t value[MAX_INCLUDED_VALUE_LEN];
	uint16_t included_handle, len = 0;
	int index;

	if (!attrib || !include)
		return NULL;

	service = attrib->service;
	included = include->service;

	/* Adjust include to point to the first attribute */
	if (include != included->attributes[0])
		include = included->attributes[0];

	included_handle = include->handle;

	put_le16(included_handle, &value[len]);
	len += sizeof(uint16_t);

	put_le16(included_handle + included->num_handles - 1, &value[len]);
	len += sizeof(uint16_t);

	/* The Service UUID shall only be present when the UUID is a 16-bit
	 * Bluetooth UUID. Vol 2. Part G. 3.2
	 */
	if (include->value_len == sizeof(uint16_t)) {
		memcpy(&value[len], include->value, include->value_len);
		len += include->value_len;
	}

	index = get_attribute_index(service, 0);
	if (!index)
		return NULL;

	service->attributes[index] = new_attribute(service,
							&included_service_uuid,
							value, len);
	if (!service->attributes[index])
		return NULL;

	/* The Attribute Permissions shall be read only and not require
	 * authentication or authorization. Vol 2. Part G. 3.2
	 *
	 * TODO handle permissions
	 */
	set_attribute_data(service->attributes[index], NULL, NULL, 0, NULL);

	return attribute_update(service, index);
}

bool gatt_db_service_set_active(struct gatt_db_attribute *attrib, bool active)
{
	if (!attrib)
		return false;

	attrib->service->active = active;

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
	uint16_t grp_start, grp_end;

	if (!service->active)
		return;

	/* Don't want more results as they have different size */
	if (search_data->stop_search)
		return;

	if (bt_uuid_cmp(&search_data->uuid, &service->attributes[0]->uuid))
		return;

	grp_start = service->attributes[0]->handle;
	grp_end = grp_start + service->num_handles - 1;

	if (grp_end < search_data->start_handle ||
				grp_start > search_data->end_handle)
		return;

	if (service->attributes[0]->handle < search_data->start_handle ||
		service->attributes[0]->handle > search_data->end_handle)
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

	queue_push_tail(search_data->queue, service->attributes[0]);
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

		queue_push_tail(search_data->queue, attribute);
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

		queue_push_tail(search_data->queue, attribute);
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

		queue_push_tail(search_data->queue, attribute);
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
	uint16_t handle = PTR_TO_UINT(user_data);
	uint16_t start, end;

	start = service->attributes[0]->handle;
	end = start + service->num_handles;

	return (start <= handle) && (handle < end);
}

struct gatt_db_attribute *gatt_db_get_attribute(struct gatt_db *db,
							uint16_t handle)
{
	struct gatt_db_service *service;
	uint16_t service_handle;

	if (!db || !handle)
		return NULL;

	service = queue_find(db->services, find_service_for_handle,
							UINT_TO_PTR(handle));
	if (!service)
		return NULL;

	service_handle = service->attributes[0]->handle;

	/*
	 * We can safely get attribute from attributes array with offset,
	 * because find_service_for_handle() check if given handle is
	 * in service range.
	 */
	return service->attributes[handle - service_handle];
}

const bt_uuid_t *gatt_db_attribute_get_type(struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return NULL;

	return &attrib->uuid;
}

uint16_t gatt_db_attribute_get_handle(struct gatt_db_attribute *attrib)
{
	if (!attrib)
		return 0;

	return attrib->handle;
}

bool gatt_db_attribute_get_service_uuid(struct gatt_db_attribute *attrib,
							bt_uuid_t *uuid)
{
	struct gatt_db_service *service;

	if (!attrib || !uuid)
		return false;

	service = attrib->service;

	if (service->attributes[0]->value_len == sizeof(uint16_t)) {
		uint16_t value;

		value = get_le16(service->attributes[0]->value);
		bt_uuid16_create(uuid, value);

		return true;
	}

	if (service->attributes[0]->value_len == sizeof(uint128_t)) {
		uint128_t value;

		bswap_128(service->attributes[0]->value, &value);
		bt_uuid128_create(uuid, value);

		return true;
	}

	return false;
}

bool gatt_db_attribute_get_service_handles(struct gatt_db_attribute *attrib,
						uint16_t *start_handle,
						uint16_t *end_handle)
{
	struct gatt_db_service *service;

	if (!attrib)
		return false;

	service = attrib->service;

	if (start_handle)
		*start_handle = service->attributes[0]->handle;

	if (end_handle)
		*end_handle = service->attributes[0]->handle +
						service->num_handles - 1;

	return true;
}

bool gatt_db_attribute_get_permissions(struct gatt_db_attribute *attrib,
							uint32_t *permissions)
{
	if (!attrib || !permissions)
		return false;

	*permissions = attrib->permissions;

	return true;
}

bool gatt_db_attribute_read(struct gatt_db_attribute *attrib, uint16_t offset,
				uint8_t opcode, bdaddr_t *bdaddr,
				gatt_db_attribute_read_t func, void *user_data)
{
	uint8_t *value;

	if (!attrib || !func)
		return false;

	if (attrib->read_func) {
		struct pending_read *p;

		p = new0(struct pending_read, 1);
		if (!p)
			return false;

		p->id = ++attrib->read_id;
		p->func = func;
		p->user_data = user_data;

		queue_push_tail(attrib->pending_reads, p);

		attrib->read_func(attrib, p->id, offset, opcode, bdaddr,
							attrib->user_data);
		return true;
	}

	/* Check boundary if value is stored in the db */
	if (offset > attrib->value_len)
		return false;

	/* Guard against invalid access if offset equals to value length */
	value = offset == attrib->value_len ? NULL : &attrib->value[offset];

	func(attrib, 0, value, attrib->value_len - offset, user_data);

	return true;
}

static bool find_pending(const void *a, const void *b)
{
	const struct pending_read *p = a;
	unsigned int id = PTR_TO_UINT(b);

	return p->id == id;
}

bool gatt_db_attribute_read_result(struct gatt_db_attribute *attrib,
					unsigned int id, int err,
					const uint8_t *value, size_t length)
{
	struct pending_read *p;

	if (!attrib || !id)
		return false;

	p = queue_remove_if(attrib->pending_reads, find_pending,
							UINT_TO_PTR(id));
	if (!p)
		return false;

	p->func(attrib, err, value, length, p->user_data);

	free(p);

	return true;
}

bool gatt_db_attribute_write(struct gatt_db_attribute *attrib, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, bdaddr_t *bdaddr,
					gatt_db_attribute_write_t func,
					void *user_data)
{
	if (!attrib || !func)
		return false;

	if (attrib->write_func) {
		struct pending_write *p;

		p = new0(struct pending_write, 1);
		if (!p)
			return false;

		p->id = ++attrib->write_id;
		p->func = func;
		p->user_data = user_data;

		queue_push_tail(attrib->pending_writes, p);

		attrib->write_func(attrib, p->id, offset, value, len, opcode,
						bdaddr, attrib->user_data);
		return true;
	}

	/* For values stored in db allocate on demand */
	if (!attrib->value || offset >= attrib->value_len ||
				len > (unsigned) (attrib->value_len - offset)) {
		attrib->value = realloc(attrib->value, len + offset);
		if (!attrib->value)
			return false;
		/* Init data in the first allocation */
		if (!attrib->value_len)
			memset(attrib->value, 0, offset);
		attrib->value_len = len + offset;
	}

	memcpy(&attrib->value[offset], value, len);

	func(attrib, 0, user_data);

	return true;
}

bool gatt_db_attribute_write_result(struct gatt_db_attribute *attrib,
						unsigned int id, int err)
{
	struct pending_write *p;

	if (!attrib || !id)
		return false;

	p = queue_remove_if(attrib->pending_writes, find_pending,
							UINT_TO_PTR(id));
	if (!p)
		return false;

	p->func(attrib, err, p->user_data);

	free(p);

	return true;
}
