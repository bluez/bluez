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

struct gatt_db;

struct gatt_db *gatt_db_new(void);
void gatt_db_destroy(struct gatt_db *db);

uint16_t gatt_db_add_service(struct gatt_db *db, const bt_uuid_t *uuid,
					bool primary, uint16_t num_handles);
bool gatt_db_remove_service(struct gatt_db *db, uint16_t handle);

typedef void (*gatt_db_read_t) (uint16_t handle, uint16_t offset,
					uint8_t att_opcode, bdaddr_t *bdaddr,
					void *user_data);

typedef void (*gatt_db_write_t) (uint16_t handle, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t att_opcode, bdaddr_t *bdaddr,
					void *user_data);

uint16_t gatt_db_add_characteristic(struct gatt_db *db, uint16_t handle,
						const bt_uuid_t *uuid,
						uint8_t permissions,
						uint8_t properties,
						gatt_db_read_t read_func,
						gatt_db_write_t write_func,
						void *user_data);

uint16_t gatt_db_add_char_descriptor(struct gatt_db *db, uint16_t handle,
						const bt_uuid_t *uuid,
						uint8_t permissions,
						gatt_db_read_t read_func,
						gatt_db_write_t write_func,
						void *user_data);

uint16_t gatt_db_add_included_service(struct gatt_db *db, uint16_t handle,
						uint16_t included_handle);

bool gatt_db_service_set_active(struct gatt_db *db, uint16_t handle,
								bool active);

void gatt_db_read_by_group_type(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							const bt_uuid_t type,
							struct queue *queue);

void gatt_db_find_by_type(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							const bt_uuid_t *type,
							struct queue *queue);

void gatt_db_read_by_type(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							const bt_uuid_t type,
							struct queue *queue);

void gatt_db_find_information(struct gatt_db *db, uint16_t start_handle,
							uint16_t end_handle,
							struct queue *queue);

bool gatt_db_read(struct gatt_db *db, uint16_t handle, uint16_t offset,
					uint8_t att_opcode, bdaddr_t *bdaddr,
					uint8_t **value, int *length);

bool gatt_db_write(struct gatt_db *db, uint16_t handle, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t att_opcode, bdaddr_t *bdaddr);

const bt_uuid_t *gatt_db_get_attribute_type(struct gatt_db *db,
							uint16_t handle);

uint16_t gatt_db_get_end_handle(struct gatt_db *db, uint16_t handle);
