/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
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
#include <stdint.h>
#include <stddef.h>

#define BT_GATT_UUID_SIZE 16

struct bt_gatt_client;

struct bt_gatt_client *bt_gatt_client_new(struct bt_att *att, uint16_t mtu);

struct bt_gatt_client *bt_gatt_client_ref(struct bt_gatt_client *client);
void bt_gatt_client_unref(struct bt_gatt_client *client);

typedef void (*bt_gatt_client_destroy_func_t)(void *user_data);
typedef void (*bt_gatt_client_callback_t)(bool success, uint8_t att_ecode,
							void *user_data);
typedef void (*bt_gatt_client_debug_func_t)(const char *str, void *user_data);
typedef void (*bt_gatt_client_write_long_callback_t)(bool success,
					bool reliable_error, uint8_t att_ecode,
					void *user_data);

bool bt_gatt_client_is_ready(struct bt_gatt_client *client);
bool bt_gatt_client_set_ready_handler(struct bt_gatt_client *client,
					bt_gatt_client_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy);
bool bt_gatt_client_set_debug(struct bt_gatt_client *client,
					bt_gatt_client_debug_func_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy);

typedef struct {
	uint16_t handle;
	uint8_t uuid[BT_GATT_UUID_SIZE];
} bt_gatt_descriptor_t;

typedef struct {
	uint16_t start_handle;
	uint16_t end_handle;
	uint16_t value_handle;
	uint8_t properties;
	uint8_t uuid[BT_GATT_UUID_SIZE];
	const bt_gatt_descriptor_t *descs;
	size_t num_descs;
} bt_gatt_characteristic_t;

typedef struct {
	uint16_t start_handle;
	uint16_t end_handle;
	uint8_t uuid[BT_GATT_UUID_SIZE];
	const bt_gatt_characteristic_t *chrcs;
	size_t num_chrcs;
} bt_gatt_service_t;

struct bt_gatt_service_iter {
	struct bt_gatt_client *client;
	void *ptr;
};

bool bt_gatt_service_iter_init(struct bt_gatt_service_iter *iter,
						struct bt_gatt_client *client);
bool bt_gatt_service_iter_next(struct bt_gatt_service_iter *iter,
						bt_gatt_service_t *service);
bool bt_gatt_service_iter_next_by_handle(struct bt_gatt_service_iter *iter,
						uint16_t start_handle,
						bt_gatt_service_t *service);
bool bt_gatt_service_iter_next_by_uuid(struct bt_gatt_service_iter *iter,
					const uint8_t uuid[BT_GATT_UUID_SIZE],
					bt_gatt_service_t *service);

typedef void (*bt_gatt_client_read_callback_t)(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data);

bool bt_gatt_client_read_value(struct bt_gatt_client *client,
					uint16_t value_handle,
					bt_gatt_client_read_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy);
bool bt_gatt_client_read_long_value(struct bt_gatt_client *client,
					uint16_t value_handle, uint16_t offset,
					bt_gatt_client_read_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy);

bool bt_gatt_client_write_without_response(struct bt_gatt_client *client,
					uint16_t value_handle,
					bool signed_write,
					uint8_t *value, uint16_t length);
bool bt_gatt_client_write_value(struct bt_gatt_client *client,
					uint16_t value_handle,
					uint8_t *value, uint16_t length,
					bt_gatt_client_callback_t callback,
					void *user_data,
					bt_gatt_client_destroy_func_t destroy);
bool bt_gatt_client_write_long_value(struct bt_gatt_client *client,
				bool reliable,
				uint16_t value_handle, uint16_t offset,
				uint8_t *value, uint16_t length,
				bt_gatt_client_write_long_callback_t callback,
				void *user_data,
				bt_gatt_client_destroy_func_t destroy);
