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

/* This file defines helpers for performing client-side procedures defined by
 * the Generic Attribute Profile.
 */

#include <stdbool.h>
#include <stdint.h>

struct bt_gatt_service {
	uint16_t start;
	uint16_t end;
	uint8_t uuid[16];
};

struct bt_gatt_characteristic {
	uint16_t start;
	uint16_t end;
	uint16_t value;
	uint8_t properties;
	uint8_t uuid[16];
};

struct bt_gatt_descriptor {
	uint16_t handle;
	uint8_t uuid[16];
};

struct bt_gatt_result;

struct bt_gatt_iter {
	struct bt_gatt_result *result;
	uint16_t pos;
};

bool bt_gatt_iter_init(struct bt_gatt_iter *iter, struct bt_gatt_result *result);
bool bt_gatt_iter_next_service(struct bt_gatt_iter *iter,
					struct bt_gatt_service *service);
bool bt_gatt_iter_next_characteristic(struct bt_gatt_iter *iter,
				struct bt_gatt_characteristic *characteristic);
bool bt_gatt_iter_next_descriptor(struct bt_gatt_iter *iter,
					struct bt_gatt_descriptor *descriptor);

typedef void (*bt_gatt_destroy_func_t)(void *user_data);

typedef void (*bt_gatt_result_callback_t)(bool success, uint8_t att_ecode,
							void *user_data);
typedef void (*bt_gatt_discovery_callback_t)(bool success, uint8_t att_code,
						struct bt_gatt_result *result,
						void *user_data);
typedef void (*bt_gatt_read_callback_t)(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data);
typedef void (*bt_gatt_write_long_callback_t)(bool success, bool reliable_error,
					uint8_t att_ecode, void *user_data);

typedef void (*bt_gatt_notify_callback_t)(uint16_t value_handle,
					const uint8_t *value, uint16_t length,
					void *user_data);

bool bt_gatt_exchange_mtu(struct bt_att *att, uint16_t client_rx_mtu,
					bt_gatt_result_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);

bool bt_gatt_discover_primary_services(struct bt_att *att, bt_uuid_t *uuid,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);
bool bt_gatt_discover_included_services(struct bt_att *att,
					uint16_t start, uint16_t end,
					bt_uuid_t *uuid,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);
bool bt_gatt_discover_characteristics(struct bt_att *att,
					uint16_t start, uint16_t end,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);
bool bt_gatt_discover_descriptors(struct bt_att *att,
					uint16_t start, uint16_t end,
					bt_gatt_discovery_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);

bool bt_gatt_read_value(struct bt_att *att, uint16_t value_handle,
					bt_gatt_read_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);
bool bt_gatt_read_long_value(struct bt_att *att,
					uint16_t value_handle, uint16_t offset,
					bt_gatt_read_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);

bool bt_gatt_write_without_response(struct bt_att *att, uint16_t value_handle,
					bool signed_write,
					uint8_t *value, uint16_t length);
bool bt_gatt_write_value(struct bt_att *att, uint16_t value_handle,
					uint8_t *value, uint16_t length,
					bt_gatt_result_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);
bool bt_gatt_write_long_value(struct bt_att *att, bool reliable,
					uint16_t value_handle, uint16_t offset,
					uint8_t *value, uint16_t length,
					bt_gatt_write_long_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);

unsigned int bt_gatt_register(struct bt_att *att, bool indications,
					bt_gatt_notify_callback_t callback,
					void *user_data,
					bt_gatt_destroy_func_t destroy);
