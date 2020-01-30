/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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
 */

/* TODO: get this number from configuration */
#define MAX_APP_KEYS	32

struct mesh_app_key;

bool appkey_key_init(struct mesh_net *net, uint16_t net_idx, uint16_t app_idx,
				uint8_t *key_value, uint8_t *new_key_value);
void appkey_key_free(void *data);
const uint8_t *appkey_get_key(struct mesh_net *net, uint16_t app_idx,
							uint8_t *key_id);
int appkey_get_key_idx(struct mesh_app_key *app_key,
				const uint8_t **key, uint8_t *key_aid,
				const uint8_t **new_key, uint8_t *new_key_aid);
bool appkey_have_key(struct mesh_net *net, uint16_t app_idx);
uint16_t appkey_net_idx(struct mesh_net *net, uint16_t app_idx);
int appkey_key_add(struct mesh_net *net, uint16_t net_idx, uint16_t app_idx,
							const uint8_t *new_key);
int appkey_key_update(struct mesh_net *net, uint16_t net_idx, uint16_t app_idx,
							const uint8_t *new_key);
int appkey_key_delete(struct mesh_net *net, uint16_t net_idx, uint16_t app_idx);
void appkey_delete_bound_keys(struct mesh_net *net, uint16_t net_idx);
uint8_t appkey_list(struct mesh_net *net, uint16_t net_idx, uint8_t *buf,
					uint16_t buf_size, uint16_t *size);
