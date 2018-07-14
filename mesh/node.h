/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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
 *
 */

#include "mesh/mesh-db.h"

struct mesh_net;
struct mesh_node;

/* To prevent local node JSON cache thrashing, minimum update times */
#define MIN_SEQ_TRIGGER	32
#define MIN_SEQ_CACHE		(2*MIN_SEQ_TRIGGER)
#define MIN_SEQ_CACHE_TIME	(5*60)

struct mesh_node *node_new(void);
void node_free(struct mesh_node *node);
uint8_t *node_uuid_get(struct mesh_node *node);
struct mesh_node *node_find_by_addr(uint16_t addr);
struct mesh_node *node_find_by_uuid(uint8_t uuid[16]);
bool node_is_provisioned(struct mesh_node *node);
bool node_app_key_delete(struct mesh_net *net, uint16_t addr,
				uint16_t net_idx, uint16_t idx);
bool node_net_key_delete(struct mesh_node *node, uint16_t index);
bool node_set_primary(struct mesh_node *node, uint16_t unicast);
uint16_t node_get_primary(struct mesh_node *node);
uint16_t node_get_primary_net_idx(struct mesh_node *node);
bool node_set_device_key(struct mesh_node *node, uint8_t key[16]);
const uint8_t *node_get_device_key(struct mesh_node *node);
void node_set_num_elements(struct mesh_node *node, uint8_t num_ele);
uint8_t node_get_num_elements(struct mesh_node *node);
bool node_parse_composition(struct mesh_node *node, uint8_t *buf, uint16_t len);
struct l_queue *node_get_net_keys(struct mesh_node *node);
struct l_queue *node_get_app_keys(struct mesh_node *node);
bool node_add_binding(struct mesh_node *node, uint8_t ele_idx,
			uint32_t model_id, uint16_t app_idx);
bool node_del_binding(struct mesh_node *node, uint8_t ele_idx,
			uint32_t model_id, uint16_t app_idx);
uint8_t node_default_ttl_get(struct mesh_node *node);
bool node_default_ttl_set(struct mesh_node *node, uint8_t ttl);
bool node_set_sequence_number(struct mesh_node *node, uint32_t seq);
uint32_t node_get_sequence_number(struct mesh_node *node);
int node_get_element_idx(struct mesh_node *node, uint16_t ele_addr);
struct l_queue *node_get_element_models(struct mesh_node *node, uint8_t ele_idx,
								int *status);
struct mesh_model *node_get_model(struct mesh_node *node, uint8_t ele_idx,
						uint32_t id, int *status);
uint16_t node_get_crpl(struct mesh_node *node);
struct mesh_node *node_create_from_storage(struct mesh_net *net,
						struct mesh_db_node *db_node,
								bool local);
uint16_t node_generate_comp(struct mesh_node *node, uint8_t *buf, uint16_t sz);
uint8_t node_lpn_mode_get(struct mesh_node *node);
bool node_relay_mode_set(struct mesh_node *node, bool enable, uint8_t cnt,
							uint16_t interval);
uint8_t node_relay_mode_get(struct mesh_node *node, uint8_t *cnt,
							uint16_t *interval);
bool node_proxy_mode_set(struct mesh_node *node, bool enable);
uint8_t node_proxy_mode_get(struct mesh_node *node);
bool node_beacon_mode_set(struct mesh_node *node, bool enable);
uint8_t node_beacon_mode_get(struct mesh_node *node);
bool node_friend_mode_set(struct mesh_node *node, bool enable);
uint8_t node_friend_mode_get(struct mesh_node *node);
uint32_t node_seq_cache(struct mesh_node *node);
void node_cleanup(struct mesh_net *net);
