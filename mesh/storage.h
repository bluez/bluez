/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2918  Intel Corporation. All rights reserved.
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

struct mesh_net;
struct mesh_node;

bool storage_load_nodes(const char *dir);
bool storage_create_node_config(struct mesh_node *node, void *db_node);
void storage_remove_node_config(struct mesh_node *node);
bool storage_save_config(struct mesh_node *node, bool no_wait,
					mesh_status_func_t cb, void *user_data);
bool storage_model_bind(struct mesh_node *node, uint16_t addr, uint32_t id,
						uint16_t app_idx, bool unbind);

bool storage_set_ttl(json_object *jnode, uint8_t ttl);
bool storage_set_relay(json_object *jnode, bool enable, uint8_t count,
							uint8_t interval);
bool storage_set_transmit_params(json_object *jnode, uint8_t count,
							uint8_t interval);
bool storage_set_mode(json_object *jnode, uint8_t mode, const char *mode_name);
bool storage_net_key_add(struct mesh_net *net, uint16_t net_idx,
					const uint8_t key[16], bool update);
bool storage_net_key_del(struct mesh_net *net, uint16_t net_idx);
bool storage_app_key_add(struct mesh_net *net, uint16_t net_idx,
			uint16_t app_idx, const uint8_t key[16], bool update);
bool storage_app_key_del(struct mesh_net *net, uint16_t net_idx,
							uint16_t app_idx);
bool storage_write_sequence_number(struct mesh_net *net, uint32_t seq);
bool storage_set_iv_index(struct mesh_net *net, uint32_t iv_index,
								bool update);
bool storage_set_device_key(struct mesh_node *node, uint8_t dev_key[16]);
bool storage_set_unicast(struct mesh_node *node, uint16_t unicast);
bool storage_set_key_refresh_phase(struct mesh_net *net, uint16_t net_idx,
								uint8_t phase);
