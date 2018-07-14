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
 *
 */

struct mesh_net;

bool storage_parse_config(struct mesh_net *net, const char *config_name);
bool storage_save_config(struct mesh_net *net, const char *config_name,
			bool no_wait, mesh_status_func_t cb, void *user_data);
bool storage_save_new_config(struct mesh_net *net, const char *config_name,
					mesh_status_func_t cb, void *user_data);
void storage_release(struct mesh_net *net);

bool storage_model_bind(struct mesh_net *net, uint16_t addr, uint32_t id,
						uint16_t app_idx, bool unbind);

bool storage_local_set_ttl(struct mesh_net *net, uint8_t ttl);
bool storage_local_set_relay(struct mesh_net *net, bool enable, uint8_t count,
							uint8_t interval);
bool storage_local_set_transmit_params(struct mesh_net *net, uint8_t count,
							uint8_t interval);
bool storage_local_set_mode(struct mesh_net *net, uint8_t mode,
							const char *mode_name);
bool storage_local_net_key_add(struct mesh_net *net, uint16_t net_idx,
					const uint8_t key[16], int phase);
bool storage_local_net_key_del(struct mesh_net *net, uint16_t net_idx);
bool storage_local_app_key_add(struct mesh_net *net, uint16_t net_idx,
			uint16_t app_idx, const uint8_t key[16], bool update);
bool storage_local_app_key_del(struct mesh_net *net, uint16_t net_idx,
							uint16_t app_idx);
bool storage_local_write_sequence_number(struct mesh_net *net, uint32_t seq);
bool storage_local_set_iv_index(struct mesh_net *net, uint32_t iv_index,
								bool update);
bool storage_local_set_device_key(struct mesh_net *net, uint8_t dev_key[16]);
bool storage_local_set_unicast(struct mesh_net *net, uint16_t unicast);
