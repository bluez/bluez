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

struct mesh_config_sub {
	bool virt;
	union {
		uint16_t addr;
		uint8_t	virt_addr[16];
	} src;
};

struct mesh_config_pub {
	bool virt;
	uint32_t period;
	uint16_t addr;
	uint16_t idx;
	uint8_t ttl;
	uint8_t credential;
	uint8_t count;
	uint8_t interval;
	uint8_t virt_addr[16];
};

struct mesh_config_model {
	struct mesh_config_sub *subs;
	struct mesh_config_pub *pub;
	uint16_t *bindings;
	uint32_t id;
	bool vendor;
	uint32_t num_bindings;
	uint32_t num_subs;
};

struct mesh_config_element {
	struct l_queue *models;
	uint16_t location;
	uint8_t index;
};

struct mesh_config_modes {
	struct {
		uint16_t interval;
		uint8_t cnt;
		uint8_t state;
	} relay;
	uint8_t lpn;
	uint8_t friend;
	uint8_t proxy;
	uint8_t beacon;
};

struct mesh_config_netkey {
	uint16_t idx;
	uint8_t key[16];
	uint8_t new_key[16];
	uint8_t phase;
};

struct mesh_config_appkey {
	uint16_t net_idx;
	uint16_t app_idx;
	uint8_t key[16];
	uint8_t new_key[16];
};

struct mesh_config_transmit {
	uint16_t interval;
	uint8_t count;
};

struct mesh_config_node {
	struct l_queue *elements;
	struct l_queue *netkeys;
	struct l_queue *appkeys;
	uint32_t seq_number;
	uint32_t iv_index;
	bool iv_update;
	uint16_t cid;
	uint16_t pid;
	uint16_t vid;
	uint16_t crpl;
	uint16_t unicast;
	struct mesh_config_transmit *net_transmit;
	struct mesh_config_modes modes;
	uint8_t ttl;
	uint8_t dev_key[16];
	uint8_t token[8];
};

typedef bool (*mesh_config_node_cb)(struct mesh_config_node *node,
							void *user_data);

bool mesh_config_read_node(json_object *jobj, mesh_config_node_cb cb,
							void *user_data);
bool mesh_config_add_node(json_object *jnode, struct mesh_config_node *node);
bool mesh_config_write_net_transmit(json_object *jobj, uint8_t cnt,
							uint16_t interval);
bool mesh_config_write_device_key(json_object *jobj, uint8_t *key);
bool mesh_config_write_token(json_object *jobj, uint8_t *token);
bool mesh_config_write_network_key(json_object *jobj, uint16_t idx,
				uint8_t *key, uint8_t *new_key, int phase);
bool mesh_config_write_app_key(json_object *jobj, uint16_t net_idx,
			uint16_t app_idx, uint8_t *key, uint8_t *new_key);
bool mesh_config_write_int(json_object *jobj, const char *keyword, int value);
bool mesh_config_write_uint16_hex(json_object *jobj, const char *desc,
								uint16_t value);
bool mesh_config_write_uint32_hex(json_object *jobj, const char *desc,
								uint32_t value);
bool mesh_config_write_bool(json_object *jobj, const char *keyword, bool value);
bool mesh_config_write_relay_mode(json_object *jnode, uint8_t mode,
					uint8_t count, uint16_t interval);
bool mesh_config_write_mode(json_object *jobj, const char *keyword, int value);
bool mesh_config_model_binding_add(json_object *jnode, uint8_t ele_idx,
						bool vendor, uint32_t mod_id,
							uint16_t app_idx);
bool mesh_config_model_binding_del(json_object *jnode, uint8_t ele_idx,
						bool vendor, uint32_t mod_id,
							uint16_t app_idx);
bool mesh_config_model_pub_add(json_object *jnode, uint16_t ele_addr,
						uint32_t mod_id, bool vendor,
						struct mesh_config_pub *pub);
bool mesh_config_model_pub_del(json_object *jnode, uint16_t ele_addr,
						uint32_t mod_id, bool vendor);
bool mesh_config_model_sub_add(json_object *jnode, uint16_t addr,
						uint32_t mod_id, bool vendor,
						struct mesh_config_sub *sub);
bool mesh_config_model_sub_del(json_object *jnode, uint16_t addr,
						uint32_t mod_id, bool vendor,
						struct mesh_config_sub *sub);
bool mesh_config_model_sub_del_all(json_object *jnode, uint16_t addr,
						uint32_t mod_id, bool vendor);
bool mesh_config_app_key_add(json_object *jnode, uint16_t net_idx,
				uint16_t app_idx, const uint8_t key[16]);
bool mesh_config_app_key_update(json_object *jobj, uint16_t app_idx,
							const uint8_t key[16]);
bool mesh_config_app_key_del(json_object *jobj, uint16_t net_idx, uint16_t idx);
bool mesh_config_net_key_add(json_object *jobj, uint16_t net_idx,
							const uint8_t key[16]);
bool mesh_config_net_key_update(json_object *jobj, uint16_t idx,
							const uint8_t key[16]);
bool mesh_config_net_key_del(json_object *jobj, uint16_t net_idx);
bool mesh_config_net_key_set_phase(json_object *jobj, uint16_t idx,
								uint8_t phase);
bool mesh_config_write_address(json_object *jobj, uint16_t address);
bool mesh_config_write_iv_index(json_object *jobj, uint32_t idx, bool update);
void mesh_config_remove_property(json_object *jobj, const char *desc);
