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

#include <json-c/json.h>

struct mesh_db_sub {
	bool virt;
	union {
		uint16_t addr;
		uint8_t	virt_addr[16];
	} src;
};

struct mesh_db_pub {
	bool virt;
	uint16_t addr;
	uint16_t idx;
	uint8_t ttl;
	uint8_t credential;
	uint8_t period;
	uint8_t retransmit;
	uint8_t virt_addr[16];
};

struct mesh_db_model {
	struct mesh_db_sub *subs;
	struct mesh_db_pub *pub;
	uint16_t *bindings;
	uint32_t id;
	bool vendor;
	uint32_t num_bindings;
	uint32_t num_subs;
};

struct mesh_db_element {
	struct l_queue *models;
	uint16_t location;
	uint8_t index;
};

struct mesh_db_modes {
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

struct mesh_db_node {
	bool provisioner;
	uint32_t seq_number;
	struct mesh_db_modes modes;
	uint16_t cid;
	uint16_t pid;
	uint16_t vid;
	uint16_t crpl;
	uint16_t unicast;
	uint8_t ttl;
	struct l_queue *elements;
	uint8_t uuid[16];
};

struct mesh_db_prov {
	uint16_t algorithm;
	struct {
		uint16_t actions;
		uint8_t size;
	} input_oob;
	uint8_t pub_type;
	struct {
		uint16_t actions;
		uint8_t size;
	} output_oob;
	uint8_t static_type;
	uint8_t priv_key[32];
};

typedef bool (*mesh_db_net_key_cb)(uint16_t idx, uint8_t key[16],
			uint8_t new_key[16], int phase, void *user_data);
typedef bool (*mesh_db_app_key_cb)(uint16_t idx, uint16_t net_idx,
			uint8_t key[16], uint8_t new_key[16], void *user_data);
typedef bool (*mesh_db_node_cb)(struct mesh_db_node *node, void *user_data);

bool mesh_db_read_node(json_object *jobj, mesh_db_node_cb cb, void *user_data);
bool mesh_db_read_unprovisioned_device(json_object *jnode, mesh_db_node_cb cb,
							void *user_data);
bool mesh_db_read_prov_info(json_object *jnode, struct mesh_db_prov *prov);
bool mesh_db_read_iv_index(json_object *jobj, uint32_t *idx, bool *update);
bool mesh_db_read_device_key(json_object *jobj, uint8_t key_buf[16]);
bool mesh_db_read_net_transmit(json_object *jobj, uint8_t *cnt,
							uint16_t *interval);
bool mesh_db_write_net_transmit(json_object *jobj, uint8_t cnt,
							uint16_t interval);
bool mesh_db_read_net_keys(json_object *jobj, mesh_db_net_key_cb cb,
							void *user_data);
bool mesh_db_read_app_keys(json_object *jobj, mesh_db_app_key_cb cb,
							void *user_data);
bool mesh_db_write_device_key(json_object *jobj, uint8_t *key);
bool mesh_db_write_network_key(json_object *jobj, uint16_t idx, uint8_t *key,
						uint8_t *new_key, int phase);
bool mesh_db_write_app_key(json_object *jobj, uint16_t net_idx,
			uint16_t app_idx, uint8_t *key, uint8_t *new_key);
bool mesh_db_write_int(json_object *jobj, const char *keyword, int value);
bool mesh_db_write_uint16_hex(json_object *jobj, const char *desc,
								uint16_t value);
bool mesh_db_write_bool(json_object *jobj, const char *keyword, bool value);
bool mesh_db_write_relay_mode(json_object *jnode, uint8_t mode, uint8_t count,
							uint16_t interval);
bool mesh_db_write_mode(json_object *jobj, const char *keyword, int value);
bool mesh_db_model_binding_add(json_object *jnode, uint8_t ele_idx, bool vendor,
					uint32_t mod_id, uint16_t app_idx);
bool mesh_db_model_binding_del(json_object *jnode, uint8_t ele_idx, bool vendor,
					uint32_t mod_id, uint16_t app_idx);
bool mesh_db_app_key_add(json_object *jnode, uint16_t net_idx, uint16_t app_idx,
					const uint8_t key[16], bool update);
bool mesh_db_app_key_del(json_object *jobj, uint16_t net_idx, uint16_t idx);
bool mesh_db_net_key_add(json_object *jobj, uint16_t net_idx,
					const uint8_t key[16], int phase);
bool mesh_db_net_key_del(json_object *jobj, uint16_t net_idx);
bool mesh_db_write_kr_phase(json_object *jobj, uint16_t net_idx, int phase);
bool mesh_db_write_address(json_object *jobj, uint16_t address);
bool mesh_db_write_iv_index(json_object *jobj, uint32_t idx, bool update);
void mesh_db_remove_property(json_object *jobj, const char *desc);
