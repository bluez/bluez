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

struct mesh_config;

struct mesh_config_sub {
	bool virt;
	union {
		uint16_t	addr;
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

typedef void (*mesh_config_status_func_t)(void *user_data, bool result);
typedef bool (*mesh_config_node_func_t)(struct mesh_config_node *node,
							const uint8_t uuid[16],
							struct mesh_config *cfg,
							void *user_data);

bool mesh_config_load_nodes(const char *cfgdir_name, mesh_config_node_func_t cb,
							void *user_data);
void mesh_config_release(struct mesh_config *cfg);
void mesh_config_destroy(struct mesh_config *cfg);
bool mesh_config_save(struct mesh_config *cfg, bool no_wait,
				mesh_config_status_func_t cb, void *user_data);
struct mesh_config *mesh_config_create(const char *cfgdir_name,
						const uint8_t uuid[16],
						struct mesh_config_node *node);

bool mesh_config_write_net_transmit(struct mesh_config *cfg, uint8_t cnt,
							uint16_t interval);
bool mesh_config_write_device_key(struct mesh_config *cfg, uint8_t *key);
bool mesh_config_write_token(struct mesh_config *cfg, uint8_t *token);
bool mesh_config_write_network_key(struct mesh_config *cfg, uint16_t idx,
				uint8_t *key, uint8_t *new_key, int phase);
bool mesh_config_write_app_key(struct mesh_config *cfg, uint16_t net_idx,
			uint16_t app_idx, uint8_t *key, uint8_t *new_key);
bool mesh_config_write_seq_number(struct mesh_config *cfg, uint32_t seq,
								bool cache);
bool mesh_config_write_unicast(struct mesh_config *cfg, uint16_t unicast);
bool mesh_config_write_relay_mode(struct mesh_config *cfg, uint8_t mode,
					uint8_t count, uint16_t interval);
bool mesh_config_write_ttl(struct mesh_config *cfg, uint8_t ttl);
bool mesh_config_write_mode(struct mesh_config *cfg, const char *keyword,
								int value);
bool mesh_config_model_binding_add(struct mesh_config *cfg, uint16_t ele_addr,
						bool vendor, uint32_t mod_id,
							uint16_t app_idx);
bool mesh_config_model_binding_del(struct mesh_config *cfg, uint16_t ele_addr,
						bool vendor, uint32_t mod_id,
							uint16_t app_idx);
bool mesh_config_model_pub_add(struct mesh_config *cfg, uint16_t ele_addr,
						uint32_t mod_id, bool vendor,
						struct mesh_config_pub *pub);
bool mesh_config_model_pub_del(struct mesh_config *cfg, uint16_t ele_addr,
						uint32_t mod_id, bool vendor);
bool mesh_config_model_sub_add(struct mesh_config *cfg, uint16_t ele_addr,
						uint32_t mod_id, bool vendor,
						struct mesh_config_sub *sub);
bool mesh_config_model_sub_del(struct mesh_config *cfg, uint16_t ele_addr,
						uint32_t mod_id, bool vendor,
						struct mesh_config_sub *sub);
bool mesh_config_model_sub_del_all(struct mesh_config *cfg, uint16_t ele_addr,
						uint32_t mod_id, bool vendor);
bool mesh_config_app_key_add(struct mesh_config *cfg, uint16_t net_idx,
				uint16_t app_idx, const uint8_t key[16]);
bool mesh_config_app_key_update(struct mesh_config *cfg, uint16_t app_idx,
							const uint8_t key[16]);
bool mesh_config_app_key_del(struct mesh_config *cfg, uint16_t net_idx,
								uint16_t idx);
bool mesh_config_net_key_add(struct mesh_config *cfg, uint16_t net_idx,
							const uint8_t key[16]);
bool mesh_config_net_key_update(struct mesh_config *cfg, uint16_t idx,
							const uint8_t key[16]);
bool mesh_config_net_key_del(struct mesh_config *cfg, uint16_t net_idx);
bool mesh_config_net_key_set_phase(struct mesh_config *cfg, uint16_t idx,
								uint8_t phase);
bool mesh_config_write_address(struct mesh_config *cfg, uint16_t address);
bool mesh_config_write_iv_index(struct mesh_config *cfg, uint32_t idx,
								bool update);
