/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 */

#include "mesh/mesh-config.h"

struct mesh_group;
struct model_pub;

bool mesh_db_create(const char *fname, const uint8_t token[8],
							const char *name);
bool mesh_db_load(const char *fname);

bool mesh_db_get_token(uint8_t token[8]);
bool mesh_db_set_iv_index(uint32_t ivi);
uint32_t mesh_db_get_iv_index(void);

bool mesh_db_add_net_key(uint16_t idx);
bool mesh_db_del_net_key(uint16_t idx);
bool mesh_db_set_net_key_phase(uint16_t net_idx, uint8_t phase);
bool mesh_db_add_app_key(uint16_t net_idx, uint16_t app_idx);
bool mesh_db_del_app_key(uint16_t app_idx);
bool mesh_db_get_addr_range(uint16_t *low, uint16_t *high);
bool mesh_db_add_node(uint8_t uuid[16], uint8_t num_els, uint16_t unicast,
							uint16_t net_idx);
bool mesh_db_del_node(uint16_t unicast);
bool mesh_db_node_set_composition(uint16_t unicast, uint8_t *data,
								uint16_t len);
bool mesh_db_add_provisioner(const char *name, uint8_t uuid[16],
				uint16_t unicast_low, uint16_t unicast_high,
				uint16_t group_low, uint16_t group_high);
bool mesh_db_node_set_net_transmit(uint16_t unicast, uint8_t cnt,
							uint16_t interval);
bool mesh_db_node_set_relay(uint16_t unicast, uint8_t relay, uint8_t cnt,
							uint16_t interval);
bool mesh_db_node_set_proxy(uint16_t unicast, uint8_t proxy);
bool mesh_db_node_set_friend(uint16_t unicast, uint8_t friend);
bool mesh_db_node_set_beacon(uint16_t unicast, bool enabled);
bool mesh_db_node_add_net_key(uint16_t unicast, uint16_t idx);
bool mesh_db_node_del_net_key(uint16_t unicast, uint16_t idx);
bool mesh_db_node_update_net_key(uint16_t unicast, uint16_t idx, bool updated);
bool mesh_db_node_add_app_key(uint16_t unicast, uint16_t idx);
bool mesh_db_node_del_app_key(uint16_t unicast, uint16_t idx);
bool mesh_db_node_update_app_key(uint16_t unicast, uint16_t idx, bool updated);
bool mesh_db_node_set_ttl(uint16_t unicast, uint8_t ttl);
bool mesh_db_node_write_mode(uint16_t unicast, const char *keyword, int value);
bool mesh_db_node_model_bind(uint16_t unicast, uint16_t ele_addr, bool vendor,
					uint32_t mod_id, uint16_t app_idx);
bool mesh_db_node_model_unbind(uint16_t unicast, uint16_t ele_addr, bool vendor,
					uint32_t mod_id, uint16_t app_idx);
bool mesh_db_node_model_add_sub(uint16_t unicast, uint16_t ele, bool vendor,
						uint32_t mod_id, uint16_t addr);
bool mesh_db_node_model_del_sub(uint16_t unicast, uint16_t ele, bool vendor,
						uint32_t mod_id, uint16_t addr);
bool mesh_db_node_model_overwrt_sub(uint16_t unicast, uint16_t ele, bool vendor,
						uint32_t mod_id, uint16_t addr);
bool mesh_db_node_model_add_sub_virt(uint16_t unicast, uint16_t ele,
						bool vendor, uint32_t mod_id,
								uint8_t *label);
bool mesh_db_node_model_del_sub_virt(uint16_t unicast, uint16_t ele,
						bool vendor, uint32_t mod_id,
								uint8_t *label);
bool mesh_db_node_model_overwrt_sub_virt(uint16_t unicast, uint16_t ele,
						bool vendor, uint32_t mod_id,
								uint8_t *label);
bool mesh_db_node_model_del_sub_all(uint16_t unicast, uint16_t ele, bool vendor,
							uint32_t mod_id);
bool mesh_db_node_model_set_pub(uint16_t unicast, uint16_t ele_addr,
					bool vendor, uint32_t mod_id,
					struct model_pub *pub, bool virt);
bool mesh_db_node_set_hb_pub(uint16_t unicast, uint16_t dst, uint16_t net_idx,
						uint8_t period_log, uint8_t ttl,
							uint16_t features);
bool mesh_db_node_set_hb_sub(uint16_t unicast, uint16_t src, uint16_t dst);
struct l_queue *mesh_db_load_groups(void);
bool mesh_db_add_group(struct mesh_group *grp);
bool mesh_db_add_rejected_addr(uint16_t unicast, uint32_t iv_index);
bool mesh_db_clear_rejected(uint32_t iv_index);
bool mesh_db_set_device_key(void *expt_cfg, uint16_t unicast, uint8_t key[16]);
bool mesh_db_set_net_key(void *expt_cfg, uint16_t idx, uint8_t key[16],
					uint8_t *old_key, uint8_t phase);
bool mesh_db_set_app_key(void *expt_cfg, uint16_t net_idx, uint16_t app_idx,
					uint8_t key[16], uint8_t *old_key);
void *mesh_db_prepare_export(void);
bool mesh_db_finish_export(bool is_error, void *expt_cfg, const char *fname);
