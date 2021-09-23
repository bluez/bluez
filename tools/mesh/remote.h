/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 */

bool remote_add_node(const uint8_t uuid[16], uint16_t unicast,
					uint8_t ele_cnt, uint16_t net_idx);
uint8_t remote_del_node(uint16_t unicast);
bool remote_set_model(uint16_t unicast, uint8_t ele_idx, uint32_t mod_id,
								bool vendor);
void remote_add_rejected_address(uint16_t addr, uint32_t iv_index, bool save);
void remote_clear_rejected_addresses(uint32_t iv_index);
uint16_t remote_get_next_unicast(uint16_t low, uint16_t high, uint8_t ele_cnt);
bool remote_add_net_key(uint16_t addr, uint16_t net_idx, bool save);
bool remote_del_net_key(uint16_t addr, uint16_t net_idx);
bool remote_update_net_key(uint16_t addr, uint16_t net_idx, bool update,
								bool save);
bool remote_add_app_key(uint16_t addr, uint16_t app_idx, bool save);
bool remote_del_app_key(uint16_t addr, uint16_t app_idx);
bool remote_update_app_key(uint16_t addr, uint16_t app_idx, bool update,
								bool save);
bool remote_finish_key_refresh(uint16_t addr, uint16_t net_idx);
void remote_set_composition(uint16_t addr, bool comp);
bool remote_has_composition(uint16_t addr);
uint16_t remote_get_subnet_idx(uint16_t addr);
void remote_print_node(uint16_t addr);
void remote_print_all(void);
