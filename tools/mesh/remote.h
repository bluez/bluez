/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 */

bool remote_add_node(const uint8_t uuid[16], uint16_t unicast,
					uint8_t ele_cnt, uint16_t net_idx);
uint16_t remote_get_next_unicast(uint16_t low, uint16_t high, uint8_t ele_cnt);
bool remote_add_net_key(uint16_t addr, uint16_t net_idx);
bool remote_del_net_key(uint16_t addr, uint16_t net_idx);
bool remote_add_app_key(uint16_t addr, uint16_t app_idx);
bool remote_del_app_key(uint16_t addr, uint16_t app_idx);
uint16_t remote_get_subnet_idx(uint16_t addr);
void remote_print_node(uint16_t addr);
void remote_print_all(void);
