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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *
 */

void keys_add_net_key(uint16_t net_idx);
void keys_del_net_key(uint16_t net_idx);
void keys_add_app_key(uint16_t net_idx, uint16_t app_idx);
void keys_del_app_key(uint16_t app_idx);
uint16_t keys_get_bound_key(uint16_t app_idx);
bool keys_subnet_exists(uint16_t idx);
void keys_print_keys(void);
