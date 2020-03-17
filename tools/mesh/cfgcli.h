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

struct mesh_group {
	uint16_t addr;
	uint8_t label[16];
};

typedef bool (*key_send_func_t) (void *user_data, uint16_t dst,
				 uint16_t idx, bool is_appkey, bool update);
typedef void (*delete_remote_func_t) (uint16_t primary, uint8_t ele_cnt);

struct model_info *cfgcli_init(key_send_func_t key_func,
				delete_remote_func_t del_node, void *user_data);
void cfgcli_cleanup(void);
