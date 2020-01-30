/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Intel Corporation. All rights reserved.
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

struct mesh_rpl {
	uint32_t iv_index;
	uint32_t seq;
	uint16_t src;
};

bool rpl_put_entry(struct mesh_node *node, uint16_t src, uint32_t iv_index,
								uint32_t seq);
void rpl_del_entry(struct mesh_node *node, uint16_t src);
bool rpl_get_list(struct mesh_node *node, struct l_queue *rpl_list);
void rpl_init(struct mesh_node *node, uint32_t iv_index);
