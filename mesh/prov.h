/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

struct prov;

typedef void (*provision_done_cb)(void *user_data, int status);

bool prov_open(struct mesh_node *node, GDBusProxy *prov_in, uint16_t net_idx,
		provision_done_cb cb, void *user_data);
bool prov_data_ready(struct mesh_node *node, uint8_t *buf, uint8_t len);
bool prov_complete(struct mesh_node *node, uint8_t status);
bool prov_set_sec_level(uint8_t level);
uint8_t prov_get_sec_level(void);
