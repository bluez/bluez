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

struct bt_mesh;
struct mesh_net;

struct bt_mesh *mesh_create(uint16_t index);
struct bt_mesh *mesh_ref(struct bt_mesh *mesh);
void mesh_unref(struct bt_mesh *mesh);
bool mesh_load_config(struct bt_mesh *mesh, const char *in_config_name);
bool mesh_set_output(struct bt_mesh *mesh, const char *out_config_name);
const char *mesh_status_str(uint8_t err);

/* Command line testing */
struct mesh_net *mesh_get_net(struct bt_mesh *mesh);
