/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Google Inc.
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

#include "src/shared/att.h"
#include "lib/uuid.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-helpers.h"
#include "src/shared/att-types.h"
#include "src/shared/util.h"

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

struct bt_gatt_server {
	struct gatt_db *db;
	struct bt_att *att;
	int ref_count;
	uint16_t mtu;

	bt_gatt_server_debug_func_t debug_callback;
	bt_gatt_server_destroy_func_t debug_destroy;
	void *debug_data;
};

static bool gatt_server_register_att_handlers(struct bt_gatt_server *server)
{
	/* TODO */
	return true;
}

static void bt_gatt_server_free(struct bt_gatt_server *server)
{
	if (server->debug_destroy)
		server->debug_destroy(server->debug_data);

	bt_att_unref(server->att);

	free(server);
}

struct bt_gatt_server *bt_gatt_server_new(struct gatt_db *db,
					struct bt_att *att, uint16_t mtu)
{
	struct bt_gatt_server *server;

	if (!att)
		return NULL;

	server = new0(struct bt_gatt_server, 1);
	if (!server)
		return NULL;

	server->db = db;
	server->att = bt_att_ref(att);
	server->mtu = MAX(mtu, BT_ATT_DEFAULT_LE_MTU);

	if (!gatt_server_register_att_handlers(server)) {
		bt_gatt_server_free(server);
		return NULL;
	}

	return bt_gatt_server_ref(server);
}

struct bt_gatt_server *bt_gatt_server_ref(struct bt_gatt_server *server)
{
	if (!server)
		return NULL;

	__sync_fetch_and_add(&server->ref_count, 1);

	return server;
}

void bt_gatt_server_unref(struct bt_gatt_server *server)
{
	if (__sync_sub_and_fetch(&server->ref_count, 1))
		return;

	bt_gatt_server_free(server);
}

bool bt_gatt_server_set_debug(struct bt_gatt_server *server,
					bt_gatt_server_debug_func_t callback,
					void *user_data,
					bt_gatt_server_destroy_func_t destroy)
{
	if (!server)
		return false;

	if (server->debug_destroy)
		server->debug_destroy(server->debug_data);

	server->debug_callback = callback;
	server->debug_destroy = destroy;
	server->debug_data = user_data;

	return true;
}
