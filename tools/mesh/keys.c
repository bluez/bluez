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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "src/shared/shell.h"
#include "mesh/mesh-defs.h"

#include "tools/mesh/mesh-db.h"
#include "tools/mesh/keys.h"

struct net_key {
	uint16_t idx;
	struct l_queue *app_keys;
};

static struct l_queue *net_keys;

static bool app_key_present(const struct net_key *key, uint16_t app_idx)
{
	const struct l_queue_entry *l;

	for (l = l_queue_get_entries(key->app_keys); l; l = l->next) {
		uint16_t idx = L_PTR_TO_UINT(l->data);

		if (idx == app_idx)
			return true;
	}

	return false;
}

static bool net_idx_match(const void *a, const void *b)
{
	const struct net_key *key = a;
	uint32_t idx = L_PTR_TO_UINT(b);

	return key->idx == idx;
}

static void delete_bound_appkey(void *a)
{
	uint32_t idx = L_PTR_TO_UINT(a);

	mesh_db_app_key_del(idx);
}

void keys_add_net_key(uint16_t net_idx)
{
	struct net_key *key;

	if (!net_keys)
		net_keys = l_queue_new();

	if (l_queue_find(net_keys, net_idx_match, L_UINT_TO_PTR(net_idx)))
		return;

	key = l_new(struct net_key, 1);
	key->idx = net_idx;

	l_queue_push_tail(net_keys, key);
}

void keys_del_net_key(uint16_t idx)
{
	struct net_key *key;

	if (!net_keys)
		return;

	key = l_queue_remove_if(net_keys, net_idx_match, L_UINT_TO_PTR(idx));
	if (!key)
		return;

	l_queue_destroy(key->app_keys, delete_bound_appkey);
	l_free(key);
}

void keys_add_app_key(uint16_t net_idx, uint16_t app_idx)
{
	struct net_key *key;

	if (!net_keys)
		return;

	key = l_queue_find(net_keys, net_idx_match, L_UINT_TO_PTR(net_idx));
	if (!key)
		return;

	if (!key->app_keys)
		key->app_keys = l_queue_new();

	if (app_key_present(key, app_idx))
		return;

	l_queue_push_tail(key->app_keys, L_UINT_TO_PTR(app_idx));
}

void keys_del_app_key(uint16_t app_idx)
{
	const struct l_queue_entry *l;

	if (!net_keys)
		return;

	for (l = l_queue_get_entries(net_keys); l; l = l->next) {
		struct net_key *key = l->data;

		if (!key->app_keys)
			continue;

		if (l_queue_remove(key->app_keys, L_UINT_TO_PTR(app_idx)))
			return;
	}
}

uint16_t keys_get_bound_key(uint16_t app_idx)
{
	const struct l_queue_entry *l;

	if (!net_keys)
		return NET_IDX_INVALID;

	for (l = l_queue_get_entries(net_keys); l; l = l->next) {
		struct net_key *key = l->data;

		if (!key->app_keys)
			continue;

		if (app_key_present(key, app_idx))
			return key->idx;
	}

	return NET_IDX_INVALID;
}

static void print_appkey(void *app_key, void *user_data)
{
	uint16_t app_idx = L_PTR_TO_UINT(app_key);

	bt_shell_printf("0x%3.3x, ", app_idx);
}

static void print_netkey(void *net_key, void *user_data)
{
	struct net_key *key = net_key;

	bt_shell_printf(COLOR_YELLOW "NetKey: 0x%3.3x\n" COLOR_OFF, key->idx);

	if (!key->app_keys || l_queue_isempty(key->app_keys))
		return;

	bt_shell_printf("\t" COLOR_GREEN "app_keys = ");
	l_queue_foreach(key->app_keys, print_appkey, NULL);
	bt_shell_printf("\n" COLOR_OFF);
}

void keys_print_keys(void)
{
	l_queue_foreach(net_keys, print_netkey, NULL);
}

bool keys_subnet_exists(uint16_t idx)
{
	if (!l_queue_find(net_keys, net_idx_match, L_UINT_TO_PTR(idx)))
		return false;

	return true;
}
