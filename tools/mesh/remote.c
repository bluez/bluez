// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019-2020  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "src/shared/shell.h"
#include "src/shared/util.h"

#include "mesh/mesh-defs.h"
#include "tools/mesh/keys.h"
#include "tools/mesh/mesh-db.h"
#include "tools/mesh/remote.h"
#include "tools/mesh/util.h"

#define abs_diff(a, b) ((a) > (b) ? (a) - (b) : (b) - (a))

struct remote_key {
	uint16_t idx;
	bool updated;
};

struct remote_node {
	uint16_t unicast;
	struct l_queue *net_keys;
	struct l_queue *app_keys;
	struct l_queue **els;
	bool comp;
	uint8_t uuid[16];
	uint8_t num_ele;
};

struct rejected_addr {
	uint32_t iv_index;
	uint16_t unicast;
};

static struct l_queue *nodes;
static struct l_queue *reject_list;

static int compare_mod_id(const void *a, const void *b, void *user_data)
{
	uint32_t id1 = L_PTR_TO_UINT(a);
	uint32_t id2 = L_PTR_TO_UINT(b);

	if (id1 >= VENDOR_ID_MASK)
		id1 &= ~VENDOR_ID_MASK;

	if (id2 >= VENDOR_ID_MASK)
		id2 &= ~VENDOR_ID_MASK;

	if (id1 < id2)
		return -1;

	if (id1 > id2)
		return 1;

	return 0;
}

static int compare_unicast(const void *a, const void *b, void *user_data)
{
	const struct remote_node *a_rmt = a;
	const struct remote_node *b_rmt = b;

	if (a_rmt->unicast < b_rmt->unicast)
		return -1;

	if (a_rmt->unicast > b_rmt->unicast)
		return 1;

	return 0;
}

static bool match_node_addr(const void *a, const void *b)
{
	const struct remote_node *rmt = a;
	uint16_t addr = L_PTR_TO_UINT(b);

	if (addr >= rmt->unicast &&
				addr <= (rmt->unicast + rmt->num_ele - 1))
		return true;

	return false;
}

static bool match_key(const void *a, const void *b)
{
	const struct remote_key *key = a;
	uint16_t idx = L_PTR_TO_UINT(b);

	return (key->idx == idx);
}

static bool match_bound_key(const void *a, const void *b)
{
	const struct remote_key *app_key = a;
	uint16_t net_idx = L_PTR_TO_UINT(b);

	return (net_idx == keys_get_bound_key(app_key->idx));
}

uint8_t remote_del_node(uint16_t unicast)
{
	struct remote_node *rmt;
	uint8_t num_ele, i;
	uint32_t iv_index = mesh_db_get_iv_index();

	rmt = l_queue_remove_if(nodes, match_node_addr, L_UINT_TO_PTR(unicast));
	if (!rmt)
		return 0;

	num_ele = rmt->num_ele;

	for (i = 0; i < num_ele; ++i) {
		l_queue_destroy(rmt->els[i], NULL);
		remote_add_rejected_address(unicast + i, iv_index, true);
	}

	l_free(rmt->els);

	l_queue_destroy(rmt->net_keys, NULL);
	l_queue_destroy(rmt->app_keys, NULL);
	l_free(rmt);

	mesh_db_del_node(unicast);

	return num_ele;
}

bool remote_add_node(const uint8_t uuid[16], uint16_t unicast,
					uint8_t ele_cnt, uint16_t net_idx)
{
	struct remote_node *rmt;
	struct remote_key *key;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(unicast));
	if (rmt)
		return false;

	rmt = l_new(struct remote_node, 1);
	memcpy(rmt->uuid, uuid, 16);
	rmt->unicast = unicast;
	rmt->num_ele = ele_cnt;
	rmt->net_keys = l_queue_new();

	key = l_new(struct remote_key, 1);
	key->idx = net_idx;

	l_queue_push_tail(rmt->net_keys, key);

	rmt->els = l_new(struct l_queue *, ele_cnt);

	if (!nodes)
		nodes = l_queue_new();

	l_queue_insert(nodes, rmt, compare_unicast, NULL);

	return true;
}

bool remote_set_model(uint16_t unicast, uint8_t ele_idx, uint32_t mod_id,
								bool vendor)
{
	struct remote_node *rmt;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(unicast));
	if (!rmt)
		return false;

	if (ele_idx >= rmt->num_ele)
		return false;

	if (!rmt->els[ele_idx])
		rmt->els[ele_idx] = l_queue_new();

	if (!vendor)
		mod_id = VENDOR_ID_MASK | mod_id;

	l_queue_insert(rmt->els[ele_idx], L_UINT_TO_PTR(mod_id),
							compare_mod_id, NULL);

	return true;
}

void remote_set_composition(uint16_t addr, bool comp)
{
	struct remote_node *rmt;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return;

	rmt->comp = comp;
}

bool remote_has_composition(uint16_t addr)
{
	struct remote_node *rmt;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return false;

	return rmt->comp;
}

bool remote_add_net_key(uint16_t addr, uint16_t net_idx, bool save)
{
	struct remote_node *rmt;
	struct remote_key *key;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return false;

	if (l_queue_find(rmt->net_keys, match_key, L_UINT_TO_PTR(net_idx)))
		return true;

	key = l_new(struct remote_key, 1);
	key->idx = net_idx;

	l_queue_push_tail(rmt->net_keys, key);

	if (save)
		return mesh_db_node_add_net_key(addr, net_idx);
	else
		return true;
}

bool remote_del_net_key(uint16_t addr, uint16_t net_idx)
{
	struct remote_node *rmt;
	struct remote_key *key;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return false;

	key = l_queue_remove_if(rmt->net_keys, match_key,
							L_UINT_TO_PTR(net_idx));
	if (!key)
		return false;

	mesh_db_node_del_net_key(addr, net_idx);

	l_free(key);
	key = l_queue_remove_if(rmt->app_keys, match_bound_key,
						L_UINT_TO_PTR(net_idx));

	while (key) {
		mesh_db_node_del_app_key(rmt->unicast, key->idx);
		l_free(key);

		key = l_queue_remove_if(rmt->app_keys, match_bound_key,
						L_UINT_TO_PTR(net_idx));
	}

	return true;
}

bool remote_update_net_key(uint16_t addr, uint16_t net_idx, bool update,
								bool save)
{
	struct remote_node *rmt;
	struct remote_key *key;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return false;

	key = l_queue_find(rmt->net_keys, match_key,
						L_UINT_TO_PTR(net_idx));
	if (!key)
		return false;

	key->updated = update;

	if (save)
		return mesh_db_node_update_net_key(addr, net_idx, update);
	else
		return true;
}

bool remote_add_app_key(uint16_t addr, uint16_t app_idx, bool save)
{
	struct remote_node *rmt;
	struct remote_key *key;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return false;

	if (!rmt->app_keys)
		rmt->app_keys = l_queue_new();

	if (l_queue_find(rmt->app_keys, match_key, L_UINT_TO_PTR(app_idx)))
		return true;

	key = l_new(struct remote_key, 1);
	key->idx = app_idx;

	l_queue_push_tail(rmt->app_keys, key);

	if (save)
		return mesh_db_node_add_app_key(addr, app_idx);
	else
		return true;
}

bool remote_del_app_key(uint16_t addr, uint16_t app_idx)
{
	struct remote_node *rmt;
	struct remote_key *key;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return false;

	key = l_queue_remove_if(rmt->app_keys, match_key,
						L_UINT_TO_PTR(app_idx));
	l_free(key);

	return mesh_db_node_del_app_key(addr, app_idx);
}

bool remote_update_app_key(uint16_t addr, uint16_t app_idx, bool update,
								bool save)
{
	struct remote_node *rmt;
	struct remote_key *key;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return false;

	key = l_queue_find(rmt->app_keys, match_key,
						L_UINT_TO_PTR(app_idx));
	if (!key)
		return false;

	key->updated = update;

	if (save)
		return mesh_db_node_update_app_key(addr, app_idx, update);
	else
		return true;
}

bool remote_finish_key_refresh(uint16_t addr, uint16_t net_idx)
{
	struct remote_node *rmt;
	struct remote_key *key;
	const struct l_queue_entry *l;
	bool res = true;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return false;

	if (!remote_update_net_key(addr, net_idx, false, true))
		return false;

	l = l_queue_get_entries(rmt->app_keys);

	for (; l; l = l->next) {
		key = l->data;

		if (net_idx != keys_get_bound_key(key->idx))
			continue;

		key->updated = false;

		res &= mesh_db_node_update_app_key(addr, key->idx, false);
	}

	return res;
}

uint16_t remote_get_subnet_idx(uint16_t addr)
{
	struct remote_node *rmt;
	struct remote_key *key;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));

	if (!rmt || l_queue_isempty(rmt->net_keys))
		return NET_IDX_INVALID;

	key = l_queue_peek_head(rmt->net_keys);

	return key->idx;
}

static void print_key(void *data, void *user_data)
{
	struct remote_key *key = data;

	bt_shell_printf("%u (0x%3.3x) %s, ", key->idx, key->idx,
						key->updated ? ", updated":"");
}

static void print_model(void *model, void *user_data)
{
	uint32_t mod_id = L_PTR_TO_UINT(model);

	if (mod_id >= VENDOR_ID_MASK) {
		mod_id &= ~VENDOR_ID_MASK;
		bt_shell_printf("\t\t\t" COLOR_GREEN "SIG model: %4.4x \"%s\"\n"
				COLOR_OFF, mod_id, sig_model_string(mod_id));
		return;
	}

	bt_shell_printf("\t\t\t" COLOR_GREEN "Vendor model: %8.8x\n"
							COLOR_OFF, mod_id);

}

static void print_element(struct l_queue *mods, int idx)
{
	if (!mods)
		return;

	bt_shell_printf("\t\t" COLOR_GREEN "element %u:\n" COLOR_OFF, idx);
	l_queue_foreach(mods, print_model, NULL);
}

static void print_node(void *rmt, void *user_data)
{
	struct remote_node *node = rmt;
	int i;
	char *str;

	bt_shell_printf(COLOR_YELLOW "Mesh node:\n" COLOR_OFF);
	str = l_util_hexstring_upper(node->uuid, 16);
	bt_shell_printf("\t" COLOR_GREEN "UUID = %s\n" COLOR_OFF, str);
	l_free(str);
	bt_shell_printf("\t" COLOR_GREEN "primary = %4.4x\n" COLOR_OFF,
								node->unicast);
	bt_shell_printf("\t" COLOR_GREEN "net_keys = ");
	l_queue_foreach(node->net_keys, print_key, NULL);
	bt_shell_printf("\n" COLOR_OFF);

	if (node->app_keys && !l_queue_isempty(node->app_keys)) {
		bt_shell_printf("\t" COLOR_GREEN "app_keys = ");
		l_queue_foreach(node->app_keys, print_key, NULL);
		bt_shell_printf("\n" COLOR_OFF);
	}

	bt_shell_printf("\t" COLOR_GREEN "elements (%u):\n" COLOR_OFF,
								node->num_ele);

	for (i = 0; i < node->num_ele; ++i)
		print_element(node->els[i], i);
}

static bool match_rejected_addr(const void *a, const void *b)
{
	const struct rejected_addr *addr = a;
	uint16_t unicast = L_PTR_TO_UINT(b);

	return addr->unicast == unicast;
}

static uint16_t get_next_addr(uint16_t high, uint16_t addr,
							uint8_t ele_cnt)
{
	while ((addr + ele_cnt - 1) <= high) {
		int i = 0;

		for (i = 0; i < ele_cnt; i++) {
			struct rejected_addr *reject;

			reject = l_queue_find(reject_list, match_rejected_addr,
						L_UINT_TO_PTR(addr + i));
			if (!reject)
				break;
		}

		addr += i;

		if ((i != ele_cnt) && (addr + ele_cnt - 1) <= high)
			return addr;
	}

	return 0;
}

static bool check_iv_index(const void *a, const void *b)
{
	const struct rejected_addr *reject = a;
	uint32_t iv_index = L_PTR_TO_UINT(b);

	return (abs_diff(iv_index, reject->iv_index) > 2);
}

void remote_print_node(uint16_t addr)
{
	struct remote_node *rmt;

	if (!nodes)
		return;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return;

	print_node(rmt, NULL);
}

void remote_print_all(void)
{
	if (!nodes)
		return;

	l_queue_foreach(nodes, print_node, NULL);
}

uint16_t remote_get_next_unicast(uint16_t low, uint16_t high, uint8_t ele_cnt)
{
	struct remote_node *rmt;
	const struct l_queue_entry *l;
	uint16_t addr;

	/* Note: the address space includes both low and high terminal values */
	if (ele_cnt > (high - low + 1))
		return 0;

	if (!nodes || l_queue_isempty(nodes))
		return low;

	addr = low;
	l = l_queue_get_entries(nodes);

	/* Cycle through the sorted (by unicast) node list */
	for (; l; l = l->next) {
		rmt = l->data;

		if (rmt->unicast < low)
			continue;

		if (rmt->unicast >= (addr + ele_cnt)) {
			uint16_t unicast;

			unicast = get_next_addr(rmt->unicast - 1, addr,
								ele_cnt);
			if (unicast)
				return unicast;
		}

		addr = rmt->unicast + rmt->num_ele;
	}

	addr = get_next_addr(high, addr, ele_cnt);

	return addr;
}

void remote_add_rejected_address(uint16_t addr, uint32_t iv_index, bool save)
{
	struct rejected_addr *reject;

	if (!reject_list)
		reject_list = l_queue_new();

	reject = l_new(struct rejected_addr, 1);
	reject->unicast = addr;
	reject->iv_index = iv_index;

	l_queue_push_tail(reject_list, reject);

	if (save)
		mesh_db_add_rejected_addr(addr, iv_index);
}

void remote_clear_rejected_addresses(uint32_t iv_index)
{
	struct rejected_addr *reject;

	reject = l_queue_remove_if(reject_list, check_iv_index,
						L_UINT_TO_PTR(iv_index));

	while (reject) {
		l_free(reject);
		reject = l_queue_remove_if(reject_list, check_iv_index,
						L_UINT_TO_PTR(iv_index));
	}

	mesh_db_clear_rejected(iv_index);
}
