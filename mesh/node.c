/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2018  Intel Corporation. All rights reserved.
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

#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/net.h"
#include "mesh/node.h"
#include "mesh/storage.h"
#include "mesh/appkey.h"
#include "mesh/model.h"

#define MIN_COMP_SIZE 14

struct node_element {
	struct l_queue *models;
	uint16_t location;
	uint8_t idx;
};

struct node_composition {
	uint16_t cid;
	uint16_t pid;
	uint16_t vid;
	uint16_t crpl;
};

struct mesh_node {
	struct mesh_net *net;
	struct l_queue *net_keys;
	struct l_queue *app_keys;
	struct l_queue *elements;
	time_t upd_sec;
	uint32_t seq_number;
	uint32_t seq_min_cache;
	uint16_t primary;
	uint16_t num_ele;
	uint8_t dev_uuid[16];
	uint8_t dev_key[16];
	uint8_t ttl;
	bool provisioner;
	struct node_composition *comp;
	struct {
		uint16_t interval;
		uint8_t cnt;
		uint8_t mode;
	} relay;
	uint8_t lpn;
	uint8_t proxy;
	uint8_t friend;
	uint8_t beacon;
};

static struct l_queue *nodes;

static bool match_node_unicast(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	uint16_t dst = L_PTR_TO_UINT(b);

	return (dst >= node->primary &&
		dst <= (node->primary + node->num_ele - 1));
}

static bool match_device_uuid(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	const uint8_t *uuid = b;

	return (memcmp(node->dev_uuid, uuid, 16) == 0);
}

static bool match_element_idx(const void *a, const void *b)
{
	const struct node_element *element = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (element->idx == index);
}

static bool match_key_idx(const void *a, const void *b)
{
	return (L_PTR_TO_UINT(a) == L_PTR_TO_UINT(b));
}

static bool match_model_id(const void *a, const void *b)
{
	const struct mesh_model *model = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return (mesh_model_get_model_id(model) == id);
}

struct mesh_node *node_find_by_addr(uint16_t addr)
{
	if (!IS_UNICAST(addr))
		return NULL;

	return l_queue_find(nodes, match_node_unicast, L_UINT_TO_PTR(addr));
}

struct mesh_node *node_find_by_uuid(uint8_t uuid[16])
{
	return l_queue_find(nodes, match_device_uuid, uuid);
}

uint8_t *node_uuid_get(struct mesh_node *node)
{
	if (!node)
		return NULL;
	return node->dev_uuid;
}

struct mesh_node *node_new(void)
{
	struct mesh_node *node;

	node = l_new(struct mesh_node, 1);

	if (!node)
		return NULL;

	l_queue_push_tail(nodes, node);

	return node;
}

static void element_free(void *data)
{
	struct node_element *element = data;

	l_queue_destroy(element->models, mesh_model_free);
	l_free(element);
}

static void free_node_resources(void *data)
{
	struct mesh_node *node = data;

	l_queue_destroy(node->net_keys, NULL);
	l_queue_destroy(node->app_keys, NULL);
	l_queue_destroy(node->elements, element_free);
	l_free(node->comp);

	if (node->net)
		mesh_net_unref(node->net);

	l_free(node);
}

void node_free(struct mesh_node *node)
{
	if (!node)
		return;
	l_queue_remove(nodes, node);
	free_node_resources(node);
}

static bool add_models(struct mesh_net *net, struct node_element *ele,
						struct mesh_db_element *db_ele)
{
	const struct l_queue_entry *entry;

	if (!ele->models)
		ele->models = l_queue_new();
	if (!ele->models)
		return false;

	entry = l_queue_get_entries(db_ele->models);
	for (; entry; entry = entry->next) {
		struct mesh_model *mod;
		struct mesh_db_model *db_mod;

		db_mod = entry->data;
		mod = mesh_model_init(net, ele->idx, db_mod);
		if (!mod)
			return false;

		l_queue_push_tail(ele->models, mod);
	}

	return true;
}

static bool add_element(struct mesh_node *node, struct mesh_db_element *db_ele)
{
	struct node_element *ele;

	ele = l_new(struct node_element, 1);
	if (!ele)
		return false;

	ele->idx = db_ele->index;
	ele->location = db_ele->location;

	if (!db_ele->models || !add_models(node->net, ele, db_ele))
		return false;

	l_queue_push_tail(node->elements, ele);
	return true;
}

static bool add_elements(struct mesh_node *node, struct mesh_db_node *db_node)
{
	const struct l_queue_entry *entry;

	if (!node->elements)
		node->elements = l_queue_new();

	if (!node->elements)
		return false;

	entry = l_queue_get_entries(db_node->elements);
	for (; entry; entry = entry->next)
		if (!add_element(node, entry->data))
			return false;

	return true;
}

struct mesh_node *node_create_from_storage(struct mesh_net *net,
						struct mesh_db_node *db_node,
								bool local)
{
	struct mesh_node *node;
	unsigned int num_ele;

	if (local && !net)
		return NULL;

	node = node_new();
	if (!node)
		return NULL;

	node->comp = l_new(struct node_composition, 1);
	if (!node->comp) {
		node_free(node);
		return NULL;
	}

	node->comp->cid = db_node->cid;
	node->comp->pid = db_node->pid;
	node->comp->vid = db_node->vid;
	node->comp->crpl = db_node->crpl;
	node->lpn = db_node->modes.lpn;

	node->proxy = db_node->modes.proxy;
	node->lpn = db_node->modes.lpn;
	node->friend = db_node->modes.friend;
	node->relay.mode = db_node->modes.relay.state;
	node->relay.cnt = db_node->modes.relay.cnt;
	node->relay.interval = db_node->modes.relay.interval;
	node->beacon = db_node->modes.beacon;

	l_info("relay %2.2x, proxy %2.2x, lpn %2.2x, friend %2.2x",
	       node->relay.mode, node->proxy, node->friend, node->lpn);
	node->ttl = db_node->ttl;
	node->seq_number = db_node->seq_number;

	num_ele = l_queue_length(db_node->elements);
	if (num_ele > 0xff) {
		node_free(node);
		return NULL;
	}

	node->num_ele = num_ele;
	if (num_ele != 0 && !add_elements(node, db_node)) {
		node_free(node);
		return NULL;
	}

	node->primary = db_node->unicast;

	memcpy(node->dev_uuid, db_node->uuid, 16);

	if (local)
		node->net = mesh_net_ref(net);

	return node;
}

void node_cleanup(struct mesh_net *net)
{
	struct mesh_node *node;

	if (!net)
		return;
	node = mesh_net_local_node_get(net);
	if (node)
		node_free(node);

	l_queue_destroy(nodes, free_node_resources);

}

bool node_is_provisioned(struct mesh_node *node)
{
	return (!IS_UNASSIGNED(node->primary));
}

bool node_net_key_delete(struct mesh_node *node, uint16_t idx)
{
	if (!node)
		return false;

	if (!l_queue_find(node->net_keys, match_key_idx, L_UINT_TO_PTR(idx)))
		return false;

	l_queue_remove(node->net_keys, L_UINT_TO_PTR(idx));
	/* TODO: remove all associated app keys and bindings */
	return true;
}

bool node_app_key_delete(struct mesh_net *net, uint16_t addr,
				uint16_t net_idx, uint16_t app_idx)
{
	struct mesh_node *node;
	uint32_t index;
	const struct l_queue_entry *entry;

	node = node_find_by_addr(addr);
	if (!node)
		return false;

	index = (net_idx << 16) + app_idx;

	if (!l_queue_find(node->app_keys, match_key_idx, L_UINT_TO_PTR(index)))
		return false;

	l_queue_remove(node->app_keys, L_UINT_TO_PTR(index));

	storage_local_app_key_del(net, net_idx, app_idx);

	entry = l_queue_get_entries(node->elements);
	for (; entry; entry = entry->next) {
		struct node_element *ele = entry->data;

		mesh_model_app_key_delete(net, ele->models, app_idx);
	}

	return true;
}

bool node_set_primary(struct mesh_node *node, uint16_t unicast)
{
	if (!node)
		return false;

	node->primary = unicast;

	/* If local node, save to storage */
	if (node->net)
		return storage_local_set_unicast(node->net, unicast);

	/* TODO: for provisioner, store remote node info */
	return true;
}

uint16_t node_get_primary(struct mesh_node *node)
{
	if (!node)
		return UNASSIGNED_ADDRESS;
	else
		return node->primary;
}

bool node_set_device_key(struct mesh_node *node, uint8_t key[16])

{
	if (!node || !key)
		return false;

	memcpy(node->dev_key, key, 16);

	/* If local node, save to storage */
	if (node->net)
		return storage_local_set_device_key(node->net, key);

	/* TODO: for provisioner, store remote node info */
	return true;
}

const uint8_t *node_get_device_key(struct mesh_node *node)
{
	if (!node)
		return NULL;
	else
		return node->dev_key;
}

uint8_t node_get_num_elements(struct mesh_node *node)
{
	return node->num_ele;
}

struct l_queue *node_get_net_keys(struct mesh_node *node)
{
	if (!node)
		return NULL;
	else
		return node->net_keys;
}

struct l_queue *node_get_app_keys(struct mesh_node *node)
{
	if (!node)
		return NULL;
	else
		return node->app_keys;
}

struct l_queue *node_get_element_models(struct mesh_node *node,
						uint8_t ele_idx, int *status)
{
	struct node_element *ele;

	if (!node) {
		if (status)
			*status = MESH_STATUS_INVALID_ADDRESS;
		return NULL;
	}

	ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(ele_idx));
	if (!ele) {
		if (status)
			*status = MESH_STATUS_INVALID_ADDRESS;
		return NULL;
	}

	if (status)
		*status = MESH_STATUS_SUCCESS;

	return ele->models;
}

struct mesh_model *node_get_model(struct mesh_node *node, uint8_t ele_idx,
						uint32_t id, int *status)
{
	struct l_queue *models;
	struct mesh_model *model;

	if (!node) {
		if (status)
			*status = MESH_STATUS_INVALID_ADDRESS;
		return NULL;
	}

	models = node_get_element_models(node, ele_idx, status);
	if (!models)
		return NULL;

	model = l_queue_find(models, match_model_id, L_UINT_TO_PTR(id));

	if (status)
		*status = (model) ? MESH_STATUS_SUCCESS :
						MESH_STATUS_INVALID_MODEL;

	return model;
}

uint8_t node_default_ttl_get(struct mesh_node *node)
{
	if (!node)
		return DEFAULT_TTL;
	return node->ttl;
}

bool node_default_ttl_set(struct mesh_node *node, uint8_t ttl)
{
	bool res, is_local;

	if (!node)
		return false;

	is_local = (node->net && mesh_net_local_node_get(node->net) == node) ?
		true : false;

	res = storage_local_set_ttl(node->net, ttl);

	if (res) {
		node->ttl = ttl;
		if (is_local)
			mesh_net_set_default_ttl(node->net, ttl);
	}

	return res;
}

bool node_set_sequence_number(struct mesh_node *node, uint32_t seq)
{
	bool is_local;
	struct timeval write_time;


	if (!node)
		return false;

	node->seq_number = seq;

	is_local = (node->net && mesh_net_local_node_get(node->net) == node) ?
		true : false;

	if (!is_local)
		return true;

	/*
	 * Holistically determine worst case 5 minute sequence consumption
	 * so that we typically (once we reach a steady state) rewrite the
	 * local node file with a new seq cache value no more than once every
	 * five minutes (or more)
	 */
	gettimeofday(&write_time, NULL);
	if (node->upd_sec) {
		uint32_t elapsed = write_time.tv_sec - node->upd_sec;

		if (elapsed < MIN_SEQ_CACHE_TIME) {
			uint32_t ideal = node->seq_min_cache;

			l_info("Old Seq Cache: %d", node->seq_min_cache);

			ideal *= (MIN_SEQ_CACHE_TIME / elapsed);

			if (ideal > node->seq_min_cache + MIN_SEQ_CACHE)
				node->seq_min_cache = ideal;
			else
				node->seq_min_cache += MIN_SEQ_CACHE;

			l_info("New Seq Cache: %d", node->seq_min_cache);
		}
	}

	node->upd_sec = write_time.tv_sec;

	l_info("Storage-Write");
	return storage_local_write_sequence_number(node->net, seq);
}

uint32_t node_get_sequence_number(struct mesh_node *node)
{
	if (!node)
		return 0xffffffff;

	return node->seq_number;
}

uint32_t node_seq_cache(struct mesh_node *node)
{
	if (node->seq_min_cache < MIN_SEQ_CACHE)
		node->seq_min_cache = MIN_SEQ_CACHE;

	return node->seq_min_cache;
}

int node_get_element_idx(struct mesh_node *node, uint16_t ele_addr)
{
	uint16_t addr;
	uint8_t num_ele;

	if (!node)
		return -1;

	num_ele = node_get_num_elements(node);
	if (!num_ele)
		return -2;

	addr = node_get_primary(node);

	if (ele_addr < addr || ele_addr >= addr + num_ele)
		return -3;
	else
		return ele_addr - addr;
}

uint16_t node_get_crpl(struct mesh_node *node)
{
	if (!node)
		return 0;

	return node->comp->crpl;
}

uint8_t node_relay_mode_get(struct mesh_node *node, uint8_t *count,
							uint16_t *interval)
{
	if (!node) {
		*count = 0;
		*interval = 0;
		return MESH_MODE_DISABLED;
	}

	*count = node->relay.cnt;
	*interval = node->relay.interval;
	return node->relay.mode;
}

uint8_t node_lpn_mode_get(struct mesh_node *node)
{
	if (!node)
		return MESH_MODE_DISABLED;

	return node->lpn;
}

bool node_relay_mode_set(struct mesh_node *node, bool enable, uint8_t cnt,
							uint16_t interval)
{
	bool res, is_local;

	if (!node || node->relay.mode == MESH_MODE_UNSUPPORTED)
		return false;

	is_local = (node->net && mesh_net_local_node_get(node->net) == node) ?
		true : false;

	res = storage_local_set_relay(node->net, enable, cnt, interval);

	if (res) {
		node->relay.mode = enable ? MESH_MODE_ENABLED :
							MESH_MODE_DISABLED;
		node->relay.cnt = cnt;
		node->relay.interval = interval;
		if (is_local)
			mesh_net_set_relay_mode(node->net, enable, cnt,
								interval);
	}

	return res;
}

bool node_proxy_mode_set(struct mesh_node *node, bool enable)
{
	bool res, is_local;
	uint8_t proxy;

	if (!node || node->proxy == MESH_MODE_UNSUPPORTED)
		return false;

	is_local = (node->net && mesh_net_local_node_get(node->net) == node) ?
		true : false;

	proxy = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_local_set_mode(node->net, proxy, "proxy");

	if (res) {
		node->proxy = proxy;
		if (is_local)
			mesh_net_set_proxy_mode(node->net, enable);
	}

	return res;
}

uint8_t node_proxy_mode_get(struct mesh_node *node)
{
	if (!node)
		return MESH_MODE_DISABLED;

	return node->proxy;
}

bool node_beacon_mode_set(struct mesh_node *node, bool enable)
{
	bool res, is_local;
	uint8_t beacon;

	if (!node)
		return false;

	is_local = (node->net && mesh_net_local_node_get(node->net) == node) ?
		true : false;

	beacon = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_local_set_mode(node->net, beacon, "beacon");

	if (res) {
		node->beacon = beacon;
		if (is_local)
			mesh_net_set_beacon_mode(node->net, enable);
	}

	return res;
}

uint8_t node_beacon_mode_get(struct mesh_node *node)
{
	if (!node)
		return MESH_MODE_DISABLED;

	return node->beacon;
}

bool node_friend_mode_set(struct mesh_node *node, bool enable)
{
	bool res, is_local;
	uint8_t friend;

	if (!node || node->friend == MESH_MODE_UNSUPPORTED)
		return false;

	is_local = (node->net && mesh_net_local_node_get(node->net) == node) ?
		true : false;

	friend = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_local_set_mode(node->net, friend, "friend");

	if (res) {
		node->friend = friend;
		if (is_local)
			mesh_net_set_friend_mode(node->net, enable);
	}

	return res;
}

uint8_t node_friend_mode_get(struct mesh_node *node)
{
	if (!node)
		return MESH_MODE_DISABLED;

	return node->friend;
}

uint16_t node_generate_comp(struct mesh_node *node, uint8_t *buf, uint16_t sz)
{
	uint16_t n, features;
	const struct l_queue_entry *ele_entry;

	if (!node || !node->comp || sz < MIN_COMP_SIZE)
		return 0;

	n = 0;

	l_put_le16(node->comp->cid, buf + n);
	n += 2;
	l_put_le16(node->comp->pid, buf + n);
	n += 2;
	l_put_le16(node->comp->vid, buf + n);
	n += 2;
	l_put_le16(node->comp->crpl, buf + n);
	n += 2;

	features = 0;

	if (node->relay.mode != MESH_MODE_UNSUPPORTED)
		features |= FEATURE_RELAY;
	if (node->proxy != MESH_MODE_UNSUPPORTED)
		features |= FEATURE_PROXY;
	if (node->friend != MESH_MODE_UNSUPPORTED)
		features |= FEATURE_FRIEND;
	if (node->lpn != MESH_MODE_UNSUPPORTED)
		features |= FEATURE_LPN;

	l_put_le16(features, buf + n);
	n += 2;

	ele_entry = l_queue_get_entries(node->elements);
	for (; ele_entry; ele_entry = ele_entry->next) {
		struct node_element *ele = ele_entry->data;
		const struct l_queue_entry *mod_entry;
		uint8_t num_s = 0, num_v = 0;
		uint8_t *mod_buf;

		/* At least fit location and zeros for number of models */
		if ((n + 4) > sz)
			return n;
		l_info("ele->location %d", ele->location);
		l_put_le16(ele->location, buf + n);
		n += 2;

		/* Store models IDs, store num_s and num_v later */
		mod_buf = buf + n;
		n += 2;

		/* Get SIG models */
		mod_entry = l_queue_get_entries(ele->models);
		for (; mod_entry; mod_entry = mod_entry->next) {
			struct mesh_model *mod = mod_entry->data;
			uint32_t mod_id;

			mod_id = mesh_model_get_model_id(
					(const struct mesh_model *) mod);

			if ((mod_id >> 16) == 0xffff) {
				if (n + 2 > sz)
					goto element_done;

				l_put_le16((uint16_t) (mod_id & 0xffff),
								buf + n);
				n += 2;
				num_s++;
			}
		}

		/* Get vendor models */
		mod_entry = l_queue_get_entries(ele->models);
		for (; mod_entry; mod_entry = mod_entry->next) {
			struct mesh_model *mod = mod_entry->data;
			uint32_t mod_id;
			uint16_t vendor;

			mod_id = mesh_model_get_model_id(
					(const struct mesh_model *) mod);

			vendor = (uint16_t) (mod_id >> 16);
			if (vendor != 0xffff) {
				if (n + 4 > sz)
					goto element_done;

				l_put_le16(vendor, buf + n);
				n += 2;
				l_put_le16((uint16_t) (mod_id & 0xffff),
								buf + n);
				n += 2;
				num_v++;
			}

		}

element_done:
		mod_buf[0] = num_s;
		mod_buf[1] = num_v;

	}

	return n;
}
