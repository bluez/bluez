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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/time.h>
#include <ell/ell.h>
#include <json-c/json.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/mesh-io.h"
#include "mesh/net.h"
#include "mesh/mesh-db.h"
#include "mesh/provision.h"
#include "mesh/storage.h"
#include "mesh/appkey.h"
#include "mesh/model.h"
#include "mesh/cfgmod.h"
#include "mesh/util.h"
#include "mesh/error.h"
#include "mesh/dbus.h"
#include "mesh/agent.h"
#include "mesh/node.h"

#define MIN_COMP_SIZE 14

#define MESH_NODE_PATH_PREFIX "/node"
#define MESH_ELEMENT_PATH_PREFIX "/ele"

/* Default element location: unknown */
#define DEFAULT_LOCATION 0x0000

#define DEFAULT_CRPL 10
#define DEFAULT_SEQUENCE_NUMBER 0

struct node_element {
	char *path;
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
	struct l_queue *elements;
	char *app_path;
	char *owner;
	char *path;
	void *jconfig;
	char *cfg_file;
	uint32_t disc_watch;
	time_t upd_sec;
	uint32_t seq_number;
	uint32_t seq_min_cache;
	uint16_t id;
	bool provisioner;
	uint16_t primary;
	struct node_composition *comp;
	struct {
		uint16_t interval;
		uint8_t cnt;
		uint8_t mode;
	} relay;
	uint8_t dev_uuid[16];
	uint8_t dev_key[16];
	uint8_t num_ele;
	uint8_t ttl;
	uint8_t lpn;
	uint8_t proxy;
	uint8_t friend;
	uint8_t beacon;
};

struct attach_obj_request {
	node_attach_ready_func_t cb;
	struct mesh_node *node;
};

struct join_obj_request {
	node_join_ready_func_t cb;
	const uint8_t *uuid;
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

static bool match_token(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	const uint64_t *token = b;
	const uint64_t tmp = l_get_u64(node->dev_key);
	return *token == tmp;
}

static bool match_element_idx(const void *a, const void *b)
{
	const struct node_element *element = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (element->idx == index);
}

static bool match_element_path(const void *a, const void *b)
{
	const struct node_element *element = a;
	const char *path = b;

	if (!element->path)
		return false;

	return (!strcmp(element->path, path));
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
	node->net = mesh_net_new(node);

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, node);

	return node;
}

static void free_element_path(void *a, void *b)
{
	struct node_element *element = a;

	l_free(element->path);
	element->path = NULL;
}

static void element_free(void *data)
{
	struct node_element *element = data;

	l_queue_destroy(element->models, mesh_model_free);
	l_free(element->path);
	l_free(element);
}

static void free_node_resources(void *data)
{
	struct mesh_node *node = data;

	/* Unregister io callbacks */
	if(node->net)
		mesh_net_detach(node->net);
	mesh_net_free(node->net);

	l_queue_destroy(node->elements, element_free);
	l_free(node->comp);
	l_free(node->app_path);
	l_free(node->owner);

	if (node->path)
		l_dbus_object_remove_interface(dbus_get_bus(), node->path,
					MESH_NODE_INTERFACE);
	l_free(node->path);

	l_free(node);
}

void node_free(struct mesh_node *node)
{
	if (!node)
		return;

	l_queue_remove(nodes, node);
	free_node_resources(node);
}

static bool add_models(struct mesh_node *node, struct node_element *ele,
						struct mesh_db_element *db_ele)
{
	const struct l_queue_entry *entry;

	if (!ele->models)
		ele->models = l_queue_new();

	entry = l_queue_get_entries(db_ele->models);
	for (; entry; entry = entry->next) {
		struct mesh_model *mod;
		struct mesh_db_model *db_mod;

		db_mod = entry->data;
		mod = mesh_model_setup(node, ele->idx, db_mod);
		if (!mod)
			return false;

		l_queue_push_tail(ele->models, mod);
	}

	return true;
}

static void add_internal_model(struct mesh_node *node, uint32_t mod_id,
								uint8_t ele_idx)
{
	struct node_element *ele;
	struct mesh_model *mod;
	struct mesh_db_model db_mod;

	ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(ele_idx));

	if (!ele)
		return;

	memset(&db_mod, 0, sizeof(db_mod));
	db_mod.id = mod_id;

	mod = mesh_model_setup(node, ele_idx, &db_mod);
	if (!mod)
		return;

	if (!ele->models)
		ele->models = l_queue_new();

	l_queue_push_tail(ele->models, mod);
}

static bool add_element(struct mesh_node *node, struct mesh_db_element *db_ele)
{
	struct node_element *ele;

	ele = l_new(struct node_element, 1);
	if (!ele)
		return false;

	ele->idx = db_ele->index;
	ele->location = db_ele->location;

	if (!db_ele->models || !add_models(node, ele, db_ele))
		return false;

	l_queue_push_tail(node->elements, ele);
	return true;
}

static bool add_elements(struct mesh_node *node, struct mesh_db_node *db_node)
{
	const struct l_queue_entry *entry;

	if (!node->elements)
		node->elements = l_queue_new();

	entry = l_queue_get_entries(db_node->elements);
	for (; entry; entry = entry->next)
		if (!add_element(node, entry->data))
			return false;

	return true;
}

bool node_init_from_storage(struct mesh_node *node, void *data)
{
	struct mesh_db_node *db_node = data;
	unsigned int num_ele;

	node->comp = l_new(struct node_composition, 1);
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

	l_debug("relay %2.2x, proxy %2.2x, lpn %2.2x, friend %2.2x",
			node->relay.mode, node->proxy, node->friend, node->lpn);
	node->ttl = db_node->ttl;
	node->seq_number = db_node->seq_number;

	num_ele = l_queue_length(db_node->elements);
	if (num_ele > 0xff)
		return false;

	node->num_ele = num_ele;
	if (num_ele != 0 && !add_elements(node, db_node))
		return false;

	node->primary = db_node->unicast;

	memcpy(node->dev_uuid, db_node->uuid, 16);

	/* Initialize configuration server model */
	mesh_config_srv_init(node, PRIMARY_ELE_IDX);

	return true;
}

void node_cleanup(void *data)
{
	struct mesh_node *node = data;
	struct mesh_net *net = node->net;

	/* Save local node configuration */
	if (node->cfg_file) {

		/* Preserve the last sequence number */
		storage_write_sequence_number(net, mesh_net_get_seq_num(net));

		if (storage_save_config(node, true, NULL, NULL))
			l_info("Saved final config to %s", node->cfg_file);
	}

	if (node->disc_watch)
		l_dbus_remove_watch(dbus_get_bus(), node->disc_watch);

	free_node_resources(node);
}

void node_cleanup_all(void)
{
	l_queue_destroy(nodes, node_cleanup);
	l_dbus_unregister_interface(dbus_get_bus(), MESH_NODE_INTERFACE);
}

bool node_is_provisioned(struct mesh_node *node)
{
	return (!IS_UNASSIGNED(node->primary));
}

bool node_app_key_delete(struct mesh_net *net, uint16_t addr,
				uint16_t net_idx, uint16_t app_idx)
{
	struct mesh_node *node;
	const struct l_queue_entry *entry;

	node = node_find_by_addr(addr);
	if (!node)
		return false;

	entry = l_queue_get_entries(node->elements);
	for (; entry; entry = entry->next) {
		struct node_element *ele = entry->data;

		mesh_model_app_key_delete(node, ele->models, app_idx);
	}
	return true;
}

uint16_t node_get_primary(struct mesh_node *node)
{
	if (!node)
		return UNASSIGNED_ADDRESS;
	else
		return node->primary;
}

void node_set_device_key(struct mesh_node *node, uint8_t key[16])
{
	memcpy(node->dev_key, key, 16);
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

uint8_t node_default_ttl_get(struct mesh_node *node)
{
	if (!node)
		return DEFAULT_TTL;
	return node->ttl;
}

bool node_default_ttl_set(struct mesh_node *node, uint8_t ttl)
{
	bool res;

	if (!node)
		return false;

	res = storage_set_ttl(node->jconfig, ttl);

	if (res) {
		node->ttl = ttl;
		mesh_net_set_default_ttl(node->net, ttl);
	}

	return res;
}

bool node_set_sequence_number(struct mesh_node *node, uint32_t seq)
{
	struct timeval write_time;

	if (!node)
		return false;

	node->seq_number = seq;

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

			l_debug("Old Seq Cache: %d", node->seq_min_cache);

			ideal *= (MIN_SEQ_CACHE_TIME / elapsed);

			if (ideal > node->seq_min_cache + MIN_SEQ_CACHE)
				node->seq_min_cache = ideal;
			else
				node->seq_min_cache += MIN_SEQ_CACHE;

			l_debug("New Seq Cache: %d", node->seq_min_cache);
		}
	}

	node->upd_sec = write_time.tv_sec;

	return storage_write_sequence_number(node->net, seq);
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
	bool res;

	if (!node || node->relay.mode == MESH_MODE_UNSUPPORTED)
		return false;

	res = storage_set_relay(node->jconfig, enable, cnt, interval);

	if (res) {
		node->relay.mode = enable ? MESH_MODE_ENABLED :
							MESH_MODE_DISABLED;
		node->relay.cnt = cnt;
		node->relay.interval = interval;
		mesh_net_set_relay_mode(node->net, enable, cnt, interval);
	}

	return res;
}

bool node_proxy_mode_set(struct mesh_node *node, bool enable)
{
	bool res;
	uint8_t proxy;

	if (!node || node->proxy == MESH_MODE_UNSUPPORTED)
		return false;

	proxy = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_set_mode(node->jconfig, proxy, "proxy");

	if (res) {
		node->proxy = proxy;
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
	bool res;
	uint8_t beacon;

	if (!node)
		return false;

	beacon = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_set_mode(node->jconfig, beacon, "beacon");

	if (res) {
		node->beacon = beacon;
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
	bool res;
	uint8_t friend;

	if (!node || node->friend == MESH_MODE_UNSUPPORTED)
		return false;

	friend = enable ? MESH_MODE_ENABLED : MESH_MODE_DISABLED;
	res = storage_set_mode(node->jconfig, friend, "friend");

	if (res) {
		node->friend = friend;
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

			if ((mod_id & VENDOR_ID_MASK) == VENDOR_ID_MASK) {
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


#define MIN_COMPOSITION_LEN 16

bool node_parse_composition(struct mesh_node *node, uint8_t *data,
								uint16_t len)
{
	struct node_composition *comp;
	uint16_t features;
	uint8_t num_ele;
	bool mode;

	if (!len)
		return false;

	/* Skip page -- We only support Page Zero */
	data++;
	len--;

	if (len < MIN_COMPOSITION_LEN)
		return false;

	comp = l_new(struct node_composition, 1);
	if (!comp)
		return false;

	node->elements = l_queue_new();
	if (!node->elements) {
		l_free(comp);
		return false;
	}

	node->comp = l_new(struct node_composition, 1);
	comp->cid = l_get_le16(&data[0]);
	comp->pid = l_get_le16(&data[2]);
	comp->vid = l_get_le16(&data[4]);
	comp->crpl = l_get_le16(&data[6]);
	features = l_get_le16(&data[8]);
	data += 10;
	len -= 10;

	mode = !!(features & FEATURE_PROXY);
	node->proxy = mode ? MESH_MODE_DISABLED : MESH_MODE_UNSUPPORTED;

	mode = !!(features & FEATURE_LPN);
	node->lpn = mode ? MESH_MODE_DISABLED : MESH_MODE_UNSUPPORTED;

	mode = !!(features & FEATURE_FRIEND);
	node->friend = mode ? MESH_MODE_DISABLED : MESH_MODE_UNSUPPORTED;

	mode = !!(features & FEATURE_RELAY);
	node->relay.mode = mode ? MESH_MODE_DISABLED : MESH_MODE_UNSUPPORTED;

	num_ele = 0;

	do {
		uint8_t m, v;
		uint16_t mod_id;
		uint16_t vendor_id;
		struct node_element *ele;
		struct mesh_model *mod;

		ele = l_new(struct node_element, 1);
		if (!ele)
			return false;

		ele->idx = num_ele;
		ele->location = l_get_le16(data);
		len -= 2;
		data += 2;

		m = *data++;
		v = *data++;
		len -= 2;

		/* Parse SIG models */
		while (len >= 2 && m--) {
			mod_id = l_get_le16(data);
			mod = mesh_model_new(ele->idx, mod_id);
			if (!mod) {
				element_free(ele);
				goto fail;
			}

			l_queue_push_tail(ele->models, mod);
			data += 2;
			len -= 2;
		}

		if (v && len < 4) {
			element_free(ele);
			goto fail;
		}

		/* Parse vendor models */
		while (len >= 4 && v--) {
			mod_id = l_get_le16(data + 2);
			vendor_id = l_get_le16(data);
			mod_id |= (vendor_id << 16);
			mod = mesh_model_vendor_new(ele->idx, vendor_id,
									mod_id);
			if (!mod) {
				element_free(ele);
				goto fail;
			}

			l_queue_push_tail(ele->models, mod);
			data += 4;
			len -= 4;
		}

		num_ele++;
		l_queue_push_tail(node->elements, ele);

	} while (len >= 6);

	/* Check the consistency for the remote node */
	if (node->num_ele > num_ele)
		goto fail;

	node->comp = comp;
	node->num_ele = num_ele;

	return true;

fail:
	l_queue_destroy(node->elements, element_free);
	l_free(comp);

	return false;
}

void node_id_set(struct mesh_node *node, uint16_t id)
{
	if (node)
		node->id = id;
}

static void attach_io(void *a, void *b)
{
	struct mesh_node *node = a;
	struct mesh_io *io = b;

	if (node->net)
		mesh_net_attach(node->net, io);
}

/* Register callbacks for io */
void node_attach_io(struct mesh_io *io)
{
	l_queue_foreach(nodes, attach_io, io);
}

static bool register_node_object(struct mesh_node *node)
{
	node->path = l_malloc(strlen(MESH_NODE_PATH_PREFIX) + 5);

	snprintf(node->path, 10, MESH_NODE_PATH_PREFIX "%4.4x", node->id);

	if (!l_dbus_object_add_interface(dbus_get_bus(), node->path,
					MESH_NODE_INTERFACE, node))
		return false;

	return true;
}

static void app_disc_cb(struct l_dbus *bus, void *user_data)
{
	struct mesh_node *node = user_data;

	l_info("App %s disconnected (%u)", node->owner, node->disc_watch);

	node->disc_watch = 0;

	l_queue_foreach(node->elements, free_element_path, NULL);

	l_free(node->owner);
	node->owner = NULL;

	l_free(node->app_path);
	node->app_path = NULL;
}

static bool validate_element_properties(struct mesh_node *node,
					const char *path,
					struct l_dbus_message_iter *properties)
{
	uint8_t ele_idx;
	struct node_element *ele;
	const char *key;
	struct l_dbus_message_iter variant;
	bool have_index = false;

	l_debug("path %s", path);

	while (l_dbus_message_iter_next_entry(properties, &key, &variant)) {
		if (!strcmp(key, "Index")) {
			have_index = true;
			break;
		}
	}

	if (!have_index) {
		l_debug("Mandatory property \"Index\" not found");
		return false;
	}

	if (!l_dbus_message_iter_get_variant(&variant, "y", &ele_idx))
		return false;

	ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(ele_idx));

	if (!ele) {
		l_debug("Element with index %u not found", ele_idx);
		return false;
	}

	/* TODO: validate models */

	ele->path = l_strdup(path);

	return true;
}

static void get_managed_objects_attach_cb(struct l_dbus_message *msg,
								void *user_data)
{
	struct l_dbus_message_iter objects, interfaces;
	struct attach_obj_request *req = user_data;
	struct mesh_node *node = req->node;
	const char *path;
	uint64_t token = l_get_u64(node->dev_key);
	uint8_t num_ele;

	if (l_dbus_message_is_error(msg)) {
		l_error("Failed to get app's dbus objects");
		goto fail;
	}

	if (!l_dbus_message_get_arguments(msg, "a{oa{sa{sv}}}", &objects)) {
		l_error("Failed to parse app's dbus objects");
		goto fail;
	}

	num_ele = 0;

	while (l_dbus_message_iter_next_entry(&objects, &path, &interfaces)) {
		struct l_dbus_message_iter properties;
		const char *interface;

		while (l_dbus_message_iter_next_entry(&interfaces, &interface,
								&properties)) {
			if (strcmp(MESH_ELEMENT_INTERFACE, interface))
				continue;

			if (!validate_element_properties(node, path,
								&properties))
				goto fail;

			num_ele++;
		}
	}

	/*
	 * Check that the number of element objects matches the expected number
	 * of elements on the node
	 */
	if (num_ele != node->num_ele)
		goto fail;

	/* Register node object with D-Bus */
	register_node_object(node);

	if (node->path) {
		struct l_dbus *bus = dbus_get_bus();

		node->disc_watch = l_dbus_add_disconnect_watch(bus, node->owner,
						app_disc_cb, node, NULL);
		req->cb(MESH_ERROR_NONE, node->path, token);

		return;
	}
fail:
	req->cb(MESH_ERROR_FAILED, NULL, token);

	l_queue_foreach(node->elements, free_element_path, NULL);
	l_free(node->app_path);
	node->app_path = NULL;

	l_free(node->owner);
	node->owner = NULL;
}

/* Establish relationship between application and mesh node */
int node_attach(const char *app_path, const char *sender, uint64_t token,
						node_attach_ready_func_t cb)
{
	struct attach_obj_request *req;
	struct mesh_node *node;

	l_debug("");

	node = l_queue_find(nodes, match_token, &token);
	if (!node)
		return MESH_ERROR_NOT_FOUND;

	/* TODO: decide what to do if previous node->app_path is not NULL */
	node->app_path = l_strdup(app_path);

	node->owner = l_strdup(sender);

	req = l_new(struct attach_obj_request, 1);
	req->node = node;
	req->cb = cb;

	l_dbus_method_call(dbus_get_bus(), sender, app_path,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_attach_cb,
					req, l_free);
	return MESH_ERROR_NONE;

}

static void add_model_from_properties(struct node_element *ele,
					struct l_dbus_message_iter *property)
{
	struct l_dbus_message_iter ids;
	uint16_t model_id;
	int i = 0;

	if (!ele->models)
		ele->models = l_queue_new();

	if (!l_dbus_message_iter_get_variant(property, "aq", &ids))
		return;

	while (l_dbus_message_iter_next_entry(&ids, &model_id)) {
		struct mesh_model *mod;
		l_debug("model_id %4.4x", model_id);
		mod = mesh_model_new(ele->idx, model_id);
		l_queue_push_tail(ele->models, mod);
		i++;
		if (i > 3)
			break;
	}
}

static void add_vendor_model_from_properties(struct node_element *ele,
					struct l_dbus_message_iter *property)
{
	struct {
		uint16_t v;
		uint16_t m;
	} id_pair;

	if (!ele->models)
		ele->models = l_queue_new();

	while (l_dbus_message_iter_next_entry(property, &id_pair)) {
		struct mesh_model *mod;
		mod = mesh_model_vendor_new(ele->idx, id_pair.v, id_pair.m);
		l_queue_push_tail(ele->models, mod);
	}
}

static bool get_element_properties(struct mesh_node *node, const char *path,
					struct l_dbus_message_iter *properties)
{
	struct node_element *ele;
	const char *key;
	struct l_dbus_message_iter variant;
	bool have_index = false;

	l_debug("path %s", path);

	ele = l_new(struct node_element, 1);
	ele->location = DEFAULT_LOCATION;

	while (l_dbus_message_iter_next_entry(properties, &key, &variant)) {
		if (!strcmp(key, "Index")) {
			if (!l_dbus_message_iter_get_variant(&variant, "y",
								&ele->idx))
				return false;
			have_index = true;
		} else if (!strcmp(key, "Location")) {
			l_dbus_message_iter_get_variant(&variant, "q",
								&ele->location);
		} else if (!strcmp(key, "Models")) {
			add_model_from_properties(ele, &variant);
		} else if (!strcmp(key, "VendorModels")) {
			add_vendor_model_from_properties(ele, &variant);
		}
	}

	if (!have_index) {
		l_debug("Mandatory property \"Index\" not found");
		return false;
	}

	l_queue_push_tail(node->elements, ele);

	return true;
}

static bool get_app_properties(struct mesh_node *node, const char *path,
					struct l_dbus_message_iter *properties)
{
	const char *key;
	struct l_dbus_message_iter variant;

	l_debug("path %s", path);

	if (!node->comp)
		node->comp = l_new(struct node_composition, 1);

	while (l_dbus_message_iter_next_entry(properties, &key, &variant)) {

		if (!strcmp(key, "CompanyID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
							&node->comp->cid))
				return false;
		} else if (!strcmp(key, "ProductID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
							&node->comp->pid))
				return false;
		} else if (!strcmp(key, "VersionID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
							&node->comp->vid))
				return false;
		}
	}

	return true;
}

static void convert_node_to_storage(struct mesh_node *node,
						struct mesh_db_node *db_node)
{
	const struct l_queue_entry *entry;

	db_node->cid = node->comp->cid;
	db_node->pid = node->comp->pid;
	db_node->vid = node->comp->vid;
	db_node->crpl = node->comp->crpl;
	db_node->modes.lpn = node->lpn;
	db_node->modes.proxy = node->proxy;

	memcpy(db_node->uuid, node->dev_uuid, 16);

	node->friend = db_node->modes.friend;
	db_node->modes.relay.state = node->relay.mode;
	db_node->modes.relay.cnt = node->relay.cnt;
	db_node->modes.relay.interval = node->relay.interval;
	db_node->modes.beacon = node->beacon;

	db_node->ttl = node->ttl;
	db_node->seq_number = node->seq_number;

	db_node->elements = l_queue_new();

	entry = l_queue_get_entries(node->elements);

	for (; entry; entry = entry->next) {
		struct node_element *ele = entry->data;
		struct mesh_db_element *db_ele;
		const struct l_queue_entry *mod_entry;

		db_ele = l_new(struct mesh_db_element, 1);

		db_ele->index = ele->idx;
		db_ele->location = ele->location;
		db_ele->models = l_queue_new();

		mod_entry = l_queue_get_entries(ele->models);

		for (; mod_entry; mod_entry = mod_entry->next) {
			struct mesh_model *mod = mod_entry->data;
			struct mesh_db_model *db_mod;
			uint32_t mod_id = mesh_model_get_model_id(mod);

			db_mod = l_new(struct mesh_db_model, 1);
			db_mod->id = mod_id;
			db_mod->vendor = ((mod_id & VENDOR_ID_MASK)
							!= VENDOR_ID_MASK);

			l_queue_push_tail(db_ele->models, db_mod);
		}
		l_queue_push_tail(db_node->elements, db_ele);
	}

}

static bool create_node_config(struct mesh_node *node)
{
	struct mesh_db_node db_node;
	const struct l_queue_entry *entry;
	bool res;

	convert_node_to_storage(node, &db_node);
	res = storage_create_node_config(node, &db_node);

	/* Free temporarily allocated resources */
	entry = l_queue_get_entries(db_node.elements);
	for (; entry; entry = entry->next) {
		struct mesh_db_element *db_ele = entry->data;

		l_queue_destroy(db_ele->models, l_free);
	}

	l_queue_destroy(db_node.elements, l_free);

	return res;
}

static void set_defaults(struct mesh_node *node)
{
	/* TODO: these values should come from mesh.conf */
	if (!node->comp)
		node->comp = l_new(struct node_composition, 1);

	node->comp->crpl = DEFAULT_CRPL;
	node->lpn = MESH_MODE_UNSUPPORTED;
	node->proxy = MESH_MODE_UNSUPPORTED;
	node->friend = MESH_MODE_UNSUPPORTED;
	node->beacon = MESH_MODE_DISABLED;
	node->relay.mode = MESH_MODE_DISABLED;
	node->ttl = DEFAULT_TTL;
	node->seq_number = DEFAULT_SEQUENCE_NUMBER;

	/* Add configuration server model on primary element */
	add_internal_model(node, CONFIG_SRV_MODEL, PRIMARY_ELE_IDX);
}

static void get_managed_objects_join_cb(struct l_dbus_message *msg,
								void *user_data)
{
	struct l_dbus_message_iter objects, interfaces;
	struct join_obj_request *req = user_data;
	const char *path;
	struct mesh_node *node = NULL;
	void *agent = NULL;

	if (l_dbus_message_is_error(msg)) {
		l_error("Failed to get app's dbus objects");
		goto fail;
	}

	if (!l_dbus_message_get_arguments(msg, "a{oa{sa{sv}}}", &objects)) {
		l_error("Failed to parse app's dbus objects");
		goto fail;
	}

	node = l_new(struct mesh_node, 1);
	node->elements = l_queue_new();

	while (l_dbus_message_iter_next_entry(&objects, &path, &interfaces)) {
		struct l_dbus_message_iter properties;
		const char *interface;

		while (l_dbus_message_iter_next_entry(&interfaces, &interface,
								&properties)) {
			bool res;

			if (!strcmp(MESH_ELEMENT_INTERFACE, interface)) {
				res = get_element_properties(node, path,
								&properties);
				if (!res)
					goto fail;

				node->num_ele++;
				continue;

			}

			if (!strcmp(MESH_APPLICATION_INTERFACE, interface)) {
				res = get_app_properties(node, path,
								&properties);
				if (!res)
					goto fail;

				continue;
			}

			if (!strcmp(MESH_PROVISION_AGENT_INTERFACE,
								interface)) {
				const char *sender;

				sender = l_dbus_message_get_sender(msg);
				agent = mesh_agent_create(path, sender,
								&properties);
				if (!agent)
					goto fail;
			}
		}
	}

	if (!node->comp){
		l_error("Interface %s not found", MESH_APPLICATION_INTERFACE);
		goto fail;
	}

	if (!agent) {
		l_error("Interface %s not found",
						MESH_PROVISION_AGENT_INTERFACE);
		goto fail;
	}

	if (!node->num_ele) {
		l_error("Interface %s not found", MESH_ELEMENT_INTERFACE);
		goto fail;
	}

	if (!l_queue_find(node->elements, match_element_idx,
				L_UINT_TO_PTR(PRIMARY_ELE_IDX))) {

		l_debug("Primary element not detected");
		goto fail;
	}

	set_defaults(node);
	memcpy(node->dev_uuid, req->uuid, 16);

	if (!create_node_config(node))
		goto fail;

	req->cb(node, agent);

	return;
fail:
	if (agent)
		free_node_resources(node);

	if (node)
		mesh_agent_remove(agent);

	req->cb(NULL, NULL);
}

/* Create a temporary pre-provisioned node */
void node_join(const char *app_path, const char *sender, const uint8_t *uuid,
						node_join_ready_func_t cb)
{
	struct join_obj_request *req;

	l_debug("");

	req = l_new(struct join_obj_request, 1);
	req->uuid = uuid;
	req->cb = cb;

	l_dbus_method_call(dbus_get_bus(), sender, app_path,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_join_cb,
					req, l_free);
}

static void build_element_config(void *a, void *b)
{
	struct node_element *ele = a;
	struct l_dbus_message_builder *builder = b;

	l_debug("Element %u", ele->idx);

	l_dbus_message_builder_enter_struct(builder, "ya(qa{sv})");

	/* Element index */
	l_dbus_message_builder_append_basic(builder, 'y', &ele->idx);

	l_dbus_message_builder_enter_array(builder, "(qa{sv})");

	/* Iterate over models */
	l_queue_foreach(ele->models, model_build_config, builder);

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_leave_struct(builder);
}

void node_build_attach_reply(struct l_dbus_message *reply, uint64_t token)
{
	struct mesh_node *node;
	struct l_dbus_message_builder *builder;

	node = l_queue_find(nodes, match_token, &token);
	if (!node)
		return;

	builder = l_dbus_message_builder_new(reply);

	/* Node object path */
	l_dbus_message_builder_append_basic(builder, 'o', node->path);

	/* Array of element configurations "a*/
	l_dbus_message_builder_enter_array(builder, "(ya(qa{sv}))");
	l_queue_foreach(node->elements, build_element_config, builder);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static struct l_dbus_message *send_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct l_dbus_message_iter iter_data;
	struct node_element *ele;
	uint16_t dst, app_idx, src;
	uint8_t data[MESH_MAX_ACCESS_PAYLOAD];
	uint32_t len;
	struct l_dbus_message *reply;

	l_debug("Send");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqqay", &ele_path, &dst,
							&app_idx, &iter_data))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	l_dbus_message_iter_get_fixed_array(&iter_data, data, &len);
	if (!len)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
						"Mesh message is empty");

	if (!mesh_model_send(node, src, dst, app_idx,
				mesh_net_get_default_ttl(node->net), data, len))
		return dbus_error(msg, MESH_ERROR_FAILED, NULL);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *publish_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct l_dbus_message_iter iter_data;
	uint16_t mod_id, src;
	struct node_element *ele;
	uint8_t data[MESH_MAX_ACCESS_PAYLOAD];
	uint32_t len;
	struct l_dbus_message *reply;
	int result;

	l_debug("Publish");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqay", &ele_path, &mod_id,
								&iter_data))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	l_dbus_message_iter_get_fixed_array(&iter_data, data, &len);
	if (!len)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
						"Mesh message is empty");

	result = mesh_model_publish(node, VENDOR_ID_MASK | mod_id, src,
				mesh_net_get_default_ttl(node->net), data, len);

	if (result != MESH_ERROR_NONE)
		return dbus_error(msg, result, NULL);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static struct l_dbus_message *vendor_publish_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct l_dbus_message_iter iter_data;
	uint16_t src;
	uint16_t model_id, vendor;
	uint32_t vendor_mod_id;
	struct node_element *ele;
	uint8_t data[MESH_MAX_ACCESS_PAYLOAD];
	uint32_t len;
	struct l_dbus_message *reply;
	int result;

	l_debug("Publish");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqqay", &ele_path, &vendor,
							&model_id, &iter_data))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	l_dbus_message_iter_get_fixed_array(&iter_data, data, &len);
	if (!len)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
						"Mesh message is empty");

	vendor_mod_id = (vendor << 16) | model_id;
	result = mesh_model_publish(node, vendor_mod_id, src,
				mesh_net_get_default_ttl(node->net), data, len);

	if (result != MESH_ERROR_NONE)
		return dbus_error(msg, result, NULL);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static void setup_node_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "Send", 0, send_call, "", "oqqay",
						"element_path", "destination",
						"key", "data");
	l_dbus_interface_method(iface, "Publish", 0, publish_call, "", "oqay",
					"element_path", "model_id", "data");
	l_dbus_interface_method(iface, "VendorPublish", 0, vendor_publish_call,
						"", "oqqay", "element_path",
						"vendor", "model_id", "data");

	/*TODO: Properties */
}

bool node_dbus_init(struct l_dbus *bus)
{
	if (!l_dbus_register_interface(bus, MESH_NODE_INTERFACE,
						setup_node_interface,
						NULL, false)) {
		l_info("Unable to register %s interface", MESH_NODE_INTERFACE);
		return false;
	}

	return true;
}

const char *node_get_owner(struct mesh_node *node)
{
	return node->owner;
}

const char *node_get_element_path(struct mesh_node *node, uint8_t ele_idx)
{
	struct node_element *ele;

	ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(ele_idx));

	if (!ele)
		return NULL;

	return ele->path;
}

bool node_add_pending_local(struct mesh_node *node, void *prov_node_info,
							struct mesh_io *io)
{
	struct mesh_prov_node_info *info = prov_node_info;
	bool kr = !!(info->flags & PROV_FLAG_KR);
	bool ivu = !!(info->flags & PROV_FLAG_IVU);

	node->net = mesh_net_new(node);

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, node);

	if (!storage_set_iv_index(node->net, info->iv_index, ivu))
		return false;

	mesh_net_set_iv_index(node->net, info->iv_index, ivu);

	if (!mesh_db_write_uint16_hex(node->jconfig, "unicastAddress",
								info->unicast))
		return false;

	node->primary = info->unicast;
	mesh_net_register_unicast(node->net, info->unicast, node->num_ele);

	memcpy(node->dev_key, info->device_key, 16);
	if (!mesh_db_write_device_key(node->jconfig, info->device_key))
		return false;

	if (mesh_net_add_key(node->net, info->net_index, info->net_key) !=
							MESH_STATUS_SUCCESS)
		return false;

	if (kr) {
		/* Duplicate net key, if the key refresh is on */
		if (mesh_net_update_key(node->net, info->net_index,
				info->net_key) != MESH_STATUS_SUCCESS)
			return false;

		if (!mesh_db_net_key_set_phase(node->jconfig, info->net_index,
							KEY_REFRESH_PHASE_TWO))
			return false;
	}

	if (!storage_save_config(node, true, NULL, NULL))
		return false;

	/* Initialize configuration server model */
	mesh_config_srv_init(node, PRIMARY_ELE_IDX);

	mesh_net_attach(node->net, io);

	return true;
}

void node_jconfig_set(struct mesh_node *node, void *jconfig)
{
	node->jconfig = jconfig;
}

void *node_jconfig_get(struct mesh_node *node)
{
	return node->jconfig;
}

void node_cfg_file_set(struct mesh_node *node, char *cfg)
{
	node->cfg_file = cfg;
}

char *node_cfg_file_get(struct mesh_node *node)
{
	return node->cfg_file;
}

struct mesh_net *node_get_net(struct mesh_node *node)
{
	return node->net;
}
