/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <sys/time.h>

#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/mesh.h"
#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/mesh-config.h"
#include "mesh/provision.h"
#include "mesh/keyring.h"
#include "mesh/model.h"
#include "mesh/cfgmod.h"
#include "mesh/util.h"
#include "mesh/error.h"
#include "mesh/dbus.h"
#include "mesh/agent.h"
#include "mesh/manager.h"
#include "mesh/node.h"

#define MIN_COMP_SIZE 14

#define MESH_NODE_PATH_PREFIX "/node"

/* Default values for a new locally created node */
#define DEFAULT_NEW_UNICAST 0x0001
#define DEFAULT_IV_INDEX 0x0000

/* Default element location: unknown */
#define DEFAULT_LOCATION 0x0000

enum request_type {
	REQUEST_TYPE_JOIN,
	REQUEST_TYPE_ATTACH,
	REQUEST_TYPE_CREATE,
	REQUEST_TYPE_IMPORT,
};

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
	char *obj_path;
	struct mesh_agent *agent;
	struct mesh_config *cfg;
	char *storage_dir;
	uint32_t disc_watch;
	uint32_t seq_number;
	bool provisioner;
	uint16_t primary;
	struct node_composition comp;
	struct {
		uint16_t interval;
		uint8_t cnt;
		uint8_t mode;
	} relay;
	uint8_t uuid[16];
	uint8_t dev_key[16];
	uint8_t token[8];
	uint8_t num_ele;
	uint8_t ttl;
	uint8_t lpn;
	uint8_t proxy;
	uint8_t friend;
	uint8_t beacon;
};

struct node_import {
	uint8_t dev_key[16];
	uint8_t net_key[16];
	uint16_t net_idx;
	struct {
		bool ivu;
		bool kr;
	} flags;
	uint32_t iv_index;
	uint16_t unicast;
};

struct managed_obj_request {
	struct mesh_node *node;
	union {
		node_ready_func_t ready_cb;
		node_join_ready_func_t join_ready_cb;
	};
	struct l_dbus_message *pending_msg;
	enum request_type type;
	union {
		struct mesh_node *attach;
		struct node_import *import;
	};
};

static struct l_queue *nodes;

static bool match_device_uuid(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	const uint8_t *uuid = b;

	return (memcmp(node->uuid, uuid, 16) == 0);
}

static bool match_token(const void *a, const void *b)
{
	const struct mesh_node *node = a;
	const uint64_t *token = b;
	const uint64_t tmp = l_get_be64(node->token);

	return *token == tmp;
}

static bool match_element_idx(const void *a, const void *b)
{
	const struct node_element *element = a;
	uint32_t index = L_PTR_TO_UINT(b);

	return (element->idx == index);
}

static int compare_element_idx(const void *a, const void *b, void *user_data)
{
	uint32_t a_idx = ((const struct node_element *)a)->idx;
	uint32_t b_idx = ((const struct node_element *)b)->idx;

	if (a_idx < b_idx)
		return -1;

	if (a_idx > b_idx)
		return 1;

	return 0;
}

static bool match_element_path(const void *a, const void *b)
{
	const struct node_element *element = a;
	const char *path = b;

	if (!element->path)
		return false;

	return (!strcmp(element->path, path));
}

static bool match_model_id(const void *a, const void *b)
{
	const struct mesh_model *mod = a;
	uint32_t mod_id = L_PTR_TO_UINT(b);

	return mesh_model_get_model_id(mod) == mod_id;
}

static int compare_model_id(const void *a, const void *b, void *user_data)
{
	uint32_t a_id = mesh_model_get_model_id(a);
	uint32_t b_id = mesh_model_get_model_id(b);

	if (a_id < b_id)
		return -1;

	if (a_id > b_id)
		return 1;

	return 0;
}

struct mesh_node *node_find_by_uuid(uint8_t uuid[16])
{
	return l_queue_find(nodes, match_device_uuid, uuid);
}

struct mesh_node *node_find_by_token(uint64_t token)
{
	return l_queue_find(nodes, match_token, (void *) &token);
}

uint8_t *node_uuid_get(struct mesh_node *node)
{
	if (!node)
		return NULL;
	return node->uuid;
}

static void add_internal_model(struct mesh_node *node, uint32_t mod_id,
								uint8_t ele_idx)
{
	struct node_element *ele;
	struct mesh_model *mod;

	ele = l_queue_find(node->elements, match_element_idx,
							L_UINT_TO_PTR(ele_idx));
	if (!ele)
		return;

	if (l_queue_find(ele->models, match_model_id, L_UINT_TO_PTR(mod_id)))
		return;

	mod = mesh_model_new(ele_idx, mod_id);

	l_queue_insert(ele->models, mod, compare_model_id, NULL);
}

static void set_defaults(struct mesh_node *node)
{
	node->lpn = MESH_MODE_UNSUPPORTED;
	node->proxy = MESH_MODE_UNSUPPORTED;
	node->friend = (mesh_friendship_supported()) ? MESH_MODE_DISABLED :
							MESH_MODE_UNSUPPORTED;
	node->beacon = (mesh_beacon_enabled()) ? MESH_MODE_ENABLED :
							MESH_MODE_DISABLED;
	node->relay.mode = (mesh_relay_supported()) ? MESH_MODE_DISABLED :
							MESH_MODE_UNSUPPORTED;
	node->ttl = TTL_MASK;
	node->seq_number = DEFAULT_SEQUENCE_NUMBER;
}

static struct mesh_node *node_new(const uint8_t uuid[16])
{
	struct mesh_node *node;

	node = l_new(struct mesh_node, 1);
	node->net = mesh_net_new(node);
	node->elements = l_queue_new();
	memcpy(node->uuid, uuid, sizeof(node->uuid));
	set_defaults(node);

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

static void free_node_dbus_resources(struct mesh_node *node)
{
	if (!node)
		return;

	if (node->disc_watch) {
		l_dbus_remove_watch(dbus_get_bus(), node->disc_watch);
		node->disc_watch = 0;
	}

	l_queue_foreach(node->elements, free_element_path, NULL);
	l_free(node->owner);
	node->owner = NULL;
	l_free(node->app_path);
	node->app_path = NULL;

	if (node->obj_path) {
		l_dbus_object_remove_interface(dbus_get_bus(), node->obj_path,
							MESH_NODE_INTERFACE);

		l_dbus_object_remove_interface(dbus_get_bus(), node->obj_path,
						MESH_MANAGEMENT_INTERFACE);

		l_dbus_object_remove_interface(dbus_get_bus(), node->obj_path,
						L_DBUS_INTERFACE_PROPERTIES);

		l_free(node->obj_path);
		node->obj_path = NULL;
	}
}

static void free_node_resources(void *data)
{
	struct mesh_node *node = data;

	/* Unregister io callbacks */
	if (node->net)
		mesh_net_detach(node->net);

	l_queue_destroy(node->elements, element_free);
	node->elements = NULL;

	/* In case of a provisioner, stop active scanning */
	if (node->provisioner)
		manager_scan_cancel(node);

	free_node_dbus_resources(node);

	mesh_net_free(node->net);
	l_free(node->storage_dir);
	l_free(node);
}

/*
 * This function is called to free resources and remove the
 * configuration files for the specified node.
 */
void node_remove(struct mesh_node *node)
{
	if (!node)
		return;

	l_queue_remove(nodes, node);

	if (node->cfg)
		mesh_config_destroy(node->cfg);

	free_node_resources(node);
}

static bool add_models_from_storage(struct mesh_node *node,
					struct node_element *ele,
					struct mesh_config_element *db_ele)
{
	const struct l_queue_entry *entry;

	if (!ele->models)
		ele->models = l_queue_new();

	entry = l_queue_get_entries(db_ele->models);

	for (; entry; entry = entry->next) {
		struct mesh_model *mod;
		struct mesh_config_model *db_mod;
		uint32_t id;

		db_mod = entry->data;

		id = db_mod->vendor ? db_mod->id : db_mod->id | VENDOR_ID_MASK;

		if (l_queue_find(ele->models, match_model_id,
							L_UINT_TO_PTR(id)))
			return false;

		mod = mesh_model_setup(node, ele->idx, db_mod);
		if (!mod)
			return false;

		l_queue_insert(ele->models, mod, compare_model_id, NULL);
	}

	return true;
}

static bool add_element_from_storage(struct mesh_node *node,
					struct mesh_config_element *db_ele)
{
	struct node_element *ele;

	ele = l_new(struct node_element, 1);
	if (!ele)
		return false;

	ele->idx = db_ele->index;
	ele->location = db_ele->location;

	if (!db_ele->models || !add_models_from_storage(node, ele, db_ele))
		return false;

	l_queue_push_tail(node->elements, ele);
	return true;
}

static bool add_elements_from_storage(struct mesh_node *node,
					struct mesh_config_node *db_node)
{
	const struct l_queue_entry *entry;

	entry = l_queue_get_entries(db_node->elements);
	for (; entry; entry = entry->next)
		if (!add_element_from_storage(node, entry->data))
			return false;

	/* Add configuration server model on the primary element */
	add_internal_model(node, CONFIG_SRV_MODEL, PRIMARY_ELE_IDX);

	return true;
}

static void set_net_key(void *a, void *b)
{
	struct mesh_config_netkey *netkey = a;
	struct mesh_node *node = b;

	mesh_net_set_key(node->net, netkey->idx, netkey->key, netkey->new_key,
								netkey->phase);
}

static void set_appkey(void *a, void *b)
{
	struct mesh_config_appkey *appkey = a;
	struct mesh_node *node = b;

	appkey_key_init(node->net, appkey->net_idx, appkey->app_idx,
						appkey->key, appkey->new_key);
}

static bool init_storage_dir(struct mesh_node *node)
{
	char uuid[33];
	char dir_name[PATH_MAX];

	if (node->storage_dir)
		return true;

	if (!hex2str(node->uuid, 16, uuid, sizeof(uuid)))
		return false;

	snprintf(dir_name, PATH_MAX, "%s/%s", mesh_get_storage_dir(), uuid);

	if (strlen(dir_name) >= PATH_MAX)
		return false;

	create_dir(dir_name);

	node->storage_dir = l_strdup(dir_name);

	return true;
}

static void update_net_settings(struct mesh_node *node)
{
	uint8_t mode;

	mode = node->proxy;
	if (mode == MESH_MODE_ENABLED || mode == MESH_MODE_DISABLED)
		mesh_net_set_proxy_mode(node->net, mode == MESH_MODE_ENABLED);

	mode = node->friend;
	if (mode == MESH_MODE_ENABLED || mode == MESH_MODE_DISABLED)
		mesh_net_set_friend_mode(node->net, mode == MESH_MODE_ENABLED);

	mode = node->relay.mode;
	if (mode == MESH_MODE_ENABLED || mode == MESH_MODE_DISABLED)
		mesh_net_set_relay_mode(node->net, mode == MESH_MODE_ENABLED,
					node->relay.cnt, node->relay.interval);

	mode = node->beacon;
	if (mode == MESH_MODE_ENABLED || mode == MESH_MODE_DISABLED)
		mesh_net_set_beacon_mode(node->net, mode == MESH_MODE_ENABLED);
}

static bool init_from_storage(struct mesh_config_node *db_node,
			const uint8_t uuid[16], struct mesh_config *cfg,
			void *user_data)
{
	unsigned int num_ele;

	struct mesh_node *node = node_new(uuid);

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, node);

	node->comp.cid = db_node->cid;
	node->comp.pid = db_node->pid;
	node->comp.vid = db_node->vid;
	node->comp.crpl = db_node->crpl;
	node->lpn = db_node->modes.lpn;

	node->proxy = db_node->modes.proxy;
	node->friend = db_node->modes.friend;
	node->relay.mode = db_node->modes.relay.state;
	node->relay.cnt = db_node->modes.relay.cnt;
	node->relay.interval = db_node->modes.relay.interval;
	node->beacon = db_node->modes.beacon;

	l_debug("relay %2.2x, proxy %2.2x, lpn %2.2x, friend %2.2x",
			node->relay.mode, node->proxy, node->lpn, node->friend);
	node->ttl = db_node->ttl;
	node->seq_number = db_node->seq_number;

	memcpy(node->dev_key, db_node->dev_key, 16);
	memcpy(node->token, db_node->token, 8);

	num_ele = l_queue_length(db_node->elements);
	if (num_ele > MAX_ELE_COUNT)
		goto fail;

	node->num_ele = num_ele;

	if (num_ele != 0 && !add_elements_from_storage(node, db_node))
		goto fail;

	node->primary = db_node->unicast;

	if (!db_node->netkeys)
		goto fail;

	if (!IS_UNASSIGNED(node->primary) &&
		!mesh_net_register_unicast(node->net, node->primary, num_ele))
		goto fail;

	mesh_net_set_iv_index(node->net, db_node->iv_index, db_node->iv_update);

	if (db_node->net_transmit)
		mesh_net_transmit_params_set(node->net,
					db_node->net_transmit->count,
					db_node->net_transmit->interval);

	l_queue_foreach(db_node->netkeys, set_net_key, node);

	if (db_node->appkeys)
		l_queue_foreach(db_node->appkeys, set_appkey, node);

	mesh_net_set_seq_num(node->net, node->seq_number);
	mesh_net_set_default_ttl(node->net, node->ttl);

	update_net_settings(node);

	/* Initialize configuration server model */
	cfgmod_server_init(node, PRIMARY_ELE_IDX);

	node->cfg = cfg;

	/* Initialize directory for storing keyring info */
	init_storage_dir(node);

	return true;
fail:
	node_remove(node);
	return false;
}

static void cleanup_node(void *data)
{
	struct mesh_node *node = data;
	struct mesh_net *net = node->net;

	/* Preserve the last sequence number */
	if (node->cfg)
		mesh_config_write_seq_number(node->cfg,
						mesh_net_get_seq_num(net),
						false);

	free_node_resources(node);
}

/*
 * This function is called to free resources and write the current
 * sequence numbers to the configuration file for each known node.
 */
void node_cleanup_all(void)
{
	l_queue_destroy(nodes, cleanup_node);
	l_dbus_unregister_interface(dbus_get_bus(), MESH_NODE_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), MESH_MANAGEMENT_INTERFACE);
}

bool node_is_provisioner(struct mesh_node *node)
{
	return node->provisioner;
}

bool node_is_provisioned(struct mesh_node *node)
{
	return (!IS_UNASSIGNED(node->primary));
}

void node_app_key_delete(struct mesh_node *node, uint16_t net_idx,
							uint16_t app_idx)
{
	const struct l_queue_entry *entry;

	entry = l_queue_get_entries(node->elements);
	for (; entry; entry = entry->next) {
		struct node_element *ele = entry->data;

		mesh_model_app_key_delete(node, ele->models, app_idx);
	}
}

uint16_t node_get_primary(struct mesh_node *node)
{
	if (!node)
		return UNASSIGNED_ADDRESS;
	else
		return node->primary;
}

const uint8_t *node_get_device_key(struct mesh_node *node)
{
	if (!node)
		return NULL;
	else
		return node->dev_key;
}

void node_set_token(struct mesh_node *node, uint8_t token[8])
{
	memcpy(node->token, token, 8);
}

const uint8_t *node_get_token(struct mesh_node *node)
{
	if (!node)
		return NULL;
	else
		return node->token;
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
		return TTL_MASK;
	return node->ttl;
}

bool node_default_ttl_set(struct mesh_node *node, uint8_t ttl)
{
	bool res;

	if (!node)
		return false;

	res = mesh_config_write_ttl(node->cfg, ttl);

	if (res) {
		node->ttl = ttl;
		mesh_net_set_default_ttl(node->net, ttl);
	}

	return res;
}

bool node_set_sequence_number(struct mesh_node *node, uint32_t seq)
{
	if (!node)
		return false;

	node->seq_number = seq;

	return mesh_config_write_seq_number(node->cfg, node->seq_number, true);
}

uint32_t node_get_sequence_number(struct mesh_node *node)
{
	if (!node)
		return 0xffffffff;

	return node->seq_number;
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

	return node->comp.crpl;
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

	res = mesh_config_write_relay_mode(node->cfg, enable, cnt, interval);

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
	res = mesh_config_write_mode(node->cfg, "proxy", proxy);

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
	res = mesh_config_write_mode(node->cfg, "beacon", beacon);

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
	res = mesh_config_write_mode(node->cfg, "friend", friend);

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
	uint16_t num_ele = 0;
	const struct l_queue_entry *ele_entry;

	if (!node || sz < MIN_COMP_SIZE)
		return 0;

	n = 0;

	l_put_le16(node->comp.cid, buf + n);
	n += 2;
	l_put_le16(node->comp.pid, buf + n);
	n += 2;
	l_put_le16(node->comp.vid, buf + n);
	n += 2;
	l_put_le16(node->comp.crpl, buf + n);
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

		if (ele->idx != num_ele)
			return 0;

		num_ele++;

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

	if (!num_ele)
		return 0;

	return n;
}

static void attach_io(void *a, void *b)
{
	struct mesh_node *node = a;
	struct mesh_io *io = b;

	if (node->net)
		mesh_net_attach(node->net, io);
}

/* Register callback for the node's io */
void node_attach_io(struct mesh_node *node, struct mesh_io *io)
{
	attach_io(node, io);
}

/* Register callbacks for all nodes io */
void node_attach_io_all(struct mesh_io *io)
{
	l_queue_foreach(nodes, attach_io, io);
}

/* Register node object with D-Bus */
static bool register_node_object(struct mesh_node *node)
{
	char uuid[33];

	if (!hex2str(node->uuid, sizeof(node->uuid), uuid, sizeof(uuid)))
		return false;

	node->obj_path = l_strdup_printf(BLUEZ_MESH_PATH MESH_NODE_PATH_PREFIX
								"%s", uuid);

	if (!l_dbus_object_add_interface(dbus_get_bus(), node->obj_path,
						MESH_NODE_INTERFACE, node))
		return false;

	if (!l_dbus_object_add_interface(dbus_get_bus(), node->obj_path,
					MESH_MANAGEMENT_INTERFACE, node))
		return false;

	if (!l_dbus_object_add_interface(dbus_get_bus(), node->obj_path,
					L_DBUS_INTERFACE_PROPERTIES, NULL))
		return false;

	return true;
}

static void app_disc_cb(struct l_dbus *bus, void *user_data)
{
	struct mesh_node *node = user_data;

	l_info("App %s disconnected (%u)", node->owner, node->disc_watch);

	node->disc_watch = 0;

	/* In case of a provisioner, stop active scanning */
	if (node->provisioner)
		manager_scan_cancel(node);

	free_node_dbus_resources(node);
}

static bool get_sig_models_from_properties(struct node_element *ele,
					struct l_dbus_message_iter *property)
{
	struct l_dbus_message_iter ids;
	uint16_t mod_id;

	if (!ele->models)
		ele->models = l_queue_new();

	if (!l_dbus_message_iter_get_variant(property, "aq", &ids))
		return false;

	/* Bluetooth SIG defined models */
	while (l_dbus_message_iter_next_entry(&ids, &mod_id)) {
		struct mesh_model *mod;
		uint32_t id = mod_id | VENDOR_ID_MASK;

		/* Allow Config Server Model only on the primary element */
		if (ele->idx != PRIMARY_ELE_IDX && id == CONFIG_SRV_MODEL)
			return false;

		/* Disallow duplicates */
		if (l_queue_find(ele->models, match_model_id,
						L_UINT_TO_PTR(id)))
			return false;

		mod = mesh_model_new(ele->idx, id);

		l_queue_insert(ele->models, mod, compare_model_id, NULL);
	}

	return true;
}

static bool get_vendor_models_from_properties(struct node_element *ele,
					struct l_dbus_message_iter *property)
{
	struct l_dbus_message_iter ids;
	uint16_t mod_id, vendor_id;

	if (!ele->models)
		ele->models = l_queue_new();

	if (!l_dbus_message_iter_get_variant(property, "a(qq)", &ids))
		return false;

	/* Vendor defined models */
	while (l_dbus_message_iter_next_entry(&ids, &vendor_id, &mod_id)) {
		struct mesh_model *mod;
		uint32_t id = mod_id | (vendor_id << 16);

		/* Disallow duplicates */
		if (l_queue_find(ele->models, match_model_id,
							L_UINT_TO_PTR(id)))
			return false;

		mod = mesh_model_new(ele->idx, id);

		l_queue_insert(ele->models, mod, compare_model_id, NULL);
	}

	return true;
}

static bool get_element_properties(struct mesh_node *node, const char *path,
					struct l_dbus_message_iter *properties)
{
	struct node_element *ele = l_new(struct node_element, 1);
	const char *key;
	struct l_dbus_message_iter var;
	bool idx = false;
	bool mods = false;
	bool vendor_mods = false;

	l_debug("path %s", path);

	ele->location = DEFAULT_LOCATION;

	while (l_dbus_message_iter_next_entry(properties, &key, &var)) {
		if (!strcmp(key, "Index")) {

			if (idx || !l_dbus_message_iter_get_variant(&var, "y",
								&ele->idx))
				goto fail;

			idx = true;

		} else if (!strcmp(key, "Models")) {

			if (mods || !get_sig_models_from_properties(ele, &var))
				goto fail;

			mods = true;
		} else if (!strcmp(key, "VendorModels")) {

			if (vendor_mods ||
				!get_vendor_models_from_properties(ele, &var))
				goto fail;

			vendor_mods = true;

		} else if (!strcmp(key, "Location")) {
			if (!l_dbus_message_iter_get_variant(&var, "q",
							&ele->location))
				goto fail;
		}
	}

	/* Check for the presence of the required properties */
	if (!idx || !mods || !vendor_mods)
		goto fail;

	if (l_queue_find(node->elements, match_element_idx,
						L_UINT_TO_PTR(ele->idx)))
		goto fail;

	l_queue_insert(node->elements, ele, compare_element_idx, NULL);

	ele->path = l_strdup(path);

	/*
	 * Add configuration server model on the primary element.
	 * We allow the application not to specify the presense of
	 * the Configuration Server model, since it's implemented by the
	 * daemon. If the model is present in the application properties,
	 * the operation below will be a "no-op".
	 */
	if (ele->idx == PRIMARY_ELE_IDX)
		add_internal_model(node, CONFIG_SRV_MODEL, PRIMARY_ELE_IDX);

	return true;
fail:
	l_free(ele);

	return false;
}

static void convert_node_to_storage(struct mesh_node *node,
					struct mesh_config_node *db_node)
{
	const struct l_queue_entry *entry;

	db_node->cid = node->comp.cid;
	db_node->pid = node->comp.pid;
	db_node->vid = node->comp.vid;
	db_node->crpl = node->comp.crpl;
	db_node->modes.lpn = node->lpn;
	db_node->modes.proxy = node->proxy;

	db_node->modes.friend = node->friend;
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
		struct mesh_config_element *db_ele;
		const struct l_queue_entry *mod_entry;

		db_ele = l_new(struct mesh_config_element, 1);

		db_ele->index = ele->idx;
		db_ele->location = ele->location;
		db_ele->models = l_queue_new();

		mod_entry = l_queue_get_entries(ele->models);

		for (; mod_entry; mod_entry = mod_entry->next) {
			struct mesh_model *mod = mod_entry->data;
			struct mesh_config_model *db_mod;
			uint32_t mod_id = mesh_model_get_model_id(mod);

			db_mod = l_new(struct mesh_config_model, 1);
			db_mod->id = mod_id;
			db_mod->vendor = ((mod_id & VENDOR_ID_MASK)
							!= VENDOR_ID_MASK);

			l_queue_push_tail(db_ele->models, db_mod);
		}
		l_queue_push_tail(db_node->elements, db_ele);
	}

}

static bool create_node_config(struct mesh_node *node, const uint8_t uuid[16])
{
	struct mesh_config_node db_node;
	const struct l_queue_entry *entry;
	const char *storage_dir;

	convert_node_to_storage(node, &db_node);
	storage_dir = mesh_get_storage_dir();
	node->cfg = mesh_config_create(storage_dir, uuid, &db_node);

	if (node->cfg)
		init_storage_dir(node);

	/* Free temporarily allocated resources */
	entry = l_queue_get_entries(db_node.elements);
	for (; entry; entry = entry->next) {
		struct mesh_config_element *db_ele = entry->data;

		l_queue_destroy(db_ele->models, l_free);
	}

	l_queue_destroy(db_node.elements, l_free);

	return node->cfg != NULL;
}

static bool get_app_properties(struct mesh_node *node, const char *path,
					struct l_dbus_message_iter *properties)
{
	const char *key;
	struct l_dbus_message_iter variant;
	bool cid = false;
	bool pid = false;
	bool vid = false;

	l_debug("path %s", path);

	node->comp.crpl = mesh_get_crpl();

	while (l_dbus_message_iter_next_entry(properties, &key, &variant)) {
		if (!cid && !strcmp(key, "CompanyID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
							&node->comp.cid))
				return false;
			cid = true;
			continue;
		}

		if (!pid && !strcmp(key, "ProductID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
							&node->comp.pid))
				return false;
			pid = true;
			continue;
		}

		if (!vid && !strcmp(key, "VersionID")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
							&node->comp.vid))
				return false;
			vid = true;
			continue;
		}

		if (!strcmp(key, "CRPL")) {
			if (!l_dbus_message_iter_get_variant(&variant, "q",
							&node->comp.crpl))
				return false;
			continue;
		}
	}

	if (!cid || !pid || !vid)
		return false;

	return true;
}

static bool add_local_node(struct mesh_node *node, uint16_t unicast, bool kr,
				bool ivu, uint32_t iv_idx, uint8_t dev_key[16],
				uint16_t net_key_idx, uint8_t net_key[16])
{
	node->net = mesh_net_new(node);

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, node);

	if (!mesh_config_write_iv_index(node->cfg, iv_idx, ivu))
		return false;

	mesh_net_set_iv_index(node->net, iv_idx, ivu);

	if (!mesh_config_write_unicast(node->cfg, unicast))
		return false;

	l_getrandom(node->token, sizeof(node->token));
	if (!mesh_config_write_token(node->cfg, node->token))
		return false;

	memcpy(node->dev_key, dev_key, 16);
	if (!mesh_config_write_device_key(node->cfg, dev_key))
		return false;

	node->primary = unicast;
	mesh_net_register_unicast(node->net, unicast, node->num_ele);

	if (mesh_net_add_key(node->net, net_key_idx, net_key) !=
							MESH_STATUS_SUCCESS)
		return false;

	if (kr) {
		/* Duplicate net key, if the key refresh is on */
		if (mesh_net_update_key(node->net, net_key_idx, net_key) !=
							MESH_STATUS_SUCCESS)
			return false;

		if (!mesh_config_net_key_set_phase(node->cfg, net_key_idx,
							KEY_REFRESH_PHASE_TWO))
			return false;
	}

	update_net_settings(node);

	mesh_config_save(node->cfg, true, NULL, NULL);

	/* Initialize configuration server model */
	cfgmod_server_init(node, PRIMARY_ELE_IDX);

	return true;
}

static bool check_req_node(struct managed_obj_request *req)
{
	uint8_t node_comp[MAX_MSG_LEN - 2];
	uint8_t attach_comp[MAX_MSG_LEN - 2];

	uint16_t node_len = node_generate_comp(req->node, node_comp,
							sizeof(node_comp));

	if (!node_len)
		return false;

	if (req->type == REQUEST_TYPE_ATTACH) {
		uint16_t attach_len = node_generate_comp(req->attach,
					attach_comp, sizeof(attach_comp));

		/* Ignore feature bits in Composition Compare */
		node_comp[8] = 0;
		attach_comp[8] = 0;

		if (node_len != attach_len ||
				memcmp(node_comp, attach_comp, node_len)) {
			l_debug("Failed to verify app's composition data");
			return false;
		}
	}

	return true;
}

static bool attach_req_node(struct mesh_node *attach, struct mesh_node *node)
{
	const struct l_queue_entry *attach_entry;
	const struct l_queue_entry *node_entry;

	attach->obj_path = node->obj_path;
	node->obj_path = NULL;

	if (!register_node_object(attach)) {
		free_node_dbus_resources(attach);
		return false;
	}

	attach_entry = l_queue_get_entries(attach->elements);
	node_entry = l_queue_get_entries(node->elements);

	/*
	 * Update existing node with paths collected in temporary node,
	 * then remove the temporary.
	 */
	while (attach_entry && node_entry) {
		struct node_element *attach_ele = attach_entry->data;
		struct node_element *node_ele = node_entry->data;

		attach_ele->path = node_ele->path;
		node_ele->path = NULL;

		attach_entry = attach_entry->next;
		node_entry = node_entry->next;
	}

	mesh_agent_remove(attach->agent);
	attach->agent = node->agent;
	node->agent = NULL;

	attach->provisioner = node->provisioner;

	attach->app_path = node->app_path;
	node->app_path = NULL;

	attach->owner = node->owner;
	node->owner = NULL;

	node_remove(node);

	return true;
}

static void get_managed_objects_cb(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_iter objects, interfaces;
	struct managed_obj_request *req = user_data;
	const char *path;
	struct mesh_node *node = req->node;
	struct node_import *import;
	void *agent = NULL;
	bool have_app = false;
	unsigned int num_ele;
	struct keyring_net_key net_key;
	uint8_t dev_key[16];

	if (l_dbus_message_is_error(msg)) {
		l_error("Failed to get app's dbus objects");
		goto fail;
	}

	if (!l_dbus_message_get_arguments(msg, "a{oa{sa{sv}}}", &objects)) {
		l_error("Failed to parse app's dbus objects");
		goto fail;
	}

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
			} else if (!strcmp(MESH_APPLICATION_INTERFACE,
								interface)) {
				if (have_app)
					goto fail;

				req->node->app_path = l_strdup(path);

				res = get_app_properties(node, path,
								&properties);
				if (!res)
					goto fail;

				have_app = true;

			} else if (!strcmp(MESH_PROVISION_AGENT_INTERFACE,
								interface)) {
				const char *sender;

				sender = l_dbus_message_get_sender(msg);
				agent = mesh_agent_create(path, sender,
								&properties);
				if (!agent)
					goto fail;

				node->agent = agent;

			} else if (!strcmp(MESH_PROVISIONER_INTERFACE,
								interface)) {
				node->provisioner = true;
			}
		}
	}

	if (!have_app) {
		l_error("Interface %s not found", MESH_APPLICATION_INTERFACE);
		goto fail;
	}

	if (l_queue_isempty(node->elements)) {
		l_error("Interface %s not found", MESH_ELEMENT_INTERFACE);
		goto fail;
	}

	if (!l_queue_find(node->elements, match_element_idx,
				L_UINT_TO_PTR(PRIMARY_ELE_IDX))) {

		l_debug("Primary element not detected");
		goto fail;
	}

	num_ele = l_queue_length(node->elements);

	if (num_ele > MAX_ELE_COUNT)
		goto fail;

	node->num_ele = num_ele;

	if (!check_req_node(req))
		goto fail;

	switch (req->type) {
	case REQUEST_TYPE_ATTACH:
		if (!attach_req_node(req->attach, node))
			goto fail;

		req->attach->disc_watch = l_dbus_add_disconnect_watch(
					dbus_get_bus(), req->attach->owner,
					app_disc_cb, req->attach, NULL);

		req->ready_cb(req->pending_msg, MESH_ERROR_NONE, req->attach);
		return;

	case REQUEST_TYPE_JOIN:
		if (!node->agent) {
			l_error("Interface %s not found",
						MESH_PROVISION_AGENT_INTERFACE);
			goto fail;
		}

		if (!create_node_config(node, node->uuid))
			goto fail;

		req->join_ready_cb(node, node->agent);

		return;

	case REQUEST_TYPE_IMPORT:
		if (!create_node_config(node, node->uuid))
			goto fail;

		import = req->import;
		if (!add_local_node(node, import->unicast, import->flags.kr,
					import->flags.ivu,
					import->iv_index, import->dev_key,
					import->net_idx, import->net_key))
			goto fail;

		req->ready_cb(req->pending_msg, MESH_ERROR_NONE, node);
		l_free(import);

		return;

	case REQUEST_TYPE_CREATE:
		if (!create_node_config(node, node->uuid))
			goto fail;

		/* Generate device and primary network keys */
		l_getrandom(dev_key, sizeof(dev_key));
		l_getrandom(net_key.old_key, sizeof(net_key.old_key));
		net_key.net_idx = PRIMARY_NET_IDX;
		net_key.phase = KEY_REFRESH_PHASE_NONE;

		if (!add_local_node(node, DEFAULT_NEW_UNICAST, false, false,
						DEFAULT_IV_INDEX, dev_key,
						PRIMARY_NET_IDX,
						net_key.old_key))
			goto fail;

		if (!keyring_put_remote_dev_key(node, DEFAULT_NEW_UNICAST,
						node->num_ele, dev_key))
			goto fail;

		if (!keyring_put_net_key(node, PRIMARY_NET_IDX, &net_key))
			goto fail;

		req->ready_cb(req->pending_msg, MESH_ERROR_NONE, node);
		return;

	default:
		goto fail;
	}

fail:
	if (agent)
		mesh_agent_remove(agent);

	/* Handle failed requests */
	if (node)
		node_remove(node);

	if (req->type == REQUEST_TYPE_JOIN)
		req->join_ready_cb(NULL, NULL);
	else
		req->ready_cb(req->pending_msg, MESH_ERROR_FAILED, NULL);

	if (req->type == REQUEST_TYPE_IMPORT)
		l_free(req->import);
}

/* Establish relationship between application and mesh node */
int node_attach(const char *app_root, const char *sender, uint64_t token,
					node_ready_func_t cb, void *user_data)
{
	struct managed_obj_request *req;
	struct mesh_node *node;

	node = l_queue_find(nodes, match_token, (void *) &token);
	if (!node)
		return MESH_ERROR_NOT_FOUND;

	/* Check if the node is already in use */
	if (node->owner) {
		l_warn("The node is already in use");
		return MESH_ERROR_ALREADY_EXISTS;
	}

	req = l_new(struct managed_obj_request, 1);

	/*
	 * Create a temporary node to collect composition data from attaching
	 * application. Existing node is passed in req->attach.
	 */
	req->node = node_new(node->uuid);
	req->node->owner = l_strdup(sender);
	req->ready_cb = cb;
	req->pending_msg = user_data;
	req->attach = node;
	req->type = REQUEST_TYPE_ATTACH;

	l_dbus_method_call(dbus_get_bus(), sender, app_root,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_cb,
					req, l_free);
	return MESH_ERROR_NONE;

}


/* Create a temporary pre-provisioned node */
void node_join(const char *app_root, const char *sender, const uint8_t *uuid,
						node_join_ready_func_t cb)
{
	struct managed_obj_request *req;

	l_debug("");

	req = l_new(struct managed_obj_request, 1);
	req->node = node_new(uuid);
	req->join_ready_cb = cb;
	req->type = REQUEST_TYPE_JOIN;

	l_dbus_method_call(dbus_get_bus(), sender, app_root,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_cb,
					req, l_free);
}

bool node_import(const char *app_root, const char *sender, const uint8_t *uuid,
			const uint8_t dev_key[16], const uint8_t net_key[16],
			uint16_t net_idx, bool kr, bool ivu,
			uint32_t iv_index, uint16_t unicast,
			node_ready_func_t cb, void *user_data)
{
	struct managed_obj_request *req;

	l_debug("");

	req = l_new(struct managed_obj_request, 1);

	req->node = node_new(uuid);
	req->ready_cb = cb;
	req->pending_msg = user_data;

	req->import = l_new(struct node_import, 1);
	memcpy(req->import->dev_key, dev_key, 16);
	memcpy(req->import->net_key, net_key, 16);
	req->import->net_idx = net_idx;
	req->import->flags.kr = kr;
	req->import->flags.ivu = ivu;
	req->import->iv_index = iv_index;
	req->import->unicast = unicast;

	req->type = REQUEST_TYPE_IMPORT;

	l_dbus_method_call(dbus_get_bus(), sender, app_root,
						L_DBUS_INTERFACE_OBJECT_MANAGER,
						"GetManagedObjects", NULL,
						get_managed_objects_cb,
						req, l_free);
	return true;
}

void node_create(const char *app_root, const char *sender, const uint8_t *uuid,
					node_ready_func_t cb, void *user_data)
{
	struct managed_obj_request *req;

	l_debug("");

	req = l_new(struct managed_obj_request, 1);
	req->node = node_new(uuid);
	req->ready_cb = cb;
	req->pending_msg = user_data;
	req->type = REQUEST_TYPE_CREATE;

	l_dbus_method_call(dbus_get_bus(), sender, app_root,
					L_DBUS_INTERFACE_OBJECT_MANAGER,
					"GetManagedObjects", NULL,
					get_managed_objects_cb,
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

void node_build_attach_reply(struct mesh_node *node,
						struct l_dbus_message *reply)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(reply);

	/* Node object path */
	l_dbus_message_builder_append_basic(builder, 'o', node->obj_path);

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
	uint8_t *data;
	uint32_t len;

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

	if (!l_dbus_message_iter_get_fixed_array(&iter_data, &data, &len) ||
					!len || len > MAX_MSG_LEN)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Incorrect data");

	if (app_idx & ~APP_IDX_MASK)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
						"Invalid key_index");

	if (!mesh_model_send(node, src, dst, app_idx, 0, DEFAULT_TTL,
								data, len))
		return dbus_error(msg, MESH_ERROR_FAILED, NULL);

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *dev_key_send_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct l_dbus_message_iter iter_data;
	struct node_element *ele;
	uint16_t dst, app_idx, net_idx, src;
	bool remote;
	uint8_t *data;
	uint32_t len;

	l_debug("DevKeySend");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqbqay", &ele_path, &dst,
						&remote, &net_idx, &iter_data))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* Loopbacks to local servers must use *remote* addressing */
	if (!remote && mesh_net_is_local_address(node->net, dst, 1))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	if (!l_dbus_message_iter_get_fixed_array(&iter_data, &data, &len) ||
						!len || len > MAX_MSG_LEN)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Incorrect data");

	app_idx = remote ? APP_IDX_DEV_REMOTE : APP_IDX_DEV_LOCAL;
	if (!mesh_model_send(node, src, dst, app_idx, net_idx, DEFAULT_TTL,
								data, len))
		return dbus_error(msg, MESH_ERROR_NOT_FOUND, NULL);

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *add_netkey_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct node_element *ele;
	uint16_t dst, sub_idx, net_idx, src;
	bool update;
	struct keyring_net_key key;
	uint8_t data[20];

	l_debug("AddNetKey");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqqqb", &ele_path, &dst,
						&sub_idx, &net_idx, &update))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	if (!keyring_get_net_key(node, sub_idx, &key))
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"NetKey not found");

	if (!update) {
		l_put_be16(OP_NETKEY_ADD, data);

		if (key.phase != KEY_REFRESH_PHASE_TWO)
			memcpy(data + 4, key.old_key, 16);
		else
			memcpy(data + 4, key.new_key, 16);
	} else {
		if (key.phase != KEY_REFRESH_PHASE_ONE)
			return dbus_error(msg, MESH_ERROR_FAILED,
							"Cannot update");
		l_put_be16(OP_NETKEY_UPDATE, data);
		memcpy(data + 4, key.new_key, 16);
	}

	l_put_le16(sub_idx, &data[2]);

	if (!mesh_model_send(node, src, dst, APP_IDX_DEV_REMOTE, net_idx,
							DEFAULT_TTL, data, 20))
		return dbus_error(msg, MESH_ERROR_NOT_FOUND, NULL);

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *add_appkey_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct mesh_node *node = user_data;
	const char *sender, *ele_path;
	struct node_element *ele;
	uint16_t dst, app_idx, net_idx, src;
	bool update;
	struct keyring_net_key net_key;
	struct keyring_app_key app_key;
	uint8_t data[20];

	l_debug("AddAppKey");

	sender = l_dbus_message_get_sender(msg);

	if (strcmp(sender, node->owner))
		return dbus_error(msg, MESH_ERROR_NOT_AUTHORIZED, NULL);

	if (!l_dbus_message_get_arguments(msg, "oqqqb", &ele_path, &dst,
						&app_idx, &net_idx, &update))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	ele = l_queue_find(node->elements, match_element_path, ele_path);
	if (!ele)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"Element not found");

	src = node_get_primary(node) + ele->idx;

	if (!keyring_get_app_key(node, app_idx, &app_key))
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
							"AppKey not found");

	if (!keyring_get_net_key(node, app_key.net_idx, &net_key)) {
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
						"Bound NetKey not found");
	}

	if (!update) {
		data[0] = OP_APPKEY_ADD;
		if (net_key.phase != KEY_REFRESH_PHASE_TWO)
			memcpy(data + 4, app_key.old_key, 16);
		else
			memcpy(data + 4, app_key.new_key, 16);
	} else {
		if (net_key.phase != KEY_REFRESH_PHASE_ONE)
			return dbus_error(msg, MESH_ERROR_FAILED,
							"Cannot update");
		data[0] = OP_APPKEY_UPDATE;
		memcpy(data + 4, app_key.new_key, 16);
	}

	/* Pack bound NetKey and AppKey into 3 octets */
	data[1] = app_key.net_idx;
	data[2] = ((app_key.net_idx >> 8) & 0xf) | ((app_idx << 4) & 0xf0);
	data[3] = app_idx >> 4;

	if (!mesh_model_send(node, src, dst, APP_IDX_DEV_REMOTE, net_idx,
							DEFAULT_TTL, data, 20))
		return dbus_error(msg, MESH_ERROR_NOT_FOUND, NULL);

	return l_dbus_message_new_method_return(msg);
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
	uint8_t *data;
	uint32_t len;
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

	if (!l_dbus_message_iter_get_fixed_array(&iter_data, &data, &len) ||
					!len || len > MAX_MSG_LEN)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Incorrect data");

	result = mesh_model_publish(node, VENDOR_ID_MASK | mod_id, src,
				mesh_net_get_default_ttl(node->net), data, len);

	if (result != MESH_ERROR_NONE)
		return dbus_error(msg, result, NULL);

	return l_dbus_message_new_method_return(msg);
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
	uint8_t *data = NULL;
	uint32_t len;
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

	if (!l_dbus_message_iter_get_fixed_array(&iter_data, &data, &len) ||
					!len || len > MAX_MSG_LEN)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Incorrect data");

	vendor_mod_id = (vendor << 16) | model_id;
	result = mesh_model_publish(node, vendor_mod_id, src,
				mesh_net_get_default_ttl(node->net), data, len);

	if (result != MESH_ERROR_NONE)
		return dbus_error(msg, result, NULL);

	return  l_dbus_message_new_method_return(msg);
}

static bool features_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct mesh_node *node = user_data;
	uint8_t friend = node_friend_mode_get(node);
	uint8_t lpn = node_lpn_mode_get(node);
	uint8_t proxy = node_proxy_mode_get(node);
	uint8_t count;
	uint16_t interval;
	uint8_t relay = node_relay_mode_get(node, &count, &interval);

	l_dbus_message_builder_enter_array(builder, "{sv}");

	if (friend != MESH_MODE_UNSUPPORTED)
		dbus_append_dict_entry_basic(builder, "Friend", "b", &friend);

	if (lpn != MESH_MODE_UNSUPPORTED)
		dbus_append_dict_entry_basic(builder, "LowPower", "b", &lpn);

	if (proxy != MESH_MODE_UNSUPPORTED)
		dbus_append_dict_entry_basic(builder, "Proxy", "b", &proxy);

	if (relay != MESH_MODE_UNSUPPORTED)
		dbus_append_dict_entry_basic(builder, "Relay", "b", &relay);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool beacon_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct mesh_node *node = user_data;
	bool beacon_mode = node_beacon_mode_get(node) == MESH_MODE_ENABLED;

	l_dbus_message_builder_append_basic(builder, 'b', &beacon_mode);

	return true;
}

static bool beaconflags_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct mesh_node *node = user_data;
	struct mesh_net *net = node_get_net(node);
	uint8_t flags;
	uint32_t iv_index;

	mesh_net_get_snb_state(net, &flags, &iv_index);

	l_dbus_message_builder_append_basic(builder, 'y', &flags);

	return true;
}

static bool ivindex_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct mesh_node *node = user_data;
	struct mesh_net *net = node_get_net(node);
	uint8_t flags;
	uint32_t iv_index;

	mesh_net_get_snb_state(net, &flags, &iv_index);

	l_dbus_message_builder_append_basic(builder, 'u', &iv_index);

	return true;
}

static bool seq_num_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct mesh_node *node = user_data;
	struct mesh_net *net = node_get_net(node);
	uint32_t seq_nr = mesh_net_get_seq_num(net);

	l_dbus_message_builder_append_basic(builder, 'u', &seq_nr);

	return true;
}

static bool lastheard_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct mesh_node *node = user_data;
	struct mesh_net *net = node_get_net(node);
	struct timeval now;
	uint32_t last_heard;

	gettimeofday(&now, NULL);

	last_heard = now.tv_sec - mesh_net_get_instant(net);

	l_dbus_message_builder_append_basic(builder, 'u', &last_heard);

	return true;

}

static bool addresses_getter(struct l_dbus *dbus, struct l_dbus_message *msg,
					struct l_dbus_message_builder *builder,
					void *user_data)
{
	struct mesh_node *node = user_data;
	const struct l_queue_entry *entry;

	l_dbus_message_builder_enter_array(builder, "q");

	entry = l_queue_get_entries(node->elements);
	for (; entry; entry = entry->next) {
		const struct node_element *ele = entry->data;
		uint16_t address = node->primary + ele->idx;

		l_dbus_message_builder_append_basic(builder, 'q', &address);
	}

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static void setup_node_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "Send", 0, send_call, "", "oqqay",
						"element_path", "destination",
						"key_index", "data");
	l_dbus_interface_method(iface, "DevKeySend", 0, dev_key_send_call,
						"", "oqbqay", "element_path",
						"destination", "remote",
						"net_index", "data");
	l_dbus_interface_method(iface, "AddNetKey", 0, add_netkey_call, "",
					"oqqqb", "element_path", "destination",
					"subnet_index", "net_index", "update");
	l_dbus_interface_method(iface, "AddAppKey", 0, add_appkey_call, "",
					"oqqqb", "element_path", "destination",
					"app_index", "net_index", "update");
	l_dbus_interface_method(iface, "Publish", 0, publish_call, "", "oqay",
					"element_path", "model_id", "data");
	l_dbus_interface_method(iface, "VendorPublish", 0, vendor_publish_call,
						"", "oqqay", "element_path",
						"vendor", "model_id", "data");

	l_dbus_interface_property(iface, "Features", 0, "a{sv}", features_getter,
									NULL);
	l_dbus_interface_property(iface, "Beacon", 0, "b", beacon_getter, NULL);
	l_dbus_interface_property(iface, "BeaconFlags", 0, "y",
						beaconflags_getter, NULL);
	l_dbus_interface_property(iface, "IvIndex", 0, "u", ivindex_getter,
									NULL);
	l_dbus_interface_property(iface, "SequenceNumber", 0, "u",
							seq_num_getter, NULL);
	l_dbus_interface_property(iface, "SecondsSinceLastHeard", 0, "u",
					lastheard_getter, NULL);
	l_dbus_interface_property(iface, "Addresses", 0, "aq", addresses_getter,
									NULL);
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

bool node_add_pending_local(struct mesh_node *node, void *prov_node_info)
{
	struct mesh_prov_node_info *info = prov_node_info;
	bool kr = !!(info->flags & PROV_FLAG_KR);
	bool ivu = !!(info->flags & PROV_FLAG_IVU);

	return add_local_node(node, info->unicast, kr, ivu, info->iv_index,
			info->device_key, info->net_index, info->net_key);
}

struct mesh_config *node_config_get(struct mesh_node *node)
{
	return node->cfg;
}

const char *node_get_storage_dir(struct mesh_node *node)
{
	return node->storage_dir;
}

const char *node_get_app_path(struct mesh_node *node)
{
	if (!node)
		return NULL;

	return node->app_path;
}

struct mesh_net *node_get_net(struct mesh_node *node)
{
	return node->net;
}

struct mesh_agent *node_get_agent(struct mesh_node *node)
{
	return node->agent;
}

bool node_load_from_storage(const char *storage_dir)
{
	return mesh_config_load_nodes(storage_dir, init_from_storage, NULL);
}
