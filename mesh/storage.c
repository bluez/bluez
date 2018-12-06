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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <json-c/json.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/node.h"

#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/model.h"
#include "mesh/storage.h"

/*
 * TODO: figure out naming convention to store alternative nodes
 * Mesh storage dir wil be in configure.ac
 */
#define DEVICE_COMPOSITION_FILE "../config/composition.json"
#define NODE_CONGIGURATION_FILE "../config/configuration.json"

static bool read_local_node_cb(struct mesh_db_node *db_node, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_node *node;
	uint32_t seq_number;
	uint16_t crpl;
	uint8_t ttl, mode, cnt, num_ele;
	uint16_t unicast, interval;
	uint8_t *uuid;

	if (!net)
		return false;

	node = node_create_from_storage(net, db_node, true);
	if (!node)
		return false;

	mesh_net_local_node_set(net, node, db_node->provisioner);
	seq_number = node_get_sequence_number(node);
	mesh_net_set_seq_num(net, seq_number);
	ttl = node_default_ttl_get(node);
	mesh_net_set_default_ttl(net, ttl);
	crpl = node_get_crpl(node);
	mesh_net_set_crpl(net, crpl);

	mode = node_proxy_mode_get(node);
	if (mode == MESH_MODE_ENABLED || mode == MESH_MODE_DISABLED)
		mesh_net_set_proxy_mode(net, mode == MESH_MODE_ENABLED);

	mode = node_friend_mode_get(node);
	if (mode == MESH_MODE_ENABLED || mode == MESH_MODE_DISABLED)
		mesh_net_set_friend_mode(net, mode == MESH_MODE_ENABLED);

	mode = node_relay_mode_get(node, &cnt, &interval);
	if (mode == MESH_MODE_ENABLED || mode == MESH_MODE_DISABLED)
		mesh_net_set_relay_mode(net, mode == MESH_MODE_ENABLED, cnt,
								interval);

	mode = node_beacon_mode_get(node);
	if (mode == MESH_MODE_ENABLED || mode == MESH_MODE_DISABLED)
		mesh_net_set_beacon_mode(net, mode == MESH_MODE_ENABLED);

	unicast = db_node->unicast;
	num_ele = node_get_num_elements(node);

	if (!IS_UNASSIGNED(unicast) &&
		!mesh_net_register_unicast(net, unicast, num_ele))
		return false;

	uuid = node_uuid_get(node);
	if (uuid)
		mesh_net_id_uuid_set(net, uuid);
	return true;
}

static bool read_net_keys_cb(uint16_t idx, uint8_t *key, uint8_t *new_key,
						int phase, void *user_data)
{
	struct mesh_net *net = user_data;

	if (!net)
		return false;

	if (mesh_net_add_key(net, false, idx, key) != MESH_STATUS_SUCCESS)
		return false;
	/* TODO: handle restoring key refresh phase and new keys */

	return true;
}

static bool read_app_keys_cb(uint16_t net_idx, uint16_t app_idx, uint8_t *key,
					uint8_t *new_key, void *user_data)
{
	struct mesh_net *net = user_data;

	if (!net)
		return false;

	return appkey_key_init(net, net_idx, app_idx, key, new_key);
}

static bool parse_local_node(struct mesh_net *net, json_object *jnode)
{
	bool bvalue;
	uint32_t iv_index;
	uint8_t key_buf[16];
	uint8_t cnt;
	uint16_t interval;

	if (mesh_db_read_iv_index(jnode, &iv_index, &bvalue))
		mesh_net_set_iv_index(net, iv_index, bvalue);

	if (mesh_db_read_net_transmit(jnode, &cnt, &interval))
		mesh_net_transmit_params_set(net, cnt, interval);

	/* Node composition/configuration info */
	if (!mesh_db_read_node(jnode, read_local_node_cb, net))
		return false;

	if (!mesh_db_read_net_keys(jnode, read_net_keys_cb, net))
		return false;

	/* TODO: use the actual "primary" network index for this node */
	if (mesh_db_read_device_key(jnode, key_buf) &&
		!node_set_device_key(mesh_net_local_node_get(net), key_buf))
		return false;

	mesh_db_read_app_keys(jnode, read_app_keys_cb, net);

	return true;
}

static bool read_unprov_device_cb(struct mesh_db_node *db_node, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_node *node;
	uint16_t crpl;
	uint8_t *uuid;

	if (!net)
		return false;

	node = node_create_from_storage(net, db_node, true);

	if (!node)
		return false;

	mesh_net_local_node_set(net, node, db_node->provisioner);
	crpl = node_get_crpl(node);
	mesh_net_set_crpl(net, crpl);

	uuid = node_uuid_get(node);
	if (uuid)
		mesh_net_id_uuid_set(net, uuid);

	return true;
}

static bool parse_unprovisioned_device(struct mesh_net *net, json_object *jnode)
{
	struct mesh_db_prov prov;
	struct mesh_net_prov_caps *caps;
	struct mesh_node *node;

	/* Node composition/configuration info */
	if (!mesh_db_read_unprovisioned_device(jnode,
					read_unprov_device_cb, net))
		return false;

	if (!mesh_db_read_prov_info(jnode, &prov))
		return false;

	caps = mesh_net_prov_caps_get(net);
	if (!caps)
		return false;

	node = mesh_net_local_node_get(net);
	if (!node)
		return false;

	caps->num_ele = node_get_num_elements(node);
	l_put_le16(prov.algorithm, &caps->algorithms);
	caps->pub_type = prov.pub_type;
	caps->static_type = prov.static_type;
	caps->output_size = prov.output_oob.size;
	l_put_le16(prov.output_oob.actions, &caps->output_action);
	caps->input_size = prov.input_oob.size;
	l_put_le16(prov.input_oob.actions, &caps->input_action);

	return mesh_net_priv_key_set(net, prov.priv_key);
}

static bool parse_config(struct mesh_net *net, const char *config_name,
							bool unprovisioned)
{
	int fd;
	char *str;
	const char *out;
	struct stat st;
	ssize_t sz;
	json_object *jnode = NULL;
	bool result = false;

	if (!config_name)
		return false;

	fd = open(config_name, O_RDONLY);
	if (!fd)
		return false;

	if (fstat(fd, &st) == -1) {
		close(fd);
		return false;
	}

	str = (char *) l_new(char, st.st_size + 1);
	if (!str) {
		close(fd);
		return false;
	}

	sz = read(fd, str, st.st_size);
	if (sz != st.st_size) {
		l_error("Failed to read configuration file");
		goto done;
	}

	jnode = json_tokener_parse(str);
	if (!jnode)
		goto done;

	mesh_net_jconfig_set(net, jnode);

	if (!unprovisioned)
		result = parse_local_node(net, jnode);
	else
		result = parse_unprovisioned_device(net, jnode);

	if (!result) {
		storage_release(net);
		goto done;
	}

	mesh_net_cfg_file_get(net, &out);
	if (!out)
		mesh_net_cfg_file_set(net, !unprovisioned ?
					config_name : NODE_CONGIGURATION_FILE);
done:
	close(fd);
	if (str)
		l_free(str);

	return result;
}

bool storage_parse_config(struct mesh_net *net, const char *config_name)
{
	bool result = false;
	bool unprovisioned = !config_name;

	if (unprovisioned) {
		result = parse_config(net, DEVICE_COMPOSITION_FILE, true);
		goto done;
	}

	result = parse_config(net, config_name, false);

	if (!result) {
		size_t len = strlen(config_name) + 5;
		char *bak = l_malloc(len);

		/* Fall-back to Backup version */
		strncpy(bak, config_name, len);
		bak = strncat(bak, ".bak", 5);

		remove(config_name);
		rename(bak, config_name);

		result = parse_config(net, config_name, false);

		l_free(bak);
	}

	/* If configuration read fails, try as unprovisioned device */
	if (!result) {
		l_info("Parse configuration failed, trying unprovisioned");
		unprovisioned = true;
		result = parse_config(net, DEVICE_COMPOSITION_FILE, true);
	}

done:
	if (result)
		mesh_net_provisioned_set(net, !unprovisioned);

	return result;
}

bool storage_local_set_ttl(struct mesh_net *net, uint8_t ttl)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_write_int(jnode, "defaultTTL", ttl);
}

bool storage_local_set_relay(struct mesh_net *net, bool enable,
				uint8_t count, uint8_t interval)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_write_relay_mode(jnode, enable, count, interval);
}

bool storage_local_set_transmit_params(struct mesh_net *net, uint8_t count,
							uint8_t interval)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_write_net_transmit(jnode, count, interval);
}

bool storage_local_set_mode(struct mesh_net *net, uint8_t mode,
						const char *mode_name)
{
	json_object *jnode;

	if (!net || !mode_name)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_write_mode(jnode, mode_name, mode);
}

bool storage_model_bind(struct mesh_net *net, uint16_t addr, uint32_t mod_id,
				uint16_t app_idx, bool unbind)
{
	json_object *jnode;
	bool is_local;

	if (!net)
		return false;

	is_local = mesh_net_is_local_address(net, addr);
	if (is_local) {
		int ele_idx;
		bool is_vendor = (mod_id > 0xffff);

		ele_idx = node_get_element_idx(mesh_net_local_node_get(net),
									addr);
		if (ele_idx < 0)
			return false;

		jnode = mesh_net_jconfig_get(net);
		if (!jnode)
			return false;

		if (unbind)
			return mesh_db_model_binding_del(jnode, ele_idx,
						is_vendor, mod_id, app_idx);
		else
			return mesh_db_model_binding_add(jnode, ele_idx,
						is_vendor, mod_id, app_idx);
	}

	/* TODO: write remote node bindings to provisioner DB */
	return false;
}

bool storage_local_app_key_add(struct mesh_net *net, uint16_t net_idx,
			uint16_t app_idx, const uint8_t key[16], bool update)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_app_key_add(jnode, net_idx, app_idx, key, update);
}

bool storage_local_app_key_del(struct mesh_net *net, uint16_t net_idx,
					uint16_t app_idx)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_app_key_del(jnode, net_idx, app_idx);

}

bool storage_local_net_key_add(struct mesh_net *net, uint16_t net_idx,
					const uint8_t key[16], int phase)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_net_key_add(jnode, net_idx, key, phase);
}

bool storage_local_net_key_del(struct mesh_net *net, uint16_t net_idx)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_net_key_del(jnode, net_idx);
}

bool storage_local_set_iv_index(struct mesh_net *net, uint32_t iv_index,
								bool update)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_write_iv_index(jnode, iv_index, update);
}

bool storage_local_set_device_key(struct mesh_net *net, uint8_t dev_key[16])
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_write_device_key(jnode, dev_key);
}

bool storage_local_set_unicast(struct mesh_net *net, uint16_t unicast)
{
	json_object *jnode;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	return mesh_db_write_uint16_hex(jnode, "unicastAddress", unicast);
}

bool storage_local_write_sequence_number(struct mesh_net *net, uint32_t seq)
{
	json_object *jnode;
	const char *cfg_file;
	bool result;

	if (!net)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	result = mesh_db_write_int(jnode, "sequenceNumber", seq);
	if (!result)
		return false;

	result = mesh_net_cfg_file_get(net, &cfg_file);
	if (result && cfg_file)
		result = storage_save_config(net, cfg_file, false, NULL, NULL);

	return result;
}

static bool save_config(struct mesh_net *net, const char *config_name)
{
	FILE *outfile;
	const char *str;
	json_object *jnode;
	bool result = false;

	if (!net || !config_name)
		return false;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	outfile = fopen(config_name, "w");
	if (!outfile) {
		l_error("Failed to save configuration to %s", config_name);
		return false;
	}

	str = json_object_to_json_string_ext(jnode, JSON_C_TO_STRING_PRETTY);

	if (fwrite(str, sizeof(char), strlen(str), outfile) < strlen(str))
		l_warn("Incomplete write of mesh configuration");
	else
		result = true;

	fclose(outfile);

	return result;
}

struct write_info {
	const char *config_name;
	struct mesh_net *net;
	void *user_data;
	mesh_status_func_t cb;
};

static void idle_save_config(void *user_data)
{
	struct write_info *info = user_data;
	size_t len = strlen(info->config_name) + 5;
	char *tmp = l_malloc(len);
	char *bak = l_malloc(len);
	bool result = false;

	strncpy(tmp, info->config_name, len);
	strncpy(bak, info->config_name, len);
	tmp = strncat(tmp, ".tmp", 5);
	bak = strncat(bak, ".bak", 5);
	remove(tmp);

	l_debug("Storage-Wrote");
	result = save_config(info->net, tmp);

	if (result) {
		remove(bak);
		rename(info->config_name, bak);
		rename(tmp, info->config_name);
	}

	remove(tmp);
	l_free(tmp);
	l_free(bak);

	if (info->cb)
		info->cb(info->user_data, result);

	l_free(info);
}

bool storage_save_config(struct mesh_net *net, const char *config_name,
			bool no_wait, mesh_status_func_t cb, void *user_data)
{
	struct write_info *info;

	info = l_new(struct write_info, 1);
	if (!info)
		return false;

	info->net = net;
	info->config_name = config_name;
	info->cb = cb;
	info->user_data = user_data;

	if (no_wait)
		idle_save_config(info);
	l_idle_oneshot(idle_save_config, info, NULL);

	return true;
}

bool storage_save_new_config(struct mesh_net *net, const char *config_name,
					mesh_status_func_t cb, void *user_data)
{
	json_object *jnode;

	jnode = mesh_net_jconfig_get(net);
	if (!jnode)
		return false;

	mesh_db_remove_property(jnode, "provision");

	return storage_save_config(net, config_name, false, cb, user_data);
}

void storage_release(struct mesh_net *net)
{
	json_object *jnode;

	jnode = mesh_net_jconfig_get(net);
	if (jnode)
		json_object_put(jnode);

	mesh_net_jconfig_set(net, NULL);
}
