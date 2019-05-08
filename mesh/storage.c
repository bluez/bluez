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

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>

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
#include "mesh/mesh-db.h"
#include "mesh/storage.h"
#include "mesh/util.h"

struct write_info {
	json_object *jnode;
	const char *config_name;
	void *user_data;
	mesh_status_func_t cb;
};

static const char *storage_dir;

static bool read_node_cb(struct mesh_db_node *db_node, void *user_data)
{
	struct mesh_node *node = user_data;
	struct mesh_net *net;
	uint32_t seq_number;
	uint8_t ttl, mode, cnt, num_ele;
	uint16_t unicast, interval;
	uint8_t *uuid;

	if (!node_init_from_storage(node, db_node)) {
		node_remove(node);
		return false;
	}

	net = node_get_net(node);
	seq_number = node_get_sequence_number(node);
	mesh_net_set_seq_num(net, seq_number);
	ttl = node_default_ttl_get(node);
	mesh_net_set_default_ttl(net, ttl);

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

	return mesh_net_set_key(net, idx, key, new_key, phase);
}

static bool read_app_keys_cb(uint16_t net_idx, uint16_t app_idx, uint8_t *key,
					uint8_t *new_key, void *user_data)
{
	struct mesh_net *net = user_data;

	if (!net)
		return false;

	return appkey_key_init(net, net_idx, app_idx, key, new_key);
}

static bool parse_node(struct mesh_node *node, json_object *jnode)
{
	bool bvalue;
	uint32_t iv_index;
	uint8_t key_buf[16];
	uint8_t cnt;
	uint16_t interval;
	struct mesh_net *net = node_get_net(node);

	if (mesh_db_read_iv_index(jnode, &iv_index, &bvalue))
		mesh_net_set_iv_index(net, iv_index, bvalue);

	if (mesh_db_read_net_transmit(jnode, &cnt, &interval))
		mesh_net_transmit_params_set(net, cnt, interval);

	/* Node composition/configuration info */
	if (!mesh_db_read_node(jnode, read_node_cb, node))
		return false;

	if (!mesh_db_read_net_keys(jnode, read_net_keys_cb, net))
		return false;

	if (!mesh_db_read_token(jnode, key_buf))
		return false;

	node_set_token(node, key_buf);

	if (!mesh_db_read_device_key(jnode, key_buf))
		return false;

	node_set_device_key(node, key_buf);

	mesh_db_read_app_keys(jnode, read_app_keys_cb, net);

	return true;
}

static bool parse_config(char *in_file, char *out_file, const uint8_t uuid[16])
{
	int fd;
	char *str;
	struct stat st;
	ssize_t sz;
	json_object *jnode = NULL;
	bool result = false;
	struct mesh_node *node;

	l_info("Loading configuration from %s", in_file);

	fd = open(in_file, O_RDONLY);
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
		l_error("Failed to read configuration file %s", in_file);
		goto done;
	}

	jnode = json_tokener_parse(str);
	if (!jnode)
		goto done;

	node = node_new(uuid);

	result = parse_node(node, jnode);

	if (!result) {
		json_object_put(jnode);
		node_remove(node);
	}

	node_jconfig_set(node, jnode);
	node_cfg_file_set(node, out_file);

done:
	close(fd);
	if (str)
		l_free(str);

	return result;
}

bool storage_set_ttl(struct mesh_node *node, uint8_t ttl)
{
	json_object *jnode = node_jconfig_get(node);

	if (!mesh_db_write_int(jnode, "defaultTTL", ttl))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_relay(struct mesh_node *node, bool enable,
				uint8_t count, uint8_t interval)
{
	json_object *jnode = node_jconfig_get(node);

	if (!mesh_db_write_relay_mode(jnode, enable, count, interval))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_transmit_params(struct mesh_node *node, uint8_t count,
							uint8_t interval)
{
	json_object *jnode = node_jconfig_get(node);

	if (!mesh_db_write_net_transmit(jnode, count, interval))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_mode(struct mesh_node *node, uint8_t mode,
						const char *mode_name)
{
	json_object *jnode = node_jconfig_get(node);

	if (!mesh_db_write_mode(jnode, mode_name, mode))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_model_bind(struct mesh_node *node, uint16_t addr, uint32_t mod_id,
				uint16_t app_idx, bool unbind)
{
	json_object *jnode;
	int ele_idx;
	bool stored, is_vendor = (mod_id > 0xffff);

	ele_idx = node_get_element_idx(node, addr);
	if (ele_idx < 0)
		return false;

	jnode = node_jconfig_get(node);

	if (unbind)
		stored = mesh_db_model_binding_del(jnode, ele_idx, is_vendor,
							mod_id, app_idx);
	else
		stored = mesh_db_model_binding_add(jnode, ele_idx, is_vendor,
							mod_id, app_idx);

	if (stored)
		storage_save_config(node, true, NULL, NULL);

	return stored;
}

bool storage_app_key_add(struct mesh_net *net, uint16_t net_idx,
			uint16_t app_idx, const uint8_t key[16], bool update)
{
	json_object *jnode;
	struct mesh_node *node = mesh_net_node_get(net);
	bool stored;

	jnode = node_jconfig_get(node);
	if (!jnode)
		return false;

	if (update)
		stored = mesh_db_app_key_update(jnode, app_idx, key);
	else
		stored = mesh_db_app_key_add(jnode, net_idx, app_idx, key);

	if (stored)
		storage_save_config(node, true, NULL, NULL);

	return stored;
}

bool storage_app_key_del(struct mesh_net *net, uint16_t net_idx,
					uint16_t app_idx)
{
	json_object *jnode;
	struct mesh_node *node = mesh_net_node_get(net);

	jnode = node_jconfig_get(node);
	if (!jnode)
		return false;

	if (!mesh_db_app_key_del(jnode, net_idx, app_idx))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_net_key_add(struct mesh_net *net, uint16_t net_idx,
					const uint8_t key[16], bool update)
{
	struct mesh_node *node = mesh_net_node_get(net);
	json_object *jnode = node_jconfig_get(node);
	bool stored;

	if (!update)
		stored = mesh_db_net_key_add(jnode, net_idx, key);
	else
		stored = mesh_db_net_key_update(jnode, net_idx, key);

	if (stored)
		storage_save_config(node, true, NULL, NULL);

	return stored;
}

bool storage_net_key_del(struct mesh_net *net, uint16_t net_idx)
{
	struct mesh_node *node = mesh_net_node_get(net);
	json_object *jnode = node_jconfig_get(node);

	if (!mesh_db_net_key_del(jnode, net_idx))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_iv_index(struct mesh_net *net, uint32_t iv_index,
								bool update)
{
	struct mesh_node *node = mesh_net_node_get(net);
	json_object *jnode = node_jconfig_get(node);

	if (!mesh_db_write_iv_index(jnode, iv_index, update))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_key_refresh_phase(struct mesh_net *net, uint16_t net_idx,
								uint8_t phase)
{
	struct mesh_node *node = mesh_net_node_get(net);
	json_object *jnode = node_jconfig_get(node);

	if (!mesh_db_net_key_set_phase(jnode, net_idx, phase))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_write_sequence_number(struct mesh_net *net, uint32_t seq)
{
	struct mesh_node *node = mesh_net_node_get(net);
	json_object *jnode = node_jconfig_get(node);

	if (!mesh_db_write_int(jnode, "sequenceNumber", seq))
		return false;

	storage_save_config(node, false, NULL, NULL);
	return true;
}

static bool save_config(json_object *jnode, const char *config_name)
{
	FILE *outfile;
	const char *str;
	bool result = false;

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
	result = save_config(info->jnode, tmp);

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

void storage_save_config(struct mesh_node *node, bool no_wait,
					mesh_status_func_t cb, void *user_data)
{
	struct write_info *info;

	info = l_new(struct write_info, 1);
	info->jnode = node_jconfig_get(node);
	info->config_name = node_cfg_file_get(node);
	info->cb = cb;
	info->user_data = user_data;

	if (no_wait)
		idle_save_config(info);
	else
		l_idle_oneshot(idle_save_config, info, NULL);
}

static int create_dir(const char *dirname)
{
	struct stat st;
	char dir[PATH_MAX + 1], *prev, *next;
	int err;

	err = stat(dirname, &st);
	if (!err && S_ISREG(st.st_mode))
		return 0;

	memset(dir, 0, PATH_MAX + 1);
	strcat(dir, "/");

	prev = strchr(dirname, '/');

	while (prev) {
		next = strchr(prev + 1, '/');
		if (!next)
			break;

		if (next - prev == 1) {
			prev = next;
			continue;
		}

		strncat(dir, prev + 1, next - prev);
		mkdir(dir, 0755);

		prev = next;
	}

	mkdir(dirname, 0755);

	return 0;
}

bool storage_load_nodes(const char *dir_name)
{
	DIR *dir;
	struct dirent *entry;

	create_dir(dir_name);
	dir = opendir(dir_name);
	if (!dir) {
		l_error("Failed to open mesh node storage directory: %s",
								dir_name);
		return false;
	}

	storage_dir = dir_name;

	while ((entry = readdir(dir)) != NULL) {
		char *cfg;
		char *bak;
		uint8_t uuid[16];

		if (entry->d_type != DT_DIR)
			continue;

		if (!str2hex(entry->d_name, strlen(entry->d_name), uuid, sizeof(uuid)))
			continue;

		cfg = l_strdup_printf("%s/%s/node.json", dir_name, entry->d_name);

		if (parse_config(cfg, cfg, uuid))
			continue;

		/* Fall-back to Backup version */
		bak = l_strdup_printf("%s/%s/node.json.bak", dir_name, entry->d_name);

		if (parse_config(bak, cfg, uuid)) {
			remove(cfg);
			rename(bak, cfg);
			l_free(cfg);
			continue;
		}

		l_free(cfg);
		l_free(bak);
	}

	return true;
}

bool storage_create_node_config(struct mesh_node *node, void *data)
{
	struct mesh_db_node *db_node = data;
	char uuid[33];
	char name_buf[PATH_MAX];
	char *filename;
	json_object *jnode;

	if (!storage_dir)
		return false;

	jnode = json_object_new_object();

	if (!mesh_db_add_node(jnode, db_node))
		return false;

	if (!hex2str(node_uuid_get(node), 16, uuid, sizeof(uuid)))
		return false;

	snprintf(name_buf, PATH_MAX, "%s/%s", storage_dir, uuid);

	/* Create a new directory and node.json file */
	if (mkdir(name_buf, 0755) != 0)
		goto fail;

	filename = l_strdup_printf("%s/node.json", name_buf);

	l_debug("New node config %s", filename);

	if (!save_config(jnode, filename)) {
		l_free(filename);
		goto fail;
	}

	node_jconfig_set(node, jnode);
	node_cfg_file_set(node, filename);

	return true;
fail:
	json_object_put(jnode);
	return false;
}

/* Permanently remove node configuration */
void storage_remove_node_config(struct mesh_node *node)
{
	char *cfg;
	struct json_object *jnode;
	const char *dir_name;
	char *bak;

	if (!node)
		return;

	/* Free the node config json object */
	jnode = node_jconfig_get(node);
	if (jnode)
		json_object_put(jnode);
	node_jconfig_set(node, NULL);

	/* Delete node configuration file */
	cfg = node_cfg_file_get(node);
	if (!cfg)
		return;

	l_debug("Delete node config file %s", cfg);
	remove(cfg);

	/* Delete the backup file */
	bak = l_strdup_printf("%s.bak", cfg);
	remove(bak);
	l_free(bak);

	/* Delete the node directory */
	dir_name = dirname(cfg);

	l_debug("Delete directory %s", dir_name);
	rmdir(dir_name);

	l_free(cfg);
	node_cfg_file_set(node, NULL);
}
