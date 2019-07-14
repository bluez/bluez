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
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <ftw.h>

#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/mesh-config.h"
#include "mesh/util.h"
#include "mesh/storage.h"

struct write_info {
	struct mesh_config *cfg;
	const char *node_path;
	void *user_data;
	mesh_status_func_t cb;
};

static const char *cfg_name = "/node.json";
static const char *bak_ext = ".bak";
static const char *tmp_ext = ".tmp";
static const char *storage_dir;

static bool read_node_cb(struct mesh_config_node *db_node,
			const uint8_t uuid[16], struct mesh_config *cfg,
			void *user_data)
{
	struct mesh_node *node = user_data;

	if (!node_init_from_storage(node, uuid, db_node)) {
		node_remove(node);
		return false;
	}

	node_config_set(node, cfg);
	return true;
}

static bool parse_config(char *in_file, char *out_dir, const uint8_t uuid[16])
{
	bool result = false;
	struct mesh_node *node;

	node = node_new(uuid);

	result = mesh_config_load_node(in_file, uuid, read_node_cb, node);

	if (!result)
		node_remove(node);
	else
		node_path_set(node, out_dir);

	return result;
}

bool storage_set_ttl(struct mesh_node *node, uint8_t ttl)
{
	if (!mesh_config_write_int(node_config_get(node), "defaultTTL", ttl))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_relay(struct mesh_node *node, bool enable,
				uint8_t count, uint8_t interval)
{
	if (!mesh_config_write_relay_mode(node_config_get(node), enable, count,
								interval))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_transmit_params(struct mesh_node *node, uint8_t count,
							uint8_t interval)
{
	if (!mesh_config_write_net_transmit(node_config_get(node), count,
								interval))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_mode(struct mesh_node *node, uint8_t mode,
						const char *mode_name)
{
	if (!mesh_config_write_mode(node_config_get(node), mode_name, mode))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_model_bind(struct mesh_node *node, uint16_t addr, uint32_t mod_id,
				uint16_t app_idx, bool unbind)
{
	struct mesh_config *cfg;
	int ele_idx;
	bool stored, is_vendor = (mod_id > 0xffff);

	ele_idx = node_get_element_idx(node, addr);
	if (ele_idx < 0)
		return false;

	cfg = node_config_get(node);

	if (unbind)
		stored = mesh_config_model_binding_del(cfg, ele_idx, is_vendor,
							mod_id, app_idx);
	else
		stored = mesh_config_model_binding_add(cfg, ele_idx, is_vendor,
							mod_id, app_idx);

	if (stored)
		storage_save_config(node, true, NULL, NULL);

	return stored;
}

bool storage_app_key_add(struct mesh_net *net, uint16_t net_idx,
			uint16_t app_idx, const uint8_t key[16], bool update)
{
	struct mesh_config *cfg;
	struct mesh_node *node = mesh_net_node_get(net);
	bool stored;

	cfg = node_config_get(node);

	if (update)
		stored = mesh_config_app_key_update(cfg, app_idx, key);
	else
		stored = mesh_config_app_key_add(cfg, net_idx, app_idx, key);

	if (stored)
		storage_save_config(node, true, NULL, NULL);

	return stored;
}

bool storage_app_key_del(struct mesh_net *net, uint16_t net_idx,
					uint16_t app_idx)
{
	struct mesh_config *cfg;
	struct mesh_node *node = mesh_net_node_get(net);

	cfg = node_config_get(node);

	if (!mesh_config_app_key_del(cfg, net_idx, app_idx))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_net_key_add(struct mesh_net *net, uint16_t net_idx,
					const uint8_t key[16], bool update)
{
	struct mesh_node *node = mesh_net_node_get(net);
	struct mesh_config *cfg = node_config_get(node);
	bool stored;

	if (!update)
		stored = mesh_config_net_key_add(cfg, net_idx, key);
	else
		stored = mesh_config_net_key_update(cfg, net_idx, key);

	if (stored)
		storage_save_config(node, true, NULL, NULL);

	return stored;
}

bool storage_net_key_del(struct mesh_net *net, uint16_t net_idx)
{
	struct mesh_node *node = mesh_net_node_get(net);
	struct mesh_config *cfg = node_config_get(node);

	if (!mesh_config_net_key_del(cfg, net_idx))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_iv_index(struct mesh_net *net, uint32_t iv_index,
								bool update)
{
	struct mesh_node *node = mesh_net_node_get(net);
	struct mesh_config *cfg = node_config_get(node);

	if (!mesh_config_write_iv_index(cfg, iv_index, update))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_set_key_refresh_phase(struct mesh_net *net, uint16_t net_idx,
								uint8_t phase)
{
	struct mesh_node *node = mesh_net_node_get(net);
	struct mesh_config *cfg = node_config_get(node);

	if (!mesh_config_net_key_set_phase(cfg, net_idx, phase))
		return false;

	storage_save_config(node, true, NULL, NULL);
	return true;
}

bool storage_write_sequence_number(struct mesh_net *net, uint32_t seq)
{
	struct mesh_node *node = mesh_net_node_get(net);
	struct mesh_config *cfg = node_config_get(node);

	if (!mesh_config_write_int(cfg, "sequenceNumber", seq))
		return false;

	storage_save_config(node, false, NULL, NULL);
	return true;
}

static void idle_save_config(void *user_data)
{
	struct write_info *info = user_data;
	char *tmp, *bak, *cfg;
	bool result = false;

	cfg = l_strdup_printf("%s%s", info->node_path, cfg_name);
	tmp = l_strdup_printf("%s%s", cfg, tmp_ext);
	bak = l_strdup_printf("%s%s", cfg, bak_ext);
	remove(tmp);

	l_debug("Storage-Wrote");
	result = mesh_config_save_config(info->cfg, tmp);

	if (result) {
		remove(bak);
		rename(cfg, bak);
		rename(tmp, cfg);
	}

	remove(tmp);
	l_free(tmp);
	l_free(bak);
	l_free(cfg);

	if (info->cb)
		info->cb(info->user_data, result);

	l_free(info);
}

void storage_save_config(struct mesh_node *node, bool no_wait,
					mesh_status_func_t cb, void *user_data)
{
	struct write_info *info;

	info = l_new(struct write_info, 1);
	info->cfg = node_config_get(node);
	info->node_path = node_path_get(node);
	info->cb = cb;
	info->user_data = user_data;

	if (no_wait)
		idle_save_config(info);
	else
		l_idle_oneshot(idle_save_config, info, NULL);
}

static int create_dir(const char *dir_name)
{
	struct stat st;
	char dir[PATH_MAX + 1], *prev, *next;
	int err;

	err = stat(dir_name, &st);
	if (!err && S_ISREG(st.st_mode))
		return 0;

	memset(dir, 0, PATH_MAX + 1);
	strcat(dir, "/");

	prev = strchr(dir_name, '/');

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

	mkdir(dir_name, 0755);

	return 0;
}

bool storage_load_nodes(const char *dir_name)
{
	DIR *dir;
	struct dirent *entry;
	size_t path_len = strlen(dir_name) + strlen(cfg_name) + strlen(bak_ext);

	create_dir(dir_name);
	dir = opendir(dir_name);
	if (!dir) {
		l_error("Failed to open mesh node storage directory: %s",
								dir_name);
		return false;
	}

	storage_dir = dir_name;

	while ((entry = readdir(dir)) != NULL) {
		char *dir, *cfg, *bak;
		uint8_t uuid[16];
		size_t node_len;

		if (entry->d_type != DT_DIR)
			continue;

		/* Check path length */
		node_len = strlen(entry->d_name);
		if (path_len + node_len + 1 >= PATH_MAX)
			continue;

		if (!str2hex(entry->d_name, node_len, uuid, sizeof(uuid)))
			continue;

		dir = l_strdup_printf("%s/%s", dir_name, entry->d_name);
		cfg = l_strdup_printf("%s%s", dir, cfg_name);

		if (!parse_config(cfg, dir, uuid)) {

			/* Fall-back to Backup version */
			bak = l_strdup_printf("%s%s", cfg, bak_ext);

			if (parse_config(bak, dir, uuid)) {
				remove(cfg);
				rename(bak, cfg);
			}
			l_free(bak);
		}
		l_free(cfg);
		l_free(dir);
	}

	return true;
}

bool storage_create_node_config(struct mesh_node *node, const uint8_t uuid[16],
					struct mesh_config_node *db_node)
{
	char uuid_buf[33];
	char name_buf[PATH_MAX];
	struct mesh_config *cfg;
	size_t max_len = strlen(cfg_name) + strlen(bak_ext);

	if (!storage_dir)
		return false;

	if (!hex2str((uint8_t *) uuid, 16, uuid_buf, sizeof(uuid_buf)))
		return false;

	snprintf(name_buf, PATH_MAX, "%s/%s", storage_dir, uuid_buf);

	if (strlen(name_buf) + max_len >= PATH_MAX)
		return false;

	/* Create a new directory and node.json file */
	if (mkdir(name_buf, 0755) != 0)
		return false;

	node_path_set(node, name_buf);

	snprintf(name_buf, PATH_MAX, "%s/%s%s", storage_dir, uuid_buf,
								cfg_name);
	l_debug("New node config %s", name_buf);

	cfg = mesh_config_create(name_buf, uuid, db_node);
	if (!cfg)
		return false;

	if (!mesh_config_save_config(cfg, name_buf)) {
		mesh_config_release(cfg);
		return false;
	}

	node_config_set(node, cfg);

	return true;
}

static int del_fobject(const char *fpath, const struct stat *sb, int typeflag,
						struct FTW *ftwbuf)
{
	switch (typeflag) {
	case FTW_DP:
		rmdir(fpath);
		l_debug("RMDIR %s", fpath);
		break;

	case FTW_SL:
	default:
		remove(fpath);
		l_debug("RM %s", fpath);
		break;
	}
	return 0;
}

/* Permanently remove node configuration */
void storage_remove_node_config(struct mesh_node *node)
{
	char *node_path, *node_name;
	char uuid[33];

	if (!node)
		return;

	/* Release node config object */
	mesh_config_release(node_config_get(node));
	node_config_set(node, NULL);

	node_path = node_path_get(node);
	l_debug("Delete node config %s", node_path);

	/* Make sure path name of node follows expected guidelines */
	if (!hex2str(node_uuid_get(node), 16, uuid, sizeof(uuid)))
		return;

	node_name = basename(node_path);

	if (strcmp(node_name, uuid))
		return;

	nftw(node_path, del_fobject, 5, FTW_DEPTH | FTW_PHYS);
}
