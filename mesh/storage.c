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

static const char *cfg_name = "/node.json";
static const char *bak_ext = ".bak";
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

	if (!mesh_config_save_config(cfg, true, NULL, NULL)) {
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
