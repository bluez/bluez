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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/stat.h>

#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/node.h"
#include "mesh/keyring.h"

const char *dev_key_dir = "/dev_keys";
const char *app_key_dir = "/app_keys";
const char *net_key_dir = "/net_keys";

bool keyring_put_net_key(struct mesh_node *node, uint16_t net_idx,
						struct keyring_net_key *key)
{
	const char *node_path;
	char key_file[PATH_MAX];
	bool result = false;
	int fd;

	if (!node || !key)
		return false;

	node_path = node_get_storage_dir(node);

	if (strlen(node_path) + strlen(net_key_dir) + 1 + 3 >= PATH_MAX)
		return false;

	snprintf(key_file, PATH_MAX, "%s%s", node_path, net_key_dir);
	mkdir(key_file, 0755);
	snprintf(key_file, PATH_MAX, "%s%s/%3.3x", node_path, net_key_dir,
								net_idx);
	l_debug("Put Net Key %s", key_file);

	fd = open(key_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd >= 0) {
		if (write(fd, key, sizeof(*key)) == sizeof(*key))
			result = true;

		close(fd);
	}

	return result;
}

bool keyring_put_app_key(struct mesh_node *node, uint16_t app_idx,
				uint16_t net_idx, struct keyring_app_key *key)
{
	const char *node_path;
	char key_file[PATH_MAX];
	bool result = false;
	int fd;

	if (!node || !key)
		return false;

	node_path = node_get_storage_dir(node);

	if (strlen(node_path) + strlen(app_key_dir) + 1 + 3 >= PATH_MAX)
		return false;

	snprintf(key_file, PATH_MAX, "%s%s", node_path, app_key_dir);
	mkdir(key_file, 0755);
	snprintf(key_file, PATH_MAX, "%s%s/%3.3x", node_path, app_key_dir,
								app_idx);
	l_debug("Put App Key %s", key_file);

	fd = open(key_file, O_RDWR);
	if (fd >= 0) {
		struct keyring_app_key old_key;

		if (read(fd, &old_key, sizeof(old_key)) == sizeof(old_key)) {
			if (old_key.net_idx != net_idx) {
				close(fd);
				return false;
			}
		}

		lseek(fd, 0, SEEK_SET);
	} else
		fd = open(key_file, O_WRONLY | O_CREAT | O_TRUNC,
							S_IRUSR | S_IWUSR);

	if (fd >= 0) {
		if (write(fd, key, sizeof(*key)) == sizeof(*key))
			result = true;

		close(fd);
	}

	return result;
}

static void finalize(int dir_fd, const char *fname, uint16_t net_idx)
{
	struct keyring_app_key key;
	int fd;

	fd = openat(dir_fd, fname, O_RDWR);

	if (fd < 0)
		return;

	if (read(fd, &key, sizeof(key)) != sizeof(key) ||
						key.net_idx != net_idx)
		goto done;

	l_debug("Finalize %s", fname);
	memcpy(key.old_key, key.new_key, 16);
	lseek(fd, 0, SEEK_SET);

	if (write(fd, &key, sizeof(key)) != sizeof(key))
		goto done;

done:
	close(fd);
}

bool keyring_finalize_app_keys(struct mesh_node *node, uint16_t net_idx)
{
	const char *node_path;
	char key_dir[PATH_MAX];
	DIR *dir;
	int dir_fd;
	struct dirent *entry;

	if (!node)
		return false;

	node_path = node_get_storage_dir(node);

	if (strlen(node_path) + strlen(app_key_dir) + 1 >= PATH_MAX)
		return false;

	snprintf(key_dir, PATH_MAX, "%s%s", node_path, app_key_dir);
	dir = opendir(key_dir);
	if (!dir) {
		if (errno == ENOENT)
			return true;

		l_error("Failed to open AppKey storage directory: %s", key_dir);
		return false;
	}

	dir_fd = dirfd(dir);

	while ((entry = readdir(dir)) != NULL) {
		/* AppKeys are stored in regular files */
		if (entry->d_type == DT_REG)
			finalize(dir_fd, entry->d_name, net_idx);
	}

	closedir(dir);

	return true;
}

bool keyring_put_remote_dev_key(struct mesh_node *node, uint16_t unicast,
					uint8_t count, uint8_t dev_key[16])
{
	const char *node_path;
	char key_file[PATH_MAX];
	bool result = true;
	int fd, i;

	if (!IS_UNICAST_RANGE(unicast, count))
		return false;

	if (!node)
		return false;

	node_path = node_get_storage_dir(node);

	if (strlen(node_path) + strlen(dev_key_dir) + 1 + 4 >= PATH_MAX)
		return false;

	snprintf(key_file, PATH_MAX, "%s%s", node_path, dev_key_dir);
	mkdir(key_file, 0755);

	for (i = 0; i < count; i++) {
		snprintf(key_file, PATH_MAX, "%s%s/%4.4x", node_path,
						dev_key_dir, unicast + i);
		l_debug("Put Dev Key %s", key_file);

		fd = open(key_file, O_WRONLY | O_CREAT | O_TRUNC,
							S_IRUSR | S_IWUSR);
		if (fd >= 0) {
			if (write(fd, dev_key, 16) != 16)
				result = false;

			close(fd);
		} else
			result = false;
	}

	return result;
}

bool keyring_get_net_key(struct mesh_node *node, uint16_t net_idx,
						struct keyring_net_key *key)
{
	const char *node_path;
	char key_file[PATH_MAX];
	bool result = false;
	int fd;

	if (!node || !key)
		return false;

	node_path = node_get_storage_dir(node);
	snprintf(key_file, PATH_MAX, "%s%s/%3.3x", node_path, net_key_dir,
								net_idx);

	fd = open(key_file, O_RDONLY);
	if (fd >= 0) {
		if (read(fd, key, sizeof(*key)) == sizeof(*key))
			result = true;

		close(fd);
	}

	return result;
}

bool keyring_get_app_key(struct mesh_node *node, uint16_t app_idx,
						struct keyring_app_key *key)
{
	const char *node_path;
	char key_file[PATH_MAX];
	bool result = false;
	int fd;

	if (!node || !key)
		return false;

	node_path = node_get_storage_dir(node);
	snprintf(key_file, PATH_MAX, "%s%s/%3.3x", node_path, app_key_dir,
								app_idx);

	fd = open(key_file, O_RDONLY);
	if (fd >= 0) {
		if (read(fd, key, sizeof(*key)) == sizeof(*key))
			result = true;

		close(fd);
	}

	return result;
}

bool keyring_get_remote_dev_key(struct mesh_node *node, uint16_t unicast,
							uint8_t dev_key[16])
{
	const char *node_path;
	char key_file[PATH_MAX];
	bool result = false;
	int fd;

	if (!IS_UNICAST(unicast))
		return false;

	if (!node)
		return false;

	node_path = node_get_storage_dir(node);

	snprintf(key_file, PATH_MAX, "%s%s/%4.4x", node_path, dev_key_dir,
								unicast);

	fd = open(key_file, O_RDONLY);
	if (fd >= 0) {
		if (read(fd, dev_key, 16) == 16)
			result = true;

		close(fd);
	}

	return result;
}

bool keyring_del_net_key(struct mesh_node *node, uint16_t net_idx)
{
	const char *node_path;
	char key_file[PATH_MAX];

	if (!node)
		return false;

	node_path = node_get_storage_dir(node);
	snprintf(key_file, PATH_MAX, "%s%s/%3.3x", node_path, net_key_dir,
								net_idx);
	l_debug("RM Net Key %s", key_file);
	remove(key_file);

	/* TODO: See if it is easiest to delete all bound App keys here */
	/* TODO: see nftw() */

	return true;
}

bool keyring_del_app_key(struct mesh_node *node, uint16_t app_idx)
{
	const char *node_path;
	char key_file[PATH_MAX];

	if (!node)
		return false;

	node_path = node_get_storage_dir(node);
	snprintf(key_file, PATH_MAX, "%s%s/%3.3x", node_path, app_key_dir,
								app_idx);
	l_debug("RM App Key %s", key_file);
	remove(key_file);

	return true;
}

bool keyring_del_remote_dev_key(struct mesh_node *node, uint16_t unicast,
								uint8_t count)
{
	const char *node_path;
	char key_file[PATH_MAX];
	int i;

	if (!IS_UNICAST_RANGE(unicast, count))
		return false;

	if (!node)
		return false;

	node_path = node_get_storage_dir(node);

	for (i = 0; i < count; i++) {
		snprintf(key_file, PATH_MAX, "%s%s/%4.4x", node_path,
						dev_key_dir, unicast + i);
		l_debug("RM Dev Key %s", key_file);
		remove(key_file);
	}

	return true;
}
