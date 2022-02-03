// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
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

#include "mesh/dbus.h"
#include "mesh/node.h"
#include "mesh/keyring.h"

const char *dev_key_dir = "/dev_keys";
const char *app_key_dir = "/app_keys";
const char *net_key_dir = "/net_keys";

static int open_key_file(struct mesh_node *node, const char *key_dir,
							uint16_t idx, int flags)
{
	const char *node_path;
	char fname[PATH_MAX];

	if (!node)
		return -1;

	node_path = node_get_storage_dir(node);

	if (strlen(node_path) + strlen(key_dir) + 1 + 3 >= PATH_MAX)
		return -1;

	if (flags & O_CREAT) {
		snprintf(fname, PATH_MAX, "%s%s", node_path, key_dir);
		if (mkdir(fname, 0755) != 0 && errno != EEXIST)
			l_error("Failed to create dir(%d): %s", errno, fname);
	}

	snprintf(fname, PATH_MAX, "%s%s/%3.3x", node_path, key_dir, idx);

	if (flags & O_CREAT)
		return open(fname, flags, 0600);
	else
		return open(fname, flags);
}

bool keyring_put_net_key(struct mesh_node *node, uint16_t net_idx,
						struct keyring_net_key *key)
{
	bool result = false;
	int fd;

	if (!key)
		return false;

	fd = open_key_file(node, net_key_dir, net_idx,
					O_WRONLY | O_CREAT | O_TRUNC);

	if (fd < 0)
		return false;

	if (write(fd, key, sizeof(*key)) == sizeof(*key))
		result = true;

	close(fd);

	return result;
}

bool keyring_put_app_key(struct mesh_node *node, uint16_t app_idx,
				uint16_t net_idx, struct keyring_app_key *key)
{
	bool result = false;
	int fd;

	if (!key)
		return false;

	fd = open_key_file(node, app_key_dir, app_idx, O_RDWR);

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
		fd = open_key_file(node, app_key_dir, app_idx,
						O_WRONLY | O_CREAT | O_TRUNC);

	if (fd < 0)
		return false;

	if (write(fd, key, sizeof(*key)) == sizeof(*key))
		result = true;

	close(fd);

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

	if (mkdir(key_file, 0755) != 0 && errno != EEXIST)
		l_error("Failed to create dir(%d): %s", errno, key_file);

	for (i = 0; i < count; i++) {
		snprintf(key_file, PATH_MAX, "%s%s/%4.4x", node_path,
						dev_key_dir, unicast + i);
		l_debug("Put Dev Key %s", key_file);

		fd = open(key_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		if (fd >= 0) {
			if (write(fd, dev_key, 16) != 16)
				result = false;

			close(fd);
		} else
			result = false;
	}

	return result;
}

static bool get_key(struct mesh_node *node, const char *key_dir,
					uint16_t key_idx, void *key, ssize_t sz)
{
	bool result = false;
	int fd;

	if (!key)
		return false;

	fd = open_key_file(node, key_dir, key_idx, O_RDONLY);

	if (fd >= 0) {
		if (read(fd, key, sz) == sz)
			result = true;

		close(fd);
	}

	return result;
}

bool keyring_get_net_key(struct mesh_node *node, uint16_t net_idx,
						struct keyring_net_key *key)
{
	return get_key(node, net_key_dir, net_idx, key, sizeof(*key));
}

bool keyring_get_app_key(struct mesh_node *node, uint16_t app_idx,
						struct keyring_app_key *key)
{
	return get_key(node, app_key_dir, app_idx, key, sizeof(*key));
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

static DIR *open_key_dir(const char *node_path, const char *key_dir_name)
{
	char dir_path[PATH_MAX];
	DIR *key_dir;

	if (strlen(node_path) + strlen(key_dir_name) + 1 >= PATH_MAX)
		return NULL;

	snprintf(dir_path, PATH_MAX, "%s%s", node_path, key_dir_name);

	key_dir = opendir(dir_path);
	if (!key_dir) {
		l_error("Failed to open keyring storage directory: %s",
								dir_path);
		return NULL;
	}

	return key_dir;
}

static int open_key_dir_entry(int dir_fd, struct dirent *entry,
							uint8_t fname_len)
{
	if (entry->d_type != DT_REG)
		return -1;

	/* Check the file name length */
	if (strlen(entry->d_name) != fname_len)
		return -1;

	return openat(dir_fd, entry->d_name, O_RDONLY);
}

static void append_old_key(struct l_dbus_message_builder *builder,
							const uint8_t key[16])
{
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "OldKey");
	l_dbus_message_builder_enter_variant(builder, "ay");
	dbus_append_byte_array(builder, key, 16);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);
}

static void build_app_keys_reply(const char *node_path,
					struct l_dbus_message_builder *builder,
					uint16_t net_idx, uint8_t phase)
{
	DIR *key_dir;
	int key_dir_fd;
	struct dirent *entry;

	key_dir = open_key_dir(node_path, app_key_dir);
	if (!key_dir)
		return;

	key_dir_fd = dirfd(key_dir);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "AppKeys");
	l_dbus_message_builder_enter_variant(builder, "a(qaya{sv})");
	l_dbus_message_builder_enter_array(builder, "(qaya{sv})");

	while ((entry = readdir(key_dir)) != NULL) {
		struct keyring_app_key key;
		int fd = open_key_dir_entry(key_dir_fd, entry, 3);

		if (fd < 0)
			continue;

		if (read(fd, &key, sizeof(key)) != sizeof(key) ||
						key.net_idx != net_idx) {
			close(fd);
			continue;
		}

		close(fd);

		l_dbus_message_builder_enter_struct(builder, "qaya{sv}");

		l_dbus_message_builder_append_basic(builder, 'q', &key.app_idx);
		dbus_append_byte_array(builder, key.new_key, 16);

		l_dbus_message_builder_enter_array(builder, "{sv}");

		if (phase != KEY_REFRESH_PHASE_NONE)
			append_old_key(builder, key.old_key);

		l_dbus_message_builder_leave_array(builder);
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	closedir(key_dir);
}

static bool build_net_keys_reply(const char *node_path,
					struct l_dbus_message_builder *builder)
{
	DIR *key_dir;
	int key_dir_fd;
	struct dirent *entry;
	bool result = false;

	key_dir = open_key_dir(node_path, net_key_dir);
	if (!key_dir)
		return false;

	key_dir_fd = dirfd(key_dir);

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "NetKeys");
	l_dbus_message_builder_enter_variant(builder, "a(qaya{sv})");
	l_dbus_message_builder_enter_array(builder, "(qaya{sv})");

	while ((entry = readdir(key_dir)) != NULL) {
		struct keyring_net_key key;
		int fd = open_key_dir_entry(key_dir_fd, entry, 3);

		if (fd < 0)
			continue;

		if (read(fd, &key, sizeof(key)) != sizeof(key)) {
			close(fd);
			goto done;
		}

		close(fd);

		/*
		 * If network key is stuck in phase 3, keyring
		 * write failed and this key info is unreliable.
		 */
		if (key.phase == KEY_REFRESH_PHASE_THREE)
			continue;

		l_dbus_message_builder_enter_struct(builder, "qaya{sv}");

		l_dbus_message_builder_append_basic(builder, 'q', &key.net_idx);
		dbus_append_byte_array(builder, key.new_key, 16);

		l_dbus_message_builder_enter_array(builder, "{sv}");

		if (key.phase != KEY_REFRESH_PHASE_NONE) {
			dbus_append_dict_entry_basic(builder, "Phase", "y",
								&key.phase);
			append_old_key(builder, key.old_key);
		}

		build_app_keys_reply(node_path, builder, key.net_idx,
								key.phase);

		l_dbus_message_builder_leave_array(builder);
		l_dbus_message_builder_leave_struct(builder);
	}

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	result = true;
done:
	closedir(key_dir);

	return result;

}

struct dev_key_entry {
	uint16_t unicast;
	uint8_t value[16];
};

static bool match_key_value(const void *a, const void *b)
{
	const struct dev_key_entry *key = a;
	const uint8_t *value = b;

	return (memcmp(key->value, value, 16) == 0);
}

static void build_dev_key_entry(void *a, void *b)
{
	struct dev_key_entry *key = a;
	struct l_dbus_message_builder *builder = b;

	l_dbus_message_builder_enter_struct(builder, "qay");
	l_dbus_message_builder_append_basic(builder, 'q', &key->unicast);
	dbus_append_byte_array(builder, key->value, 16);
	l_dbus_message_builder_leave_struct(builder);
}

static bool build_dev_keys_reply(const char *node_path,
					struct l_dbus_message_builder *builder)
{
	DIR *key_dir;
	int key_dir_fd;
	struct dirent *entry;
	struct l_queue *keys;
	bool result = false;

	key_dir = open_key_dir(node_path, dev_key_dir);
	/*
	 * There is always at least one device key present for a local node.
	 * Therefore, return false, if the directory does not exist.
	 */
	if (!key_dir)
		return false;

	key_dir_fd = dirfd(key_dir);

	keys = l_queue_new();

	while ((entry = readdir(key_dir)) != NULL) {
		uint8_t buf[16];
		uint16_t unicast;
		struct dev_key_entry *key;
		int fd = open_key_dir_entry(key_dir_fd, entry, 4);

		if (fd < 0)
			continue;

		if (read(fd, buf, 16) != 16) {
			close(fd);
			goto done;
		}

		close(fd);

		if (sscanf(entry->d_name, "%04hx", &unicast) != 1)
			goto done;

		key = l_queue_find(keys, match_key_value, buf);

		if (key) {
			if (key->unicast > unicast)
				key->unicast = unicast;
			continue;
		}

		key = l_new(struct dev_key_entry, 1);
		key->unicast = unicast;
		memcpy(key->value, buf, 16);
		l_queue_push_tail(keys, key);
	}

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', "DevKeys");
	l_dbus_message_builder_enter_variant(builder, "a(qay)");
	l_dbus_message_builder_enter_array(builder, "(qay)");

	l_queue_foreach(keys, build_dev_key_entry, builder);

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);

	result = true;
done:
	l_queue_destroy(keys, l_free);
	closedir(key_dir);

	return result;
}

bool keyring_build_export_keys_reply(struct mesh_node *node,
					struct l_dbus_message_builder *builder)
{
	const char *node_path;

	if (!node)
		return false;

	node_path = node_get_storage_dir(node);

	if (!build_net_keys_reply(node_path, builder))
		return false;

	return build_dev_keys_reply(node_path, builder);
}
