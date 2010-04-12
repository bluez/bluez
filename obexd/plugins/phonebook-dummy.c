/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009-2010  Intel Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "logging.h"
#include "phonebook.h"

#define VCARD0				\
        "BEGIN:VCARD\n"			\
        "VERSION:3.0\n"			\
        "N:Klaus;Santa\n"		\
        "FN:\n"				\
        "TEL:+001122334455\n"		\
        "END:VCARD\n"

struct dummy_data {
	phonebook_cb	cb;
	gpointer	user_data;
	const struct apparam_field *apparams;
	int fd;
};

struct cache_query {
	phonebook_entry_cb entry_cb;
	phonebook_cache_ready_cb ready_cb;
	void *user_data;
	DIR *dp;
};

static gchar *root_folder = NULL;
static int folderfd = -1;

static void dummy_free(gpointer user_data)
{
	struct dummy_data *dummy = user_data;

	if (dummy->fd >= 0)
		close(dummy->fd);

	g_free(dummy);
}

static void query_free(void *user_data)
{
	struct cache_query *query = user_data;

	if (query->dp)
		closedir(query->dp);

	g_free(query);
}

int phonebook_init(void)
{
	/* FIXME: It should NOT be hard-coded */
	root_folder = g_build_filename(getenv("HOME"), "phonebook", NULL);

	return 0;
}

void phonebook_exit(void)
{
	g_free(root_folder);

	if (folderfd >= 0)
		close(folderfd);
}

static gboolean dummy_result(gpointer data)
{
	struct dummy_data *dummy = data;

	dummy->cb(VCARD0, strlen(VCARD0), 1, 0, dummy->user_data);

	return FALSE;
}

static gboolean create_cache(void *user_data)
{
	struct cache_query *query = user_data;
	struct dirent *ep;

	while ((ep = readdir(query->dp))) {
		char *filename;
		uint32_t handle;

		if (ep->d_name[0] == '.')
			continue;

		filename = g_filename_to_utf8(ep->d_name, -1, NULL, NULL, NULL);
		if (filename == NULL) {
			error("g_filename_to_utf8: invalid filename");
			continue;
		}

		if (sscanf(filename, "%u.vcf", &handle) != 1) {
			g_free(filename);
			continue;
		}

		query->entry_cb(filename, handle, "FIXME:name", NULL,
						"FIXME:tel", query->user_data);

		g_free(filename);
	}

	query->ready_cb(query->user_data);

	return FALSE;
}

static gboolean read_entry(gpointer user_data)
{
	struct dummy_data *dummy = user_data;
	char buffer[1024];
	ssize_t count;

	memset(buffer, 0, sizeof(buffer));
	count = read(dummy->fd, buffer, sizeof(buffer));

	if (count < 0) {
		int err = errno;
		error("read(): %s(%d)", strerror(err), err);
		count = 0;
	}

	/* FIXME: Missing vCards fields filtering */

	dummy->cb(buffer, count, 1, 0, dummy->user_data);

	return FALSE;
}

static int open_folder(const char *folder)
{
	struct stat st;
	int fd, err;

	if (stat(folder, &st) < 0) {
		err = errno;
		error("stat(): %s(%d)", strerror(err), err);
		return -err;
	}

	if (!S_ISDIR(st.st_mode)) {
		error("folder %s is not a folder!", folder);
		return -EBADR;
	}

	debug("open_folder: %s", folder);

	fd = open(folder, O_RDONLY);
	if (fd < 0) {
		err = errno;
		error("open(): %s(%d)", strerror(err), err);
		return -err;
	}

	return fd;
}

gchar *phonebook_set_folder(const gchar *current_folder,
		const gchar *new_folder, guint8 flags, int *err)
{
	gboolean root, child;
	gchar *tmp1, *tmp2, *base, *absolute, *relative = NULL;
	int ret, len, fd;

	root = (g_strcmp0("/", current_folder) == 0);
	child = (new_folder && strlen(new_folder) != 0);

	switch (flags) {
	case 0x02:
		/* Go back to root */
		if (!child) {
			relative = g_strdup("/");
			goto done;
		}

		relative = g_build_filename(current_folder, new_folder, NULL);
		break;
	case 0x03:
		/* Go up 1 level */
		if (root) {
			/* Already root */
			ret = -EBADR;
			goto done;
		}

		/*
		 * Removing one level of the current folder. Current folder
		 * contains AT LEAST one level since it is not at root folder.
		 * Use glib utility functions to handle invalid chars in the
		 * folder path properly.
		 */
		tmp1 = g_path_get_basename(current_folder);
		tmp2 = g_strrstr(current_folder, tmp1);
		len = tmp2 - (current_folder + 1);

		g_free(tmp1);

		if (len == 0)
			base = g_strdup("/");
		else
			base = g_strndup(current_folder, len);

		/* Return: one level only */
		if (!child) {
			relative = base;
			goto done;
		}

		relative = g_build_filename(base, new_folder, NULL);
		g_free(base);

		break;
	default:
		ret = -EBADR;
		break;
	}

done:
	if (!relative) {
		if (err)
			*err = ret;

		return NULL;
	}

	absolute = g_build_filename(root_folder, relative, NULL);
	fd = open_folder(absolute);
	if (fd < 0) {
		ret = -EBADR;
		g_free(relative);
		relative = NULL;
	} else {
		/* Keep the current folderfd open */
		if (folderfd >= 0)
			close(folderfd);

		folderfd = fd;
	}

	g_free(absolute);

	if (err)
		*err = ret;

	return relative;
}

int phonebook_pull(const gchar *name, const struct apparam_field *params,
					phonebook_cb cb, gpointer user_data)
{
	struct dummy_data *dummy;

	dummy = g_new0(struct dummy_data, 1);
	dummy->cb = cb;
	dummy->user_data = user_data;
	dummy->apparams = params;

	g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, dummy_result, dummy,
								dummy_free);
	return 0;
}

int phonebook_get_entry(const gchar *id, const struct apparam_field *params,
					phonebook_cb cb, gpointer user_data)
{
	struct dummy_data *dummy;
	int fd;

	if (folderfd < 0)
		return -EBADR;

	fd = openat(folderfd, id, 0);
	if (fd < 0) {
		int err = errno;
		debug("openat(): %s(%d)", strerror(err), err);
		return -EBADR;
	}

	dummy = g_new0(struct dummy_data, 1);
	dummy->cb = cb;
	dummy->user_data = user_data;
	dummy->apparams = params;
	dummy->fd = fd;

	g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, read_entry, dummy, dummy_free);

	return 0;
}

int phonebook_create_cache(const gchar *name, phonebook_entry_cb entry_cb,
		phonebook_cache_ready_cb ready_cb, gpointer user_data)
{
	struct cache_query *query;
	char *foldername;
	DIR *dp;

	foldername = g_build_filename(root_folder, name, NULL);
	dp = opendir(foldername);
	g_free(foldername);

	if (dp == NULL) {
		int err = errno;
		debug("opendir(): %s(%d)", strerror(err), err);
		return -EBADR;
	}

	query = g_new0(struct cache_query, 1);
	query->entry_cb = entry_cb;
	query->ready_cb = ready_cb;
	query->user_data = user_data;
	query->dp = dp;

	g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, create_cache, query,
								query_free);
	return 0;
}
