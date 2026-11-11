// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2009-2010  Intel Corporation
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
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
#include <libical/ical.h>
#include <libical/vobject.h>
#include <libical/vcc.h>

#include "obexd/src/log.h"
#include "phonebook.h"

typedef void (*vcard_func_t) (const char *file, VObject *vo, void *user_data);

struct dummy_data {
	phonebook_cb cb;
	void *user_data;
	const struct apparam_field *apparams;
	char *folder;
	int fd;
	guint id;
	uint8_t newmissedcalls;
};

struct cache_query {
	phonebook_entry_cb entry_cb;
	phonebook_cache_ready_cb ready_cb;
	void *user_data;
	DIR *dp;
	uint8_t newmissedcalls;
};

static char *root_folder = NULL;

static void dummy_free(void *user_data)
{
	struct dummy_data *dummy = user_data;

	if (dummy->fd >= 0)
		close(dummy->fd);

	g_free(dummy->folder);
	g_free(dummy);
}

static void query_free(void *user_data)
{
	struct cache_query *query = user_data;

	if (query->dp)
		closedir(query->dp);

	g_free(query);
}

int phonebook_driver_init(void)
{
	if (root_folder)
		return 0;

	/* FIXME: It should NOT be hard-coded */
	root_folder = g_build_filename(getenv("HOME"), "phonebook", NULL);

	return 0;
}

void phonebook_driver_exit(void)
{
	g_free(root_folder);
	root_folder = NULL;
}

static int handle_cmp(gconstpointer a, gconstpointer b)
{
	const char *f1 = a;
	const char *f2 = b;
	unsigned int i1, i2;

	if (sscanf(f1, "%u.vcf", &i1) != 1)
		return -1;

	if (sscanf(f2, "%u.vcf", &i2) != 1)
		return -1;

	return (i1 - i2);
}

static int foreach_vcard(DIR *dp, vcard_func_t func, uint16_t offset,
			uint16_t maxlistcount, void *user_data, uint16_t *count)
{
	struct dirent *ep;
	GSList *sorted = NULL, *l;
	VObject *v;
	FILE *fp;
	int err, fd, folderfd;
	uint16_t n = 0;

	folderfd = dirfd(dp);
	if (folderfd < 0) {
		err = errno;
		error("dirfd(): %s(%d)", strerror(err), err);
		return -err;
	}

	/*
	 * Sorting vcards by file name. versionsort is a GNU extension.
	 * The simple sorting function implemented on handle_cmp address
	 * vcards handle only(handle is always a number). This sort function
	 * doesn't address filename started by "0".
	 */
	while ((ep = readdir(dp))) {
		char *filename;

		if (ep->d_name[0] == '.')
			continue;

		filename = g_filename_to_utf8(ep->d_name, -1, NULL, NULL, NULL);
		if (filename == NULL) {
			error("g_filename_to_utf8: invalid filename");
			continue;
		}

		if (!g_str_has_suffix(filename, ".vcf")) {
			g_free(filename);
			continue;
		}

		sorted = g_slist_insert_sorted(sorted, filename, handle_cmp);
	}

	/*
	 * Filtering only the requested vCards attributes. Offset
	 * shall be based on the first entry of the phonebook.
	 */
	for (l = g_slist_nth(sorted, offset);
			l && n < maxlistcount; l = l->next) {
		const char *filename = l->data;

		fd = openat(folderfd, filename, O_RDONLY);
		if (fd < 0) {
			err = errno;
			error("openat(%s): %s(%d)", filename, strerror(err), err);
			continue;
		}

		fp = fdopen(fd, "r");
		if (fp == NULL) {
			err = errno;
			error("fdopen(%s): %s(%d)", filename, strerror(err),
									err);
			close(fd);
			continue;
		}

		v = Parse_MIME_FromFile(fp);
		if (v != NULL) {
			if (func)
				func(filename, v, user_data);

			deleteVObject(v);
			n++;
		}

		fclose(fp);
	}

	g_slist_free_full(sorted, g_free);

	if (count)
		*count = n;

	return 0;
}

struct concat_data {
	GString *buffer;
	const struct apparam_field *params;
};

static char *filter_vcard_photo(const char *buffer, size_t length,
					const struct apparam_field *params,
					size_t *filtered_length)
{
	GString *result;
	char *copy;
	char **lines;
	gboolean include = TRUE;
	unsigned int i;

	/* PHOTO is bit 3 of the PropertySelector. */
	if (!params->filter || (params->filter & (1ULL << 3))) {
		*filtered_length = length;
		return g_strndup(buffer, length);
	}

	copy = g_strndup(buffer, length);
	lines = g_strsplit(copy, "\n", -1);
	result = g_string_new(NULL);

	for (i = 0; lines[i]; i++) {
		char *line = lines[i];
		const char *end;
		const char *name;
		size_t len = strlen(line);

		if (len && line[len - 1] == '\r')
			line[len - 1] = '\0';

		/* Nothing follows the last line break. */
		if (!lines[i + 1] && !line[0])
			break;

		if (!include) {
			/*
			 * Folded lines, and the unfolded BASE64 lines and the
			 * terminating blank line of vCard 2.1, belong to the
			 * PHOTO value.
			 */
			if (!line[0]) {
				include = TRUE;
				continue;
			}

			if (line[0] == ' ' || line[0] == '\t' ||
						!strchr(line, ':'))
				continue;
		}

		if (line[0] != ' ' && line[0] != '\t') {
			end = strpbrk(line, ";:");
			name = end ? memrchr(line, '.', end - line) : NULL;
			name = name ? name + 1 : line;
			include = !end || end - name != 5 ||
				g_ascii_strncasecmp(name, "PHOTO", 5) != 0;
		}

		if (include)
			g_string_append_printf(result, "%s\r\n", line);
	}

	g_strfreev(lines);
	g_free(copy);

	*filtered_length = result->len;
	return g_string_free(result, FALSE);
}

static void entry_concat(const char *filename, VObject *v, void *user_data)
{
	struct concat_data *data = user_data;
	char *filtered;
	char tmp[1024];
	size_t filtered_len;
	int len;

	/*
	 * VObject API uses len for IN and OUT
	 * Written bytes is also returned in the len variable
	 */
	len = sizeof(tmp);
	memset(tmp, 0, len);

	writeMemVObject(tmp, &len, v);
	filtered = filter_vcard_photo(tmp, len, data->params,
						&filtered_len);

	g_string_append_len(data->buffer, filtered, filtered_len);
	g_free(filtered);
}

static gboolean read_dir(void *user_data)
{
	struct dummy_data *dummy = user_data;
	struct concat_data data;
	DIR *dp;
	uint16_t count = 0, max, offset;

	data.buffer = g_string_new("");
	data.params = dummy->apparams;

	dp = opendir(dummy->folder);
	if (dp == NULL) {
		int err = errno;
		DBG("opendir(): %s(%d)", strerror(err), err);
		goto done;
	}

	/*
	 * For PullPhoneBook function, the decision of returning the size
	 * or contacts is made in the PBAP core. When MaxListCount is ZERO,
	 * PCE wants to know the size of a given folder, PSE shall ignore all
	 * other applicattion parameters that may be present in the request.
	 */
	if (dummy->apparams->maxlistcount == 0) {
		max = 0xffff;
		offset = 0;
	} else {
		max = dummy->apparams->maxlistcount;
		offset = dummy->apparams->liststartoffset;
	}

	foreach_vcard(dp, entry_concat, offset, max, &data, &count);

	closedir(dp);
done:
	/* FIXME: Missing vCards fields filtering */
	dummy->cb(data.buffer->str, data.buffer->len, count,
			dummy->newmissedcalls, TRUE, dummy->user_data);

	g_string_free(data.buffer, TRUE);

	return FALSE;
}

static void entry_notify(const char *filename, VObject *v, void *user_data)
{
	struct cache_query *query = user_data;
	VObject *property, *subproperty;
	GString *name;
	const char *tel;
	long unsigned int handle;

	property = isAPropertyOf(v, VCNameProp);
	if (!property)
		return;

	if (sscanf(filename, "%lu.vcf", &handle) != 1)
		return;

	if (handle > UINT32_MAX)
		return;

	/* LastName; FirstName; MiddleName; Prefix; Suffix */

	name = g_string_new("");
	subproperty = isAPropertyOf(property, VCFamilyNameProp);
	if (subproperty) {
		g_string_append(name,
				fakeCString(vObjectUStringZValue(subproperty)));
	}

	subproperty = isAPropertyOf(property, VCGivenNameProp);
	if (subproperty)
		g_string_append_printf(name, ";%s",
				fakeCString(vObjectUStringZValue(subproperty)));

	subproperty = isAPropertyOf(property, VCAdditionalNamesProp);
	if (subproperty)
		g_string_append_printf(name, ";%s",
				fakeCString(vObjectUStringZValue(subproperty)));

	subproperty = isAPropertyOf(property, VCNamePrefixesProp);
	if (subproperty)
		g_string_append_printf(name, ";%s",
				fakeCString(vObjectUStringZValue(subproperty)));


	subproperty = isAPropertyOf(property, VCNameSuffixesProp);
	if (subproperty)
		g_string_append_printf(name, ";%s",
				fakeCString(vObjectUStringZValue(subproperty)));

	property = isAPropertyOf(v, VCTelephoneProp);

	tel = property ? fakeCString(vObjectUStringZValue(property)) : NULL;

	query->entry_cb(filename, handle, name->str, NULL, tel,
							query->user_data);
	g_string_free(name, TRUE);
}

static gboolean create_cache(void *user_data)
{
	struct cache_query *query = user_data;

	/*
	 * MaxListCount and ListStartOffset shall not be used
	 * when creating the cache. All entries shall be fetched.
	 * PBAP core is responsible for consider these application
	 * parameters before reply the entries.
	 */
	foreach_vcard(query->dp, entry_notify, 0, 0xffff, query, NULL);

	query->ready_cb(query->newmissedcalls, query->user_data);

	return FALSE;
}

static gboolean read_entry(void *user_data)
{
	struct dummy_data *dummy = user_data;
	char *filtered;
	char buffer[1024];
	size_t filtered_len;
	ssize_t count;

	memset(buffer, 0, sizeof(buffer));
	count = read(dummy->fd, buffer, sizeof(buffer));

	if (count < 0) {
		int err = errno;
		error("read(): %s(%d)", strerror(err), err);
		count = 0;
	}

	filtered = filter_vcard_photo(buffer, count, dummy->apparams,
							&filtered_len);
	dummy->cb(filtered, filtered_len, 1, 0, TRUE, dummy->user_data);
	g_free(filtered);

	return FALSE;
}

static gboolean is_dir(const char *dir)
{
	struct stat st;

	if (stat(dir, &st) < 0) {
		int err = errno;
		error("stat(%s): %s (%d)", dir, strerror(err), err);
		return FALSE;
	}

	return S_ISDIR(st.st_mode);
}

static uint8_t count_vcards(const char *folder)
{
	DIR *dp;
	uint16_t count = 0;

	dp = opendir(folder);
	if (dp == NULL)
		return 0;

	foreach_vcard(dp, NULL, 0, UINT8_MAX, NULL, &count);

	closedir(dp);

	return count;
}

char *phonebook_set_folder(const char *current_folder,
		const char *new_folder, uint8_t flags, int *err)
{
	gboolean root, child;
	char *tmp1, *tmp2, *base, *absolute, *relative = NULL;
	int len, ret = 0;

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
	if (!is_dir(absolute)) {
		g_free(relative);
		relative = NULL;
		ret = -ENOENT;
	}

	g_free(absolute);

	if (err)
		*err = ret;

	return relative;
}

void phonebook_req_finalize(void *request)
{
	struct dummy_data *dummy = request;

	/* dummy_data will be cleaned when request will be finished via
	 * g_source_remove */
	if (dummy && dummy->id)
		g_source_remove(dummy->id);
}

void *phonebook_pull(const char *name, const struct apparam_field *params,
				phonebook_cb cb, void *user_data, int *err)
{
	struct dummy_data *dummy;
	char *filename, *folder;

	/*
	 * Main phonebook objects will be created dynamically based on the
	 * folder content. All vcards inside the given folder will be appended
	 * in the "virtual" main phonebook object.
	 */

	filename = g_build_filename(root_folder, name, NULL);

	if (!g_str_has_suffix(filename, ".vcf")) {
		g_free(filename);
		if (err)
			*err = -EBADR;
		return NULL;
	}

	folder = g_strndup(filename, strlen(filename) - 4);
	g_free(filename);
	if (!is_dir(folder)) {
		g_free(folder);
		if (err)
			*err = -ENOENT;
		return NULL;
	}

	dummy = g_new0(struct dummy_data, 1);
	dummy->cb = cb;
	dummy->user_data = user_data;
	dummy->apparams = params;
	dummy->folder = folder;
	dummy->fd = -1;

	if (g_strcmp0(name, PB_CALLS_MISSED) == 0)
		dummy->newmissedcalls = count_vcards(folder);

	if (err)
		*err = 0;

	return dummy;
}

int phonebook_pull_read(void *request)
{
	struct dummy_data *dummy = request;

	if (!dummy)
		return -ENOENT;

	dummy->id = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, read_dir, dummy,
								dummy_free);

	return 0;
}

void *phonebook_get_entry(const char *folder, const char *id,
			const struct apparam_field *params, phonebook_cb cb,
			void *user_data, int *err)
{
	struct dummy_data *dummy;
	char *filename;
	int fd;

	filename = g_build_filename(root_folder, folder, id, NULL);

	fd = open(filename, O_RDONLY);

	g_free(filename);

	if (fd < 0) {
		DBG("open(): %s(%d)", strerror(errno), errno);
		if (err)
			*err = -ENOENT;
		return NULL;
	}

	dummy = g_new0(struct dummy_data, 1);
	dummy->cb = cb;
	dummy->user_data = user_data;
	dummy->apparams = params;
	dummy->fd = fd;

	dummy->id = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, read_entry, dummy,
								dummy_free);

	if (err)
		*err = 0;

	return dummy;
}

void *phonebook_create_cache(const char *name, phonebook_entry_cb entry_cb,
		phonebook_cache_ready_cb ready_cb, void *user_data, int *err)
{
	struct cache_query *query;
	char *foldername;
	DIR *dp;
	struct dummy_data *dummy;

	foldername = g_build_filename(root_folder, name, NULL);
	dp = opendir(foldername);
	g_free(foldername);

	if (dp == NULL) {
		DBG("opendir(): %s(%d)", strerror(errno), errno);
		if (err)
			*err = -ENOENT;
		return NULL;
	}

	query = g_new0(struct cache_query, 1);
	query->entry_cb = entry_cb;
	query->ready_cb = ready_cb;
	query->user_data = user_data;
	query->dp = dp;

	if (g_str_equal(name, PB_CALLS_MISSED_FOLDER)) {
		foldername = g_build_filename(root_folder,
						PB_CALLS_MISSED_FOLDER, NULL);
		query->newmissedcalls = count_vcards(foldername);
		g_free(foldername);
	}

	dummy = g_new0(struct dummy_data, 1);

	dummy->id = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, create_cache,
							query, query_free);

	if (err)
		*err = 0;

	return dummy;
}
