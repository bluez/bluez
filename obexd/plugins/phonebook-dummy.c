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
#include "phonebook-metadata.h"

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

struct digest_data {
	GChecksum *primary;
	GChecksum *secondary;
	char *path;
};

static char *root_folder = NULL;

static gboolean vobject_value_present(VObject *prop)
{
	const char *str;
	const wchar_t *ustr;
	VObject *size;

	switch (vObjectValueType(prop)) {
	case VCVT_STRINGZ:
		str = vObjectStringZValue(prop);
		return str && str[0];
	case VCVT_USTRINGZ:
		ustr = vObjectUStringZValue(prop);
		return ustr && uStrLen(ustr) > 0;
	case VCVT_UINT:
	case VCVT_ULONG:
		return TRUE;
	case VCVT_RAW:
		if (!vObjectAnyValue(prop))
			return FALSE;

		size = isAPropertyOf(prop, VCDataSizeProp);
		if (!size)
			return FALSE;

		switch (vObjectValueType(size)) {
		case VCVT_UINT:
			return vObjectIntegerValue(size) > 0;
		case VCVT_ULONG:
			return vObjectLongValue(size) > 0;
		default:
			return FALSE;
		}
	case VCVT_VOBJECT:
		return vObjectVObjectValue(prop) != NULL;
	default:
		return FALSE;
	}
}

static gboolean vcard_property_present(VObject *v, const char *name)
{
	static const char * const name_fields[] = {
		VCFamilyNameProp, VCGivenNameProp, VCAdditionalNamesProp,
		VCNamePrefixesProp, VCNameSuffixesProp, NULL
	};
	static const char * const address_fields[] = {
		VCPostalBoxProp, VCExtAddressProp, VCStreetAddressProp,
		VCCityProp, VCRegionProp, VCPostalCodeProp, VCCountryNameProp,
		NULL
	};
	static const char * const org_fields[] = {
		VCOrgNameProp, VCOrgUnitProp, VCOrgUnit2Prop, VCOrgUnit3Prop,
		VCOrgUnit4Prop, NULL
	};
	const char * const *fields = NULL;
	VObjectIterator iterator;
	VObject *prop;
	unsigned int i;

	if (!g_ascii_strcasecmp(name, VCNameProp))
		fields = name_fields;
	else if (!g_ascii_strcasecmp(name, VCAdrProp))
		fields = address_fields;
	else if (!g_ascii_strcasecmp(name, VCOrgProp))
		fields = org_fields;

	initPropIterator(&iterator, v);

	while (moreIteration(&iterator)) {
		prop = nextVObject(&iterator);

		if (g_ascii_strcasecmp(vObjectName(prop), name))
			continue;

		if (vobject_value_present(prop))
			return TRUE;

		for (i = 0; fields && fields[i]; i++) {
			VObject *field = isAPropertyOf(prop, fields[i]);

			if (field && vobject_value_present(field))
				return TRUE;
		}
	}

	return FALSE;
}

static uint64_t vcard_presence_mask(VObject *v)
{
	uint64_t mask = 0;
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(phonebook_selector_properties); i++) {
		const char *property = phonebook_selector_properties[i];

		if (property && vcard_property_present(v, property))
			mask |= (1ULL << i);
	}

	return mask;
}

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

static gboolean phonebook_compute_folder_digest(const char *folder,
						uint8_t primary_digest[16],
						uint8_t secondary_digest[16]);

static const char * const version_folders[] = {
	PB_CONTACTS_FOLDER,
	PB_CALLS_COMBINED_FOLDER,
	PB_CALLS_INCOMING_FOLDER,
	PB_CALLS_MISSED_FOLDER,
	PB_CALLS_OUTGOING_FOLDER,
	PB_CALLS_SPEEDDIAL_FOLDER,
	PB_CALLS_FAVORITE_FOLDER,
	NULL,
};

static gboolean folder_has_version(const char *folder)
{
	unsigned int i;

	for (i = 0; version_folders[i]; i++) {
		if (g_str_equal(folder, version_folders[i]))
			return TRUE;
	}

	return FALSE;
}

static void dummy_metadata_init(void)
{
	static const uint8_t zeros[16] = {0};
	uint8_t primary[16], secondary[16];
	int i;

	metadata_identifier_update();

	for (i = 0; version_folders[i]; i++) {
		const char *folder = version_folders[i];

		if (phonebook_compute_folder_digest(folder, primary,
					secondary)) {
			metadata_set(folder, "primary_digest", primary);
			metadata_set(folder, "secondary_digest", secondary);
		}

		metadata_set(folder, PRIMARY_COUNTER, zeros);
		metadata_set(folder, SECONDARY_COUNTER, zeros);
	}

	metadata_save();
}

int phonebook_driver_init(void)
{
	char *metadata_path;
	uint8_t id[16];

	if (root_folder)
		return 0;

	/* FIXME: It should NOT be hard-coded */
	root_folder = g_build_filename(getenv("HOME"), "phonebook", NULL);

	metadata_path = g_build_filename(root_folder,
					"phonebook-metadata", NULL);

	if (!metadata_file_open(metadata_path)) {
		g_free(metadata_path);
		return 0;
	}

	g_free(metadata_path);

	if (!metadata_get("identifier", "value", id))
		dummy_metadata_init();

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

static char *vobject_get_string(VObject *prop)
{
	switch (vObjectValueType(prop)) {
	case VCVT_STRINGZ:
		return g_strdup(vObjectStringZValue(prop));
	case VCVT_USTRINGZ:
		return fakeCString(vObjectUStringZValue(prop));
	default:
		return NULL;
	}
}

static void digest_entry(const char *filename, VObject *v, void *user_data)
{
	struct digest_data *data = user_data;
	VObjectIterator iterator, sub_iterator;
	VObject *prop, *subprop;
	char *entry;
	char *contents;
	char *str;
	gsize len;

	/* The primary digest covers the file name and the whole contents. */
	g_checksum_update(data->primary, (const guchar *) filename,
							strlen(filename));
	g_checksum_update(data->primary, (const guchar *) "\0", 1);

	entry = g_build_filename(data->path, filename, NULL);

	if (g_file_get_contents(entry, &contents, &len, NULL)) {
		g_checksum_update(data->primary,
					(const guchar *) contents, len);
		g_free(contents);
	}

	g_free(entry);

	g_checksum_update(data->primary, (const guchar *) "\0", 1);

	/*
	 * The secondary digest covers the file name and the properties
	 * tracked by the secondary counter.
	 */
	g_checksum_update(data->secondary, (const guchar *) filename,
							strlen(filename));
	g_checksum_update(data->secondary, (const guchar *) "\0", 1);

	initPropIterator(&iterator, v);

	while (moreIteration(&iterator)) {
		prop = nextVObject(&iterator);

		if (g_ascii_strcasecmp(vObjectName(prop), VCNameProp) &&
				g_ascii_strcasecmp(vObjectName(prop),
							VCFullNameProp) &&
				g_ascii_strcasecmp(vObjectName(prop),
							VCTelephoneProp) &&
				g_ascii_strcasecmp(vObjectName(prop),
							VCEmailAddressProp) &&
				g_ascii_strcasecmp(vObjectName(prop),
							VCMailerProp) &&
				g_ascii_strcasecmp(vObjectName(prop),
							VCAdrProp) &&
				g_ascii_strcasecmp(vObjectName(prop),
							"X-BT-UCI"))
			continue;

		g_checksum_update(data->secondary,
					(const guchar *) vObjectName(prop),
					strlen(vObjectName(prop)));
		g_checksum_update(data->secondary, (const guchar *) "\0", 1);

		str = vobject_get_string(prop);
		if (str) {
			g_checksum_update(data->secondary,
					(const guchar *) str, strlen(str));
			g_free(str);
			g_checksum_update(data->secondary,
					(const guchar *) "\0", 1);
		}

		/* Property components and parameters are included. */
		initPropIterator(&sub_iterator, prop);

		while (moreIteration(&sub_iterator)) {
			subprop = nextVObject(&sub_iterator);

			g_checksum_update(data->secondary,
					(const guchar *) vObjectName(subprop),
					strlen(vObjectName(subprop)));
			g_checksum_update(data->secondary,
					(const guchar *) "\0", 1);

			str = vobject_get_string(subprop);
			if (str) {
				g_checksum_update(data->secondary,
						(const guchar *) str,
						strlen(str));
				g_free(str);
				g_checksum_update(data->secondary,
						(const guchar *) "\0", 1);
			}
		}
	}
}

/* Computes the digests used to detect changes of a folder's contents. */
static gboolean phonebook_compute_folder_digest(const char *folder,
						uint8_t primary_digest[16],
						uint8_t secondary_digest[16])
{
	struct digest_data digest;
	DIR *dp;
	char *path;
	gsize len = g_checksum_type_get_length(G_CHECKSUM_MD5);

	path = g_build_filename(root_folder, folder, NULL);

	dp = opendir(path);
	if (!dp) {
		g_free(path);
		return FALSE;
	}

	digest.primary = g_checksum_new(G_CHECKSUM_MD5);
	digest.secondary = g_checksum_new(G_CHECKSUM_MD5);
	digest.path = path;

	/* Entries beyond 65535 are not covered by the digest */
	foreach_vcard(dp, digest_entry, 0, 0xffff, &digest, NULL);

	closedir(dp);
	g_free(path);

	g_checksum_get_digest(digest.primary, primary_digest, &len);
	g_checksum_get_digest(digest.secondary, secondary_digest, &len);

	g_checksum_free(digest.primary);
	g_checksum_free(digest.secondary);

	return TRUE;
}

static void dummy_update_folder_version(const char *folder)
{
	uint8_t primary[16], secondary[16];
	uint8_t stored_primary[16], stored_secondary[16];
	uint8_t counter[16];
	gboolean primary_changed, secondary_changed;

	/* Retries a previously failed save. */
	metadata_save();

	if (!folder_has_version(folder))
		return;

	if (!phonebook_compute_folder_digest(folder, primary, secondary))
		return;

	/* Missing counters restart with a new Database Identifier. */
	if (!metadata_get(folder, PRIMARY_COUNTER, counter) ||
			!metadata_get(folder, SECONDARY_COUNTER, counter)) {
		dummy_metadata_init();
		return;
	}

	/* A missing or unreadable digest counts as a change. */
	primary_changed = !metadata_get(folder, "primary_digest",
					stored_primary) ||
			memcmp(primary, stored_primary, 16) != 0;
	secondary_changed = !metadata_get(folder, "secondary_digest",
					stored_secondary) ||
			memcmp(secondary, stored_secondary, 16) != 0;

	if (!primary_changed && !secondary_changed)
		return;

	if (!metadata_folder_version_counter_incr(folder, primary_changed,
							secondary_changed)) {
		dummy_metadata_init();
		return;
	}

	metadata_set(folder, "primary_digest", primary);
	metadata_set(folder, "secondary_digest", secondary);
	metadata_save();
}

struct concat_data {
	GString *buffer;
	const struct apparam_field *params;
	uint16_t offset;
	uint16_t max;
	uint16_t count;
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
	lines = g_strsplit_set(copy, "\r\n", -1);
	result = g_string_new(NULL);

	for (i = 0; lines[i]; i++) {
		const char *line = lines[i];
		const char *end;
		const char *name;

		if (!line[0])
			continue;

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

	if (!phonebook_selector_match(vcard_presence_mask(v),
					data->params->selector,
					data->params->selector_operator))
		return;

	data->count++;

	/*
	 * Offset and MaxListCount apply to the vCards matching the
	 * vCardSelector.
	 */
	if (data->count <= data->offset)
		return;

	if (data->count - data->offset > data->max)
		return;

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
	struct concat_data data = { 0 };
	DIR *dp;

	data.buffer = g_string_new("");
	data.params = dummy->apparams;

	/*
	 * For PullPhoneBook function, the decision of returning the size
	 * or contacts is made in the PBAP core. When MaxListCount is ZERO,
	 * PCE wants to know the size of a given folder, PSE shall ignore all
	 * other application parameters that may be present in the request,
	 * except the vCardSelector and vCardSelectorOperator, which still
	 * apply to the returned size.
	 */
	if (dummy->apparams->maxlistcount == 0)
		data.max = 0xffff;
	else {
		data.max = dummy->apparams->maxlistcount;
		data.offset = dummy->apparams->liststartoffset;
	}

	dp = opendir(dummy->folder);
	if (dp == NULL) {
		int err = errno;

		DBG("opendir(): %s(%d)", strerror(err), err);

		goto done;
	}

	foreach_vcard(dp, entry_concat, 0, 0xffff, &data, NULL);

	closedir(dp);
done:
	/* FIXME: Missing vCards fields filtering */
	dummy->cb(data.buffer->str, data.buffer->len, data.count,
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
	uint64_t mask;
	long unsigned int handle;

	property = isAPropertyOf(v, VCNameProp);
	if (!property)
		return;

	if (sscanf(filename, "%lu.vcf", &handle) != 1)
		return;

	if (handle > UINT32_MAX)
		return;

	mask = vcard_presence_mask(v);

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

	query->entry_cb(filename, handle, name->str, NULL, tel, mask,
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

	folder = g_strndup(name, strlen(name) - 4);

	dummy_update_folder_version(folder);
	g_free(folder);

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

	dummy_update_folder_version(folder);

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

	dummy_update_folder_version(name);

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
