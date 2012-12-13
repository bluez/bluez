/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/uuid.h>

#include "textfile.h"
#include "glib-helper.h"
#include "storage.h"

/* When all services should trust a remote device */
#define GLOBAL_TRUST "[all]"

struct match {
	GSList *keys;
	char *pattern;
};

static inline int create_filename(char *buf, size_t size,
				const bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}

int read_discoverable_timeout(const char *src, int *timeout)
{
	char filename[PATH_MAX + 1], *str;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "config");

	str = textfile_get(filename, "discovto");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%d", timeout) != 1) {
		free(str);
		return -ENOENT;
	}

	free(str);

	return 0;
}

int read_pairable_timeout(const char *src, int *timeout)
{
	char filename[PATH_MAX + 1], *str;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "config");

	str = textfile_get(filename, "pairto");
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%d", timeout) != 1) {
		free(str);
		return -ENOENT;
	}

	free(str);

	return 0;
}

int read_on_mode(const char *src, char *mode, int length)
{
	char filename[PATH_MAX + 1], *str;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "config");

	str = textfile_get(filename, "onmode");
	if (!str)
		return -ENOENT;

	strncpy(mode, str, length);
	mode[length - 1] = '\0';

	free(str);

	return 0;
}

int read_local_name(const bdaddr_t *bdaddr, char *name)
{
	char filename[PATH_MAX + 1], *str;
	int len;

	create_filename(filename, PATH_MAX, bdaddr, "config");

	str = textfile_get(filename, "name");
	if (!str)
		return -ENOENT;

	len = strlen(str);
	if (len > HCI_MAX_NAME_LENGTH)
		str[HCI_MAX_NAME_LENGTH] = '\0';
	strcpy(name, str);

	free(str);

	return 0;
}

int read_local_class(const bdaddr_t *bdaddr, uint8_t *class)
{
	char filename[PATH_MAX + 1], tmp[3], *str;
	int i;

	create_filename(filename, PATH_MAX, bdaddr, "config");

	str = textfile_get(filename, "class");
	if (!str)
		return -ENOENT;

	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < 3; i++) {
		memcpy(tmp, str + (i * 2) + 2, 2);
		class[2 - i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	free(str);

	return 0;
}

int read_remote_appearance(const bdaddr_t *local, const bdaddr_t *peer,
				uint8_t bdaddr_type, uint16_t *appearance)
{
	char filename[PATH_MAX + 1], key[20], *str;

	create_filename(filename, PATH_MAX, local, "appearances");

	ba2str(peer, key);
	sprintf(&key[17], "#%hhu", bdaddr_type);

	str = textfile_get(filename, key);
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%hx", appearance) != 1) {
		free(str);
		return -ENOENT;
	}

	free(str);

	return 0;
}

int write_remote_appearance(const bdaddr_t *local, const bdaddr_t *peer,
				uint8_t bdaddr_type, uint16_t appearance)
{
	char filename[PATH_MAX + 1], key[20], str[7];

	create_filename(filename, PATH_MAX, local, "appearances");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, key);
	sprintf(&key[17], "#%hhu", bdaddr_type);

	sprintf(str, "0x%4.4x", appearance);

	return textfile_put(filename, key, str);
}

int write_lastused_info(const bdaddr_t *local, const bdaddr_t *peer,
					uint8_t peer_type, struct tm *tm)
{
	char filename[PATH_MAX + 1], key[20], str[24];

	memset(str, 0, sizeof(str));
	strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S %Z", tm);

	create_filename(filename, PATH_MAX, local, "lastused");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, key);
	sprintf(&key[17], "#%hhu", peer_type);

	return textfile_put(filename, key, str);
}

ssize_t read_pin_code(const bdaddr_t *local, const bdaddr_t *peer, char *pin)
{
	char filename[PATH_MAX + 1], addr[18], *str;
	ssize_t len;

	create_filename(filename, PATH_MAX, local, "pincodes");

	ba2str(peer, addr);
	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	strncpy(pin, str, 16);
	len = strlen(pin);

	free(str);

	return len;
}

int write_device_profiles(const bdaddr_t *src, const bdaddr_t *dst,
					uint8_t dst_type, const char *profiles)
{
	char filename[PATH_MAX + 1], key[20];

	if (!profiles)
		return -EINVAL;

	create_filename(filename, PATH_MAX, src, "profiles");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dst, key);
	sprintf(&key[17], "#%hhu", dst_type);

	return textfile_put(filename, key, profiles);
}

int delete_entry(const bdaddr_t *src, const char *storage, const bdaddr_t *dst,
							uint8_t dst_type)
{
	char filename[PATH_MAX + 1], key[20];
	int err, ret;

	ba2str(dst, key);
	sprintf(&key[17], "#%hhu", dst_type);

	create_filename(filename, PATH_MAX, src, storage);

	err = 0;
	ret = textfile_del(filename, key);
	if (ret)
		err = ret;

	/* Trying without address type */
	key[17] = '\0';
	ret = textfile_del(filename, key);
	if (ret)
		err = ret;

	return err;
}

int store_record(const gchar *src, const gchar *dst, uint8_t dst_type,
							sdp_record_t *rec)
{
	char filename[PATH_MAX + 1], key[30];
	sdp_buf_t buf;
	int err, size, i;
	char *str;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	snprintf(key, sizeof(key), "%17s#%hhu#%08X", dst, dst_type,
								rec->handle);

	if (sdp_gen_record_pdu(rec, &buf) < 0)
		return -1;

	size = buf.data_size;

	str = g_malloc0(size*2+1);

	for (i = 0; i < size; i++)
		sprintf(str + (i * 2), "%02X", buf.data[i]);

	err = textfile_put(filename, key, str);

	free(buf.data);
	g_free(str);

	return err;
}

sdp_record_t *record_from_string(const gchar *str)
{
	sdp_record_t *rec;
	int size, i, len;
	uint8_t *pdata;
	char tmp[3];

	size = strlen(str)/2;
	pdata = g_malloc0(size);

	tmp[2] = 0;
	for (i = 0; i < size; i++) {
		memcpy(tmp, str + (i * 2), 2);
		pdata[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	rec = sdp_extract_pdu(pdata, size, &len);
	g_free(pdata);

	return rec;
}


sdp_record_t *fetch_record(const gchar *src, const gchar *dst,
			   uint8_t dst_type, const uint32_t handle)
{
	char filename[PATH_MAX + 1], old_key[28], key[30], *str;
	sdp_record_t *rec;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");

	snprintf(key, sizeof(key), "%17s#%hhu#%08X", dst, dst_type, handle);
	snprintf(old_key, sizeof(old_key), "%17s#%08X", dst, handle);

	str = textfile_get(filename, key);
	if (str != NULL)
		goto done;

	/* Try old format (address#handle) */
	str = textfile_get(filename, old_key);
	if (str == NULL)
		return NULL;

done:
	rec = record_from_string(str);
	free(str);

	return rec;
}

int delete_record(const gchar *src, const gchar *dst, uint8_t dst_type,
							const uint32_t handle)
{
	char filename[PATH_MAX + 1], old_key[28], key[30];
	int err, ret;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");

	snprintf(key, sizeof(key), "%17s#%hhu#%08X", dst, dst_type, handle);
	snprintf(old_key, sizeof(old_key), "%17s#%08X", dst, handle);

	err = 0;
	ret = textfile_del(filename, key);
	if (ret)
		err = ret;

	/* Try old format (address#handle) */
	ret = textfile_del(filename, old_key);
	if (ret)
		err = ret;

	return err;
}

struct record_list {
	sdp_list_t *recs;
	const gchar *addr;
};

static void create_stored_records_from_keys(char *key, char *value,
							void *user_data)
{
	struct record_list *rec_list = user_data;
	const gchar *addr = rec_list->addr;
	sdp_record_t *rec;

	if (strncmp(key, addr, 17))
		return;

	rec = record_from_string(value);

	rec_list->recs = sdp_list_append(rec_list->recs, rec);
}

void delete_all_records(const bdaddr_t *src, const bdaddr_t *dst,
							uint8_t dst_type)
{
	sdp_list_t *records, *seq;
	char srcaddr[18], dstaddr[18];

	ba2str(src, srcaddr);
	ba2str(dst, dstaddr);

	records = read_records(src, dst);

	for (seq = records; seq; seq = seq->next) {
		sdp_record_t *rec = seq->data;
		delete_record(srcaddr, dstaddr, dst_type, rec->handle);
	}

	if (records)
		sdp_list_free(records, (sdp_free_func_t) sdp_record_free);
}

sdp_list_t *read_records(const bdaddr_t *src, const bdaddr_t *dst)
{
	char filename[PATH_MAX + 1];
	struct record_list rec_list;
	char srcaddr[18], dstaddr[18];

	ba2str(src, srcaddr);
	ba2str(dst, dstaddr);

	rec_list.addr = dstaddr;
	rec_list.recs = NULL;

	create_name(filename, PATH_MAX, STORAGEDIR, srcaddr, "sdp");
	textfile_foreach(filename, create_stored_records_from_keys, &rec_list);

	return rec_list.recs;
}

sdp_record_t *find_record_in_list(sdp_list_t *recs, const char *uuid)
{
	sdp_list_t *seq;

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_list_t *svcclass = NULL;
		char *uuid_str;

		if (sdp_get_service_classes(rec, &svcclass) < 0)
			continue;

		/* Extract the uuid */
		uuid_str = bt_uuid2string(svcclass->data);
		if (!uuid_str)
			continue;

		if (!strcasecmp(uuid_str, uuid)) {
			sdp_list_free(svcclass, free);
			free(uuid_str);
			return rec;
		}

		sdp_list_free(svcclass, free);
		free(uuid_str);
	}
	return NULL;
}

int read_device_pairable(const bdaddr_t *bdaddr, gboolean *mode)
{
	char filename[PATH_MAX + 1], *str;

	create_filename(filename, PATH_MAX, bdaddr, "config");

	str = textfile_get(filename, "pairable");
	if (!str)
		return -ENOENT;

	*mode = strcmp(str, "yes") == 0 ? TRUE : FALSE;

	free(str);

	return 0;
}

int write_device_services(const bdaddr_t *sba, const bdaddr_t *dba,
			  uint8_t bdaddr_type, const char *services)
{
	char filename[PATH_MAX + 1], key[20];

	create_filename(filename, PATH_MAX, sba, "primaries");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dba, key);
	sprintf(&key[17], "#%hhu", bdaddr_type);

	return textfile_put(filename, key, services);
}

static void filter_keys(char *key, char *value, void *data)
{
	struct match *match = data;

	if (strncasecmp(key, match->pattern, strlen(match->pattern)) == 0)
		match->keys = g_slist_append(match->keys, g_strdup(key));
}

static void delete_by_pattern(const char *filename, char *pattern)
{
	struct match match;
	GSList *l;
	int err;

	memset(&match, 0, sizeof(match));
	match.pattern = pattern;

	err = textfile_foreach(filename, filter_keys, &match);
	if (err < 0)
		goto done;

	for (l = match.keys; l; l = l->next) {
		const char *key = l->data;
		textfile_del(filename, key);
	}

done:
	g_slist_free_full(match.keys, g_free);
}

int delete_device_service(const bdaddr_t *sba, const bdaddr_t *dba,
						uint8_t bdaddr_type)
{
	char filename[PATH_MAX + 1], key[20];

	memset(key, 0, sizeof(key));

	ba2str(dba, key);
	sprintf(&key[17], "#%hhu", bdaddr_type);

	/* Deleting all characteristics of a given key */
	create_filename(filename, PATH_MAX, sba, "characteristics");
	delete_by_pattern(filename, key);

	/* Deleting all attributes values of a given key */
	create_filename(filename, PATH_MAX, sba, "attributes");
	delete_by_pattern(filename, key);

	/* Deleting all CCC values of a given key */
	create_filename(filename, PATH_MAX, sba, "ccc");
	delete_by_pattern(filename, key);

	create_filename(filename, PATH_MAX, sba, "primaries");

	return textfile_del(filename, key);
}

char *read_device_services(const bdaddr_t *sba, const bdaddr_t *dba,
							uint8_t bdaddr_type)
{
	char filename[PATH_MAX + 1], key[20];

	create_filename(filename, PATH_MAX, sba, "primaries");

	ba2str(dba, key);
	sprintf(&key[17], "#%hhu", bdaddr_type);

	return textfile_caseget(filename, key);
}

int write_device_characteristics(const bdaddr_t *sba, const bdaddr_t *dba,
					uint8_t bdaddr_type, uint16_t handle,
							      const char *chars)
{
	char filename[PATH_MAX + 1], addr[18], key[25];

	create_filename(filename, PATH_MAX, sba, "characteristics");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dba, addr);
	snprintf(key, sizeof(key), "%17s#%hhu#%04X", addr, bdaddr_type, handle);

	return textfile_put(filename, key, chars);
}

char *read_device_characteristics(const bdaddr_t *sba, const bdaddr_t *dba,
					uint8_t bdaddr_type, uint16_t handle)
{
	char filename[PATH_MAX + 1], addr[18], key[25];

	create_filename(filename, PATH_MAX, sba, "characteristics");

	ba2str(dba, addr);
	snprintf(key, sizeof(key), "%17s#%hhu#%04X", addr, bdaddr_type, handle);

	return textfile_caseget(filename, key);
}

int write_device_attribute(const bdaddr_t *sba, const bdaddr_t *dba,
				uint8_t bdaddr_type, uint16_t handle,
							const char *chars)
{
	char filename[PATH_MAX + 1], addr[18], key[25];

	create_filename(filename, PATH_MAX, sba, "attributes");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dba, addr);
	snprintf(key, sizeof(key), "%17s#%hhu#%04X", addr, bdaddr_type, handle);

	return textfile_put(filename, key, chars);
}

int read_device_attributes(const bdaddr_t *sba, textfile_cb func, void *data)
{
	char filename[PATH_MAX + 1];

	create_filename(filename, PATH_MAX, sba, "attributes");

	return textfile_foreach(filename, func, data);
}

int read_device_ccc(const bdaddr_t *local, const bdaddr_t *peer,
					uint8_t bdaddr_type, uint16_t handle,
					uint16_t *value)
{
	char filename[PATH_MAX + 1], addr[18], key[25];
	char *str;
	unsigned int config;
	int err = 0;

	create_filename(filename, PATH_MAX, local, "ccc");

	ba2str(peer, addr);
	snprintf(key, sizeof(key), "%17s#%hhu#%04X", addr, bdaddr_type, handle);

	str = textfile_caseget(filename, key);
	if (str == NULL)
		return -ENOENT;

	if (sscanf(str, "%04X", &config) != 1)
		err = -ENOENT;
	else
		*value = config;

	free(str);

	return err;
}

int write_device_ccc(const bdaddr_t *local, const bdaddr_t *peer,
					uint8_t bdaddr_type, uint16_t handle,
					uint16_t value)
{
	char filename[PATH_MAX + 1], addr[18], key[25], config[5];

	create_filename(filename, PATH_MAX, local, "ccc");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	snprintf(key, sizeof(key), "%17s#%hhu#%04X", addr, bdaddr_type, handle);

	snprintf(config, sizeof(config), "%04X", value);

	return textfile_put(filename, key, config);
}

void delete_device_ccc(const bdaddr_t *local, const bdaddr_t *peer)
{
	char filename[PATH_MAX + 1], addr[18];

	ba2str(peer, addr);

	/* Deleting all CCC values of a given address */
	create_filename(filename, PATH_MAX, local, "ccc");
	delete_by_pattern(filename, addr);
}
