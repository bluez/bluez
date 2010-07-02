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
#include <sys/param.h>
#include <sys/socket.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include "textfile.h"
#include "glib-helper.h"
#include "storage.h"

static inline int create_filename(char *buf, size_t size,
				const bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}

int read_device_alias(const char *src, const char *dst, char *alias, size_t size)
{
	char filename[PATH_MAX + 1], *tmp;
	int err;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "aliases");

	tmp = textfile_get(filename, dst);
	if (!tmp)
		return -ENXIO;

	err = snprintf(alias, size, "%s", tmp);

	free(tmp);

	return err < 0 ? -EIO : 0;
}

int write_device_alias(const char *src, const char *dst, const char *alias)
{
	char filename[PATH_MAX + 1];

	create_name(filename, PATH_MAX, STORAGEDIR, src, "aliases");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return textfile_put(filename, dst, alias);
}

int write_discoverable_timeout(bdaddr_t *bdaddr, int timeout)
{
	char filename[PATH_MAX + 1], str[32];

	snprintf(str, sizeof(str), "%d", timeout);

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return textfile_put(filename, "discovto", str);
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

int write_pairable_timeout(bdaddr_t *bdaddr, int timeout)
{
	char filename[PATH_MAX + 1], str[32];

	snprintf(str, sizeof(str), "%d", timeout);

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return textfile_put(filename, "pairto", str);
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

int write_device_mode(bdaddr_t *bdaddr, const char *mode)
{
	char filename[PATH_MAX + 1];

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (strcmp(mode, "off") != 0)
		textfile_put(filename, "onmode", mode);

	return textfile_put(filename, "mode", mode);
}

int read_device_mode(const char *src, char *mode, int length)
{
	char filename[PATH_MAX + 1], *str;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "config");

	str = textfile_get(filename, "mode");
	if (!str)
		return -ENOENT;

	strncpy(mode, str, length);
	mode[length - 1] = '\0';

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

int write_local_name(bdaddr_t *bdaddr, const char *name)
{
	char filename[PATH_MAX + 1], str[249];
	int i;

	memset(str, 0, sizeof(str));
	for (i = 0; i < 248 && name[i]; i++)
		if ((unsigned char) name[i] < 32 || name[i] == 127)
			str[i] = '.';
		else
			str[i] = name[i];

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return textfile_put(filename, "name", str);
}

int read_local_name(bdaddr_t *bdaddr, char *name)
{
	char filename[PATH_MAX + 1], *str;
	int len;

	create_filename(filename, PATH_MAX, bdaddr, "config");

	str = textfile_get(filename, "name");
	if (!str)
		return -ENOENT;

	len = strlen(str);
	if (len > 248)
		str[248] = '\0';
	strcpy(name, str);

	free(str);

	return 0;
}

int write_local_class(bdaddr_t *bdaddr, uint8_t *class)
{
	char filename[PATH_MAX + 1], str[9];

	sprintf(str, "0x%2.2x%2.2x%2.2x", class[2], class[1], class[0]);

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return textfile_put(filename, "class", str);
}

int read_local_class(bdaddr_t *bdaddr, uint8_t *class)
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

int write_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t class)
{
	char filename[PATH_MAX + 1], addr[18], str[9];

	create_filename(filename, PATH_MAX, local, "classes");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	sprintf(str, "0x%6.6x", class);

	return textfile_put(filename, addr, str);
}

int read_remote_class(bdaddr_t *local, bdaddr_t *peer, uint32_t *class)
{
	char filename[PATH_MAX + 1], addr[18], *str;

	create_filename(filename, PATH_MAX, local, "classes");

	ba2str(peer, addr);

	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%x", class) != 1) {
		free(str);
		return -ENOENT;
	}

	free(str);

	return 0;
}

int write_device_name(bdaddr_t *local, bdaddr_t *peer, char *name)
{
	char filename[PATH_MAX + 1], addr[18], str[249];
	int i;

	memset(str, 0, sizeof(str));
	for (i = 0; i < 248 && name[i]; i++)
		if ((unsigned char) name[i] < 32 || name[i] == 127)
			str[i] = '.';
		else
			str[i] = name[i];

	create_filename(filename, PATH_MAX, local, "names");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	return textfile_put(filename, addr, str);
}

int read_device_name(const char *src, const char *dst, char *name)
{
	char filename[PATH_MAX + 1], *str;
	int len;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "names");

	str = textfile_get(filename, dst);
	if (!str)
		return -ENOENT;

	len = strlen(str);
	if (len > 248)
		str[248] = '\0';
	strcpy(name, str);

	free(str);

	return 0;
}

int write_remote_eir(bdaddr_t *local, bdaddr_t *peer, uint8_t *data)
{
	char filename[PATH_MAX + 1], addr[18], str[481];
	int i;

	memset(str, 0, sizeof(str));
	for (i = 0; i < 240; i++)
		sprintf(str + (i * 2), "%2.2X", data[i]);

	create_filename(filename, PATH_MAX, local, "eir");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	return textfile_put(filename, addr, str);
}

int read_remote_eir(bdaddr_t *local, bdaddr_t *peer, uint8_t *data)
{
	char filename[PATH_MAX + 1], addr[18], *str;
	int i;

	create_filename(filename, PATH_MAX, local, "eir");

	ba2str(peer, addr);

	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	if (!data) {
		free(str);
		return 0;
	}

	if (strlen(str) < 480) {
		free(str);
		return -EIO;
	}

	for (i = 0; i < 240; i++)
		sscanf(str + (i * 2), "%02hhX", &data[i]);

	free(str);

	return 0;
}

int write_l2cap_info(bdaddr_t *local, bdaddr_t *peer,
			uint16_t mtu_result, uint16_t mtu,
			uint16_t mask_result, uint32_t mask)
{
	char filename[PATH_MAX + 1], addr[18], str[18];

	if (mask_result)
		snprintf(str, sizeof(str), "%d -1", mtu_result ? -1 : mtu);
	else
		snprintf(str, sizeof(str), "%d 0x%08x", mtu_result ? -1 : mtu, mask);

	create_filename(filename, PATH_MAX, local, "l2cap");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	return textfile_put(filename, addr, str);
}

int read_l2cap_info(bdaddr_t *local, bdaddr_t *peer,
			uint16_t *mtu_result, uint16_t *mtu,
			uint16_t *mask_result, uint32_t *mask)
{
	char filename[PATH_MAX + 1], addr[18], *str, *space, *msk;

	create_filename(filename, PATH_MAX, local, "l2cap");

	ba2str(peer, addr);
	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	space = strchr(str, ' ');
	if (!space) {
		free(str);
		return -ENOENT;
	}

	msk = space + 1;
	*space = '\0';

	if (mtu_result && mtu) {
		if (str[0] == '-')
			*mtu_result = 0x0001;
		else {
			*mtu_result = 0;
			*mtu = (uint16_t) strtol(str, NULL, 0);
		}
	}

	if (mask_result && mask) {
		if (msk[0] == '-')
			*mask_result = 0x0001;
		else {
			*mask_result = 0;
			*mask = (uint32_t) strtol(msk, NULL, 16);
		}
	}

	free(str);

	return 0;
}

int write_version_info(bdaddr_t *local, bdaddr_t *peer, uint16_t manufacturer,
					uint8_t lmp_ver, uint16_t lmp_subver)
{
	char filename[PATH_MAX + 1], addr[18], str[16];

	memset(str, 0, sizeof(str));
	sprintf(str, "%d %d %d", manufacturer, lmp_ver, lmp_subver);

	create_filename(filename, PATH_MAX, local, "manufacturers");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	return textfile_put(filename, addr, str);
}

int write_features_info(bdaddr_t *local, bdaddr_t *peer,
				unsigned char *page1, unsigned char *page2)
{
	char filename[PATH_MAX + 1], addr[18];
	char str[] = "0000000000000000 0000000000000000";
	char *old_value;
	int i;

	ba2str(peer, addr);

	create_filename(filename, PATH_MAX, local, "features");
	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	old_value = textfile_get(filename, addr);

	if (page1)
		for (i = 0; i < 8; i++)
			sprintf(str + (i * 2), "%2.2X", page1[i]);
	else if (old_value && strlen(old_value) >= 16)
		strncpy(str, old_value, 16);

	if (page2)
		for (i = 0; i < 8; i++)
			sprintf(str + 17 + (i * 2), "%2.2X", page2[i]);
	else if (old_value && strlen(old_value) >= 33)
		strncpy(str + 17, old_value + 17, 16);

	free(old_value);

	return textfile_put(filename, addr, str);
}

static int decode_bytes(const char *str, unsigned char *bytes, size_t len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		if (sscanf(str + (i * 2), "%02hhX", &bytes[i]) != 1)
			return -EINVAL;
	}

	return 0;
}

int read_remote_features(bdaddr_t *local, bdaddr_t *peer,
				unsigned char *page1, unsigned char *page2)
{
	char filename[PATH_MAX + 1], addr[18], *str;
	size_t len;
	int err;

	if (page1 == NULL && page2 == NULL)
		return -EINVAL;

	create_filename(filename, PATH_MAX, local, "features");

	ba2str(peer, addr);

	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	len = strlen(str);

	err = -ENOENT;

	if (page1 && len >= 16)
		err = decode_bytes(str, page1, 8);

	if (page2 && len >= 33)
		err = decode_bytes(str + 17, page2, 8);

	free(str);

	return err;
}

int write_lastseen_info(bdaddr_t *local, bdaddr_t *peer, struct tm *tm)
{
	char filename[PATH_MAX + 1], addr[18], str[24];

	memset(str, 0, sizeof(str));
	strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S %Z", tm);

	create_filename(filename, PATH_MAX, local, "lastseen");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	return textfile_put(filename, addr, str);
}

int write_lastused_info(bdaddr_t *local, bdaddr_t *peer, struct tm *tm)
{
	char filename[PATH_MAX + 1], addr[18], str[24];

	memset(str, 0, sizeof(str));
	strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S %Z", tm);

	create_filename(filename, PATH_MAX, local, "lastused");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	return textfile_put(filename, addr, str);
}

int write_link_key(bdaddr_t *local, bdaddr_t *peer, unsigned char *key, uint8_t type, int length)
{
	char filename[PATH_MAX + 1], addr[18], str[38];
	int i;

	memset(str, 0, sizeof(str));
	for (i = 0; i < 16; i++)
		sprintf(str + (i * 2), "%2.2X", key[i]);
	sprintf(str + 32, " %d %d", type, length);

	create_filename(filename, PATH_MAX, local, "linkkeys");

	create_file(filename, S_IRUSR | S_IWUSR);

	ba2str(peer, addr);

	if (length < 0) {
		char *tmp = textfile_get(filename, addr);
		if (tmp) {
			if (strlen(tmp) > 34)
				memcpy(str + 34, tmp + 34, 3);
			free(tmp);
		}
	}

	return textfile_put(filename, addr, str);
}

int read_link_key(bdaddr_t *local, bdaddr_t *peer, unsigned char *key, uint8_t *type)
{
	char filename[PATH_MAX + 1], addr[18], tmp[3], *str;
	int i;

	create_filename(filename, PATH_MAX, local, "linkkeys");

	ba2str(peer, addr);
	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	if (!key) {
		free(str);
		return 0;
	}

	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < 16; i++) {
		memcpy(tmp, str + (i * 2), 2);
		key[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	if (type) {
		memcpy(tmp, str + 33, 2);
		*type = (uint8_t) strtol(tmp, NULL, 10);
	}

	free(str);

	return 0;
}

int read_pin_length(bdaddr_t *local, bdaddr_t *peer)
{
	char filename[PATH_MAX + 1], addr[18], *str;
	int len;

	create_filename(filename, PATH_MAX, local, "linkkeys");

	ba2str(peer, addr);
	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	if (strlen(str) < 36) {
		free(str);
		return -ENOENT;
	}

	len = atoi(str + 35);

	free(str);

	return len;
}

int read_pin_code(bdaddr_t *local, bdaddr_t *peer, char *pin)
{
	char filename[PATH_MAX + 1], addr[18], *str;
	int len;

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

static GSList *service_string_to_list(char *services)
{
	GSList *l = NULL;
	char *start = services;
	int i, finished = 0;

	for (i = 0; !finished; i++) {
		if (services[i] == '\0')
			finished = 1;

		if (services[i] == ' ' || services[i] == '\0') {
			services[i] = '\0';
			l = g_slist_append(l, start);
			start = services + i + 1;
		}
	}

	return l;
}

static char *service_list_to_string(GSList *services)
{
	char str[1024];
	int len = 0;

	if (!services)
		return g_strdup("");

	memset(str, 0, sizeof(str));

	while (services) {
		int ret;
		char *ident = services->data;

		ret = snprintf(str + len, sizeof(str) - len - 1, "%s%s",
				ident, services->next ? " " : "");

		if (ret > 0)
			len += ret;

		services = services->next;
	}

	return g_strdup(str);
}

int write_trust(const char *src, const char *addr, const char *service,
		gboolean trust)
{
	char filename[PATH_MAX + 1], *str;
	GSList *services = NULL, *match;
	gboolean trusted;
	int ret;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "trusts");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	str = textfile_caseget(filename, addr);
	if (str)
		services = service_string_to_list(str);

	match = g_slist_find_custom(services, service, (GCompareFunc) strcmp);
	trusted = match ? TRUE : FALSE;

	/* If the old setting is the same as the requested one, we're done */
	if (trusted == trust) {
		g_slist_free(services);
		free(str);
		return 0;
	}

	if (trust)
		services = g_slist_append(services, (void *) service);
	else
		services = g_slist_remove(services, match->data);

	/* Remove the entry if the last trusted service was removed */
	if (!trust && !services)
		ret = textfile_casedel(filename, addr);
	else {
		char *new_str = service_list_to_string(services);
		ret = textfile_caseput(filename, addr, new_str);
		free(new_str);
	}

	g_slist_free(services);

	free(str);

	return ret;
}

gboolean read_trust(const bdaddr_t *local, const char *addr, const char *service)
{
	char filename[PATH_MAX + 1], *str;
	GSList *services;
	gboolean ret;

	create_filename(filename, PATH_MAX, local, "trusts");

	str = textfile_caseget(filename, addr);
	if (!str)
		return FALSE;

	services = service_string_to_list(str);

	if (g_slist_find_custom(services, service, (GCompareFunc) strcmp))
		ret = TRUE;
	else
		ret = FALSE;

	g_slist_free(services);
	free(str);

	return ret;
}

struct trust_list {
	GSList *trusts;
	const char *service;
};

static void append_trust(char *key, char *value, void *data)
{
	struct trust_list *list = data;

	if (strstr(value, list->service))
		list->trusts = g_slist_append(list->trusts, g_strdup(key));
}

GSList *list_trusts(bdaddr_t *local, const char *service)
{
	char filename[PATH_MAX + 1];
	struct trust_list list;

	create_filename(filename, PATH_MAX, local, "trusts");

	list.trusts = NULL;
	list.service = service;

	if (textfile_foreach(filename, append_trust, &list) < 0)
		return NULL;

	return list.trusts;
}

int write_device_profiles(bdaddr_t *src, bdaddr_t *dst, const char *profiles)
{
	char filename[PATH_MAX + 1], addr[18];

	if (!profiles)
		return -EINVAL;

	create_filename(filename, PATH_MAX, src, "profiles");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dst, addr);
	return textfile_put(filename, addr, profiles);
}

int delete_entry(bdaddr_t *src, const char *storage, const char *key)
{
	char filename[PATH_MAX + 1];

	create_filename(filename, PATH_MAX, src, storage);

	return textfile_del(filename, key);
}

int store_record(const gchar *src, const gchar *dst, sdp_record_t *rec)
{
	char filename[PATH_MAX + 1], key[28];
	sdp_buf_t buf;
	int err, size, i;
	char *str;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	snprintf(key, sizeof(key), "%17s#%08X", dst, rec->handle);

	if (sdp_gen_record_pdu(rec, &buf) < 0)
		return -1;

	size = buf.data_size;

	str = g_malloc0(size*2+1);

	for (i = 0; i < size; i++)
		sprintf(str + (i * 2), "%02X", buf.data[i]);

	err = textfile_put(filename, key, str);

	free(buf.data);
	free(str);

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
	free(pdata);

	return rec;
}


sdp_record_t *fetch_record(const gchar *src, const gchar *dst,
						const uint32_t handle)
{
	char filename[PATH_MAX + 1], key[28], *str;
	sdp_record_t *rec;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");

	snprintf(key, sizeof(key), "%17s#%08X", dst, handle);

	str = textfile_get(filename, key);
	if (!str)
		return NULL;

	rec = record_from_string(str);
	free(str);

	return rec;
}

int delete_record(const gchar *src, const gchar *dst, const uint32_t handle)
{
	char filename[PATH_MAX + 1], key[28];

	create_name(filename, PATH_MAX, STORAGEDIR, src, "sdp");

	snprintf(key, sizeof(key), "%17s#%08X", dst, handle);

	return textfile_del(filename, key);
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

void delete_all_records(const bdaddr_t *src, const bdaddr_t *dst)
{
	sdp_list_t *records, *seq;
	char srcaddr[18], dstaddr[18];

	ba2str(src, srcaddr);
	ba2str(dst, dstaddr);

	records = read_records(src, dst);

	for (seq = records; seq; seq = seq->next) {
		sdp_record_t *rec = seq->data;
		delete_record(srcaddr, dstaddr, rec->handle);
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

int store_device_id(const gchar *src, const gchar *dst,
				const uint16_t source, const uint16_t vendor,
				const uint16_t product, const uint16_t version)
{
	char filename[PATH_MAX + 1], str[20];

	create_name(filename, PATH_MAX, STORAGEDIR, src, "did");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	snprintf(str, sizeof(str), "%04X %04X %04X %04X", source,
						vendor, product, version);

	return textfile_put(filename, dst, str);
}

static int read_device_id_from_did(const gchar *src, const gchar *dst,
					uint16_t *source, uint16_t *vendor,
					uint16_t *product, uint16_t *version)
{
	char filename[PATH_MAX + 1];
	char *str, *vendor_str, *product_str, *version_str;

	create_name(filename, PATH_MAX, STORAGEDIR, src, "did");

	str = textfile_get(filename, dst);
	if (!str)
		return -ENOENT;

	vendor_str = strchr(str, ' ');
	if (!vendor_str) {
		free(str);
		return -ENOENT;
	}
	*(vendor_str++) = 0;

	product_str = strchr(vendor_str, ' ');
	if (!product_str) {
		free(str);
		return -ENOENT;
	}
	*(product_str++) = 0;

	version_str = strchr(product_str, ' ');
	if (!version_str) {
		free(str);
		return -ENOENT;
	}
	*(version_str++) = 0;

	if (source)
		*source = (uint16_t) strtol(str, NULL, 16);
	if (vendor)
		*vendor = (uint16_t) strtol(vendor_str, NULL, 16);
	if (product)
		*product = (uint16_t) strtol(product_str, NULL, 16);
	if (version)
		*version = (uint16_t) strtol(version_str, NULL, 16);

	free(str);

	return 0;
}

int read_device_id(const gchar *srcaddr, const gchar *dstaddr,
					uint16_t *source, uint16_t *vendor,
					uint16_t *product, uint16_t *version)
{
	uint16_t lsource, lvendor, lproduct, lversion;
	sdp_list_t *recs;
	sdp_record_t *rec;
	bdaddr_t src, dst;
	int err;

	err = read_device_id_from_did(srcaddr, dstaddr, &lsource,
						vendor, product, version);
	if (!err) {
		if (lsource == 0xffff)
			err = -ENOENT;

		return err;
	}

	str2ba(srcaddr, &src);
	str2ba(dstaddr, &dst);

	recs = read_records(&src, &dst);
	rec = find_record_in_list(recs, PNP_UUID);

	if (rec) {
		sdp_data_t *pdlist;

		pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID_SOURCE);
		lsource = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, SDP_ATTR_VENDOR_ID);
		lvendor = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, SDP_ATTR_PRODUCT_ID);
		lproduct = pdlist ? pdlist->val.uint16 : 0x0000;

		pdlist = sdp_data_get(rec, SDP_ATTR_VERSION);
		lversion = pdlist ? pdlist->val.uint16 : 0x0000;

		err = 0;
	}

	sdp_list_free(recs, (sdp_free_func_t)sdp_record_free);

	if (err) {
		/* FIXME: We should try EIR data if we have it, too */

		/* If we don't have the data, we don't want to go through the
		 * above search every time. */
		lsource = 0xffff;
		lvendor = 0x0000;
		lproduct = 0x0000;
		lversion = 0x0000;
	}

	store_device_id(srcaddr, dstaddr, lsource, lvendor, lproduct, lversion);

	if (err)
		return err;

	if (source)
		*source = lsource;
	if (vendor)
		*vendor = lvendor;
	if (product)
		*product = lproduct;
	if (version)
		*version = lversion;

	return 0;
}

int write_device_pairable(bdaddr_t *bdaddr, gboolean mode)
{
	char filename[PATH_MAX + 1];

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return textfile_put(filename, "pairable", mode ? "yes" : "no");
}

int read_device_pairable(bdaddr_t *bdaddr, gboolean *mode)
{
	char filename[PATH_MAX + 1], *str;

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	str = textfile_get(filename, "pairable");
	if (!str)
		return -ENOENT;

	*mode = strcmp(str, "yes") == 0 ? TRUE : FALSE;

	free(str);

	return 0;
}

gboolean read_blocked(const bdaddr_t *local, const bdaddr_t *remote)
{
	char filename[PATH_MAX + 1], *str, addr[18];

	create_filename(filename, PATH_MAX, local, "blocked");

	ba2str(remote, addr);

	str = textfile_caseget(filename, addr);
	if (!str)
		return FALSE;

	free(str);

	return TRUE;
}

int write_blocked(const bdaddr_t *local, const bdaddr_t *remote,
							gboolean blocked)
{
	char filename[PATH_MAX + 1], addr[18];

	create_filename(filename, PATH_MAX, local, "blocked");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(remote, addr);

	if (blocked == FALSE)
		return textfile_casedel(filename, addr);

	return textfile_caseput(filename, addr, "");
}
