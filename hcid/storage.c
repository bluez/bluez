/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include "textfile.h"
#include "hcid.h"

static inline int create_filename(char *buf, size_t size, const bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}

int write_discoverable_timeout(bdaddr_t *bdaddr, int timeout)
{
	char filename[PATH_MAX + 1], str[32];

	snprintf(str, sizeof(str), "%d", timeout);

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return textfile_put(filename, "discovto", str);
}

int read_discoverable_timeout(bdaddr_t *bdaddr, int *timeout)
{
	char filename[PATH_MAX + 1], *str;

	create_filename(filename, PATH_MAX, bdaddr, "config");

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

int write_device_mode(bdaddr_t *bdaddr, const char *mode)
{
	char filename[PATH_MAX + 1];

	create_filename(filename, PATH_MAX, bdaddr, "config");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (strcmp(mode, "off") != 0)
		textfile_put(filename, "onmode", mode);

	return textfile_put(filename, "mode", mode);
}

int read_device_mode(bdaddr_t *bdaddr, char *mode, int length)
{
	char filename[PATH_MAX + 1], *str;

	create_filename(filename, PATH_MAX, bdaddr, "config");

	str = textfile_get(filename, "mode");
	if (!str)
		return -ENOENT;

	strncpy(mode, str, length);
	mode[length - 1] = '\0';

	free(str);

	return 0;
}

int read_on_mode(bdaddr_t *bdaddr, char *mode, int length)
{
	char filename[PATH_MAX + 1], *str;

	create_filename(filename, PATH_MAX, bdaddr, "config");

	str = textfile_get(filename, "onmode");
	if (!str)
		return -ENOENT;

	strncpy(mode, str, length);
	mode[length - 1] = '\0';

	free(str);

	return 0;
}

int write_local_name(bdaddr_t *bdaddr, char *name)
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

int read_device_name(bdaddr_t *local, bdaddr_t *peer, char *name)
{
	char filename[PATH_MAX + 1], addr[18], *str;
	int len;

	create_filename(filename, PATH_MAX, local, "names");

	ba2str(peer, addr);
	str = textfile_get(filename, addr);
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

int write_version_info(bdaddr_t *local, bdaddr_t *peer, uint16_t manufacturer, uint8_t lmp_ver, uint16_t lmp_subver)
{
	char filename[PATH_MAX + 1], addr[18], str[16];

	memset(str, 0, sizeof(str));
	sprintf(str, "%d %d %d", manufacturer, lmp_ver, lmp_subver);

	create_filename(filename, PATH_MAX, local, "manufacturers");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	return textfile_put(filename, addr, str);
}

int write_features_info(bdaddr_t *local, bdaddr_t *peer, unsigned char *features)
{
	char filename[PATH_MAX + 1], addr[18], str[17];
	int i;

	memset(str, 0, sizeof(str));
	for (i = 0; i < 8; i++)
		sprintf(str + (i * 2), "%2.2X", features[i]);

	create_filename(filename, PATH_MAX, local, "features");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(peer, addr);
	return textfile_put(filename, addr, str);
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

int write_trust(bdaddr_t *local, const char *addr, const char *service,
		gboolean trust)
{
	char filename[PATH_MAX + 1], *str;
	GSList *services = NULL, *match;
	gboolean trusted;
	int ret;

	create_filename(filename, PATH_MAX, local, "trusts");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	str = textfile_caseget(filename, addr);
	if (str)
		services = service_string_to_list(str);

	match = g_slist_find_custom(services, service, (GCompareFunc) strcmp);
	trusted = match ? TRUE : FALSE;

	/* If the old setting is the same as the requested one, we're done */
	if (trusted == trust) {
		g_slist_free(services);
		if (str)
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

	if (str)
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
