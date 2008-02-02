/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#include <errno.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "logging.h"
#include "textfile.h"

#include "storage.h"

int port_delete(bdaddr_t *src, bdaddr_t *dst, int16_t id)
{
	char filename[PATH_MAX + 1];
	char src_addr[18], dst_addr[18];
	char key[32];

	ba2str(src, src_addr);
	ba2str(dst, dst_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "serial");
	snprintf(key, sizeof(key), "%s#%hd", dst_addr, id);

	return textfile_del(filename, key);
}

int port_store(bdaddr_t *src, bdaddr_t *dst, int16_t id,
			uint8_t ch, const char *svcname)
{
	char filename[PATH_MAX + 1];
	char src_addr[18], dst_addr[18];
	char key[32];
	char *value;
	int size, err;

	if (!svcname)
		svcname = "Bluetooth RFCOMM port";

	ba2str(src, src_addr);
	ba2str(dst, dst_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "serial");
	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	size = strlen(svcname) + 5;
	value = g_malloc0(size);

	snprintf(key, 32, "%s#%hd", dst_addr, id);
	snprintf(value, size, "%d:%s", ch, svcname);

	err = textfile_put(filename, key, value);
	g_free(value);

	return err;
}

int proxy_delete(bdaddr_t *src, const char *tty)
{
	char filename[PATH_MAX + 1], src_addr[18];

	ba2str(src, src_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "proxy");

	return textfile_del(filename, tty);
}

int proxy_store(bdaddr_t *src, const char *uuid, const char *tty,
		const char *name, uint8_t ch, int opts, struct termios *ti)
{
	char filename[PATH_MAX + 1], key[32], src_addr[18], *value;
	int i, pos, size, err;
	uint8_t *pti;

	ba2str(src, src_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "proxy");
	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (!name)
		name = "Port Proxy Entity";

	size = MAX_LEN_UUID_STR + 16 + strlen(name) + sizeof(struct termios) * 2;
	value = g_malloc0(size);

	snprintf(key, 32, "%s", tty);

	/* tty uuid 00 0x0000 name:termios */
	pos = snprintf(value, size, "%s %d 0x%04X %s:", uuid, ch, opts, name);

	if (!ti)
		goto done;

	for (i = 0, pti = (uint8_t *) ti; i < sizeof(struct termios); i++, pti++)
		sprintf(value + pos + (i * 2), "%2.2X", *pti);

done:
	err = textfile_put(filename, key, value);
	g_free(value);

	return err;
}

int read_device_name(bdaddr_t *src, bdaddr_t *dst, char **name)
{
	char filename[PATH_MAX + 1], *str;
	char src_addr[18], dst_addr[18];
	int len;

	ba2str(src, src_addr);
	ba2str(dst, dst_addr);

	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "names");

	str = textfile_get(filename, dst_addr);
	if (!str)
		return -ENOENT;

	len = strlen(str);

	/* Max remote device name */
	if (len < 248) {
		*name = str;
		return 0;
	}

	*name = g_try_malloc0(248);
	if (!*name)
		return -ENOMEM;

	snprintf(*name, 248, "%s", str);

	free(str);

	return 0;
}
