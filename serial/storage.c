/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>

#include <bluetooth/bluetooth.h>

#include <glib.h>

#include "logging.h"
#include "textfile.h"

#include "storage.h"

int port_store(bdaddr_t *src, bdaddr_t *dst, int id,
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

	size = strlen(svcname) + 3;
	value = g_malloc0(size);

	snprintf(key, 32, "%s#%d", dst_addr, id);
	snprintf(value, size, "%d:%s", ch, svcname);

	err = textfile_put(filename, key, value);
	g_free(value);

	return err;
}
