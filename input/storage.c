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

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hidp.h>

#include "textfile.h"

#include "storage.h"

static inline int create_filename(char *buf, size_t size,
					bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}

int parse_stored_device_info(const char *str, struct hidp_connadd_req *req)
{
	char tmp[3], *desc;
	unsigned int vendor, product, version, subclass, country, parser, pos;
	int i;

	desc = malloc(4096);
	if (!desc)
		return -ENOMEM;

	memset(desc, 0, 4096);

	sscanf(str, "%04X:%04X:%04X %02X %02X %04X %4095s %08X %n",
			&vendor, &product, &version, &subclass, &country,
			&parser, desc, &req->flags, &pos);

	req->vendor   = vendor;
	req->product  = product;
	req->version  = version;
	req->subclass = subclass;
	req->country  = country;
	req->parser   = parser;

	snprintf(req->name, 128, str + pos);

	req->rd_size = strlen(desc) / 2;
	req->rd_data = malloc(req->rd_size);
	if (!req->rd_data) {
		free(desc);
		return -ENOMEM;
	}

	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < req->rd_size; i++) {
		memcpy(tmp, desc + (i * 2), 2);
		req->rd_data[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	free(desc);

	return 0;
}

int get_stored_device_info(bdaddr_t *sba, bdaddr_t *dba,
					struct hidp_connadd_req *req)
{
	char filename[PATH_MAX + 1], *str;
	char peer[18];
	int err;

	create_filename(filename, PATH_MAX, sba, "hidd");

	ba2str(dba, peer);
	str = textfile_get(filename, peer);
	if (!str)
		return -ENOENT;

	err = parse_stored_device_info(str, req);

	free(str);

	return err;
}

int del_stored_device_info(bdaddr_t *sba, bdaddr_t *dba)
{
	char filename[PATH_MAX + 1];
	char addr[18];

	create_filename(filename, PATH_MAX, sba, "hidd");

	ba2str(dba, addr);

	return textfile_del(filename, addr);
}

int store_device_info(bdaddr_t *sba, bdaddr_t *dba, struct hidp_connadd_req *req)
{
	char filename[PATH_MAX + 1], *str, *desc;
	int i, err, size;
	char addr[18];

	create_filename(filename, PATH_MAX, sba, "hidd");

	size = 15 + 3 + 3 + 5 + (req->rd_size * 2) + 1 + 9 + strlen(req->name) + 2;
	str = malloc(size);
	if (!str)
		return -ENOMEM;

	desc = malloc((req->rd_size * 2) + 1);
	if (!desc) {
		free(str);
		return -ENOMEM;
	}

	memset(desc, 0, (req->rd_size * 2) + 1);
	for (i = 0; i < req->rd_size; i++)
		sprintf(desc + (i * 2), "%2.2X", req->rd_data[i]);

	snprintf(str, size - 1, "%04X:%04X:%04X %02X %02X %04X %s %08X %s",
			req->vendor, req->product, req->version,
			req->subclass, req->country, req->parser, desc,
			req->flags, req->name);

	free(desc);

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dba, addr);

	err = textfile_put(filename, addr, str);

	free(str);

	return err;
}
