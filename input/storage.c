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

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hidp.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>

#include "logging.h"
#include "textfile.h"

#include "storage.h"

static inline int create_filename(char *buf, size_t size,
					bdaddr_t *bdaddr, const char *name)
{
	char addr[18];

	ba2str(bdaddr, addr);

	return create_name(buf, size, STORAGEDIR, addr, name);
}

int parse_stored_hidd(const char *str, struct hidp_connadd_req *req)
{
	char tmp[3];
	char *desc;
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

	req->rd_size = strlen(desc) / 2;
	req->rd_data = g_try_malloc0(req->rd_size);
	if (!req->rd_data) {
		g_free(desc);
		return -ENOMEM;
	}

	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < req->rd_size; i++) {
		memcpy(tmp, desc + (i * 2), 2);
		req->rd_data[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	g_free(desc);

	return 0;
}

int parse_stored_device_info(const char *str, struct hidp_connadd_req *req)
{
	char tmp[3];
	const char *desc;
	unsigned int vendor, product, version, subclass, country, parser, pos;
	size_t len;
	int i;

	sscanf(str, "%04X:%04X:%04X %02X %02X %04X %08X %n",
			&vendor, &product, &version, &subclass, &country,
			&parser, &req->flags, &pos);

	desc  = &str[pos];
	len = strlen(desc);
	if (len <= 0)
		return -ENOENT;

	req->vendor   = vendor;
	req->product  = product;
	req->version  = version;
	req->subclass = subclass;
	req->country  = country;
	req->parser   = parser;

	req->rd_size = len / 2;
	req->rd_data = g_try_malloc0(req->rd_size);
	if (!req->rd_data) {
		return -ENOMEM;
	}

	memset(tmp, 0, sizeof(tmp));
	for (i = 0; i < req->rd_size; i++) {
		memcpy(tmp, desc + (i * 2), 2);
		req->rd_data[i] = (uint8_t) strtol(tmp, NULL, 16);
	}

	return 0;
}

int get_stored_device_info(bdaddr_t *src, bdaddr_t *dst,
					struct hidp_connadd_req *req)
{
	char filename[PATH_MAX + 1], *str;
	char peer[18];
	int err;

	create_filename(filename, PATH_MAX, src, "input");

	ba2str(dst, peer);
	str = textfile_get(filename, peer);
	if (!str)
		return -ENOENT;

	err = parse_stored_device_info(str, req);

	free(str);

	return err;
}

int del_stored_device_info(bdaddr_t *src, bdaddr_t *dst)
{
	char filename[PATH_MAX + 1];
	char addr[18];

	ba2str(dst, addr);

	create_filename(filename, PATH_MAX, src, "hidd");
	textfile_del(filename, addr);

	create_filename(filename, PATH_MAX, src, "input");
	return textfile_del(filename, addr);
}

int store_device_info(bdaddr_t *src, bdaddr_t *dst, struct hidp_connadd_req *req)
{
	char filename[PATH_MAX + 1], *str, *desc;
	int i, err, size;
	char addr[18];

	create_filename(filename, PATH_MAX, src, "input");

	size = 15 + 3 + 3 + 5 + (req->rd_size * 2) + 2 + 9;
	str = g_try_malloc0(size);
	if (!str)
		return -ENOMEM;

	desc = g_try_malloc0((req->rd_size * 2) + 1);
	if (!desc) {
		g_free(str);
		return -ENOMEM;
	}

	for (i = 0; i < req->rd_size; i++)
		sprintf(desc + (i * 2), "%2.2X", req->rd_data[i]);

	snprintf(str, size - 1, "%04X:%04X:%04X %02X %02X %04X %08X %s",
			req->vendor, req->product, req->version,
			req->subclass, req->country, req->parser,
			req->flags, desc);

	g_free(desc);

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(dst, addr);

	err = textfile_put(filename, addr, str);

	g_free(str);

	return err;
}

int read_device_name(bdaddr_t *src, bdaddr_t *dst, char **name)
{
	char filename[PATH_MAX + 1], addr[18], *str;
	int len;

	create_filename(filename, PATH_MAX, src, "names");

	ba2str(dst, addr);
	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	len = strlen(str);

	/* HID max name size is 128 chars */
	if (len < 128) {
		*name = str;
		return 0;
	}

	*name = g_try_malloc0(128);
	if (!*name)
		return -ENOMEM;

	snprintf(*name, 128, "%s", str);

	free(str);

	return 0;
}

int read_device_class(bdaddr_t *src, bdaddr_t *dst, uint32_t *cls)
{
	char filename[PATH_MAX + 1], *str;
	char addr[18];

	ba2str(src, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "classes");

	ba2str(dst, addr);
	str = textfile_get(filename, addr);
	if (!str)
		return -ENOENT;

	if (sscanf(str, "%x", cls) != 1) {
		g_free(str);
		return -ENOENT;
	}

	g_free(str);

	return 0;
}

int encrypt_link(bdaddr_t *src, bdaddr_t *dst)
{
	char filename[PATH_MAX + 1];
	struct hci_conn_info_req *cr;
	int dd, err, dev_id;
	char addr[18], *str;

	create_filename(filename, PATH_MAX, src, "linkkeys");

	ba2str(dst, addr);

	str = textfile_get(filename, addr);
	if (!str) {
		error("Encryption link key not found");
		return -ENOKEY;
	}

	free(str);

	cr = g_try_malloc0(sizeof(*cr) + sizeof(struct hci_conn_info));
	if (!cr)
		return -ENOMEM;

	ba2str(src, addr);

	dev_id = hci_devid(addr);
	if (dev_id < 0) {
		g_free(cr);
		return -errno;
	}

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		g_free(cr);
		return -errno;
	}

	bacpy(&cr->bdaddr, dst);
	cr->type = ACL_LINK;

	if (ioctl(dd, HCIGETCONNINFO, (unsigned long) cr) < 0)
		goto fail;

	if (cr->conn_info->link_mode & HCI_LM_ENCRYPT) {
		/* Already encrypted */
		goto done;
	}

	if (hci_authenticate_link(dd, htobs(cr->conn_info->handle), 1000) < 0) {
		error("Link authentication failed: %s (%d)",
						strerror(errno), errno);
		goto fail;
	}

	if (hci_encrypt_link(dd, htobs(cr->conn_info->handle), 1, 1000) < 0) {
		error("Link encryption failed: %s (%d)",
						strerror(errno), errno);
		goto fail;
	}

done:
	g_free(cr);

	hci_close_dev(dd);

	return 0;

fail:
	g_free(cr);

	err = errno;
	hci_close_dev(dd);

	return -err;
}

gboolean has_bonding(bdaddr_t *src, bdaddr_t *dst)
{
	char filename[PATH_MAX + 1];
	char addr[18], *str;

	create_filename(filename, PATH_MAX, src, "linkkeys");

	ba2str(dst, addr);

	str = textfile_get(filename, addr);
	if (!str)
		return FALSE;

	free(str);

	return TRUE;
}
