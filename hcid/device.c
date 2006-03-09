/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "hcid.h"

#include "textfile.h"
#include "oui.h"

#define MAX_DEVICES 16

struct hci_peer {
	struct timeval lastseen;
	struct timeval lastused;

	bdaddr_t bdaddr;
	uint32_t class;
	int8_t   rssi;
	uint8_t  data[240];
	uint8_t  name[248];

	uint8_t  pscan_rep_mode;
	uint8_t  pscan_period_mode;
	uint8_t  pscan_mode;
	uint16_t clock_offset;

	struct hci_peer *next;
};

struct hci_conn {
	bdaddr_t bdaddr;
	uint16_t handle;

	struct hci_conn *next;
};

struct hci_dev {
	bdaddr_t bdaddr;
	uint8_t  features[8];
	uint8_t  lmp_ver;
	uint16_t lmp_subver;
	uint16_t hci_rev;
	uint16_t manufacturer;

	uint8_t  name[248];

	struct hci_peer *peers;
	struct hci_conn *conns;
};

static struct hci_dev devices[MAX_DEVICES];

#define ASSERT_DEV_ID { if (dev_id >= MAX_DEVICES) return -ERANGE; }

void init_devices(void)
{
	int i;

	for (i = 0; i < MAX_DEVICES; i++)
		memset(devices + i, 0, sizeof(struct hci_dev));
}

int add_device(uint16_t dev_id)
{
	struct hci_dev *dev;
	struct hci_dev_info di;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	if (hci_devinfo(dev_id, &di) < 0)
		return -errno;

	bacpy(&dev->bdaddr, &di.bdaddr);
	memcpy(dev->features, di.features, 8);

	info("Device hci%d has been added", dev_id);

	return 0;
}

int remove_device(uint16_t dev_id)
{
	struct hci_dev *dev;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	memset(dev, 0, sizeof(struct hci_dev));

	info("Device hci%d has been removed", dev_id);

	return 0;
}

int start_device(uint16_t dev_id)
{
	struct hci_dev *dev;
	struct hci_version ver;
	int dd;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("Can't open device hci%d",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		error("Can't read version info for hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	dev->hci_rev = ver.hci_rev;
	dev->lmp_ver = ver.lmp_ver;
	dev->lmp_subver = ver.lmp_subver;
	dev->manufacturer = ver.manufacturer;

	hci_close_dev(dd);

	info("Device hci%d has been activated", dev_id);

	return 0;
}

int stop_device(uint16_t dev_id)
{
	ASSERT_DEV_ID;

	info("Device hci%d has been disabled", dev_id);

	return 0;
}

int get_device_address(uint16_t dev_id, char *address, size_t size)
{
	struct hci_dev *dev;
	int dd;

	ASSERT_DEV_ID;

	if (size < 18)
		return -ENOBUFS;

	dev = &devices[dev_id];

	if (bacmp(&dev->bdaddr, BDADDR_ANY))
		return ba2str(&dev->bdaddr, address);

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("Can't open device hci%d",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	if (hci_read_bd_addr(dd, &dev->bdaddr, 2000) < 0) {
		error("Can't read address for hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	hci_close_dev(dd);

	return ba2str(&dev->bdaddr, address);
}

int get_device_version(uint16_t dev_id, char *version, size_t size)
{
	struct hci_dev *dev;
	char edr[7], *tmp;
	int err;

	ASSERT_DEV_ID;

	if (size < 14)
		return -ENOBUFS;

	dev = &devices[dev_id];

	if (dev->lmp_ver == 0x03 &&
			(dev->features[3] & (LMP_EDR_ACL_2M | LMP_EDR_ACL_3M)))
		sprintf(edr, " + EDR");
	else
		edr[0] = '\0';

	tmp = lmp_vertostr(dev->lmp_ver);

	if (strlen(tmp) == 0)
		err = snprintf(version, size, "not assigned");
	else
		err = snprintf(version, size, "Bluetooth %s%s", tmp, edr);

	bt_free(tmp);

	return err;
}

static int digi_revision(uint16_t dev_id, char *revision, size_t size)
{
	struct hci_request rq;
	unsigned char req[] = { 0x07 };
	unsigned char buf[102];
	int dd;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("Can't open device hci%d",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = 0x000e;
	rq.cparam = req;
	rq.clen   = sizeof(req);
	rq.rparam = &buf;
	rq.rlen   = sizeof(buf);

	if (hci_send_req(dd, &rq, 2000) < 0) {
		error("Can't read revision for hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	hci_close_dev(dd);

	return snprintf(revision, size, "%s", buf + 1);
}

int get_device_revision(uint16_t dev_id, char *revision, size_t size)
{
	struct hci_dev *dev;
	int err;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	switch (dev->manufacturer) {
	case 10:
		err = snprintf(revision, size, "Build %d", dev->lmp_subver);
		break;
	case 12:
		err = digi_revision(dev_id, revision, size);
		break;
	case 15:
		err = snprintf(revision, size, "%d.%d / %d",
				dev->hci_rev & 0xff,
				dev->lmp_subver >> 8, dev->lmp_subver & 0xff);
		break;
	default:
		err = snprintf(revision, size, "0x%02x", dev->lmp_subver);
		break;
	}

	return err;
}

int get_device_manufacturer(uint16_t dev_id, char *manufacturer, size_t size)
{
	char *tmp;

	ASSERT_DEV_ID;

	tmp = bt_compidtostr(devices[dev_id].manufacturer);

	return snprintf(manufacturer, size, "%s", tmp);
}

int get_device_company(uint16_t dev_id, char *company, size_t size)
{
	char *tmp, oui[9];
	int err;

	ASSERT_DEV_ID;

	ba2oui(&devices[dev_id].bdaddr, oui);
	tmp = ouitocomp(oui);

	err = snprintf(company, size, "%s", tmp);

	free(tmp);

	return err;
}

int get_device_name(uint16_t dev_id, char *name, size_t size)
{
	char tmp[249];
	int dd;

	ASSERT_DEV_ID;

	memset(tmp, 0, sizeof(tmp));

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("Can't open device hci%d",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	if (hci_read_local_name(dd, sizeof(tmp), tmp, 2000) < 0) {
		error("Can't read name for hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	hci_close_dev(dd);

	memcpy(devices[dev_id].name, tmp, 248);

	return snprintf(name, size, "%s", tmp);
}

int set_device_name(uint16_t dev_id, const char *name)
{
	int dd;

	ASSERT_DEV_ID;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		error("Can't open device hci%d",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	if (hci_write_local_name(dd, name, 5000) < 0) {
		error("Can't read name for hci%d: %s (%d)",
					dev_id, strerror(errno), errno);
		return -errno;
	}

	hci_close_dev(dd);

	return 0;
}

int get_device_alias(uint16_t dev_id, const bdaddr_t *bdaddr, char *alias, size_t size)
{
	char filename[PATH_MAX + 1], addr[18], *tmp;
	int err;

	ASSERT_DEV_ID;

	ba2str(&devices[dev_id].bdaddr, addr);
	snprintf(filename, PATH_MAX, "%s/%s/aliases", STORAGEDIR, addr);

	ba2str(bdaddr, addr);

	tmp = textfile_get(filename, addr);
	if (!tmp)
		return -ENXIO;

	err = snprintf(alias, size, "%s", tmp);

	free(tmp);

	return err;
}

int set_device_alias(uint16_t dev_id, const bdaddr_t *bdaddr, const char *alias)
{
	char filename[PATH_MAX + 1], addr[18];

	ASSERT_DEV_ID;

	ba2str(&devices[dev_id].bdaddr, addr);
	snprintf(filename, PATH_MAX, "%s/%s/aliases", STORAGEDIR, addr);

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(bdaddr, addr);

	return textfile_put(filename, addr, alias);
}

int get_encryption_key_size(uint16_t dev_id, const bdaddr_t *baddr)
{
	struct hci_dev *dev;
	int size;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	switch (dev->manufacturer) {
	default:
		size = -ENOENT;
		break;
	}

	return size;
}
