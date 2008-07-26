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
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "hcid.h"
#include "sdpd.h"

#include "logging.h"
#include "textfile.h"
#include "oui.h"

#include "adapter.h"
#include "device.h"
#include "dbus-common.h"
#include "dbus-hci.h"
#include "dbus-service.h"
#include "error.h"
#include "glib-helper.h"
#include "agent.h"
#include "dbus-sdp.h"
#include "sdp-xml.h"

#define MAX_DEVICES		16
#define DISCONNECT_TIMER	2

#define DEVICE_INTERFACE "org.bluez.Device"

struct browse_req {
	DBusConnection *conn;
	DBusMessage *msg;
	struct device *device;
	GSList *uuids_added;
	GSList *uuids_removed;
	int search_uuid;
	gboolean browse;
};

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
	int ignore;

	bdaddr_t bdaddr;
	uint8_t  features[8];
	uint8_t  lmp_ver;
	uint16_t lmp_subver;
	uint16_t hci_rev;
	uint16_t manufacturer;

	uint8_t  ssp_mode;
	uint8_t  name[248];
	uint8_t  class[3];

	struct hci_peer *peers;
	struct hci_conn *conns;
};

static struct hci_dev devices[MAX_DEVICES];

#define ASSERT_DEV_ID { if (dev_id >= MAX_DEVICES) return -ERANGE; }

static GSList *drivers = NULL;

static uint16_t uuid_list[] = {
	PUBLIC_BROWSE_GROUP,
	HID_SVCLASS_ID,
	GENERIC_AUDIO_SVCLASS_ID,
	ADVANCED_AUDIO_SVCLASS_ID,
	AV_REMOTE_SVCLASS_ID,
	0
};

void init_adapters(void)
{
	int i;

	for (i = 0; i < MAX_DEVICES; i++)
		memset(devices + i, 0, sizeof(struct hci_dev));
}

static int device_read_bdaddr(uint16_t dev_id, bdaddr_t *bdaddr)
{
	int dd, err;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	if (hci_read_bd_addr(dd, bdaddr, 2000) < 0) {
		err = errno;
		error("Can't read address for hci%d: %s (%d)",
					dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	hci_close_dev(dd);

	return 0;
}

int add_adapter(uint16_t dev_id)
{
	struct hci_dev *dev;
	struct hci_dev_info di;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	if (hci_devinfo(dev_id, &di) < 0) {
		dev->ignore = 1;
		return -errno;
	}

	if (hci_test_bit(HCI_RAW, &di.flags)) {
		info("Device hci%d is using raw mode", dev_id);
		dev->ignore = 1;
	}

	if (bacmp(&di.bdaddr, BDADDR_ANY))
		bacpy(&dev->bdaddr, &di.bdaddr);
	else {
		int err = device_read_bdaddr(dev_id, &dev->bdaddr);
		if (err < 0)
			return err;
	}
	memcpy(dev->features, di.features, 8);

	info("Device hci%d has been added", dev_id);

	return 0;
}

int remove_adapter(uint16_t dev_id)
{
	struct hci_dev *dev;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	memset(dev, 0, sizeof(struct hci_dev));

	info("Device hci%d has been removed", dev_id);

	return 0;
}

static inline uint8_t get_inquiry_mode(struct hci_dev *dev)
{
	if (dev->features[6] & LMP_EXT_INQ)
		return 2;

	if (dev->features[3] & LMP_RSSI_INQ)
		return 1;

	if (dev->manufacturer == 11 &&
			dev->hci_rev == 0x00 && dev->lmp_subver == 0x0757)
		return 1;

	if (dev->manufacturer == 15) {
		if (dev->hci_rev == 0x03 && dev->lmp_subver == 0x6963)
			return 1;
		if (dev->hci_rev == 0x09 && dev->lmp_subver == 0x6963)
			return 1;
		if (dev->hci_rev == 0x00 && dev->lmp_subver == 0x6965)
			return 1;
	}

	if (dev->manufacturer == 31 &&
			dev->hci_rev == 0x2005 && dev->lmp_subver == 0x1805)
		return 1;

	return 0;
}

static void update_ext_inquiry_response(int dd, struct hci_dev *dev)
{
	uint8_t fec = 0, data[240];

	if (!(dev->features[6] & LMP_EXT_INQ))
		return;

	memset(data, 0, sizeof(data));

	if (dev->ssp_mode > 0)
		create_ext_inquiry_response((char *) dev->name, data);

	if (hci_write_ext_inquiry_response(dd, fec, data, 2000) < 0)
		error("Can't write extended inquiry response: %s (%d)",
						strerror(errno), errno);
}

int start_adapter(uint16_t dev_id)
{
	struct hci_dev *dev;
	struct hci_version ver;
	uint8_t features[8], inqmode;
	uint8_t events[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00, 0x00 };
	char name[249];
	int dd, err;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	if (dev->ignore)
		return 0;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	if (hci_read_local_version(dd, &ver, 1000) < 0) {
		err = errno;
		error("Can't read version info for hci%d: %s (%d)",
					dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	dev->hci_rev = ver.hci_rev;
	dev->lmp_ver = ver.lmp_ver;
	dev->lmp_subver = ver.lmp_subver;
	dev->manufacturer = ver.manufacturer;

	if (hci_read_local_features(dd, features, 1000) < 0) {
		err = errno;
		error("Can't read features for hci%d: %s (%d)",
					dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	memcpy(dev->features, features, 8);

	if (hci_read_class_of_dev(dd, dev->class, 1000) < 0) {
		err = errno;
		error("Can't read class of device on hci%d: %s (%d)",
						dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	if (hci_read_local_name(dd, sizeof(name), name, 2000) < 0) {
		err = errno;
		error("Can't read local name on hci%d: %s (%d)",
						dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	memcpy(dev->name, name, 248);

	if (!(features[6] & LMP_SIMPLE_PAIR))
		goto setup;

	if (hcid_dbus_use_experimental()) {
		if (ioctl(dd, HCIGETAUTHINFO, NULL) < 0 && errno != EINVAL)
			hci_write_simple_pairing_mode(dd, 0x01, 2000);
	}

	if (hci_read_simple_pairing_mode(dd, &dev->ssp_mode, 1000) < 0) {
		err = errno;
		error("Can't read simple pairing mode on hci%d: %s (%d)",
						dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

setup:
	if (ver.hci_rev > 1) {
		if (features[5] & LMP_SNIFF_SUBR)
			events[5] |= 0x20;

		if (features[5] & LMP_PAUSE_ENC)
			events[5] |= 0x80;

		if (features[6] & LMP_EXT_INQ)
			events[5] |= 0x40;

		if (features[6] & LMP_NFLUSH_PKTS)
			events[7] |= 0x01;

		if (features[7] & LMP_LSTO)
			events[6] |= 0x80;

		if (features[6] & LMP_SIMPLE_PAIR) {
			events[6] |= 0x01;	/* IO Capability Request */
			events[6] |= 0x02;	/* IO Capability Response */
			events[6] |= 0x04;	/* User Confirmation Request */
			events[6] |= 0x08;	/* User Passkey Request */
			events[6] |= 0x10;	/* Remote OOB Data Request */
			events[6] |= 0x20;	/* Simple Pairing Complete */
			events[7] |= 0x04;	/* User Passkey Notification */
			events[7] |= 0x08;	/* Keypress Notification */
			events[7] |= 0x10;	/* Remote Host Supported Features Notification */
		}

		hci_send_cmd(dd, OGF_HOST_CTL, OCF_SET_EVENT_MASK,
						sizeof(events), events);
	}

	if (read_local_name(&dev->bdaddr, name) == 0) {
		memcpy(dev->name, name, 248);
		hci_write_local_name(dd, name, 5000);
        }

	update_ext_inquiry_response(dd, dev);

	inqmode = get_inquiry_mode(dev);
	if (inqmode < 1)
		goto done;

	if (hci_write_inquiry_mode(dd, inqmode, 2000) < 0) {
		err = errno;
		error("Can't write inquiry mode for hci%d: %s (%d)",
						dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

done:
	hci_close_dev(dd);

	info("Device hci%d has been activated", dev_id);

	return 0;
}

int stop_adapter(uint16_t dev_id)
{
	ASSERT_DEV_ID;

	info("Device hci%d has been disabled", dev_id);

	return 0;
}

int update_adapter(uint16_t dev_id)
{
	struct hci_dev *dev;
	int dd;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	if (dev->ignore)
		return 0;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		int err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	update_ext_inquiry_response(dd, dev);

	hci_close_dev(dd);

	return 0;
}

int get_device_address(uint16_t dev_id, char *address, size_t size)
{
	struct hci_dev *dev;

	ASSERT_DEV_ID;

	if (size < 18)
		return -ENOBUFS;

	dev = &devices[dev_id];

	return ba2str(&dev->bdaddr, address);
}

int get_device_class(uint16_t dev_id, uint8_t *cls)
{
	struct hci_dev *dev;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];
	memcpy(cls, dev->class, 3);

	return 0;
}

int set_device_class(uint16_t dev_id, uint8_t *cls)
{
	struct hci_dev *dev;

	ASSERT_DEV_ID;
	dev = &devices[dev_id];
	memcpy(dev->class, cls, 3);

	return 0;
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

	if ((dev->lmp_ver == 0x03 || dev->lmp_ver == 0x04) &&
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
	int dd, err;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	memset(&rq, 0, sizeof(rq));
	rq.ogf    = OGF_VENDOR_CMD;
	rq.ocf    = 0x000e;
	rq.cparam = req;
	rq.clen   = sizeof(req);
	rq.rparam = &buf;
	rq.rlen   = sizeof(buf);

	if (hci_send_req(dd, &rq, 2000) < 0) {
		err = errno;
		error("Can't read revision for hci%d: %s (%d)",
					dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
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

int set_simple_pairing_mode(uint16_t dev_id, uint8_t mode)
{
	struct hci_dev *dev;
	int dd;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	dev->ssp_mode = mode;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		int err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	update_ext_inquiry_response(dd, dev);

	hci_close_dev(dd);

	return 0;
}

int get_device_name(uint16_t dev_id, char *name, size_t size)
{
	char tmp[249];
	int dd, err;

	ASSERT_DEV_ID;

	memset(tmp, 0, sizeof(tmp));

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	if (hci_read_local_name(dd, sizeof(tmp), tmp, 2000) < 0) {
		err = errno;
		error("Can't read name for hci%d: %s (%d)",
					dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	hci_close_dev(dd);

	memcpy(devices[dev_id].name, tmp, 248);

	return snprintf(name, size, "%s", tmp);
}

int set_device_name(uint16_t dev_id, const char *name)
{
	struct hci_dev *dev;
	int dd, err;

	ASSERT_DEV_ID;

	dev = &devices[dev_id];

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	if (hci_write_local_name(dd, name, 5000) < 0) {
		err = errno;
		error("Can't write name for hci%d: %s (%d)",
					dev_id, strerror(err), err);
		hci_close_dev(dd);
		return -err;
	}

	strncpy((char *) dev->name, name, 248);

	update_ext_inquiry_response(dd, dev);

	hci_close_dev(dd);

	return 0;
}

int get_device_alias(uint16_t dev_id, const bdaddr_t *bdaddr, char *alias, size_t size)
{
	char filename[PATH_MAX + 1], addr[18], *tmp;
	int err;

	ASSERT_DEV_ID;

	ba2str(&devices[dev_id].bdaddr, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "aliases");

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
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "aliases");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(bdaddr, addr);

	return textfile_put(filename, addr, alias);
}

int remove_device_alias(uint16_t dev_id, const bdaddr_t *bdaddr)
{
	char filename[PATH_MAX + 1], addr[18];

	ASSERT_DEV_ID;

	ba2str(&devices[dev_id].bdaddr, addr);
	create_name(filename, PATH_MAX, STORAGEDIR, addr, "aliases");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(bdaddr, addr);

	return textfile_del(filename, addr);
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

static void device_free(gpointer user_data)
{
	struct device *device = user_data;

	if (device->agent)
		agent_destroy(device->agent, FALSE);

	g_slist_foreach(device->uuids, (GFunc) g_free, NULL);
	g_slist_free(device->uuids);

	if (device->disconn_timer)
		g_source_remove(device->disconn_timer);

	g_free(device->address);
	g_free(device->path);
	g_free(device);
}

static gboolean device_is_paired(struct device *device)
{
	struct adapter *adapter = device->adapter;
	char filename[PATH_MAX + 1], *str;
	gboolean ret;

	create_name(filename, PATH_MAX, STORAGEDIR,
			adapter->address, "linkkeys");
	str = textfile_caseget(filename, device->address);
	ret = str ? TRUE : FALSE;
	g_free(str);

	return ret;
}

static char *device_get_name(struct device *device)
{
	struct adapter *adapter = device->adapter;
	char filename[PATH_MAX + 1];

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "names");
	return textfile_caseget(filename, device->address);
}

static DBusMessage *get_properties(DBusConnection *conn,
				DBusMessage *msg, void *user_data)
{
	struct device *device = user_data;
	struct adapter *adapter = device->adapter;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	bdaddr_t src, dst;
	char path[MAX_PATH_LENGTH];
	char buf[64];
	const char *ptr;
	char *name, *ppath, **uuids;
	dbus_bool_t boolean;
	uint32_t class;
	int i;
	GSList *l;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Address */
	dbus_message_iter_append_dict_entry(&dict, "Address", DBUS_TYPE_STRING,
			&device->address);

	/* Name */
	name = device_get_name(device);
	if (name) {
		dbus_message_iter_append_dict_entry(&dict, "Name",
				DBUS_TYPE_STRING, &name);
	}

	str2ba(adapter->address, &src);
	str2ba(device->address, &dst);

	/* Class */
	if (read_remote_class(&src, &dst, &class) == 0) {
		dbus_message_iter_append_dict_entry(&dict, "Class",
				DBUS_TYPE_UINT32, &class);
	}

	/* Alias */
	if (get_device_alias(adapter->dev_id, &dst, buf, sizeof(buf)) > 0) {
		ptr = buf;
		dbus_message_iter_append_dict_entry(&dict, "Alias",
				DBUS_TYPE_STRING, &ptr);
	} else if (name) {
		dbus_message_iter_append_dict_entry(&dict, "Alias",
				DBUS_TYPE_STRING, &name);
		free(name);
	}

	/* Paired */
	boolean = device_is_paired(device);
	dbus_message_iter_append_dict_entry(&dict, "Paired",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* Trusted */
	boolean = read_trust(&src, device->address, GLOBAL_TRUST);
	dbus_message_iter_append_dict_entry(&dict, "Trusted",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* Connected */
	if (g_slist_find_custom(adapter->active_conn, &dst,
				active_conn_find_by_bdaddr))
		boolean = TRUE;
	else
		boolean = FALSE;

	dbus_message_iter_append_dict_entry(&dict, "Connected",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* UUIDs */
	uuids = g_new0(char *, g_slist_length(device->uuids) + 1);
	for (i = 0, l = device->uuids; l; l = l->next, i++)
		uuids[i] = l->data;
	dbus_message_iter_append_dict_entry(&dict, "UUIDs",
			DBUS_TYPE_ARRAY, &uuids);
	g_free(uuids);

	/* Adapter */
	snprintf(path, sizeof(path), "/hci%d", adapter->dev_id);
	ppath = path;
	dbus_message_iter_append_dict_entry(&dict, "Adapter",
			DBUS_TYPE_OBJECT_PATH, &ppath);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *set_alias(DBusConnection *conn, DBusMessage *msg,
					const char *alias, void *data)
{
	struct device *device = data;
	struct adapter *adapter = device->adapter;
	bdaddr_t bdaddr;
	int ecode;
	char *str, filename[PATH_MAX + 1], path[MAX_PATH_LENGTH];

	str2ba(device->address, &bdaddr);

	/* Remove alias if empty string */
	if (g_str_equal(alias, "")) {
		create_name(filename, PATH_MAX, STORAGEDIR, adapter->address,
				"names");
		str = textfile_caseget(filename, device->address);
		ecode = remove_device_alias(adapter->dev_id, &bdaddr);
	} else {
		str = g_strdup(alias);
		ecode = set_device_alias(adapter->dev_id, &bdaddr, alias);
	}

	if (ecode < 0)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				strerror(-ecode));

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, adapter->dev_id);

	g_dbus_emit_signal(conn, path,
					ADAPTER_INTERFACE, "RemoteAliasChanged",
					DBUS_TYPE_STRING, &device->address,
					DBUS_TYPE_STRING, &str,
					DBUS_TYPE_INVALID);

	dbus_connection_emit_property_changed(conn, dbus_message_get_path(msg),
					DEVICE_INTERFACE, "Alias",
					DBUS_TYPE_STRING, &str);

	g_free(str);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *set_trust(DBusConnection *conn, DBusMessage *msg,
					dbus_bool_t value, void *data)
{
	struct device *device = data;
	struct adapter *adapter = device->adapter;
	bdaddr_t local;
	char path[MAX_PATH_LENGTH];

	str2ba(adapter->address, &local);

	write_trust(&local, device->address, GLOBAL_TRUST, value);

	snprintf(path, sizeof(path), "%s/hci%d", BASE_PATH, adapter->dev_id);

	g_dbus_emit_signal(conn, path,
					ADAPTER_INTERFACE,
					value ? "TrustAdded" : "TrustRemoved",
					DBUS_TYPE_STRING, &device->address,
					DBUS_TYPE_INVALID);

	dbus_connection_emit_property_changed(conn, dbus_message_get_path(msg),
					DEVICE_INTERFACE, "Trusted",
					DBUS_TYPE_BOOLEAN, &value);

	return dbus_message_new_method_return(msg);
}

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static DBusMessage *set_property(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *property;

	if (!dbus_message_iter_init(msg, &iter))
		return invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return invalid_args(msg);
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("Trusted", property)) {
		dbus_bool_t value;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_BOOLEAN)
			return invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &value);

		return set_trust(conn, msg, value, data);
	} else if (g_str_equal("Alias", property)) {
		char *alias;

		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_STRING)
			return invalid_args(msg);
		dbus_message_iter_get_basic(&sub, &alias);

		return set_alias(conn, msg, alias, data);
	}

	return invalid_args(msg);
}

static void discover_services_req_exit(void *user_data)
{
	struct device *device = user_data;
	struct adapter *adapter = device->adapter;
	bdaddr_t src, dst;

	debug("DiscoverDevices requestor exited");

	str2ba(adapter->address, &src);
	str2ba(device->address, &dst);

	bt_cancel_discovery(&src, &dst);
}

static DBusMessage *discover_services(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct device *device = user_data;
	const char *pattern;
	int err;

	if (device->discov_active)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
							"Discover in progress");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
						DBUS_TYPE_INVALID) == FALSE)
		goto fail;

	if (strlen(pattern) == 0) {
		err = device_browse(device, conn, msg, NULL);
		if (err < 0)
			goto fail;
	} else {
		uuid_t uuid;

		if (bt_string2uuid(&uuid, pattern) < 0)
			return invalid_args(msg);

		err = device_browse(device, conn, msg, &uuid);
		if (err < 0)
			goto fail;
	}

	return NULL;

fail:
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
					"Discovery Failed");
}

static DBusMessage *cancel_discover(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct device *device = user_data;
	struct adapter *adapter = device->adapter;
	bdaddr_t src, dst;

	if (!device->discov_active)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				"No pending discovery");

	/* only the discover requestor can cancel the inquiry process */
	if (!device->discov_requestor ||
			strcmp(device->discov_requestor, dbus_message_get_sender(msg)))
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAuthorized",
				"Not Authorized");

 	str2ba(adapter->address, &src);
	str2ba(device->address, &dst);

	if (bt_cancel_discovery(&src, &dst) < 0)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				"No pending discover");

	return dbus_message_new_method_return(msg);
}

static gboolean disconnect_timeout(gpointer user_data)
{
	struct device *device = user_data;
	struct active_conn_info *ci;
	GSList *l;
	disconnect_cp cp;
	bdaddr_t bda;
	int dd;

	device->disconn_timer = 0;

	str2ba(device->address, &bda);
	l = g_slist_find_custom(device->adapter->active_conn,
				&bda, active_conn_find_by_bdaddr);
	if (!l)
		return FALSE;

	ci = l->data;
	dd = hci_open_dev(device->adapter->dev_id);
	if (dd < 0)
		goto fail;

	memset(&cp, 0, sizeof(cp));
	cp.handle = htobs(ci->handle);
	cp.reason = HCI_OE_USER_ENDED_CONNECTION;

	hci_send_cmd(dd, OGF_LINK_CTL, OCF_DISCONNECT,
			DISCONNECT_CP_SIZE, &cp);

	close(dd);

fail:
	return FALSE;
}

static DBusMessage *disconnect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct device *device = user_data;
	GSList *l;
	bdaddr_t bda;

	str2ba(device->address, &bda);
	l = g_slist_find_custom(device->adapter->active_conn,
				&bda, active_conn_find_by_bdaddr);
	if (!l)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotConnected",
				"Device is not connected");

	g_dbus_emit_signal(conn, device->path,
			DEVICE_INTERFACE, "DisconnectRequested",
			DBUS_TYPE_INVALID);

	device->disconn_timer = g_timeout_add_seconds(DISCONNECT_TIMER,
						disconnect_timeout, device);

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable device_methods[] = {
	{ "GetProperties",	"",	"a{sv}",	get_properties	},
	{ "SetProperty",	"sv",	"",		set_property	},
	{ "DiscoverServices",	"s",	"a{us}",	discover_services,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ "CancelDiscovery",	"",	"",		cancel_discover	},
	{ "Disconnect",		"",	"",		disconnect	},
	{ }
};

static GDBusSignalTable device_signals[] = {
	{ "PropertyChanged",		"sv"	},
	{ "DisconnectRequested",	""	},
	{ }
};

struct device *device_create(DBusConnection *conn, struct adapter *adapter,
					const gchar *address)
{
	gchar *address_up;
	struct device *device;

	device = g_try_malloc0(sizeof(struct device));
	if (device == NULL)
		return NULL;

	address_up = g_ascii_strup(address, -1);
	device->path = g_strdup_printf("/hci%d/dev_%s",
				adapter->dev_id, address_up);
	g_strdelimit(device->path, ":", '_');
	g_free(address_up);

	debug("Creating device %s", device->path);

	if (g_dbus_register_interface(conn, device->path, DEVICE_INTERFACE,
				device_methods, device_signals, NULL,
				device, device_free) == FALSE) {
		device_free(device);
		return NULL;
	}

	device->address = g_strdup(address);
	device->adapter = adapter;

	device->dev.path = device->path;
	str2ba(device->address, &device->dev.dst);
	str2ba(adapter->address, &device->dev.src);

	return device;
}

void device_remove(DBusConnection *conn, struct device *device)
{
	GSList *list;
	struct btd_device_driver *driver;
	gchar *path = g_strdup(device->path);

	debug("Removing device %s", path);

	for (list = device->drivers; list; list = list->next) {
		driver = (struct btd_device_driver *) list->data;

		driver->remove(&device->dev);
	}

	g_dbus_unregister_interface(conn, path, DEVICE_INTERFACE);

	g_free(path);
}

gint device_address_cmp(struct device *device, const gchar *address)
{
	return strcasecmp(device->address, address);
}

static int cmp_by_name(const void *data, const void *user_data)
{
	const struct btd_device_driver *dev_driver = data, *driver = user_data;

	return (strcmp(dev_driver->name, driver->name));
}

void device_probe_drivers(struct device *device, GSList *uuids)
{
	GSList *list;
	const char **uuid;
	int err;

	debug("Probe drivers for %s", device->path);

	for (list = drivers; list; list = list->next) {
		struct btd_device_driver *driver = list->data;
		gboolean do_probe = FALSE;

		for (uuid = driver->uuids; *uuid; uuid++) {
			GSList *match = g_slist_find_custom(uuids, *uuid,
					(GCompareFunc) strcasecmp);
			if (match) {
				do_probe = TRUE;
				break;
			}
		}

		if (do_probe == TRUE && !g_slist_find_custom(device->drivers,
					driver, (GCompareFunc) cmp_by_name)) {

			err = driver->probe(&device->dev);
			if (err < 0) {
				error("probe failed for driver %s",
							driver->name);
				continue;
			}

			device->drivers = g_slist_append(device->drivers,
								driver);
		}
	}

	for (list = uuids; list; list = list->next)
		device->uuids = g_slist_insert_sorted(device->uuids,
				list->data, (GCompareFunc) strcmp);
}

void device_remove_drivers(struct device *device, GSList *uuids)
{
	GSList *list;

	debug("Remove drivers for %s", device->path);

	for (list = device->drivers; list; list = list->next) {
		struct btd_device_driver *driver = list->data;
		const char **uuid;

		for (uuid = driver->uuids; *uuid; uuid++) {
			GSList *match = g_slist_find_custom(uuids, *uuid,
					(GCompareFunc) strcasecmp);

			if (!match)
				continue;

			driver->remove(&device->dev);
			device->drivers = g_slist_remove(device->drivers,
								driver);
		}
	}

	for (list = uuids; list; list = list->next)
		device->uuids = g_slist_remove(device->uuids, list->data);
}

static void iter_append_record(DBusMessageIter *dict, uint32_t handle,
							const char *record)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
							NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_UINT32, &handle);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &record);

	dbus_message_iter_close_container(dict, &entry);
}

static void discover_device_reply(struct browse_req *req, sdp_list_t *recs)
{
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	sdp_list_t *seq;

	reply = dbus_message_new_method_return(req->msg);
	if (!reply)
		return;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_UINT32_AS_STRING DBUS_TYPE_STRING_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_buf_t result;

		if (!rec)
			break;

		memset(&result, 0, sizeof(sdp_buf_t));

		convert_sdp_record_to_xml(rec, &result,
				append_and_grow_string);

		if (result.data) {
			const char *val = (char *) result.data;
			iter_append_record(&dict, rec->handle, val);
			free(result.data);
		}
	}

	dbus_message_iter_close_container(&iter, &dict);

	dbus_connection_send(req->conn, reply, NULL);
	dbus_message_unref(reply);
}

static void services_changed(struct browse_req *req)
{
	struct device *device = req->device;
	char **uuids;
	GSList *l;
	int i;

	uuids = g_new0(char *, g_slist_length(device->uuids) + 1);
	for (i = 0, l = device->uuids; l; l = l->next, i++)
		uuids[i] = l->data;

	dbus_connection_emit_property_changed(req->conn, device->path,
					DEVICE_INTERFACE, "UUIDs",
					DBUS_TYPE_ARRAY, &uuids);

	g_free(uuids);
}

static void update_services(struct browse_req *req, sdp_list_t *recs)
{
	struct device *device = req->device;
	sdp_list_t *seq;

	for (seq = recs; seq; seq = seq->next) {
		sdp_record_t *rec = (sdp_record_t *) seq->data;
		sdp_list_t *svcclass = NULL;
		gchar *uuid_str;
		GSList *l;

		if (!rec)
			break;

		if (sdp_get_service_classes(rec, &svcclass) < 0)
			continue;

		/* Extract the first element and skip the remainning */
		uuid_str = bt_uuid2string(svcclass->data);
		if (!uuid_str)
			continue;

		l = g_slist_find_custom(device->uuids, uuid_str,
				(GCompareFunc) strcmp);
		if (!l)
			req->uuids_added = g_slist_append(req->uuids_added,
					uuid_str);
		else {
			req->uuids_removed = g_slist_remove(req->uuids_removed,
					l->data);
			g_free(uuid_str);
		}

		sdp_list_free(svcclass, free);
	}
}

static void store(struct device *device)
{
	struct adapter *adapter = device->adapter;
	bdaddr_t src, dst;
	char *str;

	str2ba(adapter->address, &src);
	str2ba(device->address, &dst);

	if (!device->uuids) {
		write_device_profiles(&src, &dst, "");
		return;
	}

	str = bt_list2string(device->uuids);
	write_device_profiles(&src, &dst, str);
	g_free(str);
}

static void browse_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct browse_req *req = user_data;
	struct device *device = req->device;
	struct adapter *adapter = device->adapter;
	bdaddr_t src, dst;
	uuid_t uuid;
	DBusMessage *reply;

	if (err < 0)
		goto proceed;

	update_services(req, recs);

	/* Public browsing successful or Single record requested */
	if (req->browse == FALSE || (!req->search_uuid && recs))
		goto probe;

	if (uuid_list[++req->search_uuid]) {
		sdp_uuid16_create(&uuid, uuid_list[req->search_uuid]);
		str2ba(adapter->address, &src);
		str2ba(device->address, &dst);
		bt_search_service(&src, &dst, &uuid, browse_cb, user_data, NULL);
		return;
	}

probe:

	if (!req->uuids_added && !req->uuids_removed)
		goto proceed;

	/* Probe matching drivers for services added */
	if (req->uuids_added)
		device_probe_drivers(device, req->uuids_added);

	/* Remove drivers for services removed */
	if (req->uuids_removed)
		device_remove_drivers(device, req->uuids_removed);

	/* Store the device's profiles in the filesystem */
	store(device);

	/* Propagate services changes */
	services_changed(req);

proceed:
	if (dbus_message_is_method_call(req->msg, DEVICE_INTERFACE,
			"DiscoverServices")) {
		discover_device_reply(req, recs);
		goto cleanup;
	}

	g_dbus_emit_signal(req->conn, dbus_message_get_path(req->msg),
				ADAPTER_INTERFACE, "DeviceCreated",
				DBUS_TYPE_OBJECT_PATH, &device->path,
				DBUS_TYPE_INVALID);

	/* Reply create device request */
	reply = dbus_message_new_method_return(req->msg);
	if (!reply)
		goto cleanup;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &device->path,
							DBUS_TYPE_INVALID);

	dbus_connection_send(req->conn, reply, NULL);
	dbus_message_unref(reply);

cleanup:
	device->discov_active = 0;

	if (device->discov_requestor) {
		g_dbus_remove_watch(req->conn, device->discov_listener);
		device->discov_listener = 0;
		g_free(device->discov_requestor);
		device->discov_requestor = NULL;
	}

	if (recs != NULL)
		sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);

	dbus_message_unref(req->msg);
	dbus_connection_unref(req->conn);
	g_slist_free(req->uuids_added);
	g_slist_free(req->uuids_removed);
	g_free(req);
}

int device_browse(struct device *device, DBusConnection *conn,
			DBusMessage *msg, uuid_t *search)
{
	struct adapter *adapter = device->adapter;
	struct browse_req *req;
	bdaddr_t src, dst;
	uuid_t uuid;
	GSList *l;

	req = g_new0(struct browse_req, 1);
	req->conn = dbus_connection_ref(conn);
	req->msg = dbus_message_ref(msg);
	req->device = device;

	for (l = device->uuids; l; l = l->next)
		req->uuids_removed = g_slist_append(req->uuids_removed,
				l->data);

	str2ba(adapter->address, &src);
	str2ba(device->address, &dst);

	if (search) {
		memcpy(&uuid, search, sizeof(uuid_t));
		req->browse = FALSE;
	} else {
		sdp_uuid16_create(&uuid, uuid_list[req->search_uuid]);
		req->browse = TRUE;
	}

	device->discov_active = 1;
	device->discov_requestor = g_strdup(dbus_message_get_sender(msg));
	/* Track the request owner to cancel it
	 * automatically if the owner exits */
	device->discov_listener = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						discover_services_req_exit,
						device, NULL);

	return bt_search_service(&src, &dst, &uuid, browse_cb, req, NULL);
}

int btd_register_device_driver(struct btd_device_driver *driver)
{
	const char **uuid;

	drivers = g_slist_append(drivers, driver);

	for (uuid = driver->uuids; *uuid; uuid++) {
		debug("name %s uuid %s", driver->name, *uuid);
	}

	register_service(driver->name, driver->uuids);

	return 0;
}

void btd_unregister_device_driver(struct btd_device_driver *driver)
{
	unregister_service(driver->name);

	drivers = g_slist_remove(drivers, driver);
}
