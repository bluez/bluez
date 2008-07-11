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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include <gdbus.h>

#include "logging.h"
#include "textfile.h"
#include "hcid.h"
#include "sdpd.h"
#include "adapter.h"
#include "dbus-common.h"
#include "error.h"
#include "dbus-hci.h"
#include "dbus-database.h"
#include "sdp-xml.h"
#include "oui.h"
#include "agent.h"
#include "device.h"
#include "glib-helper.h"

#include "manager.h"

static DBusConnection *connection = NULL;
static int default_adapter_id = -1;
static GSList *adapters = NULL;

static int device_read_bdaddr(uint16_t dev_id, const char *address)
{
	int dd, err;
	bdaddr_t bdaddr;

	dd = hci_open_dev(dev_id);
	if (dd < 0) {
		err = errno;
		error("Can't open device hci%d: %s (%d)",
					dev_id, strerror(err), err);
		return -err;
	}

	str2ba(address, &bdaddr);
	if (hci_read_bd_addr(dd, &bdaddr, 2000) < 0) {
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
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;
	struct hci_dev_info di;

	if (hci_devinfo(dev_id, &di) < 0) {
		dev->ignore = 1;
		return -errno;
	}

	if (hci_test_bit(HCI_RAW, &di.flags)) {
		info("Device hci%d is using raw mode", dev_id);
		dev->ignore = 1;
	}

	if (bacmp(&di.bdaddr, BDADDR_ANY))
		ba2str(&di.bdaddr, adapter->address);
	else {
		int err = device_read_bdaddr(dev_id, adapter->address);
		if (err < 0)
			return err;
	}
	memcpy(dev->features, di.features, 8);

	info("Device hci%d has been added", dev_id);

	return 0;
}

int remove_adapter(uint16_t dev_id)
{
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;

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
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;
	struct hci_version ver;
	uint8_t features[8], inqmode;
	uint8_t events[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00, 0x00 };
	char name[249];
	int dd, err;
	bdaddr_t bdaddr;

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

	str2ba(adapter->address, &bdaddr);
	if (read_local_name(&bdaddr, name) == 0) {
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
	info("Device hci%d has been disabled", dev_id);

	return 0;
}

int update_adapter(uint16_t dev_id)
{
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;
	int dd;

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

int get_device_class(uint16_t dev_id, uint8_t *cls)
{
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;

	memcpy(cls, dev->class, 3);

	return 0;
}

int set_device_class(uint16_t dev_id, uint8_t *cls)
{
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;

	memcpy(dev->class, cls, 3);

	return 0;
}

int set_simple_pairing_mode(uint16_t dev_id, uint8_t mode)
{
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;
	int dd;

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
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;
	char tmp[249];
	int dd, err;

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

	memcpy(dev->name, tmp, 248);

	return snprintf(name, size, "%s", tmp);
}

int set_device_name(uint16_t dev_id, const char *name)
{
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	struct hci_dev *dev = &adapter->dev;
	int dd, err;

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
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	char filename[PATH_MAX + 1], addr[18], *tmp;
	int err;

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "aliases");

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
	struct adapter *adapter = manager_find_adapter_by_id(dev_id);
	char filename[PATH_MAX + 1], addr[18];

	create_name(filename, PATH_MAX, STORAGEDIR, adapter->address, "aliases");

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	ba2str(bdaddr, addr);

	return textfile_put(filename, addr, alias);
}

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static inline DBusMessage *no_such_adapter(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".NoSuchAdapter",
			"No such adapter");
}

static inline DBusMessage *no_such_service(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".NoSuchService",
			"No such service");
}

static inline DBusMessage *failed_strerror(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".Failed",
			strerror(err));
}

static int find_by_address(const char *str)
{
	struct hci_dev_list_req *dl;
	struct hci_dev_req *dr;
	bdaddr_t ba;
	int i, sk;
	int devid = -1;

	sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (sk < 0)
		return -1;

	dl = g_malloc0(HCI_MAX_DEV * sizeof(*dr) + sizeof(*dl));

	dl->dev_num = HCI_MAX_DEV;
	dr = dl->dev_req;

	if (ioctl(sk, HCIGETDEVLIST, dl) < 0)
		goto out;

	dr = dl->dev_req;
	str2ba(str, &ba);

	for (i = 0; i < dl->dev_num; i++, dr++) {
		struct hci_dev_info di;

		if (hci_devinfo(dr->dev_id, &di) < 0)
			continue;

		if (hci_test_bit(HCI_RAW, &di.flags))
			continue;

		if (!bacmp(&ba, &di.bdaddr)) {
			devid = dr->dev_id;
			break;
		}
	}

out:
	g_free(dl);
	close(sk);
	return devid;
}

static DBusMessage *default_adapter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct adapter *adapter;

	adapter = manager_find_adapter_by_id(default_adapter_id);
	if (!adapter)
		return no_such_adapter(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &adapter->path,
				DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *find_adapter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct adapter *adapter;
	struct hci_dev_info di;
	const char *pattern;
	int dev_id;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
							DBUS_TYPE_INVALID))
		return NULL;

	/* hci_devid() would make sense to use here, except it
	   is restricted to devices which are up */
	if (!strncmp(pattern, "hci", 3) && strlen(pattern) >= 4)
		dev_id = atoi(pattern + 3);
	else
		dev_id = find_by_address(pattern);

	if (dev_id < 0)
		return no_such_adapter(msg);

	if (hci_devinfo(dev_id, &di) < 0)
		return no_such_adapter(msg);

	if (hci_test_bit(HCI_RAW, &di.flags))
		return no_such_adapter(msg);

	adapter = manager_find_adapter_by_id(dev_id);
	if (!adapter)
		return no_such_adapter(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &adapter->path,
				DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *list_adapters(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	GSList *l;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &array_iter);

	for (l = adapters; l; l = l->next) {
		struct adapter *adapter = l->data;
		struct hci_dev_info di;

		if (hci_devinfo(adapter->dev_id, &di) < 0)
			continue;

		if (hci_test_bit(HCI_RAW, &di.flags))
			continue;

		dbus_message_iter_append_basic(&array_iter,
					DBUS_TYPE_OBJECT_PATH, &adapter->path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return reply;
}

static GDBusMethodTable manager_methods[] = {
	{ "DefaultAdapter",	"",	"o",	default_adapter	},
	{ "FindAdapter",	"s",	"o",	find_adapter	},
	{ "ListAdapters",	"",	"ao",	list_adapters	},
	{ }
};

static GDBusSignalTable manager_signals[] = {
	{ "AdapterAdded",		"o"	},
	{ "AdapterRemoved",		"o"	},
	{ "DefaultAdapterChanged",	"o"	},
	{ }
};

dbus_bool_t manager_init(DBusConnection *conn, const char *path)
{
	connection = conn;

	return g_dbus_register_interface(conn, "/", MANAGER_INTERFACE,
			manager_methods, manager_signals,
			NULL, NULL, NULL);
}

void manager_cleanup(DBusConnection *conn, const char *path)
{
	g_dbus_unregister_interface(conn, "/", MANAGER_INTERFACE);
}

static gint adapter_id_cmp(gconstpointer a, gconstpointer b)
{
	const struct adapter *adapter = a;
	uint16_t id = GPOINTER_TO_UINT(b);

	return adapter->dev_id == id ? 0 : -1;
}

static gint adapter_path_cmp(gconstpointer a, gconstpointer b)
{
	const struct adapter *adapter = a;
	const char *path = b;

	return strcmp(adapter->path, path);
}

static gint adapter_address_cmp(gconstpointer a, gconstpointer b)
{
	const struct adapter *adapter = a;
	const char *address = b;

	return strcmp(adapter->address, address);
}

struct adapter *manager_find_adapter(const bdaddr_t *sba)
{
	GSList *match;
	char address[18];

	ba2str(sba, address);

	match = g_slist_find_custom(adapters, address, adapter_address_cmp);
	if (!match)
		return NULL;

	return match->data;
}

struct adapter *manager_find_adapter_by_path(const char *path)
{
	GSList *match;

	match = g_slist_find_custom(adapters, path, adapter_path_cmp);
	if (!match)
		return NULL;

	return match->data;
}

struct adapter *manager_find_adapter_by_id(int id)
{
	GSList *match;

	match = g_slist_find_custom(adapters, GINT_TO_POINTER(id), adapter_id_cmp);
	if (!match)
		return NULL;

	return match->data;
}

static void manager_add_adapter(struct adapter *adapter)
{
	g_dbus_emit_signal(connection, "/",
			MANAGER_INTERFACE, "AdapterAdded",
			DBUS_TYPE_OBJECT_PATH, &adapter->path,
			DBUS_TYPE_INVALID);

	adapters = g_slist_append(adapters, adapter);
}

static void manager_remove_adapter(struct adapter *adapter)
{
	g_dbus_emit_signal(connection, "/",
			MANAGER_INTERFACE, "AdapterRemoved",
			DBUS_TYPE_OBJECT_PATH, &adapter->path,
			DBUS_TYPE_INVALID);

	if ((default_adapter_id == adapter->dev_id || default_adapter_id < 0)) {
		int new_default = hci_get_route(NULL);

		if (new_default >= 0)
			manager_set_default_adapter(new_default);
	}

	adapters = g_slist_remove(adapters, adapter);
}

int manager_register_adapter(int id)
{
	char path[MAX_PATH_LENGTH];
	struct adapter *adapter;

	snprintf(path, sizeof(path), "/hci%d", id);

	adapter = g_try_new0(struct adapter, 1);
	if (!adapter) {
		error("Failed to alloc memory to D-Bus path register data (%s)",
				path);
		return -1;
	}

	adapter->dev_id = id;
	adapter->pdiscov_resolve_names = 1;

	if (!adapter_init(connection, path, adapter)) {
		error("Adapter interface init failed on path %s", path);
		g_free(adapter);
		return -1;
	}

	adapter->path = g_strdup(path);

	__probe_servers(path);

	manager_add_adapter(adapter);

	return 0;
}

static void reply_pending_requests(struct adapter *adapter)
{
	DBusMessage *reply;

	if (!adapter)
		return;

	/* pending bonding */
	if (adapter->bonding) {
		reply = new_authentication_return(adapter->bonding->msg,
					HCI_OE_USER_ENDED_CONNECTION);
		g_dbus_send_message(connection, reply);
		remove_pending_device(adapter);

		g_dbus_remove_watch(adapter->bonding->conn,
					adapter->bonding->listener_id);

		if (adapter->bonding->io_id)
			g_source_remove(adapter->bonding->io_id);
		g_io_channel_close(adapter->bonding->io);
		bonding_request_free(adapter->bonding);
		adapter->bonding = NULL;
	}

	/* If there is a pending reply for discovery cancel */
	if (adapter->discovery_cancel) {
		reply = dbus_message_new_method_return(adapter->discovery_cancel);
		dbus_connection_send(connection, reply, NULL);
		dbus_message_unref(reply);
		dbus_message_unref(adapter->discovery_cancel);
		adapter->discovery_cancel = NULL;
	}

	if (adapter->discov_active) {
		/* Send discovery completed signal if there isn't name
		 * to resolve */
		g_dbus_emit_signal(connection, adapter->path,
				ADAPTER_INTERFACE, "DiscoveryCompleted",
				DBUS_TYPE_INVALID);

		/* Cancel inquiry initiated by D-Bus client */
		if (adapter->discov_requestor)
			cancel_discovery(adapter);
	}

	if (adapter->pdiscov_active) {
		/* Stop periodic inquiry initiated by D-Bus client */
		if (adapter->pdiscov_requestor)
			cancel_periodic_discovery(adapter);
	}
}

static void do_unregister(gpointer data, gpointer user_data)
{
	DBusConnection *conn = user_data;
	struct btd_device *device = data;

	device_remove(conn, device);
}

int manager_unregister_adapter(int id)
{
	struct adapter *adapter;

	adapter = manager_find_adapter_by_id(id);
	if (!adapter)
		return -1;

	info("Unregister path: %s", adapter->path);

	__remove_servers(adapter->path);

	/* check pending requests */
	reply_pending_requests(adapter);

	if (adapter->agent) {
		agent_destroy(adapter->agent, FALSE);
		adapter->agent = NULL;
	}

	if (adapter->discov_requestor) {
		g_dbus_remove_watch(connection, adapter->discov_listener);
		adapter->discov_listener = 0;
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;
	}

	if (adapter->pdiscov_requestor) {
		g_dbus_remove_watch(connection, adapter->pdiscov_listener);
		adapter->pdiscov_listener = 0;
		g_free(adapter->pdiscov_requestor);
		adapter->pdiscov_requestor = NULL;
	}

	if (adapter->found_devices) {
		g_slist_foreach(adapter->found_devices,
				(GFunc) g_free, NULL);
		g_slist_free(adapter->found_devices);
		adapter->found_devices = NULL;
	}

	if (adapter->oor_devices) {
		g_slist_foreach(adapter->oor_devices,
				(GFunc) free, NULL);
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;
	}

	if (adapter->auth_reqs) {
		g_slist_foreach(adapter->auth_reqs,
				(GFunc) g_free, NULL);
		g_slist_free(adapter->auth_reqs);
		adapter->auth_reqs = NULL;
	}

	if (adapter->active_conn) {
		g_slist_foreach(adapter->active_conn,
				(GFunc) free, NULL);
		g_slist_free(adapter->active_conn);
		adapter->active_conn = NULL;
	}

	if (adapter->devices) {
		g_slist_foreach(adapter->devices, do_unregister,
							connection);
		g_slist_free(adapter->devices);
	}

	manager_remove_adapter(adapter);

	if (!adapter_cleanup(connection, adapter->path)) {
		error("Failed to unregister adapter interface on %s object",
			adapter->path);
		return -1;
	}

	g_free(adapter->path);
	g_free(adapter);

	return 0;
}

static int active_conn_append(GSList **list, bdaddr_t *bdaddr,
				uint16_t handle)
{
	struct active_conn_info *dev;

	dev = g_new0(struct active_conn_info, 1);

	bacpy(&dev->bdaddr, bdaddr);
	dev->handle = handle;

	*list = g_slist_append(*list, dev);
	return 0;
}

static void create_stored_device_from_profiles(char *key, char *value,
						void *user_data)
{
	struct adapter *adapter = user_data;
	GSList *uuids = bt_string2list(value);
	struct btd_device *device;

	device = device_create(connection, adapter, key);
	if (device) {
		device_set_temporary(device, FALSE);
		adapter->devices = g_slist_append(adapter->devices, device);
		device_probe_drivers(device, uuids);
		g_slist_free(uuids);
	}
}

static void create_stored_device_from_linkkeys(char *key, char *value,
						void *user_data)
{
	struct adapter *adapter = user_data;
	struct btd_device *device;

	if (g_slist_find_custom(adapter->devices,
				key, (GCompareFunc) device_address_cmp))
		return;

	device = device_create(connection, adapter, key);
	if (device) {
		device_set_temporary(device, FALSE);
		adapter->devices = g_slist_append(adapter->devices, device);
	}
}

static void register_devices(bdaddr_t *src, struct adapter *adapter)
{
	char filename[PATH_MAX + 1];
	char addr[18];

	ba2str(src, addr);

	create_name(filename, PATH_MAX, STORAGEDIR, addr, "profiles");
	textfile_foreach(filename, create_stored_device_from_profiles, adapter);

	create_name(filename, PATH_MAX, STORAGEDIR, addr, "linkkeys");
	textfile_foreach(filename, create_stored_device_from_linkkeys, adapter);
}

int manager_start_adapter(int id)
{
	struct hci_dev_info di;
	struct adapter* adapter;
	struct hci_conn_list_req *cl = NULL;
	struct hci_conn_info *ci;
	const char *mode;
	int i, dd = -1, ret = -1;

	if (hci_devinfo(id, &di) < 0) {
		error("Getting device info failed: hci%d", id);
		return -1;
	}

	if (hci_test_bit(HCI_RAW, &di.flags))
		return -1;

	adapter = manager_find_adapter_by_id(id);
	if (!adapter) {
		error("Getting device data failed: hci%d", id);
		return -1;
	}

	if (hci_test_bit(HCI_INQUIRY, &di.flags))
		adapter->discov_active = 1;
	else
		adapter->discov_active = 0;

	adapter->up = 1;
	adapter->discov_timeout = get_discoverable_timeout(id);
	adapter->discov_type = DISCOVER_TYPE_NONE;

	dd = hci_open_dev(id);
	if (dd < 0)
		goto failed;

	adapter->scan_enable = get_startup_scan(id);
	hci_send_cmd(dd, OGF_HOST_CTL, OCF_WRITE_SCAN_ENABLE,
					1, &adapter->scan_enable);

	adapter->mode = get_startup_mode(id);
	if (adapter->mode == MODE_LIMITED)
		set_limited_discoverable(dd, adapter->dev.class, TRUE);

	/*
	 * retrieve the active connections: address the scenario where
	 * the are active connections before the daemon've started
	 */

	cl = g_malloc0(10 * sizeof(*ci) + sizeof(*cl));

	cl->dev_id = id;
	cl->conn_num = 10;
	ci = cl->conn_info;

	if (ioctl(dd, HCIGETCONNLIST, cl) < 0)
		goto failed;

	for (i = 0; i < cl->conn_num; i++, ci++)
		active_conn_append(&adapter->active_conn,
					&ci->bdaddr, ci->handle);

	ret = 0;

	mode = mode2str(adapter->mode);

	dbus_connection_emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Mode",
					DBUS_TYPE_STRING, &mode);

	if (manager_get_default_adapter() < 0)
		manager_set_default_adapter(id);

	register_devices(&di.bdaddr, adapter);

failed:
	if (dd >= 0)
		hci_close_dev(dd);

	g_free(cl);

	return ret;
}

int manager_stop_adapter(int id)
{
	struct adapter *adapter;
	const char *mode = "off";

	adapter = manager_find_adapter_by_id(id);
	if (!adapter) {
		error("Getting device data failed: hci%d", id);
		return -1;
	}

	/* cancel pending timeout */
	if (adapter->timeout_id) {
		g_source_remove(adapter->timeout_id);
		adapter->timeout_id = 0;
	}

	/* check pending requests */
	reply_pending_requests(adapter);

	if (adapter->discov_requestor) {
		g_dbus_remove_watch(connection, adapter->discov_listener);
		adapter->discov_listener = 0;
		g_free(adapter->discov_requestor);
		adapter->discov_requestor = NULL;
	}

	if (adapter->pdiscov_requestor) {
		g_dbus_remove_watch(connection, adapter->pdiscov_listener);
		adapter->pdiscov_listener = 0;
		g_free(adapter->pdiscov_requestor);
		adapter->pdiscov_requestor = NULL;
	}

	if (adapter->found_devices) {
		g_slist_foreach(adapter->found_devices, (GFunc) g_free, NULL);
		g_slist_free(adapter->found_devices);
		adapter->found_devices = NULL;
	}

	if (adapter->oor_devices) {
		g_slist_foreach(adapter->oor_devices, (GFunc) free, NULL);
		g_slist_free(adapter->oor_devices);
		adapter->oor_devices = NULL;
	}

	if (adapter->auth_reqs) {
		g_slist_foreach(adapter->auth_reqs, (GFunc) g_free, NULL);
		g_slist_free(adapter->auth_reqs);
		adapter->auth_reqs = NULL;
	}

	if (adapter->active_conn) {
		g_slist_foreach(adapter->active_conn, (GFunc) g_free, NULL);
		g_slist_free(adapter->active_conn);
		adapter->active_conn = NULL;
	}

	dbus_connection_emit_property_changed(connection, adapter->path,
					ADAPTER_INTERFACE, "Mode",
					DBUS_TYPE_STRING, &mode);

	adapter->up = 0;
	adapter->scan_enable = SCAN_DISABLED;
	adapter->mode = MODE_OFF;
	adapter->discov_active = 0;
	adapter->pdiscov_active = 0;
	adapter->pinq_idle = 0;
	adapter->discov_type = DISCOVER_TYPE_NONE;

	return 0;
}

int manager_get_default_adapter()
{
	return default_adapter_id;
}

void manager_set_default_adapter(int id)
{
	struct adapter *adapter = manager_find_adapter_by_id(id);

	default_adapter_id = id;

	g_dbus_emit_signal(connection, "/",
			MANAGER_INTERFACE,
			"DefaultAdapterChanged",
			DBUS_TYPE_OBJECT_PATH, &adapter->path,
			DBUS_TYPE_INVALID);
}
