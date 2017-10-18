/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2009  Bastien Nocera <hadess@hadess.net>
 *  Copyright (C) 2011  Antonio Ospite <ospite@studenti.unina.it>
 *  Copyright (C) 2013  Szymon Janc <szymon.janc@gmail.com>
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

#include <stddef.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/hidraw.h>
#include <linux/input.h>
#include <glib.h>
#include <libudev.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/uuid.h"

#include "src/adapter.h"
#include "src/device.h"
#include "src/agent.h"
#include "src/plugin.h"
#include "src/log.h"
#include "src/shared/util.h"
#include "profiles/input/sixaxis.h"

struct authentication_closure {
	guint auth_id;
	char *sysfs_path;
	struct btd_adapter *adapter;
	struct btd_device *device;
	int fd;
	bdaddr_t bdaddr; /* device bdaddr */
	CablePairingType type;
};

struct authentication_destroy_closure {
	struct authentication_closure *closure;
	bool remove_device;
};

static struct udev *ctx = NULL;
static struct udev_monitor *monitor = NULL;
static guint watch_id = 0;
static GHashTable *pending_auths = NULL; /* key = sysfs_path (const str), value = auth_closure */

/* Make sure to unset auth_id if already handled */
static void auth_closure_destroy(struct authentication_closure *closure,
				bool remove_device)
{
	if (closure->auth_id)
		btd_cancel_authorization(closure->auth_id);

	if (remove_device)
		btd_adapter_remove_device(closure->adapter, closure->device);
	close(closure->fd);
	g_free(closure->sysfs_path);
	g_free(closure);
}

static int sixaxis_get_device_bdaddr(int fd, bdaddr_t *bdaddr)
{
	uint8_t buf[18];
	int ret;

	memset(buf, 0, sizeof(buf));

	buf[0] = 0xf2;

	ret = ioctl(fd, HIDIOCGFEATURE(sizeof(buf)), buf);
	if (ret < 0) {
		error("sixaxis: failed to read device address (%s)",
							strerror(errno));
		return ret;
	}

	baswap(bdaddr, (bdaddr_t *) (buf + 4));

	return 0;
}

static int ds4_get_device_bdaddr(int fd, bdaddr_t *bdaddr)
{
	uint8_t buf[7];
	int ret;

	memset(buf, 0, sizeof(buf));

	buf[0] = 0x81;

	ret = ioctl(fd, HIDIOCGFEATURE(sizeof(buf)), buf);
	if (ret < 0) {
		error("sixaxis: failed to read DS4 device address (%s)",
		      strerror(errno));
		return ret;
	}

	/* address is little-endian on DS4 */
	bacpy(bdaddr, (bdaddr_t*) (buf + 1));

	return 0;
}

static int get_device_bdaddr(int fd, bdaddr_t *bdaddr, CablePairingType type)
{
	if (type == CABLE_PAIRING_SIXAXIS)
		return sixaxis_get_device_bdaddr(fd, bdaddr);
	else if (type == CABLE_PAIRING_DS4)
		return ds4_get_device_bdaddr(fd, bdaddr);
	return -1;
}

static int sixaxis_get_master_bdaddr(int fd, bdaddr_t *bdaddr)
{
	uint8_t buf[8];
	int ret;

	memset(buf, 0, sizeof(buf));

	buf[0] = 0xf5;

	ret = ioctl(fd, HIDIOCGFEATURE(sizeof(buf)), buf);
	if (ret < 0) {
		error("sixaxis: failed to read master address (%s)",
							strerror(errno));
		return ret;
	}

	baswap(bdaddr, (bdaddr_t *) (buf + 2));

	return 0;
}

static int ds4_get_master_bdaddr(int fd, bdaddr_t *bdaddr)
{
	uint8_t buf[16];
	int ret;

	memset(buf, 0, sizeof(buf));

	buf[0] = 0x12;

	ret = ioctl(fd, HIDIOCGFEATURE(sizeof(buf)), buf);
	if (ret < 0) {
		error("sixaxis: failed to read DS4 master address (%s)",
		      strerror(errno));
		return ret;
	}

	/* address is little-endian on DS4 */
	bacpy(bdaddr, (bdaddr_t*) (buf + 10));

	return 0;
}

static int get_master_bdaddr(int fd, bdaddr_t *bdaddr, CablePairingType type)
{
	if (type == CABLE_PAIRING_SIXAXIS)
		return sixaxis_get_master_bdaddr(fd, bdaddr);
	else if (type == CABLE_PAIRING_DS4)
		return ds4_get_master_bdaddr(fd, bdaddr);
	return -1;
}

static int sixaxis_set_master_bdaddr(int fd, const bdaddr_t *bdaddr)
{
	uint8_t buf[8];
	int ret;

	buf[0] = 0xf5;
	buf[1] = 0x01;

	baswap((bdaddr_t *) (buf + 2), bdaddr);

	ret = ioctl(fd, HIDIOCSFEATURE(sizeof(buf)), buf);
	if (ret < 0)
		error("sixaxis: failed to write master address (%s)",
							strerror(errno));

	return ret;
}

static int ds4_set_master_bdaddr(int fd, const bdaddr_t *bdaddr)
{
	uint8_t buf[23];
	int ret;

	buf[0] = 0x13;
	bacpy((bdaddr_t*) (buf + 1), bdaddr);
	/* TODO: we could put the key here but
	   there is no way to force a re-loading
	   of link keys to the kernel from here. */
	memset(buf + 7, 0, 16);

	ret = ioctl(fd, HIDIOCSFEATURE(sizeof(buf)), buf);
	if (ret < 0)
		error("sixaxis: failed to write DS4 master address (%s)",
		      strerror(errno));

	return ret;
}

static int set_master_bdaddr(int fd, const bdaddr_t *bdaddr,
					CablePairingType type)
{
	if (type == CABLE_PAIRING_SIXAXIS)
		return sixaxis_set_master_bdaddr(fd, bdaddr);
	else if (type == CABLE_PAIRING_DS4)
		return ds4_set_master_bdaddr(fd, bdaddr);
	return -1;
}

static bool is_auth_pending(struct authentication_closure *closure)
{
	GHashTableIter iter;
	gpointer value;

	g_hash_table_iter_init(&iter, pending_auths);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		struct authentication_closure *c = value;
		if (c == closure)
			return true;
	}
	return false;
}

static gboolean auth_closure_destroy_idle(gpointer user_data)
{
	struct authentication_destroy_closure *destroy = user_data;

	auth_closure_destroy(destroy->closure, destroy->remove_device);
	g_free(destroy);

	return false;
}

static void agent_auth_cb(DBusError *derr,
				void *user_data)
{
	struct authentication_closure *closure = user_data;
	struct authentication_destroy_closure *destroy;
	char master_addr[18], adapter_addr[18], device_addr[18];
	bdaddr_t master_bdaddr;
	const bdaddr_t *adapter_bdaddr;
	bool remove_device = true;

	if (!is_auth_pending(closure))
		return;

	/* Don't try to remove this auth, we're handling it already */
	closure->auth_id = 0;

	if (derr != NULL) {
		DBG("Agent replied negatively, removing temporary device");
		goto out;
	}

	if (get_master_bdaddr(closure->fd, &master_bdaddr, closure->type) < 0)
		goto out;

	adapter_bdaddr = btd_adapter_get_address(closure->adapter);
	if (bacmp(adapter_bdaddr, &master_bdaddr)) {
		if (set_master_bdaddr(closure->fd, adapter_bdaddr, closure->type) < 0)
			goto out;
	}

	remove_device = false;
	btd_device_set_trusted(closure->device, true);
	btd_device_set_temporary(closure->device, false);

	ba2str(&closure->bdaddr, device_addr);
	ba2str(&master_bdaddr, master_addr);
	ba2str(adapter_bdaddr, adapter_addr);
	DBG("remote %s old_master %s new_master %s",
				device_addr, master_addr, adapter_addr);

out:
	g_hash_table_steal(pending_auths, closure->sysfs_path);

	/* btd_adapter_remove_device() cannot be called in this
	 * callback or it would lead to a double-free in while
	 * trying to cancel the authentication that's being processed,
	 * so clean up in an idle */
	destroy = g_new0(struct authentication_destroy_closure, 1);
	destroy->closure = closure;
	destroy->remove_device = remove_device;
	g_idle_add(auth_closure_destroy_idle, destroy);
}

static bool setup_device(int fd,
				const char *sysfs_path,
				const char *name,
				uint16_t source,
				uint16_t vid,
				uint16_t pid,
				uint16_t version,
				CablePairingType type,
				struct btd_adapter *adapter)
{
	bdaddr_t device_bdaddr;
	const bdaddr_t *adapter_bdaddr;
	struct btd_device *device;
	struct authentication_closure *closure;

	if (get_device_bdaddr(fd, &device_bdaddr, type) < 0)
		return false;

	/* This can happen if controller was plugged while already connected
	 * eg. to charge up battery. */
	device = btd_adapter_find_device(adapter, &device_bdaddr,
							BDADDR_BREDR);
	if (device && btd_device_is_connected(device))
		return false;

	device = btd_adapter_get_device(adapter, &device_bdaddr, BDADDR_BREDR);

	if (g_slist_find_custom(btd_device_get_uuids(device), HID_UUID,
						(GCompareFunc)strcasecmp)) {
		char device_addr[18];
		ba2str(&device_bdaddr, device_addr);
		DBG("device %s already known, skipping", device_addr);
		return false;
	}

	info("sixaxis: setting up new device");

	btd_device_device_set_name(device, name);
	btd_device_set_pnpid(device, source, vid, pid, version);
	btd_device_set_temporary(device, true);

	closure = g_new0(struct authentication_closure, 1);
	if (!closure) {
		btd_adapter_remove_device(adapter, device);
		return false;
	}
	closure->adapter = adapter;
	closure->device = device;
	closure->sysfs_path = g_strdup(sysfs_path);
	closure->fd = fd;
	bacpy(&closure->bdaddr, &device_bdaddr);
	closure->type = type;
	adapter_bdaddr = btd_adapter_get_address(adapter);
	closure->auth_id = btd_request_authorization_cable_configured(adapter_bdaddr, &device_bdaddr,
								HID_UUID, agent_auth_cb, closure);

	g_hash_table_insert(pending_auths, closure->sysfs_path, closure);

	return true;
}

static CablePairingType get_pairing_type_for_device(struct udev_device *udevice,
								uint16_t  *bus,
								uint16_t  *vid,
								uint16_t  *pid,
								char     **sysfs_path,
								char     **name,
								uint16_t  *source,
								uint16_t  *version)
{
	struct udev_device *hid_parent;
	const char *hid_id;
	CablePairingType ret;

	hid_parent = udev_device_get_parent_with_subsystem_devtype(udevice,
								"hid", NULL);
	if (!hid_parent)
		return -1;

	hid_id = udev_device_get_property_value(hid_parent, "HID_ID");

	if (sscanf(hid_id, "%hx:%hx:%hx", bus, vid, pid) != 3)
		return -1;

	ret = get_pairing_type(*vid, *pid, name, source, version);
	*sysfs_path = g_strdup(udev_device_get_syspath(udevice));

	return ret;
}

static void device_added(struct udev_device *udevice)
{
	struct btd_adapter *adapter;
	uint16_t bus, vid, pid, source, version;
	char *name = NULL, *sysfs_path = NULL;
	CablePairingType type;
	int fd;

	adapter = btd_adapter_get_default();
	if (!adapter)
		return;

	type = get_pairing_type_for_device(udevice,
						&bus,
						&vid,
						&pid,
						&sysfs_path,
						&name,
						&source,
						&version);
	if (type != CABLE_PAIRING_SIXAXIS &&
	    type != CABLE_PAIRING_DS4)
		return;
	if (bus != BUS_USB)
		return;

	info("sixaxis: compatible device connected: %s (%04X:%04X %s)",
				name, vid, pid, sysfs_path);

	fd = open(udev_device_get_devnode(udevice), O_RDWR);
	if (fd < 0) {
		g_free(name);
		g_free(sysfs_path);
		return;
	}

	/* Only close the fd if an authentication is not pending */
	if (!setup_device(fd, sysfs_path, name, source, vid, pid, version, type, adapter))
		close(fd);

	g_free(name);
	g_free(sysfs_path);
}

static void device_removed(struct udev_device *udevice)
{
	struct authentication_closure *closure;
	const char *sysfs_path;

	sysfs_path = udev_device_get_syspath(udevice);
	if (!sysfs_path)
		return;

	closure = g_hash_table_lookup(pending_auths, sysfs_path);
	if (!closure)
		return;

	g_hash_table_steal(pending_auths, sysfs_path);
	auth_closure_destroy(closure, true);
}

static gboolean monitor_watch(GIOChannel *source, GIOCondition condition,
							gpointer data)
{
	struct udev_device *udevice;

	udevice = udev_monitor_receive_device(monitor);
	if (!udevice)
		return TRUE;

	if (!g_strcmp0(udev_device_get_action(udevice), "add"))
		device_added(udevice);
	else if (!g_strcmp0(udev_device_get_action(udevice), "remove"))
		device_removed(udevice);

	udev_device_unref(udevice);

	return TRUE;
}

static int sixaxis_init(void)
{
	GIOChannel *channel;

	DBG("");

	ctx = udev_new();
	if (!ctx)
		return -EIO;

	monitor = udev_monitor_new_from_netlink(ctx, "udev");
	if (!monitor) {
		udev_unref(ctx);
		ctx = NULL;

		return -EIO;
	}

	/* Listen for newly connected hidraw interfaces */
	udev_monitor_filter_add_match_subsystem_devtype(monitor, "hidraw",
									NULL);
	udev_monitor_enable_receiving(monitor);

	channel = g_io_channel_unix_new(udev_monitor_get_fd(monitor));
	watch_id = g_io_add_watch(channel, G_IO_IN, monitor_watch, NULL);
	g_io_channel_unref(channel);

	pending_auths = g_hash_table_new(g_str_hash,
					g_str_equal);

	return 0;
}

static void sixaxis_exit(void)
{
	GHashTableIter iter;
	gpointer value;

	DBG("");

	g_hash_table_iter_init(&iter, pending_auths);
	while (g_hash_table_iter_next(&iter, NULL, &value)) {
		struct authentication_closure *closure = value;
		auth_closure_destroy(closure, true);
	}
	g_hash_table_destroy(pending_auths);
	pending_auths = NULL;

	g_source_remove(watch_id);
	watch_id = 0;

	udev_monitor_unref(monitor);
	monitor = NULL;

	udev_unref(ctx);
	ctx = NULL;
}

BLUETOOTH_PLUGIN_DEFINE(sixaxis, VERSION, BLUETOOTH_PLUGIN_PRIORITY_LOW,
						sixaxis_init, sixaxis_exit)
