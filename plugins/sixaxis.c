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
#include "src/plugin.h"
#include "src/log.h"
#include "src/shared/util.h"

static const struct {
	const char *name;
	uint16_t source;
	uint16_t vid;
	uint16_t pid;
	uint16_t version;
} devices[] = {
	{
		.name = "Sony PLAYSTATION(R)3 Controller",
		.source = 0x0002,
		.vid = 0x054c,
		.pid = 0x0268,
		.version = 0x0000,
	},
	{
		.name = "Navigation Controller",
		.source = 0x0002,
		.vid = 0x054c,
		.pid = 0x042f,
		.version = 0x0000,
	},
};

static struct udev *ctx = NULL;
static struct udev_monitor *monitor = NULL;
static guint watch_id = 0;

static int get_device_bdaddr(int fd, bdaddr_t *bdaddr)
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

static int get_master_bdaddr(int fd, bdaddr_t *bdaddr)
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

static int set_master_bdaddr(int fd, const bdaddr_t *bdaddr)
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

static bool setup_device(int fd, int index, struct btd_adapter *adapter)
{
	char device_addr[18], master_addr[18], adapter_addr[18];
	bdaddr_t device_bdaddr, master_bdaddr;
	const bdaddr_t *adapter_bdaddr;
	struct btd_device *device;

	if (get_device_bdaddr(fd, &device_bdaddr) < 0)
		return false;

	if (get_master_bdaddr(fd, &master_bdaddr) < 0)
		return false;

	/* This can happen if controller was plugged while already connected
	 * eg. to charge up battery. */
	device = btd_adapter_find_device(adapter, &device_bdaddr,
							BDADDR_BREDR);
	if (device && btd_device_is_connected(device))
		return false;

	adapter_bdaddr = btd_adapter_get_address(adapter);

	if (bacmp(adapter_bdaddr, &master_bdaddr)) {
		if (set_master_bdaddr(fd, adapter_bdaddr) < 0)
			return false;
	}

	ba2str(&device_bdaddr, device_addr);
	ba2str(&master_bdaddr, master_addr);
	ba2str(adapter_bdaddr, adapter_addr);
	DBG("remote %s old_master %s new_master %s",
				device_addr, master_addr, adapter_addr);

	device = btd_adapter_get_device(adapter, &device_bdaddr, BDADDR_BREDR);

	if (g_slist_find_custom(btd_device_get_uuids(device), HID_UUID,
						(GCompareFunc)strcasecmp)) {
		DBG("device %s already known, skipping", device_addr);
		return true;
	}

	info("sixaxis: setting up new device");

	btd_device_device_set_name(device, devices[index].name);
	btd_device_set_pnpid(device, devices[index].source, devices[index].vid,
				devices[index].pid, devices[index].version);
	btd_device_set_temporary(device, false);

	return true;
}

static int get_supported_device(struct udev_device *udevice, uint16_t *bus)
{
	struct udev_device *hid_parent;
	uint16_t vid, pid;
	const char *hid_id;
	guint i;

	hid_parent = udev_device_get_parent_with_subsystem_devtype(udevice,
								"hid", NULL);
	if (!hid_parent)
		return -1;

	hid_id = udev_device_get_property_value(hid_parent, "HID_ID");

	if (sscanf(hid_id, "%hx:%hx:%hx", bus, &vid, &pid) != 3)
		return -1;

	for (i = 0; i < G_N_ELEMENTS(devices); i++) {
		if (devices[i].vid == vid && devices[i].pid == pid)
			return i;
	}

	return -1;
}

static void device_added(struct udev_device *udevice)
{
	struct btd_adapter *adapter;
	uint16_t bus;
	int index;
	int fd;

	adapter = btd_adapter_get_default();
	if (!adapter)
		return;

	index = get_supported_device(udevice, &bus);
	if (index < 0)
		return;
	if (bus != BUS_USB)
		return;

	info("sixaxis: compatible device connected: %s (%04X:%04X)",
				devices[index].name, devices[index].vid,
				devices[index].pid);

	fd = open(udev_device_get_devnode(udevice), O_RDWR);
	if (fd < 0)
		return;

	setup_device(fd, index, adapter);
	close(fd);
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

	return 0;
}

static void sixaxis_exit(void)
{
	DBG("");

	g_source_remove(watch_id);
	watch_id = 0;

	udev_monitor_unref(monitor);
	monitor = NULL;

	udev_unref(ctx);
	ctx = NULL;
}

BLUETOOTH_PLUGIN_DEFINE(sixaxis, VERSION, BLUETOOTH_PLUGIN_PRIORITY_LOW,
						sixaxis_init, sixaxis_exit)
