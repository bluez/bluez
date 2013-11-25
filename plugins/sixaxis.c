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
#include <glib.h>
#include <libudev.h>

#include "plugin.h"
#include "log.h"

static struct udev *ctx = NULL;
static struct udev_monitor *monitor = NULL;
static guint watch_id = 0;

static void device_added(struct udev_device *udevice)
{
	DBG("");
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
