/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>

#include <bluetooth/bluetooth.h>

#include <glib.h>

#include "plugin.h"
#include "log.h"

static struct nl_handle *handle;
static struct nl_cache *cache;
static struct genl_family *family;

static GIOChannel *channel;

static gboolean channel_callback(GIOChannel *chan,
					GIOCondition cond, void *user_data)
{
	int err;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		return FALSE;

	DBG("Message available on netlink channel");

	err = nl_recvmsgs_default(handle);

	return TRUE;
}

static int create_channel(int fd)
{
	channel = g_io_channel_unix_new(fd);
	if (channel == NULL)
		return -ENOMEM;

	g_io_add_watch(channel, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
						channel_callback, NULL);

	return 0;
}

static int netlink_init(void)
{
	info("Starting experimental netlink support");

	handle = nl_handle_alloc();
	if (!handle) {
		error("Failed to allocate netlink handle");
		return -ENOMEM;
	}

	if (genl_connect(handle) < 0) {
		error("Failed to connect to generic netlink");
		nl_handle_destroy(handle);
		return -ENOLINK;
	}

	cache = genl_ctrl_alloc_cache(handle);
	if (!cache) {
		error("Failed to allocate generic netlink cache");
		nl_handle_destroy(handle);
		return -ENOMEM;
	}

	family = genl_ctrl_search_by_name(cache, "bluetooth");
	if (!family) {
		error("Failed to find Bluetooth netlink family");
		nl_cache_free(cache);
		nl_handle_destroy(handle);
		return -ENOENT;
	}

	if (create_channel(nl_socket_get_fd(handle)) < 0)  {
		error("Failed to create netlink IO channel");
		genl_family_put(family);
		nl_cache_free(cache);
		nl_handle_destroy(handle);
		return -ENOMEM;
	}

	return 0;
}

static void netlink_exit(void)
{
	g_io_channel_unref(channel);

	genl_family_put(family);
	nl_cache_free(cache);
	nl_handle_destroy(handle);
}

BLUETOOTH_PLUGIN_DEFINE(netlink, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_DEFAULT, netlink_init, netlink_exit)
