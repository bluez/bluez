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

#include <unistd.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "log.h"

#include "glib-helper.h"
#include "btio.h"
#include "adapter.h"
#include "device.h"
#include "server.h"

static GSList *servers = NULL;
struct input_server {
	bdaddr_t src;
	GIOChannel *ctrl;
	GIOChannel *intr;
	GIOChannel *confirm;
};

static gint server_cmp(gconstpointer s, gconstpointer user_data)
{
	const struct input_server *server = s;
	const bdaddr_t *src = user_data;

	return bacmp(&server->src, src);
}

static void connect_event_cb(GIOChannel *chan, GError *err, gpointer data)
{
	uint16_t psm;
	bdaddr_t src, dst;
	GError *gerr = NULL;
	int ret;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, BT_IO_L2CAP, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_PSM, &psm,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	DBG("Incoming connection on PSM %d", psm);

	ret = input_device_set_channel(&src, &dst, psm, chan);
	if (ret == 0)
		return;

	/* Send unplug virtual cable to unknown devices */
	if (ret == -ENOENT && psm == L2CAP_PSM_HIDP_CTRL) {
		unsigned char unplug = 0x15;
		int err, sk = g_io_channel_unix_get_fd(chan);
		err = write(sk, &unplug, sizeof(unplug));
	}

	g_io_channel_shutdown(chan, TRUE, NULL);
}

static void auth_callback(DBusError *derr, void *user_data)
{
	struct input_server *server = user_data;
	bdaddr_t src, dst;
	GError *err = NULL;

	bt_io_get(server->confirm, BT_IO_L2CAP, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto reject;
	}

	if (derr) {
		error("Access denied: %s", derr->message);
		goto reject;
	}

	if (!bt_io_accept(server->confirm, connect_event_cb, server,
				NULL, &err)) {
		error("bt_io_accept: %s", err->message);
		g_error_free(err);
		goto reject;
	}

	g_io_channel_unref(server->confirm);
	server->confirm = NULL;

	return;

reject:
	g_io_channel_shutdown(server->confirm, TRUE, NULL);
	g_io_channel_unref(server->confirm);
	server->confirm = NULL;
	input_device_close_channels(&src, &dst);
}

static void confirm_event_cb(GIOChannel *chan, gpointer user_data)
{
	struct input_server *server = user_data;
	bdaddr_t src, dst;
	GError *err = NULL;
	int ret;

	bt_io_get(chan, BT_IO_L2CAP, &err,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	if (server->confirm) {
		error("Refusing connection: setup in progress");
		goto drop;
	}

	server->confirm = g_io_channel_ref(chan);

	ret = btd_request_authorization(&src, &dst, HID_UUID,
					auth_callback, server);
	if (ret == 0)
		return;

	g_io_channel_unref(server->confirm);
	server->confirm = NULL;

drop:
	input_device_close_channels(&src, &dst);
	g_io_channel_shutdown(chan, TRUE, NULL);
}

int server_start(const bdaddr_t *src)
{
	struct input_server *server;
	GError *err = NULL;

	server = g_new0(struct input_server, 1);
	bacpy(&server->src, src);

	server->ctrl = bt_io_listen(BT_IO_L2CAP, connect_event_cb, NULL,
				server, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_CTRL,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!server->ctrl) {
		error("Failed to listen on control channel");
		g_error_free(err);
		g_free(server);
		return -1;
	}

	server->intr = bt_io_listen(BT_IO_L2CAP, NULL, confirm_event_cb,
				server, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_INTR,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_LOW,
				BT_IO_OPT_INVALID);
	if (!server->intr) {
		error("Failed to listen on interrupt channel");
		g_io_channel_unref(server->ctrl);
		g_error_free(err);
		g_free(server);
		return -1;
	}

	servers = g_slist_append(servers, server);

	return 0;
}

void server_stop(const bdaddr_t *src)
{
	struct input_server *server;
	GSList *l;

	l = g_slist_find_custom(servers, src, server_cmp);
	if (!l)
		return;

	server = l->data;

	g_io_channel_shutdown(server->intr, TRUE, NULL);
	g_io_channel_unref(server->intr);

	g_io_channel_shutdown(server->ctrl, TRUE, NULL);
	g_io_channel_unref(server->ctrl);

	servers = g_slist_remove(servers, server);
	g_free(server);
}
