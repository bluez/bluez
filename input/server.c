/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include "logging.h"

#include "glib-helper.h"
#include "btio.h"
#include "adapter.h"
#include "device.h"
#include "server.h"

static GSList *servers = NULL;
struct server {
	bdaddr_t src;
	GIOChannel *ctrl;
	GIOChannel *intr;
};

struct authorization_data {
	bdaddr_t src;
	bdaddr_t dst;
};

static gint server_cmp(gconstpointer s, gconstpointer user_data)
{
	const struct server *server = s;
	const bdaddr_t *src = user_data;

	return bacmp(&server->src, src);
}

static void auth_callback(DBusError *derr, void *user_data)
{
	struct authorization_data *auth = user_data;

	if (derr) {
		error("Access denied: %s", derr->message);

		input_device_close_channels(&auth->src, &auth->dst);
	} else
		input_device_connadd(&auth->src, &auth->dst);

	g_free(auth);
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

	debug("Incoming connection on PSM %d", psm);

	ret = input_device_set_channel(&src, &dst, psm, chan);
	if (ret < 0) {
		/* Send unplug virtual cable to unknown devices */
		if (ret == -ENOENT && psm == L2CAP_PSM_HIDP_CTRL) {
			unsigned char unplug = 0x15;
			int err, sk = g_io_channel_unix_get_fd(chan);
			err = write(sk, &unplug, sizeof(unplug));
		}
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	if (psm == L2CAP_PSM_HIDP_INTR) {
		struct authorization_data *auth;

		auth = g_new0(struct authorization_data, 1);
		bacpy(&auth->src, &src);
		bacpy(&auth->dst, &dst);

		ret = btd_request_authorization(&src, &dst, HID_UUID,
							auth_callback, auth);
		if (ret < 0) {
			g_free(auth);
			input_device_close_channels(&src, &dst);
		}
	}
}

int server_start(const bdaddr_t *src)
{
	struct server *server;
	GIOChannel *ctrl_io, *intr_io;
	GError *err = NULL;

	ctrl_io = bt_io_listen(BT_IO_L2CAP, connect_event_cb, NULL,
				NULL, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_CTRL,
				BT_IO_OPT_INVALID);
	if (!ctrl_io) {
		error("Failed to listen on control channel");
		g_error_free(err);
		return -1;
	}

	intr_io = bt_io_listen(BT_IO_L2CAP, connect_event_cb, NULL,
				NULL, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_PSM, L2CAP_PSM_HIDP_INTR,
				BT_IO_OPT_INVALID);
	if (!intr_io) {
		error("Failed to listen on interrupt channel");
		g_io_channel_unref(ctrl_io);
		g_error_free(err);
		return -1;
	}

	server = g_new0(struct server, 1);
	bacpy(&server->src, src);
	server->ctrl = ctrl_io;
	server->intr = intr_io;

	servers = g_slist_append(servers, server);

	return 0;
}

void server_stop(const bdaddr_t *src)
{
	struct server *server;
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
