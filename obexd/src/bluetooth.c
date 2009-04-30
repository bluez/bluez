/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "bluetooth.h"
#include "obex.h"
#include "dbus.h"
#include "btio.h"

#define BT_RX_MTU 32767
#define BT_TX_MTU 32767

static GSList *servers = NULL;

static void connect_event(GIOChannel *io, GError *err, gpointer user_data)
{
	struct server *server = user_data;
	gint sk;

	if (err) {
		error("%s", err->message);
		return;
	}

	sk = g_io_channel_unix_get_fd(io);

	if (obex_session_start(sk, server) == 0)
		return;

	g_io_channel_shutdown(io, TRUE, NULL);
}

static void confirm_event(GIOChannel *io, gpointer user_data)
{
	struct server *server = user_data;
	GError *err = NULL;
	char address[18];
	guint8 channel;

	bt_io_get(io, BT_IO_RFCOMM, &err,
			BT_IO_OPT_DEST, address,
			BT_IO_OPT_CHANNEL, &channel,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	info("New connection from: %s, channel %u", address, channel);
	g_io_channel_set_close_on_unref(io, FALSE);

	if (server->services != OBEX_OPP) {
		if (request_service_authorization(server, io, address) < 0)
			goto drop;

		return;
	}

	if (!bt_io_accept(io, connect_event, server, NULL, &err)) {
		error("%s", err->message);
		g_error_free(err);
		goto drop;
	}

	return;

drop:
	g_io_channel_shutdown(io, TRUE, NULL);
}

static gint server_start(struct server *server)
{
	GError *err = NULL;

	/* Listen */
	if (server->secure)
		server->io = bt_io_listen(BT_IO_RFCOMM, NULL, confirm_event,
					server, NULL, &err,
					BT_IO_OPT_CHANNEL, server->channel,
					BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
					BT_IO_OPT_INVALID);
	else
		server->io = bt_io_listen(BT_IO_RFCOMM, NULL, confirm_event,
					server, NULL, &err,
					BT_IO_OPT_CHANNEL, server->channel,
					BT_IO_OPT_INVALID);
	if (!server->io)
		goto failed;

	g_io_channel_set_close_on_unref(server->io, TRUE);

	return 0;

failed:
	error("Bluetooth server register failed: ", err->message);
	g_error_free(err);

	return -EINVAL;
}

static gint server_stop(struct server *server)
{
	if (!server->io)
		return -EINVAL;

	if (server->watch) {
		g_source_remove(server->watch);
		server->watch = 0;
	}

	g_io_channel_unref(server->io);
	server->io = NULL;

	return 0;
}

static gint server_register(guint16 service, const gchar *name, guint8 channel,
			const gchar *folder, gboolean secure,
			gboolean auto_accept, gboolean symlinks,
			const gchar *capability)
{
	struct server *server;
	int err;

	server = g_new0(struct server, 1);
	server->services = service;
	server->name = g_strdup(name);
	server->folder = g_strdup(folder);
	server->auto_accept = auto_accept;
	server->symlinks = symlinks;
	server->capability = g_strdup(capability);
	server->channel = channel;
	server->secure = secure;
	server->rx_mtu = BT_RX_MTU;
	server->tx_mtu = BT_TX_MTU;

	err = server_start(server);
	if (err < 0) {
		server_free(server);
		return err;
	}

	servers = g_slist_append(servers, server);

	register_record(server, NULL);

	return 0;
}

gint bluetooth_init(guint service, const gchar *name, const gchar *folder,
				guint8 channel, gboolean secure,
				gboolean auto_accept, gboolean symlinks,
				const gchar *capability)
{
	return server_register(service, name, channel, folder,
					secure, auto_accept, symlinks,
					capability);
}

void bluetooth_exit(void)
{
	return;
}

void bluetooth_start(void)
{
	GSList *l;

	for (l = servers; l; l = l->next) {
		struct server *server = l->data;

		if (server_start(server) < 0)
			continue;

		register_record(server, NULL);
	}
}

void bluetooth_stop(void)
{
	GSList *l;

	for (l = servers; l; l = l->next) {
		struct server *server = l->data;

		server_stop(server);
	}
}
