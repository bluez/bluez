/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Nokia Corporation
 *  Copyright (C) 2007-2008  Instituto Nokia de Tecnologia (INdT)
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include "obex.h"
#include "dbus.h"

static GSList *servers = NULL;

void bluetooth_servers_foreach(GFunc func, gpointer user_data)
{
	struct server *server;
	GSList *l;

	for (l = servers; l; l = l->next) {
		server = l->data;
		func(server, user_data);
	}
}

static gboolean connect_event(GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	struct sockaddr_rc raddr;
	socklen_t alen;
	struct server *server = user_data;
	gchar address[18];
	gint err, sk, nsk;

	sk = g_io_channel_unix_get_fd(io);
	alen = sizeof(raddr);
	nsk = accept(sk, (struct sockaddr *) &raddr, &alen);
	if (nsk < 0)
		return TRUE;

	alen = sizeof(raddr);
	if (getpeername(nsk, (struct sockaddr *) &raddr, &alen) < 0) {
		err = errno;
		error("getpeername(): %s(%d)", strerror(err), err);
		close(nsk);
		return TRUE;
	}

	ba2str(&raddr.rc_bdaddr, address);
	info("New connection from: %s, channel %u, fd %d", address,
			raddr.rc_channel, nsk);

	if (server->service == OBEX_OPP) {
		if (obex_session_start(nsk, server) < 0)
			close(nsk);

		return TRUE;
	}

	if (request_service_authorization(server, nsk) < 0) {
		close(nsk);
		return TRUE;
	}

	return TRUE;
}

static void server_destroyed(gpointer user_data)
{
	struct server *server = user_data;

	error("Server destroyed");

	servers = g_slist_remove(servers, server);

	server_free(server);
}

static gint server_register(guint16 service, const gchar *name, guint8 channel,
			const gchar *folder, gboolean secure,
			gboolean auto_accept, const gchar *capability)
{
	struct sockaddr_rc laddr;
	GIOChannel *io;
	struct server *server;
	uint32_t handle;
	int err, sk, arg;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		err = errno;
		error("socket(): %s(%d)", strerror(err), err);
		return -err;
	}

	arg = fcntl(sk, F_GETFL);
	if (arg < 0) {
		err = errno;
		goto failed;
	}

	arg |= O_NONBLOCK;
	if (fcntl(sk, F_SETFL, arg) < 0) {
		err = errno;
		goto failed;
	}

	if (secure) {
		int lm = RFCOMM_LM_AUTH | RFCOMM_LM_ENCRYPT;

		if (setsockopt(sk, SOL_RFCOMM, RFCOMM_LM, &lm, sizeof(lm)) < 0) {
			err = errno;
			goto failed;
		}
	}

	memset(&laddr, 0, sizeof(laddr));
	laddr.rc_family = AF_BLUETOOTH;
	bacpy(&laddr.rc_bdaddr, BDADDR_ANY);
	laddr.rc_channel = channel;

	if (bind(sk, (struct sockaddr *) &laddr, sizeof(laddr)) < 0) {
		err = errno;
		goto failed;
	}

	if (listen(sk, 10) < 0) {
		err = errno;
		goto failed;
	}

	server = g_malloc0(sizeof(struct server));
	server->service = service;
	server->name = g_strdup(name);
	server->folder = g_strdup(folder);
	server->auto_accept = auto_accept;
	server->capability = g_strdup(capability);
	server->channel = channel;
	server->handle = handle;

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			connect_event, server, server_destroyed);
	g_io_channel_unref(io);

	servers = g_slist_append(servers, server);

	register_record(server, NULL);

	return 0;

failed:
	error("Bluetooth server register failed: %s(%d)", strerror(err), err);
	close(sk);

	return -err;
}

gint bluetooth_init(guint service, const gchar *name, const gchar *folder,
				guint8 channel, gboolean secure,
				gboolean auto_accept, const gchar *capability)
{
	return server_register(service, name, channel, folder,
					secure, auto_accept, capability);
}

void bluetooth_exit(void)
{
	return;
}
