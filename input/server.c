/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

#include <glib.h>

#include "logging.h"
#include "server.h"

static gboolean session_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	if (cond & (G_IO_HUP | G_IO_ERR))
		return FALSE;

	debug("Incoming data session");

	return FALSE;
}

static gboolean connect_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	GIOChannel *io;
	struct sockaddr_l2 addr;
	socklen_t optlen;
	int sk, nsk;

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0)
		return TRUE;

	io = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR,
						session_event, NULL);

	g_io_channel_unref(io);

	return TRUE;
}

static GIOChannel *setup_l2cap(unsigned int psm)
{
	GIOChannel *io;
	struct sockaddr_l2 addr;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, BDADDR_ANY);
	addr.l2_psm = htobs(psm);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return NULL;
	}

	if (listen(sk, 10) < 0) {
		close(sk);
		return NULL;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN, connect_event, NULL);

	return io;
}

static GIOChannel *ctrl_io = NULL;
static GIOChannel *intr_io = NULL;

int server_start(void)
{
	ctrl_io = setup_l2cap(17);
	if (!ctrl_io)
		return -1;

	intr_io = setup_l2cap(19);
	if (!intr_io) {
		g_io_channel_unref(ctrl_io);
		ctrl_io = NULL;
	}

	return 0;
}

void server_stop(void)
{
	if (intr_io)
		g_io_channel_unref(intr_io);

	if (ctrl_io)
		g_io_channel_unref(ctrl_io);
}
