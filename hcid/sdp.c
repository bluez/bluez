/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>

#include "glib-ectomy.h"

#include "sdp.h"

static gboolean session_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	int sk;

	sk = g_io_channel_unix_get_fd(chan);

	sleep(1);

	close(sk);

	return FALSE;
}

static gboolean connect_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	GIOChannel *io;
	struct sockaddr_l2 addr;
	socklen_t len;
	int sk, nsk;

	syslog(LOG_INFO, "Incoming SDP connection");

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(addr);

	nsk = accept(sk, (struct sockaddr *) &addr, &len);

	io = g_io_channel_unix_new(nsk);

	g_io_add_watch(io, G_IO_IN, session_event, NULL);

	return TRUE;
}

int start_sdp_server(void)
{
	GIOChannel *io;
	struct sockaddr_l2 addr;
	int sk;

	syslog(LOG_INFO, "Starting SDP server");

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		syslog(LOG_ERR, "Can't open L2CAP socket: %s (%d)",
						strerror(errno), errno);
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, BDADDR_ANY);
	addr.l2_psm = htobs(1);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		syslog(LOG_ERR, "Can't bind L2CAP socket: %s (%d)",
						strerror(errno), errno);
		return -errno;
	}

	listen(sk, 5);

	io = g_io_channel_unix_new(sk);

	g_io_add_watch(io, G_IO_IN, connect_event, NULL);

	return 0;
}

void stop_sdp_server(void)
{
	syslog(LOG_INFO, "Stopping SDP server");
}
