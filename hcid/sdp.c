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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>

#include <netinet/in.h>

#include "glib-ectomy.h"

#include "hcid.h"
#include "sdp.h"

struct session {
	uint16_t omtu;
	uint16_t imtu;
};

static void session_destory(gpointer data)
{
	struct session *session_data = data;

	debug("Cleanup of SDP session");

	if (session_data)
		free(session_data);
}

static gboolean session_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[672], *ptr = buf;
	sdp_pdu_hdr_t *hdr;
	gsize len;
	GIOError err;
	int sk, ret;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	debug("Incoming SDP transaction");

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf), &len);
	if (err == G_IO_ERROR_AGAIN)
		return TRUE;

	hdr = (sdp_pdu_hdr_t *) ptr;

	hdr->pdu_id = SDP_ERROR_RSP;
	hdr->plen = htons(2);
	memset(ptr + 5, 0, 2);

	sk = g_io_channel_unix_get_fd(chan);

	ret = write(sk, ptr, 7);

	return TRUE;
}

static gboolean connect_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	GIOChannel *io;
	struct session *session_data;
	struct sockaddr_l2 addr;
	struct l2cap_options opts;
	socklen_t optlen;
	int sk, nsk;

	debug("Incoming SDP connection");

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	nsk = accept(sk, (struct sockaddr *) &addr, &optlen);
	if (nsk < 0) {
		error("Can't accept L2CAP connection: %s (%d)",
						strerror(errno), errno);
		return TRUE;
	}

	memset(&opts, 0, sizeof(opts));
	optlen = sizeof(opts);

	if (getsockopt(sk, SOL_L2CAP, L2CAP_OPTIONS, &opts, &optlen) < 0) {
		error("Can't get L2CAP options: %s (%d)",
						strerror(errno), errno);
		close(nsk);
		return TRUE;
	}

	session_data = malloc(sizeof(*session_data));
	if (!session_data) {
		close(nsk);
		return TRUE;
	}

	memset(session_data, 0, sizeof(*session_data));

	session_data->omtu = opts.omtu;
	session_data->imtu = opts.imtu;

	io = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch_full(io, 0, G_IO_IN | G_IO_HUP | G_IO_ERR, session_event,
					session_data, session_destory);

	return TRUE;
}

int start_sdp_server(void)
{
	GIOChannel *io;
	struct sockaddr_l2 addr;
	int sk;

	info("Starting SDP server");

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (sk < 0) {
		error("Can't open L2CAP socket: %s (%d)",
						strerror(errno), errno);
		return -errno;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, BDADDR_ANY);
	addr.l2_psm = htobs(1);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("Can't bind L2CAP socket: %s (%d)",
						strerror(errno), errno);
		return -errno;
	}

	listen(sk, 5);

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN, connect_event, NULL);

	return 0;
}

void stop_sdp_server(void)
{
	info("Stopping SDP server");
}
