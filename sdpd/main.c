/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2001-2002  Nokia Corporation
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2007  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2002-2003  Stephen Crane <steve.crane@rococosoft.com>
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
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <sys/un.h>
#include <netinet/in.h>

#include "glib-ectomy.h"

#include "sdpd.h"
#include "logging.h"

static GMainLoop *event_loop;

static int l2cap_sock, unix_sock;

/*
 * SDP server initialization on startup includes creating the
 * l2cap and unix sockets over which discovery and registration clients
 * access us respectively
 */
static int init_server(uint16_t mtu, int master, int public)
{
	struct l2cap_options opts;
	struct sockaddr_l2 l2addr;
	struct sockaddr_un unaddr;
	socklen_t optlen;

	/* Register the public browse group root */
	register_public_browse_group(public);

	/* Register the SDP server's service record */
	register_server_service(public);

	/* Create L2CAP socket */
	l2cap_sock = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (l2cap_sock < 0) {
		error("opening L2CAP socket: %s", strerror(errno));
		return -1;
	}

	memset(&l2addr, 0, sizeof(l2addr));
	l2addr.l2_family = AF_BLUETOOTH;
	bacpy(&l2addr.l2_bdaddr, BDADDR_ANY);
	l2addr.l2_psm = htobs(SDP_PSM);

	if (bind(l2cap_sock, (struct sockaddr *) &l2addr, sizeof(l2addr)) < 0) {
		error("binding L2CAP socket: %s", strerror(errno));
		return -1;
	}

	if (master) {
		int opt = L2CAP_LM_MASTER;
		if (setsockopt(l2cap_sock, SOL_L2CAP, L2CAP_LM, &opt, sizeof(opt)) < 0) {
			error("setsockopt: %s", strerror(errno));
			return -1;
		}
	}

	if (mtu > 0) {
		memset(&opts, 0, sizeof(opts));
		optlen = sizeof(opts);

		if (getsockopt(l2cap_sock, SOL_L2CAP, L2CAP_OPTIONS, &opts, &optlen) < 0) {
			error("getsockopt: %s", strerror(errno));
			return -1;
		}

		opts.imtu = mtu;

		if (setsockopt(l2cap_sock, SOL_L2CAP, L2CAP_OPTIONS, &opts, sizeof(opts)) < 0) {
			error("setsockopt: %s", strerror(errno));
			return -1;
		}
	}

	listen(l2cap_sock, 5);

	/* Create local Unix socket */
	unix_sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (unix_sock < 0) {
		error("opening UNIX socket: %s", strerror(errno));
		return -1;
	}

	memset(&unaddr, 0, sizeof(unaddr));
	unaddr.sun_family = AF_UNIX;
	strcpy(unaddr.sun_path, SDP_UNIX_PATH);

	unlink(unaddr.sun_path);

	if (bind(unix_sock, (struct sockaddr *) &unaddr, sizeof(unaddr)) < 0) {
		error("binding UNIX socket: %s", strerror(errno));
		return -1;
	}

	listen(unix_sock, 5);

	chmod(SDP_UNIX_PATH, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

	return 0;
}

static gboolean io_session_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	sdp_pdu_hdr_t hdr;
	uint8_t *buf;
	int sk, len, size;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	len = recv(sk, &hdr, sizeof(sdp_pdu_hdr_t), MSG_PEEK);
	if (len <= 0) {
		sdp_svcdb_collect_all(sk);
		return FALSE;
	}

	size = sizeof(sdp_pdu_hdr_t) + ntohs(hdr.plen);
	buf = malloc(size);
	if (!buf)
		return TRUE;

	len = recv(sk, buf, size, 0);
	if (len <= 0) {
		sdp_svcdb_collect_all(sk);
		return FALSE;
	}
		
	handle_request(sk, buf, len);

	return TRUE;
}

static gboolean io_accept_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	GIOChannel *io;
	int nsk;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	if (data == &l2cap_sock) {
		struct sockaddr_l2 addr;
		socklen_t len = sizeof(addr);

		nsk = accept(l2cap_sock, (struct sockaddr *) &addr, &len);
	} else if (data == &unix_sock) {
		struct sockaddr_un addr;
		socklen_t len = sizeof(addr);

		nsk = accept(unix_sock, (struct sockaddr *) &addr, &len);
	} else
		return FALSE;

	if (nsk < 0) {
		error("Can't accept connection: %s", strerror(errno));
		return TRUE;
	}

	io = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(io, TRUE);

	g_io_add_watch(io, G_IO_IN, io_session_event, data);

	return TRUE;
}

static void sig_term(int sig)
{
	g_main_quit(event_loop);
}

static void sig_hup(int sig)
{
}

static void usage(void)
{
	printf("sdpd - SDP daemon ver %s\n", VERSION);
	printf("Usage: \n");
	printf("\tsdpd [-n]\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "nodaemon",	0, 0, 'n' },
	{ "mtu",	1, 0, 'm' },
	{ "public",	0, 0, 'p' },
	{ "master",	0, 0, 'M' },
	{ 0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
	struct sigaction sa;
	GIOChannel *l2cap_io, *unix_io;
	uint16_t mtu = 0;
	int opt, daemonize = 1, public = 0, master = 0;

	while ((opt = getopt_long(argc, argv, "nm:pM", main_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		case 'm':
			mtu = atoi(optarg);
			break;

		case 'p':
			public = 1;
			break;

		case 'M':
			master = 1;
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (daemonize && daemon(0, 0)) {
		error("Server startup failed: %s (%d)", strerror(errno), errno);
		exit(1);
	}

	umask(0077);

	start_logging("sdpd", "Bluetooth SDP daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

#ifdef SDP_DEBUG
	enable_debug();
#endif

	if (init_server(mtu, master, public) < 0) {
		error("Server initialization failed");
		exit(1);
	}

	/* Create event loop */
	event_loop = g_main_loop_new(NULL, FALSE);

	l2cap_io = g_io_channel_unix_new(l2cap_sock);
	g_io_channel_set_close_on_unref(l2cap_io, TRUE);

	g_io_add_watch(l2cap_io, G_IO_IN, io_accept_event, &l2cap_sock);

	unix_io = g_io_channel_unix_new(unix_sock);
	g_io_channel_set_close_on_unref(unix_io, TRUE);

	g_io_add_watch(unix_io, G_IO_IN, io_accept_event, &unix_sock);

	/* Start event processor */
	g_main_run(event_loop);

	sdp_svcdb_reset();

	g_main_loop_unref(event_loop);

	g_io_channel_unref(unix_io);

	g_io_channel_unref(l2cap_io);

	info("Exit");

	stop_logging();

	return 0;
}
