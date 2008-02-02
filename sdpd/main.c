/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2001-2002  Nokia Corporation
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>

#include <glib.h>

#include "logging.h"
#include "sdpd.h"

static GMainLoop *event_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(event_loop);
}

static void sig_hup(int sig)
{
}

static void sig_debug(int sig)
{
	toggle_debug();
}

static void usage(void)
{
	printf("sdpd - SDP daemon ver %s\n", VERSION);
	printf("Usage: \n");
	printf("\tsdpd [-n] [-d] [-m mtu] [-p]\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "nodaemon",	0, 0, 'n' },
	{ "mtu",	1, 0, 'm' },
	{ "master",	0, 0, 'M' },
	{ 0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
	struct sigaction sa;
	uint16_t mtu = 0;
	uint32_t flags = SDP_SERVER_COMPAT;
	int opt, daemonize = 1, debug = 0;

	while ((opt = getopt_long(argc, argv, "ndm:M", main_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		case 'd':
			debug = 1;
			break;

		case 'm':
			mtu = atoi(optarg);
			break;

		case 'M':
			flags |= SDP_SERVER_MASTER;
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

	sa.sa_handler = sig_debug;
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	if (debug) {
		info("Enabling debug information");
		enable_debug();
	}

	event_loop = g_main_loop_new(NULL, FALSE);

	if (start_sdp_server(mtu, NULL, flags) < 0) {
		g_main_loop_unref(event_loop);
		exit(1);
	}

	g_main_loop_run(event_loop);

	stop_sdp_server();

	g_main_loop_unref(event_loop);

	info("Exit");

	stop_logging();

	return 0;
}
