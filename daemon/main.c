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
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>

#include <dbus/dbus.h>

#include "glib-ectomy.h"
#include "logging.h"

#include "hcid.h"
#include "sdpd.h"

static GMainLoop *event_loop;

static void sig_term(int sig)
{
	g_main_quit(event_loop);
}

static void sig_hup(int sig)
{
}

static void usage(void)
{
	printf("bluetoothd - Bluetooth daemon ver %s\n\n", VERSION);
	printf("Usage:\n\tbluetoothd [-n]\n");
}

static struct option main_options[] = {
	{ "help",	0, 0, 'h' },
	{ "nodaemon",	0, 0, 'n' },
	{ 0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int opt, daemonize = 1;

	while ((opt = getopt_long(argc, argv, "nh", main_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		case 'h':
			usage();
			exit(0);

		default:
			usage();
			exit(1);
		}
	}

	if (daemonize && daemon(0, 0)) {
		error("Daemon startup failed: %s (%d)", strerror(errno), errno);
		exit(1);
	}

	umask(0077);

	start_logging("bluetoothd", "Bluetooth daemon");

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

	enable_debug();

	event_loop = g_main_loop_new(NULL, FALSE);

	g_main_run(event_loop);

	g_main_loop_unref(event_loop);

	info("Exit");

	stop_logging();

	return 0;
}
