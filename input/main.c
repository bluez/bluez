/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <dbus/dbus.h>

#include "dbus.h"
#include "logging.h"
#include "glib-ectomy.h"

#include "input-service.h"

static GMainLoop *main_loop;

static void usage(void)
{
	printf("bt.inputd - Bluetooth Input daemon ver %s\n", VERSION);
	printf("Usage: \n");
	printf("\tbt.inputd [-n not_daemon]\n");
}

static void sig_term(int sig)
{
	g_main_quit(main_loop);
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int opt, daemonize = 1;

	while ((opt = getopt(argc, argv, "n")) != EOF) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (daemonize && daemon(0, 0)) {
		error("Can't daemonize: %s (%d)", strerror(errno), errno);
		exit(1);
	}

	start_logging("bt.inputd", "Bluetooth Input daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	enable_debug();

	/* Create event loop */
	main_loop = g_main_new(FALSE);

	if (input_dbus_init() < 0) {
		error("Unable to get on D-Bus");
		exit(1);
	}

	g_main_run(main_loop);

	return 0;
}
