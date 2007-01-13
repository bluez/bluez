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
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>

#include <dbus/dbus.h>

#include "glib-ectomy.h"
#include "dbus.h"
#include "notify.h"
#include "logging.h"

#include "hcid.h"
#include "sdpd.h"

static GMainLoop *main_loop = NULL;

static DBusConnection *system_bus = NULL;

static void config_notify(int action, const char *name, void *data)
{
	switch (action) {
	case NOTIFY_CREATE:
		debug("File %s/%s created", CONFIGDIR, name);
		break;

	case NOTIFY_DELETE:
		debug("File %s/%s deleted", CONFIGDIR, name);
		break;

	case NOTIFY_MODIFY:
		debug("File %s/%s modified", CONFIGDIR, name);
		break;
	}
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
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
	printf("bluetoothd - Bluetooth daemon ver %s\n\n", VERSION);

	printf("Usage:\n\tbluetoothd [options]\n\n");

	printf("Options:\n"
		"\t--help        Display help\n"
		"\t--debug       Enable debug information\n"
		"\t--nodaemon    Run daemon in foreground\n");
}

static struct option main_options[] = {
	{ "nodaemon",	0, 0, 'n' },
	{ "debug",	0, 0, 'd' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0}
};

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int opt, debug = 0, daemonize = 1;

	while ((opt = getopt_long(argc, argv, "ndh", main_options, NULL)) != -1) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		case 'd':
			debug = 1;
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

	start_logging("bluetoothd", "Bluetooth daemon ver %s", VERSION);

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

	main_loop = g_main_loop_new(NULL, FALSE);

	notify_init();

	notify_add(CONFIGDIR, config_notify, NULL);

	system_bus = init_dbus("org.bluez", NULL, NULL);
	if (!system_bus) {
		g_main_loop_unref(main_loop);
		exit(1);
	}

	if (start_sdp_server(0, SDP_SERVER_COMPAT) < 0) {
		dbus_connection_unref(system_bus);
		g_main_loop_unref(main_loop);
		exit(1);
	}

	g_main_loop_run(main_loop);

	stop_sdp_server();

	dbus_connection_unref(system_bus);

	notify_remove(CONFIGDIR);

	notify_close();

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
