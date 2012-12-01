/*
 *
 *  OBEX Server
 *
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>
#include <glib.h>

#include <gdbus.h>

#include <openobex/obex.h>
#include <openobex/obex_const.h>

#include "logging.h"
#include "bluetooth.h"
#include "obexd.h"
#include "obex.h"

#define OPUSH_CHANNEL	9
#define FTP_CHANNEL	10

#define DEFAULT_ROOT_PATH "/tmp"

static GMainLoop *main_loop = NULL;

static int server_start(int service, const char *root_path,
			gboolean auto_accept)
{
	/* FIXME: Necessary check enabled transports(Bluetooth/USB) */

	switch (service) {
	case OBEX_OPUSH:
		bluetooth_init(OBEX_OPUSH, "OBEX OPUSH server",
				root_path, OPUSH_CHANNEL, auto_accept);
		break;
	case OBEX_FTP:
		bluetooth_init(OBEX_FTP, "OBEX FTP server",
				root_path, FTP_CHANNEL, auto_accept);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static void server_stop()
{
	/* FIXME: If Bluetooth enabled */
	bluetooth_exit();
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void usage(void)
{
	printf("OBEX Server version %s\n\n", VERSION);

	printf("Usage:\n"
		"\tobexd [options] <server>\n"
		"\n");

	printf("Options:\n"
		"\t-n, --nodaemon       Don't fork daemon to background\n"
		"\t-d, --debug          Enable output of debug information\n"
		"\t-r, --root <path>    Specify root folder location\n"
		"\t-a, --auto-accept    Automatically accept push requests\n"
		"\t-h, --help           Display help\n");
	printf("Servers:\n"
		"\t-o, --opp            Enable OPP server\n"
		"\t-f, --ftp            Enable FTP server\n"
		"\n");
}

static struct option options[] = {
	{ "nodaemon", 0, 0, 'n' },
	{ "debug",    0, 0, 'd' },
	{ "ftp",      0, 0, 'f' },
	{ "opp",      0, 0, 'o' },
	{ "help",     0, 0, 'h' },
	{ "root",     1, 0, 'r' },
	{ "auto-accept", 0, 0, 'a' },
	{ }
};

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	DBusError err;
	struct sigaction sa;
	int log_option = LOG_NDELAY | LOG_PID;
	int opt, detach = 1, debug = 0, opush = 0, ftp = 0, auto_accept = 0;
	const char *root_path = DEFAULT_ROOT_PATH;

	while ((opt = getopt_long(argc, argv, "+ndhofr:a", options, NULL)) != EOF) {
		switch(opt) {
		case 'n':
			detach = 0;
			break;
		case 'd':
			debug = 1;
			break;
		case 'h':
		case 'o':
			opush = 1;
			break;
		case 'f':
			ftp = 1;
			break;
		case 'r':
			root_path = optarg;
			break;
		case 'a':
			auto_accept = 1;
			break;
		default:
			usage();
			exit(0);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (!(opush || ftp)) {
		fprintf(stderr, "No server selected (use either "
					"--opp or --ftp or both)\n");
		exit(1);
	}

	if (detach) {
		if (daemon(0, 0)) {
			perror("Can't start daemon");
			exit(1);
		}
	} else
		log_option |= LOG_PERROR;

	openlog("obexd", log_option, LOG_DAEMON);

	if (debug) {
		info("Enabling debug information");
		enable_debug();
	}

	main_loop = g_main_loop_new(NULL, FALSE);

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SESSION, OPENOBEX_SERVICE, &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with session bus\n");
		exit(1);
	}

	if (opush)
		server_start(OBEX_OPUSH, root_path, auto_accept);

	if (ftp)
		server_start(OBEX_FTP, root_path, auto_accept);

	if (!manager_init(conn))
		goto fail;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(main_loop);

	manager_cleanup();

	server_stop();

fail:
	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	closelog();

	return 0;
}
