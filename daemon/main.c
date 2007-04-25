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

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus-helper.h"

#include "dbus.h"
#include "notify.h"
#include "logging.h"

#include "sdpd.h"

#include "system.h"
#include "manager.h"
#include "database.h"
#include "adapter.h"
#include "service.h"

static GMainLoop *main_loop = NULL;

static DBusConnection *system_bus = NULL;

static int setup_dbus(void)
{
	system_bus = init_dbus("org.bluez", NULL, NULL);
	if (!system_bus)
		return -1;

	if (dbus_connection_create_object_path(system_bus,
					SYSTEM_PATH, NULL, NULL) == FALSE) {
		error("System path registration failed");
		dbus_connection_unref(system_bus);
		return -1;
	}

	if (manager_init(system_bus) < 0) {
		dbus_connection_destroy_object_path(system_bus, SYSTEM_PATH);
		dbus_connection_unref(system_bus);
		return -1;
	}

	if (database_init(system_bus) < 0) {
		manager_exit();
		dbus_connection_destroy_object_path(system_bus, SYSTEM_PATH);
		dbus_connection_unref(system_bus);
		return -1;
	}

	if (adapter_init(system_bus) < 0) {
		database_exit();
		manager_exit();
		dbus_connection_destroy_object_path(system_bus, SYSTEM_PATH);
		dbus_connection_unref(system_bus);
		return -1;
	}

	if (service_init(system_bus) < 0) {
		adapter_exit();
		database_exit();
		manager_exit();
		dbus_connection_destroy_object_path(system_bus, SYSTEM_PATH);
		dbus_connection_unref(system_bus);
		return -1;
	}

	return 0;
}

static void cleanup_dbus(void)
{
	service_exit();

	adapter_exit();

	database_exit();

	manager_exit();

	dbus_connection_destroy_object_path(system_bus, SYSTEM_PATH);

	dbus_connection_unref(system_bus);
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

	if (setup_dbus() < 0) {
		g_main_loop_unref(main_loop);
		exit(1);
	}

	if (start_sdp_server(0, NULL, SDP_SERVER_COMPAT) < 0) {
		cleanup_dbus();
		g_main_loop_unref(main_loop);
		exit(1);
	}

	g_main_loop_run(main_loop);

	stop_sdp_server();

	cleanup_dbus();

	notify_close();

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
