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

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <glib.h>

#include "logging.h"
#include "dbus.h"

#include "manager.h"

static GMainLoop *main_loop;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	struct sigaction sa;

	start_logging("serial", "Bluetooth Serial Port daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	enable_debug();

	main_loop = g_main_loop_new(NULL, FALSE);

	conn = dbus_bus_system_setup_with_main_loop(NULL, NULL, NULL);
	if (!conn) {
		g_main_loop_unref(main_loop);
		exit(EXIT_FAILURE);
	}

	if (serial_init(conn) < 0) {
		dbus_connection_unref(conn);
		g_main_loop_unref(main_loop);
		exit(EXIT_FAILURE);
	}

	if (argc > 1 && !strcmp(argv[1], "-s"))
		register_external_service(conn, "serial", "Serial service", "");

	g_main_loop_run(main_loop);

	serial_exit();

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
