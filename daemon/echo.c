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

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "glib-ectomy.h"
#include "logging.h"

static GMainLoop *main_loop = NULL;

static DBusConnection *system_bus = NULL;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void sig_hup(int sig)
{
}

int main(int argc, char *argv[])
{
	struct sigaction sa;

	start_logging("echo", "Bluetooth echo service ver %s", VERSION);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);
	sa.sa_handler = sig_hup;
	sigaction(SIGHUP, &sa, NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	system_bus = init_dbus(NULL, NULL, NULL);
	if (!system_bus) {
		error("Connection to system bus failed");
		exit(1);
	}

	g_main_loop_run(main_loop);

	dbus_connection_unref(system_bus);

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
