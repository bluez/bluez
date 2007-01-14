/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <string.h>
#include <signal.h>
#include <sys/stat.h>

#include <dbus/dbus.h>

#include "glib-ectomy.h"

#include "logging.h"
#include "dbus.h"

static GMainLoop *main_loop;

static DBusConnection *system_bus;

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

int main(int argc, char *argv[])
{
	struct sigaction sa;

	umask(0077);

	start_logging("transfer", "Bluetooth transfer service ver %s", VERSION);

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

	enable_debug();

	main_loop = g_main_loop_new(NULL, FALSE);

	system_bus = init_dbus("org.bluez.transfer", NULL, NULL);
	if (!system_bus) {
		g_main_loop_unref(main_loop);
		exit(1);
	}

	g_main_loop_run(main_loop);

	dbus_connection_unref(system_bus);

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
