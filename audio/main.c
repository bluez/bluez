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

#include <dbus/dbus.h>

#include "dbus.h"
#include "logging.h"

#include "manager.h"

static gboolean disable_hfp = TRUE;
static gboolean sco_hci = FALSE;

static GMainLoop *main_loop = NULL;

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void read_config(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;
	gboolean no_hfp;
	char *sco_routing;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		g_key_file_free(keyfile);
		return;
	}

	sco_routing = g_key_file_get_string(keyfile, "General",
						"SCORouting", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	} else {
		if (strcmp(sco_routing, "PCM") == 0)
			sco_hci = FALSE;
		else if (strcmp(sco_routing, "HCI") == 0)
			sco_hci = TRUE;
		else
			error("Invalid Headset Routing value: %s",
					sco_routing);
		g_free(sco_routing);
	}

	no_hfp = g_key_file_get_boolean(keyfile, "Headset",
						"DisableHFP", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	} else
		disable_hfp = no_hfp;

	debug("Config options: DisableHFP=%s, SCORouting=%s",
			disable_hfp ? "true" : "false",
			sco_hci ? "HCI" : "PCM");

	g_key_file_free(keyfile);
}

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	struct sigaction sa;

	start_logging("audio", "Bluetooth Audio daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	enable_debug();

	read_config(CONFIGDIR "/audio.conf");

	main_loop = g_main_loop_new(NULL, FALSE);

	conn = dbus_bus_system_setup_with_main_loop(NULL, NULL, NULL);
	if (!conn) {
		g_main_loop_unref(main_loop);
		exit(1);
	}

	if (unix_init() < 0) {
		error("Unable to setup unix socket");
		exit(1);
	}

	if (audio_init(conn, disable_hfp, sco_hci) < 0) {
		error("Audio init failed!");
		exit(1);
	}

	if (argc > 1 && !strcmp(argv[1], "-s"))
		register_external_service(conn, "audio", "Audio service", "");

	g_main_loop_run(main_loop);

	audio_exit();

	unix_exit();

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
