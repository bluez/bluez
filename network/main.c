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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <glib.h>

#include <bluetooth/bluetooth.h>

#include "dbus.h"
#include "logging.h"

#include "manager.h"
#include "hal.h"

#define IFACE_PREFIX "bnep%d"
#define PANU_IFACE "pan0"
#define GN_IFACE "pan1"
#define NAP_IFACE "pan2"

static GMainLoop *main_loop;

static struct network_conf conf = {
	.connection_enabled = TRUE,
	.server_enabled = TRUE,
	.iface_prefix = NULL,
	.panu_script = NULL,
	.gn_script = NULL,
	.nap_script = NULL,
	.gn_iface = NULL,
	.nap_iface = NULL,
	.security = TRUE
};

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

static void read_config(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;
	const char *disabled;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		g_key_file_free(keyfile);
		return;
	}

	disabled = g_key_file_get_string(keyfile, "General",
					"Disable", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	} else {
		if (strstr(disabled, "Connection"))
			conf.connection_enabled = FALSE;
		if (strstr(disabled, "Server"))
			conf.server_enabled = FALSE;
	}

	conf.iface_prefix = g_key_file_get_string(keyfile, "General",
						"InterfacePrefix", &err);
	if (!conf.iface_prefix)
		conf.iface_prefix = g_strdup(IFACE_PREFIX);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	conf.security = !g_key_file_get_boolean(keyfile, "General",
						"DisableSecurity", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	conf.panu_script = g_key_file_get_string(keyfile, "PANU Role",
						"Script", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	conf.gn_script = g_key_file_get_string(keyfile, "GN Role",
						"Script", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	conf.nap_script = g_key_file_get_string(keyfile, "NAP Role",
						"Script", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	conf.gn_iface = g_key_file_get_string(keyfile, "GN Role",
						"Interface", &err);
	if (!conf.gn_iface)
		conf.gn_iface = g_strdup(GN_IFACE);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	conf.nap_iface = g_key_file_get_string(keyfile, "NAP Role",
						"Interface", &err);
	if (!conf.nap_iface)
		conf.nap_iface = g_strdup(NAP_IFACE);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	debug("Config options: InterfacePrefix=%s, PANU_Script=%s, "
		"GN_Script=%s, NAP_Script=%s, GN_Interface=%s, "
		"NAP_Interface=%s, Security=%s",
		conf.iface_prefix, conf.panu_script, conf.gn_script,
		conf.nap_script, conf.gn_iface, conf.nap_iface,
		conf.security ? "true" : "false");

	g_key_file_free(keyfile);
}

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	struct sigaction sa;

	start_logging("network", "Bluetooth Network daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	enable_debug();

	read_config(CONFIGDIR "/network.conf");

	main_loop = g_main_loop_new(NULL, FALSE);

	conn = dbus_bus_system_setup_with_main_loop(NULL, NULL, NULL);
	if (!conn) {
		g_main_loop_unref(main_loop);
		exit(1);
	}

	hal_init(conn);

	hal_create_device(NULL);

	if (network_init(conn, &conf) < 0) {
		dbus_connection_unref(conn);
		g_main_loop_unref(main_loop);
		exit(1);
	}

	if (argc > 1 && !strcmp(argv[1], "-s"))
		register_external_service(conn, "network", "Network service", "");

	g_main_loop_run(main_loop);

	network_exit();

	hal_remove_device(NULL);

	hal_cleanup();

	dbus_connection_unref(conn);

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
