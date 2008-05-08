/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>

#include "dbus.h"

#include "plugin.h"
#include "dbus-service.h"
#include "logging.h"
#include "manager.h"

#define IFACE_PREFIX "bnep%d"
#define GN_IFACE "pan0"
#define NAP_IFACE "pan1"

#define PANU_UUID "00001115-0000-1000-8000-00805f9b34fb"
#define NAP_UUID "00001116-0000-1000-8000-00805f9b34fb"
#define GN_UUID "00001117-0000-1000-8000-00805f9b34fb"

static const char *uuids[] = {
	PANU_UUID,
	NAP_UUID,
	GN_UUID,
	NULL
};

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

static void read_config(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;
	char *disabled;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		goto done;
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
	g_free(disabled);

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

	conf.iface_prefix = g_key_file_get_string(keyfile, "PANU Role",
						"Interface", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	conf.gn_iface = g_key_file_get_string(keyfile, "GN Role",
						"Interface", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	conf.nap_iface = g_key_file_get_string(keyfile, "NAP Role",
						"Interface", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

done:
	g_key_file_free(keyfile);

	if (!conf.iface_prefix)
		conf.iface_prefix = g_strdup(IFACE_PREFIX);
	if (!conf.gn_iface)
		conf.gn_iface = g_strdup(GN_IFACE);
	if (!conf.nap_iface)
		conf.nap_iface = g_strdup(NAP_IFACE);

	debug("Config options: InterfacePrefix=%s, PANU_Script=%s, "
		"GN_Script=%s, NAP_Script=%s, GN_Interface=%s, "
		"NAP_Interface=%s, Security=%s",
		conf.iface_prefix, conf.panu_script, conf.gn_script,
		conf.nap_script, conf.gn_iface, conf.nap_iface,
		conf.security ? "true" : "false");
}

static DBusConnection *conn;

static int network_init(void)
{
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL)
		return -EIO;

	read_config(CONFIGDIR "/network.conf");

	if (network_manager_init(conn, &conf) < 0) {
		dbus_connection_unref(conn);
		return -EIO;
	}

	register_service("network");

	register_uuids("network", uuids);

	return 0;
}

static void network_exit(void)
{
	unregister_uuids("network");

	unregister_service("network");

	network_manager_exit();

	dbus_connection_unref(conn);
}

BLUETOOTH_PLUGIN_DEFINE("network", network_init, network_exit)
