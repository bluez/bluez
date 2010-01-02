/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <gdbus.h>

#include "logging.h"

#include "adapter.h"
#include "device.h"
#include "bridge.h"
#include "manager.h"
#include "common.h"
#include "connection.h"
#include "server.h"

#define IFACE_PREFIX "bnep%d"
#define GN_IFACE  "pan0"
#define NAP_IFACE "pan1"

static struct btd_adapter_driver network_panu_server_driver;
static struct btd_adapter_driver network_gn_server_driver;
static struct btd_adapter_driver network_nap_server_driver;

static DBusConnection *connection = NULL;

static struct network_conf {
	gboolean connection_enabled;
	gboolean server_enabled;
	gboolean security;
	char *iface_prefix;
	char *panu_script;
	char *gn_script;
	char *nap_script;
	char *gn_iface;
	char *nap_iface;
} conf = {
	.connection_enabled = TRUE,
	.server_enabled = TRUE,
	.security = TRUE,
	.iface_prefix = NULL,
	.panu_script = NULL,
	.gn_script = NULL,
	.nap_script = NULL,
	.gn_iface = NULL,
	.nap_iface = NULL
};

static void conf_cleanup(void)
{
	g_free(conf.iface_prefix);
	g_free(conf.panu_script);
	g_free(conf.gn_script);
	g_free(conf.nap_script);
	g_free(conf.gn_iface);
	g_free(conf.nap_iface);
}

static void read_config(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;
	char **disabled;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_clear_error(&err);
		goto done;
	}

	disabled = g_key_file_get_string_list(keyfile, "General",
						"Disable", NULL, &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_clear_error(&err);
	} else {
		int i;
		for (i = 0; disabled[i] != NULL; i++) {
			if (g_str_equal(disabled[i], "Connection"))
				conf.connection_enabled = FALSE;
			else if (g_str_equal(disabled[i], "Server"))
				conf.server_enabled = FALSE;
		}
		g_strfreev(disabled);
	}

	conf.security = !g_key_file_get_boolean(keyfile, "General",
						"DisableSecurity", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_clear_error(&err);
	}

#if 0
	conf.panu_script = g_key_file_get_string(keyfile, "PANU Role",
						"Script", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_clear_error(&err);
	}

	conf.gn_script = g_key_file_get_string(keyfile, "GN Role",
						"Script", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_clear_error(&err);
	}

	conf.nap_script = g_key_file_get_string(keyfile, "NAP Role",
						"Script", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_clear_error(&err);
	}
#endif

	conf.iface_prefix = g_key_file_get_string(keyfile, "PANU Role",
						"Interface", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_clear_error(&err);
	}

	conf.gn_iface = g_key_file_get_string(keyfile, "GN Role",
						"Interface", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_clear_error(&err);
	}

	conf.nap_iface = g_key_file_get_string(keyfile, "NAP Role",
						"Interface", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_clear_error(&err);
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

static int network_probe(struct btd_device *device, GSList *uuids, uint16_t id)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	bdaddr_t src, dst;

	DBG("path %s", path);

	adapter_get_address(adapter, &src);
	device_get_address(device, &dst);

	return connection_register(device, path, &src, &dst, id);
}

static void network_remove(struct btd_device *device, uint16_t id)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	connection_unregister(path, id);
}

static int panu_probe(struct btd_device *device, GSList *uuids)
{
	return network_probe(device, uuids, BNEP_SVC_PANU);
}

static void panu_remove(struct btd_device *device)
{
	network_remove(device, BNEP_SVC_PANU);
}

static int gn_probe(struct btd_device *device, GSList *uuids)
{
	return network_probe(device, uuids, BNEP_SVC_GN);
}

static void gn_remove(struct btd_device *device)
{
	network_remove(device, BNEP_SVC_GN);
}

static int nap_probe(struct btd_device *device, GSList *uuids)
{
	return network_probe(device, uuids, BNEP_SVC_NAP);
}

static void nap_remove(struct btd_device *device)
{
	network_remove(device, BNEP_SVC_NAP);
}

static int network_server_probe(struct btd_adapter *adapter, uint16_t id)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	if (!conf.server_enabled)
		return 0;

	return server_register(adapter, id);
}

static void network_server_remove(struct btd_adapter *adapter, uint16_t id)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	server_unregister(adapter, id);
}

static int panu_server_probe(struct btd_adapter *adapter)
{
	return network_server_probe(adapter, BNEP_SVC_PANU);
}

static int gn_server_probe(struct btd_adapter *adapter)
{
	return network_server_probe(adapter, BNEP_SVC_GN);
}

static int nap_server_probe(struct btd_adapter *adapter)
{
	return network_server_probe(adapter, BNEP_SVC_NAP);
}

static void panu_server_remove(struct btd_adapter *adapter)
{
	network_server_remove(adapter, BNEP_SVC_PANU);
}

static void gn_server_remove(struct btd_adapter *adapter)
{
	network_server_remove(adapter, BNEP_SVC_GN);
}

static void nap_server_remove(struct btd_adapter *adapter)
{
	network_server_remove(adapter, BNEP_SVC_NAP);
}

static struct btd_device_driver network_panu_driver = {
	.name	= "network-panu",
	.uuids	= BTD_UUIDS(PANU_UUID),
	.probe	= panu_probe,
	.remove	= panu_remove,
};

static struct btd_device_driver network_gn_driver = {
	.name	= "network-gn",
	.uuids	= BTD_UUIDS(GN_UUID),
	.probe	= gn_probe,
	.remove	= gn_remove,
};

static struct btd_device_driver network_nap_driver = {
	.name	= "network-nap",
	.uuids	= BTD_UUIDS(NAP_UUID),
	.probe	= nap_probe,
	.remove	= nap_remove,
};

static struct btd_adapter_driver network_panu_server_driver = {
	.name	= "network-panu-server",
	.probe	= panu_server_probe,
	.remove	= panu_server_remove,
};

static struct btd_adapter_driver network_gn_server_driver = {
	.name	= "network-gn-server",
	.probe	= gn_server_probe,
	.remove	= gn_server_remove,
};

static struct btd_adapter_driver network_nap_server_driver = {
	.name	= "network-nap-server",
	.probe	= nap_server_probe,
	.remove	= nap_server_remove,
};

int network_manager_init(DBusConnection *conn)
{
	read_config(CONFIGDIR "/network.conf");

	if (bnep_init(conf.panu_script, conf.gn_script, conf.nap_script)) {
		error("Can't init bnep module");
		return -1;
	}

	/*
	 * There is one socket to handle the incomming connections. NAP,
	 * GN and PANU servers share the same PSM. The initial BNEP message
	 * (setup connection request) contains the destination service
	 * field that defines which service the source is connecting to.
	 */
	if (bridge_init(conf.gn_iface, conf.nap_iface) < 0) {
		error("Can't init bridge module");
		return -1;
	}

	if (server_init(conn, conf.iface_prefix, conf.security) < 0)
		return -1;

	/* Register PANU, GN and NAP servers if they don't exist */
	btd_register_adapter_driver(&network_panu_server_driver);
	btd_register_adapter_driver(&network_gn_server_driver);
	btd_register_adapter_driver(&network_nap_server_driver);

	if (connection_init(conn, conf.iface_prefix) < 0)
		return -1;

	btd_register_device_driver(&network_panu_driver);
	btd_register_device_driver(&network_gn_driver);
	btd_register_device_driver(&network_nap_driver);

	connection = dbus_connection_ref(conn);

	return 0;
}

void network_manager_exit(void)
{
	if (conf.server_enabled)
		server_exit();

	if (conf.connection_enabled) {
		btd_unregister_device_driver(&network_panu_driver);
		btd_unregister_device_driver(&network_gn_driver);
		btd_unregister_device_driver(&network_nap_driver);
		connection_exit();
	}

	btd_unregister_adapter_driver(&network_panu_server_driver);
	btd_unregister_adapter_driver(&network_gn_server_driver);
	btd_unregister_adapter_driver(&network_nap_server_driver);

	dbus_connection_unref(connection);
	connection = NULL;

	bnep_cleanup();
	bridge_cleanup();
	conf_cleanup();
}
