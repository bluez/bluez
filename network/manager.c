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
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <gdbus.h>

#include "log.h"

#include "adapter.h"
#include "device.h"
#include "manager.h"
#include "common.h"
#include "connection.h"
#include "server.h"

static DBusConnection *connection = NULL;

static gboolean conf_security = TRUE;

static void read_config(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		g_clear_error(&err);
		goto done;
	}

	conf_security = !g_key_file_get_boolean(keyfile, "General",
						"DisableSecurity", &err);
	if (err) {
		DBG("%s: %s", file, err->message);
		g_clear_error(&err);
	}

done:
	g_key_file_free(keyfile);

	DBG("Config options: Security=%s",
				conf_security ? "true" : "false");
}

static int network_probe(struct btd_device *device, GSList *uuids, uint16_t id)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	bdaddr_t src, dst;

	DBG("path %s", path);

	adapter_get_address(adapter, &src);
	device_get_address(device, &dst, NULL);

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

static int network_server_probe(struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	return server_register(adapter);
}

static void network_server_remove(struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	server_unregister(adapter);
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

static struct btd_adapter_driver network_server_driver = {
	.name	= "network-server",
	.probe	= network_server_probe,
	.remove	= network_server_remove,
};

int network_manager_init(DBusConnection *conn)
{
	read_config(CONFIGDIR "/network.conf");

	if (bnep_init()) {
		error("Can't init bnep module");
		return -1;
	}

	/*
	 * There is one socket to handle the incomming connections. NAP,
	 * GN and PANU servers share the same PSM. The initial BNEP message
	 * (setup connection request) contains the destination service
	 * field that defines which service the source is connecting to.
	 */

	if (server_init(conn, conf_security) < 0)
		return -1;

	/* Register network server if it doesn't exist */
	btd_register_adapter_driver(&network_server_driver);

	if (connection_init(conn) < 0)
		return -1;

	btd_register_device_driver(&network_panu_driver);
	btd_register_device_driver(&network_gn_driver);
	btd_register_device_driver(&network_nap_driver);

	connection = dbus_connection_ref(conn);

	return 0;
}

void network_manager_exit(void)
{
	server_exit();

	btd_unregister_device_driver(&network_panu_driver);
	btd_unregister_device_driver(&network_gn_driver);
	btd_unregister_device_driver(&network_nap_driver);

	connection_exit();

	btd_unregister_adapter_driver(&network_server_driver);

	dbus_connection_unref(connection);
	connection = NULL;

	bnep_cleanup();
}
