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
#include <ctype.h>
#include <dirent.h>

#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <gdbus.h>

#include "logging.h"
#include "textfile.h"
#include "glib-helper.h"

#include "adapter.h"
#include "device.h"
#include "driver.h"
#include "error.h"
#include "bridge.h"
#include "manager.h"
#include "common.h"

#define MAX_NAME_SIZE	256

static struct network_conf *conf = NULL;/* Network service configuration */

static struct btd_adapter_driver network_panu_server_driver;
static struct btd_adapter_driver network_gn_server_driver;
static struct btd_adapter_driver network_nap_server_driver;

static DBusConnection *connection = NULL;

static int network_probe(struct btd_device_driver *driver,
			struct btd_device *device, GSList *records)
{
	struct adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	const char *source, *destination;
	bdaddr_t src, dst;
	uint16_t id;

	DBG("path %s", path);

	source = adapter_get_address(adapter);
	destination = device_get_address(device);

	str2ba(source, &src);
	str2ba(destination, &dst);
	id = bnep_service_id(driver->uuids[0]);

	return connection_register(path, &src, &dst, id);
}

static void network_remove(struct btd_device_driver *driver,
			struct btd_device *device)
{
	const gchar *path = device_get_path(device);
	uint16_t id = bnep_service_id(driver->uuids[0]);

	DBG("path %s", path);

	connection_unregister(path, id);
}

static int network_server_probe(struct adapter *adapter, uint16_t id)
{
	const gchar *path = adapter_get_path(adapter);
	const char *source;
	bdaddr_t src;

	DBG("path %s", path);

	if (!conf->server_enabled)
		return 0;

	source = adapter_get_address(adapter);
	str2ba(source, &src);

	return server_register(path, &src, id);
}

static void network_server_remove(struct adapter *adapter, uint16_t id)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	server_unregister(path, id);
}

static int network_panu_server_probe(struct adapter *adapter)
{
	return network_server_probe(adapter, BNEP_SVC_PANU);
}

static int network_gn_server_probe(struct adapter *adapter)
{
	return network_server_probe(adapter, BNEP_SVC_GN);
}

static int network_nap_server_probe(struct adapter *adapter)
{
	return network_server_probe(adapter, BNEP_SVC_NAP);
}

static void network_panu_server_remove(struct adapter *adapter)
{
	network_server_remove(adapter, BNEP_SVC_PANU);
}

static void network_gn_server_remove(struct adapter *adapter)
{
	network_server_remove(adapter, BNEP_SVC_GN);
}

static void network_nap_server_remove(struct adapter *adapter)
{
	network_server_remove(adapter, BNEP_SVC_NAP);
}

static struct btd_device_driver network_panu_driver = {
	.name	= "network-panu",
	.uuids	= BTD_UUIDS(PANU_UUID),
	.probe	= network_probe,
	.remove	= network_remove,
};

static struct btd_device_driver network_gn_driver = {
	.name	= "network-gn",
	.uuids	= BTD_UUIDS(GN_UUID),
	.probe	= network_probe,
	.remove	= network_remove,
};

static struct btd_device_driver network_nap_driver = {
	.name	= "network-nap",
	.uuids	= BTD_UUIDS(NAP_UUID),
	.probe	= network_probe,
	.remove	= network_remove,
};

static struct btd_adapter_driver network_panu_server_driver = {
	.name	= "network-panu-server",
	.probe	= network_panu_server_probe,
	.remove	= network_panu_server_remove,
};

static struct btd_adapter_driver network_gn_server_driver = {
	.name	= "network-gn-server",
	.probe	= network_gn_server_probe,
	.remove	= network_gn_server_remove,
};

static struct btd_adapter_driver network_nap_server_driver = {
	.name	= "network-nap-server",
	.probe	= network_nap_server_probe,
	.remove	= network_nap_server_remove,
};

int network_manager_init(DBusConnection *conn, struct network_conf *service_conf)
{
	conf = service_conf;

	if (bnep_init(conf->panu_script, conf->gn_script, conf->nap_script)) {
		error("Can't init bnep module");
		return -1;
	}

	/*
	 * There is one socket to handle the incomming connections. NAP,
	 * GN and PANU servers share the same PSM. The initial BNEP message
	 * (setup connection request) contains the destination service
	 * field that defines which service the source is connecting to.
	 */
	if (bridge_init(conf->gn_iface, conf->nap_iface) < 0) {
		error("Can't init bridge module");
		return -1;
	}

	if (server_init(conn, conf->iface_prefix, conf->security) < 0)
		return -1;

	/* Register PANU, GN and NAP servers if they don't exist */
	/* FIXME: server should be registered as adapter driver */
	btd_register_adapter_driver(&network_panu_server_driver);
	btd_register_adapter_driver(&network_gn_server_driver);
	btd_register_adapter_driver(&network_nap_server_driver);

	if (connection_init(conn, conf->iface_prefix) < 0)
		return -1;

	btd_register_device_driver(&network_panu_driver);
	btd_register_device_driver(&network_gn_driver);
	btd_register_device_driver(&network_nap_driver);

	connection = dbus_connection_ref(conn);

	return 0;
}

void network_manager_exit(void)
{
	if (conf->server_enabled)
		server_exit();

	if (conf->connection_enabled) {
		btd_unregister_device_driver(&network_panu_driver);
		btd_unregister_device_driver(&network_gn_driver);
		btd_unregister_device_driver(&network_nap_driver);
		connection_exit();
	}

	dbus_connection_unref(connection);
	connection = NULL;

	bnep_cleanup();
	bridge_cleanup();
}
