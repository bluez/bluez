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

#include "../hcid/adapter.h"
#include "../hcid/device.h"
#include "error.h"
#include "bridge.h"
#include "manager.h"
#include "common.h"

#define MAX_NAME_SIZE	256

static struct network_conf *conf = NULL;/* Network service configuration */

static DBusConnection *connection = NULL;

static void register_server(uint16_t id)
{
	char path[MAX_PATH_LENGTH];
	bdaddr_t src;
	int dev_id;

	if (!conf->server_enabled)
		return;

	snprintf(path, MAX_PATH_LENGTH, NETWORK_PATH "/%s", bnep_name(id));

	bacpy(&src, BDADDR_ANY);
	dev_id = hci_get_route(&src);
	if (dev_id < 0 || hci_devba(dev_id, &src))
		return;

	if (server_register(path, &src, id) < 0)
		return;

	server_store(path);
}

static int network_probe(struct btd_device *device, uint16_t id)
{
	struct adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	const char *source, *destination;
	bdaddr_t src, dst;

	DBG("path %s", path);

	source = adapter->address;
	destination = device_get_address(device);

	str2ba(source, &src);
	str2ba(destination, &dst);

	return connection_register(path, &src, &dst, id);
}

static int panu_probe(struct btd_device *device, GSList *records)
{
	return network_probe(device, BNEP_SVC_PANU);
}

static int gn_probe(struct btd_device *device, GSList *records)
{
	return network_probe(device, BNEP_SVC_GN);
}

static int nap_probe(struct btd_device *device, GSList *records)
{
	return network_probe(device, BNEP_SVC_NAP);
}

static void network_remove(struct btd_device *device, uint16_t id)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	connection_unregister(path, id);
}

static void panu_remove(struct btd_device *device)
{
	network_remove(device, BNEP_SVC_PANU);
}

static void gn_remove(struct btd_device *device)
{
	network_remove(device, BNEP_SVC_GN);
}

static void nap_remove(struct btd_device *device)
{
	network_remove(device, BNEP_SVC_NAP);
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
	register_server(BNEP_SVC_PANU);
	register_server(BNEP_SVC_GN);
	register_server(BNEP_SVC_NAP);

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
