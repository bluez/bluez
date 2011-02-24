/*
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 Instituto Nokia de Tecnologia - INdT
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <gdbus.h>

#include "log.h"
#include "adapter.h"
#include "device.h"

#include "manager.h"
#include "server.h"

static DBusConnection *connection = NULL;

static int sap_server_probe(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);
	bdaddr_t src;

	DBG("path %s", path);

	adapter_get_address(adapter, &src);

	return sap_server_register(path, &src);
}

static void sap_server_remove(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("path %s", path);

	sap_server_unregister(path);
}

static struct btd_adapter_driver sap_server_driver = {
	.name	= "sap-server",
	.probe	= sap_server_probe,
	.remove	= sap_server_remove,
};

int sap_manager_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	if (sap_server_init(connection) < 0) {
		error("Can't init SAP server");
		dbus_connection_unref(conn);
		return -1;
	}

	btd_register_adapter_driver(&sap_server_driver);

	return 0;
}

void sap_manager_exit(void)
{
	btd_unregister_adapter_driver(&sap_server_driver);

	dbus_connection_unref(connection);
	connection = NULL;

	sap_server_exit();
}
