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

#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <gdbus.h>

#include "log.h"
#include "../src/adapter.h"

#include "manager.h"

static DBusConnection *connection = NULL;

static int server_probe(struct btd_adapter *adapter)
{
	return 0;
}

static void server_remove(struct btd_adapter *adapter)
{
}

static struct btd_adapter_driver attrib_server_driver = {
	.name = "attribute-server",
	.probe = server_probe,
	.remove = server_remove,
};

int attrib_manager_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	btd_register_adapter_driver(&attrib_server_driver);

	return 0;
}

void attrib_manager_exit(void)
{
	btd_unregister_adapter_driver(&attrib_server_driver);

	dbus_connection_unref(connection);
}
