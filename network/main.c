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

#include <gdbus.h>

#include "plugin.h"
#include "manager.h"

static int network_init(void)
{
	DBusConnection *conn;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL)
		return -EIO;

	if (network_manager_init(conn) < 0) {
		dbus_connection_unref(conn);
		return -EIO;
	}

	return 0;
}

static void network_exit(void)
{
	network_manager_exit();
}

BLUETOOTH_PLUGIN_DEFINE("network", network_init, network_exit)
