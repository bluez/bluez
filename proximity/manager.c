/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2011  Nokia Corporation
 *  Copyright (C) 2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <gdbus.h>

#include "monitor.h"
#include "manager.h"

static DBusConnection *connection = NULL;

int proximity_manager_init(DBusConnection *conn)
{
	int ret;
	/* TODO: Add Proximity Monitor/Reporter config */

	/* TODO: Register Proximity Monitor/Reporter drivers */

	connection = dbus_connection_ref(conn);

	ret = monitor_register(connection);

	if (ret < 0) {
		dbus_connection_unref(connection);
		return ret;
	}

	return 0;
}

void proximity_manager_exit(void)
{
	monitor_unregister(connection);
	dbus_connection_unref(connection);
}
