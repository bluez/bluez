/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010 GSyC/LibreSoft, Universidad Rey Juan Carlos.
 *  Authors:
 *  Santiago Carot Nemesio <sancane at gmail.com>
 *  Jose Antonio Santos-Cadenas <santoscadenas at gmail.com>
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

#include <gdbus.h>

#include "log.h"
#include <adapter.h>
#include <device.h>

int hdp_adapter_register(DBusConnection *conn, struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("New health adapter %s", path);
	return 0;
}

void hdp_adapter_unregister(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("Health adapter %s removed", path);
}

int hdp_device_register(DBusConnection *conn, struct btd_device *device)
{
	const char *path = device_get_path(device);

	DBG("New health device %s", path);
	return 0;
}

void hdp_device_unregister(struct btd_device *device)
{
	const char *path = device_get_path(device);

	DBG("Health device %s removed", path);
}

int hdp_manager_start(DBusConnection *conn)
{
	DBG("Starting Health manager");

	return 0;
}

void hdp_manager_stop()
{
	DBG("Stopped Health manager");
}
