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

#include <errno.h>
#include <stdint.h>
#include <glib.h>
#include <gdbus.h>

#include "log.h"
#include "plugin.h"
#include "manager.h"
#include "hcid.h"

static DBusConnection *connection = NULL;
static GKeyFile *config = NULL;

static GKeyFile *open_config_file(const char *file)
{
	GError *gerr = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	g_key_file_set_list_separator(keyfile, ',');

	if (!g_key_file_load_from_file(keyfile, file, 0, &gerr)) {
		error("Parsing %s failed: %s", file, gerr->message);
		g_error_free(gerr);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static int proximity_init(void)
{
	if (!main_opts.gatt_enabled) {
		DBG("GATT is disabled");
		return -ENOTSUP;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	config = open_config_file(CONFIGDIR "/proximity.conf");

	if (proximity_manager_init(connection, config) < 0) {
		dbus_connection_unref(connection);
		return -EIO;
	}

	return 0;
}

static void proximity_exit(void)
{
	if (!main_opts.gatt_enabled)
		return;

	if (config)
		g_key_file_free(config);

	proximity_manager_exit();
	dbus_connection_unref(connection);
}

BLUETOOTH_PLUGIN_DEFINE(proximity, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			proximity_init, proximity_exit)
