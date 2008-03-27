/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "plugin.h"
#include "dbus.h"
#include "logging.h"
#include "unix.h"
#include "device.h"
#include "manager.h"

static GKeyFile *load_config_file(const char *file)
{
	GError *err = NULL;
	GKeyFile *keyfile;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		g_key_file_free(keyfile);
		return NULL;
	}

	return keyfile;
}

static DBusConnection *conn;

static int audio_init(void)
{
	GKeyFile *config;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL)
		return -EIO;

	config = load_config_file(CONFIGDIR "/audio.conf");

	if (unix_init() < 0) {
		error("Unable to setup unix socket");
		return -EIO;
	}

	if (audio_manager_init(conn, config) < 0) {
		dbus_connection_unref(conn);
		return -EIO;
	}

	g_key_file_free(config);

	register_external_service(conn, "audio", "audio service", "");

	return 0;
}

static void audio_exit(void)
{
	audio_manager_exit();

	unix_exit();

	dbus_connection_unref(conn);
}

BLUETOOTH_PLUGIN_DEFINE("audio", audio_init, audio_exit)
