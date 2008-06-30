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
#include "../hcid/device.h"
#include "logging.h"
#include "unix.h"
#include "device.h"
#include "manager.h"

static DBusConnection *conn;

static int headset_probe(struct btd_device *device)
{
	DBG("path %s", device->path);

	return 0;
}

static void headset_remove(struct btd_device *device)
{
	DBG("path %s", device->path);
}

static struct btd_device_driver headset_driver = {
	.name	= "headset",
	.uuids	= BTD_UUIDS(HSP_HS_UUID, HFP_HS_UUID),
	.probe	= headset_probe,
	.remove	= headset_remove,
};

static int a2dp_probe(struct btd_device *device)
{
	DBG("path %s", device->path);

	return 0;
}

static void a2dp_remove(struct btd_device *device)
{
	DBG("path %s", device->path);
}

static struct btd_device_driver a2dp_driver = {
	.name	= "sink",
	.uuids	= BTD_UUIDS(A2DP_SINK_UUID),
	.probe	= a2dp_probe,
	.remove	= a2dp_remove,
};

static int audio_probe(struct btd_device *device)
{
	DBG("path %s", device->path);

	return 0;
}

static void audio_remove(struct btd_device *device)
{
	DBG("path %s", device->path);
}

static struct btd_device_driver audio_driver = {
	.name	= "audio",
	.uuids	= BTD_UUIDS(HSP_HS_UUID, HFP_HS_UUID, HSP_AG_UUID, HFP_AG_UUID,
			ADVANCED_AUDIO_UUID, A2DP_SOURCE_UUID, A2DP_SINK_UUID,
			AVRCP_TARGET_UUID, AVRCP_REMOTE_UUID),
	.probe	= audio_probe,
	.remove	= audio_remove,
};


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

	if (config)
		g_key_file_free(config);

	btd_register_device_driver(&headset_driver);

	btd_register_device_driver(&a2dp_driver);

	btd_register_device_driver(&audio_driver);

	return 0;
}

static void audio_exit(void)
{
	btd_unregister_device_driver(&audio_driver);

	btd_unregister_device_driver(&a2dp_driver);

	btd_unregister_device_driver(&headset_driver);

	audio_manager_exit();

	unix_exit();

	dbus_connection_unref(conn);
}

BLUETOOTH_PLUGIN_DEFINE("audio", audio_init, audio_exit)
