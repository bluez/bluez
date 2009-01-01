/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2009  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <fcntl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "glib-helper.h"
#include "plugin.h"
#include "logging.h"
#include "unix.h"
#include "device.h"
#include "headset.h"
#include "manager.h"

static GIOChannel *sco_server = NULL;

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

static void sco_server_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer data)
{
	int sk;
	struct audio_device *device;
	char addr[18];

	if (err < 0) {
		error("accept: %s (%d)", strerror(-err), -err);
		return;
	}

	device = manager_find_device(dst, NULL, FALSE);
	if (!device)
		goto drop;

	if (headset_get_state(device) < HEADSET_STATE_CONNECTED) {
		debug("Refusing SCO from non-connected headset");
		goto drop;
	}

	ba2str(dst, addr);

	if (!get_hfp_active(device)) {
		error("Refusing non-HFP SCO connect attempt from %s", addr);
		goto drop;
	}

	sk = g_io_channel_unix_get_fd(chan);
	fcntl(sk, F_SETFL, 0);

	if (headset_connect_sco(device, chan) == 0) {
		debug("Accepted SCO connection from %s", addr);
		headset_set_state(device, HEADSET_STATE_PLAYING);
	}

	return;

drop:
	g_io_channel_close(chan);
	g_io_channel_unref(chan);
}

static DBusConnection *connection;

static int audio_init(void)
{
	GKeyFile *config;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL)
		return -EIO;

	config = load_config_file(CONFIGDIR "/audio.conf");

	if (unix_init() < 0) {
		error("Unable to setup unix socket");
		return -EIO;
	}

	if (audio_manager_init(connection, config) < 0) {
		dbus_connection_unref(connection);
		return -EIO;
	}

	sco_server = bt_sco_listen(BDADDR_ANY, 0, sco_server_cb, NULL);
	if (!sco_server) {
		error("Unable to start SCO server socket");
		return -EIO;
	}

	return 0;
}

static void audio_exit(void)
{
	if (sco_server) {
		g_io_channel_close(sco_server);
		g_io_channel_unref(sco_server);
		sco_server = NULL;
	}

	audio_manager_exit();

	unix_exit();

	dbus_connection_unref(connection);
}

BLUETOOTH_PLUGIN_DEFINE("audio", audio_init, audio_exit)
