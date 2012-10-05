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

#include <stdbool.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>
#include <bluetooth/uuid.h>

#include <glib.h>
#include <gdbus.h>

#include "log.h"

#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "manager.h"
#include "common.h"
#include "connection.h"
#include "server.h"

static gboolean conf_security = TRUE;

static void read_config(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		g_clear_error(&err);
		goto done;
	}

	conf_security = !g_key_file_get_boolean(keyfile, "General",
						"DisableSecurity", &err);
	if (err) {
		DBG("%s: %s", file, err->message);
		g_clear_error(&err);
	}

done:
	g_key_file_free(keyfile);

	DBG("Config options: Security=%s",
				conf_security ? "true" : "false");
}

static int network_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	bdaddr_t *src, dst;

	DBG("path %s", path);

	src = adapter_get_address(adapter);
	device_get_address(device, &dst, NULL);

	if (g_slist_find_custom(uuids, PANU_UUID, bt_uuid_strcmp))
		connection_register(device, path, src, &dst, BNEP_SVC_PANU);
	if (g_slist_find_custom(uuids, GN_UUID, bt_uuid_strcmp))
		connection_register(device, path, src, &dst, BNEP_SVC_GN);
	if (g_slist_find_custom(uuids, NAP_UUID, bt_uuid_strcmp))
		connection_register(device, path, src, &dst, BNEP_SVC_NAP);

	return 0;
}

static void network_remove(struct btd_profile *p, struct btd_device *device)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	connection_unregister(path);
}

static int network_server_probe(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	return server_register(adapter);
}

static void network_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	server_unregister(adapter);
}

static struct btd_profile network_profile = {
	.name		= "network",
	.remote_uuids	= BTD_UUIDS(PANU_UUID, GN_UUID, NAP_UUID),
	.device_probe	= network_probe,
	.device_remove	= network_remove,

	.adapter_probe	= network_server_probe,
	.adapter_remove	= network_server_remove,
};

int network_manager_init(void)
{
	read_config(CONFIGDIR "/network.conf");

	if (bnep_init()) {
		error("Can't init bnep module");
		return -1;
	}

	/*
	 * There is one socket to handle the incoming connections. NAP,
	 * GN and PANU servers share the same PSM. The initial BNEP message
	 * (setup connection request) contains the destination service
	 * field that defines which service the source is connecting to.
	 */

	if (server_init(conf_security) < 0)
		return -1;

	btd_profile_register(&network_profile);

	return 0;
}

void network_manager_exit(void)
{
	server_exit();

	btd_profile_unregister(&network_profile);

	bnep_cleanup();
}
