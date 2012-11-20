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

struct connect_req {
	struct btd_profile	*profile;
	btd_profile_cb		cb;
};

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

static void connect_profile_cb(struct btd_device *device, int err,
						const char *pdev, void *data)
{
	struct connect_req *req = data;

	req->cb(req->profile, device, err);

	g_free(req);
}

static int connect_profile(struct btd_device *dev, struct btd_profile *profile,
						uint16_t id, btd_profile_cb cb)
{
	struct connect_req *req;
	int err;

	DBG("path %s id %u", device_get_path(dev), id);

	req  = g_new0(struct connect_req, 1);
	req->profile = profile;
	req->cb = cb;

	err = connection_connect(dev, BNEP_SVC_PANU, NULL, connect_profile_cb,
									req);
	if (err < 0) {
		g_free(req);
		return err;
	}

	return 0;
}

static int disconnect_profile(struct btd_device *dev,
						struct btd_profile *profile,
						uint16_t id, btd_profile_cb cb)
{
	int err;

	DBG("path %s id %u", device_get_path(dev), id);

	err = connection_disconnect(dev, id, NULL);
	if (err < 0)
		return err;

	if (cb)
		cb(profile, dev, 0);

	return 0;
}

static int panu_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	DBG("path %s", device_get_path(device));

	return connection_register(device, BNEP_SVC_PANU);
}

static void network_remove(struct btd_profile *p, struct btd_device *device)
{
	DBG("path %s", device_get_path(device));

	connection_unregister(device);
}

static int panu_connect(struct btd_device *dev, struct btd_profile *profile,
							btd_profile_cb cb)
{
	return connect_profile(dev, profile, BNEP_SVC_PANU, cb);
}

static int panu_disconnect(struct btd_device *dev, struct btd_profile *profile,
							btd_profile_cb cb)
{
	return disconnect_profile(dev, profile, BNEP_SVC_PANU, cb);
}

static int panu_server_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	return server_register(adapter, BNEP_SVC_PANU);
}

static void panu_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	server_unregister(adapter, BNEP_SVC_PANU);
}

static int gn_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	DBG("path %s", device_get_path(device));

	return connection_register(device, BNEP_SVC_GN);
}

static int gn_connect(struct btd_device *dev, struct btd_profile *profile,
							btd_profile_cb cb)
{
	return connect_profile(dev, profile, BNEP_SVC_GN, cb);
}

static int gn_disconnect(struct btd_device *dev, struct btd_profile *profile,
							btd_profile_cb cb)
{
	return disconnect_profile(dev, profile, BNEP_SVC_GN, cb);
}

static int gn_server_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	return server_register(adapter, BNEP_SVC_GN);
}

static void gn_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	server_unregister(adapter, BNEP_SVC_GN);
}

static int nap_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	DBG("path %s", device_get_path(device));

	return connection_register(device, BNEP_SVC_NAP);
}

static int nap_connect(struct btd_device *dev, struct btd_profile *profile,
							btd_profile_cb cb)
{
	return connect_profile(dev, profile, BNEP_SVC_NAP, cb);
}

static int nap_disconnect(struct btd_device *dev, struct btd_profile *profile,
							btd_profile_cb cb)
{
	return disconnect_profile(dev, profile, BNEP_SVC_NAP, cb);
}

static int nap_server_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	return server_register(adapter, BNEP_SVC_NAP);
}

static void nap_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	const gchar *path = adapter_get_path(adapter);

	DBG("path %s", path);

	server_unregister(adapter, BNEP_SVC_NAP);
}

static struct btd_profile panu_profile = {
	.name		= "network-panu",
	.local_uuid	= NAP_UUID,
	.remote_uuids	= BTD_UUIDS(PANU_UUID),
	.device_probe	= panu_probe,
	.device_remove	= network_remove,
	.connect	= panu_connect,
	.disconnect	= panu_disconnect,
	.adapter_probe	= panu_server_probe,
	.adapter_remove	= panu_server_remove,
};

static struct btd_profile gn_profile = {
	.name		= "network-gn",
	.local_uuid	= PANU_UUID,
	.remote_uuids	= BTD_UUIDS(GN_UUID),
	.device_probe	= gn_probe,
	.device_remove	= network_remove,
	.connect	= gn_connect,
	.disconnect	= gn_disconnect,
	.adapter_probe	= gn_server_probe,
	.adapter_remove	= gn_server_remove,
};

static struct btd_profile nap_profile = {
	.name		= "network-nap",
	.local_uuid	= PANU_UUID,
	.remote_uuids	= BTD_UUIDS(NAP_UUID),
	.device_probe	= nap_probe,
	.device_remove	= network_remove,
	.connect	= nap_connect,
	.disconnect	= nap_disconnect,
	.adapter_probe	= nap_server_probe,
	.adapter_remove	= nap_server_remove,
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

	btd_profile_register(&panu_profile);
	btd_profile_register(&gn_profile);
	btd_profile_register(&nap_profile);

	return 0;
}

void network_manager_exit(void)
{
	server_exit();

	btd_profile_unregister(&panu_profile);
	btd_profile_unregister(&gn_profile);
	btd_profile_unregister(&nap_profile);

	bnep_cleanup();
}
