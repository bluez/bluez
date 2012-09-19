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
#include <stdbool.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/uuid.h>

#include "log.h"
#include "../src/adapter.h"
#include "../src/device.h"
#include "../src/profile.h"

#include "device.h"
#include "server.h"
#include "manager.h"

static int idle_timeout = 0;

static GSList *adapters = NULL;

static void input_remove(struct btd_device *device, const char *uuid)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	input_device_unregister(path, uuid);
}

static int hid_device_probe(struct btd_profile *p, struct btd_device *device,
								GSList *uuids)
{
	const gchar *path = device_get_path(device);
	const sdp_record_t *rec = btd_device_get_record(device, uuids->data);

	DBG("path %s", path);

	if (!rec)
		return -1;

	return input_device_register(device, path, HID_UUID, rec,
							idle_timeout * 60);
}

static void hid_device_remove(struct btd_profile *p, struct btd_device *device)
{
	input_remove(device, HID_UUID);
}

static int hid_server_probe(struct btd_profile *p, struct btd_adapter *adapter)
{
	bdaddr_t src;
	int ret;

	adapter_get_address(adapter, &src);

	ret = server_start(&src);
	if (ret < 0)
		return ret;

	adapters = g_slist_append(adapters, btd_adapter_ref(adapter));

	return 0;
}

static void hid_server_remove(struct btd_profile *p,
						struct btd_adapter *adapter)
{
	bdaddr_t src;

	adapter_get_address(adapter, &src);

	server_stop(&src);

	adapters = g_slist_remove(adapters, adapter);
	btd_adapter_unref(adapter);
}

static struct btd_profile input_profile = {
	.name		= "input-hid",
	.remote_uuids	= BTD_UUIDS(HID_UUID),

	.auto_connect	= true,
	.connect	= input_device_connect,

	.device_probe	= hid_device_probe,
	.device_remove	= hid_device_remove,

	.adapter_probe	= hid_server_probe,
	.adapter_remove = hid_server_remove,
};

int input_manager_init(GKeyFile *config)
{
	GError *err = NULL;

	if (config) {
		idle_timeout = g_key_file_get_integer(config, "General",
						"IdleTimeout", &err);
		if (err) {
			DBG("input.conf: %s", err->message);
			g_error_free(err);
		}
	}

	btd_profile_register(&input_profile);

	return 0;
}

void input_manager_exit(void)
{
	btd_profile_unregister(&input_profile);
}
