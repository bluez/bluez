/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>
#include <bluetooth/mgmt.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "log.h"

#include "adapter.h"
#include "manager.h"
#include "device.h"
#include "error.h"
#include "dbus-common.h"
#include "agent.h"
#include "storage.h"
#include "event.h"

static gboolean get_adapter_and_device(const bdaddr_t *src, bdaddr_t *dst,
					struct btd_adapter **adapter,
					struct btd_device **device,
					gboolean create)
{
	char peer_addr[18];

	*adapter = manager_find_adapter(src);
	if (!*adapter) {
		error("Unable to find matching adapter");
		return FALSE;
	}

	ba2str(dst, peer_addr);

	if (create)
		*device = adapter_get_device(*adapter, peer_addr);
	else
		*device = adapter_find_device(*adapter, peer_addr);

	if (create && !*device) {
		error("Unable to get device object!");
		return FALSE;
	}

	return TRUE;
}

static void store_link_key(struct btd_adapter *adapter,
				struct btd_device *device, uint8_t *key,
				uint8_t type, uint8_t pin_length)
{
	char adapter_addr[18];
	char device_addr[18];
	char filename[PATH_MAX + 1];
	GKeyFile *key_file;
	char key_str[35];
	char *str;
	int i;
	gsize length = 0;

	ba2str(adapter_get_address(adapter), adapter_addr);
	ba2str(device_get_address(device), device_addr);

	snprintf(filename, PATH_MAX, STORAGEDIR "/%s/%s/info", adapter_addr,
								device_addr);
	filename[PATH_MAX] = '\0';

	key_file = g_key_file_new();
	g_key_file_load_from_file(key_file, filename, 0, NULL);

	key_str[0] = '0';
	key_str[1] = 'x';
	for (i = 0; i < 16; i++)
		sprintf(key_str + 2 + (i * 2), "%2.2X", key[i]);

	g_key_file_set_string(key_file, "LinkKey", "Key", key_str);

	g_key_file_set_integer(key_file, "LinkKey", "Type", type);
	g_key_file_set_integer(key_file, "LinkKey", "PINLength", pin_length);

	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	str = g_key_file_to_data(key_file, &length, NULL);
	g_file_set_contents(filename, str, length, NULL);
	g_free(str);

	g_key_file_free(key_file);
}

int btd_event_link_key_notify(bdaddr_t *local, bdaddr_t *peer,
				uint8_t *key, uint8_t key_type,
				uint8_t pin_length)
{
	struct btd_adapter *adapter;
	struct btd_device *device;

	if (!get_adapter_and_device(local, peer, &adapter, &device, TRUE))
		return -ENODEV;

	DBG("storing link key of type 0x%02x", key_type);

	store_link_key(adapter, device, key, key_type, pin_length);

	device_set_bonded(device, TRUE);

	if (device_is_temporary(device))
		device_set_temporary(device, FALSE);

	return 0;
}
