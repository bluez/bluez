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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>
#include <gdbus.h>

#include "../src/dbus-common.h"
#include "adapter.h"
#include "device.h"

#include "log.h"

#include "error.h"
#include "port.h"
#include "proxy.h"
#include "storage.h"
#include "manager.h"
#include "sdpd.h"
#include "glib-helper.h"

#define RFCOMM_UUID_STR		"00000003-0000-1000-8000-00805F9B34FB"

static DBusConnection *connection = NULL;

static int serial_probe(struct btd_device *device, const char *uuid)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	sdp_list_t *protos;
	int ch;
	bdaddr_t src, dst;
	const sdp_record_t *rec;

	DBG("path %s: %s", path, uuid);

	rec = btd_device_get_record(device, uuid);
	if (!rec)
		return -EINVAL;

	if (sdp_get_access_protos(rec, &protos) < 0)
		return -EINVAL;

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch < 1 || ch > 30) {
		error("Channel out of range: %d", ch);
		return -EINVAL;
	}

	adapter_get_address(adapter, &src);
	device_get_address(device, &dst, NULL);

	return port_register(connection, path, &src, &dst, uuid, ch);
}

static void serial_remove(struct btd_device *device)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	port_unregister(path);
}


static int port_probe(struct btd_device *device, GSList *uuids)
{
	while (uuids) {
		serial_probe(device, uuids->data);
		uuids = uuids->next;
	}

	return 0;
}

static void port_remove(struct btd_device *device)
{
	return serial_remove(device);
}

static struct btd_device_driver serial_port_driver = {
	.name	= "serial-port",
	.uuids	= BTD_UUIDS(RFCOMM_UUID_STR),
	.probe	= port_probe,
	.remove	= port_remove,
};

static int proxy_probe(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("path %s", path);

	return proxy_register(connection, adapter);
}

static void proxy_remove(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("path %s", path);

	proxy_unregister(adapter);
}

static struct btd_adapter_driver serial_proxy_driver = {
	.name	= "serial-proxy",
	.probe	= proxy_probe,
	.remove	= proxy_remove,
};

int serial_manager_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	btd_register_adapter_driver(&serial_proxy_driver);
	btd_register_device_driver(&serial_port_driver);

	return 0;
}

void serial_manager_exit(void)
{
	btd_unregister_device_driver(&serial_port_driver);

	dbus_connection_unref(connection);
	connection = NULL;
}
