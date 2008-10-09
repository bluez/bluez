/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>
#include <gdbus.h>

#include "../src/dbus-common.h"
#include "adapter.h"
#include "device.h"

#include "logging.h"
#include "textfile.h"

#include "error.h"
#include "port.h"
#include "proxy.h"
#include "storage.h"
#include "manager.h"
#include "sdpd.h"
#include "glib-helper.h"

#define SERIAL_PORT_NAME	"spp"
#define SERIAL_PORT_UUID	"00001101-0000-1000-8000-00805F9B34FB"

#define DIALUP_NET_NAME		"dun"
#define DIALUP_NET_UUID		"00001103-0000-1000-8000-00805F9B34FB"

static DBusConnection *connection = NULL;

static int serial_probe(struct btd_device *device, const sdp_record_t *rec,
			const char *name, const char *uuid)
{
	struct btd_adapter *adapter = device_get_adapter(device);
	const gchar *path = device_get_path(device);
	sdp_list_t *protos;
	int ch;
	bdaddr_t src, dst;

	DBG("path %s", path);

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
	device_get_address(device, &dst);

	return port_register(connection, path, &src, &dst, name,
			uuid, ch);
}

static void serial_remove(struct btd_device *device, const char *uuid)
{
	const gchar *path = device_get_path(device);

	DBG("path %s", path);

	port_unregister(path, uuid);
}


static int port_probe(struct btd_device *device, GSList *uuids)
{
	const sdp_record_t *record;

	record = btd_device_get_record(device, uuids->data);
	if (!record)
		return -1;

	return serial_probe(device, record, SERIAL_PORT_NAME,
				SERIAL_PORT_UUID);
}

static void port_remove(struct btd_device *device)
{
	return serial_remove(device, SERIAL_PORT_UUID);
}

static int dialup_probe(struct btd_device *device, GSList *uuids)
{
	const sdp_record_t *record;

	record = btd_device_get_record(device, uuids->data);
	if (!record)
		return -1;

	return serial_probe(device, record, DIALUP_NET_NAME, DIALUP_NET_UUID);
}

static void dialup_remove(struct btd_device *device)
{
	return serial_remove(device, DIALUP_NET_UUID);
}

static struct btd_device_driver serial_port_driver = {
	.name	= "serial-port",
	.uuids	= BTD_UUIDS(SERIAL_PORT_UUID),
	.probe	= port_probe,
	.remove	= port_remove,
};

static struct btd_device_driver serial_dialup_driver = {
	.name	= "serial-dialup",
	.uuids	= BTD_UUIDS(DIALUP_NET_UUID),
	.probe	= dialup_probe,
	.remove	= dialup_remove,
};

static int proxy_probe(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);
	bdaddr_t src;

	DBG("path %s", path);
	adapter_get_address(adapter, &src);

	return proxy_register(connection, path, &src);
}

static void proxy_remove(struct btd_adapter *adapter)
{
	const char *path = adapter_get_path(adapter);

	DBG("path %s", path);

	proxy_unregister(path);
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
	btd_register_device_driver(&serial_dialup_driver);

	return 0;
}

void serial_manager_exit(void)
{
	btd_unregister_device_driver(&serial_port_driver);
	btd_unregister_device_driver(&serial_dialup_driver);

	dbus_connection_unref(connection);
	connection = NULL;
}
