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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <gdbus.h>

#include "../src/dbus-common.h"

#include "log.h"
#include "glib-helper.h"
#include "btio.h"

#include "error.h"
#include "manager.h"
#include "adapter.h"
#include "device.h"
#include "storage.h"
#include "port.h"

#define SERIAL_PORT_INTERFACE	"org.bluez.Serial"

#define MAX_OPEN_TRIES		5
#define OPEN_WAIT		300	/* ms. udev node creation retry wait */

struct serial_device {
	DBusConnection	*conn;		/* for name listener handling */
	bdaddr_t	src;		/* Source (local) address */
	bdaddr_t	dst;		/* Destination address */
	char		*path;		/* Device path */
	GSList		*ports;		/* Available ports */
};

struct serial_port {
	DBusMessage	*msg;		/* for name listener handling */
	int16_t		id;		/* RFCOMM device id */
	uint8_t		channel;	/* RFCOMM channel */
	char		*uuid;		/* service identification */
	char		*dev;		/* RFCOMM device name */
	int		fd;		/* Opened file descriptor */
	GIOChannel	*io;		/* BtIO channel */
	guint		listener_id;
	struct serial_device *device;
};

static GSList *devices = NULL;

static struct serial_device *find_device(GSList *devices, const char *path)
{
	GSList *l;

	for (l = devices; l != NULL; l = l->next) {
		struct serial_device *device = l->data;

		if (!strcmp(device->path, path))
			return device;
	}

	return NULL;
}

static struct serial_port *find_port(GSList *ports, const char *pattern)
{
	GSList *l;
	int channel;
	char *endptr = NULL;

	channel = strtol(pattern, &endptr, 10);

	for (l = ports; l != NULL; l = l->next) {
		struct serial_port *port = l->data;
		char *uuid_str;
		int ret;

		if (port->uuid && !strcasecmp(port->uuid, pattern))
			return port;

		if (endptr && *endptr == '\0' && port->channel == channel)
			return port;

		if (port->dev && !strcmp(port->dev, pattern))
			return port;

		if (!port->uuid)
			continue;

		uuid_str = bt_name2string(pattern);
		if (!uuid_str)
			continue;

		ret = strcasecmp(port->uuid, uuid_str);
		g_free(uuid_str);
		if (ret == 0)
			return port;
	}

	return NULL;
}

static int port_release(struct serial_port *port)
{
	struct rfcomm_dev_req req;
	int rfcomm_ctl;
	int err = 0;

	if (port->id < 0) {
		if (port->io) {
			g_io_channel_shutdown(port->io, TRUE, NULL);
			g_io_channel_unref(port->io);
			port->io = NULL;
		} else
			bt_cancel_discovery(&port->device->src,
						&port->device->dst);

		return 0;
	}

	DBG("Serial port %s released", port->dev);

	rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
	if (rfcomm_ctl < 0)
		return -errno;

	if (port->fd >= 0) {
		close(port->fd);
		port->fd = -1;
	}

	memset(&req, 0, sizeof(req));
	req.dev_id = port->id;

	/*
	 * We are hitting a kernel bug inside RFCOMM code when
	 * RFCOMM_HANGUP_NOW bit is set on request's flags passed to
	 * ioctl(RFCOMMRELEASEDEV)!
	 */
	req.flags = (1 << RFCOMM_HANGUP_NOW);

	if (ioctl(rfcomm_ctl, RFCOMMRELEASEDEV, &req) < 0) {
		err = errno;
		error("Can't release device %s: %s (%d)",
				port->dev, strerror(err), err);
	}

	g_free(port->dev);
	port->dev = NULL;
	port->id = -1;
	close(rfcomm_ctl);
	return -err;
}

static void serial_port_free(struct serial_port *port)
{
	struct serial_device *device = port->device;

	if (device && port->listener_id > 0)
		g_dbus_remove_watch(device->conn, port->listener_id);

	port_release(port);

	g_free(port->uuid);
	g_free(port);
}

static void serial_device_free(struct serial_device *device)
{
	g_free(device->path);
	if (device->conn)
		dbus_connection_unref(device->conn);
	g_free(device);
}

static void port_owner_exited(DBusConnection *conn, void *user_data)
{
	struct serial_port *port = user_data;

	port_release(port);

	port->listener_id = 0;
}

static void path_unregister(void *data)
{
	struct serial_device *device = data;

	DBG("Unregistered interface %s on path %s", SERIAL_PORT_INTERFACE,
		device->path);

	devices = g_slist_remove(devices, device);
	serial_device_free(device);
}

void port_release_all(void)
{
	g_slist_foreach(devices, (GFunc) serial_device_free, NULL);
	g_slist_free(devices);
}

static void open_notify(int fd, int err, struct serial_port *port)
{
	struct serial_device *device = port->device;
	DBusMessage *reply;

	if (err < 0) {
		/* Max tries exceeded */
		port_release(port);
		reply = btd_error_failed(port->msg, strerror(-err));
	} else {
		port->fd = fd;
		reply = g_dbus_create_reply(port->msg,
				DBUS_TYPE_STRING, &port->dev,
				DBUS_TYPE_INVALID);
	}

	/* Reply to the requestor */
	g_dbus_send_message(device->conn, reply);
}

static gboolean open_continue(gpointer user_data)
{
	struct serial_port *port = user_data;
	int fd;
	static int ntries = MAX_OPEN_TRIES;

	if (!port->listener_id)
		return FALSE; /* Owner exited */

	fd = open(port->dev, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		int err = -errno;
		error("Could not open %s: %s (%d)",
				port->dev, strerror(-err), -err);
		if (!--ntries) {
			/* Reporting error */
			open_notify(fd, err, port);
			ntries = MAX_OPEN_TRIES;
			return FALSE;
		}
		return TRUE;
	}

	/* Connection succeeded */
	open_notify(fd, 0, port);
	return FALSE;
}

static int port_open(struct serial_port *port)
{
	int fd;

	fd = open(port->dev, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		g_timeout_add(OPEN_WAIT, open_continue, port);
		return -EINPROGRESS;
	}

	return fd;
}

static void rfcomm_connect_cb(GIOChannel *chan, GError *conn_err,
							gpointer user_data)
{
	struct serial_port *port = user_data;
	struct serial_device *device = port->device;
	struct rfcomm_dev_req req;
	int sk, fd;
	DBusMessage *reply;

	/* Owner exited? */
	if (!port->listener_id)
		return;

	if (conn_err) {
		error("%s", conn_err->message);
		reply = btd_error_failed(port->msg, conn_err->message);
		goto fail;
	}

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = (1 << RFCOMM_REUSE_DLC);
	bacpy(&req.src, &device->src);
	bacpy(&req.dst, &device->dst);
	req.channel = port->channel;

	g_io_channel_unref(port->io);
	port->io = NULL;

	sk = g_io_channel_unix_get_fd(chan);
	port->id = ioctl(sk, RFCOMMCREATEDEV, &req);
	if (port->id < 0) {
		int err = -errno;
		error("ioctl(RFCOMMCREATEDEV): %s (%d)", strerror(-err), -err);
		reply = btd_error_failed(port->msg, strerror(-err));
		g_io_channel_shutdown(chan, TRUE, NULL);
		goto fail;
	}

	port->dev = g_strdup_printf("/dev/rfcomm%d", port->id);

	DBG("Serial port %s created", port->dev);

	g_io_channel_shutdown(chan, TRUE, NULL);

	/* Addressing connect port */
	fd = port_open(port);
	if (fd < 0)
		/* Open in progress: Wait the callback */
		return;

	open_notify(fd, 0, port);
	return;

fail:
	g_dbus_send_message(device->conn, reply);
	g_dbus_remove_watch(device->conn, port->listener_id);
	port->listener_id = 0;
}

static void get_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct serial_port *port = user_data;
	struct serial_device *device = port->device;
	sdp_record_t *record = NULL;
	sdp_list_t *protos;
	DBusMessage *reply;
	GError *gerr = NULL;

	if (!port->listener_id) {
		reply = NULL;
		goto failed;
	}

	if (err < 0) {
		error("Unable to get service record: %s (%d)", strerror(-err),
			-err);
		reply = btd_error_failed(port->msg, strerror(-err));
		goto failed;
	}

	if (!recs || !recs->data) {
		error("No record found");
		reply = btd_error_failed(port->msg, "No record found");
		goto failed;
	}

	record = recs->data;

	if (sdp_get_access_protos(record, &protos) < 0) {
		error("Unable to get access protos from port record");
		reply = btd_error_failed(port->msg, "Invalid channel");
		goto failed;
	}

	port->channel = sdp_get_proto_port(protos, RFCOMM_UUID);

	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	port->io = bt_io_connect(BT_IO_RFCOMM, rfcomm_connect_cb, port,
				NULL, &gerr,
				BT_IO_OPT_SOURCE_BDADDR, &device->src,
				BT_IO_OPT_DEST_BDADDR, &device->dst,
				BT_IO_OPT_CHANNEL, port->channel,
				BT_IO_OPT_INVALID);
	if (!port->io) {
		error("%s", gerr->message);
		reply = btd_error_failed(port->msg, gerr->message);
		g_error_free(gerr);
		goto failed;
	}

	return;

failed:
	g_dbus_remove_watch(device->conn, port->listener_id);
	port->listener_id = 0;
	g_dbus_send_message(device->conn, reply);
}

static int connect_port(struct serial_port *port)
{
	struct serial_device *device = port->device;
	uuid_t uuid;
	int err;

	if (!port->uuid)
		goto connect;

	err = bt_string2uuid(&uuid, port->uuid);
	if (err < 0)
		return err;

	sdp_uuid128_to_uuid(&uuid);

	return bt_search_service(&device->src, &device->dst, &uuid,
				get_record_cb, port, NULL);

connect:
	port->io = bt_io_connect(BT_IO_RFCOMM, rfcomm_connect_cb, port,
				NULL, NULL,
				BT_IO_OPT_SOURCE_BDADDR, &device->src,
				BT_IO_OPT_DEST_BDADDR, &device->dst,
				BT_IO_OPT_CHANNEL, port->channel,
				BT_IO_OPT_INVALID);
	if (port->io)
		return 0;

	return -errno;
}

static struct serial_port *create_port(struct serial_device *device,
					const char *uuid, uint8_t channel)
{
	struct serial_port *port;

	port = g_new0(struct serial_port, 1);
	port->uuid = g_strdup(uuid);
	port->channel = channel;
	port->device = device;
	port->id = -1;
	port->fd = -1;

	device->ports = g_slist_append(device->ports, port);

	return port;
}

static DBusMessage *port_connect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct serial_device *device = user_data;
	struct serial_port *port;
	const char *pattern;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &pattern,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	port = find_port(device->ports, pattern);
	if (!port) {
		char *endptr = NULL;
		int channel;

		channel = strtol(pattern, &endptr, 10);
		if ((endptr && *endptr != '\0') || channel < 1 || channel > 30)
			return btd_error_does_not_exist(msg);

		port = create_port(device, NULL, channel);
	}

	if (port->listener_id)
		return btd_error_failed(msg, "Port already in use");

	port->listener_id = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						port_owner_exited, port,
						NULL);
	port->msg = dbus_message_ref(msg);

	err = connect_port(port);
	if (err < 0) {
		error("%s", strerror(-err));
		g_dbus_remove_watch(conn, port->listener_id);
		port->listener_id = 0;

		return btd_error_failed(msg, strerror(-err));
	}

	return NULL;
}

static DBusMessage *port_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct serial_device *device = user_data;
	struct serial_port *port;
	const char *dev, *owner, *caller;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &dev,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	port = find_port(device->ports, dev);
	if (!port)
		return btd_error_does_not_exist(msg);

	if (!port->listener_id)
		return btd_error_not_connected(msg);

	owner = dbus_message_get_sender(port->msg);
	caller = dbus_message_get_sender(msg);
	if (!g_str_equal(owner, caller))
		return btd_error_not_authorized(msg);

	port_release(port);

	g_dbus_remove_watch(conn, port->listener_id);
	port->listener_id = 0;

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable port_methods[] = {
	{ "Connect",    "s", "s", port_connect, G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect", "s", "",  port_disconnect },
	{ }
};

static struct serial_device *create_serial_device(DBusConnection *conn,
					const char *path, bdaddr_t *src,
					bdaddr_t *dst)
{
	struct serial_device *device;

	device = g_new0(struct serial_device, 1);
	device->conn = dbus_connection_ref(conn);
	bacpy(&device->dst, dst);
	bacpy(&device->src, src);
	device->path = g_strdup(path);

	if (!g_dbus_register_interface(conn, path,
				SERIAL_PORT_INTERFACE,
				port_methods, NULL, NULL,
				device, path_unregister)) {
		error("D-Bus failed to register %s interface",
				SERIAL_PORT_INTERFACE);
		serial_device_free(device);
		return NULL;
	}

	DBG("Registered interface %s on path %s",
		SERIAL_PORT_INTERFACE, path);

	return device;
}

int port_register(DBusConnection *conn, const char *path, bdaddr_t *src,
			bdaddr_t *dst, const char *uuid, uint8_t channel)
{
	struct serial_device *device;
	struct serial_port *port;

	device = find_device(devices, path);
	if (!device) {
		device = create_serial_device(conn, path, src, dst);
		if (!device)
			return -1;
		devices = g_slist_append(devices, device);
	}

	if (find_port(device->ports, uuid))
		return 0;

	port = g_new0(struct serial_port, 1);
	port->uuid = g_strdup(uuid);
	port->channel = channel;
	port->device = device;
	port->id = -1;
	port->fd = -1;

	device->ports = g_slist_append(device->ports, port);

	return 0;
}

int port_unregister(const char *path)
{
	struct serial_device *device;

	device = find_device(devices, path);
	if (!device)
		return -ENOENT;

	g_slist_foreach(device->ports, (GFunc) serial_port_free, NULL);
	g_slist_free(device->ports);

	g_dbus_unregister_interface(device->conn, path, SERIAL_PORT_INTERFACE);

	return 0;
}
