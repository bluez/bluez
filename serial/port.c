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

#include <glib.h>
#include <gdbus.h>

#include "../src/dbus-common.h"

#include "logging.h"
#include "glib-helper.h"

#include "error.h"
#include "manager.h"
#include "storage.h"

#define SERIAL_PORT_INTERFACE	"org.bluez.Serial"
#define ERROR_INVALID_ARGS	"org.bluez.Error.InvalidArguments"
#define ERROR_DOES_NOT_EXIST	"org.bluez.Error.DoesNotExist"

#define MAX_OPEN_TRIES		5
#define OPEN_WAIT		300	/* ms */

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

	for (l = ports; l != NULL; l = l->next) {
		struct serial_port *port = l->data;
		uuid_t uuid;
		char *uuid_str;
		int ret;

		if (!strcasecmp(port->uuid, pattern))
			return port;

		if (port->dev && !strcmp(port->dev, pattern))
			return port;

		/* The following steps converts a potential friendly-name to a
		 * UUID-128 string and compares it with the port UUID (which is
		 * also stored as a UUID-128 string */

		if (bt_string2uuid(&uuid, pattern) < 0)
			continue;

		uuid_str = bt_uuid2string(&uuid);
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

	debug("Serial port %s released", port->dev);

	rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
	if (rfcomm_ctl < 0)
		return -errno;

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
	if (port->id >= 0)
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

	if (port->id >= 0)
		port_release(port);

	port->listener_id = 0;
}

static void path_unregister(void *data)
{
	struct serial_device *device = data;

	info("Unregistered interface %s on path %s", SERIAL_PORT_INTERFACE,
		device->path);

	devices = g_slist_remove(devices, device);
	serial_device_free(device);
}

void port_release_all(void)
{
	g_slist_foreach(devices, (GFunc) serial_device_free, NULL);
	g_slist_free(devices);
}

static inline DBusMessage *does_not_exist(DBusMessage *msg,
					const char *description)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".DoesNotExist",
				description);
}

static inline DBusMessage *invalid_arguments(DBusMessage *msg,
					const char *description)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
				description);
}

static inline DBusMessage *failed(DBusMessage *msg, const char *description)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				description);
}

static void open_notify(int fd, int err, struct serial_port *port)
{
	struct serial_device *device = port->device;
	DBusMessage *reply;

	if (err) {
		/* Max tries exceeded */
		port_release(port);
		reply = failed(port->msg, strerror(err));
	} else {
		reply = g_dbus_create_reply(port->msg,
				DBUS_TYPE_STRING, &port->dev,
				DBUS_TYPE_INVALID);
	}

	/* Reply to the requestor */
	g_dbus_send_message(device->conn, reply);
}

static gboolean open_continue(struct serial_port *port)
{
	int fd;
	static int ntries = MAX_OPEN_TRIES;

	if (!port->listener_id)
		return FALSE; /* Owner exited */

	fd = open(port->dev, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		int err = errno;
		error("Could not open %s: %s (%d)",
				port->dev, strerror(err), err);
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
		g_timeout_add(OPEN_WAIT, (GSourceFunc) open_continue, port);
		return -EINPROGRESS;
	}

	return fd;
}

static void rfcomm_connect_cb(GIOChannel *chan, int err_cb, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer user_data)
{
	struct serial_port *port = user_data;
	struct serial_device *device = port->device;
	struct rfcomm_dev_req req;
	int sk, err, fd;
	DBusMessage *reply;

	/* Owner exited? */
	if (!port->listener_id)
		return;

	if (err_cb < 0) {
		error("connect(): %s (%d)", strerror(-err_cb), -err_cb);
		reply = failed(port->msg, strerror(-err_cb));
		goto fail;
	}

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = (1 << RFCOMM_REUSE_DLC);
	bacpy(&req.src, &device->src);
	bacpy(&req.dst, &device->dst);
	req.channel = port->channel;

	sk = g_io_channel_unix_get_fd(chan);
	port->id = ioctl(sk, RFCOMMCREATEDEV, &req);
	g_io_channel_close(chan);
	g_io_channel_unref(chan);
	if (port->id < 0) {
		err = errno;
		error("ioctl(RFCOMMCREATEDEV): %s (%d)", strerror(err), err);
		reply = failed(port->msg, strerror(-err_cb));
		goto fail;
	}
	port->dev = g_strdup_printf("/dev/rfcomm%d", port->id);

	debug("Serial port %s created", port->dev);

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

static DBusMessage *port_connect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct serial_device *device = user_data;
	struct serial_port *port;
	const char *uuid;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &uuid,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	port = find_port(device->ports, uuid);
	if (!port)
		return does_not_exist(msg, "Does not match");

	if (port->listener_id)
		return failed(msg, "Port already in use");

	port->listener_id = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						port_owner_exited, port,
						NULL);
	port->msg = dbus_message_ref(msg);

	err = bt_rfcomm_connect(&device->src, &device->dst, port->channel,
				rfcomm_connect_cb, port);
	if (err < 0) {
		error("RFCOMM connect failed: %s(%d)", strerror(-err), -err);
		g_dbus_remove_watch(conn, port->listener_id);
		port->listener_id = 0;
		return failed(msg, strerror(-err));
	}

	return NULL;
}

static DBusMessage *port_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct serial_device *device = user_data;
	struct serial_port *port;
	const char *dev;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &dev,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	port = find_port(device->ports, dev);
	if (!port)
		return does_not_exist(msg, "Port does not exist");

	if (!port->listener_id)
		return failed(msg, "Not connected");

	if (port->id >= 0)
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

	info("Registered interface %s on path %s",
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

	device->ports = g_slist_append(device->ports, port);

	return 0;
}

int port_unregister(const char *path, const char *uuid)
{
	struct serial_device *device;
	struct serial_port *port;

	device = find_device(devices, path);
	if (!device)
		return -ENOENT;

	port = find_port(device->ports, uuid);
	if (!port)
		return -ENOENT;

	device->ports = g_slist_remove(device->ports, port);
	serial_port_free(port);
	if (device->ports)
		return 0;

	g_dbus_unregister_interface(device->conn, path, SERIAL_PORT_INTERFACE);

	return 0;
}
