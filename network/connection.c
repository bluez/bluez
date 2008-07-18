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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <gdbus.h>

#include "../hcid/dbus-common.h"

#include "logging.h"
#include "textfile.h"
#include "glib-helper.h"

#include "error.h"
#include "common.h"
#include "connection.h"

#define NETWORK_PANU_INTERFACE "org.bluez.network.Peer"
#define NETWORK_GN_INTERFACE "org.bluez.network.Hub"
#define NETWORK_NAP_INTERFACE "org.bluez.network.Router"

typedef enum {
	CONNECTED,
	CONNECTING,
	DISCONNECTED
} conn_state;

struct network_conn {
	DBusMessage	*msg;
	bdaddr_t	src;
	bdaddr_t	dst;
	char		*path;		/* D-Bus path */
	char		dev[16];	/* Interface name */
	uint16_t	id;		/* Role: Service Class Identifier */
	conn_state	state;
	int		sk;
};

struct __service_16 {
	uint16_t dst;
	uint16_t src;
} __attribute__ ((packed));

static DBusConnection *connection = NULL;
static const char *prefix = NULL;
static GSList *connections = NULL;

gint find_connection(gconstpointer a, gconstpointer b)
{
	const struct network_conn *nc = a;
	const char *path = b;

	return strcmp(nc->path, path);
}

static inline DBusMessage *not_supported(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
							"Not suported");
}

static inline DBusMessage *already_connected(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"Device already connected");
}

static inline DBusMessage *not_connected(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"Device not connected");
}

static inline DBusMessage *no_pending_connect(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
					"Device has no pending connect");
}

static inline DBusMessage *connection_attempt_failed(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ConnectionAttemptFailed",
				err ? strerror(err) : "Connection attempt failed");
}

static const char *id2iface(uint16_t id)
{
	switch (id) {
	case BNEP_SVC_PANU:
		return NETWORK_PANU_INTERFACE;
		break;
	case BNEP_SVC_GN:
		return NETWORK_GN_INTERFACE;
		break;
	case BNEP_SVC_NAP:
		return NETWORK_NAP_INTERFACE;
		break;
	default:
		return NULL;
	}
}

static gboolean bnep_watchdog_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct network_conn *nc = data;

	if (connection != NULL) {
		const char *interface = id2iface(nc->id);

		g_dbus_emit_signal(connection, nc->path,
						interface,
						"Disconnected",
						DBUS_TYPE_INVALID);
	}

	info("%s disconnected", nc->dev);

	bnep_if_down(nc->dev);
	nc->state = DISCONNECTED;
	memset(nc->dev, 0, 16);
	strncpy(nc->dev, prefix, strlen(prefix));
	g_io_channel_close(chan);

	return FALSE;
}

static gboolean bnep_connect_cb(GIOChannel *chan, GIOCondition cond,
							gpointer data)
{
	struct network_conn *nc = data;
	struct bnep_control_rsp *rsp;
	char pkt[BNEP_MTU];
	gsize r;
	int sk;
	DBusMessage *reply;
	const char *pdev;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on l2cap server socket");
		goto failed;
	}

	memset(pkt, 0, BNEP_MTU);
	if (g_io_channel_read(chan, pkt, sizeof(pkt) - 1,
				&r) != G_IO_ERROR_NONE) {
		error("IO Channel read error");
		goto failed;
	}

	if (r <= 0) {
		error("No packet received on l2cap socket");
		goto failed;
	}

	errno = EPROTO;

	if (r < sizeof(*rsp)) {
		error("Packet received is not bnep type");
		goto failed;
	}

	rsp = (void *) pkt;
	if (rsp->type != BNEP_CONTROL) {
		error("Packet received is not bnep type");
		goto failed;
	}

	if (rsp->ctrl != BNEP_SETUP_CONN_RSP)
		return TRUE;

	r = ntohs(rsp->resp);

	if (r != BNEP_SUCCESS) {
		error("bnep failed");
		goto failed;
	}

	sk = g_io_channel_unix_get_fd(chan);

	if (bnep_connadd(sk, BNEP_SVC_PANU, nc->dev)) {
		error("%s could not be added", nc->dev);
		goto failed;
	}

	bnep_if_up(nc->dev, nc->id);
	g_dbus_emit_signal(connection, nc->path,
					id2iface(nc->id),
					"Connected",
					DBUS_TYPE_INVALID);

	pdev = nc->dev;

	reply = g_dbus_create_reply(nc->msg, DBUS_TYPE_STRING, &pdev,
							DBUS_TYPE_INVALID);
	g_dbus_send_message(connection, reply);

	nc->state = CONNECTED;

	info("%s connected", nc->dev);
	/* Start watchdog */
	g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) bnep_watchdog_cb, nc);
	return FALSE;

failed:
	if (nc->state != DISCONNECTED) {
		nc->state = DISCONNECTED;
		reply = connection_attempt_failed(nc->msg, EIO);
		g_dbus_send_message(connection, reply);
		g_io_channel_close(chan);
	}

	return FALSE;
}

static int bnep_connect(struct network_conn *nc)
{
	struct bnep_setup_conn_req *req;
	struct __service_16 *s;
	unsigned char pkt[BNEP_MTU];
	GIOChannel *io;
	int err = 0;

	/* Send request */
	req = (void *) pkt;
	req->type = BNEP_CONTROL;
	req->ctrl = BNEP_SETUP_CONN_REQ;
	req->uuid_size = 2;	/* 16bit UUID */
	s = (void *) req->service;
	s->dst = htons(nc->id);
	s->src = htons(BNEP_SVC_PANU);

	io = g_io_channel_unix_new(nc->sk);
	g_io_channel_set_close_on_unref(io, FALSE);

	if (send(nc->sk, pkt, sizeof(*req) + sizeof(*s), 0) < 0) {
		err = -errno;
		goto out;
	}

	g_io_add_watch(io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) bnep_connect_cb, nc);

out:
	g_io_channel_unref(io);
	return err;
}

static void connect_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;

	if (err < 0) {
		error("l2cap connect(): %s (%d)", strerror(-err), -err);
		goto failed;
	}

	nc->sk = g_io_channel_unix_get_fd(chan);

	err = bnep_connect(nc);
	if (err < 0) {
		error("bnep connect(): %s (%d)", strerror(-err), -err);
		g_io_channel_close(chan);
		g_io_channel_unref(chan);
		goto failed;
	}

	return;

failed:
	nc->state = DISCONNECTED;

	reply = connection_attempt_failed(nc->msg, -err);
	g_dbus_send_message(connection, reply);
}

static DBusMessage *get_interface(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	const char *pdev = nc->dev;

	if (nc->state != CONNECTED)
		return not_connected(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_STRING, &pdev,
						DBUS_TYPE_INVALID);
}

/* Connect and initiate BNEP session */
static DBusMessage *connection_connect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	int err;

	if (nc->state != DISCONNECTED)
		return already_connected(msg);

	nc->state = CONNECTING;
	nc->msg = dbus_message_ref(msg);

	err = bt_l2cap_connect(&nc->src, &nc->dst, BNEP_PSM, BNEP_MTU,
							connect_cb, nc);
	if (err < 0) {
		error("Connect failed. %s(%d)", strerror(errno), errno);
		dbus_message_unref(nc->msg);
		nc->msg = NULL;
		nc->state = DISCONNECTED;
		return connection_attempt_failed(msg, -err);
	}

	return NULL;
}

static DBusMessage *connection_cancel(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;

	if (nc->state != CONNECTING)
		return no_pending_connect(msg);

	close(nc->sk);
	nc->state = DISCONNECTED;

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *connection_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;

	if (nc->state != CONNECTED)
		return not_connected(msg);

	bnep_if_down(nc->dev);
	bnep_kill_connection(&nc->dst);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *is_connected(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	gboolean up = (nc->state == CONNECTED);

	return g_dbus_create_reply(msg, DBUS_TYPE_BOOLEAN, &up,
						DBUS_TYPE_INVALID);
}

static void connection_free(struct network_conn *nc)
{
	if (!nc)
		return;

	if (nc->path)
		g_free(nc->path);

	if (nc->state == CONNECTED) {
		bnep_if_down(nc->dev);
		bnep_kill_connection(&nc->dst);
	}

	g_free(nc);
	nc = NULL;
}

static void path_unregister(void *data)
{
	struct network_conn *nc = data;
	const char *interface = id2iface(nc->id);

	info("Unregistered interface %s on path %s", interface, nc->path);

	connections = g_slist_remove(connections, nc);
	connection_free(nc);
}

static GDBusMethodTable connection_methods[] = {
	{ "GetInterface",	"",	"s",	get_interface		},
	{ "Connect",		"",	"s",	connection_connect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "CancelConnect",	"",	"",	connection_cancel	},
	{ "Disconnect",		"",	"",	connection_disconnect	},
	{ "IsConnected",	"",	"b",	is_connected		},
	{ }
};

static GDBusSignalTable connection_signals[] = {
	{ "Connected",		""	},
	{ "Disconnected",	""	},
	{ }
};

void connection_unregister(const char *path, uint16_t id)
{
	const char *interface = id2iface(id);

	g_dbus_unregister_interface(connection, path, interface);
}

int connection_register(const char *path, bdaddr_t *src, bdaddr_t *dst,
			uint16_t id)
{
	struct network_conn *nc;
	bdaddr_t default_src;
	int dev_id;
	const char *interface;

	if (!path)
		return -EINVAL;

	bacpy(&default_src, BDADDR_ANY);
	dev_id = hci_get_route(&default_src);
	if (dev_id < 0 || hci_devba(dev_id, &default_src) < 0)
		return -1;

	nc = g_new0(struct network_conn, 1);
	interface = id2iface(id);

	if (g_dbus_register_interface(connection, path,
					interface,
					connection_methods,
					connection_signals, NULL,
					nc, path_unregister) == FALSE) {
		error("D-Bus failed to register %s interface", interface);
		return -1;
	}

	nc->path = g_strdup(path);
	bacpy(&nc->src, src);
	bacpy(&nc->dst, dst);
	nc->id = id;
	memset(nc->dev, 0, 16);
	strncpy(nc->dev, prefix, strlen(prefix));
	nc->state = DISCONNECTED;

	connections = g_slist_append(connections, nc);

	info("Registered interface %s on path %s", interface, path);

	return 0;
}

int connection_init(DBusConnection *conn, const char *iface_prefix)
{
	connection = dbus_connection_ref(conn);
	prefix = iface_prefix;

	return 0;
}

void connection_exit()
{
	dbus_connection_unref(connection);
	connection = NULL;
	prefix = NULL;
}
