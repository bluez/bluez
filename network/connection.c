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
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <gdbus.h>

#include "logging.h"
#include "glib-helper.h"
#include "dbus-common.h"

#include "error.h"
#include "common.h"

#define NETWORK_PEER_INTERFACE "org.bluez.Network"

typedef enum {
	CONNECTED,
	CONNECTING,
	DISCONNECTED
} conn_state;

struct network_peer {
	bdaddr_t	src;
	bdaddr_t	dst;
	char		*path;		/* D-Bus path */
	GSList		*connections;
};

struct network_conn {
	DBusMessage	*msg;
	char		dev[16];	/* Interface name */
	uint16_t	id;		/* Role: Service Class Identifier */
	conn_state	state;
	int		sk;
	struct network_peer *peer;
};

struct __service_16 {
	uint16_t dst;
	uint16_t src;
} __attribute__ ((packed));

static DBusConnection *connection = NULL;
static const char *prefix = NULL;
static GSList *peers = NULL;

static struct network_peer *find_peer(GSList *list, const char *path)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct network_peer *peer = l->data;

		if (!strcmp(peer->path, path))
			return peer;
	}

	return NULL;
}

static struct network_conn *find_connection(GSList *list, uint16_t id)
{
	GSList *l;

	for (l = list; l; l = l->next) {
		struct network_conn *nc = l->data;

		if (nc->id == id)
			return nc;
	}

	return NULL;
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

static inline DBusMessage *connection_attempt_failed(DBusMessage *msg, int err)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".ConnectionAttemptFailed",
				err ? strerror(err) : "Connection attempt failed");
}

static gboolean bnep_watchdog_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct network_conn *nc = data;

	if (connection != NULL) {
		const char *device = nc->dev;
		gboolean connected = FALSE;
		const char *property = "";
		g_dbus_emit_signal(connection, nc->peer->path,
				NETWORK_PEER_INTERFACE, "Disconnected",
				DBUS_TYPE_STRING, &device,
				DBUS_TYPE_INVALID);
		dbus_connection_emit_property_changed(connection,
						nc->peer->path,
						NETWORK_PEER_INTERFACE,
						"Connected",
						DBUS_TYPE_BOOLEAN, &connected);
		dbus_connection_emit_property_changed(connection,
						nc->peer->path,
						NETWORK_PEER_INTERFACE,
						"Device",
						DBUS_TYPE_STRING, &property);
		dbus_connection_emit_property_changed(connection,
						nc->peer->path,
						NETWORK_PEER_INTERFACE,
						"UUID",
						DBUS_TYPE_STRING, &property);
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
	struct timeval timeo;
	char pkt[BNEP_MTU];
	gsize r;
	int sk;
	DBusMessage *reply;
	const char *pdev, *uuid;
	gboolean connected;

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

	memset(&timeo, 0, sizeof(timeo));
	timeo.tv_sec = 0;

	setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));

	if (bnep_connadd(sk, BNEP_SVC_PANU, nc->dev)) {
		error("%s could not be added", nc->dev);
		goto failed;
	}

	bnep_if_up(nc->dev, nc->id);
	pdev = nc->dev;
	uuid = bnep_uuid(nc->id);

	g_dbus_send_reply(connection, nc->msg,
			DBUS_TYPE_STRING, &pdev,
			DBUS_TYPE_INVALID);

	connected = TRUE;
	g_dbus_emit_signal(connection, nc->peer->path,
			NETWORK_PEER_INTERFACE, "Connected",
			DBUS_TYPE_STRING, &pdev,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);
	dbus_connection_emit_property_changed(connection, nc->peer->path,
					NETWORK_PEER_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &connected);
	dbus_connection_emit_property_changed(connection, nc->peer->path,
					NETWORK_PEER_INTERFACE, "Device",
					DBUS_TYPE_BOOLEAN, &pdev);
	dbus_connection_emit_property_changed(connection, nc->peer->path,
					NETWORK_PEER_INTERFACE, "UUID",
					DBUS_TYPE_BOOLEAN, &uuid);

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
	struct timeval timeo;
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

	memset(&timeo, 0, sizeof(timeo));
	timeo.tv_sec = 30;

	setsockopt(nc->sk, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));

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

/* Connect and initiate BNEP session */
static DBusMessage *connection_connect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	struct network_conn *nc;
	const char *svc;
	uint16_t id;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &svc,
						DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	id = bnep_service_id(svc);
	nc = find_connection(peer->connections, id);
	if (!nc)
		return not_supported(msg);

	if (nc->state != DISCONNECTED)
		return already_connected(msg);

	nc->state = CONNECTING;
	nc->msg = dbus_message_ref(msg);

	err = bt_l2cap_connect(&peer->src, &peer->dst, BNEP_PSM, BNEP_MTU,
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

	if (nc->state == CONNECTED) {
		bnep_if_down(nc->dev);
		bnep_kill_connection(&nc->peer->dst);
	} else
		close(nc->sk);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *connection_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	GSList *l;

	for (l = peer->connections; l; l = l->next) {
		struct network_conn *nc = l->data;

		if (nc->state == DISCONNECTED)
			continue;

		return connection_cancel(conn, msg, nc);
	}

	return not_connected(msg);
}

static DBusMessage *is_connected(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	GSList *l;
	dbus_bool_t up = FALSE;

	for (l = peer->connections; l; l = l->next) {
		struct network_conn *nc = l->data;

		if (nc->state != CONNECTED)
			continue;

		up = TRUE;
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_BOOLEAN, &up,
						DBUS_TYPE_INVALID);
}

static DBusMessage *connection_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	struct network_conn *nc;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	dbus_bool_t connected;
	const char *property;
	GSList *l;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Connected */
	for (l = peer->connections; l; l = l->next) {
		nc = l->data;

		if (nc->state == CONNECTED)
			break;
	}
	connected = (l != NULL);
	dbus_message_iter_append_dict_entry(&dict, "Connected",
						DBUS_TYPE_BOOLEAN, &connected);

	/* Device */
	property = connected ? nc->dev : "";
	dbus_message_iter_append_dict_entry(&dict, "Device",
						DBUS_TYPE_STRING, &property);

	/* UUID */
	property = connected ? bnep_uuid(nc->id) : "";
	dbus_message_iter_append_dict_entry(&dict, "UUID",
						DBUS_TYPE_STRING, &property);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static void connection_free(struct network_conn *nc)
{
	if (nc->state == CONNECTED) {
		bnep_if_down(nc->dev);
		bnep_kill_connection(&nc->peer->dst);
	} else if (nc->state == CONNECTING)
		close(nc->sk);

	g_free(nc);
	nc = NULL;
}

static void peer_free(struct network_peer *peer)
{
	g_slist_foreach(peer->connections, (GFunc) connection_free, NULL);
	g_slist_free(peer->connections);
	g_free(peer->path);
	g_free(peer);
}

static void path_unregister(void *data)
{
	struct network_peer *peer = data;

	info("Unregistered interface %s on path %s",
		NETWORK_PEER_INTERFACE, peer->path);

	peers = g_slist_remove(peers, peer);
	peer_free(peer);
}

static GDBusMethodTable connection_methods[] = {
	{ "Connect",		"s",	"s",	connection_connect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",		"",	"",	connection_disconnect	},
	{ "IsConnected",	"",	"b",	is_connected,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "GetProperties",	"",	"a{sv}",connection_get_properties },
	{ }
};

static GDBusSignalTable connection_signals[] = {
	{ "Connected",		"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "Disconnected",	"",	G_DBUS_SIGNAL_FLAG_DEPRECATED},
	{ "PropertyChanged",	"sv"	},
	{ }
};

void connection_unregister(const char *path, uint16_t id)
{
	struct network_peer *peer;
	struct network_conn *nc;

	peer = find_peer(peers, path);
	if (!peer)
		return;

	nc = find_connection(peer->connections, id);
	if (!nc)
		return;

	peer->connections = g_slist_remove(peer->connections, nc);
	connection_free(nc);
	if (peer->connections)
		return;

	g_dbus_unregister_interface(connection, path, NETWORK_PEER_INTERFACE);
}

static struct network_peer *create_peer(const char *path, bdaddr_t *src,
				bdaddr_t *dst)
{
	struct network_peer *peer;

	peer = g_new0(struct network_peer, 1);
	peer->path = g_strdup(path);
	bacpy(&peer->src, src);
	bacpy(&peer->dst, dst);

	if (g_dbus_register_interface(connection, path,
					NETWORK_PEER_INTERFACE,
					connection_methods,
					connection_signals, NULL,
					peer, path_unregister) == FALSE) {
		error("D-Bus failed to register %s interface",
			NETWORK_PEER_INTERFACE);
		peer_free(peer);
		return NULL;
	}

	info("Registered interface %s on path %s",
		NETWORK_PEER_INTERFACE, path);

	return peer;
}

int connection_register(const char *path, bdaddr_t *src, bdaddr_t *dst,
			uint16_t id)
{
	struct network_peer *peer;
	struct network_conn *nc;

	if (!path)
		return -EINVAL;

	peer = find_peer(peers, path);
	if (!peer) {
		peer = create_peer(path, src, dst);
		if (!peer)
			return -1;
		peers = g_slist_append(peers, peer);
	}

	nc = find_connection(peer->connections, id);
	if (nc)
		return 0;

	nc = g_new0(struct network_conn, 1);
	nc->id = id;
	memset(nc->dev, 0, 16);
	strncpy(nc->dev, prefix, strlen(prefix));
	nc->state = DISCONNECTED;
	nc->peer = peer;

	peer->connections = g_slist_append(peer->connections, nc);

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
