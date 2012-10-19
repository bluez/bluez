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

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <gdbus.h>

#include "log.h"
#include "btio.h"
#include "dbus-common.h"
#include "adapter.h"
#include "device.h"

#include "error.h"
#include "common.h"
#include "connection.h"

#define NETWORK_PEER_INTERFACE "org.bluez.Network"
#define CON_SETUP_RETRIES      3
#define CON_SETUP_TO           9

typedef enum {
	CONNECTED,
	CONNECTING,
	DISCONNECTED
} conn_state;

struct network_peer {
	struct btd_device *device;
	GSList		*connections;
};

struct network_conn {
	btd_connection_cb cb;
	void		*cb_data;
	char		dev[16];	/* Interface name */
	uint16_t	id;		/* Role: Service Class Identifier */
	conn_state	state;
	GIOChannel	*io;
	char		*owner;		/* Connection initiator D-Bus client */
	guint		watch;		/* Disconnect watch */
	guint		dc_id;
	struct network_peer *peer;
	guint		attempt_cnt;
	guint		timeout_source;
};

struct __service_16 {
	uint16_t dst;
	uint16_t src;
} __attribute__ ((packed));

static GSList *peers = NULL;

static struct network_peer *find_peer(GSList *list, struct btd_device *device)
{
	for (; list; list = list->next) {
		struct network_peer *peer = list->data;

		if (peer->device == device)
			return peer;
	}

	return NULL;
}

static struct network_conn *find_connection(GSList *list, uint16_t id)
{
	for (; list; list = list->next) {
		struct network_conn *nc = list->data;

		if (nc->id == id)
			return nc;
	}

	return NULL;
}

static gboolean bnep_watchdog_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct network_conn *nc = data;
	gboolean connected = FALSE;
	const char *property = "";
	const char *path = device_get_path(nc->peer->device);

	emit_property_changed(path,
				NETWORK_PEER_INTERFACE, "Connected",
				DBUS_TYPE_BOOLEAN, &connected);
	emit_property_changed(path,
				NETWORK_PEER_INTERFACE, "Interface",
				DBUS_TYPE_STRING, &property);
	emit_property_changed(path,
				NETWORK_PEER_INTERFACE, "UUID",
				DBUS_TYPE_STRING, &property);
	device_remove_disconnect_watch(nc->peer->device, nc->dc_id);
	nc->dc_id = 0;
	if (nc->watch) {
		g_dbus_remove_watch(btd_get_dbus_connection(), nc->watch);
		nc->watch = 0;
	}

	info("%s disconnected", nc->dev);

	bnep_if_down(nc->dev);
	nc->state = DISCONNECTED;
	memset(nc->dev, 0, sizeof(nc->dev));
	strcpy(nc->dev, "bnep%d");

	return FALSE;
}

static void cancel_connection(struct network_conn *nc, int err)
{
	DBusConnection *conn = btd_get_dbus_connection();

	if (nc->timeout_source > 0) {
		g_source_remove(nc->timeout_source);
		nc->timeout_source = 0;
	}

	if (nc->watch) {
		g_dbus_remove_watch(conn, nc->watch);
		nc->watch = 0;
	}

	if (nc->cb)
		nc->cb(nc->peer->device, err, NULL, nc->cb_data);

	g_io_channel_shutdown(nc->io, TRUE, NULL);
	g_io_channel_unref(nc->io);
	nc->io = NULL;

	nc->state = DISCONNECTED;
}

static void connection_destroy(DBusConnection *conn, void *user_data)
{
	struct network_conn *nc = user_data;

	if (nc->state == CONNECTED) {
		bnep_if_down(nc->dev);
		bnep_kill_connection(device_get_address(nc->peer->device));
	} else if (nc->io)
		cancel_connection(nc, -EIO);

	if (nc->owner) {
		g_free(nc->owner);
		nc->owner = NULL;
	}
}

static void disconnect_cb(struct btd_device *device, gboolean removal,
				void *user_data)
{
	struct network_conn *nc = user_data;

	info("Network: disconnect %s", device_get_path(nc->peer->device));

	connection_destroy(NULL, user_data);
}

static gboolean bnep_setup_cb(GIOChannel *chan, GIOCondition cond,
							gpointer data)
{
	struct network_conn *nc = data;
	struct bnep_control_rsp *rsp;
	struct timeval timeo;
	char pkt[BNEP_MTU];
	ssize_t r;
	int sk;
	const char *pdev, *uuid;
	gboolean connected;
	const char *path;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (nc->timeout_source > 0) {
		g_source_remove(nc->timeout_source);
		nc->timeout_source = 0;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on l2cap server socket");
		goto failed;
	}

	sk = g_io_channel_unix_get_fd(chan);

	memset(pkt, 0, BNEP_MTU);
	r = read(sk, pkt, sizeof(pkt) -1);
	if (r < 0) {
		error("IO Channel read error");
		goto failed;
	}

	if (r == 0) {
		error("No packet received on l2cap socket");
		goto failed;
	}

	errno = EPROTO;

	if ((size_t) r < sizeof(*rsp)) {
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

	memset(&timeo, 0, sizeof(timeo));
	timeo.tv_sec = 0;

	setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));

	if (bnep_connadd(sk, BNEP_SVC_PANU, nc->dev)) {
		error("%s could not be added", nc->dev);
		goto failed;
	}

	bnep_if_up(nc->dev);
	pdev = nc->dev;
	uuid = bnep_uuid(nc->id);

	if (nc->cb)
		nc->cb(nc->peer->device, 0, pdev, nc->cb_data);

	path = device_get_path(nc->peer->device);

	connected = TRUE;
	emit_property_changed(path,
				NETWORK_PEER_INTERFACE, "Connected",
				DBUS_TYPE_BOOLEAN, &connected);
	emit_property_changed(path,
				NETWORK_PEER_INTERFACE, "Interface",
				DBUS_TYPE_STRING, &pdev);
	emit_property_changed(path,
				NETWORK_PEER_INTERFACE, "UUID",
				DBUS_TYPE_STRING, &uuid);

	nc->state = CONNECTED;
	nc->dc_id = device_add_disconnect_watch(nc->peer->device, disconnect_cb,
						nc, NULL);

	info("%s connected", nc->dev);
	/* Start watchdog */
	g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) bnep_watchdog_cb, nc);
	g_io_channel_unref(nc->io);
	nc->io = NULL;

	return FALSE;

failed:
	cancel_connection(nc, -EIO);

	return FALSE;
}

static int bnep_send_conn_req(struct network_conn *nc)
{
	struct bnep_setup_conn_req *req;
	struct __service_16 *s;
	unsigned char pkt[BNEP_MTU];
	int fd;

	/* Send request */
	req = (void *) pkt;
	req->type = BNEP_CONTROL;
	req->ctrl = BNEP_SETUP_CONN_REQ;
	req->uuid_size = 2;	/* 16bit UUID */
	s = (void *) req->service;
	s->dst = htons(nc->id);
	s->src = htons(BNEP_SVC_PANU);

	fd = g_io_channel_unix_get_fd(nc->io);
	if (write(fd, pkt, sizeof(*req) + sizeof(*s)) < 0) {
		int err = -errno;
		error("bnep connection req send failed: %s", strerror(errno));
		return err;
	}

	nc->attempt_cnt++;

	return 0;
}

static gboolean bnep_conn_req_to(gpointer user_data)
{
	struct network_conn *nc;

	nc = user_data;
	if (nc->attempt_cnt == CON_SETUP_RETRIES) {
		error("Too many bnep connection attempts");
	} else {
		error("bnep connection setup TO, retrying...");
		if (!bnep_send_conn_req(nc))
			return TRUE;
	}

	cancel_connection(nc, -ETIMEDOUT);

	return FALSE;
}

static int bnep_connect(struct network_conn *nc)
{
	int err;

	nc->attempt_cnt = 0;
	if ((err = bnep_send_conn_req(nc)))
		return err;

	nc->timeout_source = g_timeout_add_seconds(CON_SETUP_TO,
							bnep_conn_req_to, nc);

	g_io_add_watch(nc->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) bnep_setup_cb, nc);

	return 0;
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	struct network_conn *nc = data;
	const char *err_msg;
	int perr;

	if (err) {
		error("%s", err->message);
		err_msg = err->message;
		goto failed;
	}

	perr = bnep_connect(nc);
	if (perr < 0) {
		err_msg = strerror(-perr);
		error("bnep connect(): %s (%d)", err_msg, -perr);
		goto failed;
	}

	return;

failed:
	cancel_connection(nc, -EIO);
}

static void local_connect_cb(struct btd_device *device, int err,
						const char *pdev, void *data)
{
	DBusMessage *msg = data;
	DBusMessage *reply;

	if (err < 0) {
		reply = btd_error_failed(msg, strerror(-err));
		g_dbus_send_message(btd_get_dbus_connection(), reply);
		dbus_message_unref(msg);
		return;
	}

	g_dbus_send_reply(btd_get_dbus_connection(), msg,
						DBUS_TYPE_STRING, &pdev,
						DBUS_TYPE_INVALID);

	dbus_message_unref(msg);
}

static DBusMessage *local_connect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	const char *svc;
	uint16_t id;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &svc,
						DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	id = bnep_service_id(svc);

	err = connection_connect(peer->device, id, dbus_message_get_sender(msg),
							local_connect_cb, msg);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	dbus_message_ref(msg);

	return NULL;
}

/* Connect and initiate BNEP session */
int connection_connect(struct btd_device *device, uint16_t id,
					const char *owner,
					btd_connection_cb cb, void *data)
{
	struct network_peer *peer;
	struct network_conn *nc;
	GError *err = NULL;
	const bdaddr_t *src;
	const bdaddr_t *dst;

	peer = find_peer(peers, device);
	if (!peer)
		return -ENOENT;

	nc = find_connection(peer->connections, id);
	if (!nc)
		return -ENOTSUP;

	if (nc->state != DISCONNECTED)
		return -EALREADY;

	src = adapter_get_address(device_get_adapter(peer->device));
	dst = device_get_address(peer->device);

	nc->io = bt_io_connect(connect_cb, nc,
				NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, src,
				BT_IO_OPT_DEST_BDADDR, dst,
				BT_IO_OPT_PSM, BNEP_PSM,
				BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
				BT_IO_OPT_OMTU, BNEP_MTU,
				BT_IO_OPT_IMTU, BNEP_MTU,
				BT_IO_OPT_INVALID);
	if (!nc->io)
		return -EIO;

	nc->state = CONNECTING;
	nc->owner = g_strdup(owner);

	if (owner)
		nc->watch = g_dbus_add_disconnect_watch(
						btd_get_dbus_connection(),
						owner, connection_destroy,
						nc, NULL);

	return 0;
}

int connection_disconnect(struct btd_device *device, uint16_t id,
							const char *caller)
{
	struct network_peer *peer;
	struct network_conn *nc;

	peer = find_peer(peers, device);
	if (!peer)
		return -ENOENT;

	nc = find_connection(peer->connections, id);
	if (!nc)
		return -ENOTSUP;

	if (nc->state == DISCONNECTED)
		return 0;

	if (!g_str_equal(nc->owner, caller))
		return -EPERM;

	connection_destroy(NULL, nc);

	return 0;
}

static DBusMessage *local_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	const char *caller = dbus_message_get_sender(msg);
	GSList *l;

	for (l = peer->connections; l; l = l->next) {
		struct network_conn *nc = l->data;
		int err;

		if (nc->state == DISCONNECTED)
			continue;

		err = connection_disconnect(peer->device, nc->id, caller);
		if (err < 0)
			return btd_error_failed(msg, strerror(-err));

		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	return btd_error_not_connected(msg);
}

static DBusMessage *local_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	struct network_conn *nc = NULL;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	dbus_bool_t connected;
	const char *property;
	GSList *l;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Connected */
	for (l = peer->connections; l; l = l->next) {
		struct network_conn *tmp = l->data;

		if (tmp->state != CONNECTED)
			continue;

		nc = tmp;
		break;
	}

	connected = nc ? TRUE : FALSE;
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &connected);

	/* Interface */
	property = nc ? nc->dev : "";
	dict_append_entry(&dict, "Interface", DBUS_TYPE_STRING, &property);

	/* UUID */
	property = nc ? bnep_uuid(nc->id) : "";
	dict_append_entry(&dict, "UUID", DBUS_TYPE_STRING, &property);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static void connection_free(void *data)
{
	struct network_conn *nc = data;

	if (nc->dc_id)
		device_remove_disconnect_watch(nc->peer->device, nc->dc_id);

	connection_destroy(NULL, nc);

	g_free(nc);
	nc = NULL;
}

static void peer_free(struct network_peer *peer)
{
	g_slist_free_full(peer->connections, connection_free);
	btd_device_unref(peer->device);
	g_free(peer);
}

static void path_unregister(void *data)
{
	struct network_peer *peer = data;

	DBG("Unregistered interface %s on path %s",
		NETWORK_PEER_INTERFACE, device_get_path(peer->device));

	peers = g_slist_remove(peers, peer);
	peer_free(peer);
}

static const GDBusMethodTable connection_methods[] = {
	{ GDBUS_ASYNC_METHOD("Connect",
				GDBUS_ARGS({"uuid", "s"}),
				GDBUS_ARGS({"interface", "s"}),
				local_connect) },
	{ GDBUS_METHOD("Disconnect",
			NULL, NULL, local_disconnect) },
	{ GDBUS_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			local_get_properties) },
	{ }
};

static const GDBusSignalTable connection_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ }
};

void connection_unregister(struct btd_device *device)
{
	struct network_peer *peer;

	peer = find_peer(peers, device);
	if (!peer)
		return;

	g_slist_free_full(peer->connections, connection_free);
	peer->connections = NULL;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
						device_get_path(device),
						NETWORK_PEER_INTERFACE);
}

static struct network_peer *create_peer(struct btd_device *device)
{
	struct network_peer *peer;
	const char *path;

	peer = g_new0(struct network_peer, 1);
	peer->device = btd_device_ref(device);

	path = device_get_path(device);

	if (g_dbus_register_interface(btd_get_dbus_connection(), path,
					NETWORK_PEER_INTERFACE,
					connection_methods,
					connection_signals, NULL,
					peer, path_unregister) == FALSE) {
		error("D-Bus failed to register %s interface",
			NETWORK_PEER_INTERFACE);
		peer_free(peer);
		return NULL;
	}

	DBG("Registered interface %s on path %s",
		NETWORK_PEER_INTERFACE, path);

	return peer;
}

int connection_register(struct btd_device *device, uint16_t id)
{
	struct network_peer *peer;
	struct network_conn *nc;

	peer = find_peer(peers, device);
	if (!peer) {
		peer = create_peer(device);
		if (!peer)
			return -1;
		peers = g_slist_append(peers, peer);
	}

	nc = find_connection(peer->connections, id);
	if (nc)
		return 0;

	nc = g_new0(struct network_conn, 1);
	nc->id = id;
	memset(nc->dev, 0, sizeof(nc->dev));
	strcpy(nc->dev, "bnep%d");
	nc->state = DISCONNECTED;
	nc->peer = peer;

	peer->connections = g_slist_append(peer->connections, nc);

	return 0;
}
