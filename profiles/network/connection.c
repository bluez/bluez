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
#include <gdbus/gdbus.h>
#include <btio/btio.h>

#include "log.h"
#include "dbus-common.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"

#include "error.h"
#include "common.h"
#include "connection.h"

#define NETWORK_PEER_INTERFACE "org.bluez.Network1"
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
	struct btd_service *service;
	char		dev[16];	/* Interface name */
	uint16_t	id;		/* Role: Service Class Identifier */
	conn_state	state;
	GIOChannel	*io;
	guint		dc_id;
	struct network_peer *peer;
	guint		attempt_cnt;
	guint		timeout_source;
	DBusMessage	*connect;
};

struct __service_16 {
	uint16_t dst;
	uint16_t src;
} __attribute__ ((packed));

static GSList *peers = NULL;

static uint16_t get_service_id(struct btd_service *service)
{
	return bnep_service_id(btd_service_get_profile(service)->remote_uuid);
}

static struct network_peer *find_peer(GSList *list, struct btd_device *device)
{
	for (; list; list = list->next) {
		struct network_peer *peer = list->data;

		if (peer->device == device)
			return peer;
	}

	return NULL;
}

static struct network_conn *find_connection_by_state(GSList *list,
							conn_state state)
{
	for (; list; list = list->next) {
		struct network_conn *nc = list->data;

		if (nc->state == state)
			return nc;
	}

	return NULL;
}

static gboolean bnep_watchdog_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct network_conn *nc = data;
	DBusConnection *conn = btd_get_dbus_connection();
	const char *path = device_get_path(nc->peer->device);

	g_dbus_emit_property_changed(conn, path,
					NETWORK_PEER_INTERFACE, "Connected");
	g_dbus_emit_property_changed(conn, path,
					NETWORK_PEER_INTERFACE, "Interface");
	g_dbus_emit_property_changed(conn, path,
					NETWORK_PEER_INTERFACE, "UUID");
	device_remove_disconnect_watch(nc->peer->device, nc->dc_id);
	nc->dc_id = 0;

	btd_service_disconnecting_complete(nc->service, 0);

	info("%s disconnected", nc->dev);

	bnep_if_down(nc->dev);
	nc->state = DISCONNECTED;
	memset(nc->dev, 0, sizeof(nc->dev));
	strcpy(nc->dev, "bnep%d");

	return FALSE;
}

static void local_connect_cb(struct network_conn *nc, int err)
{
	DBusConnection *conn = btd_get_dbus_connection();
	const char *pdev = nc->dev;

	if (err < 0) {
		DBusMessage *reply = btd_error_failed(nc->connect,
							strerror(-err));
		g_dbus_send_message(conn, reply);
	} else {
		g_dbus_send_reply(conn, nc->connect, DBUS_TYPE_STRING, &pdev,
							DBUS_TYPE_INVALID);
	}

	dbus_message_unref(nc->connect);
	nc->connect = NULL;
}

static void cancel_connection(struct network_conn *nc, int err)
{
	if (nc->timeout_source > 0) {
		g_source_remove(nc->timeout_source);
		nc->timeout_source = 0;
	}

	btd_service_connecting_complete(nc->service, err);
	if (nc->connect)
		local_connect_cb(nc, err);

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
	const char *path;
	DBusConnection *conn;

	DBG("cond %u", cond);

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

	btd_service_connecting_complete(nc->service, 0);
	if (nc->connect)
		local_connect_cb(nc, 0);

	conn = btd_get_dbus_connection();
	path = device_get_path(nc->peer->device);

	g_dbus_emit_property_changed(conn, path,
					NETWORK_PEER_INTERFACE, "Connected");
	g_dbus_emit_property_changed(conn, path,
					NETWORK_PEER_INTERFACE, "Interface");
	g_dbus_emit_property_changed(conn, path,
					NETWORK_PEER_INTERFACE, "UUID");

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

	DBG("");

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
		if (bnep_send_conn_req(nc) == 0)
			return TRUE;
	}

	cancel_connection(nc, -ETIMEDOUT);

	return FALSE;
}

static int bnep_connect(struct network_conn *nc)
{
	int err;

	nc->attempt_cnt = 0;

	err = bnep_send_conn_req(nc);
	if (err < 0)
		return err;

	nc->timeout_source = g_timeout_add_seconds(CON_SETUP_TO,
							bnep_conn_req_to, nc);

	g_io_add_watch(nc->io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
							bnep_setup_cb, nc);

	return 0;
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	struct network_conn *nc = data;
	int perr;

	if (err) {
		error("%s", err->message);
		goto failed;
	}

	perr = bnep_connect(nc);
	if (perr < 0) {
		error("bnep connect(): %s (%d)", strerror(-perr), -perr);
		goto failed;
	}

	return;

failed:
	cancel_connection(nc, -EIO);
}

static DBusMessage *local_connect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	struct btd_service *service;
	struct network_conn *nc;
	const char *svc;
	const char *uuid;
	uint16_t id;
	int err;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &svc,
						DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	id = bnep_service_id(svc);
	uuid = bnep_uuid(id);

	if (uuid == NULL)
		return btd_error_invalid_args(msg);

	service = btd_device_get_service(peer->device, uuid);
	if (service == NULL)
		return btd_error_not_supported(msg);

	nc = btd_service_get_user_data(service);

	if (nc->connect != NULL)
		return btd_error_busy(msg);

	err = connection_connect(nc->service);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	nc->connect = dbus_message_ref(msg);

	return NULL;
}

/* Connect and initiate BNEP session */
int connection_connect(struct btd_service *service)
{
	struct network_conn *nc = btd_service_get_user_data(service);
	struct network_peer *peer = nc->peer;
	uint16_t id = get_service_id(service);
	GError *err = NULL;
	const bdaddr_t *src;
	const bdaddr_t *dst;

	DBG("id %u", id);

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

	return 0;
}

int connection_disconnect(struct btd_service *service)
{
	struct network_conn *nc = btd_service_get_user_data(service);

	if (nc->state == DISCONNECTED)
		return 0;

	connection_destroy(NULL, nc);

	return 0;
}

static DBusMessage *local_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_peer *peer = data;
	GSList *l;

	for (l = peer->connections; l; l = l->next) {
		struct network_conn *nc = l->data;
		int err;

		if (nc->state == DISCONNECTED)
			continue;

		err = connection_disconnect(nc->service);
		if (err < 0)
			return btd_error_failed(msg, strerror(-err));

		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	}

	return btd_error_not_connected(msg);
}

static gboolean
network_property_get_connected(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct network_peer *peer = data;
	struct network_conn *nc;
	dbus_bool_t connected;

	nc = find_connection_by_state(peer->connections, CONNECTED);
	connected = nc != NULL ? TRUE : FALSE;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &connected);

	return TRUE;
}

static gboolean network_property_exists(const GDBusPropertyTable *property,
								void *data)
{
	struct network_peer *peer = data;
	struct network_conn *nc;

	nc = find_connection_by_state(peer->connections, CONNECTED);
	if (nc == NULL)
		return FALSE;

	return TRUE;
}

static gboolean
network_property_get_interface(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct network_peer *peer = data;
	struct network_conn *nc;
	const char *iface;

	nc = find_connection_by_state(peer->connections, CONNECTED);
	if (nc == NULL)
		return FALSE;

	iface = nc->dev;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &iface);

	return TRUE;
}

static gboolean network_property_get_uuid(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct network_peer *peer = data;
	struct network_conn *nc;
	const char *uuid;

	nc = find_connection_by_state(peer->connections, CONNECTED);
	if (nc == NULL)
		return FALSE;

	uuid = bnep_uuid(nc->id);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &uuid);

	return TRUE;
}

static void connection_free(void *data)
{
	struct network_conn *nc = data;

	if (nc->dc_id)
		device_remove_disconnect_watch(nc->peer->device, nc->dc_id);

	connection_destroy(NULL, nc);

	if (nc->connect)
		dbus_message_unref(nc->connect);

	btd_service_unref(nc->service);
	g_free(nc);
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
	{ }
};

static const GDBusPropertyTable connection_properties[] = {
	{ "Connected", "b", network_property_get_connected },
	{ "Interface", "s", network_property_get_interface, NULL,
						network_property_exists },
	{ "UUID", "s", network_property_get_uuid, NULL,
						network_property_exists },
	{ }
};

void connection_unregister(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct network_conn *conn = btd_service_get_user_data(service);
	struct network_peer *peer = conn->peer;
	uint16_t id = get_service_id(service);

	DBG("%s id %u", device_get_path(device), id);

	peer->connections = g_slist_remove(peer->connections, conn);
	connection_free(conn);

	if (peer->connections != NULL)
		return;

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
					NULL, connection_properties,
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

int connection_register(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct network_peer *peer;
	struct network_conn *nc;
	uint16_t id = get_service_id(service);

	DBG("%s id %u", device_get_path(device), id);

	peer = find_peer(peers, device);
	if (!peer) {
		peer = create_peer(device);
		if (!peer)
			return -1;
		peers = g_slist_append(peers, peer);
	}

	nc = g_new0(struct network_conn, 1);
	nc->id = id;
	memset(nc->dev, 0, sizeof(nc->dev));
	strcpy(nc->dev, "bnep%d");
	nc->service = btd_service_ref(service);
	nc->state = DISCONNECTED;
	nc->peer = peer;

	btd_service_set_user_data(service, nc);

	DBG("id %u registered", id);

	peer->connections = g_slist_append(peer->connections, nc);

	return 0;
}
