/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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
#include <stdlib.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>

#include <glib.h>

#include <netinet/in.h>

#include "logging.h"
#include "dbus.h"
#include "error.h"
#include "common.h"

#define NETWORK_CONNECTION_INTERFACE "org.bluez.network.Connection"
#include "connection.h"

struct network_conn {
	DBusConnection *conn;
	DBusMessage *msg;
	bdaddr_t src;
	bdaddr_t dst;
	char *path;	/* D-Bus path */
	char *dev;	/* BNEP interface name */
	uint16_t id;	/* Service Class Identifier */
	gboolean up;
	int sk;
};

struct __service_16 {
	uint16_t dst;
	uint16_t src;
} __attribute__ ((packed));

static gboolean bnep_watchdog_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct network_conn *nc = data;
	DBusMessage *signal;

	signal = dbus_message_new_signal(nc->path,
			NETWORK_CONNECTION_INTERFACE, "Disconnected");

	send_message_and_unref(nc->conn, signal);
	info("%s disconnected", nc->dev);
	return (nc->up = FALSE);
}

static gboolean bnep_connect_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct network_conn *nc = data;
	struct bnep_control_rsp *rsp;
	char pkt[BNEP_MTU];
	gsize r;
	int sk;
	DBusMessage *reply, *signal;

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

	signal = dbus_message_new_signal(nc->path,
			NETWORK_CONNECTION_INTERFACE, "Connected");

	send_message_and_unref(nc->conn, signal);

	reply = dbus_message_new_method_return(nc->msg);

	send_message_and_unref(nc->conn, reply);

	nc->up = TRUE;

	info("%s connected", nc->dev);
	/* Start watchdog */
	g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) bnep_watchdog_cb, nc);
	return FALSE;
failed:
	err_connection_failed(nc->conn, nc->msg, "bnep failed");
	g_io_channel_close(chan);
	g_io_channel_unref(chan);
	return FALSE;
}

static int bnep_connect(struct network_conn *nc)
{
	struct bnep_setup_conn_req *req;
	struct __service_16 *s;
	unsigned char pkt[BNEP_MTU];
	GIOChannel *io;

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
	if (send(nc->sk, pkt, sizeof(*req) + sizeof(*s), 0) != -1) {
		g_io_add_watch(io, G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				(GIOFunc) bnep_connect_cb, nc);
		return 0;
	}

	g_io_channel_unref(io);
	return -1;
}

static gboolean l2cap_connect_cb(GIOChannel *chan,
			GIOCondition cond, gpointer data)
{
	struct network_conn *nc = data;
	socklen_t len;
	int sk, ret;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		goto failed;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		error("getsockopt(SO_ERROR): %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if (ret != 0) {
		error("connect(): %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if (bnep_connect(nc)) {
		error("connect(): %s (%d)", strerror(errno), errno);
		goto failed;
	}

	g_io_channel_unref(chan);
	return FALSE;
failed:
	err_connection_failed(nc->conn, nc->msg, strerror(errno));
	g_io_channel_close(chan);
	g_io_channel_unref(chan);
	return FALSE;
}

static int l2cap_connect(struct network_conn *nc)
{
	struct l2cap_options l2o;
	struct sockaddr_l2 l2a;
	socklen_t olen;
	char addr[18];
	GIOChannel *io;

	ba2str(&nc->dst, addr);
	info("Connecting to %s", addr);

	/* Setup L2CAP options according to BNEP spec */
	memset(&l2o, 0, sizeof(l2o));
	olen = sizeof(l2o);
	getsockopt(nc->sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, &olen);
	l2o.imtu = l2o.omtu = BNEP_MTU;
	setsockopt(nc->sk, SOL_L2CAP, L2CAP_OPTIONS, &l2o, sizeof(l2o));

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, &nc->src);

	if (bind(nc->sk, (struct sockaddr *) &l2a, sizeof(l2a))) {
		error("Bind failed. %s(%d)", strerror(errno), errno);
		return -1;
	}

	memset(&l2a, 0, sizeof(l2a));
	l2a.l2_family = AF_BLUETOOTH;
	bacpy(&l2a.l2_bdaddr, &nc->dst);
	l2a.l2_psm = htobs(BNEP_PSM);

	if (set_nonblocking(nc->sk) < 0) {
		error("Set non blocking: %s (%d)", strerror(errno), errno);
		return -1;
	}

	io = g_io_channel_unix_new(nc->sk);
	g_io_channel_set_close_on_unref(io, FALSE);

	if (connect(nc->sk, (struct sockaddr *) &l2a, sizeof(l2a))) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			error("Connect failed. %s(%d)", strerror(errno),
					errno);
			g_io_channel_close(io);
			g_io_channel_unref(io);
			return -1;
		}
		g_io_add_watch(io, G_IO_OUT | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) l2cap_connect_cb, nc);

	} else {
		l2cap_connect_cb(io, G_IO_OUT, nc);
	}

	return 0;
}

static DBusHandlerResult get_address(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;
	char raddr[18];

	ba2str(&nc->dst, raddr);
	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, raddr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_uuid(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_conn *nc = data;
	const char *uuid;
	DBusMessage *reply;

	uuid = bnep_uuid(nc->id);
	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &uuid,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_name(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_description(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_interface(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &nc->dev,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

/* Connect and initiate BNEP session */
static DBusHandlerResult connection_connect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	DBusError derr;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	nc->sk = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (nc->sk < 0) {
		error("Cannot create L2CAP socket. %s(%d)", strerror(errno),
				errno);
		goto fail;
	}

	if(l2cap_connect(nc)) {
		error("Connect failed. %s(%d)", strerror(errno), errno);
		goto fail;
	}

	nc->msg = dbus_message_ref(msg);
	return DBUS_HANDLER_RESULT_HANDLED;
fail:
	err_connection_failed(conn, msg, strerror(errno));
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult connection_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;
	char addr[18];

	if (!nc->up) {
		err_failed(conn, msg, "Device not connected");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	close(nc->sk);
	ba2str(&nc->dst, addr);
	bnep_kill_connection(addr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult is_connected(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &nc->up,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult connection_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *iface, *member;

	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (strcmp(NETWORK_CONNECTION_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "GetAddress") == 0)
		return get_address(conn, msg, data);

	if (strcmp(member, "GetUUID") == 0)
		return get_uuid(conn, msg, data);

	if (strcmp(member, "GetName") == 0)
		return get_name(conn, msg, data);

	if (strcmp(member, "GetDescription") == 0)
		return get_description(conn, msg, data);

	if (strcmp(member, "GetInterface") == 0)
		return get_interface(conn, msg, data);

	if (strcmp(member, "Connect") == 0)
		return connection_connect(conn, msg, data);

	if (strcmp(member, "Disconnect") == 0)
		return connection_disconnect(conn, msg, data);

	if (strcmp(member, "IsConnected") == 0)
		return is_connected(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void connection_free(struct network_conn *nc)
{
	char addr[18];

	if (!nc)
		return;

	if (nc->path)
		g_free(nc->path);

	if (nc->up) {
		ba2str(&nc->dst, addr);
		bnep_kill_connection(addr);
	}

	if (nc->dev)
		g_free(nc->dev);

	g_free(nc);
}

static void connection_unregister(DBusConnection *conn, void *data)
{
	struct network_conn *nc = data;

	info("Unregistered connection path:%s", nc->path);

	connection_free(nc);
}

/* Virtual table to handle connection object path hierarchy */
static const DBusObjectPathVTable connection_table = {
	.message_function = connection_message,
	.unregister_function = connection_unregister,
};

int connection_register(DBusConnection *conn, const char *path,
			const char *addr, uint16_t id)
{
	struct network_conn *nc;
	static int bnep = 0;

	if (!conn)
		return -1;

	nc = g_new0(struct network_conn, 1);

	/* register path */
	if (!dbus_connection_register_object_path(conn, path,
						&connection_table, nc)) {
		error("D-Bus failed to register %s path", path);
		goto fail;
	}

	nc->path = g_strdup(path);
	bacpy(&nc->src, BDADDR_ANY);
	str2ba(addr, &nc->dst);
	nc->id = id;
	/* FIXME: Check for device */
	nc->dev = g_new(char, 16);
	snprintf(nc->dev, 16, "bnep%d", bnep++);
	nc->up = FALSE;
	nc->conn = conn;
	info("Registered connection path:%s", path);
	return 0;
fail:
	connection_free(nc);
	return -1;
}
