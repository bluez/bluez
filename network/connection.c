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
#include <netinet/in.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/bnep.h>
#include <bluetooth/sdp.h>

#include <glib.h>

#include "logging.h"
#include "dbus-helper.h"
#include "textfile.h"
#include "glib-helper.h"

#include "error.h"
#include "common.h"
#include "connection.h"

#define NETWORK_CONNECTION_INTERFACE "org.bluez.network.Connection"

typedef enum {
	CONNECTED,
	CONNECTING,
	DISCONNECTED
} conn_state;

struct network_conn {
	DBusMessage	*msg;
	bdaddr_t	store;
	bdaddr_t	src;
	bdaddr_t	dst;
	char		*path;		/* D-Bus path */
	char		dev[16];	/* Interface name */
	char		*name;		/* Service Name */
	char		*desc;		/* Service Description*/
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

static gboolean bnep_watchdog_cb(GIOChannel *chan, GIOCondition cond,
				gpointer data)
{
	struct network_conn *nc = data;

	if (connection != NULL) {
		dbus_connection_emit_signal(connection, nc->path,
						NETWORK_CONNECTION_INTERFACE,
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
	dbus_connection_emit_signal(connection, nc->path,
					NETWORK_CONNECTION_INTERFACE,
					"Connected",
					DBUS_TYPE_INVALID);

	reply = dbus_message_new_method_return(nc->msg);

	pdev = nc->dev;
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &pdev,
					DBUS_TYPE_INVALID);
	send_message_and_unref(connection, reply);

	nc->state = CONNECTED;

	info("%s connected", nc->dev);
	/* Start watchdog */
	g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) bnep_watchdog_cb, nc);
	return FALSE;
failed:
	if (nc->state != DISCONNECTED) {
		nc->state = DISCONNECTED;
		error_connection_attempt_failed(connection, nc->msg, EIO);
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

static void connect_cb(GIOChannel *chan, int err, gpointer data)
{
	struct network_conn *nc = data;

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
	error_connection_attempt_failed(connection, nc->msg, -err);
}

static DBusHandlerResult get_adapter(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;
	char addr[18];
	const char *paddr = addr;

	ba2str(&nc->src, addr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &paddr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_address(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;
	char addr[18];
	const char *paddr = addr;

	ba2str(&nc->dst, addr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &paddr,
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
	struct network_conn *nc = data;
	DBusMessage *reply;

	if (!nc->name) {
		error_failed(conn, msg, "Cannot find service name");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &nc->name,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);

}

static DBusHandlerResult get_description(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;

	if (!nc->desc) {
		error_failed(conn, msg, "Cannot find service description");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &nc->desc,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_interface(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_conn *nc = data;
	const char *pdev = nc->dev;
	DBusMessage *reply;

	if (nc->state != CONNECTED) {
		error_failed(conn, msg, "Device not connected");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &pdev,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

/* Connect and initiate BNEP session */
static DBusHandlerResult connection_connect(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	DBusError derr;
	int err;

	if (nc->state != DISCONNECTED) {
		error_failed(conn, msg, "Device already connected");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_INVALID)) {
		error_invalid_arguments(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	nc->state = CONNECTING;
	nc->msg = dbus_message_ref(msg);

	err = bt_l2cap_connect(&nc->src, &nc->dst, BNEP_PSM, BNEP_MTU,
				connect_cb, nc);
	if (err < 0) {
		error("Connect failed. %s(%d)", strerror(errno), errno);
		goto fail;
	}

	return DBUS_HANDLER_RESULT_HANDLED;
fail:
	if (nc->msg) {
		dbus_message_unref(nc->msg);
		nc->msg = NULL;
	}
	nc->state = DISCONNECTED;
	error_connection_attempt_failed(conn, msg, errno);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult connection_cancel(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;

	if (nc->state != CONNECTING) {
		error_failed(conn, msg, "Device has no pending connect");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	close(nc->sk);
	nc->state = DISCONNECTED;

	reply = dbus_message_new_method_return(msg);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult connection_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;

	if (nc->state != CONNECTED) {
		error_failed(conn, msg, "Device not connected");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	bnep_if_down(nc->dev);
	bnep_kill_connection(&nc->dst);

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
	gboolean up;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	up = (nc->state == CONNECTED);
	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &up,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_info(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_conn *nc = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	const char *uuid;
	char raddr[18];
	const char *paddr = raddr;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dbus_message_iter_append_dict_entry(&dict, "name",
			DBUS_TYPE_STRING, &nc->name);

	uuid = bnep_uuid(nc->id);
	dbus_message_iter_append_dict_entry(&dict, "uuid",
			DBUS_TYPE_STRING, &uuid);

	ba2str(&nc->dst, raddr);
	dbus_message_iter_append_dict_entry(&dict, "address",
			DBUS_TYPE_STRING, &paddr);

	dbus_message_iter_close_container(&iter, &dict);

	return send_message_and_unref(conn, reply);
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

	if (nc->name)
		g_free(nc->name);

	if (nc->desc)
		g_free(nc->desc);
	
	g_free(nc);
	nc = NULL;
}

static void connection_unregister(DBusConnection *conn, void *data)
{
	struct network_conn *nc = data;

	info("Unregistered connection path:%s", nc->path);

	connection_free(nc);
}

static DBusMethodVTable connection_methods[] = {
	{ "GetAdapter",		get_adapter,		"",	"s"	},
	{ "GetAddress",		get_address,		"",	"s"	},
	{ "GetUUID",		get_uuid,		"",	"s"	},
	{ "GetName",		get_name,		"",	"s"	},
	{ "GetDescription",	get_description,	"",	"s"	},
	{ "GetInterface",	get_interface,		"",	"s"	},
	{ "Connect",		connection_connect,	"",	"s"	},
	{ "CancelConnect",	connection_cancel,	"",	""	},
	{ "Disconnect",		connection_disconnect,	"",	""	},
	{ "IsConnected",	is_connected,		"",	"b"	},
	{ "GetInfo",		get_info,		"",	"a{sv}" },
	{ NULL, NULL, NULL, NULL }
};

static DBusSignalVTable connection_signals[] = {
	{ "Connected",		""	},
	{ "Disconnected",	""	},
	{ NULL, NULL }
};

int connection_register(const char *path, bdaddr_t *src, bdaddr_t *dst,
			uint16_t id, const char *name, const char *desc)
{
	struct network_conn *nc;
	bdaddr_t default_src;
	int dev_id;

	if (!path)
		return -EINVAL;

	bacpy(&default_src, BDADDR_ANY);
	dev_id = hci_get_route(&default_src);
	if (dev_id < 0 || hci_devba(dev_id, &default_src) < 0)
		return -1;

	nc = g_new0(struct network_conn, 1);

	/* register path */
	if (!dbus_connection_create_object_path(connection, path, nc,
						connection_unregister)) {
		connection_free(nc);
		return -1;
	}

	if (!dbus_connection_register_interface(connection, path,
						NETWORK_CONNECTION_INTERFACE,
						connection_methods,
						connection_signals, NULL)) {
		error("D-Bus failed to register %s interface",
				NETWORK_CONNECTION_INTERFACE);
		dbus_connection_destroy_object_path(connection, path);
		return -1;
	}

	nc->path = g_strdup(path);
	bacpy(&nc->store, src);
	bacpy(&nc->src, &default_src);
	bacpy(&nc->dst, dst);
	nc->id = id;
	nc->name = g_strdup(name);
	nc->desc = g_strdup(desc);
	memset(nc->dev, 0, 16);
	strncpy(nc->dev, prefix, strlen(prefix));
	nc->state = DISCONNECTED;

	info("Registered connection path:%s", path);

	return 0;
}

int connection_store(const char *path, gboolean default_path)
{
	struct network_conn *nc;
	const char *role;
	char key[32], *value;
	char filename[PATH_MAX + 1];
	char src_addr[18], dst_addr[18];
	int len, err;

	if (!dbus_connection_get_object_user_data(connection,
				path, (void *) &nc))
		return -ENOENT;

	if (!nc->name || !nc->desc)
		return -EINVAL;

	/* FIXME: name and desc validation - remove ':' */

	ba2str(&nc->dst, dst_addr);
	role = bnep_name(nc->id);
	snprintf(key, 32, "%s#%s", dst_addr, role);

	ba2str(&nc->store, src_addr);
	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "network");
	create_file(filename, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	if (default_path)
		err = textfile_put(filename, "default", key);
	else {
		len = strlen(nc->name) + strlen(nc->desc)  + 2;
		value = g_malloc0(len);
		snprintf(value, len, "%s:%s", nc->name, nc->desc);
		err = textfile_put(filename, key, value);
		g_free(value);
	}

	return err;
}

int connection_find_data(const char *path, const char *pattern)
{
	struct network_conn *nc;
	char addr[18], key[32];
	const char *role;

	if (!dbus_connection_get_object_user_data(connection,
		path, (void *) &nc))
		return -1;

	if (strcasecmp(pattern, nc->dev) == 0)
		return 0;

	if (strcasecmp(pattern, nc->name) == 0)
		return 0;

	ba2str(&nc->dst, addr);

	if (strcasecmp(pattern, addr) == 0)
		return 0;

	role = bnep_name(nc->id);
	snprintf(key, 32, "%s#%s", addr, role);

	if (strcasecmp(pattern, key) == 0)
		return 0;

	return -1;
}

gboolean connection_has_pending(const char *path)
{
	struct network_conn *nc;

	if (!dbus_connection_get_object_user_data(connection,
				path, (void *) &nc))
		return FALSE;

	return (nc->state == CONNECTING);
}

int connection_remove_stored(const char *path)
{
	struct network_conn *nc;
	const char *role;
	char key[32];
	char filename[PATH_MAX + 1];
	char src_addr[18], dst_addr[18];
	int err;

	if (!dbus_connection_get_object_user_data(connection,
				path, (void *) &nc))
		return -ENOENT;

	ba2str(&nc->dst, dst_addr);
	role = bnep_name(nc->id);
	snprintf(key, 32, "%s#%s", dst_addr, role);

	ba2str(&nc->store, src_addr);
	create_name(filename, PATH_MAX, STORAGEDIR, src_addr, "network");

	err = textfile_del(filename, key);

	return err;
}

gboolean connection_is_connected(const char *path)
{
	struct network_conn *nc;

	if (!dbus_connection_get_object_user_data(connection,
				path, (void *) &nc))
		return FALSE;

	return (nc->state == CONNECTED);
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
