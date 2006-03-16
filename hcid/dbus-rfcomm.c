/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "list.h"
#include "glib-ectomy.h"
#include "dbus.h"

/* Waiting for udev to create the device node */
#define MAX_OPEN_TRIES 6
#define OPEN_WAIT (1000 * 300)

static int rfcomm_ctl = -1;

struct rfcomm_node {
	int16_t		id;		/* Device id */
	char		name[16];       /* Node filename */

	/* The following members are only valid for connected nodes */
	GIOChannel	*io;		/* IO Channel for the connection */
	char		*owner;		/* D-Bus name that created the node */
};

struct pending_connect {
	DBusConnection		*conn;
	DBusMessage		*msg;
	GIOChannel		*io;
	char 			*svc;
	int			canceled;
	struct sockaddr_rc	laddr;
	struct sockaddr_rc	raddr;
};

static struct slist *pending_connects = NULL;
static struct slist *connected_nodes = NULL;
static struct slist *bound_nodes = NULL;

static char *rfcomm_node_name_from_id(int16_t id, char *dev, size_t len)
{
    snprintf(dev, len, "/dev/rfcomm%d", id);
    return dev;
}

static struct rfcomm_node *find_node_by_name(struct slist *nodes, const char *name)
{
	struct slist *l;

	for (l = nodes; l != NULL; l = l->next) {
		struct rfcomm_node *node = l->data;
		if (!strcmp(node->name, name))
			return node;
	}

	return NULL;
}

static struct pending_connect *find_pending_connect(const char *bda, uint8_t ch)
{
	struct slist *l;
	bdaddr_t dba;

	str2ba(bda, &dba);

	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pending = l->data;
		if (!bacmp(&dba, &pending->raddr.rc_bdaddr)
				&& pending->raddr.rc_channel == ch)
			return pending;
	}

	return NULL;
}

static void pending_connect_free(struct pending_connect *c)
{
	if (c->svc)
		free(c->svc);
	if (c->io)
		g_io_channel_close(c->io);
	if (c->msg)
		dbus_message_unref(c->msg);
	if (c->conn)
		dbus_connection_unref(c->conn);
	free(c);
}

static int set_nonblocking(int fd, int *err)
{
	long arg;

	arg = fcntl(fd, F_GETFL);
	if (arg < 0) {
		if (err)
			*err = errno;
		error("fcntl(F_GETFL): %s (%d)", strerror(errno), errno);
		return -1;
	}

	/* Return if already nonblocking */
	if (arg & O_NONBLOCK)
		return 0;

	arg |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, arg) < 0) {
		if (err)
			*err = errno;
		error("fcntl(F_SETFL, O_NONBLOCK): %s (%d)",
				strerror(errno), errno);
		return -1;
	}

	return 0;
}

static int rfcomm_release(struct rfcomm_node *node, int *err)
{
	struct rfcomm_dev_req req;

	debug("rfcomm_release(%s)", node->name);

	if (node->io) {
		g_io_channel_close(node->io);
		node->io = NULL;
	}

	memset(&req, 0, sizeof(req));
	req.dev_id = node->id;

	if (ioctl(rfcomm_ctl, RFCOMMRELEASEDEV, &req) < 0) {
		if (err)
			*err = errno;
		error("Can't release device %d: %s (%d)", node->id,
				strerror(errno), errno);
		return -1;
	}

	bound_nodes = slist_remove(bound_nodes, node);

	if (node->owner)
		free(node->owner);

	free(node);

	return 0;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond,
					struct pending_connect *c)
{
	int sk, ret, err, fd = -1, i;
	size_t alen;
	socklen_t len;
	char *ptr;
	struct rfcomm_dev_req req;
	struct rfcomm_node *node = NULL;
	DBusMessage *reply = NULL;

	if (c->canceled) {
		error_connect_canceled(c->conn, c->msg);
		goto failed;
	}

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		error_failed(c->conn, c->msg, err);
		goto failed;
	}

	if (ret != 0) {
		error("connect(): %s (%d)", strerror(ret), ret);
		error_connection_attempt_failed(c->conn, c->msg, ret);
		goto failed;
	}

	debug("rfcomm_connect_cb: connected");

	alen = sizeof(c->laddr);
	if (getsockname(sk, (struct sockaddr *)&c->laddr, &alen) < 0) {
		err = errno;
		error_failed(c->conn, c->msg, err);
		error("getsockname: %s (%d)", strerror(err), err);
		goto failed;
	}

	node = malloc(sizeof(struct rfcomm_node));
	if (!node) {
		error_failed(c->conn, c->msg, ENOMEM);
		goto failed;
	}

	/* Create the rfcomm device node */
	memset(&req, 0, sizeof(req));

	req.dev_id = -1;
	req.flags = (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP);

	bacpy(&req.src, &c->laddr.rc_bdaddr);
	bacpy(&req.dst, &c->raddr.rc_bdaddr);
	req.channel = c->raddr.rc_channel;

	node->id = ioctl(sk, RFCOMMCREATEDEV, &req);
	if (node->id < 0) {
		err = errno;
		error("ioctl(RFCOMMCREATEDEV): %s (%d)", strerror(errno), err);
		error_failed(c->conn, c->msg, err);
		goto failed;
	}

	rfcomm_node_name_from_id(node->id, node->name, sizeof(node->name));

	/* FIXME: instead of looping here we should create a timer and
	 * return to the mainloop */
	for (i = 0; i < MAX_OPEN_TRIES; i++) {
		fd = open(node->name, O_RDONLY | O_NOCTTY);
		if (fd >= 0)
			break;
		usleep(OPEN_WAIT);
	}

	if (fd < 0) {
		err = errno;
		error("Could not open %s: %s (%d)", node->name,
				strerror(err), err);
		/* This will also try to remove the node from bound_nodes, but
		 * that's ok since the slist_remove just silently fails */
		rfcomm_release(node, NULL);
		error_connection_attempt_failed(c->conn, c->msg, err);
		goto failed;
	}

	reply = dbus_message_new_method_return(c->msg);
	if (!reply) {
		error_failed(c->conn, c->msg, ENOMEM);
		goto failed;
	}

	ptr = node->name;
	if (!dbus_message_append_args(reply,
				DBUS_TYPE_STRING, &ptr,
				DBUS_TYPE_INVALID)) {
		error_failed(c->conn, c->msg, ENOMEM);
		goto failed;
	}

	node->owner = strdup(dbus_message_get_sender(c->msg));
	if (!node->owner) {
		error_failed(c->conn, c->msg, ENOMEM);
		goto failed;
	}

	send_reply_and_unref(c->conn, reply);

        node->io = g_io_channel_unix_new(fd);

	connected_nodes = slist_append(connected_nodes, node);

	goto done;

failed:
	if (fd >= 0)
		close(fd);
	if (node)
		rfcomm_release(node, NULL);
	if (reply)
		dbus_message_unref(reply);
done:
	pending_connects = slist_remove(pending_connects, c);
	pending_connect_free(c);

	return FALSE;
}

static int rfcomm_connect(DBusConnection *conn, DBusMessage *msg, bdaddr_t *src,
			const char *bda, const char *svc, uint8_t ch, int *err)
{
	int sk = -1;
	struct pending_connect *c = NULL;

	c = malloc(sizeof(struct pending_connect));
	if (!c) {
		if (err)
			*err = ENOMEM;
		goto failed;
	}

	memset(c, 0, sizeof(struct pending_connect));

	if (svc) {
		c->svc = strdup(svc);
		if (!c->svc) {
			if (err)
				*err = ENOMEM;
			goto failed;
		}
	}

	c->laddr.rc_family = AF_BLUETOOTH;
	bacpy(&c->laddr.rc_bdaddr, src);
	c->laddr.rc_channel = 0;

	c->raddr.rc_family = AF_BLUETOOTH;
	str2ba(bda, &c->raddr.rc_bdaddr);
	c->raddr.rc_channel = ch;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		if (err)
			*err = errno;
		goto failed;
	}

	if (bind(sk, (struct sockaddr *)&c->laddr, sizeof(c->laddr)) < 0) {
		if (err)
			*err = errno;
		goto failed;
	}

	if (set_nonblocking(sk, err) < 0)
		goto failed;

	/* So we can reply to the message later */
	c->msg = dbus_message_ref(msg);
	c->conn = dbus_connection_ref(conn);

	c->io = g_io_channel_unix_new(sk);

	if (connect(sk, (struct sockaddr *)&c->raddr, sizeof(c->raddr)) < 0) {
		/* BlueZ returns EAGAIN eventhough it should return EINPROGRESS */
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			if (err)
				*err = errno;
			error("connect() failed: %s (%d)", strerror(errno), errno);
			goto failed;
		}

		debug("Connect in progress");
		g_io_add_watch(c->io, G_IO_OUT, (GIOFunc)rfcomm_connect_cb, c);
		pending_connects = slist_append(pending_connects, c);
	} else {
		debug("Connect succeeded with first try");
		(void) rfcomm_connect_cb(c->io, G_IO_OUT, c);
	}

	return 0;

failed:
	if (c)
		pending_connect_free(c);
	if (sk >= 0)
		close(sk);
	return -1;
}

static struct rfcomm_node *rfcomm_bind(bdaddr_t *src, const char *bda, uint8_t ch, int *err)
{
	struct rfcomm_dev_req req;
	struct rfcomm_node *node;

	debug("rfcomm_bind(%s, %d)", bda, ch);

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = 0;
	bacpy(&req.src, src);

	str2ba(bda, &req.dst);
	req.channel = ch;

	node = malloc(sizeof(struct rfcomm_node));
	if (!node) {
		if (err)
			*err = ENOMEM;
		return NULL;
	}

	memset(node, 0, sizeof(struct rfcomm_node));

	node->id = ioctl(rfcomm_ctl, RFCOMMCREATEDEV, &req);
	if (node->id < 0) {
		if (err)
			*err = errno;
		error("RFCOMMCREATEDEV failed: %s (%d)", strerror(errno), errno);
		free(node);
		return NULL;
	}

	rfcomm_node_name_from_id(node->id, node->name, sizeof(node->name));
	bound_nodes = slist_append(bound_nodes, node);

	return node;
}

static DBusHandlerResult rfcomm_connect_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	error("RFCOMM.Connect not implemented");
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_cancel_connect_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	error("RFCOMM.CancelConnect not implemented");
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_connect_by_ch_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	bdaddr_t bdaddr;
	const char *dst;
	uint8_t ch;
	int err;
	struct hci_dbus_data *dbus_data = data;

	hci_devba(dbus_data->dev_id, &bdaddr);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_BYTE, &ch,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (find_pending_connect(dst, ch))
		return error_connect_in_progress(conn, msg);

	if (rfcomm_connect(conn, msg, &bdaddr, dst, NULL, ch, &err) < 0)
		return error_failed(conn, msg, err);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult rfcomm_cancel_connect_by_ch_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *dst;
	uint8_t ch;
	DBusMessage *reply;
	struct pending_connect *pending;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_BYTE, &ch,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	pending = find_pending_connect(dst, ch);
	if (!pending)
		return error_connect_not_in_progress(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	pending->canceled = 1;

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult rfcomm_disconnect_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *name;
	struct rfcomm_node *node;
	int err;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	node = find_node_by_name(connected_nodes, name);
	if (!node)
		return error_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (rfcomm_release(node, &err) < 0) {
		dbus_message_unref(reply);
		return error_failed(conn, msg, err);
	}

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult rfcomm_bind_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	error("RFCOMM.Bind not implemented");
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_bind_by_ch_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	bdaddr_t bdaddr;
	DBusMessage *reply = NULL;
	uint8_t ch;
	int err;
	const char *dst, *name;
	struct hci_dbus_data *dbus_data = data;
	struct rfcomm_node *node = NULL;

	hci_devba(dbus_data->dev_id, &bdaddr);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_BYTE, &ch,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);


	node = rfcomm_bind(&bdaddr, dst, ch, &err);
	if (!node)
		return error_failed(conn, msg, err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto need_memory;

	name = node->name;
	if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID))
		goto need_memory;

	return send_reply_and_unref(conn, reply);

need_memory:
	if (reply)
		dbus_message_unref(reply);
	if (node)
		rfcomm_release(node, NULL);
	return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult rfcomm_release_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *name;
	struct rfcomm_node *node;
	int err;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	node = find_node_by_name(bound_nodes, name);
	if (!node)
		return error_binding_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (rfcomm_release(node, &err) < 0) {
		dbus_message_unref(reply);
		return error_failed(conn, msg, err);
	}

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult rfcomm_list_bindings_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	bdaddr_t bdaddr;
	DBusMessage *reply;
	DBusMessageIter iter, sub;
	struct hci_dbus_data *dbus_data = data;
	struct slist *l;

	hci_devba(dbus_data->dev_id, &bdaddr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	for (l = bound_nodes; l != NULL; l = l->next) {
		struct rfcomm_node *node = l->data;
		struct rfcomm_dev_info di = { id: node->id };
		char *name = node->name;

		if (ioctl(rfcomm_ctl, RFCOMMGETDEVINFO, &di) < 0) {
			error("RFCOMMGETDEVINFO(%d): %s (%d)",
					node->id, strerror(errno), errno);
			continue;
		}

		/* Ignore nodes not specific to this adapter */
		if (bacmp(&di.src, &bdaddr))
			continue;

		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &name);
	}

	if (!dbus_message_iter_close_container(&iter, &sub)) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	return send_reply_and_unref(conn, reply);
}

static struct service_data rfcomm_services[] = {
	{ "Connect",			rfcomm_connect_req,			},
	{ "CancelConnect",		rfcomm_cancel_connect_req,		},
	{ "ConnectByChannel",		rfcomm_connect_by_ch_req,		},
	{ "CancelConnectByChannel",	rfcomm_cancel_connect_by_ch_req,	},
	{ "Disconnect",			rfcomm_disconnect_req,			},
	{ "Bind",			rfcomm_bind_req,			},
	{ "BindByChannel",		rfcomm_bind_by_ch_req,			},
	{ "Release",			rfcomm_release_req,			},
	{ "ListBindings",		rfcomm_list_bindings_req,		},
	{ NULL,				NULL,					}
};

DBusHandlerResult handle_rfcomm_method(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	service_handler_func_t handler;

	if (!data) {
		error("RFCOMM method called with NULL data pointer!");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Initialize the RFCOMM control socket if has not yet been done */
	if (rfcomm_ctl < 0) {
		rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
		if (rfcomm_ctl < 0)
			return error_failed(conn, msg, errno);
	}

	handler = find_service_handler(rfcomm_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
