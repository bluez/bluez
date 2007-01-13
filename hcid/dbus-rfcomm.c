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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "glib-ectomy.h"
#include "dbus.h"
#include "dbus-common.h"
#include "dbus-hci.h"
#include "dbus-adapter.h"
#include "dbus-error.h"
#include "dbus-sdp.h"
#include "dbus-rfcomm.h"

/* Waiting for udev to create the device node */
#define MAX_OPEN_TRIES	5
#define OPEN_WAIT	300  /* ms */

static int rfcomm_ctl = -1;

struct rfcomm_node {
	int16_t		id;		/* Device id */
	char		name[16];       /* Node filename */

	DBusConnection	*conn;		/* for name listener handling */

	/* The following members are only valid for connected nodes */
	GIOChannel	*io;		/* IO Channel for the connection */
	guint		io_id;		/* ID for IO channel */
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

	/* Used only when we wait for udev to create the device node */
	struct rfcomm_node	*node;
	int			ntries;
};

static GSList *pending_connects = NULL;
static GSList *connected_nodes = NULL;
static GSList *bound_nodes = NULL;

static char *rfcomm_node_name_from_id(int16_t id, char *dev, size_t len)
{
	snprintf(dev, len, "/dev/rfcomm%d", id);
	return dev;
}

static void rfcomm_node_free(struct rfcomm_node *node)
{
	if (node->owner)
		free(node->owner);
	if (node->io) {
		g_io_remove_watch(node->io_id);
		g_io_channel_unref(node->io);
	}
	if (node->conn)
		dbus_connection_unref(node->conn);
	free(node);
}

static struct rfcomm_node *find_node_by_name(GSList *nodes, const char *name)
{
	GSList *l;

	for (l = nodes; l != NULL; l = l->next) {
		struct rfcomm_node *node = l->data;
		if (!strcmp(node->name, name))
			return node;
	}

	return NULL;
}

static struct pending_connect *find_pending_connect_by_channel(const char *bda,
								uint8_t ch)
{
	GSList *l;
	bdaddr_t dba;

	str2ba(bda, &dba);

	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pending = l->data;
		if (!bacmp(&dba, &pending->raddr.rc_bdaddr) &&
			pending->raddr.rc_channel == ch)
			return pending;
	}

	return NULL;
}

static struct pending_connect *find_pending_connect_by_service(const char *bda,
								const char *svc)
{
	GSList *l;
	bdaddr_t dba;

	str2ba(bda, &dba);

	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pending = l->data;
		if (!bacmp(&dba, &pending->raddr.rc_bdaddr) &&
			!strcmp(pending->svc, svc))
			return pending;
	}

	return NULL;
}

static void pending_connect_free(struct pending_connect *c)
{
	if (c->svc)
		free(c->svc);
	if (c->io)
		g_io_channel_unref(c->io);
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

	memset(&req, 0, sizeof(req));
	req.dev_id = node->id;

#if 0
	/*
	 * We are hitting a kernel bug inside RFCOMM code when
	 * RFCOMM_HANGUP_NOW bit is set on request's flags passed to
	 * ioctl(RFCOMMRELEASEDEV)!
	 */
	req.flags = (1 << RFCOMM_HANGUP_NOW);
#endif

	if (ioctl(rfcomm_ctl, RFCOMMRELEASEDEV, &req) < 0) {
		if (err)
			*err = errno;
		error("Can't release device %d: %s (%d)", node->id,
				strerror(errno), errno);
		return -1;
	}

	return 0;
}

static void rfcomm_connect_req_exit(const char *name, void *data)
{
	struct rfcomm_node *node = data;
	debug("Connect requestor %s exited. Releasing %s node",
		name, node->name);
	rfcomm_release(node, NULL);
	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);
}

static gboolean rfcomm_disconnect_cb(GIOChannel *io, GIOCondition cond,
					struct rfcomm_node *node)
{
	debug("RFCOMM node %s was disconnected", node->name);
	name_listener_remove(node->conn, node->owner,
				rfcomm_connect_req_exit, node);
	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);
	return FALSE;
}

static void rfcomm_connect_cb_devnode_opened(int fd, struct pending_connect *c,
						struct rfcomm_node *node)
{
	DBusMessage *reply = NULL;
	char *ptr;

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

	/* Check if the caller is still present */
	if (!dbus_bus_name_has_owner(c->conn, node->owner, NULL)) {
		error("RFCOMM.Connect requestor %s exited", node->owner);
		goto failed;
	}

	node->io = g_io_channel_unix_new(fd);
	g_io_channel_set_close_on_unref(node->io, TRUE);
	node->io_id = g_io_add_watch(node->io, G_IO_ERR | G_IO_HUP,
					(GIOFunc) rfcomm_disconnect_cb, node);

	send_message_and_unref(c->conn, reply);

	connected_nodes = g_slist_append(connected_nodes, node);

	node->conn = dbus_connection_ref(c->conn);
	name_listener_add(node->conn, node->owner,
			  rfcomm_connect_req_exit, node);

	goto done;

failed:
	close(fd);
	rfcomm_release(node, NULL);
	rfcomm_node_free(node);
	if (reply)
		dbus_message_unref(reply);
done:
	pending_connects = g_slist_remove(pending_connects, c);
	pending_connect_free(c);
}

static gboolean rfcomm_connect_cb_continue(void *data)
{
	struct pending_connect *c = data;
	struct rfcomm_node *node = c->node;
	int fd;

	if (c->canceled) {
		error_connect_canceled(c->conn, c->msg);
		goto failed;
	}

	fd = open(node->name, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		if (++c->ntries >= MAX_OPEN_TRIES) {
			int err = errno;
			error("Could not open %s: %s (%d)",
					node->name, strerror(err), err);
			error_connection_attempt_failed(c->conn, c->msg, err);
			goto failed;
		}
		return TRUE;
	}

	rfcomm_connect_cb_devnode_opened(fd, c, node);

	return FALSE;

failed:
	rfcomm_release(node, NULL);
	rfcomm_node_free(node);

	pending_connects = g_slist_remove(pending_connects, c);
	pending_connect_free(c);

	return FALSE;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond,
					struct pending_connect *c)
{
	struct rfcomm_node *node = NULL;
	struct rfcomm_dev_req req;
	int sk, ret, err, fd = -1;
	socklen_t len;

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

	len = sizeof(c->laddr);
	if (getsockname(sk, (struct sockaddr *) &c->laddr, &len) < 0) {
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
	memset(node, 0, sizeof(*node));

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

	fd = open(node->name, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		c->node = node;
		c->ntries = 0;
		g_timeout_add(OPEN_WAIT, rfcomm_connect_cb_continue, c);
		return FALSE;
	}

	rfcomm_connect_cb_devnode_opened(fd, c, node);

	return FALSE;

failed:
	if (node)
		rfcomm_node_free(node);

	pending_connects = g_slist_remove(pending_connects, c);
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

	if (bind(sk, (struct sockaddr *) &c->laddr, sizeof(c->laddr)) < 0) {
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
	g_io_channel_set_close_on_unref(c->io, TRUE);

	if (connect(sk, (struct sockaddr *) &c->raddr, sizeof(c->raddr)) < 0) {
		/* BlueZ returns EAGAIN eventhough it should return EINPROGRESS */
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			if (err)
				*err = errno;
			error("connect() failed: %s (%d)", strerror(errno), errno);
			goto failed;
		}

		debug("Connect in progress");
		g_io_add_watch(c->io, G_IO_OUT, (GIOFunc) rfcomm_connect_cb, c);
		pending_connects = g_slist_append(pending_connects, c);
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

static void rfcomm_bind_req_exit(const char *name, void *data)
{
	struct rfcomm_node *node = data;
	debug("Bind requestor %s exited. Releasing %s node", name, node->name);
	rfcomm_release(node, NULL);
	bound_nodes = g_slist_remove(bound_nodes, node);
	rfcomm_node_free(node);
}

static struct rfcomm_node *rfcomm_bind(bdaddr_t *src, const char *bda,
		uint8_t ch, DBusConnection *conn, const char *owner, int *err)
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

	node->owner = strdup(owner);
	if (!node->owner) {
		if (err)
			*err = ENOMEM;
		rfcomm_node_free(node);
		return NULL;
	}

	node->id = ioctl(rfcomm_ctl, RFCOMMCREATEDEV, &req);
	if (node->id < 0) {
		if (err)
			*err = errno;
		error("RFCOMMCREATEDEV failed: %s (%d)", strerror(errno), errno);
		rfcomm_node_free(node);
		return NULL;
	}

	rfcomm_node_name_from_id(node->id, node->name, sizeof(node->name));
	bound_nodes = g_slist_append(bound_nodes, node);

	node->conn = dbus_connection_ref(conn);
	name_listener_add(node->conn, node->owner, rfcomm_bind_req_exit, node);

	return node;
}

typedef struct {
	DBusConnection *conn;
	DBusMessage *msg;
	char *dst;
	char *svc;
	struct adapter *adapter;
} rfcomm_continue_data_t;

static rfcomm_continue_data_t *rfcomm_continue_data_new(DBusConnection *conn,
							DBusMessage *msg,
							const char *dst,
							const char *svc,
							struct adapter *adapter)
{
	rfcomm_continue_data_t *new;

	new = malloc(sizeof(*new));
	if (!new)
		return NULL;

	new->dst = strdup(dst);
	if (!new->dst) {
		free(new);
		return NULL;
	}

	new->svc = strdup(svc);
	if (!new->svc) {
		free(new->dst);
		free(new);
		return NULL;
	}

	new->conn = dbus_connection_ref(conn);
	new->msg = dbus_message_ref(msg);
	new->adapter = adapter;

	return new;
}

static void rfcomm_continue_data_free(rfcomm_continue_data_t *d)
{
	dbus_connection_unref(d->conn);
	dbus_message_unref(d->msg);
	free(d->svc);
	free(d->dst);
	free(d);
}

static void rfcomm_conn_req_continue(sdp_record_t *rec, void *data, int err)
{
	rfcomm_continue_data_t *cdata = data;
	int ch = -1, conn_err;
	sdp_list_t *protos;
	bdaddr_t bdaddr;

	if (err || !rec) {
		error_record_does_not_exist(cdata->conn, cdata->msg);
		goto failed;
	}

	if (!sdp_get_access_protos(rec, &protos)) {
		ch = sdp_get_proto_port(protos, RFCOMM_UUID);
		sdp_list_foreach(protos, (sdp_list_func_t)sdp_list_free, NULL);
		sdp_list_free(protos, NULL);
	}
	if (ch == -1) {
		error_record_does_not_exist(cdata->conn, cdata->msg);
		goto failed;
	}

	if (find_pending_connect_by_channel(cdata->dst, ch)) {
		error_connect_in_progress(cdata->conn, cdata->msg);
		goto failed;
	}

	hci_devba(cdata->adapter->dev_id, &bdaddr);
	if (rfcomm_connect(cdata->conn, cdata->msg, &bdaddr,
				cdata->dst, cdata->svc, ch, &conn_err) < 0)
		error_failed(cdata->conn, cdata->msg, conn_err);

failed:
	rfcomm_continue_data_free(cdata);
}

static DBusHandlerResult rfcomm_connect_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	rfcomm_continue_data_t *cdata;
	uint32_t handle;
	uuid_t uuid;
	const char *string;
	const char *dst;
	int err;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_STRING, &string,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	cdata = rfcomm_continue_data_new(conn, msg, dst, string, adapter);
	if (!cdata)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (str2uuid(&uuid, string) == 0)
		err = get_record_with_uuid(conn, msg, adapter->dev_id, dst,
					&uuid, rfcomm_conn_req_continue, cdata);
	else if ((handle = strtol(string, NULL, 0)))
		err = get_record_with_handle(conn, msg, adapter->dev_id, dst,
					handle, rfcomm_conn_req_continue, cdata);
	else {
		rfcomm_continue_data_free(cdata);
		return error_invalid_arguments(conn, msg);
	}

	if (!err)
		return DBUS_HANDLER_RESULT_HANDLED;

	rfcomm_continue_data_free(cdata);

	if (err == -ENOMEM)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return error_failed(conn, msg, err);
}

static DBusHandlerResult rfcomm_cancel_connect_req(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct pending_connect *pending;
	DBusMessage *reply;
	const char *string;
	const char *dst;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_STRING, &string,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	pending = find_pending_connect_by_service(dst, string);
	if (!pending)
		return error_connect_not_in_progress(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	pending->canceled = 1;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult rfcomm_connect_by_ch_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	bdaddr_t bdaddr;
	const char *dst;
	uint8_t ch;
	int err;
	struct adapter *adapter = data;

	hci_devba(adapter->dev_id, &bdaddr);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_BYTE, &ch,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (find_pending_connect_by_channel(dst, ch))
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

	pending = find_pending_connect_by_channel(dst, ch);
	if (!pending)
		return error_connect_not_in_progress(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	pending->canceled = 1;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult rfcomm_disconnect_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct rfcomm_node *node;
	DBusMessage *reply;
	const char *name;
	int err;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	node = find_node_by_name(connected_nodes, name);
	if (!node)
		return error_not_connected(conn, msg);

	if (strcmp(node->owner, dbus_message_get_sender(msg)))
		return error_not_authorized(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (rfcomm_release(node, &err) < 0) {
		dbus_message_unref(reply);
		return error_failed(conn, msg, err);
	}

	name_listener_remove(node->conn, node->owner,
			     rfcomm_connect_req_exit, node);
	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);

	return send_message_and_unref(conn, reply);
}

static void rfcomm_bind_req_continue(sdp_record_t *rec, void *data, int err)
{
	rfcomm_continue_data_t *cdata = data;
	struct rfcomm_node *node = NULL;
	DBusMessage *reply = NULL;
	int ch = -1, bind_err;
	sdp_list_t *protos;
	const char *name;
	bdaddr_t bdaddr;

	if (err || !rec) {
		error_record_does_not_exist(cdata->conn, cdata->msg);
		goto failed;
	}

	if (!sdp_get_access_protos(rec, &protos)) {
		ch = sdp_get_proto_port(protos, RFCOMM_UUID);
		sdp_list_foreach(protos, (sdp_list_func_t)sdp_list_free, NULL);
		sdp_list_free(protos, NULL);
	}
	if (ch == -1) {
		error_record_does_not_exist(cdata->conn, cdata->msg);
		goto failed;
	}

	hci_devba(cdata->adapter->dev_id, &bdaddr);

	node = rfcomm_bind(&bdaddr, cdata->dst, ch, cdata->conn,
			dbus_message_get_sender(cdata->msg), &bind_err);
	if (!node) {
		error_failed(cdata->conn, cdata->msg, bind_err);
		goto failed;
	}

	reply = dbus_message_new_method_return(cdata->msg);
	if (!reply) {
		error_failed(cdata->conn, cdata->msg, ENOMEM);
		goto failed;
	}

	name = node->name;
	if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID)) {
		error_failed(cdata->conn, cdata->msg, ENOMEM);
		goto failed;
	}

	send_message_and_unref(cdata->conn, reply);

	rfcomm_continue_data_free(cdata);

	return;

failed:
	if (reply)
		dbus_message_unref(reply);
	if (node) {
		bound_nodes = g_slist_remove(bound_nodes, node);
		rfcomm_release(node, NULL);
		rfcomm_node_free(node);
	}

	rfcomm_continue_data_free(cdata);
}

static DBusHandlerResult rfcomm_bind_req(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct adapter *adapter = data;
	rfcomm_continue_data_t *cdata;
	uint32_t handle;
	uuid_t uuid;
	const char *string;
	const char *dst;
	int err;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_STRING, &string,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	cdata = rfcomm_continue_data_new(conn, msg, dst, string, adapter);
	if (!cdata)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (str2uuid(&uuid, string) == 0)
		err = get_record_with_uuid(conn, msg, adapter->dev_id, dst,
					&uuid, rfcomm_bind_req_continue, cdata);
	else if ((handle = strtol(string, NULL, 0)))
		err = get_record_with_handle(conn, msg, adapter->dev_id, dst,
					handle, rfcomm_bind_req_continue, cdata);
	else {
		rfcomm_continue_data_free(cdata);
		return error_invalid_arguments(conn, msg);
	}

	if (!err)
		return DBUS_HANDLER_RESULT_HANDLED;

	rfcomm_continue_data_free(cdata);

	if (err == -ENOMEM)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return error_failed(conn, msg, err);
}

static DBusHandlerResult rfcomm_bind_by_ch_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	bdaddr_t bdaddr;
	DBusMessage *reply = NULL;
	uint8_t ch;
	int err;
	const char *dst, *name;
	struct adapter *adapter = data;
	struct rfcomm_node *node = NULL;

	hci_devba(adapter->dev_id, &bdaddr);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_BYTE, &ch,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	node = rfcomm_bind(&bdaddr, dst, ch, conn,
			dbus_message_get_sender(msg), &err);
	if (!node)
		return error_failed(conn, msg, err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto need_memory;

	name = node->name;
	if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID))
		goto need_memory;

	return send_message_and_unref(conn, reply);

need_memory:
	if (reply)
		dbus_message_unref(reply);
	if (node) {
		bound_nodes = g_slist_remove(bound_nodes, node);
		rfcomm_release(node, NULL);
		rfcomm_node_free(node);
	}
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

	if (strcmp(node->owner, dbus_message_get_sender(msg)))
		return error_not_authorized(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (rfcomm_release(node, &err) < 0) {
		dbus_message_unref(reply);
		return error_failed(conn, msg, err);
	}

	name_listener_remove(node->conn, node->owner,
				rfcomm_bind_req_exit, node);
	bound_nodes = g_slist_remove(bound_nodes, node);
	rfcomm_node_free(node);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult rfcomm_list_bindings_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	bdaddr_t bdaddr;
	DBusMessage *reply;
	DBusMessageIter iter, sub;
	struct adapter *adapter = data;
	GSList *l;

	hci_devba(adapter->dev_id, &bdaddr);

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

	return send_message_and_unref(conn, reply);
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
	const struct adapter *adapter = data;
	service_handler_func_t handler;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	if (!data) {
		error("RFCOMM method called with NULL data pointer!");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!adapter->up)
		return error_not_ready(conn, msg);

	/* Initialize the RFCOMM control socket if has not yet been done */
	if (rfcomm_ctl < 0) {
		rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
		if (rfcomm_ctl < 0)
			return error_failed(conn, msg, errno);
	}

	handler = find_service_handler(rfcomm_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return error_unknown_method(conn, msg);
}
