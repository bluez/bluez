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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>

#include "dbus.h"
#include "logging.h"

#include "manager.h"

#define SERIAL_MANAGER_PATH		"/org/bluez/serial"
#define SERIAL_MANAGER_INTERFACE	"org.bluez.serial.Manager"
#define SERIAL_ERROR_INTERFACE		"org.bluez.serial.Error"

#define PATH_LENGTH		32
#define BASE_UUID			"00000000-0000-1000-8000-00805F9B34FB"

/* Waiting for udev to create the device node */
#define MAX_OPEN_TRIES  5
#define OPEN_WAIT       300  /* ms */

struct rfcomm_node {
	int16_t         id;	/* RFCOMM device id */
	char		*name;	/* RFCOMM device name */
	DBusConnection  *conn;	/* for name listener handling */
	char		*owner; /* Bus name */
	GIOChannel	*io;	/* Connected node IO Channel */
	guint		io_id;	/* IO Channel ID  */
};

struct pending_connection {
	DBusConnection	*conn;
	DBusMessage	*msg;
	char		*addr;		/* Destination address */
	char		*adapter_path;	/* Adapter D-Bus path */
	bdaddr_t	src;
	uint8_t		channel;
	int		id;		/* RFCOMM device id */
	int		ntries;		/* Open attempts */
};

/* FIXME: Common file required */
static struct {
	const char	*name;
	uint16_t	class;
} serial_services[] = {
	{ "vcp",	VIDEO_CONF_SVCLASS_ID		},
	{ "pbap",	PBAP_SVCLASS_ID			},
	{ "sap",	SAP_SVCLASS_ID			},
	{ "ftp",	OBEX_FILETRANS_SVCLASS_ID	},
	{ "bpp",	BASIC_PRINTING_SVCLASS_ID	},
	{ "bip",	IMAGING_SVCLASS_ID		},
	{ "synch",	IRMC_SYNC_SVCLASS_ID		},
	{ "dun",	DIALUP_NET_SVCLASS_ID		},
	{ "opp",	OBEX_OBJPUSH_SVCLASS_ID		},
	{ "fax",	FAX_SVCLASS_ID			},
	{ "spp",	SERIAL_PORT_SVCLASS_ID		},
	{ NULL }
};

static DBusConnection *connection = NULL;
static GSList *connected_nodes = NULL;
static int rfcomm_ctl = -1;

static void pending_connection_free(struct pending_connection *pc)
{
	if (pc->conn)
		dbus_connection_unref(pc->conn);
	if (pc->msg)
		dbus_message_unref(pc->msg);
	if (pc->addr)
		g_free(pc->addr);
	if (pc->adapter_path)
		g_free(pc->adapter_path);
	g_free(pc);
}

static void rfcomm_node_free(struct rfcomm_node *node)
{
	if (node->name)
		g_free(node->name);
	if (node->conn)
		dbus_connection_unref(node->conn);
	if (node->owner)
		g_free(node->owner);
	if (node->io) {
		g_source_remove(node->io_id);
		g_io_channel_unref(node->io);
	}
	g_free(node);
}

static int node_cmp_by_name(struct rfcomm_node *node, const char *name)
{
	return strcmp(node->name, name);
}

static uint16_t str2class(const char *pattern)
{
	int i;

	for (i = 0; serial_services[i].name; i++) {
		if (strcasecmp(serial_services[i].name, pattern) == 0)
			return serial_services[i].class;
	}

	return 0;
}

static DBusHandlerResult err_connection_failed(DBusConnection *conn,
					DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
			SERIAL_ERROR_INTERFACE".ConnectionAttemptFailed", str));
}

static DBusHandlerResult err_does_not_exist(DBusConnection *conn,
					DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				SERIAL_ERROR_INTERFACE ".DoesNotExist", str));
}

static DBusHandlerResult err_failed(DBusConnection *conn,
				DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				SERIAL_ERROR_INTERFACE ".Failed", str));
}

static DBusHandlerResult err_invalid_args(DBusConnection *conn,
					DBusMessage *msg, const char *str)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
				SERIAL_ERROR_INTERFACE ".InvalidArguments", str));
}

static DBusHandlerResult err_not_authorized(DBusConnection *conn,
							DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
			SERIAL_ERROR_INTERFACE ".NotAuthorized",
			"Owner not allowed"));
}

static DBusHandlerResult err_not_supported(DBusConnection *conn,
							DBusMessage *msg)
{
	return send_message_and_unref(conn,
			dbus_message_new_error(msg,
			SERIAL_ERROR_INTERFACE ".NotSupported",
			"The service is not supported by the remote device"));
}

static int rfcomm_release(int16_t id)
{
	struct rfcomm_dev_req req;

	memset(&req, 0, sizeof(req));
	req.dev_id = id;

#if 0
	/*
	 * We are hitting a kernel bug inside RFCOMM code when
	 * RFCOMM_HANGUP_NOW bit is set on request's flags passed to
	 * ioctl(RFCOMMRELEASEDEV)!
	 */
	req.flags = (1 << RFCOMM_HANGUP_NOW);
#endif

	if (ioctl(rfcomm_ctl, RFCOMMRELEASEDEV, &req) < 0) {
		int err = errno;
		error("Can't release device %d: %s (%d)",
				id, strerror(err), err);
		return -err;
	}

	return 0;
}

static void send_signal(DBusConnection *conn,
		const char *sname, const char *node_name)
{
	DBusMessage *signal;

	signal = dbus_message_new_signal(SERIAL_MANAGER_PATH,
				SERIAL_MANAGER_INTERFACE, sname);
	dbus_message_append_args(signal,
			DBUS_TYPE_STRING, &node_name,
			DBUS_TYPE_INVALID);
	send_message_and_unref(conn, signal);
}

static void connect_service_exited(const char *name, struct rfcomm_node *node)
{
	debug("Connect requestor %s exited. Releasing %s node",
						name, node->name);

	rfcomm_release(node->id);

	send_signal(node->conn, "ServiceDisconnected", node->name);

	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);
} 

static gboolean rfcomm_disconnect_cb(GIOChannel *io,
		GIOCondition cond, struct rfcomm_node *node) 
{
	debug("RFCOMM node %s was disconnected", node->name);

	name_listener_remove(node->conn, node->owner,
			(name_cb_t) connect_service_exited, node);

	send_signal(node->conn, "ServiceDisconnected", node->name);

	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);

	return FALSE;
}

static int add_rfcomm_node(GIOChannel *io, int id, const char *name,
				DBusConnection *conn, const char *owner)
{
	struct rfcomm_node *node;

	node = g_new0(struct rfcomm_node, 1);
	node->id	= id;
	node->name	= g_strdup(name);
	node->conn	= dbus_connection_ref(conn);
	node->owner	= g_strdup(owner);
	node->io	= io;

	g_io_channel_set_close_on_unref(io, TRUE);
	node->io_id = g_io_add_watch(io, G_IO_ERR | G_IO_HUP,
			(GIOFunc) rfcomm_disconnect_cb, node);

	connected_nodes = g_slist_append(connected_nodes, node);

	return name_listener_add(node->conn, owner,
			(name_cb_t) connect_service_exited, node);
}

static gboolean rfcomm_connect_cb_continue(struct pending_connection *pc)
{
	const char *owner = dbus_message_get_sender(pc->msg);
	DBusMessage *reply;
	char node_name[16];
	const char *pname = node_name;
	int fd;

	/* FIXME: Check if it was canceled */

	/* Check if the caller is still present */
	if (!dbus_bus_name_has_owner(pc->conn, owner, NULL)) {
		error("Connect requestor %s exited", owner);
		rfcomm_release(pc->id);
		pending_connection_free(pc);
		return FALSE;
	}

	snprintf(node_name, sizeof(node_name), "/dev/rfcomm%d", pc->id);
	fd = open(node_name, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		int err = errno;
		error("Could not open %s: %s (%d)",
				node_name, strerror(err), err);
		if (++pc->ntries >= MAX_OPEN_TRIES) {
			rfcomm_release(pc->id);
			err_connection_failed(pc->conn, pc->msg, strerror(err));
			pending_connection_free(pc);
			return FALSE;
		}
		return TRUE;
	}

	add_rfcomm_node(g_io_channel_unix_new(fd),
			pc->id, node_name, pc->conn, owner);

	/* Reply to the requestor */
	reply = dbus_message_new_method_return(pc->msg);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pname,
			DBUS_TYPE_INVALID);
	send_message_and_unref(pc->conn, reply);

	/* Send the D-Bus signal */
	send_signal(pc->conn, "ServiceConnected", node_name);

	pending_connection_free(pc);

	return FALSE;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan,
		GIOCondition cond, struct pending_connection *pc)
{
	DBusMessage *reply;
	char node_name[16];
	const char *pname = node_name;
	struct rfcomm_dev_req req;
	int sk, ret, err, fd;
	socklen_t len;

	/* FIXME: Check if it was canceled */

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		err_connection_failed(pc->conn, pc->msg, strerror(err));
		goto fail;
	}

	if (ret != 0) {
		error("connect(): %s (%d)", strerror(ret), ret);
		err_connection_failed(pc->conn, pc->msg, strerror(ret));
		goto fail;
	}

	debug("rfcomm_connect_cb: connected");

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP);
	bacpy(&req.src, &pc->src);
	str2ba(pc->addr, &req.dst);
	req.channel = pc->channel;

	pc->id = ioctl(sk, RFCOMMCREATEDEV, &req);
	if (pc->id < 0) {
		err = errno;
		error("ioctl(RFCOMMCREATEDEV): %s (%d)", strerror(err), err);
		err_connection_failed(pc->conn, pc->msg, strerror(err));
		goto fail;
	}


	snprintf(node_name, sizeof(node_name), "/dev/rfcomm%d", pc->id);

	fd = open(node_name, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		g_timeout_add(OPEN_WAIT,
			(GSourceFunc) rfcomm_connect_cb_continue, pc);
		return FALSE;
	}

	add_rfcomm_node(g_io_channel_unix_new(fd), pc->id, node_name,
			pc->conn, dbus_message_get_sender(pc->msg));

	/* Reply to the requestor */
	reply = dbus_message_new_method_return(pc->msg);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pname,
			DBUS_TYPE_INVALID);
	send_message_and_unref(pc->conn, reply);

	/* Send the D-Bus signal */
	send_signal(pc->conn, "ServiceConnected", node_name);
fail:
	pending_connection_free(pc);
	/* FIXME: Remote from the pending connects list */
	return FALSE;
}

static int rfcomm_connect(struct pending_connection *pc)
{
	struct sockaddr_rc addr;
	GIOChannel *io;
	int sk, err = 0;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -errno;

	addr.rc_family	= AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &pc->src);
	addr.rc_channel	= 0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		return -errno;

	if (set_nonblocking(sk) < 0)
		return -errno;

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	addr.rc_family	= AF_BLUETOOTH;
	str2ba(pc->addr, &addr.rc_bdaddr);
	addr.rc_channel	= pc->channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		/* BlueZ returns EAGAIN eventhough it should return EINPROGRESS */
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect() failed: %s (%d)", strerror(err), err);
			goto fail;
		}

		debug("Connect in progress");
		g_io_add_watch(io, G_IO_OUT, (GIOFunc) rfcomm_connect_cb, pc);
		/* FIXME: Control the pending connects */
	} else {
		debug("Connect succeeded with first try");
		(void) rfcomm_connect_cb(io, G_IO_OUT, pc);
	}
fail:
	g_io_channel_unref(io);
	return -err;
}

static void record_reply(DBusPendingCall *call, void *data)
{
	struct pending_connection *pc = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	sdp_record_t *rec;
	const uint8_t *rec_bin;
	sdp_list_t *protos;
	DBusError derr;
	int len, scanned, ch, err;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
				"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pc->conn, pc->msg, derr.message);
		else
			err_not_supported(pc->conn, pc->msg);

		error("GetRemoteServiceRecord: %s(%s)",
					derr.name, derr.message);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pc->conn, pc->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pc->conn, pc->msg);
		error("Invalid service record length");
		goto fail;
	}

	rec = sdp_extract_pdu(rec_bin, &scanned);
	if (!rec) {
		error("Can't extract SDP record.");
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	if (len != scanned || (sdp_get_access_protos(rec, &protos) < 0)) {
		sdp_record_free(rec);
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch < 1 || ch > 30) {
		error("Channel out of range: %d", ch);
		sdp_record_free(rec);
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	/* FIXME: Check if there is a pending connection or if it was canceled */

	pc->channel = ch;
	err = rfcomm_connect(pc);
	if (err < 0) {
		error("RFCOMM connection failed");
		err_connection_failed(pc->conn, pc->msg, strerror(-err));
		goto fail;
	}

	dbus_message_unref(reply);
	return;
fail:
	dbus_message_unref(reply);
	dbus_error_free(&derr);
	pending_connection_free(pc);
}

static int get_record(struct pending_connection *pc, uint32_t handle,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", pc->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceRecord");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pc->addr,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pc->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pc, NULL);
	dbus_message_unref(msg);
	dbus_pending_call_unref(pending);

	return 0;
}

static void handles_reply(DBusPendingCall *call, void *data)
{
	struct pending_connection *pc = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	uint32_t *phandle;
	int len;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
				"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pc->conn, pc->msg, derr.message);
		else
			err_not_supported(pc->conn, pc->msg);

		error("GetRemoteServiceHandles: %s(%s)",
					derr.name, derr.message);
		goto fail;
	}
	
	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle,
				&len, DBUS_TYPE_INVALID)) {
		err_not_supported(pc->conn, pc->msg);
		error("%s: %s", derr.name, derr.message);
		goto fail;
	}

	if (len == 0) {
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	if (get_record(pc, *phandle, record_reply) < 0) {
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	dbus_message_unref(reply);
	return;
fail:
	dbus_message_unref(reply);
	dbus_error_free(&derr);
	pending_connection_free(pc);
}

static int get_handles(struct pending_connection *pc, const char *uuid,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", pc->adapter_path,
				"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pc->addr,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pc->conn, msg, &pending, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pending, cb, pc, NULL);
	dbus_message_unref(msg);
	dbus_pending_call_unref(pending);

	return 0;
}

static DBusHandlerResult connect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusError derr;
	bdaddr_t src;
	struct pending_connection *pc;
	const char *addr, *pattern;
	char *endptr;
	long val;
	int dev_id, err;
	uint16_t cls;
	char tmp[37];

	/* FIXME: Check if it already exist or if there is pending connect */

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	dev_id = hci_get_route(NULL);
	if ((dev_id < 0) ||  (hci_devba(dev_id, &src) < 0))
		return err_failed(conn, msg, "Adapter not available");

	pc = g_new0(struct pending_connection, 1);
	pc->conn = dbus_connection_ref(conn);
	pc->msg = dbus_message_ref(msg);
	bacpy(&pc->src, &src);
	pc->addr = g_strdup(addr);
	pc->adapter_path = g_malloc0(16);
	snprintf(pc->adapter_path, 16, "/org/bluez/hci%d", dev_id);

	memset(tmp, 0, sizeof(tmp));

	/* Friendly name */
	cls = str2class(pattern);
	if (cls) {
		uuid_t uuid16, uuid128;

		sdp_uuid16_create(&uuid16, cls);
		sdp_uuid16_to_uuid128(&uuid128, &uuid16);
		sdp_uuid2strn(&uuid128, tmp, sizeof(tmp));

		if (get_handles(pc, tmp, handles_reply) < 0) {
			pending_connection_free(pc);
			return err_not_supported(conn, msg);
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* UUID 128*/
	if (strlen(pattern) == 36) {
		strcpy(tmp, pattern);
		tmp[4] = '0';
		tmp[5] = '0';
		tmp[6] = '0';
		tmp[7] = '0';

		if (strcasecmp(BASE_UUID, tmp) != 0) {
			pending_connection_free(pc);
			return err_invalid_args(conn, msg, "invalid UUID");
		}

		if (get_handles(pc, pattern, handles_reply) < 0) {
			pending_connection_free(pc);
			return err_not_supported(conn, msg);
		}
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	errno = 0;
	val = strtol(pattern, &endptr, 0);
	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
			(errno != 0 && val == 0) || (pattern == endptr)) {
		pending_connection_free(pc);
		return err_invalid_args(conn, msg, "Invalid pattern");
	}

	/* Record handle: starts at 0x10000 */
	if (strncasecmp("0x", pattern, 2) == 0) {
		if (val < 0x10000) {
			pending_connection_free(pc);
			return err_invalid_args(conn, msg,
					"invalid record handle");
		}

		if (get_record(pc, val, record_reply) < 0) {
			pending_connection_free(pc);
			return err_not_supported(conn, msg);
		}
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* RFCOMM Channel range: 1 - 30 */
	if (val < 1 || val > 30) {
		pending_connection_free(pc);
		return err_invalid_args(conn, msg,
				"invalid RFCOMM channel");
	}

	pc->channel = val;
	err = rfcomm_connect(pc);
	if (err < 0) {
		const char *strerr = strerror(-err);
		error("RFCOMM connect failed: %s(%d)", strerr, -err);
		err_connection_failed(conn, msg, strerr);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusError derr;
	struct rfcomm_node *node;
	const char *name;
	GSList *l;
	int err;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	l = g_slist_find_custom(connected_nodes, name, (GCompareFunc) node_cmp_by_name);
	if (!l)
		return err_does_not_exist(conn, msg, "Invalid node");

	node = l->data;

	if (strcmp(node->owner, dbus_message_get_sender(msg)) != 0)
		return err_not_authorized(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	err = rfcomm_release(node->id);
	if (err < 0) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, strerror(err));
	}

	name_listener_remove(node->conn, node->owner,
			(name_cb_t) connect_service_exited, node);
	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult cancel_connect_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult manager_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *iface, *member;

	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	/* Accept messages from the manager interface only */
	if (strcmp(SERIAL_MANAGER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "ConnectService") == 0)
		return connect_service(conn, msg, data);

	if (strcmp(member, "DisconnectService") == 0)
		return disconnect_service(conn, msg, data);

	if (strcmp(member, "CancelConnectService") == 0)
		return cancel_connect_service(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	if (connected_nodes) {
		g_slist_foreach(connected_nodes,
				(GFunc) rfcomm_node_free, NULL);
		g_slist_free(connected_nodes);
		connected_nodes = NULL;
	}
}

/* Virtual table to handle manager object path hierarchy */
static const DBusObjectPathVTable manager_table = {
	.message_function	= manager_message,
	.unregister_function	= manager_unregister,
};

int serial_init(DBusConnection *conn)
{

	if (rfcomm_ctl < 0) {
		rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
		if (rfcomm_ctl < 0)
			return -errno;
	}

	connection = dbus_connection_ref(conn);

	if (dbus_connection_register_object_path(connection,
			SERIAL_MANAGER_PATH, &manager_table, NULL) == FALSE) {
		error("D-Bus failed to register %s path", SERIAL_MANAGER_PATH);
		dbus_connection_unref(connection);

		return -1;
	}

	info("Registered manager path:%s", SERIAL_MANAGER_PATH);

	return 0;
}

void serial_exit(void)
{
	dbus_connection_unregister_object_path(connection, SERIAL_MANAGER_PATH);

	dbus_connection_unref(connection);
	connection = NULL;

	if (rfcomm_ctl >= 0)
		close(rfcomm_ctl);
}
