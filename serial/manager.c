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
#include "dbus-helper.h"
#include "logging.h"

#include "error.h"
#include "port.h"
#include "manager.h"

#define BASE_UUID			"00000000-0000-1000-8000-00805F9B34FB"

struct pending_connect {
	DBusConnection	*conn;
	DBusMessage	*msg;
	char		*bda;		/* Destination address  */
	char		*adapter_path;	/* Adapter D-Bus path   */
	char		*pattern;	/* Connection request pattern */
	bdaddr_t	src;
	uint8_t		channel;
	int		id;		/* RFCOMM device id */
	int		ntries;		/* Open attempts */
	int 		canceled;	/* Operation canceled */
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
static GSList *pending_connects = NULL;
static int rfcomm_ctl = -1;

static void pending_connect_free(struct pending_connect *pc)
{
	if (pc->conn)
		dbus_connection_unref(pc->conn);
	if (pc->msg)
		dbus_message_unref(pc->msg);
	if (pc->bda)
		g_free(pc->bda);
	if (pc->pattern)
		g_free(pc->pattern);
	if (pc->adapter_path)
		g_free(pc->adapter_path);
	g_free(pc);
}

static void pending_connect_remove(struct pending_connect *pc)
{
	pending_connects = g_slist_remove(pending_connects, pc);
	pending_connect_free(pc);
}

static struct pending_connect *find_pending_connect_by_pattern(const char *bda,
							const char *pattern)
{
	GSList *l;

	/* Pattern can be friendly name, uuid128, record handle or channel */
	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pending = l->data;
		if (!strcasecmp(pending->bda, bda) &&
				!strcasecmp(pending->pattern, pattern))
			return pending;
	}

	return NULL;
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

int rfcomm_release(int16_t id)
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

static int rfcomm_bind(bdaddr_t *src, bdaddr_t *dst, uint8_t ch)
{
	struct rfcomm_dev_req req;
	int id;

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = 0;
	bacpy(&req.src, src);
	bacpy(&req.dst, dst);
	req.channel = ch;

	id = ioctl(rfcomm_ctl, RFCOMMCREATEDEV, &req);
	if (id < 0) {
		int err = errno;
		error("RFCOMMCREATEDEV failed: %s (%d)", strerror(err), err);
		return -err;
	}

	return id;
}

static void open_notify(int fd, int err, void *data)
{
	char port_name[16];
	char path[MAX_PATH_LENGTH];
	const char *pname = port_name;
	const char *ppath = path;
	const char *owner;
	DBusMessage *reply;
	struct pending_connect *pc = data;

	if (err) {
		/* Max tries exceeded */
		err_connection_failed(pc->conn, pc->msg, strerror(err));
		return;
	}

	if (pc->canceled) {
		rfcomm_release(pc->id);
		err_connection_canceled(pc->conn, pc->msg);
		return;
	}

	/* Check if the caller is still present */
	owner = dbus_message_get_sender(pc->msg);
	if (!dbus_bus_name_has_owner(pc->conn, owner, NULL)) {
		error("Connect requestor %s exited", owner);
		rfcomm_release(pc->id);
		return;
	}

	snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", pc->id);

	/* Reply to the requestor */
	reply = dbus_message_new_method_return(pc->msg);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pname,
			DBUS_TYPE_INVALID);
	send_message_and_unref(pc->conn, reply);

	/* Send the D-Bus signal */
	port_register(pc->conn, pc->id, fd, pname, owner, path);
	dbus_connection_emit_signal(pc->conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "PortCreated" ,
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);

	dbus_connection_emit_signal(pc->conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceConnected" ,
			DBUS_TYPE_STRING, &pname,
			DBUS_TYPE_INVALID);

}

static gboolean rfcomm_connect_cb(GIOChannel *chan,
		GIOCondition cond, struct pending_connect *pc)
{
	char port_name[16];
	struct rfcomm_dev_req req;
	int sk, err, fd, close_chan = 1;

	if (pc->canceled) {
		err_connection_canceled(pc->conn, pc->msg);
		goto fail;
	}

	sk = g_io_channel_unix_get_fd(chan);

	if (cond & G_IO_NVAL) {
		close_chan = 0;
		err_connection_failed(pc->conn, pc->msg,
				"File descriptor is not open");
		goto fail;
	}

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		socklen_t len;
		int ret;

		len = sizeof(ret);
		if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
			err = errno;
			error("getsockopt(SO_ERROR): %s (%d)",
						strerror(err), err);
			err_connection_failed(pc->conn,
					pc->msg, strerror(err));
			goto fail;
		}

		if (ret != 0) {
			error("connect(): %s (%d)", strerror(ret), ret);
			err_connection_failed(pc->conn, pc->msg, strerror(ret));
			goto fail;
		}

		error("Hangup on rfcomm socket");
		err_connection_canceled(pc->conn, pc->msg);
		goto fail;
	}

	debug("rfcomm_connect_cb: connected");

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = (1 << RFCOMM_REUSE_DLC) | (1 << RFCOMM_RELEASE_ONHUP);
	bacpy(&req.src, &pc->src);
	str2ba(pc->bda, &req.dst);
	req.channel = pc->channel;

	pc->id = ioctl(sk, RFCOMMCREATEDEV, &req);
	if (pc->id < 0) {
		err = errno;
		error("ioctl(RFCOMMCREATEDEV): %s (%d)", strerror(err), err);
		err_connection_failed(pc->conn, pc->msg, strerror(err));
		goto fail;
	}

	snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", pc->id);
	/* Addressing connect port */
	fd = port_open(port_name, open_notify, pc,
			(udata_free_t) pending_connect_remove);
	if (fd < 0) {
		g_io_channel_close(chan);
		/* Open in progress: Wait the callback */
		return FALSE;
	}

	open_notify(fd, 0, pc);
fail:
	pending_connects = g_slist_remove(pending_connects, pc);
	pending_connect_free(pc);
	if (close_chan)
		g_io_channel_close(chan);

	return FALSE;
}

static int rfcomm_connect(struct pending_connect *pc)
{
	struct sockaddr_rc addr;
	GIOChannel *io;
	int sk, err = 0;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family	= AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &pc->src);
	addr.rc_channel	= 0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		return -errno;

	if (set_nonblocking(sk) < 0)
		return -errno;

	io = g_io_channel_unix_new(sk);

	addr.rc_family	= AF_BLUETOOTH;
	str2ba(pc->bda, &addr.rc_bdaddr);
	addr.rc_channel	= pc->channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		/* BlueZ returns EAGAIN eventhough it should return EINPROGRESS */
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect() failed: %s (%d)", strerror(err), err);
			goto fail;
		}

		debug("Connect in progress");
		g_io_add_watch(io, G_IO_OUT | G_IO_ERR | G_IO_NVAL | G_IO_HUP,
						(GIOFunc) rfcomm_connect_cb, pc);
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
	struct pending_connect *pc = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	sdp_record_t *rec;
	const uint8_t *rec_bin;
	sdp_list_t *protos;
	DBusError derr;
	int len, scanned, ch, err;

	if (pc->canceled) {
		err_connection_canceled(pc->conn, pc->msg);
		goto fail;
	}

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
				"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pc->conn, pc->msg, derr.message);
		else
			err_not_supported(pc->conn, pc->msg);

		error("GetRemoteServiceRecord: %s(%s)",
					derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}

	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &rec_bin, &len,
				DBUS_TYPE_INVALID)) {
		err_not_supported(pc->conn, pc->msg);
		error("%s: %s", derr.name, derr.message);
		dbus_error_free(&derr);
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

	sdp_record_free(rec);

	if (ch < 1 || ch > 30) {
		error("Channel out of range: %d", ch);
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	if (dbus_message_has_member(pc->msg, "CreatePort")) {
		char path[MAX_PATH_LENGTH];
		char port_name[16];
		const char *ppath = path;
		DBusMessage *reply;
		bdaddr_t dst;

		str2ba(pc->bda, &dst);
		err = rfcomm_bind(&pc->src, &dst, ch);
		if (err < 0) {
			err_failed(pc->conn, pc->msg, strerror(-err));
			goto fail;
		}

		snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", err);
		port_register(pc->conn, err, -1, port_name, NULL, path);

		reply = dbus_message_new_method_return(pc->msg);
		dbus_message_append_args(reply,
				DBUS_TYPE_STRING, &ppath,
				DBUS_TYPE_INVALID);
		send_message_and_unref(pc->conn, reply);

		dbus_connection_emit_signal(pc->conn, SERIAL_MANAGER_PATH,
				SERIAL_MANAGER_INTERFACE, "PortCreated" ,
				DBUS_TYPE_STRING, &ppath,
				DBUS_TYPE_INVALID);
	} else {
		/* ConnectService */
		pc->channel = ch;
		err = rfcomm_connect(pc);
		if (err < 0) {
			error("RFCOMM connection failed");
			err_connection_failed(pc->conn, pc->msg, strerror(-err));
			goto fail;
		}

		/* Wait the connect callback */
		dbus_message_unref(reply);
		return;
	}

fail:
	dbus_message_unref(reply);
	pending_connects = g_slist_remove(pending_connects, pc);
	pending_connect_free(pc);
}

static int get_record(struct pending_connect *pc, uint32_t handle,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", pc->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceRecord");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pc->bda,
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
	struct pending_connect *pc = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	uint32_t *phandle;
	int len;

	if (pc->canceled) {
		err_connection_canceled(pc->conn, pc->msg);
		goto fail;
	}

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		if (dbus_error_has_name(&derr,
				"org.bluez.Error.ConnectionAttemptFailed"))
			err_connection_failed(pc->conn, pc->msg, derr.message);
		else
			err_not_supported(pc->conn, pc->msg);

		error("GetRemoteServiceHandles: %s(%s)",
					derr.name, derr.message);
		dbus_error_free(&derr);
		goto fail;
	}
	
	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &phandle,
				&len, DBUS_TYPE_INVALID)) {
		err_not_supported(pc->conn, pc->msg);
		error("%s: %s", derr.name, derr.message);
		dbus_error_free(&derr);
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
	pending_connects = g_slist_remove(pending_connects, pc);
	pending_connect_free(pc);
}

static int get_handles(struct pending_connect *pc, const char *uuid,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", pc->adapter_path,
				"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pc->bda,
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

static int pattern2uuid128(const char *pattern, char *uuid, size_t size)
{
	uint16_t cls;

	/* Friendly name */
	cls = str2class(pattern);
	if (cls) {
		uuid_t uuid16, uuid128;

		sdp_uuid16_create(&uuid16, cls);
		sdp_uuid16_to_uuid128(&uuid128, &uuid16);
		sdp_uuid2strn(&uuid128, uuid, size);
		return 0;
	}

	/* UUID 128*/
	if ((strlen(pattern) == 36) &&
		(strncasecmp(BASE_UUID, pattern, 3) == 0) &&
		(strncasecmp(BASE_UUID + 8, pattern + 8, 28) == 0)) {

		strncpy(uuid, pattern, size);
		return 0;
	}

	return -EINVAL;
}

static int pattern2long(const char *pattern, long *pval)
{
	char *endptr;
	long val;

	errno = 0;
	val = strtol(pattern, &endptr, 0);
	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
			(errno != 0 && val == 0) || (pattern == endptr)) {
		return -EINVAL;
	}

	*pval = val;

	return 0;
}

static DBusHandlerResult create_port(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct pending_connect *pending, *pc;
	DBusMessage *reply;
	DBusError derr;
	bdaddr_t src, dst;
	char path[MAX_PATH_LENGTH];
	const char *bda, *pattern, *ppath = path;
	long val;
	int dev_id, err;
	char port_name[16];
	char uuid[37];

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &bda,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	pending = find_pending_connect_by_pattern(bda, pattern);
	if (pending)
		return err_connection_in_progress(conn, msg);

	dev_id = hci_get_route(NULL);
	if ((dev_id < 0) ||  (hci_devba(dev_id, &src) < 0))
		return err_failed(conn, msg, "Adapter not available");

	pc = g_new0(struct pending_connect, 1);
	bacpy(&pc->src, &src);
	pc->conn = dbus_connection_ref(conn);
	pc->msg = dbus_message_ref(msg);
	pc->bda = g_strdup(bda);
	pc->pattern = g_strdup(pattern);
	pc->adapter_path = g_malloc0(16);
	snprintf(pc->adapter_path, 16, "/org/bluez/hci%d", dev_id);

	memset(uuid, 0, sizeof(uuid));

	/* Friendly name or uuid128 */
	if (pattern2uuid128(pattern, uuid, sizeof(uuid)) == 0) {
		if (get_handles(pc, uuid, handles_reply) < 0) {
			pending_connect_free(pc);
			return err_not_supported(conn, msg);
		}
		pending_connects = g_slist_append(pending_connects, pc);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Record handle or channel */
	err = pattern2long(pattern, &val);
	if (err < 0) {
		pending_connect_free(pc);
		return err_invalid_args(conn, msg, "invalid pattern");
	}

	/* Record handle: starts at 0x10000 */
	if (strncasecmp("0x", pattern, 2) == 0) {
		if (val < 0x10000) {
			pending_connect_free(pc);
			return err_invalid_args(conn, msg,
					"invalid record handle");
		}

		if (get_record(pc, val, record_reply) < 0) {
			pending_connect_free(pc);
			return err_not_supported(conn, msg);
		}
		pending_connects = g_slist_append(pending_connects, pc);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	pending_connect_free(pc);
	/* RFCOMM Channel range: 1 - 30 */
	if (val < 1 || val > 30)
		return err_invalid_args(conn, msg,
				"invalid RFCOMM channel");

	str2ba(bda, &dst);
	err = rfcomm_bind(&src, &dst, val);
	if (err < 0)
		return err_failed(conn, msg, strerror(-err));

	snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", err);
	port_register(conn, err, -1, port_name, NULL, path);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);
	send_message_and_unref(conn, reply);

	dbus_connection_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "PortCreated" ,
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult list_ports(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult remove_port(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult connect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct pending_connect *pending, *pc;
	DBusError derr;
	bdaddr_t src;
	const char *bda, *pattern;
	long val;
	int dev_id, err;
	char uuid[37];

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &bda,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	pending = find_pending_connect_by_pattern(bda, pattern);
	if (pending)
		return err_connection_in_progress(conn, msg);

	dev_id = hci_get_route(NULL);
	if ((dev_id < 0) ||  (hci_devba(dev_id, &src) < 0))
		return err_failed(conn, msg, "Adapter not available");

	pc = g_new0(struct pending_connect, 1);
	bacpy(&pc->src, &src);
	pc->conn = dbus_connection_ref(conn);
	pc->msg = dbus_message_ref(msg);
	pc->bda = g_strdup(bda);
	pc->pattern = g_strdup(pattern);
	pc->adapter_path = g_malloc0(16);
	snprintf(pc->adapter_path, 16, "/org/bluez/hci%d", dev_id);

	memset(uuid, 0, sizeof(uuid));

	/* Friendly name or uuid128 */
	if (pattern2uuid128(pattern, uuid, sizeof(uuid)) == 0) {
		if (get_handles(pc, uuid, handles_reply) < 0) {
			pending_connect_free(pc);
			return err_not_supported(conn, msg);
		}
		pending_connects = g_slist_append(pending_connects, pc);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* Record handle or channel */
	err = pattern2long(pattern, &val);
	if (err < 0) {
		pending_connect_free(pc);
		return err_invalid_args(conn, msg, "invalid pattern");
	}

	/* Record handle: starts at 0x10000 */
	if (strncasecmp("0x", pattern, 2) == 0) {
		if (val < 0x10000) {
			pending_connect_free(pc);
			return err_invalid_args(conn, msg,
					"invalid record handle");
		}

		if (get_record(pc, val, record_reply) < 0) {
			pending_connect_free(pc);
			return err_not_supported(conn, msg);
		}
		pending_connects = g_slist_append(pending_connects, pc);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* RFCOMM Channel range: 1 - 30 */
	if (val < 1 || val > 30) {
		pending_connect_free(pc);
		return err_invalid_args(conn, msg,
				"invalid RFCOMM channel");
	}

	/* Add here since connect() in the first try can happen */
	pending_connects = g_slist_append(pending_connects, pc);

	pc->channel = val;
	err = rfcomm_connect(pc);
	if (err < 0) {
		const char *strerr = strerror(-err);
		error("RFCOMM connect failed: %s(%d)", strerr, -err);
		pending_connects = g_slist_remove(pending_connects, pc);
		pending_connect_free(pc);
		return err_connection_failed(conn, msg, strerr);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusError derr;
	const char *name, *owner;
	int err;
	int id;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (sscanf(name, "/dev/rfcomm%d", &id) != 1)
		return err_invalid_args(conn, msg, "invalid RFCOMM node");

	owner = port_get_owner(conn, id);
	if (!owner)
		return err_does_not_exist(conn, msg, "Invalid RFCOMM node");

	if (strcmp(owner, dbus_message_get_sender(msg)) != 0)
		return err_not_authorized(conn, msg);

	err = rfcomm_release(id);
	if (err < 0)
		return err_failed(conn, msg, strerror(-err));

	return send_message_and_unref(conn,
			dbus_message_new_method_return(msg));
}

static DBusHandlerResult cancel_connect_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct pending_connect *pending;
	DBusMessage *reply;
	DBusError derr;
	const char *bda, *pattern;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &bda,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	pending = find_pending_connect_by_pattern(bda, pattern);
	if (!pending)
		return err_connection_not_in_progress(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	pending->canceled = 1;

	return send_message_and_unref(conn, reply);
}

static void manager_unregister(DBusConnection *conn, void *data)
{
	if (pending_connects) {
		g_slist_foreach(pending_connects,
				(GFunc) pending_connect_free, NULL);
		g_slist_free(pending_connects);
		pending_connects = NULL;
	}
}

static DBusMethodVTable manager_methods[] = {
	{ "CreatePort",			create_port,		"ss",	"s"	},
	{ "ListPorts",			list_ports,		"",	"as"	},
	{ "RemovePort",			remove_port,		"s",	""	},
	{ "ConnectService",		connect_service,	"ss",	"s"	},
	{ "DisconnectService",		disconnect_service,	"s",	""	},
	{ "CancelConnectService",	cancel_connect_service,	"ss",	""	},
	{ NULL, NULL, NULL, NULL },
};

static DBusSignalVTable manager_signals[] = {
	{ "ServiceConnected",		"s"	},
	{ "ServiceDisconnected",	"s"	},
	{ "PortCreated",		"s"	},
	{ "PortRemoved",		"s"	},
	{ NULL, NULL }
};

int serial_init(DBusConnection *conn)
{

	if (rfcomm_ctl < 0) {
		rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
		if (rfcomm_ctl < 0)
			return -errno;
	}

	if (!dbus_connection_create_object_path(conn, SERIAL_MANAGER_PATH,
						NULL, manager_unregister)) {
		error("D-Bus failed to register %s path", SERIAL_MANAGER_PATH);
		return -1;
	}

	if (!dbus_connection_register_interface(conn, SERIAL_MANAGER_PATH,
						SERIAL_MANAGER_INTERFACE,
						manager_methods,
						manager_signals, NULL)) {
		error("Failed to register %s interface to %s",
				SERIAL_MANAGER_INTERFACE, SERIAL_MANAGER_PATH);
		dbus_connection_destroy_object_path(connection,
							SERIAL_MANAGER_PATH);
		return -1;
	}

	connection = dbus_connection_ref(conn);

	info("Registered manager path:%s", SERIAL_MANAGER_PATH);

	return 0;
}

void serial_exit(void)
{
	dbus_connection_destroy_object_path(connection, SERIAL_MANAGER_PATH);

	dbus_connection_unref(connection);
	connection = NULL;

	if (rfcomm_ctl >= 0)
		close(rfcomm_ctl);
}
