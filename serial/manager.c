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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>

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
#include "textfile.h"

#include "error.h"
#include "port.h"
#include "storage.h"
#include "manager.h"

#define BASE_UUID			"00000000-0000-1000-8000-00805F9B34FB"
#define SERIAL_PROXY_INTERFACE		"org.bluez.serial.Proxy"
#define BUF_SIZE			1024

/* Waiting for udev to create the device node */
#define MAX_OPEN_TRIES 		5
#define OPEN_WAIT		300	/* ms */

struct pending_connect {
	DBusConnection	*conn;
	DBusMessage	*msg;
	DBusPendingCall *pcall;		/* Pending get handles/records */
	char		*bda;		/* Destination address  */
	char		*adapter_path;	/* Adapter D-Bus path   */
	char		*pattern;	/* Connection request pattern */
	bdaddr_t	src;
	uint8_t		channel;
	guint		io_id;		/* GIOChannel watch id */
	GIOChannel	*io;		/* GIOChannel for RFCOMM connect */
	char		*dev;		/* tty device name */
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

struct proxy {
	bdaddr_t	src;
	bdaddr_t	dst;
	uuid_t		uuid;		/* UUID 128 */
	char		*tty;		/* TTY name */
	struct termios  sys_ti;		/* Default TTY setting */
	struct termios  proxy_ti;	/* Proxy TTY settings */
	uint8_t		channel;	/* RFCOMM channel */
	uint32_t	record_id;	/* Service record id */
	guint		listen_watch;	/* Server listen watch */
	guint		rfcomm_watch;	/* RFCOMM connection watch */
	guint		tty_watch;	/* Openned TTY watch */
};

static DBusConnection *connection = NULL;
static GSList *pending_connects = NULL;
static GSList *ports_paths = NULL;
static GSList *proxies_paths = NULL;
static int rfcomm_ctl = -1;

static void proxy_free(struct proxy *prx)
{
	if (prx->tty)
		g_free(prx->tty);
	g_free(prx);
}

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
	if (pc->pcall)
		dbus_pending_call_unref(pc->pcall);
	if (pc->dev)
		g_free(pc->dev);
	if (pc->io_id > 0)
		g_source_remove(pc->io_id);
	if (pc->io) {
		g_io_channel_close(pc->io);
		g_io_channel_unref(pc->io);
	}
	g_free(pc);
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

static void transaction_owner_exited(const char *name, void *data)
{
	GSList *l, *tmp = NULL;
	debug("transaction owner %s exited", name);

	/* Clean all pending calls that belongs to this owner */
	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pc = l->data;
		if (strcmp(name, dbus_message_get_sender(pc->msg)) != 0) {
			tmp = g_slist_append(tmp, pc);
			continue;
		}

		if (pc->pcall)
			dbus_pending_call_cancel(pc->pcall);

		if (pc->id >= 0)
			rfcomm_release(pc->id);

		pending_connect_free(pc);
	}

	g_slist_free(pending_connects);
	pending_connects = tmp;
}

static void pending_connect_remove(struct pending_connect *pc)
{
	/* Remove the connection request owner */
	name_listener_remove(pc->conn, dbus_message_get_sender(pc->msg),
				(name_cb_t) transaction_owner_exited, NULL);

	pending_connects = g_slist_remove(pending_connects, pc);
	pending_connect_free(pc);
}

static void open_notify(int fd, int err, struct pending_connect *pc)
{
	DBusMessage *reply;
	bdaddr_t dst;

	if (err) {
		/* Max tries exceeded */
		rfcomm_release(pc->id);
		err_connection_failed(pc->conn, pc->msg, strerror(err));
		return;
	}

	if (pc->canceled) {
		rfcomm_release(pc->id);
		err_connection_canceled(pc->conn, pc->msg);
		return;
	}

	/* Reply to the requestor */
	reply = dbus_message_new_method_return(pc->msg);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pc->dev,
			DBUS_TYPE_INVALID);
	send_message_and_unref(pc->conn, reply);

	/* Send the D-Bus signal */
	dbus_connection_emit_signal(pc->conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceConnected" ,
			DBUS_TYPE_STRING, &pc->dev,
			DBUS_TYPE_INVALID);

	str2ba(pc->bda, &dst);

	/* Add the RFCOMM connection listener */
	port_add_listener(pc->conn, pc->id, &dst, fd,
			pc->dev, dbus_message_get_sender(pc->msg));
}

static gboolean open_continue(struct pending_connect *pc)
{
	int fd;

	if (!g_slist_find(pending_connects, pc))
		return FALSE; /* Owner exited */

	fd = open(pc->dev, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		int err = errno;
		error("Could not open %s: %s (%d)",
				pc->dev, strerror(err), err);
		if (++pc->ntries >= MAX_OPEN_TRIES) {
			/* Reporting error */
			open_notify(fd, err, pc);
			pending_connect_remove(pc);
			return FALSE;
		}
		return TRUE;
	}
	/* Connection succeeded */
	open_notify(fd, 0, pc);
	pending_connect_remove(pc);
	return FALSE;
}

int port_open(struct pending_connect *pc)
{
	int fd;

	fd = open(pc->dev, O_RDONLY | O_NOCTTY);
	if (fd < 0) {
		g_timeout_add(OPEN_WAIT, (GSourceFunc) open_continue, pc);
		return -EINPROGRESS;
	}

	return fd;
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

	/*
	 * We are hitting a kernel bug inside RFCOMM code when
	 * RFCOMM_HANGUP_NOW bit is set on request's flags passed to
	 * ioctl(RFCOMMRELEASEDEV)!
	 */
	req.flags = (1 << RFCOMM_HANGUP_NOW);

	if (ioctl(rfcomm_ctl, RFCOMMRELEASEDEV, &req) < 0) {
		int err = errno;
		error("Can't release device %d: %s (%d)",
				id, strerror(err), err);
		return -err;
	}

	return 0;
}

static int rfcomm_bind(bdaddr_t *src, bdaddr_t *dst, int16_t dev_id, uint8_t ch)
{
	struct rfcomm_dev_req req;
	int id;

	memset(&req, 0, sizeof(req));
	req.dev_id = dev_id;
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

static gboolean rfcomm_connect_cb(GIOChannel *chan,
		GIOCondition cond, struct pending_connect *pc)
{
	struct rfcomm_dev_req req;
	int sk, err, fd, ret;
	socklen_t len;

	if (pc->canceled) {
		err_connection_canceled(pc->conn, pc->msg);
		goto fail;
	}

	if (cond & G_IO_NVAL) {
		/* Avoid close invalid file descriptor */
		g_io_channel_unref(pc->io);
		pc->io = NULL;
		err_connection_canceled(pc->conn, pc->msg);
		goto fail;
	}

	sk = g_io_channel_unix_get_fd(chan);
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
	pc->dev	= g_new0(char, 16);
	snprintf(pc->dev, 16, "/dev/rfcomm%d", pc->id);

	/* Addressing connect port */
	fd = port_open(pc);
	if (fd < 0)
		/* Open in progress: Wait the callback */
		return FALSE;

	open_notify(fd, 0, pc);
fail:
	pending_connect_remove(pc);
	return FALSE;
}

static int rfcomm_connect(struct pending_connect *pc)
{
	struct sockaddr_rc addr;
	int sk, err;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family	= AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &pc->src);
	addr.rc_channel	= 0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto fail;

	if (set_nonblocking(sk) < 0)
		goto fail;

	pc->io = g_io_channel_unix_new(sk);
	addr.rc_family	= AF_BLUETOOTH;
	str2ba(pc->bda, &addr.rc_bdaddr);
	addr.rc_channel	= pc->channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		/* BlueZ returns EAGAIN eventhough it should return EINPROGRESS */
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			error("connect() failed: %s (%d)",
					strerror(errno), errno);
			goto fail;
		}

		debug("Connect in progress");
		pc->io_id = g_io_add_watch(pc->io,
				G_IO_OUT | G_IO_ERR | G_IO_NVAL | G_IO_HUP,
				(GIOFunc) rfcomm_connect_cb, pc);
	} else {
		debug("Connect succeeded with first try");
		(void) rfcomm_connect_cb(pc->io, G_IO_OUT, pc);
	}

	return 0;
fail:
	err = errno;
	close(sk);
	errno = err;

	return -err;
}

static void record_reply(DBusPendingCall *call, void *data)
{
	struct pending_connect *pc = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	sdp_record_t *rec = NULL;
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
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch < 1 || ch > 30) {
		error("Channel out of range: %d", ch);
		err_not_supported(pc->conn, pc->msg);
		goto fail;
	}
	if (dbus_message_has_member(pc->msg, "CreatePort")) {
		char path[MAX_PATH_LENGTH], port_name[16];
		const char *ppath = path;
		sdp_data_t *d;
		char *svcname = NULL;
		DBusMessage *reply;
		bdaddr_t dst;

		str2ba(pc->bda, &dst);
		err = rfcomm_bind(&pc->src, &dst, -1, ch);
		if (err < 0) {
			err_failed(pc->conn, pc->msg, strerror(-err));
			goto fail;
		}
		snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", err);

		d = sdp_data_get(rec, SDP_ATTR_SVCNAME_PRIMARY);
		if (d) {
			svcname = g_new0(char, d->unitSize);
			snprintf(svcname, d->unitSize, "%.*s",
					d->unitSize, d->val.str);
		}

		port_store(&pc->src, &dst, err, ch, svcname);
		if (svcname)
			g_free(svcname);

		port_register(pc->conn, err, &dst, port_name, path);
		ports_paths = g_slist_append(ports_paths, g_strdup(path));

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
		goto done;
	}

fail:
	pending_connect_remove(pc);
done:
	if (rec)
		sdp_record_free(rec);
	dbus_message_unref(reply);
}

static int get_record(struct pending_connect *pc, uint32_t handle,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call("org.bluez", pc->adapter_path,
			"org.bluez.Adapter", "GetRemoteServiceRecord");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pc->bda,
			DBUS_TYPE_UINT32, &handle,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pc->conn, msg, &pc->pcall, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pc->pcall, cb, pc, NULL);
	dbus_message_unref(msg);

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
	pending_connect_remove(pc);
}

static int get_handles(struct pending_connect *pc, const char *uuid,
					DBusPendingCallNotifyFunction cb)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call("org.bluez", pc->adapter_path,
				"org.bluez.Adapter", "GetRemoteServiceHandles");
	if (!msg)
		return -1;

	dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &pc->bda,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(pc->conn, msg, &pc->pcall, -1) == FALSE) {
		error("Can't send D-Bus message.");
		return -1;
	}

	dbus_pending_call_set_notify(pc->pcall, cb, pc, NULL);
	dbus_message_unref(msg);

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
	char path[MAX_PATH_LENGTH], port_name[16], uuid[37];
	const char *bda, *pattern, *ppath = path;
	long val;
	int dev_id, err;

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
	pc->id = -1;
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
		name_listener_add(conn, dbus_message_get_sender(msg),
				(name_cb_t) transaction_owner_exited, NULL);
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
		name_listener_add(conn, dbus_message_get_sender(msg),
				(name_cb_t) transaction_owner_exited, NULL);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	pending_connect_free(pc);
	/* RFCOMM Channel range: 1 - 30 */
	if (val < 1 || val > 30)
		return err_invalid_args(conn, msg,
				"invalid RFCOMM channel");

	str2ba(bda, &dst);
	err = rfcomm_bind(&src, &dst, -1, val);
	if (err < 0)
		return err_failed(conn, msg, strerror(-err));

	snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", err);
	port_store(&src, &dst, err, val, NULL);
	port_register(conn, err, &dst, port_name, path);
	ports_paths = g_slist_append(ports_paths, g_strdup(path));

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

static void message_append_paths(DBusMessage *msg, const GSList *list)
{
	const GSList *l;
	const char *path;
	DBusMessageIter iter, iter_array;

	dbus_message_iter_init_append(msg, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &iter_array);

	for (l = list; l; l = l->next) {
		path = l->data;
		dbus_message_iter_append_basic(&iter_array,
				DBUS_TYPE_STRING, &path);
	}

	dbus_message_iter_close_container(&iter, &iter_array);
}

static DBusHandlerResult list_ports(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	message_append_paths(reply, ports_paths);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult remove_port(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct rfcomm_dev_info di;
	DBusError derr;
	const char *path;
	int16_t id;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (sscanf(path, SERIAL_MANAGER_PATH"/rfcomm%hd", &id) != 1)
		return err_does_not_exist(conn, msg, "Invalid RFCOMM node");

	di.id = id;
	if (ioctl(rfcomm_ctl, RFCOMMGETDEVINFO, &di) < 0)
		return err_does_not_exist(conn, msg, "Invalid RFCOMM node");
	port_delete(&di.src, &di.dst, id);

	if (port_unregister(path) < 0)
		return err_does_not_exist(conn, msg, "Invalid RFCOMM node");

	send_message_and_unref(conn,
			dbus_message_new_method_return(msg));

	dbus_connection_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "PortRemoved" ,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static int rfcomm_listen(bdaddr_t *src, uint8_t *channel, int opts)
{
	struct sockaddr_rc laddr;
	socklen_t alen;
	int err, sk;

	sk = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -errno;

	if (setsockopt(sk, SOL_RFCOMM, RFCOMM_LM, &opts, sizeof(opts)) < 0)
		goto fail;

	memset(&laddr, 0, sizeof(laddr));
	laddr.rc_family = AF_BLUETOOTH;
	bacpy(&laddr.rc_bdaddr, src);
	laddr.rc_channel = (channel ? *channel : 0);

	alen = sizeof(laddr);
	if (bind(sk, (struct sockaddr *) &laddr, alen) < 0)
		goto fail;

	if (listen(sk, 1) < 0)
		goto fail;

	if (!channel)
		return sk;

	memset(&laddr, 0, sizeof(laddr));
	if (getsockname(sk, (struct sockaddr *)&laddr, &alen) < 0)
		goto fail;

	*channel = laddr.rc_channel;

	return sk;

fail:
	err = errno;
	close(sk);
	errno = err;

	return -err;
}

static void add_lang_attr(sdp_record_t *r)
{
	sdp_lang_attr_t base_lang;
	sdp_list_t *langs = 0;

	/* UTF-8 MIBenum (http://www.iana.org/assignments/character-sets) */
	base_lang.code_ISO639 = (0x65 << 8) | 0x6e;
	base_lang.encoding = 106;
	base_lang.base_offset = SDP_PRIMARY_LANG_BASE;
	langs = sdp_list_append(0, &base_lang);
	sdp_set_lang_attr(r, langs);
	sdp_list_free(langs, 0);
}

static int create_proxy_record(sdp_buf_t *buf, uuid_t *uuid, uint8_t channel)
{
	sdp_list_t *apseq, *aproto, *profiles, *proto[2], *root, *svclass_id;
	uuid_t root_uuid, l2cap, rfcomm;
	sdp_profile_desc_t profile;
	sdp_record_t record;
	sdp_data_t *ch;
	int ret;

	memset(&record, 0, sizeof(sdp_record_t));
	record.handle = 0xffffffff;
	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(&record, root);
	sdp_list_free(root, NULL);

	svclass_id = sdp_list_append(NULL, uuid);
	sdp_set_service_classes(&record, svclass_id);
	sdp_list_free(svclass_id, NULL);

	sdp_uuid16_create(&profile.uuid, SERIAL_PORT_PROFILE_ID);
	profile.version = 0x0100;
	profiles = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(&record, profiles);
	sdp_list_free(profiles, NULL);

	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	ch = sdp_data_alloc(SDP_UINT8, &channel);
	proto[1] = sdp_list_append(proto[1], ch);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(&record, aproto);

	add_lang_attr(&record);

	sdp_set_info_attr(&record, "Port Proxy Entity",
				NULL, "Port Proxy Entity");

	ret = sdp_gen_record_pdu(&record, buf);

	sdp_data_free(ch);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(aproto, 0);

	return ret;

}

static gboolean forward_data(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[BUF_SIZE];
	GIOChannel *dest = data;
	GIOError err;
	gsize rbytes, wbytes, written;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_close(dest);
		return FALSE;
	}

	memset(buf, 0, sizeof(buf));
	rbytes = wbytes = written = 0;

	err = g_io_channel_read(chan, buf, sizeof(buf) - 1, &rbytes);
	if (err != G_IO_ERROR_NONE)
		return TRUE;

	while (wbytes < rbytes) {
		err = g_io_channel_write(dest,
				buf + wbytes,
				rbytes - wbytes,
				&written);
		if (err != G_IO_ERROR_NONE)
			break;
		wbytes += written;
	}

	return TRUE;
}

static uint32_t add_proxy_record(DBusConnection *conn, sdp_buf_t *buf)
{
	DBusMessage *msg, *reply;
	DBusError derr;
	dbus_uint32_t rec_id;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
			"org.bluez.Database", "AddServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	dbus_message_append_args(msg,
			DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
			&buf->data, buf->data_size,
			DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &derr);

	free(buf->data);
	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) ||
			dbus_set_error_from_message(&derr, reply)) {
		error("Adding service record failed: %s", derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_get_args(reply, &derr,
			DBUS_TYPE_UINT32, &rec_id,
			DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error("Invalid arguments to AddServiceRecord reply: %s",
				derr.message);
		dbus_message_unref(reply);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	return rec_id;
}

static int remove_proxy_record(DBusConnection *conn, uint32_t rec_id)
{
	DBusMessage *msg, *reply;
	DBusError derr;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "RemoveServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return -ENOMEM;
	}

	dbus_message_append_args(msg,
			DBUS_TYPE_UINT32, &rec_id,
			DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr)) {
		error("Removing service record 0x%x failed: %s",
						rec_id, derr.message);
		dbus_error_free(&derr);
		return -1;
	}

	dbus_message_unref(reply);

	return 0;
}

static gboolean connect_event(GIOChannel *chan,
			GIOCondition cond, gpointer data)
{
	struct proxy *prx = data;
	struct sockaddr_rc raddr;
	GIOChannel *node_io, *tty_io;
	socklen_t alen;
	int sk, nsk, tty_sk;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		g_io_channel_close(chan);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	memset(&raddr, 0, sizeof(raddr));
	alen = sizeof(raddr);
	nsk = accept(sk, (struct sockaddr *) &raddr, &alen);
	if (nsk < 0)
		return TRUE;

	bacpy(&prx->dst, &raddr.rc_bdaddr);

	/* TTY open */
	tty_sk = open(prx->tty, O_RDWR | O_NOCTTY);
	if (tty_sk < 0) {
		error("Unable to open %s: %s(%d)",
				prx->tty, strerror(errno), errno);
		close(nsk);
		return TRUE;
	}

	node_io = g_io_channel_unix_new(nsk);
	g_io_channel_set_close_on_unref(node_io, TRUE);
	tty_io = g_io_channel_unix_new(tty_sk);
	g_io_channel_set_close_on_unref(tty_io, TRUE);

	prx->rfcomm_watch = g_io_add_watch(node_io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				forward_data, tty_io);

	prx->tty_watch = g_io_add_watch(tty_io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				forward_data, node_io);

	g_io_channel_unref(node_io);
	g_io_channel_unref(tty_io);

	return TRUE;
}

static void listen_watch_notify(gpointer data)
{
	struct proxy *prx = data;

	prx->listen_watch = 0;

	if (prx->rfcomm_watch) {
		g_source_remove(prx->rfcomm_watch);
		prx->rfcomm_watch = 0;
	}

	if (prx->tty_watch) {
		g_source_remove(prx->tty_watch);
		prx->tty_watch = 0;
	}

	remove_proxy_record(connection, prx->record_id);
	prx->record_id = 0;
}

static DBusHandlerResult proxy_enable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx = data;
	GIOChannel *io;
	sdp_buf_t buf;
	int sk;

	if (prx->listen_watch)
		return err_failed(conn, msg, "Already enabled");

	/* Listen */
	/* FIXME: missing options, update the stored channel */
	sk = rfcomm_listen(&prx->src, &prx->channel, 0);
	if (sk < 0) {
		const char *strerr = strerror(errno);
		error("RFCOMM listen socket failed: %s(%d)", strerr, errno);
		return err_failed(conn, msg, strerr);
	}

	/* Create the record */
	create_proxy_record(&buf, &prx->uuid, prx->channel);

	/* Register the record */
	prx->record_id = add_proxy_record(conn, &buf);
	if (!prx->record_id) {
		close(sk);
		return err_failed(conn, msg, "Service registration failed");
	}

	/* Add incomming connection watch */
	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);
	prx->listen_watch = g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			connect_event, prx, listen_watch_notify);
	g_io_channel_unref(io);

	return send_message_and_unref(conn,
			dbus_message_new_method_return(msg));
}

static DBusHandlerResult proxy_disable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx = data;

	if (!prx->listen_watch)
		return err_failed(conn, msg, "Not enabled");

	/* Remove the watches and unregister the record: see watch notify */
	g_source_remove(prx->listen_watch);

	return send_message_and_unref(conn,
			dbus_message_new_method_return(msg));
}

static DBusHandlerResult proxy_get_info(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx = data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	dbus_bool_t boolean;
	char uuid_str[MAX_LEN_UUID_STR];
	char bda[18];
	const char *pstr;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	sdp_uuid2strn(&prx->uuid, uuid_str, MAX_LEN_UUID_STR);
	pstr = uuid_str;
	dbus_message_iter_append_dict_entry(&dict, "uuid",
			DBUS_TYPE_STRING, &pstr);

	dbus_message_iter_append_dict_entry(&dict, "tty",
			DBUS_TYPE_STRING, &prx->tty);

	if (prx->channel)
		dbus_message_iter_append_dict_entry(&dict, "channel",
				DBUS_TYPE_BYTE, &prx->channel);

	boolean = (prx->listen_watch ? TRUE : FALSE);
	dbus_message_iter_append_dict_entry(&dict, "enabled",
			DBUS_TYPE_BOOLEAN, &boolean);

	boolean = (prx->rfcomm_watch ? TRUE : FALSE);
	dbus_message_iter_append_dict_entry(&dict, "connected",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* If connected: append the remote address */
	if (boolean) {
		ba2str(&prx->dst, bda);
		pstr = bda;
		dbus_message_iter_append_dict_entry(&dict, "address",
				DBUS_TYPE_STRING, &pstr);
	}

	dbus_message_iter_close_container(&iter, &dict);

	return send_message_and_unref(conn, reply);
}

static DBusMethodVTable proxy_methods[] = {
	{ "Enable",			proxy_enable,		"",	""	},
	{ "Disable",			proxy_disable,		"",	""	},
	{ "GetInfo",			proxy_get_info,		"",	"{sv}"	},
	{ NULL, NULL, NULL, NULL },
};

static void proxy_handler_unregister(DBusConnection *conn, void *data)
{
	struct proxy *prx = data;
	int sk;

	info("Unregistered proxy: %s", prx->tty);

	/* Restore the initial TTY configuration */
	sk =  open(prx->tty, O_RDWR | O_NOCTTY);
	if (sk) {
		tcsetattr(sk, TCSAFLUSH, &prx->sys_ti);
		close(sk);
	}

	if (prx->listen_watch)
		g_source_remove(prx->listen_watch);

	proxy_free(prx);
}

static int proxy_register(DBusConnection *conn, bdaddr_t *src, const char *path,
			uuid_t *uuid, const char *tty, struct termios *ti)
{
	struct proxy *prx;

	prx = g_new0(struct proxy, 1);
	prx->tty = g_strdup(tty);
	memcpy(&prx->uuid, uuid, sizeof(uuid_t));
	bacpy(&prx->src, src);
	memcpy(&prx->sys_ti, ti, sizeof(*ti));
	memcpy(&prx->proxy_ti, ti, sizeof(*ti));

	if (!dbus_connection_create_object_path(conn, path, prx,
				proxy_handler_unregister)) {
		proxy_free(prx);
		return -1;
	}

	if (!dbus_connection_register_interface(conn, path,
				SERIAL_PROXY_INTERFACE,
				proxy_methods,
				NULL, NULL)) {
		dbus_connection_destroy_object_path(conn, path);
		return -1;
	}

	dbus_connection_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ProxyCreated",
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	info("Registered proxy:%s path:%s", tty, path);

	return 0;
}

static int str2uuid(uuid_t *uuid, const char *string)
{
	uint16_t data1, data2, data3, data5;
	uint32_t data0, data4;

	if (strlen(string) == 36 &&
			string[8] == '-' &&
			string[13] == '-' &&
			string[18] == '-' &&
			string[23] == '-' &&
			sscanf(string, "%08x-%04hx-%04hx-%04hx-%08x%04hx",
				&data0, &data1, &data2, &data3, &data4, &data5) == 6) {
		uint8_t val[16];

		data0 = htonl(data0);
		data1 = htons(data1);
		data2 = htons(data2);
		data3 = htons(data3);
		data4 = htonl(data4);
		data5 = htons(data5);

		memcpy(&val[0], &data0, 4);
		memcpy(&val[4], &data1, 2);
		memcpy(&val[6], &data2, 2);
		memcpy(&val[8], &data3, 2);
		memcpy(&val[10], &data4, 4);
		memcpy(&val[14], &data5, 2);

		sdp_uuid128_create(uuid, val);

		return 0;
	}

	return -1;
}

static DBusHandlerResult create_proxy(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	char path[MAX_PATH_LENGTH];
	const char *uuidstr, *tty, *ppath = path;
	struct termios ti;
	DBusMessage *reply;
	GSList *l;
	DBusError derr;
	struct stat st;
	bdaddr_t src;
	uuid_t uuid;
	int sk, dev_id, pos = 0;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &uuidstr,
				DBUS_TYPE_STRING, &tty,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (str2uuid(&uuid, uuidstr) < 0)
		return err_invalid_args(conn, msg, "Invalid UUID");

	sscanf(tty, "/dev/%n", &pos);
	if (!pos || stat(tty, &st) < 0)
		return err_invalid_args(conn, msg, "Invalid TTY");

	/* Get the current setting to restore later */
	sk = open(tty, O_RDWR | O_NOCTTY);
	if (sk < 0)
		return err_invalid_args(conn, msg, "Can't open TTY");

	tcgetattr(sk, &ti);
	close(sk);

	snprintf(path, MAX_PATH_LENGTH - 1,
			"/org/bluez/serial/proxy%s", tty + pos);

	l = g_slist_find_custom(proxies_paths, path, (GCompareFunc) strcmp);
	if (l)
		return err_already_exists(conn, msg, "Proxy already exists");

	dev_id = hci_get_route(NULL);
	if ((dev_id < 0) || (hci_devba(dev_id, &src) < 0)) {
		error("Adapter not available");
		return err_failed(conn, msg, "Adapter not available");
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (proxy_register(conn, &src, path, &uuid, tty, &ti) < 0) {
		dbus_message_unref(reply);
		return err_failed(conn, msg, "Create object path failed");
	}

	proxies_paths = g_slist_append(proxies_paths, g_strdup(path));

	proxy_store(&src, uuidstr, tty, NULL, 0, 0, &ti);

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_proxies(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	message_append_paths(reply, proxies_paths);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult remove_proxy(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx = NULL;
	const char *path;
	GSList *l;
	DBusError derr;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	l = g_slist_find_custom(proxies_paths, path, (GCompareFunc) strcmp);
	if (!l)
		return err_does_not_exist(conn, msg, "Invalid proxy path");

	/* Remove from storage */
	if (dbus_connection_get_object_user_data(conn,
				path, (void *) &prx) && prx)
		proxy_delete(&prx->src, prx->tty);

	g_free(l->data);
	proxies_paths = g_slist_remove(proxies_paths, l->data);

	dbus_connection_destroy_object_path(conn, path);

	dbus_connection_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ProxyRemoved",
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn,
			dbus_message_new_method_return(msg));
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
	if ((dev_id < 0) || (hci_devba(dev_id, &src) < 0))
		return err_failed(conn, msg, "Adapter not available");

	pc = g_new0(struct pending_connect, 1);
	bacpy(&pc->src, &src);
	pc->conn = dbus_connection_ref(conn);
	pc->msg = dbus_message_ref(msg);
	pc->bda = g_strdup(bda);
	pc->id = -1;
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
		goto done;
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
		goto done;
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
done:
	name_listener_add(conn, dbus_message_get_sender(msg),
			(name_cb_t) transaction_owner_exited, NULL);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusError derr;
	const char *name;
	int err, id;

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

	err = port_remove_listener(dbus_message_get_sender(msg), name);
	if (err < 0)
		return err_does_not_exist(conn, msg, "Invalid RFCOMM node");

	send_message_and_unref(conn,
			dbus_message_new_method_return(msg));

	dbus_connection_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceDisconnected" ,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID);

	return DBUS_HANDLER_RESULT_HANDLED;
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
	char **dev;
	int i;

	if (pending_connects) {
		g_slist_foreach(pending_connects,
				(GFunc) pending_connect_free, NULL);
		g_slist_free(pending_connects);
		pending_connects = NULL;
	}

	if (proxies_paths) {
		g_slist_foreach(proxies_paths,
				(GFunc) g_free, NULL);
		g_slist_free(proxies_paths);
		proxies_paths = NULL;
	}

	if (ports_paths) {
		g_slist_foreach(ports_paths,
				(GFunc) g_free, NULL);
		g_slist_free(ports_paths);
		ports_paths = NULL;
	}

	/* Unregister all paths in serial hierarchy */
	if (!dbus_connection_list_registered(conn, SERIAL_MANAGER_PATH, &dev))
		return;

	for (i = 0; dev[i]; i++) {
		char dev_path[MAX_PATH_LENGTH];

		snprintf(dev_path, sizeof(dev_path), "%s/%s", SERIAL_MANAGER_PATH,
				dev[i]);

		dbus_connection_destroy_object_path(conn, dev_path);
	}

	dbus_free_string_array(dev);
}

static DBusMethodVTable manager_methods[] = {
	{ "CreatePort",			create_port,		"ss",	"s"	},
	{ "ListPorts",			list_ports,		"",	"as"	},
	{ "RemovePort",			remove_port,		"s",	""	},
	{ "CreateProxy",		create_proxy,		"ss",	"s"	},
	{ "ListProxies",		list_proxies,		"",	"as"	},
	{ "RemoveProxy",		remove_proxy,		"s",	""	},
	{ "ConnectService",		connect_service,	"ss",	"s"	},
	{ "DisconnectService",		disconnect_service,	"s",	""	},
	{ "CancelConnectService",	cancel_connect_service,	"ss",	""	},
	{ NULL, NULL, NULL, NULL },
};

static DBusSignalVTable manager_signals[] = {
	{ "PortCreated",		"s"	},
	{ "PortRemoved",		"s"	},
	{ "ProxyCreated",		"s"	},
	{ "ProxyRemoved",		"s"	},
	{ "ServiceConnected",		"s"	},
	{ "ServiceDisconnected",	"s"	},
	{ NULL, NULL }
};

static void parse_port(char *key, char *value, void *data)
{
	char path[MAX_PATH_LENGTH], port_name[16], dst_addr[18];
	char *src_addr = data;
	bdaddr_t dst, src;
	int ch, id;

	memset(dst_addr, 0, sizeof(dst_addr));
	if (sscanf(key,"%17s#%d", dst_addr, &id) != 2)
		return;

	if (sscanf(value,"%d:", &ch) != 1)
		return;

	str2ba(dst_addr, &dst);
	str2ba(src_addr, &src);

	if (rfcomm_bind(&src, &dst, id, ch) < 0)
		return;

	snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", id);

	if (port_register(connection, id, &dst, port_name, path) < 0) {
		rfcomm_release(id);
		return;
	}

	ports_paths = g_slist_append(ports_paths, g_strdup(path));
}

static void parse_proxy(char *key, char *value, void *data)
{
	char path[MAX_PATH_LENGTH], uuid_str[MAX_LEN_UUID_STR], tmp[3], *pvalue;
	char *src_addr = data;
	struct termios ti;
	int ch, opts, pos = 0;
	bdaddr_t src;
	uuid_t uuid;
	uint8_t *pti;

	memset(uuid_str, 0, sizeof(uuid_str));
	if (sscanf(value,"%s %d 0x%04X %n", uuid_str, &ch, &opts, &pos) != 3)
		return;

	/* UUID format valid? */
	if (str2uuid(&uuid, uuid_str) < 0)
		return;

	/* Extracting name */
	value += pos;
	pvalue = strchr(value, ':');
	if (!pvalue)
		return;

	/* FIXME: currently name is not used */
	*pvalue = '\0';

	/* Extracting termios */
	pvalue++;
	if (strlen(pvalue) != (2 * sizeof(ti)))
		return;

	memset(&ti, 0, sizeof(ti));
	memset(tmp, 0, sizeof(tmp));

	/* Converting to termios struct */
	pti = (uint8_t *) &ti;
	for (pos = 0; pos < sizeof(ti); pos++, pvalue += 2, pti++) {
		memcpy(tmp, pvalue, 2);
		*pti = (uint8_t) strtol(tmp, NULL, 16);
	}

	pos = 0;
	sscanf(key, "/dev/%n", &pos);
	if (!pos)
		return;

	snprintf(path, MAX_PATH_LENGTH - 1,
			"/org/bluez/serial/proxy%s", key + pos);

	str2ba(src_addr, &src);
	proxy_register(connection, &src, path, &uuid, key, &ti);

	proxies_paths = g_slist_append(proxies_paths, g_strdup(path));
}

static void register_stored(void)
{
	char filename[PATH_MAX + 1];
	struct dirent *de;
	DIR *dir;

	snprintf(filename, PATH_MAX, "%s", STORAGEDIR);

	dir = opendir(filename);
	if (!dir)
		return;

	while ((de = readdir(dir)) != NULL) {
		if (!isdigit(de->d_name[0]))
			continue;

		snprintf(filename, PATH_MAX, "%s/%s/serial", STORAGEDIR, de->d_name);
		textfile_foreach(filename, parse_port, de->d_name);

		snprintf(filename, PATH_MAX, "%s/%s/proxy", STORAGEDIR, de->d_name);
		textfile_foreach(filename, parse_proxy, de->d_name);
	}

	closedir(dir);
}

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

	register_stored();

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
