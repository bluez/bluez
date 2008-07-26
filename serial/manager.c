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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>
#include <gdbus.h>

#include "../hcid/dbus-common.h"

#include "logging.h"
#include "textfile.h"

#include "error.h"
#include "port.h"
#include "storage.h"
#include "manager.h"
#include "sdpd.h"
#include "glib-helper.h"

#define SERIAL_PROXY_INTERFACE		"org.bluez.serial.Proxy"
#define BUF_SIZE			1024

/* Waiting for udev to create the device node */
#define MAX_OPEN_TRIES		5
#define OPEN_WAIT		300	/* ms */

struct pending_connect {
	DBusConnection	*conn;
	DBusMessage	*msg;
	char		*adapter;	/* Adapter address */
	char		*address;	/* Destination address  */
	char		*pattern;	/* Connection request pattern */
	uint8_t		channel;
	char		*dev;		/* tty device name */
	int		id;		/* RFCOMM device id */
	int		ntries;		/* Open attempts */
	int		canceled;	/* Operation canceled */
	guint		listener_id;
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

typedef enum {
	TTY_PROXY,
	UNIX_SOCKET_PROXY,
	TCP_SOCKET_PROXY,
	UNKNOWN_PROXY_TYPE = 0xFF
} proxy_type_t;

struct proxy {
	bdaddr_t	src;
	bdaddr_t	dst;
	char		*uuid128;	/* UUID 128 */
	char		*address;	/* TTY or Unix socket name */
	char		*path;		/* D-Bus path */
	short int	port;		/* TCP port */
	proxy_type_t	type;		/* TTY or Unix socket */
	struct termios  sys_ti;		/* Default TTY setting */
	struct termios  proxy_ti;	/* Proxy TTY settings */
	uint8_t		channel;	/* RFCOMM channel */
	uint32_t	record_id;	/* Service record id */
	GIOChannel	*io;		/* Server listen */
	guint		rfcomm_watch;	/* RFCOMM watch: Remote */
	guint		local_watch;	/* Local watch: TTY or Unix socket */
};

static DBusConnection *connection = NULL;
static GSList *pending_connects = NULL;
static GSList *ports_paths = NULL;
static GSList *proxies = NULL;
static int rfcomm_ctl = -1;
static int sk_counter = 0;

static void disable_proxy(struct proxy *prx)
{
	if (prx->rfcomm_watch) {
		g_source_remove(prx->rfcomm_watch);
		prx->rfcomm_watch = 0;
	}

	if (prx->local_watch) {
		g_source_remove(prx->local_watch);
		prx->local_watch = 0;
	}

	remove_record_from_server(prx->record_id);
	prx->record_id = 0;

	g_io_channel_unref(prx->io);
	prx->io = NULL;
}

static void proxy_free(struct proxy *prx)
{
	g_free(prx->address);
	g_free(prx->uuid128);
	g_free(prx);
}

static void pending_connect_free(struct pending_connect *pc)
{
	if (pc->conn)
		dbus_connection_unref(pc->conn);
	if (pc->msg)
		dbus_message_unref(pc->msg);
	if (pc->adapter)
		g_free(pc->adapter);
	if (pc->address)
		g_free(pc->address);
	if (pc->pattern)
		g_free(pc->pattern);
	if (pc->dev)
		g_free(pc->dev);
	g_free(pc);
}

static struct pending_connect *find_pending_connect_by_pattern(const char *bda,
							const char *pattern)
{
	GSList *l;

	/* Pattern can be friendly name, uuid128, record handle or channel */
	for (l = pending_connects; l != NULL; l = l->next) {
		struct pending_connect *pending = l->data;
		if (!strcasecmp(pending->address, bda) &&
				!strcasecmp(pending->pattern, pattern))
			return pending;
	}

	return NULL;
}

static void transaction_owner_exited(void *data)
{
	struct pending_connect *pc = data;

	debug("transaction owner exited");

	if (pc->id >= 0)
		rfcomm_release(pc->id);

	pending_connects = g_slist_remove(pending_connects, pc);

	pending_connect_free(pc);
}

static void pending_connect_remove(struct pending_connect *pc)
{
	g_dbus_remove_watch(pc->conn, pc->listener_id);
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
		error_connection_attempt_failed(pc->conn, pc->msg, err);
		return;
	}

	if (pc->canceled) {
		rfcomm_release(pc->id);
		error_canceled(pc->conn, pc->msg, "Connection canceled");
		return;
	}

	/* Reply to the requestor */
	reply = dbus_message_new_method_return(pc->msg);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pc->dev,
			DBUS_TYPE_INVALID);
	dbus_connection_send(pc->conn, reply, NULL);
	dbus_message_unref(reply);

	/* Send the D-Bus signal */
	g_dbus_emit_signal(pc->conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceConnected" ,
			DBUS_TYPE_STRING, &pc->dev,
			DBUS_TYPE_INVALID);

	str2ba(pc->address, &dst);

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

static void rfcomm_connect_cb(GIOChannel *chan, int err_cb, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer user_data)
{
	struct pending_connect *pc = user_data;
	struct rfcomm_dev_req req;
	int sk, err, fd;

	/* Owner exited? */
	if (!g_slist_find(pending_connects, pc))
		return;

	if (pc->canceled) {
		error_canceled(pc->conn, pc->msg, "Connection canceled");
		goto fail;
	}

	if (err_cb < 0) {
		error("connect(): %s (%d)", strerror(-err_cb), -err_cb);
		error_connection_attempt_failed(pc->conn, pc->msg, -err_cb);
		goto fail;
	}

	debug("rfcomm_connect_cb: connected");

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = (1 << RFCOMM_REUSE_DLC);
	str2ba(pc->adapter, &req.src);
	str2ba(pc->address, &req.dst);
	req.channel = pc->channel;

	sk = g_io_channel_unix_get_fd(chan);
	pc->id = ioctl(sk, RFCOMMCREATEDEV, &req);
	g_io_channel_close(chan);
	g_io_channel_unref(chan);
	if (pc->id < 0) {
		err = errno;
		error("ioctl(RFCOMMCREATEDEV): %s (%d)", strerror(err), err);
		error_connection_attempt_failed(pc->conn, pc->msg, err);
		goto fail;
	}
	pc->dev	= g_new0(char, 16);
	snprintf(pc->dev, 16, "/dev/rfcomm%d", pc->id);

	/* Addressing connect port */
	fd = port_open(pc);
	if (fd < 0)
		/* Open in progress: Wait the callback */
		return;

	open_notify(fd, 0, pc);
fail:
	pending_connect_remove(pc);
}

static inline DBusMessage *does_not_exist(DBusMessage *msg,
					const char *description)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".DoesNotExist",
				description);
}

static inline DBusMessage *invalid_arguments(DBusMessage *msg,
					const char *description)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
				description);
}

static inline DBusMessage *failed(DBusMessage *msg, const char *description)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
				description);
}

static DBusMessage *create_channel_port(DBusConnection *conn,
				DBusMessage *msg, const char *adapter,
				const char *address, const char *name,
				long channel, void *data)
{
	char path[MAX_PATH_LENGTH], port_name[16];
	const char *ppath = path;
	DBusMessage *reply;
	int err;
	bdaddr_t src, dst;

	if (channel < 1 || channel > 30)
		return invalid_arguments(msg, "Invalid RFCOMM channel");

	str2ba(adapter, &src);
	str2ba(address, &dst);
	err = rfcomm_bind(&src, &dst, -1, channel);
	if (err < 0)
		return failed(msg, strerror(-err));

	snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", err);
	port_store(&src, &dst, err, channel, name);
	port_register(conn, err, &src, &dst, port_name, path, name);
	ports_paths = g_slist_append(ports_paths, g_strdup(path));

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);
	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	g_dbus_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "PortCreated" ,
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);

	return NULL;
}

static DBusMessage *connect_pending(DBusConnection *conn, DBusMessage *msg,
					struct pending_connect *pc)
{
	int err;
	bdaddr_t src, dst;

	if (!g_slist_find(pending_connects, pc)) {
		pending_connects = g_slist_append(pending_connects, pc);
		pc->listener_id = g_dbus_add_disconnect_watch(conn,
						dbus_message_get_sender(msg),
						transaction_owner_exited, pc,
						NULL);
	}

	str2ba(pc->adapter, &src);
	str2ba(pc->address, &dst);

	err = bt_rfcomm_connect(&src, &dst, pc->channel, rfcomm_connect_cb, pc);
	if (err < 0) {
		const char *strerr = strerror(-err);
		error("RFCOMM connect failed: %s(%d)", strerr, -err);
		pending_connects = g_slist_remove(pending_connects, pc);
		pending_connect_free(pc);
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".ConnectionAttemptFailed",
						"%s", strerror(-err));
	}

	return NULL;
}

static void record_cb(sdp_list_t *recs, int err, gpointer data)
{
	struct pending_connect *pc;
	sdp_record_t *rec = NULL;
	sdp_list_t *protos;
	int ch;
	bdaddr_t dst;

	/* Owner exited? */
	if (!g_slist_find(pending_connects, data))
		return;

	pc = data;
	if (pc->canceled) {
		error_canceled(pc->conn, pc->msg, "Connection canceled");
		goto fail;
	}

	if (err < 0) {
		error_connection_attempt_failed(pc->conn, pc->msg, -err);
		goto fail;
	}

	if (!recs || !recs->data) {
		error_not_supported(pc->conn, pc->msg);
		error("Invalid service record length");
		goto fail;
	}

	rec = recs->data;
	if (sdp_get_access_protos(rec, &protos) < 0) {
		error_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch < 1 || ch > 30) {
		error("Channel out of range: %d", ch);
		error_not_supported(pc->conn, pc->msg);
		goto fail;
	}

	str2ba(pc->address, &dst);

	if (dbus_message_has_member(pc->msg, "CreatePort")) {
		sdp_data_t *d;
		char *svcname = NULL;

		d = sdp_data_get(rec, SDP_ATTR_SVCNAME_PRIMARY);
		if (d) {
			svcname = g_new0(char, d->unitSize);
			snprintf(svcname, d->unitSize, "%.*s",
					d->unitSize, d->val.str);
		}

		create_channel_port(pc->conn, pc->msg, pc->adapter,
				pc->address, svcname, ch, data);

		if (svcname)
			g_free(svcname);
	} else {
		/* ConnectService */
		pc->channel = ch;

		connect_pending(pc->conn, pc->msg, pc);

		/* Wait the connect callback */
		goto done;
	}

fail:
	pending_connect_remove(pc);
done:
	if (recs)
		sdp_list_free(recs, (sdp_free_func_t) sdp_record_free);
}

static int pattern2uuid(const char *pattern, uuid_t *uuid)
{
	uint16_t cls;
	int i;

	/* Friendly name */
	cls = str2class(pattern);
	if (cls) {
		sdp_uuid16_create(uuid, cls);
		return 0;
	}

	/* UUID 128*/
	if (strlen(pattern) != 36)
		return -EINVAL;

	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (pattern[i] != '-')
				return -EINVAL;

		} else if (!isxdigit(pattern[i]))
			return -EINVAL;
	}

	bt_string2uuid(uuid, pattern);
	return 0;
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

static DBusMessage *search_uuid(DBusConnection *conn, DBusMessage *msg,
				const char *adapter, const char *address,
				const char *pattern, uuid_t *uuid, void *data)
{
	struct pending_connect *pc;
	int err;
	bdaddr_t src, dst;

	pc = g_new0(struct pending_connect, 1);
	pc->conn = dbus_connection_ref(conn);
	pc->msg = dbus_message_ref(msg);
	pc->adapter = g_strdup(adapter);
	pc->address = g_strdup(address);
	pc->id = -1;
	pc->pattern = g_strdup(pattern);

	str2ba(adapter, &src);
	str2ba(address, &dst);

	err = bt_search_service(&src, &dst, uuid, record_cb, pc, NULL);
	if (err < 0) {
		pending_connect_free(pc);
		return g_dbus_create_error(msg, ERROR_INTERFACE ".NotSuppported",
						"Not Supported");
	}

	pending_connects = g_slist_append(pending_connects, pc);
	pc->listener_id = g_dbus_add_disconnect_watch(conn,
					dbus_message_get_sender(msg),
					transaction_owner_exited, pc, NULL);

	return NULL;
}

static DBusMessage *create_port(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	const char *address, *pattern;
	struct pending_connect *pending;
	long val;
	uuid_t uuid;
	char adp[18];
	int dev_id;
	bdaddr_t src;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return NULL;

	dev_id = hci_get_route(NULL);
	if ((dev_id < 0) || (hci_devba(dev_id, &src) < 0))
		return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
						"Adapter not Available");

	pending = find_pending_connect_by_pattern(address, pattern);
	if (pending)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
						"Connection in Progress");

	ba2str(&src, adp);

	/* Friendly name or uuid128 */
	if (pattern2uuid(pattern, &uuid) == 0)
		return search_uuid(conn, msg, adp, address, pattern, &uuid,
				data);

	/* RFCOMM Channel */
	if (pattern2long(pattern, &val) == 0)
		return create_channel_port(conn, msg, adp, address, pattern,
				val, data);

	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArgument",
					"Invalid pattern");
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

static DBusMessage *list_ports(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	message_append_paths(reply, ports_paths);

	return reply;
}

static DBusMessage *remove_port(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct rfcomm_dev_info di;
	const char *path;
	GSList *l;
	int16_t id;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return NULL;

	if (sscanf(path, SERIAL_MANAGER_PATH"/rfcomm%hd", &id) != 1)
		return does_not_exist(msg, "Invalid RFCOMM node");

	di.id = id;
	if (ioctl(rfcomm_ctl, RFCOMMGETDEVINFO, &di) < 0)
		return does_not_exist(msg, "Invalid RFCOMM node");
	port_delete(&di.src, &di.dst, id);

	if (port_unregister(path) < 0)
		return does_not_exist(msg, "Invalid RFCOMM node");

	g_dbus_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "PortRemoved" ,
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	l = g_slist_find_custom(ports_paths, path, (GCompareFunc) strcmp);
	if (l) {
		g_free(l->data);
		ports_paths = g_slist_remove(ports_paths, l->data);
	}

	return dbus_message_new_method_return(msg);
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

static sdp_record_t *proxy_record_new(const char *uuid128, uint8_t channel)
{
	sdp_list_t *apseq, *aproto, *profiles, *proto[2], *root, *svclass_id;
	uuid_t uuid, root_uuid, l2cap, rfcomm;
	sdp_profile_desc_t profile;
	sdp_record_t *record;
	sdp_data_t *ch;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);
	sdp_list_free(root, NULL);

	bt_string2uuid(&uuid, uuid128);
	svclass_id = sdp_list_append(NULL, &uuid);
	sdp_set_service_classes(record, svclass_id);
	sdp_list_free(svclass_id, NULL);

	sdp_uuid16_create(&profile.uuid, SERIAL_PORT_PROFILE_ID);
	profile.version = 0x0100;
	profiles = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, profiles);
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
	sdp_set_access_protos(record, aproto);

	add_lang_attr(record);

	sdp_set_info_attr(record, "Port Proxy Entity",
				NULL, "Port Proxy Entity");

	sdp_data_free(ch);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto, NULL);

	return record;
}

static GIOError channel_write(GIOChannel *chan, char *buf, size_t size)
{
	GIOError err = G_IO_ERROR_NONE;
	gsize wbytes, written;

	wbytes = written = 0;
	while (wbytes < size) {
		err = g_io_channel_write(chan,
				buf + wbytes,
				size - wbytes,
				&written);

		if (err != G_IO_ERROR_NONE)
			return err;

		wbytes += written;
	}

	return err;
}

static gboolean forward_data(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	char buf[BUF_SIZE];
	GIOChannel *dest = data;
	GIOError err;
	size_t rbytes;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		/* Try forward remaining data */
		do {
			rbytes = 0;
			err = g_io_channel_read(chan, buf, sizeof(buf), &rbytes);
			if (err != G_IO_ERROR_NONE || rbytes == 0)
				break;

			err = channel_write(dest, buf, rbytes);
		} while (err == G_IO_ERROR_NONE);

		g_io_channel_close(dest);
		return FALSE;
	}

	rbytes = 0;
	err = g_io_channel_read(chan, buf, sizeof(buf), &rbytes);
	if (err != G_IO_ERROR_NONE)
		return FALSE;

	err = channel_write(dest, buf, rbytes);
	if (err != G_IO_ERROR_NONE)
		return FALSE;

	return TRUE;
}

static inline int unix_socket_connect(const char *address)
{
	struct sockaddr_un addr;
	int err, sk;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	if (strncmp("x00", address, 3) == 0) {
		/*
		 * Abstract namespace: first byte NULL, x00
		 * must be removed from the original address.
		 */
		strcpy(addr.sun_path + 1, address + 3);
	} else {
		/* Filesystem address */
		strcpy(addr.sun_path, address);
	}

	/* Unix socket */
	sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		error("Unix socket(%s) create failed: %s(%d)",
				address, strerror(err), err);
		return -err;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		error("Unix socket(%s) connect failed: %s(%d)",
				address, strerror(err), err);
		close(sk);
		errno = err;
		return -err;
	}

	return sk;
}

static int tcp_socket_connect(const char *address)
{
	struct sockaddr_in addr;
	int err, sk;
	unsigned short int port;

	memset(&addr, 0, sizeof(addr));

	if (strncmp(address, "localhost", 9) != 0) {
		error("Address should have the form localhost:port.");
		return -1;
	}
	port = atoi(strchr(address, ':') + 1);
	if (port <= 0) {
		error("Invalid port '%d'.", port);
		return -1;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(port);

	sk = socket(PF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		err = errno;
		error("TCP socket(%s) create failed %s(%d)", address,
							strerror(err), err);
		return -err;
	}
	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		error("TCP socket(%s) connect failed: %s(%d)",
						address, strerror(err), err);
		close(sk);
		errno = err;
		return -err;
	}
	return sk;
}

static inline int tty_open(const char *tty, struct termios *ti)
{
	int err, sk;

	sk = open(tty, O_RDWR | O_NOCTTY);
	if (sk < 0) {
		err = errno;
		error("Can't open TTY %s: %s(%d)", tty, strerror(err), err);
		return -err;
	}

	if (ti && tcsetattr(sk, TCSANOW, ti) < 0) {
		err = errno;
		error("Can't change serial settings: %s(%d)",
				strerror(err), err);
		close(sk);
		errno = err;
		return -err;
	}

	return sk;
}

static void connect_event_cb(GIOChannel *chan, int err, const bdaddr_t *src,
				const bdaddr_t *dst, gpointer data)
{
	struct proxy *prx = data;
	GIOChannel *io;
	int sk;

	if (err < 0) {
		error("accept: %s (%d)", strerror(-err), -err);
		return;
	}

	bacpy(&prx->dst, dst);

	switch (prx->type) {
	case UNIX_SOCKET_PROXY:
		sk = unix_socket_connect(prx->address);
		break;
	case TTY_PROXY:
		sk = tty_open(prx->address, &prx->proxy_ti);
		break;
	case TCP_SOCKET_PROXY:
		sk = tcp_socket_connect(prx->address);
		break;
	default:
		sk = -1;
	}

	if (sk < 0) {
		g_io_channel_unref(chan);
		return;
	}

	g_io_channel_set_close_on_unref(chan, TRUE);
	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	prx->rfcomm_watch = g_io_add_watch(chan,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				forward_data, io);

	prx->local_watch = g_io_add_watch(io,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				forward_data, chan);

	g_io_channel_unref(chan);
	g_io_channel_unref(io);

	return;
}

static DBusMessage *proxy_enable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx = data;
	sdp_record_t *record;

	if (prx->io)
		return failed(msg, "Already enabled");

	/* Listen */
	prx->io = bt_rfcomm_listen_allocate(&prx->src, &prx->channel, 0,
				connect_event_cb, prx);
	if (!prx->io) {
		const char *strerr = strerror(errno);
		error("RFCOMM listen socket failed: %s(%d)", strerr, errno);
		return failed(msg, strerr);
	}

	g_io_channel_set_close_on_unref(prx->io, TRUE);

	record = proxy_record_new(prx->uuid128, prx->channel);
	if (!record) {
		g_io_channel_unref(prx->io);
		return failed(msg, "Unable to allocate new service record");
	}

	if (add_record_to_server(&prx->src, record) < 0) {
		sdp_record_free(record);
		g_io_channel_unref(prx->io);
		return failed(msg, "Service registration failed");
	}

	prx->record_id = record->handle;

	return dbus_message_new_method_return(msg);
}

static DBusMessage *proxy_disable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx = data;

	if (!prx->io)
		return failed(msg, "Not enabled");

	/* Remove the watches and unregister the record */
	disable_proxy(prx);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *proxy_get_info(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx = data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	dbus_bool_t boolean;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dbus_message_iter_append_dict_entry(&dict, "uuid",
			DBUS_TYPE_STRING, &prx->uuid128);

	dbus_message_iter_append_dict_entry(&dict, "address",
			DBUS_TYPE_STRING, &prx->address);

	if (prx->channel)
		dbus_message_iter_append_dict_entry(&dict, "channel",
				DBUS_TYPE_BYTE, &prx->channel);

	boolean = (prx->io ? TRUE : FALSE);
	dbus_message_iter_append_dict_entry(&dict, "enabled",
			DBUS_TYPE_BOOLEAN, &boolean);

	boolean = (prx->rfcomm_watch ? TRUE : FALSE);
	dbus_message_iter_append_dict_entry(&dict, "connected",
			DBUS_TYPE_BOOLEAN, &boolean);

	/* If connected: append the remote address */
	if (boolean) {
		char bda[18];
		const char *pstr = bda;

		ba2str(&prx->dst, bda);
		dbus_message_iter_append_dict_entry(&dict, "address",
				DBUS_TYPE_STRING, &pstr);
	}

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static struct {
	const char	*str;
	speed_t		speed;
} supported_speed[]  = {
	{"50",		B50	},
	{"300",		B300	},
	{"600",		B600	},
	{"1200",	B1200	},
	{"1800",	B1800	},
	{"2400",	B2400	},
	{"4800",	B4800	},
	{"9600",	B9600	},
	{"19200",	B19200	},
	{"38400",	B38400	},
	{"57600",	B57600	},
	{"115200",	B115200	},
	{ NULL,		B0	}
};

static speed_t str2speed(const char *str, speed_t *speed)
{
	int i;

	for (i = 0; supported_speed[i].str; i++) {
		if (strcmp(supported_speed[i].str, str) != 0)
			continue;

		if (speed)
			*speed = supported_speed[i].speed;

		return supported_speed[i].speed;
	}

	return B0;
}

static int set_parity(const char *str, tcflag_t *ctrl)
{
	if (strcasecmp("even", str) == 0) {
		*ctrl |= PARENB;
		*ctrl &= ~PARODD;
	} else if (strcasecmp("odd", str) == 0) {
		*ctrl |= PARENB;
		*ctrl |= PARODD;
	} else if (strcasecmp("mark", str) == 0)
		*ctrl |= PARENB;
	else if ((strcasecmp("none", str) == 0) ||
			(strcasecmp("space", str) == 0))
		*ctrl &= ~PARENB;
	else
		return -1;

	return 0;
}

static int set_databits(uint8_t databits, tcflag_t *ctrl)
{
	if (databits < 5 || databits > 8)
		return -EINVAL;

	*ctrl &= ~CSIZE;
	switch (databits) {
	case 5:
		*ctrl |= CS5;
		break;
	case 6:
		*ctrl |= CS6;
		break;
	case 7:
		*ctrl |= CS7;
		break;
	case 8:
		*ctrl |= CS8;
		break;
	}

	return 0;
}

static int set_stopbits(uint8_t stopbits, tcflag_t *ctrl)
{
	/* 1.5 will not be allowed */
	switch (stopbits) {
	case 1:
		*ctrl &= ~CSTOPB;
		return 0;
	case 2:
		*ctrl |= CSTOPB;
		return 0;
	}

	return -EINVAL;
}

static DBusMessage *proxy_set_serial_params(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct proxy *prx = data;
	const char *ratestr, *paritystr;
	uint8_t databits, stopbits;
	tcflag_t ctrl;		/* Control mode flags */
	speed_t speed = B0;	/* In/Out speed */

	/* Don't allow change TTY settings if it is open */
	if (prx->local_watch)
		return failed(msg, "Not allowed");

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &ratestr,
				DBUS_TYPE_BYTE, &databits,
				DBUS_TYPE_BYTE, &stopbits,
				DBUS_TYPE_STRING, &paritystr,
				DBUS_TYPE_INVALID))
		return NULL;

	if (str2speed(ratestr, &speed)  == B0)
		return invalid_arguments(msg, "Invalid baud rate");

	ctrl = prx->proxy_ti.c_cflag;
	if (set_databits(databits, &ctrl) < 0)
		return invalid_arguments(msg, "Invalid data bits");

	if (set_stopbits(stopbits, &ctrl) < 0)
		return invalid_arguments(msg, "Invalid stop bits");

	if (set_parity(paritystr, &ctrl) < 0)
		return invalid_arguments(msg, "Invalid parity");

	prx->proxy_ti.c_cflag = ctrl;
	prx->proxy_ti.c_cflag |= (CLOCAL | CREAD);
	cfsetispeed(&prx->proxy_ti, speed);
	cfsetospeed(&prx->proxy_ti, speed);

	proxy_store(&prx->src, prx->uuid128, prx->address, NULL,
				prx->channel, 0, &prx->proxy_ti);

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable proxy_methods[] = {
	{ "Enable",			"",	"",	proxy_enable },
	{ "Disable",			"",	"",	proxy_disable },
	{ "GetInfo",			"",	"a{sv}",proxy_get_info },
	{ "SetSerialParameters",	"syys",	"",	proxy_set_serial_params },
	{ },
};

static void proxy_unregister(gpointer data)
{
	struct proxy *prx = data;
	int sk;

	info("Unregistered proxy: %s", prx->address);

	if (prx->type != TTY_PROXY)
		goto done;

	/* Restore the initial TTY configuration */
	sk =  open(prx->address, O_RDWR | O_NOCTTY);
	if (sk) {
		tcsetattr(sk, TCSAFLUSH, &prx->sys_ti);
		close(sk);
	}
done:

	proxy_free(prx);
}

static int register_proxy_object(struct proxy *prx, char *outpath, size_t size)
{
	char path[MAX_PATH_LENGTH + 1];

	snprintf(path, MAX_PATH_LENGTH, "/org/bluez/serial/proxy%d",
			sk_counter++);

	if (!g_dbus_register_interface(connection, path,
					SERIAL_PROXY_INTERFACE,
					proxy_methods, NULL, NULL,
					prx, proxy_unregister)) {
		error("D-Bus failed to register %s path", path);
		return -1;
	}

	prx->path = g_strdup(path);
	proxies = g_slist_append(proxies, prx);

	if (outpath)
		strncpy(outpath, path, size);

	info("Registered proxy:%s", path);

	return 0;
}

static int proxy_tty_register(bdaddr_t *src, const char *uuid128,
				const char *address, struct termios *ti,
				char *outpath, size_t size, gboolean save)
{
	struct termios sys_ti;
	struct proxy *prx;
	int sk, ret;

	sk = open(address, O_RDONLY | O_NOCTTY);
	if (sk < 0) {
		error("Cant open TTY: %s(%d)", strerror(errno), errno);
		return -EINVAL;
	}

	prx = g_new0(struct proxy, 1);
	prx->address = g_strdup(address);
	prx->uuid128 = g_strdup(uuid128);
	prx->type = TTY_PROXY;
	bacpy(&prx->src, src);

	/* Current TTY settings */
	memset(&sys_ti, 0, sizeof(sys_ti));
	tcgetattr(sk, &sys_ti);
	memcpy(&prx->sys_ti, &sys_ti, sizeof(sys_ti));
	close(sk);

	if (!ti) {
		/* Use current settings */
		memcpy(&prx->proxy_ti, &sys_ti, sizeof(sys_ti));
	} else {
		/* New TTY settings: user provided */
		memcpy(&prx->proxy_ti, ti, sizeof(*ti));
	}

	ret = register_proxy_object(prx, outpath, size);
	if (ret < 0)
		proxy_free(prx);

	if (save)
		proxy_store(src, uuid128, address, NULL,
			prx->channel, 0, &prx->proxy_ti);

	return ret;
}

static int proxy_socket_register(bdaddr_t *src, const char *uuid128,
				const char *address, char *outpath,
				size_t size, gboolean save)
{
	struct proxy *prx;
	int ret;

	prx = g_new0(struct proxy, 1);
	prx->address = g_strdup(address);
	prx->uuid128 = g_strdup(uuid128);
	prx->type = UNIX_SOCKET_PROXY;
	bacpy(&prx->src, src);

	ret = register_proxy_object(prx, outpath, size);
	if (ret < 0)
		proxy_free(prx);

	if (save)
		proxy_store(src, uuid128, address, NULL,
				prx->channel, 0, NULL);

	return ret;
}

static int proxy_tcp_register(bdaddr_t *src, const char *uuid128,
				const char *address, char *outpath,
				size_t size, gboolean save)
{
	struct proxy *prx;
	int ret;

	prx = g_new0(struct proxy, 1);
	prx->address = g_strdup(address);
	prx->uuid128 = g_strdup(uuid128);
	prx->type = TCP_SOCKET_PROXY;
	bacpy(&prx->src, src);

	ret = register_proxy_object(prx, outpath, size);
	if (ret < 0)
		proxy_free(prx);

	if (save)
		proxy_store(src, uuid128, address, NULL,
				prx->channel, 0, NULL);

	return ret;
}

static proxy_type_t addr2type(const char *address)
{
	struct stat st;

	if (stat(address, &st) < 0) {
		/*
		 * Unix socket: if the sun_path starts with null byte
		 * it refers to abstract namespace. 'x00' will be used
		 * to represent the null byte.
		 */
		if (strncmp("localhost:", address, 10) == 0)
			return TCP_SOCKET_PROXY;
		if (strncmp("x00", address, 3) != 0)
			return UNKNOWN_PROXY_TYPE;
		else
			return UNIX_SOCKET_PROXY;
	} else {
		/* Filesystem: char device or unix socket */
		if (S_ISCHR(st.st_mode) && strncmp("/dev/", address, 4) == 0)
			return TTY_PROXY;
		else if (S_ISSOCK(st.st_mode))
			return UNIX_SOCKET_PROXY;
		else
			return UNKNOWN_PROXY_TYPE;
	}
}

static int proxy_addrcmp(gconstpointer proxy, gconstpointer addr)
{
	const struct proxy *prx = proxy;
	const char *address = addr;

	return strcmp(prx->address, address);
}

static int proxy_pathcmp(gconstpointer proxy, gconstpointer p)
{
	const struct proxy *prx = proxy;
	const char *path = p;

	return strcmp(prx->path, path);
}

static DBusMessage *create_proxy(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	char path[MAX_PATH_LENGTH + 1];
	const char *uuid128, *address, *ppath = path;
	DBusMessage *reply;
	proxy_type_t type;
	bdaddr_t src;
	uuid_t uuid;
	int dev_id, ret;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &uuid128,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID))
		return NULL;

	if (bt_string2uuid(&uuid, uuid128) < 0)
		return invalid_arguments(msg, "Invalid UUID");

	type = addr2type(address);
	if (type == UNKNOWN_PROXY_TYPE)
		return invalid_arguments(msg, "Invalid address");

	/* Only one proxy per address(TTY or unix socket) is allowed */
	if (g_slist_find_custom(proxies, address, proxy_addrcmp))
		return g_dbus_create_error(msg, ERROR_INTERFACE ".AlreadyExist",
						"Proxy already exists");

	dev_id = hci_get_route(NULL);
	if ((dev_id < 0) || (hci_devba(dev_id, &src) < 0)) {
		error("Adapter not available");
		return failed(msg, "Adapter no available");
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	switch (type) {
	case UNIX_SOCKET_PROXY:
		ret = proxy_socket_register(&src, uuid128, address,
						path, sizeof(path), TRUE);
		break;
	case TTY_PROXY:
		ret = proxy_tty_register(&src, uuid128, address,
				NULL, path, sizeof(path), TRUE);
		break;
	case TCP_SOCKET_PROXY:
		ret = proxy_tcp_register(&src, uuid128, address,
					path, sizeof(path), TRUE);
		break;
	default:
		ret = -1;
	}
	if (ret < 0) {
		dbus_message_unref(reply);
		return failed(msg, "Create object path failed");
	}

	g_dbus_emit_signal(connection, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ProxyCreated",
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &ppath,
			DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *list_proxies(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx;
	const GSList *l;
	DBusMessage *reply;
	DBusMessageIter iter, iter_array;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &iter_array);

	for (l = proxies; l; l = l->next) {
		prx = l->data;
		dbus_message_iter_append_basic(&iter_array,
				DBUS_TYPE_STRING, &prx->path);
	}

	dbus_message_iter_close_container(&iter, &iter_array);

	return reply;
}

static DBusMessage *remove_proxy(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct proxy *prx;
	const char *path;
	GSList *l;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return NULL;

	l = g_slist_find_custom(proxies, path, proxy_pathcmp);
	if (!l)
		return does_not_exist(msg, "Invalid proxy path");

	g_dbus_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ProxyRemoved",
			DBUS_TYPE_STRING, &path,
			DBUS_TYPE_INVALID);

	prx = l->data;
	proxy_delete(&prx->src, prx->address);
	proxies = g_slist_remove(proxies, prx);

	g_dbus_unregister_interface(conn, path, SERIAL_PROXY_INTERFACE);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *connect_channel(DBusConnection *conn, DBusMessage *msg,
				const char *adapter, const char *address,
				const char *pattern, long channel, void *data)
{
	struct pending_connect *pc;

	if (channel < 1 || channel > 30)
		return invalid_arguments(msg, "Invalid RFCOMM channel");

	pc = g_new0(struct pending_connect, 1);
	pc->conn = dbus_connection_ref(conn);
	pc->msg = dbus_message_ref(msg);
	pc->adapter = g_strdup(adapter);
	pc->address = g_strdup(address);
	pc->id = -1;
	pc->pattern = g_strdup(pattern);
	pc->channel = channel;

	return connect_pending(conn, msg, pc);
}

DBusMessage *service_connect(DBusConnection *conn, DBusMessage *msg,
						const char *adapter,
						const char *address,
						const char *pattern)
{
	int dev_id;
	bdaddr_t src;
	char adp[18];
	uuid_t uuid;
	long val;

	if (!adapter)
		dev_id = hci_get_route(NULL);
	else
		dev_id = hci_devid(adapter);

	if ((dev_id < 0) || (hci_devba(dev_id, &src) < 0))
		return failed(msg, "Adapter not Available");

	ba2str(&src, adp);

	/* Friendly name or uuid128 */
	if (pattern2uuid(pattern, &uuid) == 0)
		return search_uuid(conn, msg, adp, address,
						pattern, &uuid, NULL);

	/* RFCOMM Channel */
	if (pattern2long(pattern, &val) == 0)
		return connect_channel(conn, msg, adp, address,
							pattern, val, NULL);

	return invalid_arguments(msg, "Invalid Pattern");
}

static DBusMessage *connect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *address, *pattern;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return NULL;

	return service_connect(conn, msg, NULL, address, pattern);
}

static DBusMessage *connect_service_from_adapter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *adapter, *address, *pattern;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &adapter,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return NULL;

	return service_connect(conn, msg, adapter, address, pattern);
}

static DBusMessage *disconnect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *name;
	int err, id;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID))
		return NULL;

	if (sscanf(name, "/dev/rfcomm%d", &id) != 1)
		return invalid_arguments(msg, "Invalid RFCOMM node");

	err = port_remove_listener(dbus_message_get_sender(msg), name);
	if (err < 0)
		return does_not_exist(msg, "Invalid RFCOMM node");

	g_dbus_emit_signal(conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceDisconnected" ,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *cancel_connect_service(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct pending_connect *pending;
	const char *bda, *pattern;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &bda,
				DBUS_TYPE_STRING, &pattern,
				DBUS_TYPE_INVALID))
		return NULL;

	pending = find_pending_connect_by_pattern(bda, pattern);
	if (!pending)
		return does_not_exist(msg, "No such connection request");

	pending->canceled = 1;

	return dbus_message_new_method_return(msg);
}

static void manager_unregister(void *data)
{
	if (pending_connects) {
		g_slist_foreach(pending_connects,
				(GFunc) pending_connect_free, NULL);
		g_slist_free(pending_connects);
		pending_connects = NULL;
	}

	if (proxies) {
		g_slist_foreach(proxies,
				(GFunc) proxy_unregister, NULL);
		g_slist_free(proxies);
		proxies = NULL;
	}

	if (ports_paths) {
		g_slist_foreach(ports_paths,
				(GFunc) g_free, NULL);
		g_slist_free(ports_paths);
		ports_paths = NULL;
	}
}

static GDBusMethodTable manager_methods[] = {
	{ "CreatePort",			"ss",	"s",	create_port,
							G_DBUS_METHOD_FLAG_ASYNC },
	{ "ListPorts",			"",	"as",	list_ports },
	{ "RemovePort",			"s",	"",	remove_port },
	{ "CreateProxy",		"ss",	"s",	create_proxy },
	{ "ListProxies",		"",	"as",	list_proxies },
	{ "RemoveProxy",		"s",	"",	remove_proxy },
	{ "ConnectService",		"ss",	"s",	connect_service,
							G_DBUS_METHOD_FLAG_ASYNC },
	{ "ConnectServiceFromAdapter",	"sss",	"s",	connect_service_from_adapter,
							G_DBUS_METHOD_FLAG_ASYNC },
	{ "DisconnectService",		"s",	"",	disconnect_service },
	{ "CancelConnectService",	"ss",	"",	cancel_connect_service },
	{ },
};

static GDBusSignalTable manager_signals[] = {
	{ "PortCreated",		"s"	},
	{ "PortRemoved",		"s"	},
	{ "ProxyCreated",		"s"	},
	{ "ProxyRemoved",		"s"	},
	{ "ServiceConnected",		"s"	},
	{ "ServiceDisconnected",	"s"	},
	{ }
};

static void parse_port(char *key, char *value, void *data)
{
	char path[MAX_PATH_LENGTH], port_name[16], dst_addr[18], *svc;
	char *src_addr = data;
	bdaddr_t dst, src;
	int ch, id;

	memset(dst_addr, 0, sizeof(dst_addr));
	if (sscanf(key,"%17s#%d", dst_addr, &id) != 2)
		return;

	if (sscanf(value,"%d:", &ch) != 1)
		return;

	svc = strchr(value, ':');
	if (svc && *svc)
		svc++;

	str2ba(dst_addr, &dst);
	str2ba(src_addr, &src);

	if (rfcomm_bind(&src, &dst, id, ch) < 0)
		return;

	snprintf(port_name, sizeof(port_name), "/dev/rfcomm%d", id);

	if (port_register(connection, id, &src, &dst,
				port_name, path, svc) < 0) {
		rfcomm_release(id);
		return;
	}

	ports_paths = g_slist_append(ports_paths, g_strdup(path));
}

static void parse_proxy(char *key, char *value, void *data)
{
	char uuid128[MAX_LEN_UUID_STR], tmp[3];
	char *pvalue, *src_addr = data;
	proxy_type_t type;
	int ch, opts, pos;
	bdaddr_t src;
	struct termios ti;
	uint8_t *pti;

	memset(uuid128, 0, sizeof(uuid128));
	ch = opts = pos = 0;
	if (sscanf(value,"%s %d 0x%04X %n", uuid128, &ch, &opts, &pos) != 3)
		return;

	/* Extracting name */
	value += pos;
	pvalue = strchr(value, ':');
	if (!pvalue)
		return;

	/* FIXME: currently name is not used */
	*pvalue = '\0';

	str2ba(src_addr, &src);
	type = addr2type(key);
	switch (type) {
	case TTY_PROXY:
		/* Extracting termios */
		pvalue++;
		if (!pvalue || strlen(pvalue) != (2 * sizeof(ti)))
			return;

		memset(&ti, 0, sizeof(ti));
		memset(tmp, 0, sizeof(tmp));

		/* Converting to termios struct */
		pti = (uint8_t *) &ti;
		for (pos = 0; pos < sizeof(ti); pos++, pvalue += 2, pti++) {
			memcpy(tmp, pvalue, 2);
			*pti = (uint8_t) strtol(tmp, NULL, 16);
		}

		proxy_tty_register(&src, uuid128, key, &ti, NULL, 0, FALSE);
		break;
	case UNIX_SOCKET_PROXY:
		proxy_socket_register(&src, uuid128, key, NULL, 0, FALSE);
		break;
	case TCP_SOCKET_PROXY:
		proxy_tcp_register(&src, uuid128, key, NULL, 0, FALSE);
		break;
	default:
		return;
	}
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

int serial_manager_init(DBusConnection *conn)
{

	if (rfcomm_ctl < 0) {
		rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
		if (rfcomm_ctl < 0)
			return -errno;
	}

	if (!g_dbus_register_interface(conn, SERIAL_MANAGER_PATH,
					SERIAL_MANAGER_INTERFACE,
					manager_methods, manager_signals, NULL,
					NULL, manager_unregister)) {
		error("Failed to register %s interface to %s",
				SERIAL_MANAGER_INTERFACE, SERIAL_MANAGER_PATH);
		return -1;
	}

	connection = dbus_connection_ref(conn);

	info("Registered manager path:%s", SERIAL_MANAGER_PATH);

	register_stored();

	return 0;
}

void serial_manager_exit(void)
{
	g_dbus_unregister_interface(connection, SERIAL_MANAGER_PATH,
						SERIAL_MANAGER_INTERFACE);

	dbus_connection_unref(connection);
	connection = NULL;

	port_release_all();

	if (rfcomm_ctl >= 0)
		close(rfcomm_ctl);
}
