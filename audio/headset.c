/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2005-2006  Marcel Holtmann <marcel@holtmann.org>
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
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "logging.h"
#include "glib-ectomy.c"

#define HEADSET_PATH "/org/bluez/headset"
static const char *hs_path = HEADSET_PATH;

struct pending_connect {
	bdaddr_t bda;
	int ch;
	DBusConnection *conn;
	DBusMessage *msg;
	GIOChannel *io;
};

struct hs_connection {
	char address[18];
	GIOChannel *rfcomm;
	GIOChannel *sco;
};

static gboolean connect_in_progress = FALSE;

static uint8_t config_channel = 0;

static uint32_t record_id = 0;

static char *on_init_bda = NULL;

static int started = 0;

static DBusConnection *connection = NULL;

static GMainLoop *main_loop = NULL;

static struct hs_connection *connected_hs = NULL;

static GIOChannel *server_sk = NULL;

static DBusHandlerResult hs_connect(DBusConnection *conn, DBusMessage *msg,
					const char *address);
static DBusHandlerResult hs_disconnect(DBusConnection *conn, DBusMessage *msg);
static DBusHandlerResult hs_ring(DBusConnection *conn, DBusMessage *msg);

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

static void pending_connect_free(struct pending_connect *c, gboolean unref_io)
{
	if (unref_io && c->io)
		g_io_channel_unref(c->io);
	if (c->msg)
		dbus_message_unref(c->msg);
	if (c->conn)
		dbus_connection_unref(c->conn);
	free(c);

	connect_in_progress = FALSE;
}

static DBusHandlerResult error_reply(DBusConnection *conn, DBusMessage *msg,
					const char *name, const char *descr)
{
	DBusMessage *derr;

	if (!conn)
		return DBUS_HANDLER_RESULT_HANDLED;

	derr = dbus_message_new_error(msg, name, descr);
	if (derr) {
		dbus_connection_send(conn, derr, NULL);
		return DBUS_HANDLER_RESULT_HANDLED;
	} else {
	       	error("Unable to allocate new error return");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}
}

static DBusHandlerResult err_invalid_args(DBusConnection *conn, DBusMessage *msg,
						const char *descr)
{
	return error_reply(conn, msg, "org.bluez.Error.InvalidArguments",
			descr ? descr : "Invalid arguments in method call");
}

static DBusHandlerResult err_already_connected(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, "org.bluez.Error.AlreadyConnected",
				"Already connected to a device");
}

static DBusHandlerResult err_not_connected(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, "org.bluez.Error.NotConnected",
				"Not connected to any device");
}

static DBusHandlerResult err_not_supported(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, "org.bluez.Error.NotSupported",
			"The service is not supported by the remote device");
}

static DBusHandlerResult err_connect_failed(DBusConnection *conn, DBusMessage *msg, int err)
{
	return error_reply(conn, msg, "org.bluez.Error.ConnectFailed", strerror(err));
}

static DBusHandlerResult err_failed(DBusConnection *conn, DBusMessage *msg)
{
	return error_reply(conn, msg, "org.bluez.Error.Failed", "Failed");
}

static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond, struct hs_connection *hs)
{
	int sk, ret;
	unsigned char buf[1024];

	debug("rfcomm_io_cb");

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	sk = g_io_channel_unix_get_fd(chan);

	ret = read(sk, buf, sizeof(buf) - 1);
	if (ret > 0) {
		buf[ret] = '\0';
		printf("%s\n", buf);
	}

	return TRUE;

failed:
	info("Disconnected from %s", hs->address);
	if (hs->sco)
		g_io_channel_close(hs->sco);
	g_io_channel_close(chan);
	free(hs);
	connected_hs = NULL;
	return FALSE;
}

static gboolean server_io_cb(GIOChannel *chan, GIOCondition cond, void *data)
{
	int srv_sk, cli_sk;
	struct sockaddr_rc addr;
	socklen_t size;

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on rfcomm server socket");
		g_io_channel_close(chan);
		server_sk = NULL;
		return TRUE;
	}

	srv_sk = g_io_channel_unix_get_fd(chan);

	size = sizeof(struct sockaddr_rc);
	cli_sk = accept(srv_sk, (struct sockaddr *) &addr, &size);
	if (cli_sk < 0) {
		error("accept: %s (%d)", strerror(errno), errno);
		return TRUE;
	}

	if (connected_hs || connect_in_progress) {
		debug("Refusing new connection since one already exists");
		close(cli_sk);
		return TRUE;
	}

	connected_hs = malloc(sizeof(struct hs_connection));
	if (!connected_hs) {
		error("Allocating new hs connection struct failed!");
		close(cli_sk);
		return TRUE;
	}

	memset(connected_hs, 0, sizeof(struct hs_connection));

	connected_hs->rfcomm = g_io_channel_unix_new(cli_sk);
	if (!connected_hs->rfcomm) {
		error("Allocating new GIOChannel failed!");
		close(cli_sk);
		free(connected_hs);
		connected_hs = NULL;
		return TRUE;
	}

	ba2str(&addr.rc_bdaddr, connected_hs->address);

	debug("rfcomm_connect_cb: connected to %s", connected_hs->address);

	g_io_add_watch(connected_hs->rfcomm, G_IO_IN, (GIOFunc) rfcomm_io_cb,
			connected_hs);

	return TRUE;
}


static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond, struct pending_connect *c)
{
	int sk, ret, err;
	socklen_t len;

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (ret != 0) {
		err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	connected_hs = malloc(sizeof(struct hs_connection));
	if (!connected_hs) {
		err = ENOMEM;
		error("Allocating new hs connection struct failed!");
		goto failed;
	}

	memset(connected_hs, 0, sizeof(struct hs_connection));

	ba2str(&c->bda, connected_hs->address);
	connected_hs->rfcomm = chan;

	debug("rfcomm_connect_cb: connected to %s", connected_hs->address);

	g_io_add_watch(chan, G_IO_IN, (GIOFunc) rfcomm_io_cb, connected_hs);

	pending_connect_free(c, FALSE);

	return FALSE;

failed:
	err_connect_failed(c->conn, c->msg, err);
	pending_connect_free(c, TRUE);

	return FALSE;
}

static int rfcomm_connect(struct pending_connect *c, int *err)
{
	struct sockaddr_rc addr;
	char address[18];
	int sk;

	ba2str(&c->bda, address);

	debug("Connecting to %s channel %d", address, c->ch);

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		if (err)
			*err = errno;
		error("socket: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = 0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (err)
			*err = errno;
		error("bind: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if (set_nonblocking(sk, err) < 0)
		goto failed;

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &c->bda);
	addr.rc_channel = c->ch;

	c->io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(c->io, TRUE);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			if (err)
				*err = errno;
			error("connect() failed: %s (%d)", strerror(errno), errno);
			goto failed;
		}

		debug("Connect in progress");

		g_io_add_watch(c->io, G_IO_OUT, (GIOFunc) rfcomm_connect_cb, c);
	} else {
		debug("Connect succeeded with first try");
		rfcomm_connect_cb(c->io, G_IO_OUT, c);
	}

	return 0;

failed:
	if (sk >= 0)
		close(sk);
	return -1;
}

static void sig_term(int sig)
{
	g_main_quit(main_loop);
}

static int server_socket(uint8_t *channel)
{
	int sock;
	struct sockaddr_rc addr;
	socklen_t sa_len;

	sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sock < 0) {
		error("server socket: %s (%d)", strerror(errno), errno);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = 0;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("server bind: %s", strerror(errno), errno);
		close(sock);
		return -1;
	}

	if (listen(sock, 1) < 0) {
		error("server listen: %s", strerror(errno), errno);
		close(sock);
		return -1;
	}

	sa_len = sizeof(struct sockaddr_rc);
	getsockname(sock, (struct sockaddr *) &addr, &sa_len);
	*channel = addr.rc_channel;

	return sock;
}

static int create_ag_record(sdp_buf_t *buf, uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid, l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	sdp_data_t *channel;
	int ret;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, HEADSET_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HEADSET_PROFILE_ID);
	profile.version = 0x0100;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(&record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Headset", 0, 0);

	if (sdp_gen_record_pdu(&record, buf) < 0)
		ret = -1;
	else
		ret = 0;

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);
	sdp_list_free(record.attrlist, (sdp_free_func_t) sdp_data_free);
	sdp_list_free(record.pattern, free);

	return ret;
}

static uint32_t add_ag_record(uint8_t channel)
{
	DBusMessage *msg, *reply;
	DBusError derr;
	dbus_uint32_t rec_id;
	sdp_buf_t buf;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
					"org.bluez.Manager", "AddServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	if (create_ag_record(&buf, channel) < 0) {
		error("Unable to allocate new service record");
		dbus_message_unref(msg);
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &hs_path,
					DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &buf.data, buf.data_size,
					DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &derr);

	free(buf.data);
	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) || dbus_set_error_from_message(&derr, reply)) {
		error("Adding service record failed: %s", derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_get_args(reply, &derr, DBUS_TYPE_UINT32, &rec_id,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error("Invalid arguments to AddServiceRecord reply: %s", derr.message);
		dbus_message_unref(reply);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	debug("add_ag_record: got record id 0x%x", rec_id);

	return rec_id;
}

static int remove_ag_record(uint32_t rec_id)
{
	DBusMessage *msg, *reply;
	DBusError derr;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
					"org.bluez.Manager", "RemoveServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &hs_path,
					DBUS_TYPE_UINT32, &rec_id,
					DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &derr);

	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr)) {
		error("Removing service record 0x%x failed: %s", rec_id, derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	return 0;
}

static void create_server_socket(void)
{
	uint8_t chan = config_channel;
	int srv_sk;

	srv_sk = server_socket(&chan);
	if (srv_sk < 0) {
		error("Unable to create server socket");
		return;
	}

	if (!record_id)
		record_id = add_ag_record(chan);

	if (!record_id) {
		error("Unable to register service record");
		close(srv_sk);
		return;
	}

	server_sk = g_io_channel_unix_new(srv_sk);
	if (!server_sk) {
		error("Unable to allocate new GIOChannel");
		remove_ag_record(record_id);
		record_id = 0;
		return;
	}

	g_io_add_watch(server_sk, G_IO_IN, (GIOFunc) server_io_cb, NULL);
}


static DBusHandlerResult start_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	info("Starting headset service");

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		error("Can't create reply message");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	create_server_socket();

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	started = 1;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult stop_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	info("Stopping headset service");

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		error("Can't create reply message");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	if (connected_hs) {
		if (connected_hs->sco)
			g_io_channel_close(connected_hs->sco);
		if (connected_hs->rfcomm)
			g_io_channel_close(connected_hs->rfcomm);
		free(connected_hs);
		connected_hs = NULL;
	}

	if (!config_channel && record_id) {
		remove_ag_record(record_id);
		record_id = 0;
	}

	if (server_sk) {
		g_io_channel_close(server_sk);
		server_sk = NULL;
	}

	started = 0;

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult release_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		error("Can't create reply message");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	info("Got Release method. Exiting.");

	raise(SIGTERM);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *interface, *member;

	interface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (strcmp(interface, "org.bluez.ServiceAgent") == 0) {
		if (strcmp(member, "Start") == 0)
			return start_message(conn, msg, data);
		if (strcmp(member, "Stop") == 0)
			return stop_message(conn, msg, data);
		if (strcmp(member, "Release") == 0)
			return release_message(conn, msg, data);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (strcmp(interface, "org.bluez.Headset") != 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "Connect") == 0)
		return hs_connect(conn, msg, NULL);

	if (strcmp(member, "Disconnect") == 0)
		return hs_disconnect(conn, msg);

	if (strcmp(member, "Ring") == 0)
		return hs_ring(conn, msg);

	/* Handle Headset interface methods here */

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable hs_table = {
	.message_function = hs_message,
};

static void register_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Registering failed: %s", derr.message);
		dbus_error_free(&derr);
		dbus_message_unref(reply);
		raise(SIGTERM);
		return;
	}

	debug("Successfully registered headset service");

	dbus_message_unref(reply);

	if (config_channel)
		record_id = add_ag_record(config_channel);

	if (on_init_bda)
		hs_connect(NULL, NULL, on_init_bda);
}

int headset_dbus_init(char *bda)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	const char *name = "Headset service";
	const char *description = "A service for headsets";

	connection = init_dbus(NULL, NULL, NULL);
	if (!connection)
		return -1;

	if (!dbus_connection_register_object_path(connection, hs_path,
						&hs_table, NULL)) {
		error("D-Bus failed to register %s path", hs_path);
		return -1;
	}

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
					"org.bluez.Manager", "RegisterService");
	if (!msg) {
		error("Can't allocate new method call");
		return -1;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &hs_path,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_STRING, &description,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending Register method call failed");
		dbus_message_unref(msg);
		return -1;
	}

	dbus_pending_call_set_notify(pending, register_reply, NULL, NULL);
	dbus_message_unref(msg);

	return 0;
}

static void record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply;
	DBusError derr;
	uint8_t *array;
	int array_len, record_len, err = EIO;
	sdp_record_t *record = NULL;
	sdp_list_t *protos;
	struct pending_connect *c = data;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceRecord failed: %s", derr.message);
		err_not_supported(c->conn, c->msg);
		dbus_error_free(&derr);
		goto failed;
	}

	dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &array, &array_len,
				DBUS_TYPE_INVALID);

	if (!array) {
		error("Unable to get handle array from reply");
		err_not_supported(c->conn, c->msg);
		goto failed;
	}

	record = sdp_extract_pdu(array, &record_len);
	if (!record) {
		error("Unable to extract service record from reply");
		err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (record_len != array_len)
		debug("warning: array len (%d) != record len (%d)",
				array_len, record_len);

	if (!sdp_get_access_protos(record, &protos)) {
		c->ch = sdp_get_proto_port(protos, RFCOMM_UUID);
		sdp_list_foreach(protos, (sdp_list_func_t)sdp_list_free, NULL);
		sdp_list_free(protos, NULL);
	}

	if (c->ch == -1) {
		error("Unable to extract RFCOMM channel from service record");
		err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (rfcomm_connect(c, &err) < 0) {
		error("Unable to connect");
		err_connect_failed(c->conn, c->msg, err);
		goto failed;
	}

	sdp_record_free(record);
	dbus_message_unref(reply);

	return;

failed:
	if (record)
		sdp_record_free(record);
	dbus_message_unref(reply);
	pending_connect_free(c, TRUE);
}

static void handles_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *msg = NULL, *reply;
	DBusPendingCall *pending;
	DBusError derr;
	struct pending_connect *c = data;
	char address[18], *addr_ptr = address;
	dbus_uint32_t *array = NULL;
	dbus_uint32_t handle;
	int array_len;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceHandles failed: %s", derr.message);
		if (dbus_error_has_name(&derr, "org.bluez.Error.ConnectFailed"))
			err_connect_failed(c->conn, c->msg, EHOSTDOWN);
		else
			err_not_supported(c->conn, c->msg);
		dbus_error_free(&derr);
		goto failed;
	}

	dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &array, &array_len,
				DBUS_TYPE_INVALID);

	if (!array) {
		error("Unable to get handle array from reply");
		err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (array_len < 1) {
		debug("No record handles found");
		err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (array_len > 1)
		debug("Multiple records found. Using the first one.");

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez/hci0",
						"org.bluez.Adapter",
						"GetRemoteServiceRecord");
	if (!msg) {
		error("Unable to allocate new method call");
		err_connect_failed(c->conn, c->msg, ENOMEM);
		goto failed;
	}

	ba2str(&c->bda, address);

	handle = array[0];

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_UINT32, &handle,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending GetRemoteServiceRecord failed");
		err_connect_failed(c->conn, c->msg, EIO);
		goto failed;
	}

	dbus_pending_call_set_notify(pending, record_reply, c, NULL);
	dbus_message_unref(msg);

	dbus_message_unref(reply);

	return;

failed:
	if (msg)
		dbus_message_unref(msg);
	dbus_message_unref(reply);
	pending_connect_free(c, TRUE);
}

static DBusHandlerResult hs_disconnect(DBusConnection *conn, DBusMessage *msg)
{
	DBusError derr;
	DBusMessage *reply;
	const char *address;

	dbus_error_init(&derr);

	dbus_message_get_args(msg, &derr,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (!connected_hs || strcasecmp(address, connected_hs->address) != 0)
		return err_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (connected_hs->sco)
		g_io_channel_close(connected_hs->sco);
	if (connected_hs->rfcomm)
		g_io_channel_close(connected_hs->rfcomm);

	free(connected_hs);
	connected_hs = NULL;

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_connect(DBusConnection *conn, DBusMessage *msg,
					const char *address)
{
	DBusPendingCall *pending;
	struct pending_connect *c;
	const char *hs_svc = "hsp";

	if (!address) {
		DBusError derr;

		dbus_error_init(&derr);

		dbus_message_get_args(msg, &derr,
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_INVALID);

		if (dbus_error_is_set(&derr)) {
			err_invalid_args(conn, msg, derr.message);
			dbus_error_free(&derr);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
	}

	if (connected_hs)
		return err_already_connected(conn, msg);

	c = malloc(sizeof(struct pending_connect));
	if (!c) {
		error("Out of memory when allocating new struct pending_connect");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}       

	connect_in_progress = TRUE;

	memset(c, 0, sizeof(struct pending_connect));

	str2ba(address, &c->bda);

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez/hci0",
						"org.bluez.Adapter",
						"GetRemoteServiceHandles");
	if (!msg) {
		pending_connect_free(c, TRUE);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &address,
					DBUS_TYPE_STRING, &hs_svc,
					DBUS_TYPE_INVALID);


	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending GetRemoteServiceHandles failed");
		pending_connect_free(c, TRUE);
		dbus_message_unref(msg);
		return err_connect_failed(connection, msg, EIO);
	}

	dbus_pending_call_set_notify(pending, handles_reply, c, NULL);
	dbus_message_unref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;;
}

static DBusHandlerResult hs_ring(DBusConnection *conn, DBusMessage *msg)
{
	DBusMessage *reply;
	const char *ring_str = "\r\nRING\r\n";
	int sk, ret;

	if (!connected_hs)
		return err_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	sk = g_io_channel_unix_get_fd(connected_hs->rfcomm);

	ret = write(sk, ring_str, strlen(ring_str));
	if (ret < strlen(ring_str)) {
		dbus_message_unref(reply);
		return err_failed(conn, msg);
	}

	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int opt, daemonize = 1;

	while ((opt = getopt(argc, argv, "nc:")) != EOF) {
		switch (opt) {
		case 'n':
			daemonize = 0;
			break;

		case 'c':
			config_channel = strtol(optarg, NULL, 0);
			break;

		default:
			printf("Usage: %s -c local_channel [-n] [bdaddr]\n", argv[0]);
			exit(1);
		}
	}

	if (!config_channel) {
		printf("You need to supply a local channel with the -c switch\n");
		exit(1);
	}

	if (argv[optind]) {
		on_init_bda = argv[optind];
		daemonize = 0;
	}

	if (daemonize && daemon(0, 0)) {
		error("Can't daemonize: %s (%d)", strerror(errno), errno);
		exit(1);
	}

	start_logging("bt.headsetd", "Bluetooth Headset daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	enable_debug();

	main_loop = g_main_new(FALSE);

	if (headset_dbus_init(NULL) < 0) {
		error("Unable to get on D-Bus");
		exit(1);
	}

	g_main_run(main_loop);

	return 0;
}
