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

struct pending_connect {
	bdaddr_t bda;
	DBusConnection *conn;
	DBusMessage *msg;
	GIOChannel *io;
};

struct hs_connection {
	char address[18];
	GIOChannel *rfcomm;
	GIOChannel *sco;
};

static char *on_init_bda = NULL;

static int started = 0;

static DBusConnection *connection = NULL;

static GMainLoop *main_loop = NULL;

static struct hs_connection *connected_hs = NULL;

static int hs_connect(const char *address);

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
}

static void connect_failed(DBusConnection *conn, DBusMessage *msg, int err)
{
	DBusMessage *derr;

	if (!conn)
		return;

	derr = dbus_message_new_error(msg, "org.bluez.Error.ConnectFailed",
					strerror(err));
	if (!derr) {
		error("Unable to allocate new error return");
		return;
	}

	dbus_connection_send(conn, derr, NULL);
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

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond, struct pending_connect *c)
{
	int sk, ret, err;
	socklen_t len;
	struct hs_connection *hs;

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

	hs = malloc(sizeof(struct hs_connection));
	if (!hs) {
		err = ENOMEM;
		error("Allocating new hs connection struct failed!");
		goto failed;
	}

	memset(hs, 0, sizeof(struct hs_connection));

	ba2str(&c->bda, hs->address);
	hs->rfcomm = chan;

	debug("rfcomm_connect_cb: connected to %s", hs->address);

	connected_hs = hs;

	g_io_add_watch(chan, G_IO_ERR | G_IO_HUP | G_IO_IN | G_IO_NVAL,
			(GIOFunc) rfcomm_io_cb, hs);

	pending_connect_free(c, FALSE);

	return FALSE;

failed:
	connect_failed(c->conn, c->msg, err);
	pending_connect_free(c, TRUE);

	return FALSE;
}

static int rfcomm_connect(DBusConnection *conn, DBusMessage *msg, bdaddr_t *src,
				const char *bda, uint8_t ch, int *err)
{
	struct pending_connect *c = NULL;
	struct sockaddr_rc addr;
	int sk;

	debug("Connecting to %s channel %d", bda, ch);

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		if (err)
			*err = errno;
		error("socket: %s (%d)", strerror(errno), errno);
		return -1;
	}

	c = malloc(sizeof(struct pending_connect));
	if (!c) {
		if (err)
			*err = ENOMEM;
		goto failed;
	}

	memset(c, 0, sizeof(struct pending_connect));

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, src);
	addr.rc_channel = 0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (err)
			*err = errno;
		error("bind: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if (set_nonblocking(sk, err) < 0)
		goto failed;

	str2ba(bda, &c->bda);

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &c->bda);
	addr.rc_channel = ch;

	if (conn && msg) {
		c->conn = dbus_connection_ref(conn);
		c->msg = dbus_message_ref(msg);
	}

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
	if (c)
		pending_connect_free(c, TRUE);
	if (sk >= 0)
		close(sk);
	return -1;
}

static void sig_term(int sig)
{
	g_main_quit(main_loop);
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
	const char *interface;
	const char *member;

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

	if (!on_init_bda)
		return;

	if (hs_connect(on_init_bda) < 0)
		exit(1);
}

int headset_dbus_init(char *bda)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	const char *name = "Headset service";
	const char *description = "A service for headsets";
	const char *hs_path = HEADSET_PATH;

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
	int array_len, record_len, ch = -1;
	sdp_record_t *record = NULL;
	sdp_list_t *protos;
	char *address = data;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceRecord failed: %s", derr.message);
		dbus_error_free(&derr);
		goto failed;
	}

	dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &array, &array_len,
				DBUS_TYPE_INVALID);

	if (!array) {
		error("Unable to get handle array from reply");
		goto failed;
	}

	record = sdp_extract_pdu(array, &record_len);
	if (!record) {
		error("Unable to extract service record from reply");
		goto failed;
	}

	if (record_len != array_len)
		debug("warning: array len (%d) != record len (%d)",
				array_len, record_len);

	if (!sdp_get_access_protos(record, &protos)) {
		ch = sdp_get_proto_port(protos, RFCOMM_UUID);
		sdp_list_foreach(protos, (sdp_list_func_t)sdp_list_free, NULL);
		sdp_list_free(protos, NULL);
	}

	if (ch == -1) {
		error("Unable to extract RFCOMM channel from service record");
		goto failed;
	}

	if (rfcomm_connect(NULL, NULL, BDADDR_ANY, address, ch, NULL) < 0) {
		error("Unable to connect to %s", address);
		goto failed;
	}

failed:
	if (record)
		sdp_record_free(record);
	dbus_message_unref(reply);
	free(data);
}

static void handles_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *msg = NULL, *reply;
	DBusPendingCall *pending;
	DBusError derr;
	char *address = data;
	dbus_uint32_t *array = NULL;
	dbus_uint32_t handle;
	int array_len;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceHandles failed: %s", derr.message);
		dbus_error_free(&derr);
		goto failed;
	}

	dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &array, &array_len,
				DBUS_TYPE_INVALID);

	if (!array) {
		error("Unable to get handle array from reply");
		goto failed;
	}

	if (array_len < 1) {
		debug("No record handles found");
		goto failed;
	}

	if (array_len > 1)
		debug("Multiple records found. Using the first one.");

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez/hci0",
						"org.bluez.Adapter",
						"GetRemoteServiceRecord");
	if (!msg) {
		error("Unable to allocate new method call");
		goto failed;
	}

	handle = array[0];

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &address,
					DBUS_TYPE_UINT32, &handle,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending GetRemoteServiceRecord failed");
		goto failed;
	}

	dbus_pending_call_set_notify(pending, record_reply, data, NULL);
	dbus_message_unref(msg);

	dbus_message_unref(reply);

	return;

failed:
	if (msg)
		dbus_message_unref(msg);
	dbus_message_unref(reply);
	free(data);
}

static int hs_connect(const char *address)
{
	DBusMessage *msg;
	DBusPendingCall *pending;
	char *data;
	const char *hs_svc = "hsp";

	data = strdup(address);
	if (!data)
		return -ENOMEM;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez/hci0",
						"org.bluez.Adapter",
						"GetRemoteServiceHandles");
	if (!msg) {
		free(data);
		return -ENOMEM;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &address,
					DBUS_TYPE_STRING, &hs_svc,
					DBUS_TYPE_INVALID);


	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending GetRemoteServiceHandles failed");
		free(data);
		dbus_message_unref(msg);
		return -1;
	}

	dbus_pending_call_set_notify(pending, handles_reply, data, NULL);
	dbus_message_unref(msg);

	return 0;
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

		default:
			printf("Usage: %s [-n] [bdaddr]\n", argv[0]);
			exit(1);
		}
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
