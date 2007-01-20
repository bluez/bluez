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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
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
#include "glib-ectomy.h"

#define BUF_SIZE 1024

#define RING_INTERVAL 3000

#define HEADSET_PATH "/org/bluez/headset"
static const char *hs_path = HEADSET_PATH;

struct pending_connect {
	bdaddr_t bda;
	int ch;
	DBusConnection *conn;
	DBusMessage *msg;
	GIOChannel *io;
};

struct headset {
	char address[18];

	GIOChannel *rfcomm;
	GIOChannel *sco;

	GIOChannel *audio_input;
	int out;

	guint ring_timer;

	char buf[BUF_SIZE];
	int data_start;
	int data_length;
};

static struct pending_connect *connect_in_progress = NULL;

static uint8_t config_channel = 12;

static uint32_t record_id = 0;

static char *on_init_bda = NULL;

static DBusConnection *connection = NULL;

static GMainLoop *main_loop = NULL;

static struct headset *hs = NULL;

static GIOChannel *server_sk = NULL;

static char *audio_input = NULL;
static char *audio_output = NULL;

static DBusHandlerResult hs_connect(DBusConnection *conn, DBusMessage *msg,
					const char *address);
static DBusHandlerResult hs_disconnect(DBusConnection *conn, DBusMessage *msg);
static DBusHandlerResult hs_ring(DBusConnection *conn, DBusMessage *msg);
static DBusHandlerResult hs_cancel_ringing(DBusConnection *conn, DBusMessage *msg);
static DBusHandlerResult hs_play(DBusConnection *conn, DBusMessage *msg);
static DBusHandlerResult hs_stop(DBusConnection *conn, DBusMessage *msg);

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

	connect_in_progress = NULL;
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

static void send_gain_setting(const char *buf)
{
	const char *name;
	DBusMessage *signal;
	dbus_uint16_t gain;

	if (strlen(buf) < 6) {
		error("Too short string for Gain setting");
		return;
	}

	switch (buf[3]) {
	case 'S':
		name = "SpeakerGainChanged";
		break;
	case 'M':
		name = "MicrophoneGainChanged";
		break;
	default:
		error("Unknown gain setting");
		return;
	}

	signal = dbus_message_new_signal(HEADSET_PATH, "org.bluez.Headset", name);
	if (!signal) {
		error("Unable to allocate new GainChanged signal");
		return;
	}

	gain = (dbus_uint16_t) strtol(&buf[5], NULL, 10);

	dbus_message_append_args(signal, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static void send_simple_signal(const char *name)
{
	DBusMessage *signal;

	signal = dbus_message_new_signal(HEADSET_PATH, "org.bluez.Headset", name);
	if (!signal) {
		error("Unable to allocate new AnswerRequested signal");
		return;
	}

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static void parse_headset_event(const char *buf, char *rsp, int rsp_len)
{
	printf("Received: %s\n", buf);

	/* Return an error if this is not a proper AT command */
	if (strncmp(buf, "AT", 2)) {
		snprintf(rsp, rsp_len, "\r\nERROR\r\n");
		return;
	}

	buf += 2;

	if (!strncmp(buf, "+CKPD", 5))
		send_simple_signal("AnswerRequested");
	else if (!strncmp(buf, "+VG", 3))
		send_gain_setting(buf);

	snprintf(rsp, rsp_len, "\r\nOK\r\n");
}

static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond, gpointer user_data)
{
	int sk, ret, free_space;
	unsigned char buf[BUF_SIZE];
	char *cr;

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	sk = g_io_channel_unix_get_fd(chan);

	ret = read(sk, buf, sizeof(buf) - 1);
	if (ret <= 0)
		goto failed;

	free_space = sizeof(hs->buf) - hs->data_start - hs->data_length - 1;

	if (free_space < ret) {
		/* Very likely that the HS is sending us garbage so
		 * just ignore the data and disconnect */
		error("Too much data to fit incomming buffer");
		goto failed;
	}

	memcpy(&hs->buf[hs->data_start], buf, ret);
	hs->data_length += ret;

	/* Make sure the data is null terminated so we can use string
	 * functions */
	hs->buf[hs->data_start + hs->data_length] = '\0';

	cr = strchr(&hs->buf[hs->data_start], '\r');
	if (cr) {
		char rsp[BUF_SIZE];
		int len, written;
		off_t cmd_len;

		cmd_len	= 1 + (off_t) cr - (off_t) &hs->buf[hs->data_start];
		*cr = '\0';

		memset(rsp, 0, sizeof(rsp));

		parse_headset_event(&hs->buf[hs->data_start],
				rsp, sizeof(rsp));

		len = strlen(rsp);
		written = 0;

		while (written < len) {
			int ret;

			ret = write(sk, &rsp[written], len - written);
			if (ret < 0) {
				error("write: %s (%d)", strerror(errno), errno);
				break;
			}

			written += ret;
		}

		hs->data_start += cmd_len;
		hs->data_length -= cmd_len;

		if (!hs->data_length)
			hs->data_start = 0;
	}

	if (hs->ring_timer) {
		g_timeout_remove(hs->ring_timer);
		hs->ring_timer = 0;
	}

	return TRUE;

failed:
	info("Disconnected from %s", hs->address);
	send_simple_signal("Disconnected");
	if (hs->sco)
		g_io_channel_close(hs->sco);
	if (hs->out >= 0)
		close(hs->out);
	g_io_channel_close(chan);
	free(hs);
	hs = NULL;
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

	if (hs || connect_in_progress) {
		debug("Refusing new connection since one already exists");
		close(cli_sk);
		return TRUE;
	}

	hs = malloc(sizeof(struct headset));
	if (!hs) {
		error("Allocating new hs connection struct failed!");
		close(cli_sk);
		return TRUE;
	}

	memset(hs, 0, sizeof(struct headset));

	hs->out = -1;

	hs->rfcomm = g_io_channel_unix_new(cli_sk);
	if (!hs->rfcomm) {
		error("Allocating new GIOChannel failed!");
		close(cli_sk);
		free(hs);
		hs = NULL;
		return TRUE;
	}

	ba2str(&addr.rc_bdaddr, hs->address);

	debug("Accepted connection from %s", hs->address);

	send_simple_signal("Connected");

	g_io_add_watch(hs->rfcomm, G_IO_IN, (GIOFunc) rfcomm_io_cb,
			hs);

	return TRUE;
}

static gboolean audio_input_cb(GIOChannel *chan, GIOCondition cond, gpointer user_data)
{
	int in, out, data_size, written;
	char buf[1024];

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		hs->audio_input = NULL;
		return FALSE;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_close(hs->audio_input);
		hs->audio_input = NULL;
		if (hs->out >= 0) {
			close(hs->out);
			hs->out = -1;
		}
		return FALSE;
	}

	in = g_io_channel_unix_get_fd(chan);
	out = g_io_channel_unix_get_fd(hs->sco);

	data_size = read(in, buf, sizeof(buf));
	if (data_size < 0) {
		error("read: %s (%d)", strerror(errno), errno);
		g_io_channel_close(chan);
		hs->audio_input = NULL;
		return TRUE;
	}

	/* EOF */
	if (data_size == 0) {
		debug("Reached end of file");
		g_io_channel_close(chan);
		hs->audio_input = NULL;
		return TRUE;
	}

	written = 0;

	while (written < data_size) {
		int ret;

		ret = write(out, &buf[written], data_size - written);

		if (ret < 0) {
			error("write(%d, %p, %d): %s (%d)", out, &buf[data_size],
					data_size - written, strerror(errno), errno);
			g_io_channel_close(chan);
			hs->audio_input = NULL;
			return TRUE;
		}

		debug("wrote %d bytes to %s", ret, audio_output); 

		written += ret;
	}

	return TRUE;
}

static gboolean sco_io_cb(GIOChannel *chan, GIOCondition cond, gpointer user_data)
{
	int in, ret;
	char buf[1024];

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		if (hs) {
			if (hs->audio_input) {
				g_io_channel_close(hs->audio_input);
				hs->audio_input = NULL;
			}
			if (hs->out >= 0) {
				close(hs->out);
				hs->out = -1;
			}
		}

		return FALSE;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Audio connection got disconnected");
		g_io_channel_close(chan);
		hs->sco = NULL;
		if (hs->audio_input) {
			g_io_channel_close(hs->audio_input);
			hs->audio_input = NULL;
		}
		send_simple_signal("Stopped");
		return FALSE;
	}

	if (!audio_output) {
		debug("sco_io_cb: Unhandled IO condition");
		return TRUE;
	}

	in = g_io_channel_unix_get_fd(chan);
	if (hs->out < 0)
		hs->out = open(audio_output, O_WRONLY | O_SYNC | O_CREAT);

	if (hs->out < 0) {
		error("open(%s): %s (%d)", audio_output, strerror(errno), errno);
		g_io_channel_close(chan);
		return TRUE;
	}

	ret = read(in, buf, sizeof(buf));
	if (ret > 0)
		ret = write(hs->out, buf, ret);

	return TRUE;
}

static gboolean sco_connect_cb(GIOChannel *chan, GIOCondition cond,
				struct pending_connect *c)
{
	int ret, sk, err, flags;
	DBusMessage *reply;
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

	debug("SCO socket %d opened", sk);

	if (audio_output)
		flags = G_IO_IN;
	else
		flags = 0;

	hs->sco = chan;
	g_io_add_watch(chan, flags, sco_io_cb, NULL);

	reply = dbus_message_new_method_return(c->msg);
	if (reply) {
		dbus_connection_send(c->conn, reply, NULL);
		dbus_message_unref(reply);
	}

	if (audio_input) {
		int in;
	       
		in = open(audio_input, O_RDONLY | O_NOCTTY);

		if (in < 0)
			error("open(%s): %s %d", audio_input, strerror(errno), errno);
		else {
			hs->audio_input = g_io_channel_unix_new(in);
			g_io_add_watch(hs->audio_input, G_IO_IN, audio_input_cb, NULL);
		}
		
	}

	pending_connect_free(c, FALSE);

	send_simple_signal("Playing");

	return FALSE;

failed:
	err_connect_failed(c->conn, c->msg, err);
	pending_connect_free(c, TRUE);

	return FALSE;
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

	hs = malloc(sizeof(struct headset));
	if (!hs) {
		err = ENOMEM;
		error("Allocating new hs connection struct failed!");
		goto failed;
	}

	memset(hs, 0, sizeof(struct headset));

	hs->out = -1;

	ba2str(&c->bda, hs->address);
	hs->rfcomm = chan;

	send_simple_signal("Connected");

	debug("Connected to %s", hs->address);

	g_io_add_watch(chan, G_IO_IN, (GIOFunc) rfcomm_io_cb, hs);

	if (c->msg) {
		DBusMessage *reply;

		reply = dbus_message_new_method_return(c->msg);
		if (reply) {
			dbus_connection_send(c->conn, reply, NULL);
			dbus_message_unref(reply);
		}
	}

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
				"org.bluez.Database", "AddServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	if (create_ag_record(&buf, channel) < 0) {
		error("Unable to allocate new service record");
		dbus_message_unref(msg);
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&buf.data, buf.data_size, DBUS_TYPE_INVALID);

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
				"org.bluez.Database", "RemoveServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_UINT32, &rec_id,
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

static DBusHandlerResult hs_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *interface, *member;

	interface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, interface) &&
			!strcmp("Introspect", member))
		return simple_introspect(conn, msg, data);

	if (strcmp(interface, "org.bluez.Headset") != 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "ConnectHeadset") == 0)
		return hs_connect(conn, msg, NULL);

	if (strcmp(member, "Disconnect") == 0)
		return hs_disconnect(conn, msg);

	if (strcmp(member, "IndicateCall") == 0)
		return hs_ring(conn, msg);

	if (strcmp(member, "CancelCall") == 0)
		return hs_cancel_ringing(conn, msg);

	if (strcmp(member, "Play") == 0)
		return hs_play(conn, msg);

	if (strcmp(member, "Stop") == 0)
		return hs_stop(conn, msg);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable hs_table = {
	.message_function = hs_message,
};

int headset_dbus_init(char *bda)
{
	connection = init_dbus(NULL, NULL, NULL);
	if (!connection)
		return -1;

	if (!dbus_connection_register_object_path(connection, hs_path,
						&hs_table, NULL)) {
		error("D-Bus failed to register %s path", hs_path);
		return -1;
	}

	if (config_channel)
		record_id = add_ag_record(config_channel);

	if (on_init_bda)
		hs_connect(NULL, NULL, on_init_bda);

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

	if (!hs || strcasecmp(address, hs->address) != 0)
		return err_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->sco)
		g_io_channel_close(hs->sco);
	if (hs->out >= 0) {
		close(hs->out);
		hs->out = -1;
	}
	if (hs->rfcomm)
		g_io_channel_close(hs->rfcomm);

	info("Disconnected from %s", hs->address);

	send_simple_signal("Disconnected");

	free(hs);
	hs = NULL;

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

	if (hs)
		return err_already_connected(conn, msg);

	c = malloc(sizeof(struct pending_connect));
	if (!c) {
		error("Out of memory when allocating new struct pending_connect");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}       

	connect_in_progress = c;

	memset(c, 0, sizeof(struct pending_connect));

	str2ba(address, &c->bda);

	c->conn = dbus_connection_ref(conn);
	c->msg = dbus_message_ref(msg);

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


	if (!dbus_connection_send_with_reply(conn, msg, &pending, -1)) {
		error("Sending GetRemoteServiceHandles failed");
		pending_connect_free(c, TRUE);
		dbus_message_unref(msg);
		return err_connect_failed(connection, msg, EIO);
	}

	dbus_pending_call_set_notify(pending, handles_reply, c, NULL);
	dbus_message_unref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;;
}

static int send_ring(GIOChannel *io)
{
	const char *ring_str = "\r\nRING\r\n";
	int sk, written, len;

	sk = g_io_channel_unix_get_fd(hs->rfcomm);

	len = strlen(ring_str);
	written = 0;

	while (written < len) {
		int ret;

		ret = write(sk, ring_str + written, len - written);

		if (ret < 0)
			return ret;

		written += ret;
	}

	return 0;
}

static gboolean ring_timer(gpointer user_data)
{
	if (send_ring(hs->rfcomm) < 0)
		error("Sending RING failed");

	return TRUE;
}

static DBusHandlerResult hs_ring(DBusConnection *conn, DBusMessage *msg)
{
	DBusMessage *reply;

	if (!hs)
		return err_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->ring_timer) {
		debug("Got Ring method call while ringing already in progress");
		goto done;
	}

	if (send_ring(hs->rfcomm) < 0) {
		dbus_message_unref(reply);
		return err_failed(conn, msg);
	}

	hs->ring_timer = g_timeout_add(RING_INTERVAL, ring_timer, NULL);

done:
	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_cancel_ringing(DBusConnection *conn, DBusMessage *msg)
{
	DBusMessage *reply;

	if (!hs)
		return err_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (!hs->ring_timer) {
		debug("Got CancelRinging method call but ringing is not in progress");
		goto done;
	}

	g_timeout_remove(hs->ring_timer);
	hs->ring_timer = 0;

done:
	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_play(DBusConnection *conn, DBusMessage *msg)
{
	struct sockaddr_sco addr;
	struct pending_connect *c;
	int sk, err;

	if (!hs)
		return err_not_connected(conn, msg);

	if (hs->sco)
		return err_already_connected(conn, msg);

	c = malloc(sizeof(struct pending_connect));
	if (!c)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	memset(c, 0, sizeof(struct pending_connect));

	c->conn = dbus_connection_ref(conn);
	c->msg = dbus_message_ref(msg);

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		err_connect_failed(conn, msg, err);
		goto failed;
	}

	c->io = g_io_channel_unix_new(sk);
	if (!c->io) {
		close(sk);
		pending_connect_free(c, TRUE);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	g_io_channel_set_close_on_unref(c->io, TRUE);

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, BDADDR_ANY);
	if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		err_connect_failed(conn, msg, err);
		goto failed;
	}

	if (set_nonblocking(sk, &err) < 0) {
		err_connect_failed(conn, msg, err);
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	str2ba(hs->address, &addr.sco_bdaddr);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect: %s (%d)", strerror(errno), errno);
			goto failed;
		}

		debug("Connect in progress");

		g_io_add_watch(c->io, G_IO_OUT, (GIOFunc) sco_connect_cb, c);
	} else {
		debug("Connect succeeded with first try");
		sco_connect_cb(c->io, G_IO_OUT, c);
	}

	return 0;

failed:
	if (c)
		pending_connect_free(c, TRUE);
	close(sk);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_stop(DBusConnection *conn, DBusMessage *msg)
{
	DBusMessage *reply;

	if (!hs || !hs->sco)
		return err_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	g_io_channel_close(hs->sco);
	hs->sco = NULL;

	if (hs->out >= 0) {
		close(hs->out);
		hs->out = -1;
	}

	send_simple_signal("Stopped");

	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	int opt;

	while ((opt = getopt(argc, argv, "c:o:i:")) != EOF) {
		switch (opt) {
		case 'c':
			config_channel = strtol(optarg, NULL, 0);
			break;

		case 'i':
			audio_input = optarg;
			break;

		case 'o':
			audio_output = optarg;
			break;

		default:
			printf("Usage: %s -c local_channel [-n] [-o output] [-i input] [bdaddr]\n", argv[0]);
			exit(1);
		}
	}

	if (argv[optind])
		on_init_bda = argv[optind];

	start_logging("headset", "Bluetooth Headset daemon");

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

	create_server_socket();

	g_main_run(main_loop);

	return 0;
}
