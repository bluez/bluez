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
#include <assert.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "logging.h"

#define BUF_SIZE 1024

#define RING_INTERVAL 3000

#define AUDIO_MANAGER_PATH "/org/bluez/audio"
#define AUDIO_HEADSET_PATH_BASE "/org/bluez/audio/headset"

struct pending_connect {
	int ch;
	DBusConnection *conn;
	DBusMessage *msg;
	GIOChannel *io;
};

typedef enum {
	HEADSET_STATE_UNAUTHORIZED,
	HEADSET_STATE_DISCONNECTED,
	HEADSET_STATE_CONNECT_IN_PROGRESS,
	HEADSET_STATE_CONNECTED,
	HEADSET_STATE_PLAY_IN_PROGRESS,
	HEADSET_STATE_PLAYING,
} headset_state_t;

struct headset {
	char object_path[128];
	bdaddr_t bda;

	GIOChannel *rfcomm;
	GIOChannel *sco;

	char *input;
	GIOChannel *audio_input;
	char *output;
	GIOChannel *audio_output;

	guint ring_timer;

	char buf[BUF_SIZE];
	int data_start;
	int data_length;

	headset_state_t state;
	struct pending_connect *pending_connect;
};

struct manager {
	GIOChannel *server_sk;
	uint32_t record_id;
	GSList *headset_list;
};

static DBusConnection *connection = NULL;
static GMainLoop *main_loop = NULL;

struct manager *audio_manager_new(DBusConnection *conn);
void audio_manager_free(struct manager *amanager);
struct headset *audio_manager_find_headset_by_bda(struct manager *amanager, const bdaddr_t *bda);
void audio_manager_add_headset(struct manager *amanager, struct headset *hs);
gboolean audio_manager_create_headset_server(struct manager *amanager, uint8_t chan);
static DBusHandlerResult am_get_default_headset(struct manager *amanager, DBusMessage *msg);
static DBusHandlerResult am_create_headset(struct manager *amanager, DBusMessage *msg);

struct headset *audio_headset_new(DBusConnection *conn, const bdaddr_t *bda);
void audio_headset_unref(struct headset *hs);
gboolean audio_headset_close_input(struct headset *hs);
gboolean audio_headset_open_input(struct headset *hs, const char *audio_input);
gboolean audio_headset_close_output(struct headset *hs);
gboolean audio_headset_open_output(struct headset *hs, const char *audio_output);
GIOError audio_headset_send_ring(struct headset *hs);

static DBusHandlerResult hs_connect(struct headset *hs, DBusMessage *msg);
static DBusHandlerResult hs_disconnect(struct headset *hs, DBusMessage *msg);
static DBusHandlerResult hs_ring(struct headset *hs, DBusMessage *msg);
static DBusHandlerResult hs_cancel_ringing(struct headset *hs, DBusMessage *msg);
static DBusHandlerResult hs_play(struct headset *hs, DBusMessage *msg);
static DBusHandlerResult hs_stop(struct headset *hs, DBusMessage *msg);
static void hs_signal(struct headset *hs, const char *name);
static void hs_signal_gain_setting(struct headset *hs, const char *buf);

static void pending_connect_free(struct pending_connect *c)
{
	if (c->io)
		g_io_channel_unref(c->io);
	if (c->msg)
		dbus_message_unref(c->msg);
	if (c->conn)
		dbus_connection_unref(c->conn);
	free(c);
}

static DBusHandlerResult error_reply(DBusConnection *conn, DBusMessage *msg,
					const char *name, const char *descr)
{
	DBusMessage *derr;

	if (!conn || !msg)
		return DBUS_HANDLER_RESULT_HANDLED;

	derr = dbus_message_new_error(msg, name, descr);
	if (!derr) {
	       	error("Unable to allocate new error return");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	return send_message_and_unref(conn, derr);
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

static void hs_signal_gain_setting(struct headset *hs, const char *buf)
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

	signal = dbus_message_new_signal(hs->object_path, "org.bluez.audio.Headset", name);
	if (!signal) {
		error("Unable to allocate new GainChanged signal");
		return;
	}

	gain = (dbus_uint16_t) strtol(&buf[5], NULL, 10);

	dbus_message_append_args(signal, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	send_message_and_unref(connection, signal);
}

static void hs_signal(struct headset *hs, const char *name)
{
	DBusMessage *signal;

	signal = dbus_message_new_signal(hs->object_path, "org.bluez.audio.Headset", name);
	if (!signal) {
		error("Unable to allocate new AnswerRequested signal");
		return;
	}

	send_message_and_unref(connection, signal);
}

static int parse_headset_event(const char *buf, char *rsp, int rsp_len)
{
	int rv = 0;

	printf("Received: %s\n", buf);

	/* Return an error if this is not a proper AT command */
	if (strncmp(buf, "AT", 2)) {
		snprintf(rsp, rsp_len, "\r\nERROR\r\n");
		return rv;
	}

	buf += 2;

	if (!strncmp(buf, "+CKPD", 5))
		rv = 0;
	else if (!strncmp(buf, "+VG", 3))
		rv = 1;

	snprintf(rsp, rsp_len, "\r\nOK\r\n");

	/* return 1 if gain event */
	return rv;
}

static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct headset *hs = data;
	unsigned char buf[BUF_SIZE];
	char *cr;
	gsize bytes_read = 0;
	gsize free_space;
	GIOError err;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	err = g_io_channel_read(chan, (gchar *)buf, sizeof(buf) - 1, &bytes_read);
	if (err != G_IO_ERROR_NONE)
		goto failed;

	free_space = sizeof(hs->buf) - hs->data_start - hs->data_length - 1;

	if (free_space < bytes_read) {
		/* Very likely that the HS is sending us garbage so
		 * just ignore the data and disconnect */
		error("Too much data to fit incomming buffer");
		goto failed;
	}

	memcpy(&hs->buf[hs->data_start], buf, bytes_read);
	hs->data_length += bytes_read;

	/* Make sure the data is null terminated so we can use string
	 * functions */
	hs->buf[hs->data_start + hs->data_length] = '\0';

	cr = strchr(&hs->buf[hs->data_start], '\r');
	if (cr) {
		char rsp[BUF_SIZE];
		gsize count, bytes_written, total_bytes_written;
		off_t cmd_len;

		cmd_len	= 1 + (off_t) cr - (off_t) &hs->buf[hs->data_start];
		*cr = '\0';

		memset(rsp, 0, sizeof(rsp));

		/* FIXME: make a better parse function */
		if (parse_headset_event(&hs->buf[hs->data_start], rsp, sizeof(rsp)) == 1)
			hs_signal_gain_setting(hs, &hs->buf[hs->data_start] + 2);
		else
			hs_signal(hs, "AnswerRequested");

		count = strlen(rsp);
		total_bytes_written = bytes_written = 0;
		err = G_IO_ERROR_NONE;

		while (err == G_IO_ERROR_NONE && total_bytes_written < count) {
			/* FIXME: make it async */
			err = g_io_channel_write(hs->rfcomm, rsp + total_bytes_written, 
						count - total_bytes_written, &bytes_written);
			if (err != G_IO_ERROR_NONE)
				error("Error while writting to the audio output channel");
			total_bytes_written += bytes_written;
		};

		hs->data_start += cmd_len;
		hs->data_length -= cmd_len;

		if (!hs->data_length)
			hs->data_start = 0;
	}

	if (hs->ring_timer) {
		g_source_remove(hs->ring_timer);
		hs->ring_timer = 0;
	}

	return TRUE;

failed:
	hs_disconnect(hs, NULL);

	return FALSE;
}

static gboolean server_io_cb(GIOChannel *chan, GIOCondition cond, void *data)
{
	int srv_sk, cli_sk;
	struct sockaddr_rc addr;
	socklen_t size;
	char hs_address[18];
	struct headset *hs = NULL;
	struct manager *amanager = (struct manager *) data;

	assert(amanager != NULL);

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Hangup or error on rfcomm server socket");
		g_io_channel_close(chan);
		raise(SIGTERM);
		return FALSE;
	}

	srv_sk = g_io_channel_unix_get_fd(chan);

	size = sizeof(struct sockaddr_rc);
	cli_sk = accept(srv_sk, (struct sockaddr *) &addr, &size);
	if (cli_sk < 0) {
		error("accept: %s (%d)", strerror(errno), errno);
		return TRUE;
	}

	hs = audio_manager_find_headset_by_bda(amanager, &addr.rc_bdaddr);
	if (!hs) {
		hs = audio_headset_new(connection, &addr.rc_bdaddr);
		if (!hs) {
			error("Unable to create a new headset object");
			close(cli_sk);
			return TRUE;
		}
	}

	/* audio_headset_authorize(hs); */

	debug("Incoming connection on the server_sk for object %s", hs->object_path);

	if (hs->state > HEADSET_STATE_DISCONNECTED || hs->rfcomm) {
		debug("Refusing new connection since one already exists");
		close(cli_sk);
		return TRUE;
	}

	hs->rfcomm = g_io_channel_unix_new(cli_sk);
	if (!hs->rfcomm) {
		error("Allocating new GIOChannel failed!");
		close(cli_sk);
		return TRUE;
	}

	g_io_add_watch(hs->rfcomm, G_IO_IN, (GIOFunc) rfcomm_io_cb, hs);
	g_io_channel_unref(hs->rfcomm);

	ba2str(&addr.rc_bdaddr, hs_address);

	debug("Accepted connection from %s, %s", hs_address, hs->object_path);

	hs->state = HEADSET_STATE_CONNECTED;
	hs_signal(hs, "Connected");

	return TRUE;
}

static gboolean audio_input_to_sco_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct headset *hs = data;
	char buf[1024];
	gsize bytes_read;
	gsize bytes_written, total_bytes_written;
	GIOError err;

	if (!hs || !hs->sco) {
		error("The headset is invalid or does not have a SCO connection up");
		audio_headset_close_input(hs);
		return FALSE;
	}

	if (cond & G_IO_NVAL) {
		g_io_channel_unref(chan);
		return FALSE;
	}

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		audio_headset_close_input(hs);
		return FALSE;
	}

	err = g_io_channel_read(chan, buf, sizeof(buf), &bytes_read);
	if (err != G_IO_ERROR_NONE) {
		audio_headset_close_input(hs);
		return FALSE;
	}
	
	total_bytes_written = bytes_written = 0;
	err = G_IO_ERROR_NONE;

	while (err == G_IO_ERROR_NONE && total_bytes_written < bytes_read) {
		/* FIXME: make it async */
		err = g_io_channel_write(hs->sco, buf + total_bytes_written, 
					bytes_read - total_bytes_written, &bytes_written);
		if (err != G_IO_ERROR_NONE)
			error("Error while writting to the audio output channel");
		total_bytes_written += bytes_written;
	};

	return TRUE;
}

static gboolean sco_input_to_audio_output_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct headset *hs = data;
	char buf[1024];
	gsize bytes_read;
	gsize bytes_written, total_bytes_written;
	GIOError err;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		error("Audio connection got disconnected");
		g_io_channel_close(chan);
		g_io_channel_unref(hs->sco);
		hs->sco = NULL;
		if (hs->audio_output) {
			g_io_channel_close(hs->audio_output);
			hs->audio_output = NULL;
		}
		assert(hs->rfcomm);
		hs->state = HEADSET_STATE_CONNECTED;
		hs_signal(hs, "Stopped");
		return FALSE;
	}

	if (!hs->audio_output && hs->output)
		audio_headset_open_output(hs, hs->output);

	err = g_io_channel_read(chan, buf, sizeof(buf), &bytes_read);

	if (err != G_IO_ERROR_NONE)
		return FALSE;
	
	if (!hs->audio_output) {
		error("no audio output");
		return TRUE;
	}

	total_bytes_written = bytes_written = 0;
	err = G_IO_ERROR_NONE;

	while (err == G_IO_ERROR_NONE && total_bytes_written < bytes_read) {
		/* FIXME: make it async */
		err = g_io_channel_write(hs->audio_output, buf + total_bytes_written, 
					bytes_read - total_bytes_written, &bytes_written);
		if (err != G_IO_ERROR_NONE) {
			error("Error while writting to the audio output channel");
		}
		total_bytes_written += bytes_written;
	};

	return TRUE;
}

static gboolean sco_connect_cb(GIOChannel *chan, GIOCondition cond,
				struct headset *hs)
{
	int ret, sk, err, flags;
	DBusMessage *reply;
	socklen_t len;

	if (cond & G_IO_NVAL)
		return FALSE;

	assert(hs != NULL && hs->pending_connect != NULL && 
		hs->sco == NULL && hs->state == HEADSET_STATE_PLAY_IN_PROGRESS);

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

	debug("SCO socket opened for headset %s", hs->object_path);

	hs->sco = chan;
	hs->pending_connect->io = NULL;

	flags = hs->audio_output ? G_IO_IN : 0;
	g_io_add_watch(hs->sco, flags, sco_input_to_audio_output_cb, hs);

	if (hs->pending_connect->msg) {
		reply = dbus_message_new_method_return(hs->pending_connect->msg);
		if (reply)
			send_message_and_unref(connection, reply);
	}

	/* FIXME: do we allow both? pull & push model at the same time on sco && audio_input? */
	if (hs->audio_input)
		g_io_add_watch(hs->audio_input, G_IO_IN, audio_input_to_sco_cb, hs);

	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	hs->state = HEADSET_STATE_PLAYING;
	hs_signal(hs, "Playing");

	return FALSE;

failed:
	if (hs->pending_connect) {
		err_connect_failed(hs->pending_connect->conn, hs->pending_connect->msg, err);
		if (hs->pending_connect->io)
			g_io_channel_close(hs->pending_connect->io);
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
	}

	assert(hs->rfcomm);
	hs->state = HEADSET_STATE_CONNECTED;

	return FALSE;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond, struct headset *hs)
{
	char hs_address[18];
	int sk, ret, err;
	socklen_t len;
	
	if (cond & G_IO_NVAL)
		return FALSE;

	assert(hs != NULL && hs->pending_connect != NULL && 
			hs->rfcomm == NULL &&
			hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS);

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

	ba2str(&hs->bda, hs_address);
	hs->rfcomm = chan;
	hs->pending_connect->io = NULL;

	hs->state = HEADSET_STATE_CONNECTED;
	hs_signal(hs, "Connected");

	debug("Connected to %s", hs_address);

	g_io_add_watch(chan, G_IO_IN, (GIOFunc) rfcomm_io_cb, hs);

	if (hs->pending_connect->msg) {
		DBusMessage *reply;

		reply = dbus_message_new_method_return(hs->pending_connect->msg);
		if (reply)
			send_message_and_unref(connection, reply);
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
	}

	return FALSE;

failed:
	if (hs->pending_connect) {
		err_connect_failed(hs->pending_connect->conn, hs->pending_connect->msg, err);
		if (hs->pending_connect->io)
			g_io_channel_close(hs->pending_connect->io);
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
	}

	hs->state = HEADSET_STATE_DISCONNECTED;

	return FALSE;
}

static int rfcomm_connect(struct headset *hs, int *err)
{
	struct sockaddr_rc addr;
	char address[18];
	int sk;

	assert(hs != NULL && hs->pending_connect != NULL && 
			hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS);

	ba2str(&hs->bda, address);

	debug("Connecting to %s channel %d", address, hs->pending_connect->ch);

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

	if (set_nonblocking(sk) < 0) {
		*err = errno;
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &hs->bda);
	addr.rc_channel = hs->pending_connect->ch;

	hs->pending_connect->io = g_io_channel_unix_new(sk);
	if (!hs->pending_connect->io) {
		error("channel_unix_new failed in rfcomm connect");
		goto failed;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			if (err)
				*err = errno;
			error("connect() failed: %s (%d)", strerror(errno), errno);
			goto failed;
		}

		debug("Connect in progress");

		g_io_add_watch(hs->pending_connect->io, G_IO_OUT, (GIOFunc) rfcomm_connect_cb, hs);
	} else {
		debug("Connect succeeded with first try");
		rfcomm_connect_cb(hs->pending_connect->io, G_IO_OUT, hs);
	}

	return 0;

failed:
	if (!hs->pending_connect->io && sk >= 0)
		close(sk);

	return -1;
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

static void get_record_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *reply;
	DBusError derr;
	uint8_t *array;
	int array_len, record_len, err = EIO;
	sdp_record_t *record = NULL;
	sdp_list_t *protos;
	struct headset *hs = data;
	struct pending_connect *c;

	assert(hs != NULL && hs->pending_connect && !hs->rfcomm);
	c = hs->pending_connect;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceRecord failed: %s", derr.message);
		if (c->msg) 
			err_not_supported(c->conn, c->msg);
		dbus_error_free(&derr);
		goto failed;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &array, &array_len,
				DBUS_TYPE_INVALID)) {
		error("Unable to get args from GetRecordReply");
		if (c->msg) 
			err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (!array) {
		error("Unable to get handle array from reply");
		if (c->msg) 
			err_not_supported(c->conn, c->msg);
		goto failed;
	}

	record = sdp_extract_pdu(array, &record_len);
	if (!record) {
		error("Unable to extract service record from reply");
		if (c->msg) 
			err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (record_len != array_len)
		debug("warning: array len (%d) != record len (%d)",
				array_len, record_len);

	if (!sdp_get_access_protos(record, &protos)) {
		c->ch = sdp_get_proto_port(protos, RFCOMM_UUID);
		sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
		sdp_list_free(protos, NULL);
		protos = NULL;
	}

	if (c->ch == -1) {
		error("Unable to extract RFCOMM channel from service record");
		if (c->msg) 
			err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (rfcomm_connect(hs, &err) < 0) {
		error("Unable to connect");
		if (c->msg) 
			err_connect_failed(c->conn, c->msg, err);
		goto failed;
	}

	sdp_record_free(record);
	dbus_message_unref(reply);

	return;

failed:
	if (record)
		sdp_record_free(record);
	if (reply)
		dbus_message_unref(reply);
	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;
	hs->state = HEADSET_STATE_DISCONNECTED;
}

static DBusHandlerResult hs_disconnect(struct headset *hs, DBusMessage *msg)
{
	DBusMessage *reply = NULL;
	char hs_address[18];

	assert(hs);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (hs->state > HEADSET_STATE_CONNECTED)
		hs_stop(hs, NULL);

	if (hs->rfcomm) {
		g_io_channel_close(hs->rfcomm);
		g_io_channel_unref(hs->rfcomm);
		hs->rfcomm = NULL;
	}

	if (hs->pending_connect) {
		if (hs->pending_connect->io)
			g_io_channel_close(hs->pending_connect->io);
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
	}

	hs->state = HEADSET_STATE_DISCONNECTED;

	ba2str(&hs->bda, hs_address);
	info("Disconnected from %s, %s", &hs_address, hs->object_path);

	hs_signal(hs, "Disconnected");

	if (reply)
		send_message_and_unref(connection, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static void get_handles_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *msg = NULL, *reply;
	DBusPendingCall *pending;
	DBusError derr;
	struct headset *hs = data;
	struct pending_connect *c;
	char address[18], *addr_ptr = address;
	dbus_uint32_t *array = NULL;
	dbus_uint32_t handle;
	int array_len;

	assert(hs != NULL && hs->pending_connect);
	c = hs->pending_connect;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceHandles failed: %s", derr.message);
		if (c->msg) {
			if (dbus_error_has_name(&derr, "org.bluez.Error.ConnectFailed"))
				err_connect_failed(c->conn, c->msg, EHOSTDOWN);
			else
				err_not_supported(c->conn, c->msg);
		}
		dbus_error_free(&derr);
		goto failed;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &array, &array_len,
				DBUS_TYPE_INVALID)) {
	  
		error("Unable to get args from reply");
		if (c->msg) 
			err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (!array) {
		error("Unable to get handle array from reply");
		if (c->msg) 
			err_not_supported(c->conn, c->msg);
		goto failed;
	}

	if (array_len < 1) {
		debug("No record handles found");
		if (c->msg) 
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
		if (c->msg) 
			err_connect_failed(c->conn, c->msg, ENOMEM);
		goto failed;
	}

	ba2str(&hs->bda, address);

	handle = array[0];

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_UINT32, &handle,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending GetRemoteServiceRecord failed");
		if (c->msg) 
			err_connect_failed(c->conn, c->msg, EIO);
		goto failed;
	}

	dbus_pending_call_set_notify(pending, get_record_reply, hs, NULL);
	dbus_message_unref(msg);

	dbus_message_unref(reply);

	return;

failed:
	if (msg)
		dbus_message_unref(msg);
	dbus_message_unref(reply);
	hs_disconnect(hs, NULL);
}

static DBusHandlerResult hs_connect(struct headset *hs, DBusMessage *msg)
{
	DBusPendingCall *pending;
	const char *hs_svc = "hsp";
	const char *addr_ptr;
	char hs_address[18];

	assert(hs != NULL);

	if (hs->state == HEADSET_STATE_UNAUTHORIZED) {
		error("This headset has not been audiothorized");
	}

	if (hs->state > HEADSET_STATE_DISCONNECTED || hs->pending_connect) {
		error("Already connected");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	hs->pending_connect = g_try_new0(struct pending_connect, 1);
	if (!hs->pending_connect) {
		error("Out of memory when allocating new struct pending_connect");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	hs->state = HEADSET_STATE_CONNECT_IN_PROGRESS;

	hs->pending_connect->conn = dbus_connection_ref(connection);
	hs->pending_connect->msg = msg ? dbus_message_ref(msg) : NULL;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez/hci0",
						"org.bluez.Adapter",
						"GetRemoteServiceHandles");
	if (!msg) {
		error("Could not create a new dbus message");
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
		hs->state = HEADSET_STATE_DISCONNECTED;
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	ba2str(&hs->bda, hs_address);
	addr_ptr = hs_address;
	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_STRING, &hs_svc,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &pending, -1)) {
		error("Sending GetRemoteServiceHandles failed");
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
		hs->state = HEADSET_STATE_DISCONNECTED;
		dbus_message_unref(msg);
		return err_connect_failed(connection, msg, EIO);
	}

	dbus_pending_call_set_notify(pending, get_handles_reply, hs, NULL);
	dbus_message_unref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;;
}

GIOError audio_headset_send_ring(struct headset *hs)
{
	const char *ring_str = "\r\nRING\r\n";
	GIOError err;
	gsize total_written, written, count;

	assert(hs != NULL);
	if (hs->state < HEADSET_STATE_CONNECTED || !hs->rfcomm) {
		error("the headset %s is not connected", hs->object_path);
		return G_IO_ERROR_UNKNOWN;
	}

	count = strlen(ring_str);
	written = total_written = 0;

	while (total_written < count) {
		err = g_io_channel_write(hs->rfcomm, ring_str + total_written,
					count - total_written, &written);
		if (err != G_IO_ERROR_NONE)
			return err;
		total_written += written;
	}

	return G_IO_ERROR_NONE;
}

static gboolean ring_timer_cb(gpointer data)
{
	struct headset *hs = data;

	assert(hs != NULL);

	if (audio_headset_send_ring(hs) != G_IO_ERROR_NONE)
		error("Sending RING failed");

	return TRUE;
}

static DBusHandlerResult hs_ring(struct headset *hs, DBusMessage *msg)
{
	DBusMessage *reply = NULL;

	assert(hs != NULL);

	if (hs->state < HEADSET_STATE_CONNECTED)
		return err_not_connected(connection, msg);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (hs->ring_timer) {
		debug("Got Ring method call while ringing already in progress");
		goto done;
	}

	if (audio_headset_send_ring(hs) != G_IO_ERROR_NONE) {
		dbus_message_unref(reply);
		return err_failed(connection, msg);
	}

	hs->ring_timer = g_timeout_add(RING_INTERVAL, ring_timer_cb, hs);

done:
	if (reply)
		send_message_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_cancel_ringing(struct headset *hs, DBusMessage *msg)
{
	DBusMessage *reply = NULL;

	if (!hs)
		return err_not_connected(connection, msg);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (!hs->ring_timer) {
		debug("Got CancelRinging method call but ringing is not in progress");
		goto done;
	}

	g_source_remove(hs->ring_timer);
	hs->ring_timer = 0;

done:
	if (reply)
		send_message_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_play(struct headset *hs, DBusMessage *msg)
{
	struct sockaddr_sco addr;
	struct pending_connect *c;
	int sk, err;

	if (!hs)
		return err_not_connected(connection, msg);

	if (hs->state < HEADSET_STATE_CONNECTED)
		return err_not_connected(connection, msg); /* FIXME: in progress error? */

	if (hs->state >= HEADSET_STATE_PLAY_IN_PROGRESS || hs->pending_connect)
		return err_already_connected(connection, msg);

	if (hs->sco)
		return err_already_connected(connection, msg);

	hs->pending_connect = g_try_new0(struct pending_connect, 1);
	if (!hs->pending_connect)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	hs->state = HEADSET_STATE_PLAY_IN_PROGRESS;

	c = hs->pending_connect;
	c->conn = dbus_connection_ref(connection);
	c->msg = msg ? dbus_message_ref(msg) : NULL;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		err_connect_failed(connection, msg, err);
		goto failed;
	}

	c->io = g_io_channel_unix_new(sk);
	if (!c->io) {
		close(sk);
		pending_connect_free(c);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, BDADDR_ANY);

	if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		err_connect_failed(connection, msg, err);
		goto failed;
	}

	if (set_nonblocking(sk) < 0) {
		err = errno;
		err_connect_failed(connection, msg, err);
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, &hs->bda);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect: %s (%d)", strerror(errno), errno);
			goto failed;
		}

		debug("Connect in progress");

		g_io_add_watch(c->io, G_IO_OUT, (GIOFunc) sco_connect_cb, hs);
	} else {
		debug("Connect succeeded with first try");
		sco_connect_cb(c->io, G_IO_OUT, hs);
	}

	return 0;

failed:
	if (hs->pending_connect) {
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL; 
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_stop(struct headset *hs, DBusMessage *msg)
{
	DBusMessage *reply = NULL;

	if (!hs || !hs->sco)
		return err_not_connected(connection, msg);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (hs->state == HEADSET_STATE_PLAY_IN_PROGRESS && hs->pending_connect) {
		g_io_channel_close(hs->pending_connect->io);
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
		hs->state = HEADSET_STATE_CONNECTED;
	}

	if (hs->sco) {
		g_io_channel_close(hs->sco);
		hs->sco = NULL;
		hs->state = HEADSET_STATE_CONNECTED;
	}

	hs_signal(hs, "Stopped");
	hs->state = HEADSET_STATE_CONNECTED;

	if (reply)
		send_message_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct headset *hs = data;
	const char *interface, *member;

	assert(hs != NULL);

	interface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, interface) &&
			!strcmp("Introspect", member))
		return simple_introspect(conn, msg, data);

	if (strcmp(interface, "org.bluez.audio.Headset") != 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "Connect") == 0)
		return hs_connect(hs, msg);

	if (strcmp(member, "Disconnect") == 0)
		return hs_disconnect(hs, msg);

	if (strcmp(member, "IndicateCall") == 0)
		return hs_ring(hs, msg);

	if (strcmp(member, "CancelCall") == 0)
		return hs_cancel_ringing(hs, msg);

	if (strcmp(member, "Play") == 0)
		return hs_play(hs, msg);

	if (strcmp(member, "Stop") == 0)
		return hs_stop(hs, msg);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable hs_table = {
	.message_function = hs_message,
};

/*
** audio_headset_new:
** Create a unique dbus object path for the headset and allocates a new
** headset or return NULL if fail
*/
struct headset *audio_headset_new(DBusConnection *conn, const bdaddr_t *bda)
{
	static int headset_uid = 0;
	struct headset *hs;

	hs = g_try_new0(struct headset, 1);
	if (!hs) {
		error("Allocating new hs connection struct failed!");
		return NULL;
	}

	snprintf(hs->object_path, sizeof(hs->object_path),
			AUDIO_HEADSET_PATH_BASE "%d", headset_uid++);

	if (!dbus_connection_register_object_path(conn, hs->object_path,
						&hs_table, hs)) {
		error("D-Bus failed to register %s path", hs->object_path);
		free (hs);
		return NULL;
	}

	bacpy(&hs->bda, bda);

	return hs;
}

void audio_headset_unref(struct headset *hs)
{
	assert(hs != NULL);

	free(hs);
}

gboolean audio_headset_close_output(struct headset *hs)
{
	assert(hs != NULL);

	if (hs->audio_output == NULL) 
		return FALSE;

	g_io_channel_unref(hs->audio_output);
	hs->audio_output = NULL;

	return TRUE;
}

/* FIXME: in the furture, that would be great to provide user space alsa driver (not plugin) */
gboolean audio_headset_open_output(struct headset *hs, const char *output)
{
	int out;

	assert(hs != NULL && output != NULL);

	audio_headset_close_output(hs);
	if (output && hs->output) {
		free(hs->output);
		hs->output = strdup(output);
	}

	assert(hs->output);

	out = open(hs->output, O_WRONLY | O_SYNC | O_CREAT);

	if (out < 0) {
		error("open(%s): %s %d", hs->output, strerror(errno), errno);
		return FALSE;
	}

	hs->audio_output = g_io_channel_unix_new(out);
	if (!hs->audio_output) {
		error("Allocating new channel for audio output!");
		return FALSE;
	}

	g_io_channel_set_close_on_unref(hs->audio_output, TRUE);

	return TRUE;
}

gboolean audio_headset_close_input(struct headset *hs)
{
	assert(hs != NULL);

	if (hs->audio_input == NULL) 
		return FALSE;

	g_io_channel_unref(hs->audio_input);
	hs->audio_input = NULL;

	hs->state = HEADSET_STATE_CONNECTED;

	return TRUE;
}

gboolean audio_headset_open_input(struct headset *hs, const char *input)
{
	int in;

	assert(hs != NULL);
	
	audio_headset_close_input(hs);

	/* we keep the input name, and NULL can be use to reopen */
	if (input && hs->input) {
		free(hs->input);
		hs->input = strdup(input);
	}

	assert(hs->input);

	in = open(hs->input, O_RDONLY | O_NOCTTY);

	if (in < 0) {
		error("open(%s): %s %d", hs->input, strerror(errno), errno);
		return FALSE;
	}

	hs->audio_input = g_io_channel_unix_new(in);
	if (!hs->audio_input) {
		error("Allocating new channel for audio input!");
		return FALSE;
	}

	g_io_channel_set_close_on_unref(hs->audio_input, TRUE);

	return TRUE;
}

gboolean audio_manager_create_headset_server(struct manager *amanager, uint8_t chan)
{
	int srv_sk;

	assert(amanager != NULL);

	if (amanager->server_sk) {
		error("Server socket already created");
		return FALSE;
	}

	srv_sk = server_socket(&chan);
	if (srv_sk < 0) {
		error("Unable to create server socket");
		return FALSE;
	}

	if (!amanager->record_id)
		amanager->record_id = add_ag_record(chan);

	if (!amanager->record_id) {
		error("Unable to register service record");
		close(srv_sk);
		return FALSE;
	}

	amanager->server_sk = g_io_channel_unix_new(srv_sk);
	if (!amanager->server_sk) {
		error("Unable to allocate new GIOChannel");
		remove_ag_record(amanager->record_id);
		amanager->record_id = 0;
		close(srv_sk);
		return FALSE;
	}

	g_io_add_watch(amanager->server_sk, G_IO_IN, (GIOFunc) server_io_cb, amanager);

	return TRUE;
}

static gint headset_bda_cmp(gconstpointer headset, gconstpointer bda)
{
	const struct headset *hs = headset;

	return bacmp(&hs->bda, bda);
}

struct headset *audio_manager_find_headset_by_bda(struct manager *amanager, const bdaddr_t *bda)
{
	GSList *elem;

	assert(amanager);
	elem = g_slist_find_custom(amanager->headset_list, bda, headset_bda_cmp);

	return elem ? elem->data : NULL;
}

void audio_manager_add_headset(struct manager *amanager, struct headset *hs)
{
	assert(amanager && hs);

	if (g_slist_find(amanager->headset_list, hs))
		return;

	amanager->headset_list = g_slist_append(amanager->headset_list, hs);
}

static DBusHandlerResult am_create_headset(struct manager *amanager, 
						DBusMessage *msg)
{
	const char *object_path;
	const char *address;
	struct headset *hs;
	bdaddr_t bda;
	DBusMessage *reply;
	DBusError derr;

	if (!amanager)
		return err_not_connected(connection, msg);
	
	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_INVALID)) {
		err_invalid_args(connection, msg, derr.message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	str2ba(address, &bda);
	hs = audio_manager_find_headset_by_bda(amanager, &bda);
	if (!hs) {
		hs = audio_headset_new(connection, &bda);
		if (!hs)
			return error_reply(connection, msg,
					"org.bluez.Error.Failed",
					"Unable to create new headset object");
	}

	object_path = hs->object_path;
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &object_path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_get_default_headset(struct manager *amanager, 
						DBusMessage *msg)
{
	DBusMessage *reply;
	char object_path[128];
	const char *opath = object_path;

	if (!amanager)
		return err_not_connected(connection, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	snprintf(object_path, sizeof(object_path), AUDIO_HEADSET_PATH_BASE "%d", 0);
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &opath,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *interface, *member;
	struct manager *amanager = (struct manager *)data;

	interface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, interface) &&
			!strcmp("Introspect", member))
		return simple_introspect(conn, msg, data);

	if (strcmp(interface, "org.bluez.audio.Headset") != 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "CreateHeadset") == 0)
		return am_create_headset(amanager, msg);

	if (strcmp(member, "DefaultHeadset") == 0)
		return am_get_default_headset(amanager, msg);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable am_table = {
	.message_function = am_message,
};

struct manager* audio_manager_new(DBusConnection *conn)
{
	struct manager *amanager;

	amanager = malloc(sizeof(struct manager));

	if (!amanager) {
		error("Allocating new hs connection struct failed!");
		return NULL;
	}

	memset(amanager, 0, sizeof(struct manager));

	if (!dbus_connection_register_object_path(conn, AUDIO_MANAGER_PATH,
						&am_table, amanager)) {
		error("D-Bus failed to register %s path", AUDIO_MANAGER_PATH);
		free(amanager);
		return NULL;
	}

	return amanager;
}

void audio_manager_free(struct manager* amanager)
{
	assert(amanager != NULL);

	if (amanager->record_id) {
		remove_ag_record(amanager->record_id);
		amanager->record_id = 0;
	}

	if (amanager->server_sk) {
		g_io_channel_unref(amanager->server_sk);
		amanager->server_sk = NULL;
	}

	if (amanager->headset_list) {
		g_slist_foreach(amanager->headset_list, (GFunc) audio_headset_unref,
				amanager);
		g_slist_free(amanager->headset_list);
		amanager->headset_list = NULL;
	}

	free(amanager);
}

static gboolean register_service(const char *ident, const char *name,
					const char *desc)
{
	DBusMessage *msg, *reply;
	DBusError derr;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
					"org.bluez.Database", "RegisterService");

	if (!msg) {
		error("Unable to allocate new message");
		return FALSE;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &ident,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_STRING, &desc,
					DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection, msg, -1, &derr);
	if (dbus_error_is_set(&derr)) {
		error("RegisterService: %s", derr.message);
		dbus_error_free(&derr);
		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

static void sig_term(int sig)
{
	g_main_loop_quit(main_loop);
}

int main(int argc, char *argv[])
{
	uint8_t opt_channel = 12;
	char *opt_bda = NULL;
	char *opt_input = NULL;
	char *opt_output = NULL;
	gboolean register_svc = FALSE;
	bdaddr_t bda;
	struct headset *hs;
	struct manager *manager;
	struct sigaction sa;
	int opt;

	while ((opt = getopt(argc, argv, "c:o:i:dr")) != EOF) {
		switch (opt) {
		case 'c':
			opt_channel = strtol(optarg, NULL, 0);
			break;

		case 'i':
			opt_input = optarg;
			break;

		case 'o':
			opt_output = optarg;
			break;

		case 'd':
			enable_debug();
			break;

		case 'r':
			register_svc = TRUE;
			break;

		default:
			printf("Usage: %s -c local_channel [-d] [-o output] [-i input] [bdaddr]\n", argv[0]);
			exit(1);
		}
	}

	if (optind < argc && argv[optind])
		opt_bda = argv[optind];

	start_logging("headset", "Bluetooth headset service daemon");

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGCHLD, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);

	main_loop = g_main_loop_new(NULL, FALSE);

	connection = init_dbus("org.bluez.audio", NULL, NULL);
	if (!connection) {
		error("Connection to system bus failed");
		g_main_loop_unref(main_loop);
		exit(1);
	}

	if (register_svc && !register_service("headset", "Headset service",
						"Headset service")) {
		error("Unable to register service");
		dbus_connection_unref(connection);
		g_main_loop_unref(main_loop);
		exit(1);
	}

	manager = audio_manager_new(connection);
	if (!manager) {
		error("Failed to create an audio manager");
		dbus_connection_unref(connection);
		g_main_loop_unref(main_loop);
		exit(1);
	}

	audio_manager_create_headset_server(manager, opt_channel);

	if (opt_bda) {
		str2ba(opt_bda, &bda);
		hs = audio_headset_new(connection, &bda);
		if (!hs) {
			error("Connection setup failed");
			dbus_connection_unref(connection);
			g_main_loop_unref(main_loop);
			exit(1);
		}

		if (opt_output)
			audio_headset_open_output(hs, opt_output);
		if (opt_input)
			audio_headset_open_input(hs, opt_input);

		audio_manager_add_headset(manager, hs);
		/* connect */
		hs_connect(hs, NULL);
	}

	g_main_loop_run(main_loop);

	audio_manager_free(manager);
	manager = NULL;

	dbus_connection_unref(connection);

	g_main_loop_unref(main_loop);

	info("Exit");

	stop_logging();

	return 0;
}
