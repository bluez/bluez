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
#include "manager.h"
#include "headset.h"

#define DEFAULT_HS_AG_CHANNEL 12

#define RING_INTERVAL 3000

typedef enum {
	HEADSET_EVENT_KEYPRESS,
	HEADSET_EVENT_GAIN,
	HEADSET_EVENT_UNKNOWN,
	HEADSET_EVENT_INVALID
} headset_event_t; 

typedef enum {
	HEADSET_STATE_UNAUTHORIZED,
	HEADSET_STATE_DISCONNECTED,
	HEADSET_STATE_CONNECT_IN_PROGRESS,
	HEADSET_STATE_CONNECTED,
	HEADSET_STATE_PLAY_IN_PROGRESS,
	HEADSET_STATE_PLAYING,
} headset_state_t;

struct pending_connect {
	int ch;
	DBusMessage *msg;
	GIOChannel *io;
};

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

static DBusHandlerResult hs_disconnect(struct headset *hs, DBusMessage *msg);

static GIOChannel *hs_server = NULL;

static uint32_t hs_record_id = 0;

static GSList *headsets = NULL;

static DBusConnection *connection = NULL;

static void pending_connect_free(struct pending_connect *c)
{
	if (c->io)
		g_io_channel_unref(c->io);
	if (c->msg)
		dbus_message_unref(c->msg);
	g_free(c);
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

static gint headset_bda_cmp(gconstpointer headset, gconstpointer bda)
{
	const struct headset *hs = headset;

	return bacmp(&hs->bda, bda);
}

static gboolean headset_close_output(struct headset *hs)
{
	assert(hs != NULL);

	if (hs->audio_output == NULL) 
		return FALSE;

	g_io_channel_close(hs->audio_output);
	g_io_channel_unref(hs->audio_output);
	hs->audio_output = NULL;

	return TRUE;
}

/* FIXME: in the furture, that would be great to provide user space alsa driver (not plugin) */
static gboolean headset_open_output(struct headset *hs, const char *output)
{
	int out;

	assert(hs != NULL && output != NULL);

	headset_close_output(hs);
	if (output && hs->output) {
		g_free(hs->output);
		hs->output = g_strdup(output);
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

static gboolean headset_close_input(struct headset *hs)
{
	assert(hs != NULL);

	if (hs->audio_input == NULL) 
		return FALSE;

	g_io_channel_close(hs->audio_input);
	g_io_channel_unref(hs->audio_input);
	hs->audio_input = NULL;

	return TRUE;
}

#if 0
static gboolean headset_open_input(struct headset *hs, const char *input)
{
	int in;

	assert(hs != NULL);
	
	/* we keep the input name, and NULL can be use to reopen */
	if (input && hs->input) {
		g_free(hs->input);
		hs->input = g_strdup(input);
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

	return TRUE;
}
#endif

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

static headset_event_t parse_headset_event(const char *buf, char *rsp, int rsp_len)
{
	printf("Received: %s\n", buf);

	/* Return an error if this is not a proper AT command */
	if (strncmp(buf, "AT", 2)) {
		snprintf(rsp, rsp_len, "\r\nERROR\r\n");
		return HEADSET_EVENT_INVALID;
	}

	buf += 2;

	snprintf(rsp, rsp_len, "\r\nOK\r\n");

	if (!strncmp(buf, "+CKPD", 5))
		return HEADSET_EVENT_KEYPRESS;
	else if (!strncmp(buf, "+VG", 3))
		return HEADSET_EVENT_GAIN;
	else
		return HEADSET_EVENT_UNKNOWN;
}

static void close_sco(struct headset *hs)
{
	g_io_channel_close(hs->sco);
	g_io_channel_unref(hs->sco);
	hs->sco = NULL;
	if (hs->audio_output) {
		g_io_channel_unref(hs->audio_output);
		hs->audio_output = NULL;
	}
	if (hs->audio_input)
		headset_close_input(hs);
	assert(hs->rfcomm);
	hs->state = HEADSET_STATE_CONNECTED;
	hs_signal(hs, "Stopped");
}


static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond,
				struct headset *hs)
{
	unsigned char buf[BUF_SIZE];
	char *cr, rsp[BUF_SIZE];
	gsize bytes_read = 0;
	gsize free_space, count, bytes_written, total_bytes_written;
	GIOError err;
	off_t cmd_len;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf) - 1, &bytes_read);
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
	if (!cr)
		return TRUE;

	cmd_len	= 1 + (off_t) cr - (off_t) &hs->buf[hs->data_start];
	*cr = '\0';

	memset(rsp, 0, sizeof(rsp));

	switch (parse_headset_event(&hs->buf[hs->data_start], rsp, sizeof(rsp))) {
	case HEADSET_EVENT_GAIN:
		hs_signal_gain_setting(hs, &hs->buf[hs->data_start] + 2);
		break;

	case HEADSET_EVENT_KEYPRESS:
		if (hs->ring_timer) {
			g_source_remove(hs->ring_timer);
			hs->ring_timer = 0;
		}

		hs_signal(hs, "AnswerRequested");
		break;

	case HEADSET_EVENT_INVALID:
	case HEADSET_EVENT_UNKNOWN:
	default:
		debug("Unknown headset event");
		break;
	}

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

	return TRUE;

failed:
	if (hs->sco)
		close_sco(hs);
	hs_disconnect(hs, NULL);

	return FALSE;
}

static void send_cancel_auth(struct headset *hs)
{
	DBusMessage *cancel;
	char addr[18], *address = addr;
	const char *uuid = "";

	cancel = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"CancelAuthorizationRequest");
	if (!cancel) {
		error("Unable to allocate new method call");
		return;
	}

	ba2str(&hs->bda, addr);

	dbus_message_append_args(cancel, DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &uuid, DBUS_TYPE_INVALID);

	send_message_and_unref(connection, cancel);
}

static void auth_callback(DBusPendingCall *call, void *data)
{
	struct headset *hs = data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Access denied: %s", err.message);
		if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY)) {
			debug("Canceling authorization request");
			send_cancel_auth(hs);
		}
		dbus_error_free(&err);
		g_io_channel_close(hs->rfcomm);
		g_io_channel_unref(hs->rfcomm);
		hs->rfcomm = NULL;
	} else {
		char hs_address[18];

		g_io_add_watch(hs->rfcomm, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) rfcomm_io_cb, hs);

		ba2str(&hs->bda, hs_address);

		debug("Accepted connection from %s for %s", hs_address, hs->object_path);

		hs->state = HEADSET_STATE_CONNECTED;
		hs_signal(hs, "Connected");
	}

	dbus_message_unref(reply);
}

static gboolean audio_input_to_sco_cb(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct headset *hs = data;
	char buf[1024];
	gsize bytes_read;
	gsize bytes_written, total_bytes_written;
	GIOError err;

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR))
		goto failed;

	err = g_io_channel_read(chan, buf, sizeof(buf), &bytes_read);
	if (err != G_IO_ERROR_NONE)
		goto failed;
	
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

failed:
	headset_close_input(hs);
	return FALSE;
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

	if (cond & (G_IO_HUP | G_IO_ERR))
		goto disconn;

	if (!hs->audio_output && hs->output)
		headset_open_output(hs, hs->output);

	err = g_io_channel_read(chan, buf, sizeof(buf), &bytes_read);

	if (err != G_IO_ERROR_NONE)
		goto disconn;
	
	if (!hs->audio_output) {
		error("got %d bytes audio but have nowhere to write it", bytes_read);
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

disconn:
	error("Audio connection got disconnected");
	if (hs->sco)
		close_sco(hs);
	return FALSE;
}

static gboolean sco_connect_cb(GIOChannel *chan, GIOCondition cond,
				struct headset *hs)
{
	int ret, sk, err, flags;
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

	flags = G_IO_ERR | G_IO_HUP | G_IO_NVAL;
	if (hs->audio_output)
		flags |= G_IO_IN;

	g_io_add_watch(hs->sco, flags, sco_input_to_audio_output_cb, hs);

	if (hs->pending_connect->msg) {
		DBusMessage *reply;

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
		err_connect_failed(connection, hs->pending_connect->msg, err);
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

	g_io_add_watch(chan, G_IO_IN | G_IO_ERR | G_IO_HUP| G_IO_NVAL,
			(GIOFunc) rfcomm_io_cb, hs);

	if (hs->pending_connect) {
		if (hs->pending_connect->msg) {
			DBusMessage *reply;

			reply = dbus_message_new_method_return(hs->pending_connect->msg);
			if (reply)
				send_message_and_unref(connection, reply);
		}

		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
	}

	return FALSE;

failed:
	if (hs->pending_connect) {
		err_connect_failed(connection, hs->pending_connect->msg, err);
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

static uint32_t headset_add_ag_record(uint8_t channel)
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
	reply = dbus_connection_send_with_reply_and_block(connection, msg,
								-1, &derr);

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

int headset_remove_ag_record(uint32_t rec_id)
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
	reply = dbus_connection_send_with_reply_and_block(connection, msg,
								-1, &derr);

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
			err_not_supported(connection, c->msg);
		dbus_error_free(&derr);
		goto failed;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &array, &array_len,
				DBUS_TYPE_INVALID)) {
		error("Unable to get args from GetRecordReply");
		if (c->msg) 
			err_not_supported(connection, c->msg);
		goto failed;
	}

	if (!array) {
		error("Unable to get handle array from reply");
		if (c->msg) 
			err_not_supported(connection, c->msg);
		goto failed;
	}

	record = sdp_extract_pdu(array, &record_len);
	if (!record) {
		error("Unable to extract service record from reply");
		if (c->msg) 
			err_not_supported(connection, c->msg);
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
			err_not_supported(connection, c->msg);
		goto failed;
	}

	if (rfcomm_connect(hs, &err) < 0) {
		error("Unable to connect");
		if (c->msg) 
			err_connect_failed(connection, c->msg, err);
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
		if (hs->pending_connect->msg)
			err_connect_failed(connection, hs->pending_connect->msg,
						EINTR);
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
		hs->state = HEADSET_STATE_CONNECTED;
	}

	close_sco(hs);

	if (reply)
		send_message_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
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
		if (hs->pending_connect->msg)
			err_connect_failed(connection, hs->pending_connect->msg,
						EINTR);
		pending_connect_free(hs->pending_connect);
		hs->pending_connect = NULL;
	}

	hs->state = HEADSET_STATE_DISCONNECTED;

	ba2str(&hs->bda, hs_address);
	info("Disconnected from %s, %s", &hs_address, hs->object_path);

	hs_signal(hs, "Disconnected");

	hs->data_start = 0;
	hs->data_length = 0;

	if (reply)
		send_message_and_unref(connection, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_is_connected(struct headset *hs, DBusMessage *msg)
{
	DBusMessage *reply;
	dbus_bool_t connected;

	assert(hs);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->state >= HEADSET_STATE_CONNECTED)
		connected = TRUE;
	else
		connected = FALSE;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

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
			if (dbus_error_has_name(&derr, "org.bluez.Error.ConnectionAttemptFailed"))
				err_connect_failed(connection, c->msg, EHOSTDOWN);
			else
				err_not_supported(connection, c->msg);
		}
		dbus_error_free(&derr);
		goto failed;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &array, &array_len,
				DBUS_TYPE_INVALID)) {
	  
		error("Unable to get args from reply");
		if (c->msg) 
			err_not_supported(connection, c->msg);
		goto failed;
	}

	if (!array) {
		error("Unable to get handle array from reply");
		if (c->msg) 
			err_not_supported(connection, c->msg);
		goto failed;
	}

	if (array_len < 1) {
		debug("No record handles found");
		if (c->msg) 
			err_not_supported(connection, c->msg);
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
			err_connect_failed(connection, c->msg, ENOMEM);
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
			err_connect_failed(connection, c->msg, EIO);
		goto failed;
	}

	dbus_pending_call_set_notify(pending, get_record_reply, hs, NULL);
	dbus_pending_call_unref(pending);
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
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;;
}

static GIOError headset_send_ring(struct headset *hs)
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

	if (headset_send_ring(hs) != G_IO_ERROR_NONE)
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

	if (headset_send_ring(hs) != G_IO_ERROR_NONE) {
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

	if (hs->state < HEADSET_STATE_CONNECTED)
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

	if (hs->state < HEADSET_STATE_CONNECTED)
		return err_not_connected(connection, msg); /* FIXME: in progress error? */

	if (hs->state >= HEADSET_STATE_PLAY_IN_PROGRESS || hs->pending_connect)
		return err_already_connected(connection, msg);

	if (hs->sco)
		return err_already_connected(connection, msg);

	c = g_try_new0(struct pending_connect, 1);
	if (!c)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	hs->state = HEADSET_STATE_PLAY_IN_PROGRESS;

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

	hs->pending_connect = c;

	return 0;

failed:
	if (c)
		pending_connect_free(c);

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

	if (strcmp(member, "IsConnected") == 0)
		return hs_is_connected(hs, msg);

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

static struct headset *headset_add_internal(const bdaddr_t *bda)
{
	static int headset_uid = 0;
	struct headset *hs;
	GSList *match;

	match = g_slist_find_custom(headsets, bda, headset_bda_cmp);
	if (match)
		return match->data;

	hs = g_try_new0(struct headset, 1);
	if (!hs) {
		error("Allocating new hs connection struct failed!");
		return NULL;
	}

	snprintf(hs->object_path, sizeof(hs->object_path),
			HEADSET_PATH_BASE "%d", headset_uid++);

	if (!dbus_connection_register_object_path(connection, hs->object_path,
						&hs_table, hs)) {
		error("D-Bus failed to register %s path", hs->object_path);
		free (hs);
		return NULL;
	}

	bacpy(&hs->bda, bda);

	headsets = g_slist_append(headsets, hs);

	return hs;
}

const char *headset_add(const bdaddr_t *bda)
{
	struct headset *hs;

	hs = headset_add_internal(bda);
	if (!hs)
		return NULL;

	return hs->object_path;
}

const char *headset_get(const bdaddr_t *bda)
{
	GSList *match;
	struct headset *hs;

	match = g_slist_find_custom(headsets, bda, headset_bda_cmp);
	if (!match)
		return NULL;

	hs = match->data;

	return hs->object_path;
}

void headset_remove(const char *path)
{
	struct headset *hs;

	if (!dbus_connection_get_object_path_data(connection, path,
							(void *) &hs))
		return;

	if (hs->state > HEADSET_STATE_DISCONNECTED)
		hs_disconnect(hs, NULL);

	if (!dbus_connection_unregister_object_path(connection, path))
		error("D-Bus failed to unregister %s path", path);

	headsets = g_slist_remove(headsets, hs);

	g_free(hs);
}

static gboolean headset_server_io_cb(GIOChannel *chan, GIOCondition cond, void *data)
{
	int srv_sk, cli_sk;
	struct sockaddr_rc addr;
	socklen_t size;
	char hs_address[18], *address = hs_address;
	const char *uuid = "";
	struct headset *hs = NULL;
	DBusMessage *auth;
	DBusPendingCall *pending;
	GSList *match;

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

	match = g_slist_find_custom(headsets, &addr.rc_bdaddr, headset_bda_cmp);
	if (!match) {
		hs = headset_add_internal(&addr.rc_bdaddr);
		if (!hs) {
			error("Unable to create a new headset object");
			close(cli_sk);
			return TRUE;
		}

		manager_add_headset(hs->object_path);
	}
	else
		hs = match->data;

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

	auth = dbus_message_new_method_call("org.bluez", "/org/bluez", "org.bluez.Database",
						"RequestAuthorization");
	if (!auth) {
		error("Unable to allocat new RequestAuthorization method call");
		goto failed;
	}

	ba2str(&hs->bda, hs_address);

	dbus_message_append_args(auth, DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &uuid, DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, auth, &pending, -1) == FALSE) {
		error("Sending of authorization request failed");
		goto failed;
	}

	dbus_pending_call_set_notify(pending, auth_callback, hs, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(auth);

	return TRUE;

failed:
	if (hs->rfcomm) {
		g_io_channel_close(hs->rfcomm);
		g_io_channel_unref(hs->rfcomm);
		hs->rfcomm = NULL;
	}

	return TRUE;
}

static GIOChannel *server_socket(uint8_t *channel)
{
	int sock, lm;
	struct sockaddr_rc addr;
	socklen_t sa_len;
	GIOChannel *io;

	sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sock < 0) {
		error("server socket: %s (%d)", strerror(errno), errno);
		return NULL;
	}

	lm = RFCOMM_LM_SECURE;
	if (setsockopt(sock, SOL_RFCOMM, RFCOMM_LM, &lm, sizeof(lm)) < 0) {
		error("server setsockopt: %s (%d)", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = 0;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("server bind: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	if (listen(sock, 1) < 0) {
		error("server listen: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	sa_len = sizeof(struct sockaddr_rc);
	getsockname(sock, (struct sockaddr *) &addr, &sa_len);
	*channel = addr.rc_channel;

	io = g_io_channel_unix_new(sock);
	if (!io) {
		error("Unable to allocate new io channel");
		close(sock);
		return NULL;
	}

	return io;
}

int headset_init(DBusConnection *conn)
{
	uint8_t chan = DEFAULT_HS_AG_CHANNEL;

	connection = dbus_connection_ref(conn);

	hs_server = server_socket(&chan);
	if (!hs_server)
		return -1;

	if (!hs_record_id)
		hs_record_id = headset_add_ag_record(chan);

	if (!hs_record_id) {
		error("Unable to register service record");
		g_io_channel_unref(hs_server);
		hs_server = NULL;
		return -1;
	}

	g_io_add_watch(hs_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) headset_server_io_cb, NULL);

	return 0;
}

void headset_exit(void)
{
	if (hs_record_id) {
		headset_remove_ag_record(hs_record_id);
		hs_record_id = 0;
	}

	if (hs_server) {
		g_io_channel_unref(hs_server);
		hs_server = NULL;
	}

	dbus_connection_unref(connection);
	connection = NULL;
}
