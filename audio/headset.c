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
#include "dbus-helper.h"
#include "logging.h"
#include "manager.h"
#include "headset.h"

#define DEFAULT_HS_AG_CHANNEL 12
#define DEFAULT_HF_AG_CHANNEL 13

#define RING_INTERVAL 3000

#define BUF_SIZE 1024

typedef enum {
	HEADSET_EVENT_KEYPRESS,
	HEADSET_EVENT_GAIN,
	HEADSET_EVENT_UNKNOWN,
	HEADSET_EVENT_INVALID
} headset_event_t; 

typedef enum {
	HEADSET_STATE_DISCONNECTED = 0,
	HEADSET_STATE_CONNECT_IN_PROGRESS,
	HEADSET_STATE_CONNECTED,
	HEADSET_STATE_PLAY_IN_PROGRESS,
	HEADSET_STATE_PLAYING,
} headset_state_t;

typedef enum {
	SVC_HEADSET,
	SVC_HANDSFREE
} hs_type;

struct pending_connect {
	DBusMessage *msg;
	GIOChannel *io;
};

struct headset {
	uint32_t hsp_handle;
	uint32_t hfp_handle;

	int rfcomm_ch;

	GIOChannel *rfcomm;
	GIOChannel *sco;

	guint ring_timer;

	char buf[BUF_SIZE];
	int data_start;
	int data_length;

	hs_type type;

	headset_state_t state;
	struct pending_connect *pending_connect;
};

static DBusHandlerResult hs_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data);

static gboolean disable_hfp = FALSE;

static GIOChannel *hs_server = NULL;
static GIOChannel *hf_server = NULL;

static uint32_t hs_record_id = 0;
static uint32_t hf_record_id = 0;

static DBusConnection *connection = NULL;

static void pending_connect_free(struct pending_connect *c)
{
	if (c->io)
		g_io_channel_unref(c->io);
	if (c->msg)
		dbus_message_unref(c->msg);
	g_free(c);
}

static void hs_signal_gain_setting(audio_device_t *device, const char *buf)
{
	const char *name;
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

	gain = (dbus_uint16_t) strtol(&buf[5], NULL, 10);

	dbus_connection_emit_signal(connection, device->object_path,
					AUDIO_HEADSET_INTERFACE, name,
					DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);
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

static void close_sco(audio_device_t *device)
{
	struct headset *hs = device->headset;

	g_io_channel_close(hs->sco);
	g_io_channel_unref(hs->sco);
	hs->sco = NULL;
	assert(hs->rfcomm);
	hs->state = HEADSET_STATE_CONNECTED;
	dbus_connection_emit_signal(connection, device->object_path,
					AUDIO_HEADSET_INTERFACE, "Stopped",
					DBUS_TYPE_INVALID);
}

static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond,
				audio_device_t *device)
{
	struct headset *hs;
	unsigned char buf[BUF_SIZE];
	char *cr, rsp[BUF_SIZE];
	gsize bytes_read = 0;
	gsize free_space, count, bytes_written, total_bytes_written;
	GIOError err;
	off_t cmd_len;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

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
		hs_signal_gain_setting(device, &hs->buf[hs->data_start] + 2);
		break;

	case HEADSET_EVENT_KEYPRESS:
		if (hs->ring_timer) {
			g_source_remove(hs->ring_timer);
			hs->ring_timer = 0;
		}

		dbus_connection_emit_signal(connection, device->object_path,
						AUDIO_HEADSET_INTERFACE,
						"AnswerRequested",
						DBUS_TYPE_INVALID);
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
		close_sco(device);
	hs_disconnect(NULL, NULL, device);

	return FALSE;
}

static void send_cancel_auth(audio_device_t *device)
{
	DBusMessage *cancel;
	char addr[18], *address = addr;
	const char *uuid = HSP_AG_UUID;

	cancel = dbus_message_new_method_call("org.bluez", "/org/bluez",
						"org.bluez.Database",
						"CancelAuthorizationRequest");
	if (!cancel) {
		error("Unable to allocate new method call");
		return;
	}

	ba2str(&device->bda, addr);

	dbus_message_append_args(cancel, DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &uuid, DBUS_TYPE_INVALID);

	send_message_and_unref(connection, cancel);
}

static void auth_callback(DBusPendingCall *call, void *data)
{
	audio_device_t *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Access denied: %s", err.message);
		if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY)) {
			debug("Canceling authorization request");
			send_cancel_auth(device);
		}
		dbus_error_free(&err);
		g_io_channel_close(hs->rfcomm);
		g_io_channel_unref(hs->rfcomm);
		hs->rfcomm = NULL;
	} else {
		char hs_address[18];

		g_io_add_watch(hs->rfcomm, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) rfcomm_io_cb, device);

		ba2str(&device->bda, hs_address);

		debug("Accepted headset connection from %s for %s", hs_address,
				device->object_path);

		hs->state = HEADSET_STATE_CONNECTED;
		dbus_connection_emit_signal(connection, device->object_path,
						AUDIO_HEADSET_INTERFACE,
						"Connected",
						DBUS_TYPE_INVALID);
	}

	dbus_message_unref(reply);
}

static gboolean sco_cb(GIOChannel *chan, GIOCondition cond, audio_device_t *device)
{
	struct headset *hs;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

	error("Audio connection got disconnected");

	if (hs->sco)
		close_sco(device);

	return FALSE;
}

static gboolean sco_connect_cb(GIOChannel *chan, GIOCondition cond,
				audio_device_t *device)
{
	struct headset *hs = device->headset;
	int ret, sk, err, flags;
	socklen_t len;
	DBusMessage *reply;

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

	debug("SCO socket opened for headset %s", device->object_path);

	hs->sco = chan;
	hs->pending_connect->io = NULL;

	flags = G_IO_ERR | G_IO_HUP | G_IO_NVAL;

	g_io_add_watch(hs->sco, flags, (GIOFunc) sco_cb, device);

	reply = dbus_message_new_method_return(hs->pending_connect->msg);
	if (reply)
		send_message_and_unref(connection, reply);

	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	hs->state = HEADSET_STATE_PLAYING;
	dbus_connection_emit_signal(connection, device->object_path,
					AUDIO_HEADSET_INTERFACE,
					"Playing", DBUS_TYPE_INVALID);

	return FALSE;

failed:
	err_connect_failed(connection, hs->pending_connect->msg, err);
	if (hs->pending_connect->io)
		g_io_channel_close(hs->pending_connect->io);
	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	assert(hs->rfcomm);
	hs->state = HEADSET_STATE_CONNECTED;

	return FALSE;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond,
					audio_device_t *device)
{
	struct headset *hs = device->headset;
	char hs_address[18];
	int sk, ret, err;
	socklen_t len;
	
	if (cond & G_IO_NVAL)
		return FALSE;

	assert(hs != NULL);
       	assert(hs->pending_connect != NULL);
	assert(hs->rfcomm == NULL);
	assert(hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS);

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

	ba2str(&device->bda, hs_address);
	hs->rfcomm = chan;
	hs->pending_connect->io = NULL;

	hs->state = HEADSET_STATE_CONNECTED;
	dbus_connection_emit_signal(connection, device->object_path,
					AUDIO_HEADSET_INTERFACE,
					"Connected", DBUS_TYPE_INVALID);

	debug("Connected to %s", hs_address);

	g_io_add_watch(chan, G_IO_IN | G_IO_ERR | G_IO_HUP| G_IO_NVAL,
			(GIOFunc) rfcomm_io_cb, device);

	if (hs->pending_connect->msg) {
		DBusMessage *reply;

		reply = dbus_message_new_method_return(hs->pending_connect->msg);
		if (reply)
			send_message_and_unref(connection, reply);
	}

	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	return FALSE;

failed:
	err_connect_failed(connection, hs->pending_connect->msg, err);
	if (hs->pending_connect->io)
		g_io_channel_close(hs->pending_connect->io);
	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;

	hs->state = HEADSET_STATE_DISCONNECTED;

	return FALSE;
}

static int rfcomm_connect(audio_device_t *device, int *err)
{
	struct headset *hs = device->headset;
	struct sockaddr_rc addr;
	char address[18];
	int sk;

	assert(hs != NULL && hs->pending_connect != NULL && 
			hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS);

	hs->type = hs->hfp_handle ? SVC_HANDSFREE : SVC_HEADSET;

	ba2str(&device->bda, address);

	debug("Connecting to %s channel %d", address, hs->rfcomm_ch);

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
	bacpy(&addr.rc_bdaddr, &device->bda);
	addr.rc_channel = hs->rfcomm_ch;

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

		g_io_add_watch(hs->pending_connect->io, G_IO_OUT | G_IO_NVAL,
				(GIOFunc) rfcomm_connect_cb, device);
	} else {
		debug("Connect succeeded with first try");
		rfcomm_connect_cb(hs->pending_connect->io, G_IO_OUT, device);
	}

	return 0;

failed:
	if (!hs->pending_connect->io && sk >= 0)
		close(sk);

	return -1;
}

static int create_hsp_ag_record(sdp_buf_t *buf, uint8_t ch)
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

	sdp_set_info_attr(&record, "Headset Audio Gateway", 0, 0);

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

static int create_hfp_ag_record(sdp_buf_t *buf, uint8_t ch)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid, l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t record;
	uint16_t u16 = 0x0009;
	sdp_data_t *channel, *features;
	uint8_t netid =  0x01;
	sdp_data_t *network = sdp_data_alloc(SDP_UINT8, &netid);
	int ret;

	memset(&record, 0, sizeof(sdp_record_t));

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(&record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(&record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = 0x0105;
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

	features = sdp_data_alloc(SDP_UINT16, &u16);
	sdp_attr_add(&record, SDP_ATTR_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(&record, aproto);

	sdp_set_info_attr(&record, "Hands-Free Audio Gateway", 0, 0);

	sdp_attr_add(&record, SDP_ATTR_EXTERNAL_NETWORK, network);

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

static uint32_t headset_add_ag_record(uint8_t channel, sdp_buf_t *buf)
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

	dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&buf->data, buf->data_size, DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(connection, msg,
								-1, &derr);

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
	int array_len, record_len, err = EIO, ch = -1;
	sdp_record_t *record = NULL;
	sdp_list_t *protos, *classes = NULL;
	uuid_t uuid;
	audio_device_t *device = data;
	struct headset *hs = device->headset;
	struct pending_connect *c;

	assert(hs != NULL && hs->pending_connect && !hs->rfcomm);
	c = hs->pending_connect;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceRecord failed: %s", derr.message);
		dbus_error_free(&derr);
		goto failed_not_supported;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &array, &array_len,
				DBUS_TYPE_INVALID)) {
		error("Unable to get args from GetRecordReply");
		goto failed_not_supported;
	}

	if (!array) {
		error("Unable to get handle array from reply");
		goto failed_not_supported;
	}

	record = sdp_extract_pdu(array, &record_len);
	if (!record) {
		error("Unable to extract service record from reply");
		goto failed_not_supported;
	}

	if (record_len != array_len)
		debug("warning: array len (%d) != record len (%d)",
				array_len, record_len);

	if (sdp_get_service_classes(record, &classes) < 0) {
		error("Unable to get service classes from record");
		goto failed_not_supported;
	}

	memcpy(&uuid, classes->data, sizeof(uuid));

	if (!sdp_uuid128_to_uuid(&uuid)) {
		error("Not a 16 bit UUID");
		goto failed_not_supported;
	}

	if ((uuid.type == SDP_UUID32 && uuid.value.uuid32 != HEADSET_SVCLASS_ID) ||
			(uuid.type == SDP_UUID16 && uuid.value.uuid16 != HEADSET_SVCLASS_ID)) {
		error("Service classes did not contain the expected UUID");
		goto failed_not_supported;
	}

	if (!sdp_get_access_protos(record, &protos)) {
		ch = sdp_get_proto_port(protos, RFCOMM_UUID);
		sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
		sdp_list_free(protos, NULL);
		protos = NULL;
	}

	if (ch == -1) {
		error("Unable to extract RFCOMM channel from service record");
		goto failed_not_supported;
	}

	hs->rfcomm_ch = ch;

	if (rfcomm_connect(device, &err) < 0) {
		error("Unable to connect");
		if (c->msg) 
			err_connect_failed(connection, c->msg, err);
		goto failed;
	}

	sdp_list_free(classes, free);
	sdp_record_free(record);
	dbus_message_unref(reply);

	finish_sdp_transaction(connection, &device->bda);

	return;

failed_not_supported:
	if (c->msg) 
		err_not_supported(connection, c->msg);
failed:
	if (classes)
		sdp_list_free(classes, free);
	if (record)
		sdp_record_free(record);
	if (reply)
		dbus_message_unref(reply);
	pending_connect_free(hs->pending_connect);
	hs->pending_connect = NULL;
	hs->state = HEADSET_STATE_DISCONNECTED;
	finish_sdp_transaction(connection, &device->bda);
}

static DBusHandlerResult hs_stop(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	audio_device_t *device = data;
	struct headset *hs = device->headset;
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

	close_sco(device);

	if (reply)
		send_message_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_is_playing(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	audio_device_t *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_bool_t playing;

	assert(hs);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->state == HEADSET_STATE_PLAYING)
		playing = TRUE;
	else
		playing = FALSE;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &playing,
					DBUS_TYPE_INVALID);

	send_message_and_unref(connection, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	audio_device_t *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;
	char hs_address[18];

	assert(hs);

	if (msg) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	if (hs->state > HEADSET_STATE_CONNECTED)
		hs_stop(NULL, NULL, device);

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

	ba2str(&device->bda, hs_address);
	info("Disconnected from %s, %s", hs_address, device->object_path);

	dbus_connection_emit_signal(connection, device->object_path,
					AUDIO_HEADSET_INTERFACE,
					"Disconnected", DBUS_TYPE_INVALID);

	hs->data_start = 0;
	hs->data_length = 0;

	if (reply)
		send_message_and_unref(connection, reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_is_connected(DBusConnection *conn, DBusMessage *msg,
						void *data)
{
	audio_device_t *device = data;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	connected = headset_is_connected(device->headset);

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
	audio_device_t *device = data;
	struct headset *hs = device->headset;
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

	ba2str(&device->bda, address);

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

	dbus_pending_call_set_notify(pending, get_record_reply, device, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);
	dbus_message_unref(reply);

	return;

failed:
	if (msg)
		dbus_message_unref(msg);
	dbus_message_unref(reply);
	hs_disconnect(NULL, NULL, hs);
}

static DBusHandlerResult hs_connect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	DBusPendingCall *pending;
	audio_device_t *device = data;
	struct headset *hs = device->headset;
	const char *hs_svc = "hsp";
	const char *addr_ptr;
	char hs_address[18];
	int err;

	assert(hs != NULL);

	if (hs->state > HEADSET_STATE_DISCONNECTED || hs->pending_connect)
		return err_already_connected(connection, msg);

	hs->pending_connect = g_try_new0(struct pending_connect, 1);
	if (!hs->pending_connect) {
		error("Out of memory when allocating new struct pending_connect");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	hs->state = HEADSET_STATE_CONNECT_IN_PROGRESS;

	hs->pending_connect->msg = msg ? dbus_message_ref(msg) : NULL;

	if (hs->rfcomm_ch > 0) {
	       	if (rfcomm_connect(device, &err) < 0) {
			error("Unable to connect");
			pending_connect_free(hs->pending_connect);
			hs->pending_connect = NULL;
			hs->state = HEADSET_STATE_DISCONNECTED;
			return err_connect_failed(conn, msg, err);
		} else
			return DBUS_HANDLER_RESULT_HANDLED;
	}

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

	ba2str(&device->bda, hs_address);
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

	dbus_pending_call_set_notify(pending, get_handles_reply, device, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;;
}

static GIOError headset_send_ring(audio_device_t *device)
{
	struct headset *hs = device->headset;
	const char *ring_str = "\r\nRING\r\n";
	GIOError err;
	gsize total_written, written, count;

	assert(hs != NULL);
	if (hs->state < HEADSET_STATE_CONNECTED || !hs->rfcomm) {
		error("the headset %s is not connected", device->object_path);
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
	audio_device_t *device = data;

	assert(device != NULL);

	if (headset_send_ring(device) != G_IO_ERROR_NONE)
		error("Sending RING failed");

	return TRUE;
}

static DBusHandlerResult hs_ring(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	audio_device_t *device = data;
	struct headset *hs = device->headset;
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

	if (headset_send_ring(device) != G_IO_ERROR_NONE) {
		dbus_message_unref(reply);
		return err_failed(connection, msg, "Failed");
	}

	hs->ring_timer = g_timeout_add(RING_INTERVAL, ring_timer_cb, device);

done:
	if (reply)
		send_message_and_unref(connection, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_cancel_ringing(DBusConnection *conn, DBusMessage *msg,
						void *data)
{
	audio_device_t *device = data;
	struct headset *hs = device->headset;
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

static DBusHandlerResult hs_play(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	audio_device_t *device = data;
	struct headset *hs = device->headset;
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
	bacpy(&addr.sco_bdaddr, &device->bda);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect: %s (%d)", strerror(errno), errno);
			goto failed;
		}

		debug("Connect in progress");

		g_io_add_watch(c->io, G_IO_OUT | G_IO_NVAL,
				(GIOFunc) sco_connect_cb, device);
	} else {
		debug("Connect succeeded with first try");
		sco_connect_cb(c->io, G_IO_OUT, device);
	}

	hs->pending_connect = c;

	return 0;

failed:
	if (c)
		pending_connect_free(c);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusMethodVTable headset_methods[] = {
	{ "Connect",		hs_connect,		"",	""	},
	{ "Disconnect",		hs_disconnect,		"",	""	},
	{ "IsConnected",	hs_is_connected,	"",	"b"	},
	{ "IndicateCall",	hs_ring,		"",	""	},
	{ "CancelCall",		hs_cancel_ringing,	"",	""	},
	{ "Play",		hs_play,		"",	""	},
	{ "Stop",		hs_stop,		"",	""	},
	{ "IsPlaying",		hs_is_playing,		"",	"b"	},
	{ NULL, NULL, NULL, NULL }
};

static DBusSignalVTable headset_signals[] = {
	{ "Connected",			""	},
	{ "Disconnected",		""	},
	{ "AnswerRequested",		""	},
	{ "Stopped",			""	},
	{ "Playing",			""	},
	{ "SpeakerGainChanged",		"q"	},
	{ "MicrophoneGainChanged",	"q"	},
	{ NULL, NULL }
};

static void headset_set_channel(headset_t *headset, sdp_record_t *record)
{
	int ch;
	sdp_list_t *protos;

	if (sdp_get_access_protos(record, &protos) < 0) {
		error("Unable to get access protos from headset record");
		return;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);

	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch > 0) {
		headset->rfcomm_ch = ch;
		debug("Discovered Headset service on RFCOMM channel %d", ch);
	} else
		error("Unable to get RFCOMM channel from Headset record");
}

void headset_update(headset_t *headset, sdp_record_t *record, uint16_t svc)
{
	switch (svc) {
	case HANDSFREE_SVCLASS_ID:
		if (disable_hfp) {
			debug("Ignoring Handsfree record since HFP support"
					" has been disabled");
			return;
		}

		if (headset->hfp_handle &&
				(headset->hfp_handle != record->handle)) {
			error("More than one HFP record found on device");
			return;
		}

		headset->hfp_handle = record->handle;
		break;

	case HEADSET_SVCLASS_ID:
		if (headset->hsp_handle &&
				(headset->hsp_handle != record->handle)) {
			error("More than one HSP record found on device");
			return;
		}

		headset->hsp_handle = record->handle;

		/* Ignore this record if we already have access to HFP */
		if (headset->hfp_handle)
			return;

		break;

	default:
		debug("Invalid record passed to headset_update");
		return;
	}

	headset_set_channel(headset, record);
}

headset_t *headset_init(const char *object_path, sdp_record_t *record,
			uint16_t svc)
{
	headset_t *headset;

	headset = g_new0(headset_t, 1);
	headset->rfcomm_ch = -1;

	if (!record)
		goto register_iface;

	switch (svc) {
	case HANDSFREE_SVCLASS_ID:
		if (disable_hfp) {
			debug("Ignoring Handsfree record since HFP support"
				       " has been disabled");
			g_free(headset);
			return NULL;
		}

		headset->hfp_handle = record->handle;
		break;

	case HEADSET_SVCLASS_ID:
		headset->hsp_handle = record->handle;
		break;

	default:
		debug("Invalid record passed to headset_init");
		g_free(headset);
		return NULL;
	}

register_iface:
	if (!dbus_connection_register_interface(connection, object_path,
							AUDIO_HEADSET_INTERFACE,
							headset_methods,
							headset_signals, NULL)) {
		g_free(headset);
		return NULL;
	}

	if (record)
		headset_set_channel(headset, record);

	return headset;
}

void headset_free(const char *object_path)
{ 
	audio_device_t *device;

	if (!dbus_connection_get_object_user_data(connection, object_path,
						(void *) &device))
		return;

	if (device->headset->state != HEADSET_STATE_DISCONNECTED)
		hs_disconnect(NULL, NULL, device);

	g_free(device->headset);
	device->headset = NULL;
}

static gboolean headset_server_io_cb(GIOChannel *chan, GIOCondition cond, void *data)
{
	int srv_sk, cli_sk;
	struct sockaddr_rc addr;
	socklen_t size;
	char hs_address[18], *address = hs_address;
	const char *uuid = HSP_AG_UUID;
	audio_device_t *device;
	struct headset *hs;
	DBusMessage *auth;
	DBusPendingCall *pending;

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

	device = manager_headset_connected(&addr.rc_bdaddr);
	if (!device) {
		close(cli_sk);
		return TRUE;
	}

	hs = device->headset;

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

	if (chan == hs_server)
		hs->type = SVC_HEADSET;
	else
		hs->type = SVC_HANDSFREE;

	auth = dbus_message_new_method_call("org.bluez", "/org/bluez", "org.bluez.Database",
						"RequestAuthorization");
	if (!auth) {
		error("Unable to allocat new RequestAuthorization method call");
		goto failed;
	}

	ba2str(&device->bda, hs_address);

	dbus_message_append_args(auth, DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &uuid, DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, auth, &pending, -1) == FALSE) {
		error("Sending of authorization request failed");
		goto failed;
	}

	dbus_pending_call_set_notify(pending, auth_callback, device, NULL);
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
	addr.rc_channel = channel ? *channel : 0;

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

gboolean headset_is_connected(headset_t *headset)
{
	if (headset->state >= HEADSET_STATE_CONNECTED)
		return TRUE;
	else
		return FALSE;
}

int headset_server_init(DBusConnection *conn, gboolean no_hfp,
			gboolean sco_hci)
{
	uint8_t chan = DEFAULT_HS_AG_CHANNEL;
	sdp_buf_t buf;

	connection = dbus_connection_ref(conn);

	hs_server = server_socket(&chan);
	if (!hs_server)
		return -1;

	if (create_hsp_ag_record(&buf, chan) < 0) {
		error("Unable to allocate new service record");
		return -1;
	}

	hs_record_id = headset_add_ag_record(chan, &buf);
	free(buf.data);
	if (!hs_record_id) {
		error("Unable to register HS AG service record");
		g_io_channel_unref(hs_server);
		hs_server = NULL;
		return -1;
	}

	g_io_add_watch(hs_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) headset_server_io_cb, NULL);

	disable_hfp = no_hfp;

	if (disable_hfp)
		return 0;

	chan = DEFAULT_HF_AG_CHANNEL;

	hf_server = server_socket(&chan);
	if (!hf_server)
		return -1;

	if (create_hfp_ag_record(&buf, chan) < 0) {
		error("Unable to allocate new service record");
		return -1;
	}

	hf_record_id = headset_add_ag_record(chan, &buf);
	free(buf.data);
	if (!hf_record_id) {
		error("Unable to register HS AG service record");
		g_io_channel_unref(hf_server);
		hs_server = NULL;
		return -1;
	}

	g_io_add_watch(hf_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
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

	if (hf_record_id) {
		headset_remove_ag_record(hf_record_id);
		hf_record_id = 0;
	}

	if (hf_server) {
		g_io_channel_unref(hf_server);
		hf_server = NULL;
	}

	dbus_connection_unref(connection);
	connection = NULL;
}
