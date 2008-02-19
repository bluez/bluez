/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
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

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"
#include "device.h"
#include "manager.h"
#include "error.h"
#include "headset.h"

#define RING_INTERVAL 3000

#define BUF_SIZE 1024

#define HEADSET_GAIN_SPEAKER 'S'
#define HEADSET_GAIN_MICROPHONE 'M'

#define AG_FEATURE_THREE_WAY_CALLING             0x0001
#define AG_FEATURE_EC_ANDOR_NR                   0x0002
#define AG_FEATURE_VOICE_RECOGNITION             0x0004
#define AG_FEATURE_INBAND_RINGTONE               0x0008
#define AG_FEATURE_ATTACH_NUMBER_TO_VOICETAG     0x0010
#define AG_FEATURE_REJECT_A_CALL                 0x0020
#define AG_FEATURE_ENHANCES_CALL_STATUS          0x0040
#define AG_FEATURE_ENHANCES_CALL_CONTROL         0x0080
#define AG_FEATURE_EXTENDED_ERROR_RESULT_CODES   0x0100

static uint32_t ag_features = 0;

static gboolean sco_hci = TRUE;

static char *str_state[] = {
	"HEADSET_STATE_DISCONNECTED",
	"HEADSET_STATE_CONNECT_IN_PROGRESS",
	"HEADSET_STATE_CONNECTED",
	"HEADSET_STATE_PLAY_IN_PROGRESS",
	"HEADSET_STATE_PLAYING",
};

struct connect_cb {
	unsigned int id;
	headset_stream_cb_t cb;
	void *cb_data;
};

struct pending_connect {
	DBusMessage *msg;
	DBusPendingCall *call;
	GIOChannel *io;
	int err;
	headset_state_t target_state;
	GSList *callbacks;
};

struct headset {
	uint32_t hsp_handle;
	uint32_t hfp_handle;

	int rfcomm_ch;

	GIOChannel *rfcomm;
	GIOChannel *tmp_rfcomm;
	GIOChannel *sco;
	guint sco_id;

	gboolean auto_dc;

	guint ring_timer;

	char buf[BUF_SIZE];
	int data_start;
	int data_length;

	gboolean hfp_active;
	gboolean search_hfp;
	gboolean cli_active;
	char *ph_number;
	int type;

	headset_state_t state;
	struct pending_connect *pending;

	int sp_gain;
	int mic_gain;

	unsigned int hfp_features;
	headset_lock_t lock;
};

struct event {
	const char *cmd;
	int (*callback) (struct device *device, const char *buf);
};

static int rfcomm_connect(struct device *device, headset_stream_cb_t cb,
				void *user_data, unsigned int *cb_id);
static int get_handles(struct device *device, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id);

static int headset_send(struct headset *hs, char *format, ...)
{
	char rsp[BUF_SIZE];
	va_list ap;
	ssize_t total_written, written, count;
	int fd;

	va_start(ap, format);
	count = vsnprintf(rsp, sizeof(rsp), format, ap);
	va_end(ap);

	if (count < 0)
		return -EINVAL;

	if (!hs->rfcomm) {
		error("headset_send: the headset is not connected");
		return -EIO;
	}

	written = total_written = 0;
	fd = g_io_channel_unix_get_fd(hs->rfcomm);

	while (total_written < count) {
		written = write(fd, rsp + total_written, count - total_written);
		if (written < 0)
			return -errno;

		total_written += written;
	}

	return 0;
}

static int supported_features(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;
	int err;

	if (strlen(buf) < 9)
		return -EINVAL;

	hs->hfp_features = strtoul(&buf[8], NULL, 10);
	err = headset_send(hs, "\r\n+BRSF=%u\r\n", ag_features);
	if (err < 0)
		return err;

	return headset_send(hs, "\r\nOK\r\n");
}

static int report_indicators(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;
	int err;

	if (buf[7] == '=')
		err = headset_send(hs, "\r\n+CIND:(\"service\",(0,1)),"
				"(\"call\",(0,1)),(\"callsetup\",(0-3))\r\n");
	else
		err = headset_send(hs, "\r\n+CIND:1,0,0\r\n");

	if (err < 0)
		return err;

	return headset_send(hs, "\r\nOK\r\n");
}

static void pending_connect_complete(struct connect_cb *cb, struct device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->pending->err)
		cb->cb(NULL, cb->cb_data);
	else
		cb->cb(dev, cb->cb_data);
}

static void pending_connect_finalize(struct device *dev)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	g_slist_foreach(p->callbacks, (GFunc) pending_connect_complete, dev);

	g_slist_foreach(p->callbacks, (GFunc) g_free, NULL);
	g_slist_free(p->callbacks);

	if (p->io) {
		g_io_channel_close(p->io);
		g_io_channel_unref(p->io);
	}

	if (p->msg)
		dbus_message_unref(p->msg);

	if (p->call) {
		dbus_pending_call_cancel(p->call);
		dbus_pending_call_unref(p->call);
	}

	g_free(p);

	hs->pending = NULL;
}

static void pending_connect_init(struct headset *hs, headset_state_t target_state)
{
	if (hs->pending) {
		if (hs->pending->target_state < target_state)
			hs->pending->target_state = target_state;
		return;
	}

	hs->pending = g_new0(struct pending_connect, 1);
	hs->pending->target_state = target_state;
}

static unsigned int connect_cb_new(struct headset *hs,
					headset_state_t target_state,
					headset_stream_cb_t func,
					void *user_data)
{
	struct connect_cb *cb;
	unsigned int free_cb_id = 1;

	pending_connect_init(hs, target_state);

	cb = g_new(struct connect_cb, 1);

	cb->cb = func;
	cb->cb_data = user_data;
	cb->id = free_cb_id++;

	hs->pending->callbacks = g_slist_append(hs->pending->callbacks,
						cb);

	return cb->id;
}

static gboolean sco_connect_cb(GIOChannel *chan, GIOCondition cond,
				struct device *device)
{
	struct headset *hs;
	int ret, sk;
	socklen_t len;
	struct pending_connect *p;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;
	p = hs->pending;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		p->err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(p->err),
				p->err);
		goto failed;
	}

	if (ret != 0) {
		p->err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	debug("SCO socket opened for headset %s", device->path);

	info("SCO fd=%d", sk);
	hs->sco = chan;
	p->io = NULL;

	pending_connect_finalize(device);

	fcntl(sk, F_SETFL, 0);

	headset_set_state(device, HEADSET_STATE_PLAYING);

	return FALSE;

failed:
	pending_connect_finalize(device);
	if (hs->rfcomm)
		headset_set_state(device, HEADSET_STATE_CONNECTED);
	else
		headset_set_state(device, HEADSET_STATE_DISCONNECTED);

	return FALSE;
}

static int sco_connect(struct device *dev, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id)
{
	struct headset *hs = dev->headset;
	struct sockaddr_sco addr;
	GIOChannel *io;
	int sk, err;

	if (hs->state != HEADSET_STATE_CONNECTED)
		return -EINVAL;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		return -err;
	}

	io = g_io_channel_unix_new(sk);
	if (!io) {
		close(sk);
		return -ENOMEM;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, BDADDR_ANY);

	if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		goto failed;
	}

	if (set_nonblocking(sk) < 0) {
		err = errno;
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, &dev->dst);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));

	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) {
		err = errno;
		error("connect: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	headset_set_state(dev, HEADSET_STATE_PLAY_IN_PROGRESS);

	pending_connect_init(hs, HEADSET_STATE_PLAYING);

	if (cb) {
		unsigned int id = connect_cb_new(hs, HEADSET_STATE_PLAYING,
							cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	g_io_add_watch(io, G_IO_OUT | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
			(GIOFunc) sco_connect_cb, dev);

	hs->pending->io = io;

	return 0;

failed:
	g_io_channel_close(io);
	g_io_channel_unref(io);
	return -err;
}

static void hfp_slc_complete(struct device *dev)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	debug("HFP Service Level Connection established");

	headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (p == NULL)
		return;

	if (p->msg) {
		DBusMessage *reply = dbus_message_new_method_return(p->msg);
		send_message_and_unref(dev->conn, reply);
	}

	if (p->target_state == HEADSET_STATE_CONNECTED) {
		pending_connect_finalize(dev);
		return;
	}

	p->err = sco_connect(dev, NULL, NULL, NULL);
	if (p->err < 0)
		pending_connect_finalize(dev);
}

static int event_reporting(struct device *dev, const char *buf)
{
	struct headset *hs = dev->headset;
	int ret;

	ret = headset_send(hs, "\r\nOK\r\n");
	if (ret < 0)
		return ret;

	if (hs->state != HEADSET_STATE_CONNECT_IN_PROGRESS)
		return 0;

	if (ag_features & AG_FEATURE_THREE_WAY_CALLING)
		return 0;

	hfp_slc_complete(dev);

	return 0;
}

static int call_hold(struct device *dev, const char *buf)
{
	struct headset *hs = dev->headset;
	int err;

	err = headset_send(hs, "\r\n+CHLD:(0,1,1x,2,2x,3,4)\r\n");
	if (err < 0)
		return err;

	err = headset_send(hs, "\r\nOK\r\n");
	if (err < 0)
		return err;

	if (hs->state != HEADSET_STATE_CONNECT_IN_PROGRESS)
		return 0;

	hfp_slc_complete(dev);

	return 0;
}

static int answer_call(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;
	int err;

	dbus_connection_emit_signal(device->conn, device->path,
			AUDIO_HEADSET_INTERFACE, "AnswerRequested",
			DBUS_TYPE_INVALID);

	if (hs->ring_timer) {
		g_source_remove(hs->ring_timer);
		hs->ring_timer = 0;
	}

	if (!hs->hfp_active)
		return headset_send(hs, "\r\nOK\r\n");

	if (hs->ph_number) {
		g_free(hs->ph_number);
		hs->ph_number = NULL;
	}

	err = headset_send(hs, "\r\nOK\r\n");
	if (err < 0)
		return err;

	/*+CIEV: (call = 1)*/
	err = headset_send(hs, "\r\n+CIEV:2,1\r\n");
	if (err < 0)
		return err;

	/*+CIEV: (callsetup = 0)*/
	return headset_send(hs, "\r\n+CIEV:3,0\r\n");
}

static int terminate_call(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;
	int err;

	dbus_connection_emit_signal(device->conn, device->path,
			AUDIO_HEADSET_INTERFACE, "CallTerminated",
			DBUS_TYPE_INVALID);

	err = headset_send(hs, "\r\nOK\r\n");
	if (err < 0)
		return err;

	if (hs->ph_number) {
		g_free(hs->ph_number);
		hs->ph_number = NULL;
	}

	if (hs->ring_timer) {
		g_source_remove(hs->ring_timer);
		hs->ring_timer = 0;
		/*+CIEV: (callsetup = 0)*/
		return headset_send(hs, "\r\n+CIEV:3,0\r\n");
	}

	/*+CIEV: (call = 0)*/
	return headset_send(hs, "\r\n+CIEV:2,0\r\n");
}

static int cli_notification(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;

	if (strlen(buf) < 9)
		return -EINVAL;

	hs->cli_active = buf[8] == '1' ? TRUE : FALSE;

	return headset_send(hs, "\r\nOK\r\n");
}

static int signal_gain_setting(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;
	const char *name;
	dbus_uint16_t gain;

	if (strlen(buf) < 8) {
		error("Too short string for Gain setting");
		return -EINVAL;
	}

	gain = (dbus_uint16_t) strtol(&buf[7], NULL, 10);

	if (gain > 15) {
		error("Invalid gain value received: %u", gain);
		return -EINVAL;
	}

	switch (buf[5]) {
	case HEADSET_GAIN_SPEAKER:
		if (hs->sp_gain == gain)
			goto ok;
		name = "SpeakerGainChanged";
		hs->sp_gain = gain;
		break;
	case HEADSET_GAIN_MICROPHONE:
		if (hs->mic_gain == gain)
			goto ok;
		name = "MicrophoneGainChanged";
		hs->mic_gain = gain;
		break;
	default:
		error("Unknown gain setting");
		return -EINVAL;
	}

	dbus_connection_emit_signal(device->conn, device->path,
				    AUDIO_HEADSET_INTERFACE, name,
				    DBUS_TYPE_UINT16, &gain,
				    DBUS_TYPE_INVALID);

ok:
	return headset_send(hs, "\r\nOK\r\n");
}

static struct event event_callbacks[] = {
	{ "ATA", answer_call },
	{ "AT+VG", signal_gain_setting },
	{ "AT+BRSF", supported_features },
	{ "AT+CIND", report_indicators },
	{ "AT+CMER", event_reporting },
	{ "AT+CHLD", call_hold },
	{ "AT+CHUP", terminate_call },
	{ "AT+CKPD", answer_call },
	{ "AT+CLIP", cli_notification },
	{ 0 }
};

static int handle_event(struct device *device, const char *buf)
{
	struct event *ev;

	debug("Received %s", buf);

	for (ev = event_callbacks; ev->cmd; ev++) {
		if (!strncmp(buf, ev->cmd, strlen(ev->cmd)))
			return ev->callback(device, buf);
	}

	return -EINVAL;
}

static void close_sco(struct device *device)
{
	struct headset *hs = device->headset;

	if (hs->sco) {
		g_source_remove(hs->sco_id);
		hs->sco_id = 0;
		g_io_channel_close(hs->sco);
		g_io_channel_unref(hs->sco);
		hs->sco = NULL;
	}
}

static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond,
				struct device *device)
{
	struct headset *hs;
	unsigned char buf[BUF_SIZE];
	char *cr;
	gsize bytes_read = 0;
	gsize free_space;
	int err;
	off_t cmd_len;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

	if (cond & (G_IO_ERR | G_IO_HUP))
		goto failed;

	if (g_io_channel_read(chan, (gchar *) buf, sizeof(buf) - 1,
				&bytes_read) != G_IO_ERROR_NONE)
		return TRUE;

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

	cmd_len = 1 + (off_t) cr - (off_t) &hs->buf[hs->data_start];
	*cr = '\0';

	err = handle_event(device, &hs->buf[hs->data_start]);
	if (err == -EINVAL) {
		error("Badly formated or unrecognized command: %s",
				&hs->buf[hs->data_start]);
		err = headset_send(hs, "\r\nERROR\r\n");
	} else if (err < 0)
		error("Error handling command %s: %s (%d)",
			&hs->buf[hs->data_start], strerror(-err), -err);

	hs->data_start += cmd_len;
	hs->data_length -= cmd_len;

	if (!hs->data_length)
		hs->data_start = 0;

	return TRUE;

failed:
	headset_set_state(device, HEADSET_STATE_DISCONNECTED);

	return FALSE;
}

static gboolean sco_cb(GIOChannel *chan, GIOCondition cond,
			struct device *device)
{
	struct headset *hs;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

	error("Audio connection got disconnected");

	headset_set_state(device, HEADSET_STATE_CONNECTED);

	return FALSE;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond,
					struct device *dev)
{
	struct headset *hs;
	struct pending_connect *p;
	char hs_address[18];
	int sk, ret;
	socklen_t len;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = dev->headset;
	p = hs->pending;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		p->err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(p->err), p->err);
		goto failed;
	}

	if (ret != 0) {
		p->err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	ba2str(&dev->dst, hs_address);
	hs->rfcomm = chan;
	p->io = NULL;

	if (server_is_enabled(HANDSFREE_SVCLASS_ID) && hs->hfp_handle != 0)
		hs->hfp_active = TRUE;
	else
		hs->hfp_active = FALSE;

	g_io_add_watch(chan, G_IO_IN | G_IO_ERR | G_IO_HUP| G_IO_NVAL,
			(GIOFunc) rfcomm_io_cb, dev);

	debug("%s: Connected to %s", dev->path, hs_address);

	/* In HFP mode wait for Service Level Connection */
	if (hs->hfp_active)
		return FALSE;

	headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (p->target_state == HEADSET_STATE_PLAYING) {
		p->err = sco_connect(dev, NULL, NULL, NULL);
		if (p->err < 0)
			goto failed;
		return FALSE;
	}

	if (p->msg) {
		DBusMessage *reply = dbus_message_new_method_return(p->msg);
		send_message_and_unref(dev->conn, reply);
	}

	pending_connect_finalize(dev);

	return FALSE;

failed:
	if (p->msg)
		error_connection_attempt_failed(dev->conn, p->msg, p->err);
	pending_connect_finalize(dev);
	if (hs->rfcomm)
		headset_set_state(dev, HEADSET_STATE_CONNECTED);
	else
		headset_set_state(dev, HEADSET_STATE_DISCONNECTED);

	return FALSE;
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
	struct device *dev = data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceRecord failed: %s", derr.message);
		dbus_error_free(&derr);
		goto failed_not_supported;
	}

	dbus_error_init(&derr);
	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&array, &array_len,
				DBUS_TYPE_INVALID)) {
		error("Unable to get args from GetRecordReply: %s", derr.message);
		dbus_error_free(&derr);
		goto failed_not_supported;
	}

	if (!array) {
		error("get_record_reply: Unable to get handle array from reply");
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

	if (!sdp_uuid128_to_uuid(&uuid) || uuid.type != SDP_UUID16) {
		error("Not a 16 bit UUID");
		goto failed_not_supported;
	}

	if (hs->search_hfp) {
		if (uuid.value.uuid16 != HANDSFREE_SVCLASS_ID) {
			error("Service record didn't contain the HFP UUID");
			goto failed_not_supported;
		}
		hs->hfp_handle = record->handle;
	} else {
		if (uuid.value.uuid16 != HEADSET_SVCLASS_ID) {
			error("Service record didn't contain the HSP UUID");
			goto failed_not_supported;
		}
		hs->hsp_handle = record->handle;
	}

	if (!sdp_get_access_protos(record, &protos)) {
		ch = sdp_get_proto_port(protos, RFCOMM_UUID);
		sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free,
					NULL);
		sdp_list_free(protos, NULL);
		protos = NULL;
	}

	if (ch == -1) {
		error("Unable to extract RFCOMM channel from service record");
		goto failed_not_supported;
	}

	hs->rfcomm_ch = ch;

	err = rfcomm_connect(dev, NULL, NULL, NULL);
	if (err < 0) {
		error("Unable to connect: %s (%s)", strerror(-err), -err);
		p->err = -err;
		error_connection_attempt_failed(dev->conn, p->msg, p->err);
		goto failed;
	}

	sdp_list_free(classes, free);
	sdp_record_free(record);
	dbus_message_unref(reply);

	device_finish_sdp_transaction(dev);

	return;

failed_not_supported:
	if (p->msg) {
		error_not_supported(dev->conn, p->msg);
		dbus_message_unref(p->msg);
		p->msg = NULL;
	}
failed:
	if (classes)
		sdp_list_free(classes, free);
	if (record)
		sdp_record_free(record);
	if (reply)
		dbus_message_unref(reply);
	pending_connect_finalize(dev);
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
	device_finish_sdp_transaction(dev);
}

static void get_handles_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *msg = NULL, *reply;
	DBusPendingCall *pending;
	DBusError derr;
	struct device *dev = data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;
	char address[18], *addr_ptr = address;
	dbus_uint32_t *array = NULL;
	dbus_uint32_t handle;
	int array_len;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceHandles failed: %s", derr.message);
		if (p->msg) {
			if (dbus_error_has_name(&derr,
						"org.bluez.Error.ConnectionAttemptFailed"))
				error_connection_attempt_failed(dev->conn, p->msg,
								EHOSTDOWN);
			else
				error_not_supported(dev->conn, p->msg);
		}
		dbus_error_free(&derr);
		goto failed;
	}

	dbus_error_init(&derr);
	if (!dbus_message_get_args(reply, &derr,
				DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
				&array, &array_len,
				DBUS_TYPE_INVALID)) {
		error("Unable to get args from reply: %s", derr.message);
		dbus_error_free(&derr);
		if (p->msg)
			error_not_supported(dev->conn, p->msg);
		goto failed;
	}

	if (!array) {
		error("get_handles_reply: Unable to get handle array from reply");
		if (p->msg)
			error_not_supported(dev->conn, p->msg);
		goto failed;
	}

	if (array_len < 1) {
		if (hs->search_hfp) {
			debug("No record handles found for hfp");
			hs->search_hfp = FALSE;
			get_handles(dev, NULL, NULL, NULL);
			dbus_message_unref(reply);
			return;
		}

		debug("No record handles found for hsp");

		if (p->msg)
			error_not_supported(dev->conn, p->msg);
		goto failed;
	}

	if (array_len > 1)
		debug("Multiple records found. Using the first one.");

	msg = dbus_message_new_method_call("org.bluez", dev->adapter_path,
						"org.bluez.Adapter",
						"GetRemoteServiceRecord");
	if (!msg) {
		error("Unable to allocate new method call");
		if (p->msg)
			error_out_of_memory(dev->conn, p->msg);
		goto failed;
	}

	ba2str(&dev->dst, address);

	handle = array[0];

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_UINT32, &handle,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(dev->conn, msg, &pending, -1)) {
		error("Sending GetRemoteServiceRecord failed");
		if (p->msg)
			error_connection_attempt_failed(dev->conn, p->msg, EIO);
		goto failed;
	}

	dbus_pending_call_set_notify(pending, get_record_reply, dev, NULL);
	dbus_pending_call_unref(pending);
	dbus_message_unref(msg);
	dbus_message_unref(reply);

	return;

failed:
	if (msg)
		dbus_message_unref(msg);
	dbus_message_unref(reply);
	p->err = EIO;
	pending_connect_finalize(dev);
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

static int get_handles(struct device *device, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id)
{
	DBusPendingCall *pending;
	struct headset *hs = device->headset;
	const char *hs_svc;
	const char *addr_ptr;
	char hs_address[18];
	DBusMessage *msg;

	msg = dbus_message_new_method_call("org.bluez", device->adapter_path,
						"org.bluez.Adapter",
						"GetRemoteServiceHandles");
	if (!msg) {
		error("Could not create a new dbus message");
		return -ENOMEM;
	}

	if (hs->search_hfp)
		hs_svc = "hfp";
	else
		hs_svc = "hsp";

	ba2str(&device->dst, hs_address);
	addr_ptr = hs_address;
	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_STRING, &hs_svc,
					DBUS_TYPE_INVALID);

	headset_set_state(device, HEADSET_STATE_CONNECT_IN_PROGRESS);
	if (!dbus_connection_send_with_reply(device->conn, msg, &pending, -1)) {
		error("Sending GetRemoteServiceHandles failed");
		dbus_message_unref(msg);
		return -EIO;
	}

	pending_connect_init(hs, HEADSET_STATE_CONNECTED);

	if (cb) {
		unsigned int id;
		id = connect_cb_new(hs, HEADSET_STATE_CONNECTED,
					cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	dbus_pending_call_set_notify(pending, get_handles_reply, device, NULL);

	if (hs->pending)
		hs->pending->call = pending;
	else
		dbus_pending_call_unref(pending);

	dbus_message_unref(msg);

	return 0;
}

static int rfcomm_connect(struct device *dev, headset_stream_cb_t cb,
				void *user_data, unsigned int *cb_id)
{
	struct headset *hs = dev->headset;
	struct sockaddr_rc addr;
	GIOChannel *io;
	char address[18];
	int sk, err;

	if (hs->rfcomm_ch < 0)
		return get_handles(dev, cb, user_data, cb_id);

	ba2str(&dev->dst, address);

	debug("%s: Connecting to %s channel %d", dev->path, address,
		hs->rfcomm_ch);

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		err = errno;
		error("socket(BTPROTO_RFCOMM): %s (%d)", strerror(err), err);
		return -err;
	}

	io = g_io_channel_unix_new(sk);
	if (!io) {
		close(sk);
		return -ENOMEM;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = 0;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = errno;
		error("bind: %s (%d)", strerror(errno), errno);
		goto failed;
	}

	if (set_nonblocking(sk) < 0) {
		err = errno;
		goto failed;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &dev->dst);
	addr.rc_channel = hs->rfcomm_ch;

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));

	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) {
		err = errno;
		error("connect() failed: %s (%d)", strerror(err), err);
		goto failed;
	}

	headset_set_state(dev, HEADSET_STATE_CONNECT_IN_PROGRESS);

	pending_connect_init(hs, HEADSET_STATE_CONNECTED);

	if (cb) {
		unsigned int id = connect_cb_new(hs, HEADSET_STATE_CONNECTED,
							cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	g_io_add_watch(io, G_IO_OUT | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
			(GIOFunc) rfcomm_connect_cb, dev);

	hs->pending->io = io;

	return 0;

failed:
	g_io_channel_close(io);
	g_io_channel_unref(io);
	return -err;
}

static DBusHandlerResult hs_stop(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->state < HEADSET_STATE_PLAY_IN_PROGRESS)
		return error_not_connected(conn, msg);

	headset_set_state(device, HEADSET_STATE_CONNECTED);
	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_is_playing(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_bool_t playing;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	playing = (hs->state == HEADSET_STATE_PLAYING);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &playing,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;
	char hs_address[18];

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->state == HEADSET_STATE_DISCONNECTED)
		return error_not_connected(conn, msg);

	headset_set_state(device, HEADSET_STATE_DISCONNECTED);
	ba2str(&device->dst, hs_address);
	info("Disconnected from %s, %s", hs_address, device->path);

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_is_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	connected = (device->headset->state >= HEADSET_STATE_CONNECTED);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_connect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	int err;

	if (hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS)
		return error_in_progress(conn, msg, "Connect in progress");
	else if (hs->state > HEADSET_STATE_CONNECT_IN_PROGRESS)
		return error_already_connected(conn, msg);

	err = rfcomm_connect(device, NULL, NULL, NULL);
	if (err < 0)
		return error_connection_attempt_failed(conn, msg, -err);

	hs->auto_dc = FALSE;

	hs->pending->msg = dbus_message_ref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static gboolean ring_timer_cb(gpointer data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	int err;

	err = headset_send(hs, "\r\nRING\r\n");

	if (err < 0)
		error("Error while sending RING: %s (%d)",
				strerror(-err), -err);

	if (hs->cli_active && hs->ph_number) {
		err = headset_send(hs, "\r\n+CLIP:\"%s\",%d\r\n",
					hs->ph_number, hs->type);

		if (err < 0)
			error("Error while sending CLIP: %s (%d)",
					strerror(-err), -err);
	}

	return TRUE;
}

static DBusHandlerResult hs_ring(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;
	int err;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return error_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->ring_timer) {
		debug("IndicateCall received when already indicating");
		goto done;
	}

	err = headset_send(hs, "\r\nRING\r\n");
	if (err < 0) {
		dbus_message_unref(reply);
		return error_failed_errno(conn, msg, -err);
	}

	if (hs->cli_active && hs->ph_number) {
		err = headset_send(hs, "\r\n+CLIP:\"%s\",%d\r\n",
					hs->ph_number, hs->type);
		if (err < 0) {
			dbus_message_unref(reply);
			return error_failed_errno(conn, msg, -err);
		}
	}

	hs->ring_timer = g_timeout_add(RING_INTERVAL, ring_timer_cb, device);

done:
	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_cancel_ringing(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return error_not_connected(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (!hs->ring_timer) {
		debug("Got CancelRinging method call but ringing is not in progress");
		goto done;
	}

	g_source_remove(hs->ring_timer);
	hs->ring_timer = 0;

done:
	if (hs->hfp_active) {
		int err;
		/*+CIEV: (callsetup = 0)*/
		err = headset_send(hs, "\r\n+CIEV:3,0\r\n");
		if (err < 0) {
			dbus_message_unref(reply);
			return error_failed_errno(conn, msg, -err);
		}
	}

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_play(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	int err;

	if (sco_hci) {
		error("Refusing Headset.Play() because SCO HCI routing "
				"is enabled");
		return error_not_available(conn, msg);
	}

	switch (hs->state) {
	case HEADSET_STATE_DISCONNECTED:
	case HEADSET_STATE_CONNECT_IN_PROGRESS:
		return error_not_connected(conn, msg);
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		return error_in_progress(conn, msg, "Play in progress");
	case HEADSET_STATE_PLAYING:
		return error_already_connected(conn, msg);
	case HEADSET_STATE_CONNECTED:
	default:
		break;
	}

	err = sco_connect(device, NULL, NULL, NULL);
	if (err < 0)
		return error_failed(conn, msg, strerror(-err));

	hs->pending->msg = dbus_message_ref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_get_speaker_gain(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_uint16_t gain;

	if (hs->state < HEADSET_STATE_CONNECTED || hs->sp_gain < 0)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	gain = (dbus_uint16_t) hs->sp_gain;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_get_mic_gain(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_uint16_t gain;

	if (hs->state < HEADSET_STATE_CONNECTED || hs->mic_gain < 0)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	gain = (dbus_uint16_t) hs->mic_gain;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_set_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data, char type)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	DBusError derr;
	dbus_uint16_t gain;
	int err;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return error_not_connected(conn, msg);

	dbus_error_init(&derr);
	dbus_message_get_args(msg, &derr, DBUS_TYPE_UINT16, &gain,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error_invalid_arguments(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (gain > 15)
		return error_invalid_arguments(conn, msg,
					"Must be less than or equal to 15");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (hs->state != HEADSET_STATE_PLAYING)
		goto done;

	err = headset_send(hs, "\r\n+VG%c=%u\r\n", type, gain);
	if (err < 0) {
		dbus_message_unref(reply);
		return error_failed(conn, msg, "Unable to send to headset");
	}

done:
	if (type == HEADSET_GAIN_SPEAKER) {
		hs->sp_gain = gain;
		dbus_connection_emit_signal(conn, device->path,
						AUDIO_HEADSET_INTERFACE,
						"SpeakerGainChanged",
						DBUS_TYPE_UINT16, &gain,
						DBUS_TYPE_INVALID);
	} else {
		hs->mic_gain = gain;
		dbus_connection_emit_signal(conn, device->path,
						AUDIO_HEADSET_INTERFACE,
						"MicrophoneGainChanged",
						DBUS_TYPE_UINT16, &gain,
						DBUS_TYPE_INVALID);
	}

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_set_speaker_gain(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	return hs_set_gain(conn, msg, data, HEADSET_GAIN_SPEAKER);
}

static DBusHandlerResult hs_set_mic_gain(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	return hs_set_gain(conn, msg, data, HEADSET_GAIN_MICROPHONE);
}

static DBusHandlerResult hf_setup_call(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	DBusError derr;
	const char *value;
	int err;

	if (!hs->hfp_active)
		return error_not_supported(device->conn, msg);

	if (hs->state < HEADSET_STATE_CONNECTED)
		return error_not_connected(conn, msg);

	dbus_error_init(&derr);
	dbus_message_get_args(msg, &derr, DBUS_TYPE_STRING, &value,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error_invalid_arguments(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (!strncmp(value, "incoming", 8))
		err = headset_send(hs, "\r\n+CIEV:3,1\r\n");
	else if (!strncmp(value, "outgoing", 8))
		err = headset_send(hs, "\r\n+CIEV:3,2\r\n");
	else if (!strncmp(value, "remote", 6))
		err = headset_send(hs, "\r\n+CIEV:3,3\r\n");
	else
		err = -EINVAL;

	if (err < 0) {
		dbus_message_unref(reply);
		return error_failed_errno(conn, msg, -err);
	}

	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hf_identify_call(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	DBusError derr;
	const char *number;
	dbus_int32_t type;

	if (!hs->hfp_active && !hs->cli_active)
		return error_not_supported(device->conn, msg);

	if (hs->state < HEADSET_STATE_CONNECTED)
		return error_not_connected(conn, msg);

	dbus_error_init(&derr);
	dbus_message_get_args(msg, &derr, DBUS_TYPE_STRING, &number,
			      DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error_invalid_arguments(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	g_free(hs->ph_number);

	hs->ph_number = g_strdup(number);
	hs->type = type;

	send_message_and_unref(conn, reply);

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
	{ "GetSpeakerGain",	hs_get_speaker_gain,	"",	"q"	},
	{ "GetMicrophoneGain",	hs_get_mic_gain,	"",	"q"	},
	{ "SetSpeakerGain",	hs_set_speaker_gain,	"q",	""	},
	{ "SetMicrophoneGain",	hs_set_mic_gain,	"q",	""	},
	{ "SetupCall",		hf_setup_call,		"s",	""	},
	{ "IdentifyCall",	hf_identify_call,	"si",	""	},
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
	{ "CallTerminated",		""	},
	{ NULL, NULL }
};

static void headset_set_channel(struct headset *headset, sdp_record_t *record,
				uint16_t svc)
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
		debug("Discovered %s service on RFCOMM channel %d",
			svc == HEADSET_SVCLASS_ID ? "Headset" : "Handsfree",
			ch);
	} else
		error("Unable to get RFCOMM channel from Headset record");
}

void headset_update(struct device *dev, sdp_record_t *record, uint16_t svc)
{
	struct headset *headset = dev->headset;

	switch (svc) {
	case HANDSFREE_SVCLASS_ID:
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

	headset_set_channel(headset, record, svc);
}

struct headset *headset_init(struct device *dev, sdp_record_t *record,
				uint16_t svc)
{
	struct headset *hs;

	hs = g_new0(struct headset, 1);
	hs->rfcomm_ch = -1;
	hs->sp_gain = -1;
	hs->mic_gain = -1;
	hs->search_hfp = server_is_enabled(HANDSFREE_SVCLASS_ID);
	hs->hfp_active = FALSE;
	hs->cli_active = FALSE;
	hs->ph_number = NULL;

	if (!record)
		goto register_iface;

	switch (svc) {
	case HANDSFREE_SVCLASS_ID:
		hs->hfp_handle = record->handle;
		break;

	case HEADSET_SVCLASS_ID:
		hs->hsp_handle = record->handle;
		break;

	default:
		debug("Invalid record passed to headset_init");
		g_free(hs);
		return NULL;
	}

	headset_set_channel(hs, record, svc);
register_iface:
	if (!dbus_connection_register_interface(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						headset_methods,
						headset_signals, NULL)) {
		g_free(hs);
		return NULL;
	}

	return hs;
}

uint32_t headset_config_init(GKeyFile *config)
{
	GError *err = NULL;
	gboolean value;
	char *str;

	/* Use the default values if there is no config file */
	if (config == NULL)
		return ag_features;

	str = g_key_file_get_string(config, "General", "SCORouting",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else {
		if (strcmp(str, "PCM") == 0)
			sco_hci = FALSE;
		else if (strcmp(str, "HCI") == 0)
			sco_hci = TRUE;
		else
			error("Invalid Headset Routing value: %s", str);
		g_free(str);
	}

	value = g_key_file_get_boolean(config, "Headset", "3WayCalling",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_THREE_WAY_CALLING;

	value = g_key_file_get_boolean(config, "Headset", "EchoCancelNoiseCancel",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_EC_ANDOR_NR;

	value = g_key_file_get_boolean(config, "Headset", "VoiceRecognition",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_VOICE_RECOGNITION;

	value = g_key_file_get_boolean(config, "Headset", "InBandRingtone",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_INBAND_RINGTONE;

	value = g_key_file_get_boolean(config, "Headset", "VoiceTags",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_ATTACH_NUMBER_TO_VOICETAG;

	value = g_key_file_get_boolean(config, "Headset", "RejectingCalls",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_REJECT_A_CALL;

	value = g_key_file_get_boolean(config, "Headset", "EnhancedCallStatus",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_ENHANCES_CALL_STATUS;

	value = g_key_file_get_boolean(config, "Headset", "EnhancedCallControl",
					&err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_ENHANCES_CALL_CONTROL;

	value = g_key_file_get_boolean(config, "Headset",
					"ExtendedErrorResultCodes", &err);
	if (err) {
		debug("audio.conf: %s", err->message);
		g_error_free(err);
		err = NULL;
	} else if (value)
		ag_features |= AG_FEATURE_EXTENDED_ERROR_RESULT_CODES;

	return ag_features;
}

void headset_free(struct device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->sco) {
		g_io_channel_close(hs->sco);
		g_io_channel_unref(hs->sco);
	}

	if (hs->rfcomm) {
		g_io_channel_close(hs->rfcomm);
		g_io_channel_unref(hs->rfcomm);
	}

	g_free(hs);
	dev->headset = NULL;
}

gboolean headset_cancel_stream(struct device *dev, unsigned int id)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;
	GSList *l;
	struct connect_cb *cb = NULL;

	if (!p)
		return FALSE;

	for (l = p->callbacks; l != NULL; l = l->next) {
		struct connect_cb *tmp = l->data;

		if (tmp->id == id) {
			cb = tmp;
			break;
		}
	}

	if (!cb)
		return FALSE;

	p->callbacks = g_slist_remove(p->callbacks, cb);
	g_free(cb);

	if (p->callbacks || p->msg)
		return TRUE;

	pending_connect_finalize(dev);

	if (hs->auto_dc)
		headset_set_state(dev, HEADSET_STATE_DISCONNECTED);

	return TRUE;
}

static gboolean dummy_connect_complete(struct device *dev)
{
	pending_connect_finalize(dev);
	return FALSE;
}

unsigned int headset_request_stream(struct device *dev, headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	unsigned int id;

	if (hs->rfcomm && hs->sco) {
		id = connect_cb_new(hs, HEADSET_STATE_PLAYING, cb, user_data);
		g_idle_add((GSourceFunc) dummy_connect_complete, dev);
		return id;
	}

	if (hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS)
		return connect_cb_new(hs, HEADSET_STATE_PLAYING, cb, user_data);

	if (hs->rfcomm == NULL) {
		if (rfcomm_connect(dev, cb, user_data, &id) < 0)
			return 0;
		hs->auto_dc = TRUE;
	} else {
		if (sco_connect(dev, cb, user_data, &id) < 0)
			return 0;
	}

	hs->pending->target_state = HEADSET_STATE_PLAYING;

	return id;
}

gboolean get_hfp_active(struct device *dev)
{
	struct headset *hs = dev->headset;

	return hs->hfp_active;
}

void set_hfp_active(struct device *dev, gboolean active)
{
	struct headset *hs = dev->headset;

	hs->hfp_active = active;
}

int headset_connect_rfcomm(struct device *dev, int sock)
{
	struct headset *hs = dev->headset;

	hs->tmp_rfcomm = g_io_channel_unix_new(sock);

	return hs->tmp_rfcomm ? 0 : -EINVAL;
}

int headset_close_rfcomm(struct device *dev)
{
	struct headset *hs = dev->headset;
	GIOChannel *rfcomm = hs->tmp_rfcomm ? hs->tmp_rfcomm : hs->rfcomm;

	if (hs->ring_timer) {
		g_source_remove(hs->ring_timer);
		hs->ring_timer = 0;
	}

	if (rfcomm) {
		g_io_channel_close(rfcomm);
		g_io_channel_unref(rfcomm);
		hs->tmp_rfcomm = NULL;
		hs->rfcomm = NULL;
	}

	hs->data_start = 0;
	hs->data_length = 0;

	return 0;
}

void headset_set_authorized(struct device *dev)
{
	struct headset *hs = dev->headset;

	hs->rfcomm = hs->tmp_rfcomm;
	hs->tmp_rfcomm = NULL;

	g_io_add_watch(hs->rfcomm,
			G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			(GIOFunc) rfcomm_io_cb, dev);

	hs->auto_dc = FALSE;

	if (!hs->hfp_active)
		headset_set_state(dev, HEADSET_STATE_CONNECTED);
}

void headset_set_state(struct device *dev, headset_state_t state)
{
	struct headset *hs = dev->headset;

	if (hs->state == state)
		return;

	switch (state) {
	case HEADSET_STATE_DISCONNECTED:
		close_sco(dev);
		headset_close_rfcomm(dev);
		dbus_connection_emit_signal(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Disconnected",
						DBUS_TYPE_INVALID);
		break;
	case HEADSET_STATE_CONNECT_IN_PROGRESS:
		break;
	case HEADSET_STATE_CONNECTED:
		close_sco(dev);
		if (hs->state < state) {
			dbus_connection_emit_signal(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Connected",
						DBUS_TYPE_INVALID);
		} else if (hs->state == HEADSET_STATE_PLAYING) {
			dbus_connection_emit_signal(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Stopped",
						DBUS_TYPE_INVALID);
		}
		break;
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		break;
	case HEADSET_STATE_PLAYING:
		hs->sco_id = g_io_add_watch(hs->sco,
					G_IO_ERR | G_IO_HUP | G_IO_NVAL,
					(GIOFunc) sco_cb, dev);

		dbus_connection_emit_signal(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Playing", DBUS_TYPE_INVALID);

		if (hs->sp_gain >= 0)
			headset_send(hs, "\r\n+VGS=%u\r\n", hs->sp_gain);
		if (hs->mic_gain >= 0)
			headset_send(hs, "\r\n+VGM=%u\r\n", hs->mic_gain);
		break;
	}

	debug("State changed %s: %s -> %s", dev->path, str_state[hs->state],
		str_state[state]);
	hs->state = state;
}

headset_state_t headset_get_state(struct device *dev)
{
	struct headset *hs = dev->headset;

	return hs->state;
}

int headset_get_channel(struct device *dev)
{
	struct headset *hs = dev->headset;

	return hs->rfcomm_ch;
}

gboolean headset_is_active(struct device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->state != HEADSET_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

gboolean headset_lock(struct device *dev, headset_lock_t lock)
{
	struct headset *hs = dev->headset;

	if (hs->lock & lock)
		return FALSE;

	hs->lock |= lock;

	return TRUE;
}

gboolean headset_unlock(struct device *dev, headset_lock_t lock)
{
	struct headset *hs = dev->headset;

	if (!(hs->lock & lock))
		return FALSE;

	hs->lock &= ~lock;

	if (hs->lock)
		return TRUE;

	if (hs->auto_dc)
		headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
	else if (hs->state == HEADSET_STATE_PLAYING)
		headset_set_state(dev, HEADSET_STATE_CONNECTED);

	return TRUE;
}

gboolean headset_suspend(struct device *dev, void *data)
{
	return TRUE;
}

gboolean headset_play(struct device *dev, void *data)
{
	return TRUE;
}

int headset_get_sco_fd(struct device *dev)
{
	struct headset *hs = dev->headset;

	if (!hs->sco)
		return -1;

	return g_io_channel_unix_get_fd(hs->sco);
}
