/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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
/*Audio Gateway features.Default is In-band Ringtone*/
static unsigned int ag_features;
static gboolean sco_hci = TRUE;

static char *str_state[] = {
	"HEADSET_STATE_DISCONNECTED",
	"HEADSET_STATE_CONNECT_IN_PROGRESS",
	"HEADSET_STATE_CONNECTED",
	"HEADSET_STATE_PLAY_IN_PROGRESS",
	"HEADSET_STATE_PLAYING",
	};

struct pending_connect {
	DBusMessage *msg;
	DBusPendingCall *call;
	GIOChannel *io;
	int sock;
	int err;
	unsigned int id;
	headset_stream_cb_t cb;
	void *cb_data;
};

struct headset {
	uint32_t hsp_handle;
	uint32_t hfp_handle;

	int rfcomm_ch;

	GIOChannel *rfcomm;
	GIOChannel *sco;
	guint sco_id;

	guint ring_timer;

	char buf[BUF_SIZE];
	int data_start;
	int data_length;

	gboolean hfp_active;
	gboolean search_hfp;

	headset_state_t state;
	GSList *pending;

	int sp_gain;
	int mic_gain;

	unsigned int hfp_features;
	headset_lock_t lock;
};

struct event {
	const char *cmd;
	int (*callback) (struct device *device, const char *buf);
};

static int rfcomm_connect(struct device *device, struct pending_connect *c);
static int get_handles(struct device *device, struct pending_connect *c);

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

	if (hs->state < HEADSET_STATE_CONNECTED || !hs->rfcomm) {
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
		err = headset_send(hs, "\r\n+CIND:1, 0, 0\r\n");

	if (err < 0)
		return err;

	return headset_send(hs, "\r\nOK\r\n");
}

static int event_reporting(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;
	return headset_send(hs, "\r\nOK\r\n");
}

static int call_hold(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;
	int err;

	err = headset_send(hs, "\r\n+CHLD:(0,1,1x,2,2x,3,4)\r\n");
	if (err < 0)
		return err;

	return headset_send(hs, "\r\nOK\r\n");
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

	err = headset_send(hs, "\r\nOK\r\n");
	if (err < 0)
		return err;

	/*+CIEV: (call = 1)*/
	err = headset_send(hs, "\r\n+CIEV:2, 1\r\n");
	if (err < 0)
		return err;

	/*+CIEV: (callsetup = 0)*/
	return headset_send(hs, "\r\n+CIEV:3, 0\r\n");
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

	if (hs->ring_timer) {
		g_source_remove(hs->ring_timer);
		hs->ring_timer = 0;
		/*+CIEV: (callsetup = 0)*/
		return headset_send(hs, "\r\n+CIEV:3, 0\r\n");
	}

	/*+CIEV: (call = 0)*/
	return headset_send(hs, "\r\n+CIEV:2, 0\r\n");
}

static int signal_gain_setting(struct device *device, const char *buf)
{
	struct headset *hs = device->headset;
	const char *name;
	dbus_uint16_t gain;

	if (strlen(buf) < 8) {
		error("Too short string for Gain setting");
		return -1;
	}

	gain = (dbus_uint16_t) strtol(&buf[7], NULL, 10);

	if (gain > 15) {
		error("Invalid gain value received: %u", gain);
		return -1;
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
		return G_IO_ERROR_INVAL;
	}

	dbus_connection_emit_signal(device->conn, device->path,
				    AUDIO_HEADSET_INTERFACE, name,
				    DBUS_TYPE_UINT16, &gain,
				    DBUS_TYPE_INVALID);

ok:
	return headset_send(hs, "\r\nOK\r\n");
}

static struct event event_callbacks[] = {
	{"ATA", answer_call},
	{"AT+VG", signal_gain_setting},
	{"AT+BRSF", supported_features},
	{"AT+CIND", report_indicators},
	{"AT+CMER", event_reporting},
	{"AT+CHLD", call_hold},
	{"AT+CHUP", terminate_call},
	{"AT+CKPD", answer_call},
	{0}
};

static GIOError handle_event(struct device *device, const char *buf)
{
	struct event *pt;

	debug("Received %s", buf);

	for (pt = event_callbacks; pt->cmd; pt++) {
		if (!strncmp(buf, pt->cmd, strlen(pt->cmd)))
			return pt->callback(device, buf);
	}

	return -EINVAL;
}

static void pending_connect_free(struct pending_connect *c)
{
	if (c->io) {
		g_io_channel_close(c->io);
		g_io_channel_unref(c->io);
	}
	if (c->msg)
		dbus_message_unref(c->msg);
	if (c->call) {
		dbus_pending_call_cancel(c->call);
		dbus_pending_call_unref(c->call);
	}

	g_free(c);
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

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf) - 1,
				&bytes_read);
	if (err != G_IO_ERROR_NONE)
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
	if (err < 0)
		error("Error handling command %s: %s (%d)", &hs->buf[hs->data_start],
		      strerror(-err), -err);

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

static void pending_connect_ok(struct pending_connect *c, struct device *dev)
{
	struct headset *hs = dev->headset;

	if (c->msg) {
		DBusMessage *reply = dbus_message_new_method_return(c->msg);
		if (reply)
			send_message_and_unref(dev->conn, reply);
	}

	if (c->cb) {
		if (hs->rfcomm && hs->sco)
			c->cb(dev, c->cb_data);
		else
			c->cb(NULL, c->cb_data);
	}

	pending_connect_free(c);
}

static gboolean finalize_stream_setup(struct device *dev)
{
	struct headset *hs = dev->headset;

	g_slist_foreach(hs->pending, (GFunc) pending_connect_ok, dev);
	g_slist_free(hs->pending);
	hs->pending = NULL;

	return FALSE;
}

static void pending_connect_failed(struct pending_connect *c, struct device *dev)
{
	if (c->msg)
		error_connection_attempt_failed(dev->conn, c->msg, c->err);
	if (c->cb)
		c->cb(NULL, c->cb_data);
	pending_connect_free(c);
}

static gboolean sco_connect_cb(GIOChannel *chan, GIOCondition cond,
				struct device *device)
{
	struct headset *hs;
	struct pending_connect *c;
	int ret, sk;
	socklen_t len;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;
	c = hs->pending->data;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		c->err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(c->err),
				c->err);
		goto failed;
	}

	if (ret != 0) {
		c->err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	debug("SCO socket opened for headset %s", device->path);

	info("SCO fd=%d", sk);
	hs->sco = chan;
	c->io = NULL;

	g_slist_foreach(hs->pending, (GFunc) pending_connect_ok, device);
	g_slist_free(hs->pending);
	hs->pending = NULL;
	fcntl(sk, F_SETFL, 0);

	headset_set_state(device, HEADSET_STATE_PLAYING);

	return FALSE;

failed:
	g_slist_foreach(hs->pending, (GFunc) pending_connect_failed, device);
	g_slist_free(hs->pending);
	hs->pending = NULL;
	headset_set_state(device, HEADSET_STATE_CONNECTED);

	return FALSE;
}

static int sco_connect(struct device *device, struct pending_connect *c)
{
	struct headset *hs = device->headset;
	struct sockaddr_sco addr;
	gboolean do_callback = FALSE;
	int sk, err;

	if (!g_slist_find(hs->pending, c))
		hs->pending = g_slist_append(hs->pending, c);

	if (hs->state != HEADSET_STATE_CONNECTED)
		return 0;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		return -err;
	}

	c->io = g_io_channel_unix_new(sk);
	if (!c->io) {
		close(sk);
		return -EINVAL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, BDADDR_ANY);

	if (bind(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		err = errno;
		error("socket(BTPROTO_SCO): %s (%d)", strerror(err), err);
		return -err;
	}

	if (set_nonblocking(sk) < 0) {
		err = errno;
		return -err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, &device->dst);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect: %s (%d)", strerror(errno), errno);
			return -err;
		}

		g_io_add_watch(c->io,
				G_IO_OUT | G_IO_NVAL | G_IO_ERR | G_IO_HUP,
				(GIOFunc) sco_connect_cb, device);
	} else
		do_callback = TRUE;

	headset_set_state(device, HEADSET_STATE_PLAY_IN_PROGRESS);
	if (!g_slist_find(hs->pending, c))
		hs->pending = g_slist_append(hs->pending, c);

	if (do_callback)
		sco_connect_cb(c->io, G_IO_OUT, device);

	return 0;
}

static gboolean rfcomm_connect_cb(GIOChannel *chan, GIOCondition cond,
					struct device *device)
{
	struct headset *hs;
	struct pending_connect *c;
	char hs_address[18];
	int sk, ret;
	socklen_t len;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;
	c = hs->pending->data;

	sk = g_io_channel_unix_get_fd(chan);

	len = sizeof(ret);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &ret, &len) < 0) {
		c->err = errno;
		error("getsockopt(SO_ERROR): %s (%d)", strerror(c->err), c->err);
		goto failed;
	}

	if (ret != 0) {
		c->err = ret;
		error("connect(): %s (%d)", strerror(ret), ret);
		goto failed;
	}

	ba2str(&device->dst, hs_address);
	hs->rfcomm = chan;
	c->io = NULL;

	if (server_is_enabled(HANDSFREE_SVCLASS_ID) && hs->hfp_handle != 0)
		hs->hfp_active = TRUE;
	else
		hs->hfp_active = FALSE;

	headset_set_state(device, HEADSET_STATE_CONNECTED);

	debug("%s: Connected to %s", device->path, hs_address);

	g_io_add_watch(chan, G_IO_IN | G_IO_ERR | G_IO_HUP| G_IO_NVAL,
			(GIOFunc) rfcomm_io_cb, device);

	if (c->cb) {
		if (sco_connect(device, c) < 0) {
			c->err = EIO;
			goto failed;
		}
		return FALSE;
	}

	g_slist_foreach(hs->pending, (GFunc) pending_connect_ok, device);
	g_slist_free(hs->pending);
	hs->pending = NULL;

	return FALSE;

failed:
	g_slist_foreach(hs->pending, (GFunc) pending_connect_failed, device);
	g_slist_free(hs->pending);
	hs->pending = NULL;
	if (hs->rfcomm)
		headset_set_state(device, HEADSET_STATE_CONNECTED);
	else
		headset_set_state(device, HEADSET_STATE_DISCONNECTED);

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
	struct device *device = data;
	struct headset *hs = device->headset;
	struct pending_connect *c;

	c = hs->pending->data;

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

	err = rfcomm_connect(device, NULL);
	if (err < 0) {
		error("Unable to connect: %s (%s)", strerror(-err), -err);
		c->err = -err;
		goto failed;
	}

	sdp_list_free(classes, free);
	sdp_record_free(record);
	dbus_message_unref(reply);

	device_finish_sdp_transaction(device);

	return;

failed_not_supported:
	if (c->msg) {
		error_not_supported(device->conn, c->msg);
		dbus_message_unref(c->msg);
		c->msg = NULL;
	}
failed:
	if (classes)
		sdp_list_free(classes, free);
	if (record)
		sdp_record_free(record);
	if (reply)
		dbus_message_unref(reply);
	g_slist_foreach(hs->pending, (GFunc) pending_connect_failed, device);
	g_slist_free(hs->pending);
	hs->pending = NULL;
	headset_set_state(device, HEADSET_STATE_DISCONNECTED);
	device_finish_sdp_transaction(device);
}

static void get_handles_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *msg = NULL, *reply;
	DBusPendingCall *pending;
	DBusError derr;
	struct device *device = data;
	struct headset *hs = device->headset;
	struct pending_connect *c;
	char address[18], *addr_ptr = address;
	dbus_uint32_t *array = NULL;
	dbus_uint32_t handle;
	int array_len;

	c = hs->pending->data;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("GetRemoteServiceHandles failed: %s", derr.message);
		if (c->msg) {
			if (dbus_error_has_name(&derr,
						"org.bluez.Error.ConnectionAttemptFailed"))
				error_connection_attempt_failed(device->conn, c->msg,
					EHOSTDOWN);
			else
				error_not_supported(device->conn, c->msg);
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
		if (c->msg)
			error_not_supported(device->conn, c->msg);
		goto failed;
	}

	if (!array) {
		error("get_handles_reply: Unable to get handle array from reply");
		if (c->msg)
			error_not_supported(device->conn, c->msg);
		goto failed;
	}

	if (array_len < 1) {
		if (hs->search_hfp) {
			debug("No record handles found for hfp");
			hs->search_hfp = FALSE;
			get_handles(device, c);
			dbus_message_unref(reply);
			return;
		}

		debug("No record handles found for hsp");

		if (c->msg)
			error_not_supported(device->conn, c->msg);
		goto failed;
	}

	if (array_len > 1)
		debug("Multiple records found. Using the first one.");

	msg = dbus_message_new_method_call("org.bluez", device->adapter_path,
						"org.bluez.Adapter",
						"GetRemoteServiceRecord");
	if (!msg) {
		error("Unable to allocate new method call");
		if (c->msg)
			error_out_of_memory(device->conn, c->msg);
		goto failed;
	}

	ba2str(&device->dst, address);

	handle = array[0];

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &addr_ptr,
					DBUS_TYPE_UINT32, &handle,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(device->conn, msg, &pending, -1)) {
		error("Sending GetRemoteServiceRecord failed");
		if (c->msg)
			error_connection_attempt_failed(device->conn, c->msg, EIO);
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
	/* The reply was already sent above */
	if (c->msg) {
		dbus_message_unref(c->msg);
		c->msg = NULL;
	}
	dbus_message_unref(reply);
	g_slist_foreach(hs->pending, (GFunc) pending_connect_failed, device);
	g_slist_free(hs->pending);
	hs->pending = NULL;
	headset_set_state(device, HEADSET_STATE_DISCONNECTED);
}

static int get_handles(struct device *device, struct pending_connect *c)
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
		return -EINVAL;
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

	dbus_pending_call_set_notify(pending, get_handles_reply, device, NULL);
	if (c)
		c->call = pending;
	else
		dbus_pending_call_unref(pending);
	dbus_message_unref(msg);

	return 0;
}

static int rfcomm_connect(struct device *device, struct pending_connect *c)
{
	struct headset *hs = device->headset;
	struct sockaddr_rc addr;
	char address[18];
	int sk, err;

	if (c != NULL) {
		if (!g_slist_find(hs->pending, c))
			hs->pending = g_slist_append(hs->pending, c);

		if (hs->state == HEADSET_STATE_DISCONNECTED)
			return get_handles(device, c);
		else
			return 0;
	}
	else
		c = hs->pending->data;

	ba2str(&device->dst, address);

	debug("%s: Connecting to %s channel %d", device->path, address,
		hs->rfcomm_ch);

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0) {
		err = errno;
		error("socket: %s (%d)", strerror(err), err);
		goto failed;
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
	bacpy(&addr.rc_bdaddr, &device->dst);
	addr.rc_channel = hs->rfcomm_ch;

	c->io = g_io_channel_unix_new(sk);
	if (!c->io) {
		err = ENOMEM;
		error("channel_unix_new failed in rfcomm connect");
		goto failed;
	}

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (!(errno == EAGAIN || errno == EINPROGRESS)) {
			err = errno;
			error("connect() failed: %s (%d)", strerror(err), err);
			goto failed;
		}

		g_io_add_watch(c->io, G_IO_OUT | G_IO_NVAL,
				(GIOFunc) rfcomm_connect_cb, device);
	} else
		rfcomm_connect_cb(c->io, G_IO_OUT, device);

	return 0;

failed:
	if (!c->io && sk >= 0)
		close(sk);

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
	struct pending_connect *c;
	int err;

	if (hs->state > HEADSET_STATE_DISCONNECTED)
		return error_already_connected(conn, msg);

	c = g_try_new0(struct pending_connect, 1);
	if (!c) {
		error("Out of memory when allocating struct pending_connect");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	c->msg = dbus_message_ref(msg);

	err = rfcomm_connect(device, c);
	if (err < 0)
		goto error;

	return DBUS_HANDLER_RESULT_HANDLED;

error:
	pending_connect_free(c);
	return error_connection_attempt_failed(conn, msg, -err);
}

static gboolean ring_timer_cb(gpointer data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	int err;

	err = headset_send(hs, "\r\nRING\r\n");

	if (err < 0)
		error("Sending RING failed");

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
		return error_failed(conn, msg, "Failed");
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
	send_message_and_unref(conn, reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult hs_play(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct device *device = data;
	struct headset *hs = device->headset;
	struct pending_connect *c;
	int err;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return error_not_connected(conn, msg);

	if (hs->state >= HEADSET_STATE_PLAY_IN_PROGRESS)
		return error_already_connected(conn, msg);

	c = g_try_new0(struct pending_connect, 1);
	if (!c)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	c->msg = msg ? dbus_message_ref(msg) : NULL;

	err = sco_connect(device, c);
	if (err < 0) {
		pending_connect_free(c);
		return error_failed(conn, msg, strerror(-err));
	}

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
		err = headset_send(hs, "\r\n+CIEV:3, 1\r\n");
	else if (!strncmp(value, "outgoing", 8))
		err = headset_send(hs, "\r\n+CIEV:3, 2\r\n");
	else if (!strncmp(value, "remote", 6))
		err = headset_send(hs, "\r\n+CIEV:3, 3\r\n");
	else
		err = -EINVAL;

	if (err < 0) {
		dbus_message_unref(reply);
		return error_failed_errno(conn, msg, -err);
	}

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

static void headset_set_channel(struct headset *headset, sdp_record_t *record)
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

	headset_set_channel(headset, record);
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

	headset_set_channel(hs, record);
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

int headset_config_init(GKeyFile *config)
{
	GError *err = NULL;
	gboolean value;
	char *str;

	/* Use the default values if there is no config file */
	if (config == NULL)
		return 0;

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

	return 0;
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
	GSList *l;
	struct pending_connect *pending = NULL;

	for (l = hs->pending; l != NULL; l = l->next) {
		struct pending_connect *tmp = l->data;

		if (tmp->id == id) {
			pending = tmp;
			break;
		}
	}

	if (!pending)
		return FALSE;

	hs->pending = g_slist_remove(hs->pending, pending);
	pending_connect_free(pending);

	if (!hs->pending)
		headset_set_state(dev, HEADSET_STATE_DISCONNECTED);

	return TRUE;
}

unsigned int headset_request_stream(struct device *dev, headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	struct pending_connect *c;
	static unsigned int cb_id = 0;
	int err;

	c = g_new0(struct pending_connect, 1);
	c->cb = cb;
	c->cb_data = user_data;
	c->id = ++cb_id;

	if (hs->rfcomm && hs->sco) {
		hs->pending = g_slist_append(hs->pending, c);
		g_idle_add((GSourceFunc) finalize_stream_setup, dev);
		return c->id;
	}

	if (hs->rfcomm == NULL)
		err = rfcomm_connect(dev, c);
	else if (hs->sco == NULL)
		err = sco_connect(dev, c);

	if (err < 0)
		goto error;

	return c->id;

error:
	pending_connect_free(c);
	return 0;
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

	hs->rfcomm = g_io_channel_unix_new(sock);

	return hs->rfcomm ? 0 : -EINVAL;
}

int headset_close_rfcomm(struct device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->ring_timer) {
		g_source_remove(hs->ring_timer);
		hs->ring_timer = 0;
	}
	if (hs->rfcomm) {
		g_io_channel_close(hs->rfcomm);
		g_io_channel_unref(hs->rfcomm);
		hs->rfcomm = NULL;
	}

	hs->data_start = 0;
	hs->data_length = 0;

	return 0;
}

void headset_set_state(struct device *dev, headset_state_t state)
{
	struct headset *hs = dev->headset;

	if (hs->state == state)
		return;

	switch(state) {
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
			g_io_add_watch(hs->rfcomm,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) rfcomm_io_cb, dev);

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

	if (!hs->lock && hs->state > HEADSET_STATE_DISCONNECTED)
		headset_set_state(dev, HEADSET_STATE_DISCONNECTED);

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
