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
#include <gdbus.h>

#include "logging.h"
#include "device.h"
#include "manager.h"
#include "error.h"
#include "headset.h"
#include "glib-helper.h"

#define DC_TIMEOUT 3000

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

	guint dc_timer;

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
	int (*callback) (struct audio_device *device, const char *buf);
};

static int rfcomm_connect(struct audio_device *device, headset_stream_cb_t cb,
				void *user_data, unsigned int *cb_id);
static int get_records(struct audio_device *device, headset_stream_cb_t cb,
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

static int supported_features(struct audio_device *device, const char *buf)
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

static int report_indicators(struct audio_device *device, const char *buf)
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

static void pending_connect_complete(struct connect_cb *cb, struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->pending->err)
		cb->cb(NULL, cb->cb_data);
	else
		cb->cb(dev, cb->cb_data);
}

static void pending_connect_finalize(struct audio_device *dev)
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

static void sco_connect_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer user_data)
{
	int sk;
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	if (err < 0) {
		error("connect(): %s (%d)", strerror(-err), -err);

		if (p->msg)
			error_connection_attempt_failed(dev->conn, p->msg, p->err);

		pending_connect_finalize(dev);
		if (hs->rfcomm)
			headset_set_state(dev, HEADSET_STATE_CONNECTED);
		else
			headset_set_state(dev, HEADSET_STATE_DISCONNECTED);

		return;
	}

	debug("SCO socket opened for headset %s", dev->path);

	sk = g_io_channel_unix_get_fd(chan);

	info("SCO fd=%d", sk);
	hs->sco = chan;
	p->io = NULL;

	if (p->msg) {
		DBusMessage *reply = dbus_message_new_method_return(p->msg);
		dbus_connection_send(dev->conn, reply, NULL);
		dbus_message_unref(reply);
	}

	pending_connect_finalize(dev);

	fcntl(sk, F_SETFL, 0);

	headset_set_state(dev, HEADSET_STATE_PLAYING);
}

static int sco_connect(struct audio_device *dev, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id)
{
	struct headset *hs = dev->headset;
	int err;

	if (hs->state != HEADSET_STATE_CONNECTED)
		return -EINVAL;

	err = bt_sco_connect(&dev->src, &dev->dst, sco_connect_cb, dev);
	if (err < 0) {
		error("connect: %s (%d)", strerror(-err), -err);
		return -err;
	}

	headset_set_state(dev, HEADSET_STATE_PLAY_IN_PROGRESS);

	pending_connect_init(hs, HEADSET_STATE_PLAYING);

	if (cb) {
		unsigned int id = connect_cb_new(hs, HEADSET_STATE_PLAYING,
							cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	return 0;
}

static void hfp_slc_complete(struct audio_device *dev)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	debug("HFP Service Level Connection established");

	headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (p == NULL)
		return;

	if (p->msg) {
		DBusMessage *reply = dbus_message_new_method_return(p->msg);
		dbus_connection_send(dev->conn, reply, NULL);
		dbus_message_unref(reply);
	}

	if (p->target_state == HEADSET_STATE_CONNECTED) {
		pending_connect_finalize(dev);
		return;
	}

	p->err = sco_connect(dev, NULL, NULL, NULL);
	if (p->err < 0)
		pending_connect_finalize(dev);
}

static int event_reporting(struct audio_device *dev, const char *buf)
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

static int call_hold(struct audio_device *dev, const char *buf)
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

static int answer_call(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	int err;

	g_dbus_emit_signal(device->conn, device->path,
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

static int terminate_call(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	int err;

	g_dbus_emit_signal(device->conn, device->path,
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

static int cli_notification(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;

	if (strlen(buf) < 9)
		return -EINVAL;

	hs->cli_active = buf[8] == '1' ? TRUE : FALSE;

	return headset_send(hs, "\r\nOK\r\n");
}

static int signal_gain_setting(struct audio_device *device, const char *buf)
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

	g_dbus_emit_signal(device->conn, device->path,
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

static int handle_event(struct audio_device *device, const char *buf)
{
	struct event *ev;

	debug("Received %s", buf);

	for (ev = event_callbacks; ev->cmd; ev++) {
		if (!strncmp(buf, ev->cmd, strlen(ev->cmd)))
			return ev->callback(device, buf);
	}

	return -EINVAL;
}

static void close_sco(struct audio_device *device)
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
				struct audio_device *device)
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
			struct audio_device *device)
{
	struct headset *hs;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;

	error("Audio connection got disconnected");

	headset_set_state(device, HEADSET_STATE_CONNECTED);

	return FALSE;
}

static void rfcomm_connect_cb(GIOChannel *chan, int err, const bdaddr_t *src,
			const bdaddr_t *dst, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;
	char hs_address[18];

	if (err < 0) {
		error("connect(): %s (%d)", strerror(-err), -err);
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
		return;

	headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (p->target_state == HEADSET_STATE_PLAYING) {
		p->err = sco_connect(dev, NULL, NULL, NULL);
		if (p->err < 0)
			goto failed;
		return;
	}

	if (p->msg) {
		DBusMessage *reply = dbus_message_new_method_return(p->msg);
		dbus_connection_send(dev->conn, reply, NULL);
		dbus_message_unref(reply);
	}

	pending_connect_finalize(dev);

	return;

failed:
	if (p->msg)
		error_connection_attempt_failed(dev->conn, p->msg, p->err);
	pending_connect_finalize(dev);
	if (hs->rfcomm)
		headset_set_state(dev, HEADSET_STATE_CONNECTED);
	else
		headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

static void get_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;
	int ch = -1;
	sdp_record_t *record = NULL;
	sdp_list_t *protos, *classes = NULL;
	uuid_t uuid;

	if (err < 0) {
		error("Unable to get service record: %s (%d)", strerror(-err),
			-err);
		goto failed_not_supported;
	}

	if (!recs || !recs->data) {
		error("No records found");
		goto failed_not_supported;
	}

	record = recs->data;

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
	pending_connect_finalize(dev);
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

static int get_records(struct audio_device *device, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id)
{
	struct headset *hs = device->headset;
	uuid_t uuid;

	sdp_uuid16_create(&uuid, hs->search_hfp ? HANDSFREE_SVCLASS_ID :
				HEADSET_SVCLASS_ID);

	headset_set_state(device, HEADSET_STATE_CONNECT_IN_PROGRESS);

	pending_connect_init(hs, HEADSET_STATE_CONNECTED);

	if (cb) {
		unsigned int id;
		id = connect_cb_new(hs, HEADSET_STATE_CONNECTED,
					cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	return bt_search_service(&device->src, &device->dst, &uuid,
			get_record_cb, device, NULL);
}

static int rfcomm_connect(struct audio_device *dev, headset_stream_cb_t cb,
				void *user_data, unsigned int *cb_id)
{
	struct headset *hs = dev->headset;
	char address[18];
	int err;

	if (hs->rfcomm_ch < 0)
		return get_records(dev, cb, user_data, cb_id);

	ba2str(&dev->dst, address);

	debug("%s: Connecting to %s channel %d", dev->path, address,
		hs->rfcomm_ch);

	err = bt_rfcomm_connect(&dev->src, &dev->dst, hs->rfcomm_ch,
			rfcomm_connect_cb, dev);
	if (err < 0) {
		error("connect() failed: %s (%d)", strerror(-err), -err);
		return err;
	}

	headset_set_state(dev, HEADSET_STATE_CONNECT_IN_PROGRESS);

	pending_connect_init(hs, HEADSET_STATE_CONNECTED);

	if (cb) {
		unsigned int id = connect_cb_new(hs, HEADSET_STATE_CONNECTED,
							cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	return 0;
}

static DBusMessage *hs_stop(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	if (hs->state < HEADSET_STATE_PLAY_IN_PROGRESS)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	headset_set_state(device, HEADSET_STATE_CONNECTED);

	return reply;
}

static DBusMessage *hs_is_playing(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_bool_t playing;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	playing = (hs->state == HEADSET_STATE_PLAYING);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &playing,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *hs_disconnect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;
	char hs_address[18];

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (hs->state == HEADSET_STATE_DISCONNECTED)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	headset_set_state(device, HEADSET_STATE_DISCONNECTED);
	ba2str(&device->dst, hs_address);
	info("Disconnected from %s, %s", hs_address, device->path);

	return reply;
}

static DBusMessage *hs_is_connected(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	dbus_bool_t connected;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	connected = (device->headset->state >= HEADSET_STATE_CONNECTED);

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &connected,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *hs_connect(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	int err;

	if (hs->state == HEADSET_STATE_CONNECT_IN_PROGRESS)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".InProgress",
						"Connect in Progress");
	else if (hs->state > HEADSET_STATE_CONNECT_IN_PROGRESS)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".AlreadyConnected",
						"Already Connected");

	err = rfcomm_connect(device, NULL, NULL, NULL);
	if (err < 0)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".ConnectAttemptFailed",
						"Connect Attempt Failed");

	hs->auto_dc = FALSE;

	hs->pending->msg = dbus_message_ref(msg);

	return NULL;
}

static gboolean ring_timer_cb(gpointer data)
{
	struct audio_device *device = data;
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

static DBusMessage *hs_ring(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;
	int err;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (hs->ring_timer) {
		debug("IndicateCall received when already indicating");
		goto done;
	}

	err = headset_send(hs, "\r\nRING\r\n");
	if (err < 0) {
		dbus_message_unref(reply);
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"%s", strerror(-err));
	}

	if (hs->cli_active && hs->ph_number) {
		err = headset_send(hs, "\r\n+CLIP:\"%s\",%d\r\n",
					hs->ph_number, hs->type);
		if (err < 0) {
			dbus_message_unref(reply);
			return g_dbus_create_error(msg, ERROR_INTERFACE
						".Failed", "%s",
						strerror(-err));
		}
	}

	hs->ring_timer = g_timeout_add(RING_INTERVAL, ring_timer_cb, device);

done:
	return reply;
}

static DBusMessage *hs_cancel_ringing(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

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
			return g_dbus_create_error(msg, ERROR_INTERFACE
						".Failed", "%s",
						strerror(-err));
		}
	}

	return reply;
}

static DBusMessage *hs_play(DBusConnection *conn, DBusMessage *msg,
				void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	int err;

	if (sco_hci) {
		error("Refusing Headset.Play() because SCO HCI routing "
				"is enabled");
		return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
						"Operation not Available");
	}

	switch (hs->state) {
	case HEADSET_STATE_DISCONNECTED:
	case HEADSET_STATE_CONNECT_IN_PROGRESS:
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".InProgress",
						"Play in Progress");
	case HEADSET_STATE_PLAYING:
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".AlreadyConnected",
						"Device Already Connected");
	case HEADSET_STATE_CONNECTED:
	default:
		break;
	}

	err = sco_connect(device, NULL, NULL, NULL);
	if (err < 0)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"%s", strerror(-err));

	hs->pending->msg = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *hs_get_speaker_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_uint16_t gain;

	if (hs->state < HEADSET_STATE_CONNECTED || hs->sp_gain < 0)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
						"Operation not Available");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	gain = (dbus_uint16_t) hs->sp_gain;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *hs_get_mic_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_uint16_t gain;

	if (hs->state < HEADSET_STATE_CONNECTED || hs->mic_gain < 0)
		return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
						"Operation not Available");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	gain = (dbus_uint16_t) hs->mic_gain;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *hs_set_gain(DBusConnection *conn,
				DBusMessage *msg,
				void *data, char type)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	dbus_uint16_t gain;
	int err;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT16, &gain,
				DBUS_TYPE_INVALID))
		return NULL;

	if (gain > 15)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".InvalidArgument",
						"Must be less than or equal to 15");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (hs->state != HEADSET_STATE_PLAYING)
		goto done;

	err = headset_send(hs, "\r\n+VG%c=%u\r\n", type, gain);
	if (err < 0) {
		dbus_message_unref(reply);
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"%s", strerror(-err));
	}

done:
	if (type == HEADSET_GAIN_SPEAKER) {
		hs->sp_gain = gain;
		g_dbus_emit_signal(conn, device->path,
						AUDIO_HEADSET_INTERFACE,
						"SpeakerGainChanged",
						DBUS_TYPE_UINT16, &gain,
						DBUS_TYPE_INVALID);
	} else {
		hs->mic_gain = gain;
		g_dbus_emit_signal(conn, device->path,
						AUDIO_HEADSET_INTERFACE,
						"MicrophoneGainChanged",
						DBUS_TYPE_UINT16, &gain,
						DBUS_TYPE_INVALID);
	}

	return reply;
}

static DBusMessage *hs_set_speaker_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	return hs_set_gain(conn, msg, data, HEADSET_GAIN_SPEAKER);
}

static DBusMessage *hs_set_mic_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	return hs_set_gain(conn, msg, data, HEADSET_GAIN_MICROPHONE);
}

static DBusMessage *hf_setup_call(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	const char *value;
	int err;

	if (!hs->hfp_active)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotSuppported",
						"Not Supported");

	if (hs->state < HEADSET_STATE_CONNECTED)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &value,
				DBUS_TYPE_INVALID))
		return NULL;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

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
		return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
						"%s", strerror(-err));
	}

	return reply;
}

static DBusMessage *hf_identify_call(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	const char *number;
	dbus_int32_t type;

	if (!hs->hfp_active && !hs->cli_active)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotSuppported",
						"Not Supported");

	if (hs->state < HEADSET_STATE_CONNECTED)
		return g_dbus_create_error(msg, ERROR_INTERFACE
						".NotConnected",
						"Device not Connected");

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &number,
			      DBUS_TYPE_INT32, &type, DBUS_TYPE_INVALID))
		return NULL;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	g_free(hs->ph_number);

	hs->ph_number = g_strdup(number);
	hs->type = type;

	return reply;
}

static GDBusMethodTable headset_methods[] = {
	{ "Connect",		"",	"",	hs_connect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",		"",	"",	hs_disconnect },
	{ "IsConnected",	"",	"b",	hs_is_connected },
	{ "IndicateCall",	"",	"",	hs_ring },
	{ "CancelCall",		"",	"",	hs_cancel_ringing },
	{ "Play",		"",	"",	hs_play,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Stop",		"",	"",	hs_stop },
	{ "IsPlaying",		"",	"b",	hs_is_playing },
	{ "GetSpeakerGain",	"",	"q",	hs_get_speaker_gain },
	{ "GetMicrophoneGain",	"",	"q",	hs_get_mic_gain },
	{ "SetSpeakerGain",	"q",	"",	hs_set_speaker_gain },
	{ "SetMicrophoneGain",	"q",	"",	hs_set_mic_gain },
	{ "SetupCall",		"s",	"",	hf_setup_call },
	{ "IdentifyCall",	"si",	"",	hf_identify_call },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable headset_signals[] = {
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

void headset_update(struct audio_device *dev, sdp_record_t *record, uint16_t svc)
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

struct headset *headset_init(struct audio_device *dev, sdp_record_t *record,
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
	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE,
					headset_methods, headset_signals, NULL,
					dev, NULL)) {
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

void headset_free(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

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

static gboolean hs_dc_timeout(struct audio_device *dev)
{
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
	return FALSE;
}

gboolean headset_cancel_stream(struct audio_device *dev, unsigned int id)
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

	if (hs->auto_dc) {
		if (hs->rfcomm)
			hs->dc_timer = g_timeout_add(DC_TIMEOUT,
						(GSourceFunc) hs_dc_timeout,
						dev);
		else
			headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
	}

	return TRUE;
}

static gboolean dummy_connect_complete(struct audio_device *dev)
{
	pending_connect_finalize(dev);
	return FALSE;
}

unsigned int headset_request_stream(struct audio_device *dev, headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	unsigned int id;

	if (hs->rfcomm && hs->sco) {
		id = connect_cb_new(hs, HEADSET_STATE_PLAYING, cb, user_data);
		g_idle_add((GSourceFunc) dummy_connect_complete, dev);
		return id;
	}

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
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

gboolean get_hfp_active(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->hfp_active;
}

void set_hfp_active(struct audio_device *dev, gboolean active)
{
	struct headset *hs = dev->headset;

	hs->hfp_active = active;
}

int headset_connect_rfcomm(struct audio_device *dev, GIOChannel *io)
{
	struct headset *hs = dev->headset;

	hs->tmp_rfcomm = io;

	return hs->tmp_rfcomm ? 0 : -EINVAL;
}

int headset_close_rfcomm(struct audio_device *dev)
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

void headset_set_authorized(struct audio_device *dev)
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

void headset_set_state(struct audio_device *dev, headset_state_t state)
{
	struct headset *hs = dev->headset;

	if (hs->state == state)
		return;

	switch (state) {
	case HEADSET_STATE_DISCONNECTED:
		close_sco(dev);
		headset_close_rfcomm(dev);
		g_dbus_emit_signal(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Disconnected",
						DBUS_TYPE_INVALID);
		break;
	case HEADSET_STATE_CONNECT_IN_PROGRESS:
		break;
	case HEADSET_STATE_CONNECTED:
		close_sco(dev);
		if (hs->state < state) {
			g_dbus_emit_signal(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Connected",
						DBUS_TYPE_INVALID);
		} else if (hs->state == HEADSET_STATE_PLAYING) {
			g_dbus_emit_signal(dev->conn, dev->path,
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

		g_dbus_emit_signal(dev->conn, dev->path,
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

headset_state_t headset_get_state(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->state;
}

int headset_get_channel(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->rfcomm_ch;
}

gboolean headset_is_active(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->state != HEADSET_STATE_DISCONNECTED)
		return TRUE;

	return FALSE;
}

gboolean headset_lock(struct audio_device *dev, headset_lock_t lock)
{
	struct headset *hs = dev->headset;

	if (hs->lock & lock)
		return FALSE;

	hs->lock |= lock;

	return TRUE;
}

gboolean headset_unlock(struct audio_device *dev, headset_lock_t lock)
{
	struct headset *hs = dev->headset;

	if (!(hs->lock & lock))
		return FALSE;

	hs->lock &= ~lock;

	if (hs->lock)
		return TRUE;

	if (hs->state == HEADSET_STATE_PLAYING)
		headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (hs->auto_dc) {
		if (hs->state == HEADSET_STATE_CONNECTED)
			hs->dc_timer = g_timeout_add(DC_TIMEOUT,
						(GSourceFunc) hs_dc_timeout,
						dev);
		else
			headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
	}

	return TRUE;
}

gboolean headset_suspend(struct audio_device *dev, void *data)
{
	return TRUE;
}

gboolean headset_play(struct audio_device *dev, void *data)
{
	return TRUE;
}

int headset_get_sco_fd(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (!hs->sco)
		return -1;

	return g_io_channel_unix_get_fd(hs->sco);
}
