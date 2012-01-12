/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <assert.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "device.h"
#include "manager.h"
#include "error.h"
#include "telephony.h"
#include "headset.h"
#include "glib-compat.h"
#include "sdp-client.h"
#include "btio.h"
#include "dbus-common.h"
#include "../src/adapter.h"
#include "../src/device.h"

#define DC_TIMEOUT 3

#define RING_INTERVAL 3

#define BUF_SIZE 1024

#define HEADSET_GAIN_SPEAKER 'S'
#define HEADSET_GAIN_MICROPHONE 'M'

static struct {
	gboolean telephony_ready;	/* Telephony plugin initialized */
	uint32_t features;		/* HFP AG features */
	const struct indicator *indicators;	/* Available HFP indicators */
	int er_mode;			/* Event reporting mode */
	int er_ind;			/* Event reporting for indicators */
	int rh;				/* Response and Hold state */
	char *number;			/* Incoming phone number */
	int number_type;		/* Incoming number type */
	guint ring_timer;		/* For incoming call indication */
	const char *chld;		/* Response to AT+CHLD=? */
} ag = {
	.telephony_ready = FALSE,
	.features = 0,
	.er_mode = 3,
	.er_ind = 0,
	.rh = BTRH_NOT_SUPPORTED,
	.number = NULL,
	.number_type = 0,
	.ring_timer = 0,
};

static gboolean sco_hci = TRUE;
static gboolean fast_connectable = FALSE;

static GSList *active_devices = NULL;

static char *str_state[] = {
	"HEADSET_STATE_DISCONNECTED",
	"HEADSET_STATE_CONNECTING",
	"HEADSET_STATE_CONNECTED",
	"HEADSET_STATE_PLAY_IN_PROGRESS",
	"HEADSET_STATE_PLAYING",
};

struct headset_state_callback {
	headset_state_cb cb;
	void *user_data;
	unsigned int id;
};

struct headset_nrec_callback {
	unsigned int id;
	headset_nrec_cb cb;
	void *user_data;
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
	uint16_t svclass;
};

struct headset_slc {
	char buf[BUF_SIZE];
	int data_start;
	int data_length;

	gboolean cli_active;
	gboolean cme_enabled;
	gboolean cwa_enabled;
	gboolean pending_ring;
	gboolean inband_ring;
	gboolean nrec;
	gboolean nrec_req;

	int sp_gain;
	int mic_gain;

	unsigned int hf_features;
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

	guint dc_timer;

	gboolean hfp_active;
	gboolean search_hfp;
	gboolean rfcomm_initiator;

	headset_state_t state;
	struct pending_connect *pending;

	headset_lock_t lock;
	struct headset_slc *slc;
	GSList *nrec_cbs;
};

struct event {
	const char *cmd;
	int (*callback) (struct audio_device *device, const char *buf);
};

static GSList *headset_callbacks = NULL;

static void error_connect_failed(DBusConnection *conn, DBusMessage *msg,
								int err)
{
	DBusMessage *reply = btd_error_failed(msg,
			err < 0 ? strerror(-err) : "Connect failed");
	g_dbus_send_message(conn, reply);
}

static int rfcomm_connect(struct audio_device *device, headset_stream_cb_t cb,
				void *user_data, unsigned int *cb_id);
static int get_records(struct audio_device *device, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id);

static void print_ag_features(uint32_t features)
{
	GString *gstr;
	char *str;

	if (features == 0) {
		DBG("HFP AG features: (none)");
		return;
	}

	gstr = g_string_new("HFP AG features: ");

	if (features & AG_FEATURE_THREE_WAY_CALLING)
		g_string_append(gstr, "\"Three-way calling\" ");
	if (features & AG_FEATURE_EC_ANDOR_NR)
		g_string_append(gstr, "\"EC and/or NR function\" ");
	if (features & AG_FEATURE_VOICE_RECOGNITION)
		g_string_append(gstr, "\"Voice recognition function\" ");
	if (features & AG_FEATURE_INBAND_RINGTONE)
		g_string_append(gstr, "\"In-band ring tone capability\" ");
	if (features & AG_FEATURE_ATTACH_NUMBER_TO_VOICETAG)
		g_string_append(gstr, "\"Attach a number to a voice tag\" ");
	if (features & AG_FEATURE_REJECT_A_CALL)
		g_string_append(gstr, "\"Ability to reject a call\" ");
	if (features & AG_FEATURE_ENHANCED_CALL_STATUS)
		g_string_append(gstr, "\"Enhanced call status\" ");
	if (features & AG_FEATURE_ENHANCED_CALL_CONTROL)
		g_string_append(gstr, "\"Enhanced call control\" ");
	if (features & AG_FEATURE_EXTENDED_ERROR_RESULT_CODES)
		g_string_append(gstr, "\"Extended Error Result Codes\" ");

	str = g_string_free(gstr, FALSE);

	DBG("%s", str);

	g_free(str);
}

static void print_hf_features(uint32_t features)
{
	GString *gstr;
	char *str;

	if (features == 0) {
		DBG("HFP HF features: (none)");
		return;
	}

	gstr = g_string_new("HFP HF features: ");

	if (features & HF_FEATURE_EC_ANDOR_NR)
		g_string_append(gstr, "\"EC and/or NR function\" ");
	if (features & HF_FEATURE_CALL_WAITING_AND_3WAY)
		g_string_append(gstr, "\"Call waiting and 3-way calling\" ");
	if (features & HF_FEATURE_CLI_PRESENTATION)
		g_string_append(gstr, "\"CLI presentation capability\" ");
	if (features & HF_FEATURE_VOICE_RECOGNITION)
		g_string_append(gstr, "\"Voice recognition activation\" ");
	if (features & HF_FEATURE_REMOTE_VOLUME_CONTROL)
		g_string_append(gstr, "\"Remote volume control\" ");
	if (features & HF_FEATURE_ENHANCED_CALL_STATUS)
		g_string_append(gstr, "\"Enhanced call status\" ");
	if (features & HF_FEATURE_ENHANCED_CALL_CONTROL)
		g_string_append(gstr, "\"Enhanced call control\" ");

	str = g_string_free(gstr, FALSE);

	DBG("%s", str);

	g_free(str);
}

static const char *state2str(headset_state_t state)
{
	switch (state) {
	case HEADSET_STATE_DISCONNECTED:
		return "disconnected";
	case HEADSET_STATE_CONNECTING:
		return "connecting";
	case HEADSET_STATE_CONNECTED:
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		return "connected";
	case HEADSET_STATE_PLAYING:
		return "playing";
	}

	return NULL;
}

static int headset_send_valist(struct headset *hs, char *format, va_list ap)
{
	char rsp[BUF_SIZE];
	ssize_t total_written, count;
	int fd;

	count = vsnprintf(rsp, sizeof(rsp), format, ap);

	if (count < 0)
		return -EINVAL;

	if (!hs->rfcomm) {
		error("headset_send: the headset is not connected");
		return -EIO;
	}

	total_written = 0;
	fd = g_io_channel_unix_get_fd(hs->rfcomm);

	while (total_written < count) {
		ssize_t written;

		written = write(fd, rsp + total_written,
				count - total_written);
		if (written < 0)
			return -errno;

		total_written += written;
	}

	return 0;
}

static int __attribute__((format(printf, 2, 3)))
			headset_send(struct headset *hs, char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = headset_send_valist(hs, format, ap);
	va_end(ap);

	return ret;
}

static int supported_features(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;
	int err;

	if (strlen(buf) < 9)
		return -EINVAL;

	slc->hf_features = strtoul(&buf[8], NULL, 10);

	print_hf_features(slc->hf_features);

	err = headset_send(hs, "\r\n+BRSF: %u\r\n", ag.features);
	if (err < 0)
		return err;

	return headset_send(hs, "\r\nOK\r\n");
}

static char *indicator_ranges(const struct indicator *indicators)
{
	int i;
	GString *gstr;

	gstr = g_string_new("\r\n+CIND: ");

	for (i = 0; indicators[i].desc != NULL; i++) {
		if (i == 0)
			g_string_append_printf(gstr, "(\"%s\",(%s))",
						indicators[i].desc,
						indicators[i].range);
		else
			g_string_append_printf(gstr, ",(\"%s\",(%s))",
						indicators[i].desc,
						indicators[i].range);
	}

	g_string_append(gstr, "\r\n");

	return g_string_free(gstr, FALSE);
}

static char *indicator_values(const struct indicator *indicators)
{
	int i;
	GString *gstr;

	gstr = g_string_new("\r\n+CIND: ");

	for (i = 0; indicators[i].desc != NULL; i++) {
		if (i == 0)
			g_string_append_printf(gstr, "%d", indicators[i].val);
		else
			g_string_append_printf(gstr, ",%d", indicators[i].val);
	}

	g_string_append(gstr, "\r\n");

	return g_string_free(gstr, FALSE);
}

static int report_indicators(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	int err;
	char *str;

	if (strlen(buf) < 8)
		return -EINVAL;

	if (ag.indicators == NULL) {
		error("HFP AG indicators not initialized");
		return headset_send(hs, "\r\nERROR\r\n");
	}

	if (buf[7] == '=')
		str = indicator_ranges(ag.indicators);
	else
		str = indicator_values(ag.indicators);

	err = headset_send(hs, "%s", str);

	g_free(str);

	if (err < 0)
		return err;

	return headset_send(hs, "\r\nOK\r\n");
}

static void pending_connect_complete(struct connect_cb *cb, struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->pending->err < 0)
		cb->cb(NULL, cb->cb_data);
	else
		cb->cb(dev, cb->cb_data);
}

static void pending_connect_finalize(struct audio_device *dev)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	if (p == NULL)
		return;

	if (p->svclass)
		bt_cancel_discovery(&dev->src, &dev->dst);

	g_slist_foreach(p->callbacks, (GFunc) pending_connect_complete, dev);

	g_slist_free_full(p->callbacks, g_free);

	if (p->io) {
		g_io_channel_shutdown(p->io, TRUE, NULL);
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
	static unsigned int free_cb_id = 1;

	pending_connect_init(hs, target_state);

	if (!func)
		return 0;

	cb = g_new(struct connect_cb, 1);

	cb->cb = func;
	cb->cb_data = user_data;
	cb->id = free_cb_id++;

	hs->pending->callbacks = g_slist_append(hs->pending->callbacks,
						cb);

	return cb->id;
}

static void __attribute__((format(printf, 3, 4)))
		send_foreach_headset(GSList *devices,
					int (*cmp) (struct headset *hs),
					char *format, ...)
{
	GSList *l;
	va_list ap;

	for (l = devices; l != NULL; l = l->next) {
		struct audio_device *device = l->data;
		struct headset *hs = device->headset;
		int ret;

		assert(hs != NULL);

		if (cmp && cmp(hs) != 0)
			continue;

		va_start(ap, format);
		ret = headset_send_valist(hs, format, ap);
		if (ret < 0)
			error("Failed to send to headset: %s (%d)",
					strerror(-ret), -ret);
		va_end(ap);
	}
}

static int cli_cmp(struct headset *hs)
{
	struct headset_slc *slc = hs->slc;

	if (!hs->hfp_active)
		return -1;

	if (slc->cli_active)
		return 0;
	else
		return -1;
}

static gboolean ring_timer_cb(gpointer data)
{
	send_foreach_headset(active_devices, NULL, "\r\nRING\r\n");

	if (ag.number)
		send_foreach_headset(active_devices, cli_cmp,
					"\r\n+CLIP: \"%s\",%d\r\n",
					ag.number, ag.number_type);

	return TRUE;
}

static void sco_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	int sk;
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct headset_slc *slc = hs->slc;
	struct pending_connect *p = hs->pending;

	if (err) {
		error("%s", err->message);

		if (p != NULL) {
			p->err = -errno;
			if (p->msg)
				error_connect_failed(dev->conn, p->msg, p->err);
			pending_connect_finalize(dev);
		}

		if (hs->rfcomm)
			headset_set_state(dev, HEADSET_STATE_CONNECTED);
		else
			headset_set_state(dev, HEADSET_STATE_DISCONNECTED);

		return;
	}

	DBG("SCO socket opened for headset %s", dev->path);

	sk = g_io_channel_unix_get_fd(chan);

	DBG("SCO fd=%d", sk);

	if (p) {
		p->io = NULL;
		if (p->msg) {
			DBusMessage *reply;
			reply = dbus_message_new_method_return(p->msg);
			g_dbus_send_message(dev->conn, reply);
		}

		pending_connect_finalize(dev);
	}

	fcntl(sk, F_SETFL, 0);

	headset_set_state(dev, HEADSET_STATE_PLAYING);

	if (slc->pending_ring) {
		ring_timer_cb(NULL);
		ag.ring_timer = g_timeout_add_seconds(RING_INTERVAL,
						ring_timer_cb,
						NULL);
		slc->pending_ring = FALSE;
	}
}

static int sco_connect(struct audio_device *dev, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id)
{
	struct headset *hs = dev->headset;
	GError *err = NULL;
	GIOChannel *io;

	if (hs->state != HEADSET_STATE_CONNECTED)
		return -EINVAL;

	io = bt_io_connect(BT_IO_SCO, sco_connect_cb, dev, NULL, &err,
				BT_IO_OPT_SOURCE_BDADDR, &dev->src,
				BT_IO_OPT_DEST_BDADDR, &dev->dst,
				BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
		return -EIO;
	}

	hs->sco = io;

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

static int hfp_cmp(struct headset *hs)
{
	if (hs->hfp_active)
		return 0;
	else
		return -1;
}

static void hfp_slc_complete(struct audio_device *dev)
{
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;

	DBG("HFP Service Level Connection established");

	headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (p == NULL)
		return;

	if (p->target_state == HEADSET_STATE_CONNECTED) {
		if (p->msg) {
			DBusMessage *reply = dbus_message_new_method_return(p->msg);
			g_dbus_send_message(dev->conn, reply);
		}
		pending_connect_finalize(dev);
		return;
	}

	p->err = sco_connect(dev, NULL, NULL, NULL);
	if (p->err < 0) {
		if (p->msg)
			error_connect_failed(dev->conn, p->msg, p->err);
		pending_connect_finalize(dev);
	}
}

static int telephony_generic_rsp(struct audio_device *device, cme_error_t err)
{
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;

	if ((err != CME_ERROR_NONE) && slc->cme_enabled)
		return headset_send(hs, "\r\n+CME ERROR: %d\r\n", err);

	switch (err) {
	case CME_ERROR_NONE:
		return headset_send(hs, "\r\nOK\r\n");
	case CME_ERROR_NO_NETWORK_SERVICE:
		return headset_send(hs, "\r\nNO CARRIER\r\n");
	default:
		return headset_send(hs, "\r\nERROR\r\n");
	}
}

int telephony_event_reporting_rsp(void *telephony_device, cme_error_t err)
{
	struct audio_device *device = telephony_device;
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;
	int ret;

	if (err != CME_ERROR_NONE)
		return telephony_generic_rsp(telephony_device, err);

	ret = headset_send(hs, "\r\nOK\r\n");
	if (ret < 0)
		return ret;

	if (hs->state != HEADSET_STATE_CONNECTING)
		return 0;

	if (slc->hf_features & HF_FEATURE_CALL_WAITING_AND_3WAY &&
			ag.features & AG_FEATURE_THREE_WAY_CALLING)
		return 0;

	hfp_slc_complete(device);

	return 0;
}

static int event_reporting(struct audio_device *dev, const char *buf)
{
	char **tokens; /* <mode>, <keyp>, <disp>, <ind>, <bfr> */

	if (strlen(buf) < 13)
		return -EINVAL;

	tokens = g_strsplit(&buf[8], ",", 5);
	if (g_strv_length(tokens) < 4) {
		g_strfreev(tokens);
		return -EINVAL;
	}

	ag.er_mode = atoi(tokens[0]);
	ag.er_ind = atoi(tokens[3]);

	g_strfreev(tokens);
	tokens = NULL;

	DBG("Event reporting (CMER): mode=%d, ind=%d",
			ag.er_mode, ag.er_ind);

	switch (ag.er_ind) {
	case 0:
	case 1:
		telephony_event_reporting_req(dev, ag.er_ind);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int call_hold(struct audio_device *dev, const char *buf)
{
	struct headset *hs = dev->headset;
	int err;

	if (strlen(buf) < 9)
		return -EINVAL;

	if (buf[8] != '?') {
		telephony_call_hold_req(dev, &buf[8]);
		return 0;
	}

	err = headset_send(hs, "\r\n+CHLD: (%s)\r\n", ag.chld);
	if (err < 0)
		return err;

	err = headset_send(hs, "\r\nOK\r\n");
	if (err < 0)
		return err;

	if (hs->state != HEADSET_STATE_CONNECTING)
		return 0;

	hfp_slc_complete(dev);

	return 0;
}

int telephony_key_press_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

static int key_press(struct audio_device *device, const char *buf)
{
	if (strlen(buf) < 9)
		return -EINVAL;

	g_dbus_emit_signal(device->conn, device->path,
			AUDIO_HEADSET_INTERFACE, "AnswerRequested",
			DBUS_TYPE_INVALID);

	if (ag.ring_timer) {
		g_source_remove(ag.ring_timer);
		ag.ring_timer = 0;
	}

	telephony_key_press_req(device, &buf[8]);

	return 0;
}

int telephony_answer_call_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

static int answer_call(struct audio_device *device, const char *buf)
{
	if (ag.ring_timer) {
		g_source_remove(ag.ring_timer);
		ag.ring_timer = 0;
	}

	if (ag.number) {
		g_free(ag.number);
		ag.number = NULL;
	}

	telephony_answer_call_req(device);

	return 0;
}

int telephony_terminate_call_rsp(void *telephony_device,
					cme_error_t err)
{
	struct audio_device *device = telephony_device;
	struct headset *hs = device->headset;

	if (err != CME_ERROR_NONE)
		return telephony_generic_rsp(telephony_device, err);

	g_dbus_emit_signal(device->conn, device->path,
			AUDIO_HEADSET_INTERFACE, "CallTerminated",
			DBUS_TYPE_INVALID);

	return headset_send(hs, "\r\nOK\r\n");
}

static int terminate_call(struct audio_device *device, const char *buf)
{
	if (ag.number) {
		g_free(ag.number);
		ag.number = NULL;
	}

	if (ag.ring_timer) {
		g_source_remove(ag.ring_timer);
		ag.ring_timer = 0;
	}

	telephony_terminate_call_req(device);

	return 0;
}

static int cli_notification(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;

	if (strlen(buf) < 9)
		return -EINVAL;

	slc->cli_active = buf[8] == '1' ? TRUE : FALSE;

	return headset_send(hs, "\r\nOK\r\n");
}

int telephony_response_and_hold_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

static int response_and_hold(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;

	if (strlen(buf) < 8)
		return -EINVAL;

	if (ag.rh == BTRH_NOT_SUPPORTED)
		return telephony_generic_rsp(device, CME_ERROR_NOT_SUPPORTED);

	if (buf[7] == '=') {
		telephony_response_and_hold_req(device, atoi(&buf[8]) < 0);
		return 0;
	}

	if (ag.rh >= 0)
		headset_send(hs, "\r\n+BTRH: %d\r\n", ag.rh);

	return headset_send(hs, "\r\nOK\r\n");
}

int telephony_last_dialed_number_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

static int last_dialed_number(struct audio_device *device, const char *buf)
{
	telephony_last_dialed_number_req(device);

	return 0;
}

int telephony_dial_number_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

static int dial_number(struct audio_device *device, const char *buf)
{
	char number[BUF_SIZE];
	size_t buf_len;

	buf_len = strlen(buf);

	if (buf[buf_len - 1] != ';') {
		DBG("Rejecting non-voice call dial request");
		return -EINVAL;
	}

	memset(number, 0, sizeof(number));
	strncpy(number, &buf[3], buf_len - 4);

	telephony_dial_number_req(device, number);

	return 0;
}

static int headset_set_gain(struct audio_device *device, uint16_t gain, char type)
{
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;
	const char *name, *property;

	if (gain > 15) {
		error("Invalid gain value: %u", gain);
		return -EINVAL;
	}

	switch (type) {
	case HEADSET_GAIN_SPEAKER:
		if (slc->sp_gain == gain) {
			DBG("Ignoring no-change in speaker gain");
			return -EALREADY;
		}
		name = "SpeakerGainChanged";
		property = "SpeakerGain";
		slc->sp_gain = gain;
		break;
	case HEADSET_GAIN_MICROPHONE:
		if (slc->mic_gain == gain) {
			DBG("Ignoring no-change in microphone gain");
			return -EALREADY;
		}
		name = "MicrophoneGainChanged";
		property = "MicrophoneGain";
		slc->mic_gain = gain;
		break;
	default:
		error("Unknown gain setting");
		return -EINVAL;
	}

	g_dbus_emit_signal(device->conn, device->path,
				AUDIO_HEADSET_INTERFACE, name,
				DBUS_TYPE_UINT16, &gain,
				DBUS_TYPE_INVALID);

	emit_property_changed(device->conn, device->path,
				AUDIO_HEADSET_INTERFACE, property,
				DBUS_TYPE_UINT16, &gain);

	return 0;
}

static int signal_gain_setting(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	dbus_uint16_t gain;
	int err;

	if (strlen(buf) < 8) {
		error("Too short string for Gain setting");
		return -EINVAL;
	}

	gain = (dbus_uint16_t) strtol(&buf[7], NULL, 10);

	err = headset_set_gain(device, gain, buf[5]);
	if (err < 0 && err != -EALREADY)
		return err;

	return headset_send(hs, "\r\nOK\r\n");
}

int telephony_transmit_dtmf_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

static int dtmf_tone(struct audio_device *device, const char *buf)
{
	char tone;

	if (strlen(buf) < 8) {
		error("Too short string for DTMF tone");
		return -EINVAL;
	}

	tone = buf[7];
	if (tone >= '#' && tone <= 'D')
		telephony_transmit_dtmf_req(device, tone);
	else
		return -EINVAL;

	return 0;
}

int telephony_subscriber_number_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

static int subscriber_number(struct audio_device *device, const char *buf)
{
	telephony_subscriber_number_req(device);

	return 0;
}

int telephony_list_current_calls_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

static int list_current_calls(struct audio_device *device, const char *buf)
{
	telephony_list_current_calls_req(device);

	return 0;
}

static int extended_errors(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;

	if (strlen(buf) < 9)
		return -EINVAL;

	if (buf[8] == '1') {
		slc->cme_enabled = TRUE;
		DBG("CME errors enabled for headset %p", hs);
	} else {
		slc->cme_enabled = FALSE;
		DBG("CME errors disabled for headset %p", hs);
	}

	return headset_send(hs, "\r\nOK\r\n");
}

static int call_waiting_notify(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;

	if (strlen(buf) < 9)
		return -EINVAL;

	if (buf[8] == '1') {
		slc->cwa_enabled = TRUE;
		DBG("Call waiting notification enabled for headset %p", hs);
	} else {
		slc->cwa_enabled = FALSE;
		DBG("Call waiting notification disabled for headset %p", hs);
	}

	return headset_send(hs, "\r\nOK\r\n");
}

int telephony_operator_selection_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

int telephony_call_hold_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

int telephony_nr_and_ec_rsp(void *telephony_device, cme_error_t err)
{
	struct audio_device *device = telephony_device;
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;

	if (err == CME_ERROR_NONE) {
		GSList *l;

		for (l = hs->nrec_cbs; l; l = l->next) {
			struct headset_nrec_callback *nrec_cb = l->data;

			nrec_cb->cb(device, slc->nrec_req, nrec_cb->user_data);
		}

		slc->nrec = hs->slc->nrec_req;
	}

	return telephony_generic_rsp(telephony_device, err);
}

int telephony_voice_dial_rsp(void *telephony_device, cme_error_t err)
{
	return telephony_generic_rsp(telephony_device, err);
}

int telephony_operator_selection_ind(int mode, const char *oper)
{
	if (!active_devices)
		return -ENODEV;

	send_foreach_headset(active_devices, hfp_cmp,
				"\r\n+COPS: %d,0,\"%s\"\r\n",
				mode, oper);
	return 0;
}

static int operator_selection(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;

	if (strlen(buf) < 8)
		return -EINVAL;

	switch (buf[7]) {
	case '?':
		telephony_operator_selection_req(device);
		break;
	case '=':
		return headset_send(hs, "\r\nOK\r\n");
	default:
		return -EINVAL;
	}

	return 0;
}

static int nr_and_ec(struct audio_device *device, const char *buf)
{
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;

	if (strlen(buf) < 9)
		return -EINVAL;

	if (buf[8] == '0')
		slc->nrec_req = FALSE;
	else
		slc->nrec_req = TRUE;

	telephony_nr_and_ec_req(device, slc->nrec_req);

	return 0;
}

static int voice_dial(struct audio_device *device, const char *buf)
{
	gboolean enable;

	if (strlen(buf) < 9)
		return -EINVAL;

	if (buf[8] == '0')
		enable = FALSE;
	else
		enable = TRUE;

	telephony_voice_dial_req(device, enable);

	return 0;
}

static int apple_command(struct audio_device *device, const char *buf)
{
	DBG("Got Apple command: %s", buf);

	return telephony_generic_rsp(device, CME_ERROR_NONE);
}

static struct event event_callbacks[] = {
	{ "ATA", answer_call },
	{ "ATD", dial_number },
	{ "AT+VG", signal_gain_setting },
	{ "AT+BRSF", supported_features },
	{ "AT+CIND", report_indicators },
	{ "AT+CMER", event_reporting },
	{ "AT+CHLD", call_hold },
	{ "AT+CHUP", terminate_call },
	{ "AT+CKPD", key_press },
	{ "AT+CLIP", cli_notification },
	{ "AT+BTRH", response_and_hold },
	{ "AT+BLDN", last_dialed_number },
	{ "AT+VTS", dtmf_tone },
	{ "AT+CNUM", subscriber_number },
	{ "AT+CLCC", list_current_calls },
	{ "AT+CMEE", extended_errors },
	{ "AT+CCWA", call_waiting_notify },
	{ "AT+COPS", operator_selection },
	{ "AT+NREC", nr_and_ec },
	{ "AT+BVRA", voice_dial },
	{ "AT+XAPL", apple_command },
	{ "AT+IPHONEACCEV", apple_command },
	{ 0 }
};

static int handle_event(struct audio_device *device, const char *buf)
{
	struct event *ev;

	DBG("Received %s", buf);

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
		int sock = g_io_channel_unix_get_fd(hs->sco);
		shutdown(sock, SHUT_RDWR);
		g_io_channel_shutdown(hs->sco, TRUE, NULL);
		g_io_channel_unref(hs->sco);
		hs->sco = NULL;
	}

	if (hs->sco_id) {
		g_source_remove(hs->sco_id);
		hs->sco_id = 0;
	}
}

static gboolean rfcomm_io_cb(GIOChannel *chan, GIOCondition cond,
				struct audio_device *device)
{
	struct headset *hs;
	struct headset_slc *slc;
	unsigned char buf[BUF_SIZE];
	ssize_t bytes_read;
	size_t free_space;
	int fd;

	if (cond & G_IO_NVAL)
		return FALSE;

	hs = device->headset;
	slc = hs->slc;

	if (cond & (G_IO_ERR | G_IO_HUP)) {
		DBG("ERR or HUP on RFCOMM socket");
		goto failed;
	}

	fd = g_io_channel_unix_get_fd(chan);

	bytes_read = read(fd, buf, sizeof(buf) - 1);
	if (bytes_read < 0)
		return TRUE;

	free_space = sizeof(slc->buf) - slc->data_start -
			slc->data_length - 1;

	if (free_space < (size_t) bytes_read) {
		/* Very likely that the HS is sending us garbage so
		 * just ignore the data and disconnect */
		error("Too much data to fit incomming buffer");
		goto failed;
	}

	memcpy(&slc->buf[slc->data_start], buf, bytes_read);
	slc->data_length += bytes_read;

	/* Make sure the data is null terminated so we can use string
	 * functions */
	slc->buf[slc->data_start + slc->data_length] = '\0';

	while (slc->data_length > 0) {
		char *cr;
		int err;
		off_t cmd_len;

		cr = strchr(&slc->buf[slc->data_start], '\r');
		if (!cr)
			break;

		cmd_len = 1 + (off_t) cr - (off_t) &slc->buf[slc->data_start];
		*cr = '\0';

		if (cmd_len > 1)
			err = handle_event(device, &slc->buf[slc->data_start]);
		else
			/* Silently skip empty commands */
			err = 0;

		if (err == -EINVAL) {
			error("Badly formated or unrecognized command: %s",
					&slc->buf[slc->data_start]);
			err = telephony_generic_rsp(device,
						CME_ERROR_NOT_SUPPORTED);
			if (err < 0)
				goto failed;
		} else if (err < 0)
			error("Error handling command %s: %s (%d)",
						&slc->buf[slc->data_start],
						strerror(-err), -err);

		slc->data_start += cmd_len;
		slc->data_length -= cmd_len;

		if (!slc->data_length)
			slc->data_start = 0;
	}

	return TRUE;

failed:
	headset_set_state(device, HEADSET_STATE_DISCONNECTED);

	return FALSE;
}

static gboolean sco_cb(GIOChannel *chan, GIOCondition cond,
			struct audio_device *device)
{
	if (cond & G_IO_NVAL)
		return FALSE;

	error("Audio connection got disconnected");

	pending_connect_finalize(device);
	headset_set_state(device, HEADSET_STATE_CONNECTED);

	return FALSE;
}

void headset_connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;
	char hs_address[18];

	if (err) {
		error("%s", err->message);
		goto failed;
	}

	/* For HFP telephony isn't ready just disconnect */
	if (hs->hfp_active && !ag.telephony_ready) {
		error("Unable to accept HFP connection since the telephony "
				"subsystem isn't initialized");
		goto failed;
	}

	hs->rfcomm = hs->tmp_rfcomm;
	hs->tmp_rfcomm = NULL;

	ba2str(&dev->dst, hs_address);

	if (p)
		p->io = NULL;
	else
		hs->auto_dc = FALSE;

	g_io_add_watch(chan, G_IO_IN | G_IO_ERR | G_IO_HUP| G_IO_NVAL,
			(GIOFunc) rfcomm_io_cb, dev);

	DBG("%s: Connected to %s", dev->path, hs_address);

	hs->slc = g_new0(struct headset_slc, 1);
	hs->slc->sp_gain = 15;
	hs->slc->mic_gain = 15;
	hs->slc->nrec = TRUE;

	/* In HFP mode wait for Service Level Connection */
	if (hs->hfp_active)
		return;

	headset_set_state(dev, HEADSET_STATE_CONNECTED);

	if (p && p->target_state == HEADSET_STATE_PLAYING) {
		p->err = sco_connect(dev, NULL, NULL, NULL);
		if (p->err < 0)
			goto failed;
		return;
	}

	if (p && p->msg) {
		DBusMessage *reply = dbus_message_new_method_return(p->msg);
		g_dbus_send_message(dev->conn, reply);
	}

	pending_connect_finalize(dev);

	return;

failed:
	if (p && p->msg)
		error_connect_failed(dev->conn, p->msg, p->err);
	pending_connect_finalize(dev);
	if (hs->rfcomm)
		headset_set_state(dev, HEADSET_STATE_CONNECTED);
	else
		headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

static int headset_set_channel(struct headset *headset,
				const sdp_record_t *record, uint16_t svc)
{
	int ch;
	sdp_list_t *protos;

	if (sdp_get_access_protos(record, &protos) < 0) {
		error("Unable to get access protos from headset record");
		return -1;
	}

	ch = sdp_get_proto_port(protos, RFCOMM_UUID);

	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);

	if (ch <= 0) {
		error("Unable to get RFCOMM channel from Headset record");
		return -1;
	}

	headset->rfcomm_ch = ch;

	if (svc == HANDSFREE_SVCLASS_ID) {
		headset->hfp_handle = record->handle;
		DBG("Discovered Handsfree service on channel %d", ch);
	} else {
		headset->hsp_handle = record->handle;
		DBG("Discovered Headset service on channel %d", ch);
	}

	return 0;
}

static void get_record_cb(sdp_list_t *recs, int err, gpointer user_data)
{
	struct audio_device *dev = user_data;
	struct headset *hs = dev->headset;
	struct pending_connect *p = hs->pending;
	sdp_record_t *record = NULL;
	sdp_list_t *r;
	uuid_t uuid;

	assert(hs->pending != NULL);

	if (err < 0) {
		error("Unable to get service record: %s (%d)",
							strerror(-err), -err);
		p->err = -err;
		if (p->msg)
			error_connect_failed(dev->conn, p->msg, p->err);
		goto failed;
	}

	if (!recs || !recs->data) {
		error("No records found");
		goto failed_not_supported;
	}

	sdp_uuid16_create(&uuid, p->svclass);

	for (r = recs; r != NULL; r = r->next) {
		sdp_list_t *classes;
		uuid_t class;

		record = r->data;

		if (sdp_get_service_classes(record, &classes) < 0) {
			error("Unable to get service classes from record");
			continue;
		}

		memcpy(&class, classes->data, sizeof(uuid));

		sdp_list_free(classes, free);

		if (sdp_uuid_cmp(&class, &uuid) == 0)
			break;
	}

	if (r == NULL) {
		error("No record found with UUID 0x%04x", p->svclass);
		goto failed_not_supported;
	}

	if (headset_set_channel(hs, record, p->svclass) < 0) {
		error("Unable to extract RFCOMM channel from service record");
		goto failed_not_supported;
	}

	/* Set svclass to 0 so we can easily check that SDP is no-longer
	 * going on (to know if bt_cancel_discovery needs to be called) */
	p->svclass = 0;

	err = rfcomm_connect(dev, NULL, NULL, NULL);
	if (err < 0) {
		error("Unable to connect: %s (%d)", strerror(-err), -err);
		p->err = -err;
		if (p->msg != NULL)
			error_connect_failed(dev->conn, p->msg, p->err);
		goto failed;
	}

	return;

failed_not_supported:
	if (p->svclass == HANDSFREE_SVCLASS_ID &&
			get_records(dev, NULL, NULL, NULL) == 0)
		return;
	if (p->msg) {
		DBusMessage *reply = btd_error_not_supported(p->msg);
		g_dbus_send_message(dev->conn, reply);
	}
failed:
	p->svclass = 0;
	pending_connect_finalize(dev);
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

static int get_records(struct audio_device *device, headset_stream_cb_t cb,
			void *user_data, unsigned int *cb_id)
{
	struct headset *hs = device->headset;
	uint16_t svclass;
	uuid_t uuid;
	int err;

	if (hs->pending && hs->pending->svclass == HANDSFREE_SVCLASS_ID)
		svclass = HEADSET_SVCLASS_ID;
	else
		svclass = hs->search_hfp ? HANDSFREE_SVCLASS_ID :
							HEADSET_SVCLASS_ID;

	sdp_uuid16_create(&uuid, svclass);

	err = bt_search_service(&device->src, &device->dst, &uuid,
						get_record_cb, device, NULL);
	if (err < 0)
		return err;

	if (hs->pending) {
		hs->pending->svclass = svclass;
		return 0;
	}

	headset_set_state(device, HEADSET_STATE_CONNECTING);

	pending_connect_init(hs, HEADSET_STATE_CONNECTED);

	hs->pending->svclass = svclass;

	if (cb) {
		unsigned int id;
		id = connect_cb_new(hs, HEADSET_STATE_CONNECTED,
					cb, user_data);
		if (cb_id)
			*cb_id = id;
	}

	return 0;
}

static int rfcomm_connect(struct audio_device *dev, headset_stream_cb_t cb,
				void *user_data, unsigned int *cb_id)
{
	struct headset *hs = dev->headset;
	char address[18];
	GError *err = NULL;

	if (!manager_allow_headset_connection(dev))
		return -ECONNREFUSED;

	if (hs->rfcomm_ch < 0)
		return get_records(dev, cb, user_data, cb_id);

	ba2str(&dev->dst, address);

	DBG("%s: Connecting to %s channel %d", dev->path, address,
		hs->rfcomm_ch);

	hs->tmp_rfcomm = bt_io_connect(BT_IO_RFCOMM, headset_connect_cb, dev,
					NULL, &err,
					BT_IO_OPT_SOURCE_BDADDR, &dev->src,
					BT_IO_OPT_DEST_BDADDR, &dev->dst,
					BT_IO_OPT_CHANNEL, hs->rfcomm_ch,
					BT_IO_OPT_INVALID);

	hs->rfcomm_ch = -1;

	if (!hs->tmp_rfcomm) {
		error("%s", err->message);
		g_error_free(err);
		return -EIO;
	}

	hs->hfp_active = hs->hfp_handle != 0 ? TRUE : FALSE;
	hs->rfcomm_initiator = FALSE;

	headset_set_state(dev, HEADSET_STATE_CONNECTING);

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
		return btd_error_not_connected(msg);

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
	char hs_address[18];

	if (hs->state == HEADSET_STATE_DISCONNECTED)
		return btd_error_not_connected(msg);

	headset_shutdown(device);
	ba2str(&device->dst, hs_address);
	info("Disconnected from %s, %s", hs_address, device->path);

	return dbus_message_new_method_return(msg);

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

	if (hs->state == HEADSET_STATE_CONNECTING)
		return btd_error_in_progress(msg);
	else if (hs->state > HEADSET_STATE_CONNECTING)
		return btd_error_already_connected(msg);

	if (hs->hfp_handle && !ag.telephony_ready)
		return btd_error_not_ready(msg);

	device->auto_connect = FALSE;

	err = rfcomm_connect(device, NULL, NULL, NULL);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	hs->auto_dc = FALSE;

	hs->pending->msg = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *hs_ring(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;
	int err;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return btd_error_not_connected(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (ag.ring_timer) {
		DBG("IndicateCall received when already indicating");
		return reply;
	}

	err = headset_send(hs, "\r\nRING\r\n");
	if (err < 0) {
		dbus_message_unref(reply);
		return btd_error_failed(msg, strerror(-err));
	}

	ring_timer_cb(NULL);
	ag.ring_timer = g_timeout_add_seconds(RING_INTERVAL, ring_timer_cb,
						NULL);

	return reply;
}

static DBusMessage *hs_cancel_call(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply = NULL;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return btd_error_not_connected(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (ag.ring_timer) {
		g_source_remove(ag.ring_timer);
		ag.ring_timer = 0;
	} else
		DBG("Got CancelCall method call but no call is active");

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
		return btd_error_not_available(msg);
	}

	switch (hs->state) {
	case HEADSET_STATE_DISCONNECTED:
	case HEADSET_STATE_CONNECTING:
		return btd_error_not_connected(msg);
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		if (hs->pending && hs->pending->msg == NULL) {
			hs->pending->msg = dbus_message_ref(msg);
			return NULL;
		}
		return btd_error_busy(msg);
	case HEADSET_STATE_PLAYING:
		return btd_error_already_connected(msg);
	case HEADSET_STATE_CONNECTED:
	default:
		break;
	}

	err = sco_connect(device, NULL, NULL, NULL);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	hs->pending->msg = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *hs_get_speaker_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	struct headset_slc *slc = hs->slc;
	DBusMessage *reply;
	dbus_uint16_t gain;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return btd_error_not_available(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	gain = (dbus_uint16_t) slc->sp_gain;

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
	struct headset_slc *slc = hs->slc;
	DBusMessage *reply;
	dbus_uint16_t gain;

	if (hs->state < HEADSET_STATE_CONNECTED || slc == NULL)
		return btd_error_not_available(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	gain = (dbus_uint16_t) slc->mic_gain;

	dbus_message_append_args(reply, DBUS_TYPE_UINT16, &gain,
					DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *hs_set_gain(DBusConnection *conn,
				DBusMessage *msg,
				void *data, uint16_t gain,
				char type)
{
	struct audio_device *device = data;
	struct headset *hs = device->headset;
	DBusMessage *reply;
	int err;

	if (hs->state < HEADSET_STATE_CONNECTED)
		return btd_error_not_connected(msg);

	err = headset_set_gain(device, gain, type);
	if (err < 0)
		return btd_error_invalid_args(msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	if (hs->state == HEADSET_STATE_PLAYING) {
		err = headset_send(hs, "\r\n+VG%c=%u\r\n", type, gain);
		if (err < 0) {
			dbus_message_unref(reply);
			return btd_error_failed(msg, strerror(-err));
		}
	}

	return reply;
}

static DBusMessage *hs_set_speaker_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	uint16_t gain;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT16, &gain,
				DBUS_TYPE_INVALID))
		return NULL;

	return hs_set_gain(conn, msg, data, gain, HEADSET_GAIN_SPEAKER);
}

static DBusMessage *hs_set_mic_gain(DBusConnection *conn,
					DBusMessage *msg,
					void *data)
{
	uint16_t gain;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT16, &gain,
				DBUS_TYPE_INVALID))
		return NULL;

	return hs_set_gain(conn, msg, data, gain, HEADSET_GAIN_MICROPHONE);
}

static DBusMessage *hs_get_properties(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct audio_device *device = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	gboolean value;
	const char *state;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);


	/* Playing */
	value = (device->headset->state == HEADSET_STATE_PLAYING);
	dict_append_entry(&dict, "Playing", DBUS_TYPE_BOOLEAN, &value);

	/* State */
	state = state2str(device->headset->state);
	if (state)
		dict_append_entry(&dict, "State", DBUS_TYPE_STRING, &state);

	/* Connected */
	value = (device->headset->state >= HEADSET_STATE_CONNECTED);
	dict_append_entry(&dict, "Connected", DBUS_TYPE_BOOLEAN, &value);

	if (!value)
		goto done;

	/* SpeakerGain */
	dict_append_entry(&dict, "SpeakerGain",
				DBUS_TYPE_UINT16,
				&device->headset->slc->sp_gain);

	/* MicrophoneGain */
	dict_append_entry(&dict, "MicrophoneGain",
				DBUS_TYPE_UINT16,
				&device->headset->slc->mic_gain);

done:
	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *hs_set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *property;
	DBusMessageIter iter;
	DBusMessageIter sub;
	uint16_t gain;

	if (!dbus_message_iter_init(msg, &iter))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&iter, &property);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return btd_error_invalid_args(msg);
	dbus_message_iter_recurse(&iter, &sub);

	if (g_str_equal("SpeakerGain", property)) {
		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT16)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &gain);
		return hs_set_gain(conn, msg, data, gain,
					HEADSET_GAIN_SPEAKER);
	} else if (g_str_equal("MicrophoneGain", property)) {
		if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_UINT16)
			return btd_error_invalid_args(msg);

		dbus_message_iter_get_basic(&sub, &gain);
		return hs_set_gain(conn, msg, data, gain,
					HEADSET_GAIN_MICROPHONE);
	}

	return btd_error_invalid_args(msg);
}

static GDBusMethodTable headset_methods[] = {
	{ "Connect",		"",	"",	hs_connect,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "Disconnect",		"",	"",	hs_disconnect },
	{ "IsConnected",	"",	"b",	hs_is_connected },
	{ "IndicateCall",	"",	"",	hs_ring },
	{ "CancelCall",		"",	"",	hs_cancel_call },
	{ "Play",		"",	"",	hs_play,
						G_DBUS_METHOD_FLAG_ASYNC |
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "Stop",		"",	"",	hs_stop },
	{ "IsPlaying",		"",	"b",	hs_is_playing,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "GetSpeakerGain",	"",	"q",	hs_get_speaker_gain,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "GetMicrophoneGain",	"",	"q",	hs_get_mic_gain,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "SetSpeakerGain",	"q",	"",	hs_set_speaker_gain,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "SetMicrophoneGain",	"q",	"",	hs_set_mic_gain,
						G_DBUS_METHOD_FLAG_DEPRECATED },
	{ "GetProperties",	"",	"a{sv}",hs_get_properties },
	{ "SetProperty",	"sv",	"",	hs_set_property },
	{ NULL, NULL, NULL, NULL }
};

static GDBusSignalTable headset_signals[] = {
	{ "Connected",			"",	G_DBUS_SIGNAL_FLAG_DEPRECATED },
	{ "Disconnected",		"",	G_DBUS_SIGNAL_FLAG_DEPRECATED },
	{ "AnswerRequested",		""	},
	{ "Stopped",			"",	G_DBUS_SIGNAL_FLAG_DEPRECATED },
	{ "Playing",			"",	G_DBUS_SIGNAL_FLAG_DEPRECATED },
	{ "SpeakerGainChanged",		"q",	G_DBUS_SIGNAL_FLAG_DEPRECATED },
	{ "MicrophoneGainChanged",	"q",	G_DBUS_SIGNAL_FLAG_DEPRECATED },
	{ "CallTerminated",		""	},
	{ "PropertyChanged",		"sv"	},
	{ NULL, NULL }
};

void headset_update(struct audio_device *dev, uint16_t svc,
			const char *uuidstr)
{
	struct headset *headset = dev->headset;
	const sdp_record_t *record;

	record = btd_device_get_record(dev->btd_dev, uuidstr);
	if (!record)
		return;

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
		DBG("Invalid record passed to headset_update");
		return;
	}
}

static int headset_close_rfcomm(struct audio_device *dev)
{
	struct headset *hs = dev->headset;
	GIOChannel *rfcomm = hs->tmp_rfcomm ? hs->tmp_rfcomm : hs->rfcomm;

	if (rfcomm) {
		g_io_channel_shutdown(rfcomm, TRUE, NULL);
		g_io_channel_unref(rfcomm);
		hs->tmp_rfcomm = NULL;
		hs->rfcomm = NULL;
	}

	g_free(hs->slc);
	hs->slc = NULL;

	return 0;
}

static void headset_free(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

	close_sco(dev);

	headset_close_rfcomm(dev);

	g_slist_free_full(hs->nrec_cbs, g_free);

	g_free(hs);
	dev->headset = NULL;
}

static void path_unregister(void *data)
{
	struct audio_device *dev = data;
	struct headset *hs = dev->headset;

	if (hs->state > HEADSET_STATE_DISCONNECTED) {
		DBG("Headset unregistered while device was connected!");
		headset_shutdown(dev);
	}

	DBG("Unregistered interface %s on path %s",
		AUDIO_HEADSET_INTERFACE, dev->path);

	headset_free(dev);
}

void headset_unregister(struct audio_device *dev)
{
	g_dbus_unregister_interface(dev->conn, dev->path,
		AUDIO_HEADSET_INTERFACE);
}

struct headset *headset_init(struct audio_device *dev, uint16_t svc,
				const char *uuidstr)
{
	struct headset *hs;
	const sdp_record_t *record;

	hs = g_new0(struct headset, 1);
	hs->rfcomm_ch = -1;
	hs->search_hfp = server_is_enabled(&dev->src, HANDSFREE_SVCLASS_ID);

	record = btd_device_get_record(dev->btd_dev, uuidstr);
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
		DBG("Invalid record passed to headset_init");
		g_free(hs);
		return NULL;
	}

register_iface:
	if (!g_dbus_register_interface(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE,
					headset_methods, headset_signals, NULL,
					dev, path_unregister)) {
		g_free(hs);
		return NULL;
	}

	DBG("Registered interface %s on path %s",
		AUDIO_HEADSET_INTERFACE, dev->path);

	return hs;
}

uint32_t headset_config_init(GKeyFile *config)
{
	GError *err = NULL;
	char *str;

	/* Use the default values if there is no config file */
	if (config == NULL)
		return ag.features;

	str = g_key_file_get_string(config, "General", "SCORouting",
					&err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		if (strcmp(str, "PCM") == 0)
			sco_hci = FALSE;
		else if (strcmp(str, "HCI") == 0)
			sco_hci = TRUE;
		else
			error("Invalid Headset Routing value: %s", str);
		g_free(str);
	}

	/* Init fast connectable option */
	str = g_key_file_get_string(config, "Headset", "FastConnectable",
					&err);
	if (err) {
		DBG("audio.conf: %s", err->message);
		g_clear_error(&err);
	} else {
		fast_connectable = strcmp(str, "true") == 0;
		if (fast_connectable)
			manager_set_fast_connectable(FALSE);
		g_free(str);
	}

	return ag.features;
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

	if (hs->auto_dc) {
		if (hs->rfcomm)
			hs->dc_timer = g_timeout_add_seconds(DC_TIMEOUT,
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

unsigned int headset_request_stream(struct audio_device *dev,
					headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	unsigned int id;

	if (hs->state == HEADSET_STATE_PLAYING) {
		id = connect_cb_new(hs, HEADSET_STATE_PLAYING, cb, user_data);
		g_idle_add((GSourceFunc) dummy_connect_complete, dev);
		return id;
	}

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

	if (hs->state == HEADSET_STATE_CONNECTING ||
			hs->state == HEADSET_STATE_PLAY_IN_PROGRESS)
		return connect_cb_new(hs, HEADSET_STATE_PLAYING, cb, user_data);

	if (hs->rfcomm == NULL) {
		if (rfcomm_connect(dev, cb, user_data, &id) < 0)
			return 0;
		hs->auto_dc = TRUE;
	} else if (sco_connect(dev, cb, user_data, &id) < 0)
		return 0;

	hs->pending->target_state = HEADSET_STATE_PLAYING;

	return id;
}

unsigned int headset_config_stream(struct audio_device *dev,
					gboolean auto_dc,
					headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	unsigned int id = 0;

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

	if (hs->state == HEADSET_STATE_CONNECTING)
		return connect_cb_new(hs, HEADSET_STATE_CONNECTED, cb,
					user_data);

	if (hs->rfcomm)
		goto done;

	if (rfcomm_connect(dev, cb, user_data, &id) < 0)
		return 0;

	hs->auto_dc = auto_dc;
	hs->pending->target_state = HEADSET_STATE_CONNECTED;

	return id;

done:
	id = connect_cb_new(hs, HEADSET_STATE_CONNECTED, cb, user_data);
	g_idle_add((GSourceFunc) dummy_connect_complete, dev);
	return id;
}

unsigned int headset_suspend_stream(struct audio_device *dev,
					headset_stream_cb_t cb,
					void *user_data)
{
	struct headset *hs = dev->headset;
	unsigned int id;
	int sock;

	if (hs->state == HEADSET_STATE_DISCONNECTED ||
				hs->state == HEADSET_STATE_CONNECTING)
		return 0;

	if (hs->dc_timer) {
		g_source_remove(hs->dc_timer);
		hs->dc_timer = 0;
	}

	if (hs->sco) {
		sock = g_io_channel_unix_get_fd(hs->sco);

		/* shutdown but leave the socket open and wait for hup */
		shutdown(sock, SHUT_RDWR);
	} else {
		headset_set_state(dev, HEADSET_STATE_CONNECTED);

		g_idle_add((GSourceFunc) dummy_connect_complete, dev);
	}

	id = connect_cb_new(hs, HEADSET_STATE_CONNECTED, cb, user_data);

	return id;
}

gboolean headset_get_hfp_active(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->hfp_active;
}

void headset_set_hfp_active(struct audio_device *dev, gboolean active)
{
	struct headset *hs = dev->headset;

	hs->hfp_active = active;
}

gboolean headset_get_rfcomm_initiator(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->rfcomm_initiator;
}

void headset_set_rfcomm_initiator(struct audio_device *dev,
					gboolean initiator)
{
	struct headset *hs = dev->headset;

	hs->rfcomm_initiator = initiator;
}

GIOChannel *headset_get_rfcomm(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->tmp_rfcomm;
}

int headset_connect_rfcomm(struct audio_device *dev, GIOChannel *io)
{
	struct headset *hs = dev->headset;

	if (hs->tmp_rfcomm)
		return -EALREADY;

	hs->tmp_rfcomm = g_io_channel_ref(io);

	return 0;
}

int headset_connect_sco(struct audio_device *dev, GIOChannel *io)
{
	struct headset *hs = dev->headset;
	struct headset_slc *slc = hs->slc;

	if (hs->sco)
		return -EISCONN;

	hs->sco = g_io_channel_ref(io);

	if (slc->pending_ring) {
		ring_timer_cb(NULL);
		ag.ring_timer = g_timeout_add_seconds(RING_INTERVAL,
						ring_timer_cb,
						NULL);
		slc->pending_ring = FALSE;
	}

	return 0;
}

void headset_set_state(struct audio_device *dev, headset_state_t state)
{
	struct headset *hs = dev->headset;
	struct headset_slc *slc = hs->slc;
	gboolean value;
	const char *state_str;
	headset_state_t old_state = hs->state;
	GSList *l;

	if (old_state == state)
		return;

	state_str = state2str(state);

	switch (state) {
	case HEADSET_STATE_DISCONNECTED:
		value = FALSE;
		close_sco(dev);
		headset_close_rfcomm(dev);
		emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);
		g_dbus_emit_signal(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE,
					"Disconnected",
					DBUS_TYPE_INVALID);
		if (hs->state > HEADSET_STATE_CONNECTING) {
			emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "Connected",
					DBUS_TYPE_BOOLEAN, &value);
			telephony_device_disconnected(dev);
		}
		active_devices = g_slist_remove(active_devices, dev);
		break;
	case HEADSET_STATE_CONNECTING:
		emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);
		break;
	case HEADSET_STATE_CONNECTED:
		close_sco(dev);
		if (hs->state != HEADSET_STATE_PLAY_IN_PROGRESS)
			emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);
		if (hs->state < state) {
			if (ag.features & AG_FEATURE_INBAND_RINGTONE)
				slc->inband_ring = TRUE;
			else
				slc->inband_ring = FALSE;
			g_dbus_emit_signal(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Connected",
						DBUS_TYPE_INVALID);
			value = TRUE;
			emit_property_changed(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Connected",
						DBUS_TYPE_BOOLEAN, &value);
			active_devices = g_slist_append(active_devices, dev);
			telephony_device_connected(dev);
		} else if (hs->state == HEADSET_STATE_PLAYING) {
			value = FALSE;
			g_dbus_emit_signal(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Stopped",
						DBUS_TYPE_INVALID);
			emit_property_changed(dev->conn, dev->path,
						AUDIO_HEADSET_INTERFACE,
						"Playing",
						DBUS_TYPE_BOOLEAN, &value);
		}
		break;
	case HEADSET_STATE_PLAY_IN_PROGRESS:
		break;
	case HEADSET_STATE_PLAYING:
		value = TRUE;
		emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "State",
					DBUS_TYPE_STRING, &state_str);

		/* Do not watch HUP since we need to know when the link is
		   really disconnected */
		hs->sco_id = g_io_add_watch(hs->sco,
					G_IO_ERR | G_IO_NVAL,
					(GIOFunc) sco_cb, dev);

		g_dbus_emit_signal(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "Playing",
					DBUS_TYPE_INVALID);
		emit_property_changed(dev->conn, dev->path,
					AUDIO_HEADSET_INTERFACE, "Playing",
					DBUS_TYPE_BOOLEAN, &value);

		if (slc->sp_gain >= 0)
			headset_send(hs, "\r\n+VGS=%u\r\n", slc->sp_gain);
		if (slc->mic_gain >= 0)
			headset_send(hs, "\r\n+VGM=%u\r\n", slc->mic_gain);
		break;
	}

	hs->state = state;

	DBG("State changed %s: %s -> %s", dev->path, str_state[old_state],
		str_state[state]);

	for (l = headset_callbacks; l != NULL; l = l->next) {
		struct headset_state_callback *cb = l->data;
		cb->cb(dev, old_state, state, cb->user_data);
	}
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

headset_lock_t headset_get_lock(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	return hs->lock;
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
			hs->dc_timer = g_timeout_add_seconds(DC_TIMEOUT,
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

gboolean headset_get_nrec(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (!hs->slc)
		return TRUE;

	return hs->slc->nrec;
}

unsigned int headset_add_nrec_cb(struct audio_device *dev,
					headset_nrec_cb cb, void *user_data)
{
	struct headset *hs = dev->headset;
	struct headset_nrec_callback *nrec_cb;
	static unsigned int id = 0;

	nrec_cb = g_new(struct headset_nrec_callback, 1);
	nrec_cb->cb = cb;
	nrec_cb->user_data = user_data;
	nrec_cb->id = ++id;

	hs->nrec_cbs = g_slist_prepend(hs->nrec_cbs, nrec_cb);

	return nrec_cb->id;
}

gboolean headset_remove_nrec_cb(struct audio_device *dev, unsigned int id)
{
	struct headset *hs = dev->headset;
	GSList *l;

	for (l = hs->nrec_cbs; l != NULL; l = l->next) {
		struct headset_nrec_callback *cb = l->data;
		if (cb && cb->id == id) {
			hs->nrec_cbs = g_slist_remove(hs->nrec_cbs, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}

gboolean headset_get_inband(struct audio_device *dev)
{
	struct headset *hs = dev->headset;

	if (!hs->slc)
		return TRUE;

	return hs->slc->inband_ring;
}

gboolean headset_get_sco_hci(struct audio_device *dev)
{
	return sco_hci;
}

void headset_shutdown(struct audio_device *dev)
{
	struct pending_connect *p = dev->headset->pending;

	if (p && p->msg)
		error_connect_failed(dev->conn, p->msg, ECANCELED);

	pending_connect_finalize(dev);
	headset_set_state(dev, HEADSET_STATE_DISCONNECTED);
}

int telephony_event_ind(int index)
{
	if (!active_devices)
		return -ENODEV;

	if (!ag.er_ind) {
		DBG("telephony_report_event called but events are disabled");
		return -EINVAL;
	}

	send_foreach_headset(active_devices, hfp_cmp,
				"\r\n+CIEV: %d,%d\r\n", index + 1,
				ag.indicators[index].val);

	return 0;
}

int telephony_response_and_hold_ind(int rh)
{
	if (!active_devices)
		return -ENODEV;

	ag.rh = rh;

	/* If we aren't in any response and hold state don't send anything */
	if (ag.rh < 0)
		return 0;

	send_foreach_headset(active_devices, hfp_cmp, "\r\n+BTRH: %d\r\n",
				ag.rh);

	return 0;
}

int telephony_incoming_call_ind(const char *number, int type)
{
	struct audio_device *dev;
	struct headset *hs;
	struct headset_slc *slc;

	if (fast_connectable)
		manager_set_fast_connectable(TRUE);

	if (!active_devices)
		return -ENODEV;

	/* Get the latest connected device */
	dev = active_devices->data;
	hs = dev->headset;
	slc = hs->slc;

	if (ag.ring_timer) {
		DBG("telephony_incoming_call_ind: already calling");
		return -EBUSY;
	}

	/* With HSP 1.2 the RING messages should *not* be sent if inband
	 * ringtone is being used */
	if (!hs->hfp_active && slc->inband_ring)
		return 0;

	g_free(ag.number);
	ag.number = g_strdup(number);
	ag.number_type = type;

	if (slc->inband_ring && hs->hfp_active &&
					hs->state != HEADSET_STATE_PLAYING) {
		slc->pending_ring = TRUE;
		return 0;
	}

	ring_timer_cb(NULL);
	ag.ring_timer = g_timeout_add_seconds(RING_INTERVAL, ring_timer_cb,
						NULL);

	return 0;
}

int telephony_calling_stopped_ind(void)
{
	struct audio_device *dev;

	if (fast_connectable)
		manager_set_fast_connectable(FALSE);

	if (ag.ring_timer) {
		g_source_remove(ag.ring_timer);
		ag.ring_timer = 0;
	}

	if (!active_devices)
		return 0;

	/* In case SCO isn't fully up yet */
	dev = active_devices->data;

	if (!dev->headset->slc->pending_ring && !ag.ring_timer)
		return -EINVAL;

	dev->headset->slc->pending_ring = FALSE;

	return 0;
}

int telephony_ready_ind(uint32_t features,
			const struct indicator *indicators, int rh,
			const char *chld)
{
	ag.telephony_ready = TRUE;
	ag.features = features;
	ag.indicators = indicators;
	ag.rh = rh;
	ag.chld = chld;

	DBG("Telephony plugin initialized");

	print_ag_features(ag.features);

	return 0;
}

int telephony_deinit(void)
{
	g_free(ag.number);

	memset(&ag, 0, sizeof(ag));

	ag.er_mode = 3;
	ag.rh = BTRH_NOT_SUPPORTED;

	DBG("Telephony deinitialized");

	return 0;
}

int telephony_list_current_call_ind(int idx, int dir, int status, int mode,
					int mprty, const char *number,
					int type)
{
	if (!active_devices)
		return -ENODEV;

	if (number && strlen(number) > 0)
		send_foreach_headset(active_devices, hfp_cmp,
				"\r\n+CLCC: %d,%d,%d,%d,%d,\"%s\",%d\r\n",
				idx, dir, status, mode, mprty, number, type);
	else
		send_foreach_headset(active_devices, hfp_cmp,
					"\r\n+CLCC: %d,%d,%d,%d,%d\r\n",
					idx, dir, status, mode, mprty);

	return 0;
}

int telephony_subscriber_number_ind(const char *number, int type, int service)
{
	if (!active_devices)
		return -ENODEV;

	send_foreach_headset(active_devices, hfp_cmp,
				"\r\n+CNUM: ,%s,%d,,%d\r\n",
				number, type, service);

	return 0;
}

static int cwa_cmp(struct headset *hs)
{
	if (!hs->hfp_active)
		return -1;

	if (hs->slc->cwa_enabled)
		return 0;
	else
		return -1;
}

int telephony_call_waiting_ind(const char *number, int type)
{
	if (!active_devices)
		return -ENODEV;

	send_foreach_headset(active_devices, cwa_cmp,
				"\r\n+CCWA: \"%s\",%d\r\n",
				number, type);

	return 0;
}

unsigned int headset_add_state_cb(headset_state_cb cb, void *user_data)
{
	struct headset_state_callback *state_cb;
	static unsigned int id = 0;

	state_cb = g_new(struct headset_state_callback, 1);
	state_cb->cb = cb;
	state_cb->user_data = user_data;
	state_cb->id = ++id;

	headset_callbacks = g_slist_append(headset_callbacks, state_cb);

	return state_cb->id;
}

gboolean headset_remove_state_cb(unsigned int id)
{
	GSList *l;

	for (l = headset_callbacks; l != NULL; l = l->next) {
		struct headset_state_callback *cb = l->data;
		if (cb && cb->id == id) {
			headset_callbacks = g_slist_remove(headset_callbacks, cb);
			g_free(cb);
			return TRUE;
		}
	}

	return FALSE;
}
