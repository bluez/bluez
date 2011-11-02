/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2008-2010  Nokia Corporation
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include <bluetooth/sdp.h>

#include "glib-compat.h"
#include "log.h"
#include "telephony.h"
#include "error.h"

/* SSC D-Bus definitions */
#define SSC_DBUS_NAME  "com.nokia.phone.SSC"
#define SSC_DBUS_IFACE "com.nokia.phone.SSC"
#define SSC_DBUS_PATH  "/com/nokia/phone/SSC"

/* libcsnet D-Bus definitions */
#define CSD_CSNET_BUS_NAME	"com.nokia.csd.CSNet"
#define CSD_CSNET_PATH		"/com/nokia/csd/csnet"
#define CSD_CSNET_IFACE		"com.nokia.csd.CSNet"
#define CSD_CSNET_REGISTRATION	"com.nokia.csd.CSNet.NetworkRegistration"
#define CSD_CSNET_OPERATOR	"com.nokia.csd.CSNet.NetworkOperator"
#define CSD_CSNET_SIGNAL	"com.nokia.csd.CSNet.SignalStrength"

enum net_registration_status {
	NETWORK_REG_STATUS_HOME,
	NETWORK_REG_STATUS_ROAMING,
	NETWORK_REG_STATUS_OFFLINE,
	NETWORK_REG_STATUS_SEARCHING,
	NETWORK_REG_STATUS_NO_SIM,
	NETWORK_REG_STATUS_POWEROFF,
	NETWORK_REG_STATUS_POWERSAFE,
	NETWORK_REG_STATUS_NO_COVERAGE,
	NETWORK_REG_STATUS_REJECTED,
	NETWORK_REG_STATUS_UNKOWN
};

/* CSD CALL plugin D-Bus definitions */
#define CSD_CALL_BUS_NAME	"com.nokia.csd.Call"
#define CSD_CALL_INTERFACE	"com.nokia.csd.Call"
#define CSD_CALL_INSTANCE	"com.nokia.csd.Call.Instance"
#define CSD_CALL_CONFERENCE	"com.nokia.csd.Call.Conference"
#define CSD_CALL_PATH		"/com/nokia/csd/call"
#define CSD_CALL_CONFERENCE_PATH "/com/nokia/csd/call/conference"

/* Call status values as exported by the CSD CALL plugin */
#define CSD_CALL_STATUS_IDLE			0
#define CSD_CALL_STATUS_CREATE			1
#define CSD_CALL_STATUS_COMING			2
#define CSD_CALL_STATUS_PROCEEDING		3
#define CSD_CALL_STATUS_MO_ALERTING		4
#define CSD_CALL_STATUS_MT_ALERTING		5
#define CSD_CALL_STATUS_WAITING			6
#define CSD_CALL_STATUS_ANSWERED		7
#define CSD_CALL_STATUS_ACTIVE			8
#define CSD_CALL_STATUS_MO_RELEASE		9
#define CSD_CALL_STATUS_MT_RELEASE		10
#define CSD_CALL_STATUS_HOLD_INITIATED		11
#define CSD_CALL_STATUS_HOLD			12
#define CSD_CALL_STATUS_RETRIEVE_INITIATED	13
#define CSD_CALL_STATUS_RECONNECT_PENDING	14
#define CSD_CALL_STATUS_TERMINATED		15
#define CSD_CALL_STATUS_SWAP_INITIATED		16

#define CALL_FLAG_NONE				0
#define CALL_FLAG_PRESENTATION_ALLOWED		0x01
#define CALL_FLAG_PRESENTATION_RESTRICTED	0x02

/* SIM Phonebook D-Bus definitions */
#define CSD_SIMPB_BUS_NAME			"com.nokia.csd.SIM"
#define CSD_SIMPB_INTERFACE			"com.nokia.csd.SIM.Phonebook"
#define CSD_SIMPB_PATH				"/com/nokia/csd/sim/phonebook"

#define CSD_SIMPB_TYPE_ADN			"ADN"
#define CSD_SIMPB_TYPE_FDN			"FDN"
#define CSD_SIMPB_TYPE_SDN			"SDN"
#define CSD_SIMPB_TYPE_VMBX			"VMBX"
#define CSD_SIMPB_TYPE_MBDN			"MBDN"
#define CSD_SIMPB_TYPE_EN			"EN"
#define CSD_SIMPB_TYPE_MSISDN			"MSISDN"

/* OHM plugin D-Bus definitions */
#define OHM_BUS_NAME		"com.nokia.NonGraphicFeedback1"
#define OHM_INTERFACE		"com.nokia.NonGraphicFeedback1"
#define OHM_PATH		"/com/nokia/NonGraphicFeedback1"

/* tone-genenerator D-Bus definitions */
#define TONEGEN_BUS_NAME	"com.Nokia.Telephony.Tones"
#define TONEGEN_INTERFACE	"com.Nokia.Telephony.Tones"
#define TONEGEN_PATH		"/com/Nokia/Telephony/Tones"

/* tone-generator DTMF definitions */
#define DTMF_ASTERISK   10
#define DTMF_HASHMARK   11
#define DTMF_A          12
#define DTMF_B          13
#define DTMF_C          14
#define DTMF_D          15

#define FEEDBACK_TONE_DURATION			200

struct csd_call {
	char *object_path;
	int status;
	gboolean originating;
	gboolean emergency;
	gboolean on_hold;
	gboolean conference;
	char *number;
	gboolean setup;
};

static struct {
	char *operator_name;
	uint8_t status;
	int32_t signal_bars;
} net = {
	.operator_name = NULL,
	.status = NETWORK_REG_STATUS_UNKOWN,
	/* Init as 0 meaning inactive mode. In modem power off state
	 * can be be -1, but we treat all values as 0s regardless
	 * inactive or power off. */
	.signal_bars = 0,
};

struct pending_req {
	DBusPendingCall *call;
	void *user_data;
};

static int get_property(const char *iface, const char *prop);

static DBusConnection *connection = NULL;

static GSList *calls = NULL;
static GSList *watches = NULL;
static GSList *pending = NULL;

/* Reference count for determining the call indicator status */
static GSList *active_calls = NULL;

/* Queue of DTMF tones to play */
static GSList *tones = NULL;
static guint create_tones_timer = 0;

static char *msisdn = NULL;	/* Subscriber number */
static char *vmbx = NULL;	/* Voice mailbox number */

/* HAL battery namespace key values */
static int battchg_cur = -1;	/* "battery.charge_level.current" */
static int battchg_last = -1;	/* "battery.charge_level.last_full" */
static int battchg_design = -1;	/* "battery.charge_level.design" */

static gboolean get_calls_active = FALSE;

static gboolean events_enabled = FALSE;

/* Supported set of call hold operations */
static const char *chld_str = "0,1,1x,2,2x,3,4";

/* Timer for tracking call creation requests */
static guint create_request_timer = 0;

static struct indicator maemo_indicators[] =
{
	{ "battchg",	"0-5",	5,	TRUE },
	/* signal strength in terms of bars */
	{ "signal",	"0-5",	0,	TRUE },
	{ "service",	"0,1",	0,	TRUE },
	{ "call",	"0,1",	0,	TRUE },
	{ "callsetup",	"0-3",	0,	TRUE },
	{ "callheld",	"0-2",	0,	FALSE },
	{ "roam",	"0,1",	0,	TRUE },
	{ NULL }
};

static char *call_status_str[] = {
	"IDLE",
	"CREATE",
	"COMING",
	"PROCEEDING",
	"MO_ALERTING",
	"MT_ALERTING",
	"WAITING",
	"ANSWERED",
	"ACTIVE",
	"MO_RELEASE",
	"MT_RELEASE",
	"HOLD_INITIATED",
	"HOLD",
	"RETRIEVE_INITIATED",
	"RECONNECT_PENDING",
	"TERMINATED",
	"SWAP_INITIATED",
	"???"
};

static int send_method_call(const char *dest, const char *path,
				const char *interface, const char *method,
				DBusPendingCallNotifyFunction cb,
				void *user_data, int type, ...)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	va_list args;
	struct pending_req *req;

	msg = dbus_message_new_method_call(dest, path, interface, method);
	if (!msg) {
		error("Unable to allocate new D-Bus %s message", method);
		return -ENOMEM;
	}

	va_start(args, type);

	if (!dbus_message_append_args_valist(msg, type, args)) {
		dbus_message_unref(msg);
		va_end(args);
		return -EIO;
	}

	va_end(args);

	if (!cb) {
		g_dbus_send_message(connection, msg);
		return 0;
	}

	if (!dbus_connection_send_with_reply(connection, msg, &call, -1)) {
		error("Sending %s failed", method);
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, cb, user_data, NULL);

	req = g_new0(struct pending_req, 1);
	req->call = call;
	req->user_data = user_data;

	pending = g_slist_prepend(pending, req);
	dbus_message_unref(msg);

	return 0;
}

static struct csd_call *find_call(const char *path)
{
	GSList *l;

	for (l = calls; l != NULL; l = l->next) {
		struct csd_call *call = l->data;

		if (g_str_equal(call->object_path, path))
			return call;
	}

	return NULL;
}

static struct csd_call *find_non_held_call(void)
{
	GSList *l;

	for (l = calls; l != NULL; l = l->next) {
		struct csd_call *call = l->data;

		if (call->status == CSD_CALL_STATUS_IDLE)
			continue;

		if (call->status != CSD_CALL_STATUS_HOLD)
			return call;
	}

	return NULL;
}

static struct csd_call *find_non_idle_call(void)
{
	GSList *l;

	for (l = calls; l != NULL; l = l->next) {
		struct csd_call *call = l->data;

		if (call->status != CSD_CALL_STATUS_IDLE)
			return call;
	}

	return NULL;
}

static struct csd_call *find_call_with_status(int status)
{
	GSList *l;

	for (l = calls; l != NULL; l = l->next) {
		struct csd_call *call = l->data;

		if (call->status == status)
			return call;
	}

	return NULL;
}

static int release_conference(void)
{
	DBusMessage *msg;

	DBG("telephony-maemo6: releasing conference call");

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME,
						CSD_CALL_CONFERENCE_PATH,
						CSD_CALL_INSTANCE,
						"Release");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static int release_call(struct csd_call *call)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME,
						call->object_path,
						CSD_CALL_INSTANCE,
						"Release");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static int answer_call(struct csd_call *call)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME,
						call->object_path,
						CSD_CALL_INSTANCE,
						"Answer");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static struct pending_req *find_request(const DBusPendingCall *call)
{
	GSList *l;

	for (l = pending; l; l = l->next) {
		struct pending_req *req = l->data;

		if (req->call == call)
			return req;
	}

	return NULL;
}

static void pending_req_finalize(void *data)
{
	struct pending_req *req = data;

	if (!dbus_pending_call_get_completed(req->call))
		dbus_pending_call_cancel(req->call);

	dbus_pending_call_unref(req->call);
	g_free(req);
}

static void remove_pending(DBusPendingCall *call)
{
	struct pending_req *req = find_request(call);

	pending = g_slist_remove(pending, req);
	pending_req_finalize(req);
}

static void stop_ringtone_reply(DBusPendingCall *call, void *user_data)
{
	struct csd_call *coming = user_data;

	remove_pending(call);
	answer_call(coming);
}

static int stop_ringtone_and_answer(struct csd_call *call)
{
	int ret;

	ret = send_method_call(OHM_BUS_NAME, OHM_PATH,
				OHM_INTERFACE, "StopRingtone",
				stop_ringtone_reply, call,
				DBUS_TYPE_INVALID);
	if (ret < 0)
		return answer_call(call);

	return 0;
}

static int split_call(struct csd_call *call)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME,
						call->object_path,
						CSD_CALL_INSTANCE,
						"Split");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static int unhold_call(struct csd_call *call)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
						CSD_CALL_INTERFACE,
						"Unhold");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static int hold_call(struct csd_call *call)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
						CSD_CALL_INTERFACE,
						"Hold");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static int swap_calls(void)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
						CSD_CALL_INTERFACE,
						"Swap");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static int create_conference(void)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
						CSD_CALL_INTERFACE,
						"Conference");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static int call_transfer(void)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
						CSD_CALL_INTERFACE,
						"Transfer");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	g_dbus_send_message(connection, msg);

	return 0;
}

static int number_type(const char *number)
{
	if (number == NULL)
		return NUMBER_TYPE_TELEPHONY;

	if (number[0] == '+' || strncmp(number, "00", 2) == 0)
		return NUMBER_TYPE_INTERNATIONAL;

	return NUMBER_TYPE_TELEPHONY;
}

void telephony_device_connected(void *telephony_device)
{
	struct csd_call *coming;

	DBG("telephony-maemo6: device %p connected", telephony_device);

	coming = find_call_with_status(CSD_CALL_STATUS_MT_ALERTING);
	if (coming) {
		if (find_call_with_status(CSD_CALL_STATUS_ACTIVE))
			telephony_call_waiting_ind(coming->number,
						number_type(coming->number));
		else
			telephony_incoming_call_ind(coming->number,
						number_type(coming->number));
	}
}

static void remove_pending_by_data(gpointer data, gpointer user_data)
{
	struct pending_req *req = data;

	if (req->user_data == user_data) {
		pending = g_slist_remove(pending, req);
		pending_req_finalize(req);
	}
}

void telephony_device_disconnected(void *telephony_device)
{
	DBG("telephony-maemo6: device %p disconnected", telephony_device);
	events_enabled = FALSE;

	g_slist_foreach(pending, remove_pending_by_data, telephony_device);
}

void telephony_event_reporting_req(void *telephony_device, int ind)
{
	events_enabled = ind == 1 ? TRUE : FALSE;

	telephony_event_reporting_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_response_and_hold_req(void *telephony_device, int rh)
{
	telephony_response_and_hold_rsp(telephony_device,
						CME_ERROR_NOT_SUPPORTED);
}

void telephony_terminate_call_req(void *telephony_device)
{
	struct csd_call *call;
	struct csd_call *alerting;
	int err;

	call = find_call_with_status(CSD_CALL_STATUS_ACTIVE);
	if (!call)
		call = find_non_idle_call();

	if (!call) {
		error("No active call");
		telephony_terminate_call_rsp(telephony_device,
						CME_ERROR_NOT_ALLOWED);
		return;
	}

	alerting = find_call_with_status(CSD_CALL_STATUS_MO_ALERTING);
	if (call->on_hold && alerting)
		err = release_call(alerting);
	else if (call->conference)
		err = release_conference();
	else
		err = release_call(call);

	if (err < 0)
		telephony_terminate_call_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
	else
		telephony_terminate_call_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_answer_call_req(void *telephony_device)
{
	struct csd_call *call;

	call = find_call_with_status(CSD_CALL_STATUS_COMING);
	if (!call)
		call = find_call_with_status(CSD_CALL_STATUS_MT_ALERTING);

	if (!call)
		call = find_call_with_status(CSD_CALL_STATUS_PROCEEDING);

	if (!call)
		call = find_call_with_status(CSD_CALL_STATUS_WAITING);

	if (!call) {
		telephony_answer_call_rsp(telephony_device,
						CME_ERROR_NOT_ALLOWED);
		return;
	}

	if (stop_ringtone_and_answer(call) < 0)
		telephony_answer_call_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
	else
		telephony_answer_call_rsp(telephony_device, CME_ERROR_NONE);
}

static void create_call_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	void *telephony_device = user_data;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("csd replied with an error: %s, %s",
				err.name, err.message);
		if (g_strcmp0(err.name,
				"com.nokia.csd.Call.Error.CSInactive") == 0)
			telephony_dial_number_rsp(telephony_device,
						CME_ERROR_NO_NETWORK_SERVICE);
		else
			telephony_dial_number_rsp(telephony_device,
							CME_ERROR_AG_FAILURE);
		dbus_error_free(&err);
	} else
		telephony_dial_number_rsp(telephony_device, CME_ERROR_NONE);

	dbus_message_unref(reply);
	remove_pending(call);
}

void telephony_last_dialed_number_req(void *telephony_device)
{
	int ret;

	DBG("telephony-maemo6: last dialed number request");

	ret = send_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
				CSD_CALL_INTERFACE, "CreateFromLast",
				create_call_reply, telephony_device,
				DBUS_TYPE_INVALID);
	if (ret < 0)
		telephony_dial_number_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
}

static const char *memory_dial_lookup(int location)
{
	if (location == 1)
		return vmbx;
	else
		return NULL;
}

void telephony_dial_number_req(void *telephony_device, const char *number)
{
	int ret;

	DBG("telephony-maemo6: dial request to %s", number);

	if (strncmp(number, "*31#", 4) == 0)
		number += 4;
	else if (strncmp(number, "#31#", 4) == 0)
		number += 4;
	else if (number[0] == '>') {
		const char *location = &number[1];

		number = memory_dial_lookup(strtol(&number[1], NULL, 0));
		if (!number) {
			error("No number at memory location %s", location);
			telephony_dial_number_rsp(telephony_device,
						CME_ERROR_INVALID_INDEX);
			return;
		}
	}

	ret = send_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
				CSD_CALL_INTERFACE, "Create",
				create_call_reply, telephony_device,
				DBUS_TYPE_STRING, &number,
				DBUS_TYPE_INVALID);
	if (ret < 0)
		telephony_dial_number_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
}

static void start_dtmf_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("csd replied with an error: %s, %s",
				err.name, err.message);

		dbus_error_free(&err);
	} else
		send_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
				CSD_CALL_INTERFACE, "StopDTMF",
				NULL, NULL,
				DBUS_TYPE_INVALID);

	dbus_message_unref(reply);
	remove_pending(call);
}

static void start_dtmf(void *telephony_device, char tone)
{
	int ret;

	/*
	 * Stop tone immediately, modem will place it in queue and play
	 * required time.
	 */
	ret = send_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
				CSD_CALL_INTERFACE, "StartDTMF",
				start_dtmf_reply, NULL,
				DBUS_TYPE_BYTE, &tone,
				DBUS_TYPE_INVALID);
	if (ret < 0) {
		telephony_transmit_dtmf_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
		return;
	}

	telephony_transmit_dtmf_rsp(telephony_device, CME_ERROR_NONE);
}

static int tonegen_startevent(char tone)
{
	int ret;
	dbus_uint32_t event_tone;
	dbus_int32_t dbm0 = -15;
	dbus_uint32_t duration = 150;

	switch (tone) {
	case '*':
		event_tone = DTMF_ASTERISK;
		break;
	case '#':
		event_tone = DTMF_HASHMARK;
		break;
	case 'A':
		event_tone = DTMF_A;
		break;
	case 'B':
		event_tone = DTMF_B;
		break;
	case 'C':
		event_tone = DTMF_C;
		break;
	case 'D':
		event_tone = DTMF_D;
		break;
	default:
		ret = g_ascii_digit_value(tone);
		if (ret < 0)
			return -EINVAL;
		event_tone = ret;
	}

	ret = send_method_call(TONEGEN_BUS_NAME, TONEGEN_PATH,
				TONEGEN_INTERFACE, "StartEventTone",
				NULL, NULL,
				DBUS_TYPE_UINT32, &event_tone,
				DBUS_TYPE_INT32, &dbm0,
				DBUS_TYPE_UINT32, &duration,
				DBUS_TYPE_INVALID);
	return ret;
}

static gboolean stop_feedback_tone(gpointer user_data)
{
	if (g_slist_length(tones) > 0) {
		gpointer ptone;
		int ret;

		send_method_call(TONEGEN_BUS_NAME, TONEGEN_PATH,
				TONEGEN_INTERFACE, "StopTone",
				NULL, NULL,
				DBUS_TYPE_INVALID);

		ptone = g_slist_nth_data(tones, 0);
		tones = g_slist_remove(tones, ptone);

		ret = tonegen_startevent(GPOINTER_TO_UINT(ptone));
		if (ret < 0)
			goto done;

		return TRUE;
	}
done:
	return FALSE;
}

static void tones_timer_notify(gpointer data)
{
	send_method_call(TONEGEN_BUS_NAME, TONEGEN_PATH,
				TONEGEN_INTERFACE, "StopTone",
				NULL, NULL,
				DBUS_TYPE_INVALID);
	g_slist_free(tones);
	tones = NULL;

	create_tones_timer = 0;
}

static void start_feedback_tone(char tone)
{
	if (!create_tones_timer) {
		int ret;

		ret = tonegen_startevent(tone);
		if (ret < 0)
			return;

		create_tones_timer = g_timeout_add_full(G_PRIORITY_DEFAULT,
						FEEDBACK_TONE_DURATION,
						stop_feedback_tone,
						NULL,
						tones_timer_notify);
	} else {
		glong dtmf_tone = tone;

		DBG("add %c to queue", tone);
		tones = g_slist_append(tones, GUINT_TO_POINTER(dtmf_tone));
	}
}

void telephony_transmit_dtmf_req(void *telephony_device, char tone)
{
	DBG("telephony-maemo6: transmit dtmf: %c", tone);

	start_dtmf(telephony_device, tone);

	if (!find_call_with_status(CSD_CALL_STATUS_ACTIVE))
		error("No active call");
	else
		start_feedback_tone(tone);
}

void telephony_subscriber_number_req(void *telephony_device)
{
	DBG("telephony-maemo6: subscriber number request");
	if (msisdn)
		telephony_subscriber_number_ind(msisdn,
						number_type(msisdn),
						SUBSCRIBER_SERVICE_VOICE);
	telephony_subscriber_number_rsp(telephony_device, CME_ERROR_NONE);
}

static int csd_status_to_hfp(struct csd_call *call)
{
	switch (call->status) {
	case CSD_CALL_STATUS_IDLE:
	case CSD_CALL_STATUS_MO_RELEASE:
	case CSD_CALL_STATUS_MT_RELEASE:
	case CSD_CALL_STATUS_TERMINATED:
		return -1;
	case CSD_CALL_STATUS_CREATE:
		return CALL_STATUS_DIALING;
	case CSD_CALL_STATUS_WAITING:
		return CALL_STATUS_WAITING;
	case CSD_CALL_STATUS_PROCEEDING:
		/* PROCEEDING can happen in outgoing/incoming */
		if (call->originating)
			return CALL_STATUS_DIALING;

		/*
		 * PROCEEDING is followed by WAITING CSD status, therefore
		 * second incoming call status indication is set immediately
		 * to waiting.
		 */
		if (g_slist_length(active_calls) > 0)
			return CALL_STATUS_WAITING;

		return CALL_STATUS_INCOMING;
	case CSD_CALL_STATUS_COMING:
		if (g_slist_length(active_calls) > 0)
			return CALL_STATUS_WAITING;

		return CALL_STATUS_INCOMING;
	case CSD_CALL_STATUS_MO_ALERTING:
		return CALL_STATUS_ALERTING;
	case CSD_CALL_STATUS_MT_ALERTING:
		return CALL_STATUS_INCOMING;
	case CSD_CALL_STATUS_ANSWERED:
	case CSD_CALL_STATUS_ACTIVE:
	case CSD_CALL_STATUS_RECONNECT_PENDING:
	case CSD_CALL_STATUS_SWAP_INITIATED:
	case CSD_CALL_STATUS_HOLD_INITIATED:
		return CALL_STATUS_ACTIVE;
	case CSD_CALL_STATUS_RETRIEVE_INITIATED:
	case CSD_CALL_STATUS_HOLD:
		return CALL_STATUS_HELD;
	default:
		return -1;
	}
}

void telephony_list_current_calls_req(void *telephony_device)
{
	GSList *l;
	int i;

	DBG("telephony-maemo6: list current calls request");

	for (l = calls, i = 1; l != NULL; l = l->next, i++) {
		struct csd_call *call = l->data;
		int status, direction, multiparty;

		status = csd_status_to_hfp(call);
		if (status < 0)
			continue;

		direction = call->originating ?
				CALL_DIR_OUTGOING : CALL_DIR_INCOMING;

		multiparty = call->conference ?
				CALL_MULTIPARTY_YES : CALL_MULTIPARTY_NO;

		telephony_list_current_call_ind(i, direction, status,
						CALL_MODE_VOICE, multiparty,
						call->number,
						number_type(call->number));
	}

	telephony_list_current_calls_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_operator_selection_req(void *telephony_device)
{
	telephony_operator_selection_ind(OPERATOR_MODE_AUTO,
				net.operator_name ? net.operator_name : "");
	telephony_operator_selection_rsp(telephony_device, CME_ERROR_NONE);
}

static void foreach_call_with_status(int status,
					int (*func)(struct csd_call *call))
{
	GSList *l;

	for (l = calls; l != NULL; l = l->next) {
		struct csd_call *call = l->data;

		if (call->status == status)
			func(call);
	}
}

void telephony_call_hold_req(void *telephony_device, const char *cmd)
{
	const char *idx;
	struct csd_call *call;
	int err = 0;

	DBG("telephony-maemo6: got call hold request %s", cmd);

	if (strlen(cmd) > 1)
		idx = &cmd[1];
	else
		idx = NULL;

	if (idx)
		call = g_slist_nth_data(calls, strtol(idx, NULL, 0) - 1);
	else
		call = NULL;

	switch (cmd[0]) {
	case '0':
		if (find_call_with_status(CSD_CALL_STATUS_WAITING))
			foreach_call_with_status(CSD_CALL_STATUS_WAITING,
								release_call);
		else
			foreach_call_with_status(CSD_CALL_STATUS_HOLD,
								release_call);
		break;
	case '1':
		if (idx) {
			if (call)
				err = release_call(call);
			break;
		}
		foreach_call_with_status(CSD_CALL_STATUS_ACTIVE, release_call);
		call = find_call_with_status(CSD_CALL_STATUS_WAITING);
		if (call)
			err = answer_call(call);
		break;
	case '2':
		if (idx) {
			if (call)
				err = split_call(call);
		} else {
			struct csd_call *held, *wait;

			call = find_call_with_status(CSD_CALL_STATUS_ACTIVE);
			held = find_call_with_status(CSD_CALL_STATUS_HOLD);
			wait = find_call_with_status(CSD_CALL_STATUS_WAITING);

			if (wait)
				err = answer_call(wait);
			else if (call && held)
				err = swap_calls();
			else {
				if (call)
					err = hold_call(call);
				if (held)
					err = unhold_call(held);
			}
		}
		break;
	case '3':
		if (find_call_with_status(CSD_CALL_STATUS_HOLD) ||
				find_call_with_status(CSD_CALL_STATUS_WAITING))
			err = create_conference();
		break;
	case '4':
		err = call_transfer();
		break;
	default:
		DBG("Unknown call hold request");
		break;
	}

	if (err)
		telephony_call_hold_rsp(telephony_device,
					CME_ERROR_AG_FAILURE);
	else
		telephony_call_hold_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_nr_and_ec_req(void *telephony_device, gboolean enable)
{
	DBG("telephony-maemo6: got %s NR and EC request",
			enable ? "enable" : "disable");
	telephony_nr_and_ec_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_key_press_req(void *telephony_device, const char *keys)
{
	struct csd_call *active, *waiting;
	int err;

	DBG("telephony-maemo6: got key press request for %s", keys);

	waiting = find_call_with_status(CSD_CALL_STATUS_COMING);
	if (!waiting)
		waiting = find_call_with_status(CSD_CALL_STATUS_MT_ALERTING);
	if (!waiting)
		waiting = find_call_with_status(CSD_CALL_STATUS_PROCEEDING);

	active = find_call_with_status(CSD_CALL_STATUS_ACTIVE);

	if (waiting)
		err = answer_call(waiting);
	else if (active)
		err = release_call(active);
	else
		err = 0;

	if (err < 0)
		telephony_key_press_rsp(telephony_device,
							CME_ERROR_AG_FAILURE);
	else
		telephony_key_press_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_voice_dial_req(void *telephony_device, gboolean enable)
{
	DBG("telephony-maemo6: got %s voice dial request",
			enable ? "enable" : "disable");

	telephony_voice_dial_rsp(telephony_device, CME_ERROR_NOT_SUPPORTED);
}

static void handle_incoming_call(DBusMessage *msg)
{
	const char *number, *call_path;
	struct csd_call *call;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_OBJECT_PATH, &call_path,
					DBUS_TYPE_STRING, &number,
					DBUS_TYPE_INVALID)) {
		error("Unexpected parameters in Call.Coming() signal");
		return;
	}

	call = find_call(call_path);
	if (!call) {
		error("Didn't find any matching call object for %s",
				call_path);
		return;
	}

	DBG("Incoming call to %s from number %s", call_path, number);

	g_free(call->number);
	call->number = g_strdup(number);

	if (find_call_with_status(CSD_CALL_STATUS_ACTIVE) ||
			find_call_with_status(CSD_CALL_STATUS_HOLD))
		telephony_call_waiting_ind(call->number,
						number_type(call->number));
	else
		telephony_incoming_call_ind(call->number,
						number_type(call->number));

	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_INCOMING);
}

static void handle_outgoing_call(DBusMessage *msg)
{
	const char *number, *call_path;
	struct csd_call *call;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_OBJECT_PATH, &call_path,
					DBUS_TYPE_STRING, &number,
					DBUS_TYPE_INVALID)) {
		error("Unexpected parameters in Call.Created() signal");
		return;
	}

	call = find_call(call_path);
	if (!call) {
		error("Didn't find any matching call object for %s",
				call_path);
		return;
	}

	DBG("Outgoing call from %s to number %s", call_path, number);

	g_free(call->number);
	call->number = g_strdup(number);

	if (create_request_timer) {
		g_source_remove(create_request_timer);
		create_request_timer = 0;
	}
}

static gboolean create_timeout(gpointer user_data)
{
	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_INACTIVE);
	create_request_timer = 0;
	return FALSE;
}

static void handle_create_requested(DBusMessage *msg)
{
	DBG("Call.CreateRequested()");

	if (create_request_timer)
		g_source_remove(create_request_timer);

	create_request_timer = g_timeout_add_seconds(5, create_timeout, NULL);

	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_OUTGOING);
}

static void call_set_status(struct csd_call *call, dbus_uint32_t status)
{
	dbus_uint32_t prev_status;
	int callheld = telephony_get_indicator(maemo_indicators, "callheld");

	prev_status = call->status;
	DBG("Call %s changed from %s to %s", call->object_path,
		call_status_str[prev_status], call_status_str[status]);

	if (prev_status == status) {
		DBG("Ignoring CSD Call state change to existing state");
		return;
	}

	call->status = (int) status;

	switch (status) {
	case CSD_CALL_STATUS_IDLE:
		if (call->setup) {
			telephony_update_indicator(maemo_indicators,
							"callsetup",
							EV_CALLSETUP_INACTIVE);
			if (!call->originating)
				telephony_calling_stopped_ind();
		}

		g_free(call->number);
		call->number = NULL;
		call->originating = FALSE;
		call->emergency = FALSE;
		call->on_hold = FALSE;
		call->conference = FALSE;
		call->setup = FALSE;
		break;
	case CSD_CALL_STATUS_CREATE:
		call->originating = TRUE;
		call->setup = TRUE;
		break;
	case CSD_CALL_STATUS_COMING:
		call->originating = FALSE;
		call->setup = TRUE;
		break;
	case CSD_CALL_STATUS_PROCEEDING:
		break;
	case CSD_CALL_STATUS_MO_ALERTING:
		telephony_update_indicator(maemo_indicators, "callsetup",
						EV_CALLSETUP_ALERTING);
		break;
	case CSD_CALL_STATUS_MT_ALERTING:
		/* Some headsets expect incoming call notification before they
		 * can send ATA command. When call changed status from waiting
		 * to alerting we need to send missing notification. Otherwise
		 * headsets like Nokia BH-108 or BackBeat 903 are unable to
		 * answer incoming call that was previously waiting. */
		if (prev_status == CSD_CALL_STATUS_WAITING)
			telephony_incoming_call_ind(call->number,
						number_type(call->number));
		break;
	case CSD_CALL_STATUS_WAITING:
		break;
	case CSD_CALL_STATUS_ANSWERED:
		break;
	case CSD_CALL_STATUS_ACTIVE:
		if (call->on_hold) {
			call->on_hold = FALSE;
			if (find_call_with_status(CSD_CALL_STATUS_HOLD))
				telephony_update_indicator(maemo_indicators,
							"callheld",
							EV_CALLHELD_MULTIPLE);
			else
				telephony_update_indicator(maemo_indicators,
							"callheld",
							EV_CALLHELD_NONE);
		} else {
			if (!g_slist_find(active_calls, call))
				active_calls = g_slist_prepend(active_calls, call);
			if (g_slist_length(active_calls) == 1)
				telephony_update_indicator(maemo_indicators,
								"call",
								EV_CALL_ACTIVE);
			/* Upgrade callheld status if necessary */
			if (callheld == EV_CALLHELD_ON_HOLD)
				telephony_update_indicator(maemo_indicators,
							"callheld",
							EV_CALLHELD_MULTIPLE);
			telephony_update_indicator(maemo_indicators,
							"callsetup",
							EV_CALLSETUP_INACTIVE);
			if (!call->originating)
				telephony_calling_stopped_ind();
			call->setup = FALSE;
		}
		break;
	case CSD_CALL_STATUS_MO_RELEASE:
	case CSD_CALL_STATUS_MT_RELEASE:
		active_calls = g_slist_remove(active_calls, call);
		if (g_slist_length(active_calls) == 0)
			telephony_update_indicator(maemo_indicators, "call",
							EV_CALL_INACTIVE);

		if (create_tones_timer)
			g_source_remove(create_tones_timer);
		break;
	case CSD_CALL_STATUS_HOLD_INITIATED:
		break;
	case CSD_CALL_STATUS_HOLD:
		call->on_hold = TRUE;
		if (find_non_held_call())
			telephony_update_indicator(maemo_indicators,
							"callheld",
							EV_CALLHELD_MULTIPLE);
		else
			telephony_update_indicator(maemo_indicators,
							"callheld",
							EV_CALLHELD_ON_HOLD);
		break;
	case CSD_CALL_STATUS_RETRIEVE_INITIATED:
		break;
	case CSD_CALL_STATUS_RECONNECT_PENDING:
		break;
	case CSD_CALL_STATUS_TERMINATED:
		if (call->on_hold &&
				!find_call_with_status(CSD_CALL_STATUS_HOLD)) {
			telephony_update_indicator(maemo_indicators,
							"callheld",
							EV_CALLHELD_NONE);
			return;
		}

		if (callheld == EV_CALLHELD_MULTIPLE &&
				find_call_with_status(CSD_CALL_STATUS_HOLD) &&
				!find_call_with_status(CSD_CALL_STATUS_ACTIVE))
			telephony_update_indicator(maemo_indicators,
							"callheld",
							EV_CALLHELD_ON_HOLD);
		break;
	case CSD_CALL_STATUS_SWAP_INITIATED:
		break;
	default:
		error("Unknown call status %u", status);
		break;
	}
}

static void handle_call_status(DBusMessage *msg, const char *call_path)
{
	struct csd_call *call;
	dbus_uint32_t status, cause_type, cause;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_UINT32, &status,
					DBUS_TYPE_UINT32, &cause_type,
					DBUS_TYPE_UINT32, &cause,
					DBUS_TYPE_INVALID)) {
		error("Unexpected paramters in Instance.CallStatus() signal");
		return;
	}

	call = find_call(call_path);
	if (!call) {
		error("Didn't find any matching call object for %s",
				call_path);
		return;
	}

	if (status > 16) {
		error("Invalid call status %u", status);
		return;
	}

	call_set_status(call, status);
}

static void handle_conference(DBusMessage *msg, gboolean joined)
{
	const char *path;
	struct csd_call *call;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_OBJECT_PATH, &path,
					DBUS_TYPE_INVALID)) {
		error("Unexpected parameters in Conference.%s",
					dbus_message_get_member(msg));
		return;
	}

	call = find_call(path);
	if (!call) {
		error("Conference signal for unknown call %s", path);
		return;
	}

	DBG("Call %s %s the conference", path, joined ? "joined" : "left");

	call->conference = joined;
}

static uint8_t str2status(const char *state)
{
	if (g_strcmp0(state, "Home") == 0)
		return NETWORK_REG_STATUS_HOME;
	else if (g_strcmp0(state, "Roaming") == 0)
		return NETWORK_REG_STATUS_ROAMING;
	else if (g_strcmp0(state, "Offline") == 0)
		return NETWORK_REG_STATUS_OFFLINE;
	else if (g_strcmp0(state, "Searching") == 0)
		return NETWORK_REG_STATUS_SEARCHING;
	else if (g_strcmp0(state, "NoSim") == 0)
		return NETWORK_REG_STATUS_NO_SIM;
	else if (g_strcmp0(state, "Poweroff") == 0)
		return NETWORK_REG_STATUS_POWEROFF;
	else if (g_strcmp0(state, "Powersafe") == 0)
		return NETWORK_REG_STATUS_POWERSAFE;
	else if (g_strcmp0(state, "NoCoverage") == 0)
		return NETWORK_REG_STATUS_NO_COVERAGE;
	else if (g_strcmp0(state, "Reject") == 0)
		return NETWORK_REG_STATUS_REJECTED;
	else
		return NETWORK_REG_STATUS_UNKOWN;
}

static void update_registration_status(const char *status)
{
	uint8_t new_status;

	new_status = str2status(status);

	if (net.status == new_status)
		return;

	switch (new_status) {
	case NETWORK_REG_STATUS_HOME:
		telephony_update_indicator(maemo_indicators, "roam",
							EV_ROAM_INACTIVE);
		if (net.status > NETWORK_REG_STATUS_ROAMING)
			telephony_update_indicator(maemo_indicators,
							"service",
							EV_SERVICE_PRESENT);
		break;
	case NETWORK_REG_STATUS_ROAMING:
		telephony_update_indicator(maemo_indicators, "roam",
							EV_ROAM_ACTIVE);
		if (net.status > NETWORK_REG_STATUS_ROAMING)
			telephony_update_indicator(maemo_indicators,
							"service",
							EV_SERVICE_PRESENT);
		break;
	case NETWORK_REG_STATUS_OFFLINE:
	case NETWORK_REG_STATUS_SEARCHING:
	case NETWORK_REG_STATUS_NO_SIM:
	case NETWORK_REG_STATUS_POWEROFF:
	case NETWORK_REG_STATUS_POWERSAFE:
	case NETWORK_REG_STATUS_NO_COVERAGE:
	case NETWORK_REG_STATUS_REJECTED:
	case NETWORK_REG_STATUS_UNKOWN:
		if (net.status < NETWORK_REG_STATUS_OFFLINE)
			telephony_update_indicator(maemo_indicators,
							"service",
							EV_SERVICE_NONE);
		break;
	}

	net.status = new_status;

	DBG("telephony-maemo6: registration status changed: %s", status);
}

static void handle_registration_changed(DBusMessage *msg)
{
	const char *status;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &status,
					DBUS_TYPE_INVALID)) {
		error("Unexpected parameters in RegistrationChanged");
		return;
	}

	update_registration_status(status);
}

static void update_signal_strength(int32_t signal_bars)
{
	if (signal_bars < 0) {
		DBG("signal strength smaller than expected: %d < 0",
								signal_bars);
		signal_bars = 0;
	} else if (signal_bars > 5) {
		DBG("signal strength greater than expected: %d > 5",
								signal_bars);
		signal_bars = 5;
	}

	if (net.signal_bars == signal_bars)
		return;

	telephony_update_indicator(maemo_indicators, "signal", signal_bars);

	net.signal_bars = signal_bars;
	DBG("telephony-maemo6: signal strength updated: %d/5", signal_bars);
}

static void handle_signal_bars_changed(DBusMessage *msg)
{
	int32_t signal_bars;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_INT32, &signal_bars,
					DBUS_TYPE_INVALID)) {
		error("Unexpected parameters in SignalBarsChanged");
		return;
	}

	update_signal_strength(signal_bars);
}

static gboolean iter_get_basic_args(DBusMessageIter *iter,
					int first_arg_type, ...)
{
	int type;
	va_list ap;

	va_start(ap, first_arg_type);

	for (type = first_arg_type; type != DBUS_TYPE_INVALID;
			type = va_arg(ap, int)) {
		void *value = va_arg(ap, void *);
		int real_type = dbus_message_iter_get_arg_type(iter);

		if (real_type != type) {
			error("iter_get_basic_args: expected %c but got %c",
					(char) type, (char) real_type);
			break;
		}

		dbus_message_iter_get_basic(iter, value);
		dbus_message_iter_next(iter);
	}

	va_end(ap);

	return type == DBUS_TYPE_INVALID ? TRUE : FALSE;
}

static void hal_battery_level_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	dbus_int32_t level;
	int *value = user_data;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("hald replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	if (!dbus_message_get_args(reply, NULL,
				DBUS_TYPE_INT32, &level,
				DBUS_TYPE_INVALID)) {
		error("Unexpected args in hald reply");
		goto done;
	}

	*value = (int) level;

	if (value == &battchg_last)
		DBG("telephony-maemo6: battery.charge_level.last_full is %d",
				*value);
	else if (value == &battchg_design)
		DBG("telephony-maemo6: battery.charge_level.design is %d",
				*value);
	else
		DBG("telephony-maemo6: battery.charge_level.current is %d",
				*value);

	if ((battchg_design > 0 || battchg_last > 0) && battchg_cur >= 0) {
		int new, max;

		if (battchg_last > 0)
			max = battchg_last;
		else
			max = battchg_design;

		new = battchg_cur * 5 / max;

		telephony_update_indicator(maemo_indicators, "battchg", new);
	}

done:
	dbus_message_unref(reply);
	remove_pending(call);
}

static void hal_get_integer(const char *path, const char *key, void *user_data)
{
	send_method_call("org.freedesktop.Hal", path,
				"org.freedesktop.Hal.Device",
				"GetPropertyInteger",
				hal_battery_level_reply, user_data,
				DBUS_TYPE_STRING, &key,
				DBUS_TYPE_INVALID);
}

static void handle_hal_property_modified(DBusMessage *msg)
{
	DBusMessageIter iter, array;
	dbus_int32_t num_changes;
	const char *path;

	path = dbus_message_get_path(msg);

	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32) {
		error("Unexpected signature in hal PropertyModified signal");
		return;
	}

	dbus_message_iter_get_basic(&iter, &num_changes);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("Unexpected signature in hal PropertyModified signal");
		return;
	}

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_INVALID) {
		DBusMessageIter prop;
		const char *name;
		dbus_bool_t added, removed;

		dbus_message_iter_recurse(&array, &prop);

		if (!iter_get_basic_args(&prop,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_BOOLEAN, &added,
					DBUS_TYPE_BOOLEAN, &removed,
					DBUS_TYPE_INVALID)) {
			error("Invalid hal PropertyModified parameters");
			break;
		}

		if (g_str_equal(name, "battery.charge_level.last_full"))
			hal_get_integer(path, name, &battchg_last);
		else if (g_str_equal(name, "battery.charge_level.current"))
			hal_get_integer(path, name, &battchg_cur);
		else if (g_str_equal(name, "battery.charge_level.design"))
			hal_get_integer(path, name, &battchg_design);

		dbus_message_iter_next(&array);
	}
}

static void csd_call_free(void *data)
{
	struct csd_call *call = data;

	if (!call)
		return;

	g_free(call->object_path);
	g_free(call->number);

	g_slist_foreach(pending, remove_pending_by_data, call);

	g_free(call);
}

static void parse_call_list(DBusMessageIter *iter)
{
	do {
		DBusMessageIter call_iter;
		struct csd_call *call;
		const char *object_path, *number;
		dbus_uint32_t status;
		dbus_bool_t originating, terminating, emerg, on_hold, conf;

		if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRUCT) {
			error("Unexpected signature in GetCallInfoAll reply");
			break;
		}

		dbus_message_iter_recurse(iter, &call_iter);

		if (!iter_get_basic_args(&call_iter,
					DBUS_TYPE_OBJECT_PATH, &object_path,
					DBUS_TYPE_UINT32, &status,
					DBUS_TYPE_BOOLEAN, &originating,
					DBUS_TYPE_BOOLEAN, &terminating,
					DBUS_TYPE_BOOLEAN, &emerg,
					DBUS_TYPE_BOOLEAN, &on_hold,
					DBUS_TYPE_BOOLEAN, &conf,
					DBUS_TYPE_STRING, &number,
					DBUS_TYPE_INVALID)) {
			error("Parsing call D-Bus parameters failed");
			break;
		}

		call = find_call(object_path);
		if (!call) {
			call = g_new0(struct csd_call, 1);
			call->object_path = g_strdup(object_path);
			calls = g_slist_append(calls, call);
			DBG("telephony-maemo6: new csd call instance at %s",
								object_path);
		}

		if (status == CSD_CALL_STATUS_IDLE)
			continue;

		/* CSD gives incorrect call_hold property sometimes */
		if ((call->status != CSD_CALL_STATUS_HOLD && on_hold) ||
				(call->status == CSD_CALL_STATUS_HOLD &&
								!on_hold)) {
			error("Conflicting call status and on_hold property!");
			on_hold = call->status == CSD_CALL_STATUS_HOLD;
		}

		call->originating = originating;
		call->on_hold = on_hold;
		call->conference = conf;
		g_free(call->number);
		call->number = g_strdup(number);

		/* Update indicators */
		call_set_status(call, status);

	} while (dbus_message_iter_next(iter));
}

static void update_operator_name(const char *name)
{
	if (name == NULL)
		return;

	g_free(net.operator_name);
	net.operator_name = g_strndup(name, 16);
	DBG("telephony-maemo6: operator name updated: %s", name);
}

static void get_property_reply(DBusPendingCall *call, void *user_data)
{
	char *prop = user_data;
	DBusError err;
	DBusMessage *reply;
	DBusMessageIter iter, sub;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("csd replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_message_iter_init(reply, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
		error("Unexpected signature in Get return");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &sub);

	if (g_strcmp0(prop, "RegistrationStatus") == 0) {
		const char *status;

		dbus_message_iter_get_basic(&sub, &status);
		update_registration_status(status);

		get_property(CSD_CSNET_OPERATOR, "OperatorName");
		get_property(CSD_CSNET_SIGNAL, "SignalBars");
	} else if (g_strcmp0(prop, "OperatorName") == 0) {
		const char *name;

		dbus_message_iter_get_basic(&sub, &name);
		update_operator_name(name);
	} else if (g_strcmp0(prop, "SignalBars") == 0) {
		int32_t signal_bars;

		dbus_message_iter_get_basic(&sub, &signal_bars);
		update_signal_strength(signal_bars);
	}

done:
	g_free(prop);
	dbus_message_unref(reply);
	remove_pending(call);
}

static int get_property(const char *iface, const char *prop)
{
	return send_method_call(CSD_CSNET_BUS_NAME, CSD_CSNET_PATH,
				DBUS_INTERFACE_PROPERTIES, "Get",
				get_property_reply, g_strdup(prop),
				DBUS_TYPE_STRING, &iface,
				DBUS_TYPE_STRING, &prop,
				DBUS_TYPE_INVALID);
}

static void handle_operator_name_changed(DBusMessage *msg)
{
	const char *name;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID)) {
		error("Unexpected parameters in OperatorNameChanged");
		return;
	}

	update_operator_name(name);
}

static void call_info_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	DBusMessageIter iter, sub;

	get_calls_active = FALSE;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("csd replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_message_iter_init(reply, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("Unexpected signature in GetCallInfoAll return");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &sub);

	parse_call_list(&sub);

	get_property(CSD_CSNET_REGISTRATION, "RegistrationStatus");

done:
	dbus_message_unref(reply);
	remove_pending(call);
}


static void phonebook_read_reply(DBusPendingCall *call, void *user_data)
{
	DBusError derr;
	DBusMessage *reply;
	const char *name, *number, *secondname, *additionalnumber, *email;
	int index;
	char **number_type = user_data;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("%s.ReadFirst replied with an error: %s, %s",
				CSD_SIMPB_INTERFACE, derr.name, derr.message);
		dbus_error_free(&derr);
		if (number_type == &vmbx)
			vmbx = g_strdup(getenv("VMBX_NUMBER"));
		goto done;
	}

	dbus_error_init(&derr);
	if (dbus_message_get_args(reply, NULL,
				DBUS_TYPE_INT32, &index,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &number,
				DBUS_TYPE_STRING, &secondname,
				DBUS_TYPE_STRING, &additionalnumber,
				DBUS_TYPE_STRING, &email,
				DBUS_TYPE_INVALID) == FALSE) {
		error("Unable to parse %s.ReadFirst arguments: %s, %s",
				CSD_SIMPB_INTERFACE, derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	if (number_type == &msisdn) {
		g_free(msisdn);
		msisdn = g_strdup(number);
		DBG("Got MSISDN %s (%s)", number, name);
	} else {
		g_free(vmbx);
		vmbx = g_strdup(number);
		DBG("Got voice mailbox number %s (%s)", number, name);
	}

done:
	dbus_message_unref(reply);
	remove_pending(call);
}

static void csd_init(void)
{
	const char *pb_type;
	int ret;

	ret = send_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
				CSD_CALL_INTERFACE, "GetCallInfoAll",
				call_info_reply, NULL, DBUS_TYPE_INVALID);
	if (ret < 0) {
		error("Unable to sent GetCallInfoAll method call");
		return;
	}

	get_calls_active = TRUE;

	pb_type = CSD_SIMPB_TYPE_MSISDN;

	ret = send_method_call(CSD_SIMPB_BUS_NAME, CSD_SIMPB_PATH,
				CSD_SIMPB_INTERFACE, "ReadFirst",
				phonebook_read_reply, &msisdn,
				DBUS_TYPE_STRING, &pb_type,
				DBUS_TYPE_INVALID);
	if (ret < 0) {
		error("Unable to send " CSD_SIMPB_INTERFACE ".read()");
		return;
	}

	/* Voicemail should be in MBDN index 0 */
	pb_type = CSD_SIMPB_TYPE_MBDN;

	ret = send_method_call(CSD_SIMPB_BUS_NAME, CSD_SIMPB_PATH,
				CSD_SIMPB_INTERFACE, "ReadFirst",
				phonebook_read_reply, &vmbx,
				DBUS_TYPE_STRING, &pb_type,
				DBUS_TYPE_INVALID);
	if (ret < 0) {
		error("Unable to send " CSD_SIMPB_INTERFACE ".read()");
		return;
	}
}

static void handle_modem_state(DBusMessage *msg)
{
	const char *state;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &state,
							DBUS_TYPE_INVALID)) {
		error("Unexpected modem state parameters");
		return;
	}

	DBG("SSC modem state: %s", state);

	if (calls != NULL || get_calls_active)
		return;

	if (g_str_equal(state, "cmt_ready") || g_str_equal(state, "online"))
		csd_init();
}

static void modem_state_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError err;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("get_modem_state: %s, %s", err.name, err.message);
		dbus_error_free(&err);
	} else
		handle_modem_state(reply);

	dbus_message_unref(reply);
	remove_pending(call);
}

static gboolean signal_filter(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	const char *path = dbus_message_get_path(msg);

	if (dbus_message_is_signal(msg, CSD_CALL_INTERFACE, "Coming"))
		handle_incoming_call(msg);
	else if (dbus_message_is_signal(msg, CSD_CALL_INTERFACE, "Created"))
		handle_outgoing_call(msg);
	else if (dbus_message_is_signal(msg, CSD_CALL_INTERFACE,
							"CreateRequested"))
		handle_create_requested(msg);
	else if (dbus_message_is_signal(msg, CSD_CALL_INSTANCE, "CallStatus"))
		handle_call_status(msg, path);
	else if (dbus_message_is_signal(msg, CSD_CALL_CONFERENCE, "Joined"))
		handle_conference(msg, TRUE);
	else if (dbus_message_is_signal(msg, CSD_CALL_CONFERENCE, "Left"))
		handle_conference(msg, FALSE);
	else if (dbus_message_is_signal(msg, CSD_CSNET_REGISTRATION,
				"RegistrationChanged"))
		handle_registration_changed(msg);
	else if (dbus_message_is_signal(msg, CSD_CSNET_OPERATOR,
				"OperatorNameChanged"))
		handle_operator_name_changed(msg);
	else if (dbus_message_is_signal(msg, CSD_CSNET_SIGNAL,
				"SignalBarsChanged"))
		handle_signal_bars_changed(msg);
	else if (dbus_message_is_signal(msg, "org.freedesktop.Hal.Device",
					"PropertyModified"))
		handle_hal_property_modified(msg);
	else if (dbus_message_is_signal(msg, SSC_DBUS_IFACE,
						"modem_state_changed_ind"))
		handle_modem_state(msg);

	return TRUE;
}

static void add_watch(const char *sender, const char *path,
				const char *interface, const char *member)
{
	guint watch;

	watch = g_dbus_add_signal_watch(connection, sender, path, interface,
					member, signal_filter, NULL, NULL);

	watches = g_slist_prepend(watches, GUINT_TO_POINTER(watch));
}

static void hal_find_device_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	DBusMessageIter iter, sub;
	const char *path;
	int type;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("hald replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_message_iter_init(reply, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("Unexpected signature in FindDeviceByCapability return");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &sub);

	type = dbus_message_iter_get_arg_type(&sub);

	if (type != DBUS_TYPE_OBJECT_PATH && type != DBUS_TYPE_STRING) {
		error("No hal device with battery capability found");
		goto done;
	}

	dbus_message_iter_get_basic(&sub, &path);

	DBG("telephony-maemo6: found battery device at %s", path);

	add_watch(NULL, path, "org.freedesktop.Hal.Device",
							"PropertyModified");

	hal_get_integer(path, "battery.charge_level.last_full", &battchg_last);
	hal_get_integer(path, "battery.charge_level.current", &battchg_cur);
	hal_get_integer(path, "battery.charge_level.design", &battchg_design);

done:
	dbus_message_unref(reply);
	remove_pending(call);
}

int telephony_init(void)
{
	const char *battery_cap = "battery";
	uint32_t features = AG_FEATURE_EC_ANDOR_NR |
				AG_FEATURE_INBAND_RINGTONE |
				AG_FEATURE_REJECT_A_CALL |
				AG_FEATURE_ENHANCED_CALL_STATUS |
				AG_FEATURE_ENHANCED_CALL_CONTROL |
				AG_FEATURE_EXTENDED_ERROR_RESULT_CODES |
				AG_FEATURE_THREE_WAY_CALLING;
	int i;

	DBG("");

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	add_watch(NULL, NULL, CSD_CALL_INTERFACE, NULL);
	add_watch(NULL, NULL, CSD_CALL_INSTANCE, NULL);
	add_watch(NULL, NULL, CSD_CALL_CONFERENCE, NULL);
	add_watch(NULL, NULL, CSD_CSNET_REGISTRATION, "RegistrationChanged");
	add_watch(NULL, NULL, CSD_CSNET_OPERATOR, "OperatorNameChanged");
	add_watch(NULL, NULL, CSD_CSNET_SIGNAL, "SignalBarsChanged");
	add_watch(NULL, NULL, SSC_DBUS_IFACE, "modem_state_changed_ind");

	if (send_method_call(SSC_DBUS_NAME, SSC_DBUS_PATH, SSC_DBUS_IFACE,
					"get_modem_state", modem_state_reply,
					NULL, DBUS_TYPE_INVALID) < 0)
		error("Unable to send " SSC_DBUS_IFACE ".get_modem_state()");

	/* Reset indicators */
	for (i = 0; maemo_indicators[i].desc != NULL; i++) {
		if (g_str_equal(maemo_indicators[i].desc, "battchg"))
			maemo_indicators[i].val = 5;
		else
			maemo_indicators[i].val = 0;
	}

	telephony_ready_ind(features, maemo_indicators, BTRH_NOT_SUPPORTED,
								chld_str);
	if (send_method_call("org.freedesktop.Hal",
				"/org/freedesktop/Hal/Manager",
				"org.freedesktop.Hal.Manager",
				"FindDeviceByCapability",
				hal_find_device_reply, NULL,
				DBUS_TYPE_STRING, &battery_cap,
				DBUS_TYPE_INVALID) < 0)
		error("Unable to send HAL method call");

	return 0;
}

static void remove_watch(gpointer data)
{
	g_dbus_remove_watch(connection, GPOINTER_TO_UINT(data));
}

void telephony_exit(void)
{
	DBG("");

	g_free(net.operator_name);
	net.operator_name = NULL;

	net.status = NETWORK_REG_STATUS_UNKOWN;
	net.signal_bars = 0;

	g_slist_free(active_calls);
	active_calls = NULL;

	g_slist_free_full(calls, csd_call_free);
	calls = NULL;

	g_slist_free_full(pending, pending_req_finalize);
	pending = NULL;

	g_slist_free_full(watches, remove_watch);
	watches = NULL;

	dbus_connection_unref(connection);
	connection = NULL;

	telephony_deinit();
}
