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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "telephony.h"

/* CSD CALL plugin D-Bus definitions */
#define CSD_CALL_BUS_NAME	"com.nokia.csd.Call"
#define CSD_CALL_INTERFACE	"com.nokia.csd.Call"
#define CSD_CALL_INSTANCE	"com.nokia.csd.Call.Instance"
#define CSD_CALL_CONFERENCE	"com.nokia.csd.Call.Conference"
#define CSD_CALL_PATH		"/com/nokia/csd/call"

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

struct csd_call {
	char *object_path;
	int status;
	gboolean originating;
	gboolean emergency;
	gboolean on_hold;
	gboolean conference;
	char *number;
};

static DBusConnection *connection = NULL;

GSList *calls = NULL;

static char *subscriber_number = NULL;
static char *active_call_number = NULL;
static int active_call_status = 0;
static int active_call_dir = 0;

static gboolean events_enabled = FALSE;

/* Response and hold state
 * -1 = none
 *  0 = incoming call is put on hold in the AG
 *  1 = held incoming call is accepted in the AG
 *  2 = held incoming call is rejected in the AG
 */
static int response_and_hold = -1;

static struct indicator maemo_indicators[] =
{
	{ "battchg",	"0-5",	5 },
	{ "signal",	"0-5",	5 },
	{ "service",	"0,1",	1 },
	{ "call",	"0,1",	0 },
	{ "callsetup",	"0-3",	0 },
	{ "callheld",	"0-2",	0 },
	{ "roam",	"0,1",	0 },
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

void telephony_device_connected(void *telephony_device)
{
	debug("telephony-maemo: device %p connected", telephony_device);
}

void telephony_device_disconnected(void *telephony_device)
{
	debug("telephony-maemo: device %p disconnected", telephony_device);
	events_enabled = FALSE;
}

void telephony_event_reporting_req(void *telephony_device, int ind)
{
	events_enabled = ind == 1 ? TRUE : FALSE;

	telephony_event_reporting_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_response_and_hold_req(void *telephony_device, int rh)
{
	response_and_hold = rh;

	telephony_response_and_hold_ind(response_and_hold);

	telephony_response_and_hold_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_last_dialed_number_req(void *telephony_device)
{
	telephony_last_dialed_number_rsp(telephony_device, CME_ERROR_NONE);

	/* Notify outgoing call set-up successfully initiated */
	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_OUTGOING);
	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_ALERTING);

	active_call_status = CALL_STATUS_ALERTING;
	active_call_dir = CALL_DIR_OUTGOING;
}

void telephony_terminate_call_req(void *telephony_device)
{
	g_free(active_call_number);
	active_call_number = NULL;

	telephony_terminate_call_rsp(telephony_device, CME_ERROR_NONE);

	if (telephony_get_indicator(maemo_indicators, "callsetup") > 0)
		telephony_update_indicator(maemo_indicators, "callsetup",
						EV_CALLSETUP_INACTIVE);
	else
		telephony_update_indicator(maemo_indicators, "call",
						EV_CALL_INACTIVE);
}

void telephony_answer_call_req(void *telephony_device)
{
	telephony_answer_call_rsp(telephony_device, CME_ERROR_NONE);

	telephony_update_indicator(maemo_indicators, "call", EV_CALL_ACTIVE);
	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_INACTIVE);

	active_call_status = CALL_STATUS_ACTIVE;
}

void telephony_dial_number_req(void *telephony_device, const char *number)
{
	g_free(active_call_number);
	active_call_number = g_strdup(number);

	debug("telephony-maemo: dial request to %s", active_call_number);

	telephony_dial_number_rsp(telephony_device, CME_ERROR_NONE);

	/* Notify outgoing call set-up successfully initiated */
	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_OUTGOING);
	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_ALERTING);

	active_call_status = CALL_STATUS_ALERTING;
	active_call_dir = CALL_DIR_OUTGOING;
}

void telephony_transmit_dtmf_req(void *telephony_device, char tone)
{
	debug("telephony-maemo: transmit dtmf: %c", tone);
	telephony_transmit_dtmf_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_subscriber_number_req(void *telephony_device)
{
	debug("telephony-maemo: subscriber number request");
	if (subscriber_number)
		telephony_subscriber_number_ind(subscriber_number, 0,
						SUBSCRIBER_SERVICE_VOICE);
	telephony_subscriber_number_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_list_current_calls_req(void *telephony_device)
{
	debug("telephony-maemo: list current calls request");
	if (active_call_number)
		telephony_list_current_call_ind(1, active_call_dir,
						active_call_status,
						CALL_MODE_VOICE,
						CALL_MULTIPARTY_NO,
						active_call_number,
						0);
	telephony_list_current_calls_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_operator_selection_req(void *telephony_device)
{
	telephony_operator_selection_ind(OPERATOR_MODE_AUTO, "DummyOperator");
	telephony_operator_selection_rsp(telephony_device, CME_ERROR_NONE);
}

static struct csd_call *find_call(const char *path)
{
	GSList *l;

	for (l = calls ; l != NULL; l = l->next) {
		struct csd_call *call = l->data;

		if (g_str_equal(call->object_path, path))
			return call;
	}

	return NULL;
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

	g_free(call->number);
	call->number = g_strdup(number);

	debug("Incoming call to %s from number %s", call_path, number);
}

static void handle_call_status(DBusMessage *msg, const char *call_path)
{
	struct csd_call *call;
	uint8_t status;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_BYTE, &status,
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

	debug("Call %s changed to %s", call_path, call_status_str[status]);

	call->status = (int) status;

	switch (status) {
	case CSD_CALL_STATUS_IDLE:
		break;
	case CSD_CALL_STATUS_CREATE:
		break;
	case CSD_CALL_STATUS_COMING:
		break;
	case CSD_CALL_STATUS_PROCEEDING:
		break;
	case CSD_CALL_STATUS_MO_ALERTING:
		break;
	case CSD_CALL_STATUS_MT_ALERTING:
		break;
	case CSD_CALL_STATUS_WAITING:
		break;
	case CSD_CALL_STATUS_ANSWERED:
		break;
	case CSD_CALL_STATUS_ACTIVE:
		break;
	case CSD_CALL_STATUS_MO_RELEASE:
		break;
	case CSD_CALL_STATUS_MT_RELEASE:
		break;
	case CSD_CALL_STATUS_HOLD_INITIATED:
		break;
	case CSD_CALL_STATUS_HOLD:
		break;
	case CSD_CALL_STATUS_RETRIEVE_INITIATED:
		break;
	case CSD_CALL_STATUS_RECONNECT_PENDING:
		break;
	case CSD_CALL_STATUS_TERMINATED:
		break;
	case CSD_CALL_STATUS_SWAP_INITIATED:
		break;
	default:
		error("Unknown call status %u", status);
		break;
	}
}

static void handle_call_error(DBusMessage *msg, const char *call_path)
{
}

static DBusHandlerResult csd_signal_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *interface = dbus_message_get_interface(msg);
	const char *member = dbus_message_get_member(msg);
	const char *path = dbus_message_get_path(msg);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL ||
			!g_str_has_prefix(interface, CSD_CALL_INTERFACE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	debug("telephony-maemo: received %s %s.%s", path, interface, member);

	if (dbus_message_is_signal(msg, CSD_CALL_INTERFACE, "Coming"))
		handle_incoming_call(msg);
	else if (dbus_message_is_signal(msg, CSD_CALL_INSTANCE, "CallStatus"))
		handle_call_status(msg, path);
	else if (dbus_message_is_signal(msg, CSD_CALL_INSTANCE,
					"CallServiceError"))
		handle_call_error(msg, path);
	else
		debug("csd_signal_filter: didn't handle %s %s.%s",
				path, interface, member);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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

static void csd_call_free(struct csd_call *call)
{
	if (!call)
		return;

	g_free(call->object_path);
	g_free(call->number);

	g_free(call);
}

static void parse_call_list(DBusMessageIter *iter)
{
	while (dbus_message_iter_get_arg_type(iter)
						!= DBUS_TYPE_INVALID) {
		DBusMessageIter call_iter;
		struct csd_call *call;
		const char *object_path, *number;
		dbus_uint32_t status;
		dbus_bool_t originating, terminating, emerg, on_hold, conf;

		dbus_message_iter_recurse(iter, &call_iter);

		if (!iter_get_basic_args(&call_iter,
					DBUS_TYPE_OBJECT_PATH, &object_path,
					DBUS_TYPE_UINT32, &status,
					DBUS_TYPE_BOOLEAN, &originating,
					DBUS_TYPE_BOOLEAN, &terminating,
					DBUS_TYPE_BOOLEAN, &on_hold,
					DBUS_TYPE_BOOLEAN, &emerg,
					DBUS_TYPE_BOOLEAN, &conf,
					DBUS_TYPE_STRING, &number,
					DBUS_TYPE_INVALID)) {
			error("Parsing call D-Bus parameters failed");
			continue;
		}

		call = g_new0(struct csd_call, 1);

		call->object_path = g_strdup(object_path);
		call->status = (int) status;

		calls = g_slist_append(calls, call);

		debug("telephony-maemo: new csd call instance at %s", object_path);

		if (call->status == CSD_CALL_STATUS_IDLE) {
			dbus_message_iter_next(iter);
			continue;
		}

		call->originating = originating;
		call->on_hold = on_hold;
		call->conference = conf;
		call->number = g_strdup(number);

		dbus_message_iter_next(iter);
	}
}

static void call_info_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	DBusMessageIter iter, sub;;
	uint32_t features = AG_FEATURE_REJECT_A_CALL |
				AG_FEATURE_ENHANCED_CALL_STATUS |
				AG_FEATURE_EXTENDED_ERROR_RESULT_CODES;

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

	telephony_ready_ind(features, maemo_indicators, response_and_hold);

done:
	dbus_message_unref(reply);
}

int telephony_init(void)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	char match_string[128];

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (!dbus_connection_add_filter(connection, csd_signal_filter,
						NULL, NULL)) {
		error("Can't add signal filter");
		return -EIO;
	}

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
						CSD_CALL_INTERFACE,
						"GetCallInfoAll");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	if (!dbus_connection_send_with_reply(connection, msg, &call, -1)) {
		error("Sending GetCallInfoAll failed");
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_pending_call_set_notify(call, call_info_reply, NULL, NULL);
	dbus_pending_call_unref(call);

	snprintf(match_string, sizeof(match_string),
			"type=signal,interface=%s", CSD_CALL_INTERFACE);
	dbus_bus_add_match(connection, match_string, NULL);

	snprintf(match_string, sizeof(match_string),
			"type=signal,interface=%s", CSD_CALL_INSTANCE);
	dbus_bus_add_match(connection, match_string, NULL);

	return 0;
}

void telephony_exit(void)
{
	g_slist_foreach(calls, (GFunc) csd_call_free, NULL);
	g_slist_free(calls);
	calls = NULL;

	dbus_connection_unref(connection);
	connection = NULL;
}
