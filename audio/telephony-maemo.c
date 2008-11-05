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
#include <string.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "logging.h"
#include "telephony.h"

/* libcsnet D-Bus definitions */
#define NETWORK_BUS_NAME		"com.nokia.phone.net"
#define NETWORK_INTERFACE		"Phone.Net"
#define NETWORK_PATH			"/com/nokia/phone/net"

/* Mask bits for supported services */
#define NETWORK_MASK_GPRS_SUPPORT	0x01
#define NETWORK_MASK_CS_SERVICES	0x02
#define NETWORK_MASK_EGPRS_SUPPORT	0x04
#define NETWORK_MASK_HSDPA_AVAIL	0x08
#define NETWORK_MASK_HSUPA_AVAIL	0x10

/* network get cell info: cell type */
#define NETWORK_UNKNOWN_CELL		0
#define NETWORK_GSM_CELL		1
#define NETWORK_WCDMA_CELL		2

enum net_registration_status {
	NETWORK_REG_STATUS_HOME = 0x00,
	NETWORK_REG_STATUS_ROAM,
	NETWORK_REG_STATUS_ROAM_BLINK,
	NETWORK_REG_STATUS_NOSERV,
	NETWORK_REG_STATUS_NOSERV_SEARCHING,
	NETWORK_REG_STATUS_NOSERV_NOTSEARCHING,
	NETWORK_REG_STATUS_NOSERV_NOSIM,
	NETWORK_REG_STATUS_POWER_OFF = 0x08,
	NETWORK_REG_STATUS_NSPS,
	NETWORK_REG_STATUS_NSPS_NO_COVERAGE,
	NETWORK_REG_STATUS_NOSERV_SIM_REJECTED_BY_NW
};

enum network_types {
	NETWORK_GSM_HOME_PLMN = 0,
	NETWORK_GSM_PREFERRED_PLMN,
	NETWORK_GSM_FORBIDDEN_PLMN,
	NETWORK_GSM_OTHER_PLMN,
	NETWORK_GSM_NO_PLMN_AVAIL
};

enum network_alpha_tag_name_type {
	NETWORK_HARDCODED_LATIN_OPER_NAME = 0,
	NETWORK_HARDCODED_USC2_OPER_NAME,
	NETWORK_NITZ_SHORT_OPER_NAME,
	NETWORK_NITZ_FULL_OPER_NAME,
};

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

/* Call direction (as returned by GetRemote */
#define CSD_CALL_DIRECTION_OUTGOING		1
#define CSD_CALL_DIRECTION_INCOMING		2

#define CALL_FLAG_NONE				0
#define CALL_FLAG_PRESENTATION_ALLOWED		0x01
#define CALL_FLAG_PRESENTATION_RESTRICTED	0x02

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
	uint8_t status;
	uint16_t lac;
	uint32_t cell_id;
	uint32_t operator_code;
	uint32_t country_code;
	uint8_t network_type;
	uint8_t supported_services;
	uint16_t signals_bar;
	char *operator_name;
} net = {
	.status = NETWORK_REG_STATUS_NOSERV,
	.lac = 0,
	.cell_id = 0,
	.operator_code = 0,
	.country_code = 0,
	.network_type = NETWORK_GSM_NO_PLMN_AVAIL,
	.supported_services = 0,
	.signals_bar = 0,
	.operator_name = NULL,
};

static DBusConnection *connection = NULL;

static GSList *calls = NULL;

static char *subscriber_number = NULL;

static gboolean events_enabled = FALSE;

/* Supported set of call hold operations */
static const char *chld_str = "0,1,1x,2,2x,3,4";

/* Response and hold state
 * -1 = none
 *  0 = incoming call is put on hold in the AG
 *  1 = held incoming call is accepted in the AG
 *  2 = held incoming call is rejected in the AG
 */
static int response_and_hold = -1;

static char *last_dialed_number = NULL;

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

static struct csd_call *find_active_call(void)
{
	GSList *l;

	for (l = calls ; l != NULL; l = l->next) {
		struct csd_call *call = l->data;

		if (call->status != CSD_CALL_STATUS_IDLE)
			return call;
	}

	return NULL;
}

static struct csd_call *find_call_with_status(int status)
{
	GSList *l;

	for (l = calls ; l != NULL; l = l->next) {
		struct csd_call *call = l->data;

		if (call->status == status)
			return call;
	}

	return NULL;
}

static gboolean update_network_indicators(gpointer user_data)
{
	if (net.status < NETWORK_REG_STATUS_NOSERV) {
		int signal;
		telephony_update_indicator(maemo_indicators, "service",
						EV_SERVICE_PRESENT);
	        signal = telephony_get_indicator(maemo_indicators, "signal");
		telephony_update_indicator(maemo_indicators, "signal", signal);
	} else
		telephony_update_indicator(maemo_indicators, "service",
						EV_SERVICE_NONE);

	switch (net.status) {
	case NETWORK_REG_STATUS_HOME:
		telephony_update_indicator(maemo_indicators, "roam",
						EV_ROAM_INACTIVE);
		break;
	case NETWORK_REG_STATUS_ROAM:
	case NETWORK_REG_STATUS_ROAM_BLINK:
		telephony_update_indicator(maemo_indicators, "roam",
						EV_ROAM_ACTIVE);
		break;
	}

	return FALSE;
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

void telephony_device_connected(void *telephony_device)
{
	debug("telephony-maemo: device %p connected", telephony_device);

	g_timeout_add_seconds(1, update_network_indicators, NULL);
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
	debug("telephony-maemo: last dialed number request");

	if (last_dialed_number)
		telephony_dial_number_req(telephony_device,
						last_dialed_number);
	else
		telephony_last_dialed_number_rsp(telephony_device,
						CME_ERROR_NOT_ALLOWED);
}

void telephony_terminate_call_req(void *telephony_device)
{
	struct csd_call *call;

	call = find_active_call();
	if (!call) {
		error("No active call");
		telephony_terminate_call_rsp(telephony_device,
						CME_ERROR_NOT_ALLOWED);
		return;
	}

	if (release_call(call) < 0)
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

	if (!call) {
		telephony_answer_call_rsp(telephony_device,
						CME_ERROR_NOT_ALLOWED);
		return;
	}

	if (answer_call(call) < 0)
		telephony_answer_call_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
	else
		telephony_answer_call_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_dial_number_req(void *telephony_device, const char *number)
{
	uint32_t flags;
	DBusMessage *msg;

	debug("telephony-maemo: dial request to %s", number);

	if (strncmp(number, "*31#", 4) == 0) {
		number += 4;
		flags = CALL_FLAG_PRESENTATION_ALLOWED;
	} else if (strncmp(number, "#31#", 4) == 0) {
		number += 4;
		flags = CALL_FLAG_PRESENTATION_RESTRICTED;
	} else
		flags = CALL_FLAG_NONE;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
					CSD_CALL_INTERFACE, "CreateWith");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		telephony_dial_number_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &number,
					DBUS_TYPE_UINT32, &flags,
					DBUS_TYPE_INVALID);

	g_dbus_send_message(connection, msg);

	telephony_dial_number_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_transmit_dtmf_req(void *telephony_device, char tone)
{
	DBusMessage *msg;
	char buf[2] = { tone, '\0' }, *buf_ptr = buf;

	debug("telephony-maemo: transmit dtmf: %s", buf);

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
					   CSD_CALL_INTERFACE, "SendDTMF");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		telephony_transmit_dtmf_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &buf_ptr,
					DBUS_TYPE_INVALID);

	g_dbus_send_message(connection, msg);

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

static int csd_status_to_hfp(int csd_status)
{
	switch (csd_status) {
	case CSD_CALL_STATUS_IDLE:
	case CSD_CALL_STATUS_MO_RELEASE:
	case CSD_CALL_STATUS_MT_RELEASE:
	case CSD_CALL_STATUS_TERMINATED:
		return -1;
	case CSD_CALL_STATUS_CREATE:
		/* Is PROCEEDING == DIALING correct? */
	case CSD_CALL_STATUS_PROCEEDING:
		return CALL_STATUS_DIALING;
	case CSD_CALL_STATUS_COMING:
		return CALL_STATUS_INCOMING;
	case CSD_CALL_STATUS_MO_ALERTING:
		return CALL_STATUS_INCOMING;
	case CSD_CALL_STATUS_MT_ALERTING:
		return CALL_STATUS_ALERTING;
	case CSD_CALL_STATUS_ANSWERED:
	case CSD_CALL_STATUS_ACTIVE:
	case CSD_CALL_STATUS_RETRIEVE_INITIATED:
	case CSD_CALL_STATUS_RECONNECT_PENDING:
	case CSD_CALL_STATUS_SWAP_INITIATED:
		return CALL_STATUS_ACTIVE;
	case CSD_CALL_STATUS_HOLD_INITIATED:
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

	debug("telephony-maemo: list current calls request");

	for (l = calls, i = 1; l != NULL; l = l->next, i++) {
		struct csd_call *call = l->data;
		int status, direction, multiparty;

		status = csd_status_to_hfp(call->status);
		if (status < 0)
			continue;

		direction = call->originating ?
				CALL_DIR_OUTGOING : CALL_DIR_INCOMING;

		multiparty = call->conference ?
				CALL_MULTIPARTY_YES : CALL_MULTIPARTY_NO;

		telephony_list_current_call_ind(i, direction, status,
						CALL_MODE_VOICE, multiparty,
						call->number, 0);
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

	debug("telephony-maemo: got call hold request %s", cmd);

	if (strlen(cmd) > 1)
		idx = &cmd[1];
	else
		idx = NULL;

	if (idx)
		call = g_slist_nth_data(calls, strtol(idx, NULL, 0) - 1);

	switch (cmd[0]) {
	case '0':
		foreach_call_with_status(CSD_CALL_STATUS_HOLD, release_call);
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
			answer_call(call);
		break;
	case '2':
		if (idx) {
			if (call)
				err = split_call(call);
			break;
		}
		foreach_call_with_status(CSD_CALL_STATUS_ACTIVE, hold_call);
		foreach_call_with_status(CSD_CALL_STATUS_HOLD, unhold_call);
		break;
	case '3':
		call = find_call_with_status(CSD_CALL_STATUS_HOLD);
		if (call)
			err = unhold_call(call);
		break;
	case '4':
		err = call_transfer();
		break;
	default:
		debug("Unknown call hold request");
		break;
	}

	if (err)
		telephony_call_hold_rsp(telephony_device,
					CME_ERROR_NONE);
	else
		telephony_call_hold_rsp(telephony_device, CME_ERROR_NONE);
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

	debug("Incoming call to %s from number %s", call_path, number);

	g_free(call->number);
	call->number = g_strdup(number);

	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_INCOMING);

	telephony_incoming_call_ind(number, 0);
}

static void get_remote_reply(DBusPendingCall *pending_call, void *user_data)
{
	struct csd_call *call = user_data;
	DBusMessage *reply;
	DBusError err;
	const char *number;
	dbus_bool_t originating, terminating;

	reply = dbus_pending_call_steal_reply(pending_call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("%s GetRemote failed: %s, %s",
				call->object_path, err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(reply, NULL,
					DBUS_TYPE_STRING, &number,
					DBUS_TYPE_BOOLEAN, &originating,
					DBUS_TYPE_BOOLEAN, &terminating,
					DBUS_TYPE_INVALID)) {
		error("Unexpected paramters in %s GetRemote reply:",
				call->object_path, err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	if (strlen(number) == 0)
		goto done;

	g_free(call->number);
	call->number = g_strdup(number);

	if (originating) {
		g_free(last_dialed_number);
		last_dialed_number = g_strdup(number);
	}

done:
	dbus_message_unref(reply);
}

static void resolve_number(struct csd_call *call)
{
	DBusMessage *msg;
	DBusPendingCall *pcall;

	msg = dbus_message_new_method_call(CSD_CALL_BUS_NAME,
					call->object_path,
					CSD_CALL_INSTANCE, "GetRemote");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return;
	}

	if (!dbus_connection_send_with_reply(connection, msg, &pcall, -1)) {
		error("Sending GetRemote failed");
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(pcall, get_remote_reply, call, NULL);
	dbus_pending_call_unref(pcall);
	dbus_message_unref(msg);
}

static void handle_call_status(DBusMessage *msg, const char *call_path)
{
	struct csd_call *call, *active_call;
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

	debug("Call %s changed from %s to %s", call_path,
		call_status_str[call->status], call_status_str[status]);

	active_call = find_call_with_status(CSD_CALL_STATUS_ACTIVE);

	switch (status) {
	case CSD_CALL_STATUS_IDLE:
		if (call->setup) {
			telephony_update_indicator(maemo_indicators,
							"callsetup",
							EV_CALLSETUP_INACTIVE);
			if (!call->originating)
				telephony_calling_stopped_ind();
		} else
			telephony_update_indicator(maemo_indicators, "call",
							EV_CALL_INACTIVE);

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
		telephony_update_indicator(maemo_indicators, "callsetup",
						EV_CALLSETUP_OUTGOING);
		break;
	case CSD_CALL_STATUS_COMING:
		/* Actuall incoming call handling is done in
		 * handle_incoming_call() which is called when we get the
		 * Call.Coming() signal */
		call->originating = FALSE;
		call->setup = TRUE;
		break;
	case CSD_CALL_STATUS_PROCEEDING:
		break;
	case CSD_CALL_STATUS_MO_ALERTING:
		telephony_update_indicator(maemo_indicators, "callsetup",
						EV_CALLSETUP_ALERTING);
		resolve_number(call);
		break;
	case CSD_CALL_STATUS_MT_ALERTING:
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
			telephony_update_indicator(maemo_indicators, "call",
							EV_CALL_ACTIVE);
			telephony_update_indicator(maemo_indicators,
							"callsetup",
							EV_CALLSETUP_INACTIVE);
			call->setup = FALSE;
		}
		break;
	case CSD_CALL_STATUS_MO_RELEASE:
		break;
	case CSD_CALL_STATUS_MT_RELEASE:
		break;
	case CSD_CALL_STATUS_HOLD_INITIATED:
		break;
	case CSD_CALL_STATUS_HOLD:
		call->on_hold = TRUE;
		if (active_call && active_call != call)
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
		break;
	case CSD_CALL_STATUS_SWAP_INITIATED:
		break;
	default:
		error("Unknown call status %u", status);
		break;
	}

	call->status = (int) status;
}

static void get_operator_name_reply(DBusPendingCall *pending_call,
					void *user_data)
{
	DBusMessage *reply;
	DBusError err;
	const char *name;
	dbus_int32_t net_err;

	reply = dbus_pending_call_steal_reply(pending_call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("%s get_operator_name failed: %s, %s",
			err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(reply, NULL,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INT32, &net_err,
					DBUS_TYPE_INVALID)) {
		error("Unexpected paramters in get_operator_name reply:",
			err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	if (net_err != 0) {
		error("get_remote_name failed with code %d", net_err);
		goto done;
	}

	if (strlen(name) == 0)
		goto done;

	g_free(net.operator_name);
	net.operator_name = g_strdup(name);

	debug("telephony-maemo: operator name updated: %s", name);

done:
	dbus_message_unref(reply);
}

static void resolve_operator_name(uint32_t operator, uint32_t country)
{
	DBusMessage *msg;
	DBusPendingCall *pcall;
	uint8_t name_type = NETWORK_HARDCODED_LATIN_OPER_NAME;

	msg = dbus_message_new_method_call(NETWORK_BUS_NAME, NETWORK_PATH,
						NETWORK_INTERFACE,
						"get_operator_name");
	if (!msg) {
		error("Unable to allocate a new D-Bus method call");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_BYTE, &name_type,
					DBUS_TYPE_UINT32, &operator,
					DBUS_TYPE_UINT32, &country,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(connection, msg, &pcall, -1)) {
		error("Sending get_operator_name failed");
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(pcall, get_operator_name_reply, NULL,
					NULL);
	dbus_pending_call_unref(pcall);
	dbus_message_unref(msg);
}

static void update_registration_status(uint8_t status, uint16_t lac,
					uint32_t cell_id,
					uint32_t operator_code,
					uint32_t country_code,
					uint8_t network_type,
					uint8_t supported_services)
{
	if (net.status != status) {
		switch (status) {
		case NETWORK_REG_STATUS_HOME:
			telephony_update_indicator(maemo_indicators, "roam",
							EV_ROAM_INACTIVE);
			if (net.status >= NETWORK_REG_STATUS_NOSERV)
				telephony_update_indicator(maemo_indicators,
							"service",
							EV_SERVICE_PRESENT);
			break;
		case NETWORK_REG_STATUS_ROAM:
		case NETWORK_REG_STATUS_ROAM_BLINK:
			telephony_update_indicator(maemo_indicators, "roam",
							EV_ROAM_ACTIVE);
			if (net.status >= NETWORK_REG_STATUS_NOSERV)
				telephony_update_indicator(maemo_indicators,
							"service",
							EV_SERVICE_PRESENT);
			break;
		case NETWORK_REG_STATUS_NOSERV:
		case NETWORK_REG_STATUS_NOSERV_SEARCHING:
		case NETWORK_REG_STATUS_NOSERV_NOTSEARCHING:
		case NETWORK_REG_STATUS_NOSERV_NOSIM:
		case NETWORK_REG_STATUS_POWER_OFF:
		case NETWORK_REG_STATUS_NSPS:
		case NETWORK_REG_STATUS_NSPS_NO_COVERAGE:
		case NETWORK_REG_STATUS_NOSERV_SIM_REJECTED_BY_NW:
			if (net.status < NETWORK_REG_STATUS_NOSERV)
				telephony_update_indicator(maemo_indicators,
							"service",
							EV_SERVICE_NONE);
			break;
		}

		net.status = status;
	}

	net.lac = lac;
	net.cell_id = cell_id;

	if (net.operator_code != operator_code ||
			net.country_code != country_code) {
		g_free(net.operator_name);
		net.operator_name = NULL;
		resolve_operator_name(operator_code, country_code);
		net.operator_code = operator_code;
		net.country_code = country_code;
	}

	net.network_type = network_type;
	net.supported_services = supported_services;
}

static void handle_registration_status_change(DBusMessage *msg)
{
	uint8_t status;
	dbus_uint16_t lac, network_type, supported_services;
	dbus_uint32_t cell_id, operator_code, country_code;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_BYTE, &status,
					DBUS_TYPE_UINT16, &lac,
					DBUS_TYPE_UINT32, &cell_id,
					DBUS_TYPE_UINT32, &operator_code,
					DBUS_TYPE_UINT32, &country_code,
					DBUS_TYPE_BYTE, &network_type,
					DBUS_TYPE_BYTE, &supported_services,
					DBUS_TYPE_INVALID)) {
		error("Unexpected parameters in registration_status_change");
		return;
	}

	update_registration_status(status, lac, cell_id, operator_code,
					country_code, network_type,
					supported_services);
}

static void update_signal_strength(uint8_t signals_bar)
{
	int signal;

	if (signals_bar > 100) {
		debug("signals_bar greater than expected: %u", signals_bar);
		signals_bar = 100;
	}

	if (net.signals_bar == signals_bar)
		return;

	/* A simple conversion from 0-100 to 0-5 (used by HFP) */
	signal = (signals_bar + 20) / 21;

	telephony_update_indicator(maemo_indicators, "signal", signal);

	net.signals_bar = signals_bar;

	debug("Signal strength updated: %u/100, %d/5", signals_bar, signal);
}

static void handle_signal_strength_change(DBusMessage *msg)
{
	uint8_t signals_bar, rssi_in_dbm;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_BYTE, &signals_bar,
					DBUS_TYPE_BYTE, &rssi_in_dbm,
					DBUS_TYPE_INVALID)) {
		error("Unexpected parameters in signal_strength_change");
		return;
	}

	update_signal_strength(signals_bar);
}

static DBusHandlerResult cs_signal_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *interface = dbus_message_get_interface(msg);
	const char *member = dbus_message_get_member(msg);
	const char *path = dbus_message_get_path(msg);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL ||
			!(g_str_has_prefix(interface, CSD_CALL_INTERFACE) ||
				g_str_equal(interface, NETWORK_INTERFACE)))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	debug("telephony-maemo: received %s %s.%s", path, interface, member);

	if (dbus_message_is_signal(msg, CSD_CALL_INTERFACE, "Coming"))
		handle_incoming_call(msg);
	else if (dbus_message_is_signal(msg, CSD_CALL_INSTANCE, "CallStatus"))
		handle_call_status(msg, path);
	else if (dbus_message_is_signal(msg, NETWORK_INTERFACE,
					"registration_status_change"))
		handle_registration_status_change(msg);
	else if (dbus_message_is_signal(msg, NETWORK_INTERFACE,
					"signal_strength_change"))
		handle_signal_strength_change(msg);

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
					DBUS_TYPE_BOOLEAN, &emerg,
					DBUS_TYPE_BOOLEAN, &on_hold,
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

static void signal_strength_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	uint8_t signals_bar, rssi_in_dbm;
	dbus_int32_t net_err;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Unable to get signal strength: %s, %s",
			err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(reply, NULL,
					DBUS_TYPE_BYTE, &signals_bar,
					DBUS_TYPE_BYTE, &rssi_in_dbm,
					DBUS_TYPE_INT32, &net_err,
					DBUS_TYPE_INVALID)) {
		error("Unable to parse signal_strength reply:",
				err.name, err.message);
		dbus_error_free(&err);
		return;
	}

	if (net_err != 0) {
		error("get_signal_strength failed with code %d", net_err);
		return;
	}

	update_signal_strength(signals_bar);

done:
	dbus_message_unref(reply);
}

static int get_signal_strength(void)
{
	DBusMessage *msg;
	DBusPendingCall *pcall;

	msg = dbus_message_new_method_call(NETWORK_BUS_NAME, NETWORK_PATH,
						NETWORK_INTERFACE,
						"get_signal_strength");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	if (!dbus_connection_send_with_reply(connection, msg, &pcall, -1)) {
		error("Sending get_signal_strength failed");
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_pending_call_set_notify(pcall, signal_strength_reply, NULL,
					NULL);
	dbus_pending_call_unref(pcall);
	dbus_message_unref(msg);

	return 0;
}

static void registration_status_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	uint8_t status;
	dbus_uint16_t lac, network_type, supported_services;
	dbus_uint32_t cell_id, operator_code, country_code;
	dbus_int32_t net_err;
	uint32_t features = AG_FEATURE_REJECT_A_CALL |
				AG_FEATURE_ENHANCED_CALL_STATUS |
				AG_FEATURE_EXTENDED_ERROR_RESULT_CODES |
				AG_FEATURE_INBAND_RINGTONE;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Unable to get registration status: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(reply, NULL,
					DBUS_TYPE_BYTE, &status,
					DBUS_TYPE_UINT16, &lac,
					DBUS_TYPE_UINT32, &cell_id,
					DBUS_TYPE_UINT32, &operator_code,
					DBUS_TYPE_UINT32, &country_code,
					DBUS_TYPE_BYTE, &network_type,
					DBUS_TYPE_BYTE, &supported_services,
					DBUS_TYPE_INT32, &net_err,
					DBUS_TYPE_INVALID)) {
		error("Unable to parse registration_status_change reply:",
				err.name, err.message);
		dbus_error_free(&err);
		return;
	}

	if (net_err != 0) {
		error("get_registration_status failed with code %d", net_err);
		return;
	}

	update_registration_status(status, lac, cell_id, operator_code,
					country_code, network_type,
					supported_services);

	telephony_ready_ind(features, maemo_indicators, response_and_hold,
				chld_str);

	get_signal_strength();

done:
	dbus_message_unref(reply);
}

static int get_registration_status(void)
{
	DBusMessage *msg;
	DBusPendingCall *pcall;

	msg = dbus_message_new_method_call(NETWORK_BUS_NAME, NETWORK_PATH,
						NETWORK_INTERFACE,
						"get_registration_status");
	if (!msg) {
		error("Unable to allocate new D-Bus message");
		return -ENOMEM;
	}

	if (!dbus_connection_send_with_reply(connection, msg, &pcall, -1)) {
		error("Sending get_registration_status failed");
		dbus_message_unref(msg);
		return -EIO;
	}

	dbus_pending_call_set_notify(pcall, registration_status_reply, NULL,
					NULL);
	dbus_pending_call_unref(pcall);
	dbus_message_unref(msg);

	return 0;
}

static void call_info_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	DBusMessageIter iter, sub;;

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

	get_registration_status();

done:
	dbus_message_unref(reply);
}

int telephony_init(void)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	char match_string[128];

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (!dbus_connection_add_filter(connection, cs_signal_filter,
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
	dbus_message_unref(msg);

	snprintf(match_string, sizeof(match_string),
			"type=signal,interface=%s", CSD_CALL_INTERFACE);
	dbus_bus_add_match(connection, match_string, NULL);

	snprintf(match_string, sizeof(match_string),
			"type=signal,interface=%s", CSD_CALL_INSTANCE);
	dbus_bus_add_match(connection, match_string, NULL);

	snprintf(match_string, sizeof(match_string),
			"type=signal,interface=%s", CSD_CALL_INSTANCE);
	dbus_bus_add_match(connection, match_string, NULL);

	snprintf(match_string, sizeof(match_string),
			"type=signal,interface=%s", NETWORK_INTERFACE);
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
