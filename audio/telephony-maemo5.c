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

#include "log.h"
#include "telephony.h"
#include "error.h"

/* SSC D-Bus definitions */
#define SSC_DBUS_NAME  "com.nokia.phone.SSC"
#define SSC_DBUS_IFACE "com.nokia.phone.SSC"
#define SSC_DBUS_PATH  "/com/nokia/phone/SSC"

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

#define TELEPHONY_MAEMO_PATH		"/com/nokia/MaemoTelephony"
#define TELEPHONY_MAEMO_INTERFACE	"com.nokia.MaemoTelephony"

#define CALLERID_BASE		"/var/lib/bluetooth/maemo-callerid-"
#define ALLOWED_FLAG_FILE	"/var/lib/bluetooth/maemo-callerid-allowed"
#define RESTRICTED_FLAG_FILE	"/var/lib/bluetooth/maemo-callerid-restricted"
#define NONE_FLAG_FILE		"/var/lib/bluetooth/maemo-callerid-none"

static uint32_t callerid = 0;

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
#define SIM_PHONEBOOK_BUS_NAME			"com.nokia.phone.SIM"
#define SIM_PHONEBOOK_INTERFACE			"Phone.Sim.Phonebook"
#define SIM_PHONEBOOK_PATH			"/com/nokia/phone/SIM/phonebook"

#define PHONEBOOK_INDEX_FIRST_ENTRY		0xFFFF
#define PHONEBOOK_INDEX_NEXT_FREE_LOCATION	0xFFFE

enum sim_phonebook_type {
	SIM_PHONEBOOK_TYPE_ADN = 0x0,
	SIM_PHONEBOOK_TYPE_SDN,
	SIM_PHONEBOOK_TYPE_FDN,
	SIM_PHONEBOOK_TYPE_VMBX,
	SIM_PHONEBOOK_TYPE_MBDN,
	SIM_PHONEBOOK_TYPE_EN,
	SIM_PHONEBOOK_TYPE_MSISDN
};

enum sim_phonebook_location_type {
	SIM_PHONEBOOK_LOCATION_EXACT = 0x0,
	SIM_PHONEBOOK_LOCATION_NEXT
};

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

/* Reference count for determining the call indicator status */
static GSList *active_calls = NULL;

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

static char *last_dialed_number = NULL;

/* Timer for tracking call creation requests */
static guint create_request_timer = 0;

static struct indicator maemo_indicators[] =
{
	{ "battchg",	"0-5",	5,	TRUE },
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

	DBG("telephony-maemo: releasing conference call");

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

	DBG("telephony-maemo: device %p connected", telephony_device);

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

void telephony_device_disconnected(void *telephony_device)
{
	DBG("telephony-maemo: device %p disconnected", telephony_device);
	events_enabled = FALSE;
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

void telephony_last_dialed_number_req(void *telephony_device)
{
	DBG("telephony-maemo: last dialed number request");

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

	if (call->conference)
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

	if (answer_call(call) < 0)
		telephony_answer_call_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
	else
		telephony_answer_call_rsp(telephony_device, CME_ERROR_NONE);
}

static int send_method_call(const char *dest, const char *path,
				const char *interface, const char *method,
				DBusPendingCallNotifyFunction cb,
				void *user_data, int type, ...)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	va_list args;

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
	dbus_pending_call_unref(call);
	dbus_message_unref(msg);

	return 0;
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
	uint32_t flags = callerid;
	int ret;

	DBG("telephony-maemo: dial request to %s", number);

	if (strncmp(number, "*31#", 4) == 0) {
		number += 4;
		flags = CALL_FLAG_PRESENTATION_ALLOWED;
	} else if (strncmp(number, "#31#", 4) == 0) {
		number += 4;
		flags = CALL_FLAG_PRESENTATION_RESTRICTED;
	} else if (number[0] == '>') {
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
				CSD_CALL_INTERFACE, "CreateWith",
				NULL, NULL,
				DBUS_TYPE_STRING, &number,
				DBUS_TYPE_UINT32, &flags,
				DBUS_TYPE_INVALID);
	if (ret < 0) {
		telephony_dial_number_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
		return;
	}

	telephony_dial_number_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_transmit_dtmf_req(void *telephony_device, char tone)
{
	int ret;
	char buf[2] = { tone, '\0' }, *buf_ptr = buf;

	DBG("telephony-maemo: transmit dtmf: %s", buf);

	ret = send_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
				CSD_CALL_INTERFACE, "SendDTMF",
				NULL, NULL,
				DBUS_TYPE_STRING, &buf_ptr,
				DBUS_TYPE_INVALID);
	if (ret < 0) {
		telephony_transmit_dtmf_rsp(telephony_device,
						CME_ERROR_AG_FAILURE);
		return;
	}

	telephony_transmit_dtmf_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_subscriber_number_req(void *telephony_device)
{
	DBG("telephony-maemo: subscriber number request");
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
		else
			return CALL_STATUS_INCOMING;
	case CSD_CALL_STATUS_COMING:
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

	DBG("telephony-maemo: list current calls request");

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

	DBG("telephony-maemo: got call hold request %s", cmd);

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
		foreach_call_with_status(CSD_CALL_STATUS_HOLD, release_call);
		foreach_call_with_status(CSD_CALL_STATUS_WAITING,
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
	DBG("telephony-maemo: got %s NR and EC request",
			enable ? "enable" : "disable");
	telephony_nr_and_ec_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_key_press_req(void *telephony_device, const char *keys)
{
	struct csd_call *active, *waiting;
	int err;

	DBG("telephony-maemo: got key press request for %s", keys);

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
	DBG("telephony-maemo: got %s voice dial request",
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

	telephony_update_indicator(maemo_indicators, "callsetup",
					EV_CALLSETUP_INCOMING);

	if (find_call_with_status(CSD_CALL_STATUS_ACTIVE))
		telephony_call_waiting_ind(call->number,
						number_type(call->number));
	else
		telephony_incoming_call_ind(call->number,
						number_type(call->number));
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

	g_free(last_dialed_number);
	last_dialed_number = g_strdup(number);

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

static void handle_call_status(DBusMessage *msg, const char *call_path)
{
	struct csd_call *call;
	dbus_uint32_t status, cause_type, cause;
	int callheld = telephony_get_indicator(maemo_indicators, "callheld");

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

	DBG("Call %s changed from %s to %s", call_path,
		call_status_str[call->status], call_status_str[status]);

	if (call->status == (int) status) {
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
				!find_call_with_status(CSD_CALL_STATUS_HOLD))
			telephony_update_indicator(maemo_indicators,
							"callheld",
							EV_CALLHELD_NONE);
		else if (callheld == EV_CALLHELD_MULTIPLE &&
				find_call_with_status(CSD_CALL_STATUS_HOLD))
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
		error("get_operator_name failed: %s, %s",
			err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(reply, &err,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INT32, &net_err,
					DBUS_TYPE_INVALID)) {
		error("Unexpected get_operator_name reply parameters: %s, %s",
			err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	if (net_err != 0) {
		error("get_operator_name failed with code %d", net_err);
		goto done;
	}

	if (strlen(name) == 0)
		goto done;

	g_free(net.operator_name);
	net.operator_name = g_strdup(name);

	DBG("telephony-maemo: operator name updated: %s", name);

done:
	dbus_message_unref(reply);
}

static void resolve_operator_name(uint32_t operator, uint32_t country)
{
	uint8_t name_type = NETWORK_HARDCODED_LATIN_OPER_NAME;

	send_method_call(NETWORK_BUS_NAME, NETWORK_PATH,
				NETWORK_INTERFACE, "get_operator_name",
				get_operator_name_reply, NULL,
				DBUS_TYPE_BYTE, &name_type,
				DBUS_TYPE_UINT32, &operator,
				DBUS_TYPE_UINT32, &country,
				DBUS_TYPE_INVALID);
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
		DBG("signals_bar greater than expected: %u", signals_bar);
		signals_bar = 100;
	}

	if (net.signals_bar == signals_bar)
		return;

	/* A simple conversion from 0-100 to 0-5 (used by HFP) */
	signal = (signals_bar + 20) / 21;

	telephony_update_indicator(maemo_indicators, "signal", signal);

	net.signals_bar = signals_bar;

	DBG("Signal strength updated: %u/100, %d/5", signals_bar, signal);
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

	dbus_error_init(&err);
	if (dbus_message_get_args(reply, &err,
				DBUS_TYPE_INT32, &level,
				DBUS_TYPE_INVALID) == FALSE) {
		error("Unable to parse GetPropertyInteger reply: %s, %s",
							err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	*value = (int) level;

	if (value == &battchg_last)
		DBG("telephony-maemo: battery.charge_level.last_full is %d",
				*value);
	else if (value == &battchg_design)
		DBG("telephony-maemo: battery.charge_level.design is %d",
				*value);
	else
		DBG("telephony-maemo: battery.charge_level.current is %d",
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
			call->status = (int) status;
			calls = g_slist_append(calls, call);
			DBG("telephony-maemo: new csd call instance at %s",
								object_path);
		}

		if (call->status == CSD_CALL_STATUS_IDLE)
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

	} while (dbus_message_iter_next(iter));
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
	if (!dbus_message_get_args(reply, &err,
					DBUS_TYPE_BYTE, &signals_bar,
					DBUS_TYPE_BYTE, &rssi_in_dbm,
					DBUS_TYPE_INT32, &net_err,
					DBUS_TYPE_INVALID)) {
		error("Unable to parse signal_strength reply: %s, %s",
							err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	if (net_err != 0) {
		error("get_signal_strength failed with code %d", net_err);
		goto done;
	}

	update_signal_strength(signals_bar);

done:
	dbus_message_unref(reply);
}

static int get_signal_strength(void)
{
	return send_method_call(NETWORK_BUS_NAME, NETWORK_PATH,
				NETWORK_INTERFACE, "get_signal_strength",
				signal_strength_reply, NULL,
				DBUS_TYPE_INVALID);
}

static void registration_status_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	uint8_t status;
	dbus_uint16_t lac, network_type, supported_services;
	dbus_uint32_t cell_id, operator_code, country_code;
	dbus_int32_t net_err;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("Unable to get registration status: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(reply, &err,
					DBUS_TYPE_BYTE, &status,
					DBUS_TYPE_UINT16, &lac,
					DBUS_TYPE_UINT32, &cell_id,
					DBUS_TYPE_UINT32, &operator_code,
					DBUS_TYPE_UINT32, &country_code,
					DBUS_TYPE_BYTE, &network_type,
					DBUS_TYPE_BYTE, &supported_services,
					DBUS_TYPE_INT32, &net_err,
					DBUS_TYPE_INVALID)) {
		error("Unable to parse registration_status_change reply:"
					" %s, %s", err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	if (net_err != 0) {
		error("get_registration_status failed with code %d", net_err);
		goto done;
	}

	update_registration_status(status, lac, cell_id, operator_code,
					country_code, network_type,
					supported_services);

	get_signal_strength();

done:
	dbus_message_unref(reply);
}

static int get_registration_status(void)
{
	return send_method_call(NETWORK_BUS_NAME, NETWORK_PATH,
				NETWORK_INTERFACE, "get_registration_status",
				registration_status_reply, NULL,
				DBUS_TYPE_INVALID);
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

	get_registration_status();

done:
	dbus_message_unref(reply);
}

static void hal_find_device_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	DBusMessageIter iter, sub;
	const char *path;
	char match_string[256];
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

	DBG("telephony-maemo: found battery device at %s", path);

	snprintf(match_string, sizeof(match_string),
			"type='signal',"
			"path='%s',"
			"interface='org.freedesktop.Hal.Device',"
			"member='PropertyModified'", path);
	dbus_bus_add_match(connection, match_string, NULL);

	hal_get_integer(path, "battery.charge_level.last_full", &battchg_last);
	hal_get_integer(path, "battery.charge_level.current", &battchg_cur);
	hal_get_integer(path, "battery.charge_level.design", &battchg_design);

done:
	dbus_message_unref(reply);
}

static void phonebook_read_reply(DBusPendingCall *call, void *user_data)
{
	DBusError derr;
	DBusMessage *reply;
	const char *name, *number;
	char **number_type = user_data;
	dbus_int32_t current_location, err;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("SIM.Phonebook replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	dbus_error_init(&derr);
	if (dbus_message_get_args(reply, &derr,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_STRING, &number,
				DBUS_TYPE_INT32, &current_location,
				DBUS_TYPE_INT32, &err,
				DBUS_TYPE_INVALID) == FALSE) {
		error("Unable to parse SIM.Phonebook.read arguments: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		goto done;
	}

	if (err != 0) {
		error("SIM.Phonebook.read failed with error %d", err);
		if (number_type == &vmbx)
			vmbx = g_strdup(getenv("VMBX_NUMBER"));
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
}

static void csd_init(void)
{
	dbus_uint32_t location;
	uint8_t pb_type, location_type;
	int ret;

	ret = send_method_call(CSD_CALL_BUS_NAME, CSD_CALL_PATH,
				CSD_CALL_INTERFACE, "GetCallInfoAll",
				call_info_reply, NULL, DBUS_TYPE_INVALID);
	if (ret < 0) {
		error("Unable to sent GetCallInfoAll method call");
		return;
	}

	get_calls_active = TRUE;

	pb_type = SIM_PHONEBOOK_TYPE_MSISDN;
	location = PHONEBOOK_INDEX_FIRST_ENTRY;
	location_type = SIM_PHONEBOOK_LOCATION_NEXT;

	ret = send_method_call(SIM_PHONEBOOK_BUS_NAME, SIM_PHONEBOOK_PATH,
				SIM_PHONEBOOK_INTERFACE, "read",
				phonebook_read_reply, &msisdn,
				DBUS_TYPE_BYTE, &pb_type,
				DBUS_TYPE_INT32, &location,
				DBUS_TYPE_BYTE, &location_type,
				DBUS_TYPE_INVALID);
	if (ret < 0) {
		error("Unable to send " SIM_PHONEBOOK_INTERFACE ".read()");
		return;
	}

	pb_type = SIM_PHONEBOOK_TYPE_MBDN;
	location = PHONEBOOK_INDEX_FIRST_ENTRY;
	location_type = SIM_PHONEBOOK_LOCATION_NEXT;

	ret = send_method_call(SIM_PHONEBOOK_BUS_NAME, SIM_PHONEBOOK_PATH,
				SIM_PHONEBOOK_INTERFACE, "read",
				phonebook_read_reply, &vmbx,
				DBUS_TYPE_BYTE, &pb_type,
				DBUS_TYPE_INT32, &location,
				DBUS_TYPE_BYTE, &location_type,
				DBUS_TYPE_INVALID);
	if (ret < 0) {
		error("Unable to send " SIM_PHONEBOOK_INTERFACE ".read()");
		return;
	}
}

static uint32_t get_callflag(const char *callerid_setting)
{
	if (callerid_setting != NULL) {
		if (g_str_equal(callerid_setting, "allowed"))
			return CALL_FLAG_PRESENTATION_ALLOWED;
		else if (g_str_equal(callerid_setting, "restricted"))
			return CALL_FLAG_PRESENTATION_RESTRICTED;
		else
			return CALL_FLAG_NONE;
	} else
		return CALL_FLAG_NONE;
}

static void generate_flag_file(const char *filename)
{
	int fd;

	if (g_file_test(ALLOWED_FLAG_FILE, G_FILE_TEST_EXISTS) ||
			g_file_test(RESTRICTED_FLAG_FILE, G_FILE_TEST_EXISTS) ||
			g_file_test(NONE_FLAG_FILE, G_FILE_TEST_EXISTS))
		return;

	fd = open(filename, O_WRONLY | O_CREAT, 0);
	if (fd >= 0)
		close(fd);
}

static void save_callerid_to_file(const char *callerid_setting)
{
	char callerid_file[FILENAME_MAX];

	snprintf(callerid_file, sizeof(callerid_file), "%s%s",
					CALLERID_BASE, callerid_setting);

	if (g_file_test(ALLOWED_FLAG_FILE, G_FILE_TEST_EXISTS))
		rename(ALLOWED_FLAG_FILE, callerid_file);
	else if (g_file_test(RESTRICTED_FLAG_FILE, G_FILE_TEST_EXISTS))
		rename(RESTRICTED_FLAG_FILE, callerid_file);
	else if (g_file_test(NONE_FLAG_FILE, G_FILE_TEST_EXISTS))
		rename(NONE_FLAG_FILE, callerid_file);
	else
		generate_flag_file(callerid_file);
}

static uint32_t callerid_from_file(void)
{
	if (g_file_test(ALLOWED_FLAG_FILE, G_FILE_TEST_EXISTS))
		return CALL_FLAG_PRESENTATION_ALLOWED;
	else if (g_file_test(RESTRICTED_FLAG_FILE, G_FILE_TEST_EXISTS))
		return CALL_FLAG_PRESENTATION_RESTRICTED;
	else if (g_file_test(NONE_FLAG_FILE, G_FILE_TEST_EXISTS))
		return CALL_FLAG_NONE;
	else
		return CALL_FLAG_NONE;
}

static DBusMessage *set_callerid(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	const char *callerid_setting;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING,
						&callerid_setting,
						DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	if (g_str_equal(callerid_setting, "allowed") ||
			g_str_equal(callerid_setting, "restricted") ||
			g_str_equal(callerid_setting, "none")) {
		save_callerid_to_file(callerid_setting);
		callerid = get_callflag(callerid_setting);
		DBG("telephony-maemo setting callerid flag: %s",
							callerid_setting);
		return dbus_message_new_method_return(msg);
	}

	error("telephony-maemo: invalid argument %s for method call"
					" SetCallerId", callerid_setting);
		return btd_error_invalid_args(msg);
}

static GDBusMethodTable telephony_maemo_methods[] = {
	{"SetCallerId",		"s",	"",	set_callerid,
						G_DBUS_METHOD_FLAG_ASYNC},
	{ }
};

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
		error("get_modem_status: %s, %s", err.name, err.message);
		dbus_error_free(&err);
	} else
		handle_modem_state(reply);

	dbus_message_unref(reply);
}

static DBusHandlerResult signal_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path = dbus_message_get_path(msg);

	if (dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

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
	else if (dbus_message_is_signal(msg, NETWORK_INTERFACE,
					"registration_status_change"))
		handle_registration_status_change(msg);
	else if (dbus_message_is_signal(msg, NETWORK_INTERFACE,
					"signal_strength_change"))
		handle_signal_strength_change(msg);
	else if (dbus_message_is_signal(msg, "org.freedesktop.Hal.Device",
					"PropertyModified"))
		handle_hal_property_modified(msg);
	else if (dbus_message_is_signal(msg, SSC_DBUS_IFACE,
						"modem_state_changed_ind"))
		handle_modem_state(msg);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (!dbus_connection_add_filter(connection, signal_filter,
						NULL, NULL))
		error("Can't add signal filter");

	dbus_bus_add_match(connection,
			"type=signal,interface=" CSD_CALL_INTERFACE, NULL);
	dbus_bus_add_match(connection,
			"type=signal,interface=" CSD_CALL_INSTANCE, NULL);
	dbus_bus_add_match(connection,
			"type=signal,interface=" CSD_CALL_CONFERENCE, NULL);
	dbus_bus_add_match(connection,
			"type=signal,interface=" NETWORK_INTERFACE, NULL);
	dbus_bus_add_match(connection,
				"type=signal,interface=" SSC_DBUS_IFACE
				",member=modem_state_changed_ind", NULL);

	if (send_method_call(SSC_DBUS_NAME, SSC_DBUS_PATH, SSC_DBUS_IFACE,
					"get_modem_state", modem_state_reply,
					NULL, DBUS_TYPE_INVALID) < 0)
		error("Unable to send " SSC_DBUS_IFACE ".get_modem_state()");

	generate_flag_file(NONE_FLAG_FILE);
	callerid = callerid_from_file();

	if (!g_dbus_register_interface(connection, TELEPHONY_MAEMO_PATH,
			TELEPHONY_MAEMO_INTERFACE, telephony_maemo_methods,
			NULL, NULL, NULL, NULL)) {
		error("telephony-maemo interface %s init failed on path %s",
			TELEPHONY_MAEMO_INTERFACE, TELEPHONY_MAEMO_PATH);
	}

	DBG("telephony-maemo registering %s interface on path %s",
			TELEPHONY_MAEMO_INTERFACE, TELEPHONY_MAEMO_PATH);

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

void telephony_exit(void)
{
	g_slist_foreach(calls, (GFunc) csd_call_free, NULL);
	g_slist_free(calls);
	calls = NULL;

	dbus_connection_remove_filter(connection, signal_filter, NULL);

	dbus_connection_unref(connection);
	connection = NULL;

	telephony_deinit();
}
