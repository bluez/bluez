/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2009-2010  Intel Corporation
 *  Copyright (C) 2006-2009  Nokia Corporation
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
#include <string.h>
#include <stdint.h>
#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "log.h"
#include "telephony.h"

enum net_registration_status {
	NETWORK_REG_STATUS_HOME = 0x00,
	NETWORK_REG_STATUS_ROAM,
	NETWORK_REG_STATUS_NOSERV
};

struct voice_call {
	char *obj_path;
	int status;
	gboolean originating;
	char *number;
	guint watch;
};

static DBusConnection *connection = NULL;
static char *modem_obj_path = NULL;
static char *last_dialed_number = NULL;
static GSList *calls = NULL;

#define OFONO_BUS_NAME "org.ofono"
#define OFONO_PATH "/"
#define OFONO_MANAGER_INTERFACE "org.ofono.Manager"
#define OFONO_NETWORKREG_INTERFACE "org.ofono.NetworkRegistration"
#define OFONO_VCMANAGER_INTERFACE "org.ofono.VoiceCallManager"
#define OFONO_VC_INTERFACE "org.ofono.VoiceCall"

static guint registration_watch = 0;
static guint voice_watch = 0;
static guint device_watch = 0;

/* HAL battery namespace key values */
static int battchg_cur = -1;    /* "battery.charge_level.current" */
static int battchg_last = -1;   /* "battery.charge_level.last_full" */
static int battchg_design = -1; /* "battery.charge_level.design" */

static struct {
	uint8_t status;
	uint32_t signals_bar;
	char *operator_name;
} net = {
	.status = NETWORK_REG_STATUS_NOSERV,
	.signals_bar = 0,
	.operator_name = NULL,
};

static const char *chld_str = "0,1,1x,2,2x,3,4";
static char *subscriber_number = NULL;

static gboolean events_enabled = FALSE;

/* Response and hold state
 * -1 = none
 *  0 = incoming call is put on hold in the AG
 *  1 = held incoming call is accepted in the AG
 *  2 = held incoming call is rejected in the AG
 */
static int response_and_hold = -1;

static struct indicator ofono_indicators[] =
{
	{ "battchg",	"0-5",	5,	TRUE },
	{ "signal",	"0-5",	5,	TRUE },
	{ "service",	"0,1",	1,	TRUE },
	{ "call",	"0,1",	0,	TRUE },
	{ "callsetup",	"0-3",	0,	TRUE },
	{ "callheld",	"0-2",	0,	FALSE },
	{ "roam",	"0,1",	0,	TRUE },
	{ NULL }
};

static struct voice_call *find_vc(const char *path)
{
	GSList *l;

	for (l = calls; l != NULL; l = l->next) {
		struct voice_call *vc = l->data;

		if (g_str_equal(vc->obj_path, path))
			return vc;
	}

	return NULL;
}

static struct voice_call *find_vc_with_status(int status)
{
	GSList *l;

	for (l = calls; l != NULL; l = l->next) {
		struct voice_call *vc = l->data;

		if (vc->status == status)
			return vc;
	}

	return NULL;
}

void telephony_device_connected(void *telephony_device)
{
	DBG("telephony-ofono: device %p connected", telephony_device);
}

void telephony_device_disconnected(void *telephony_device)
{
	DBG("telephony-ofono: device %p disconnected", telephony_device);
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
	DBG("telephony-ofono: last dialed number request");

	if (last_dialed_number)
		telephony_dial_number_req(telephony_device, last_dialed_number);
	else
		telephony_last_dialed_number_rsp(telephony_device,
				CME_ERROR_NOT_ALLOWED);
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

void telephony_terminate_call_req(void *telephony_device)
{
	struct voice_call *vc;
	int ret;

	if ((vc = find_vc_with_status(CALL_STATUS_ACTIVE))) {
	} else if ((vc = find_vc_with_status(CALL_STATUS_DIALING))) {
	} else if ((vc = find_vc_with_status(CALL_STATUS_ALERTING))) {
	} else if ((vc = find_vc_with_status(CALL_STATUS_INCOMING))) {
	}

	if (!vc) {
		error("in telephony_terminate_call_req, no active call");
		telephony_terminate_call_rsp(telephony_device,
					CME_ERROR_NOT_ALLOWED);
		return;
	}

	ret = send_method_call(OFONO_BUS_NAME, vc->obj_path,
					OFONO_VC_INTERFACE,
					"Hangup", NULL,
					NULL, DBUS_TYPE_INVALID);

	if (ret < 0) {
		telephony_answer_call_rsp(telephony_device,
					CME_ERROR_AG_FAILURE);
		return;
	}

	telephony_answer_call_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_answer_call_req(void *telephony_device)
{
	struct voice_call *vc = find_vc_with_status(CALL_STATUS_INCOMING);
	int ret;

	if (!vc) {
		telephony_answer_call_rsp(telephony_device,
					CME_ERROR_NOT_ALLOWED);
		return;
	}

	ret = send_method_call(OFONO_BUS_NAME, vc->obj_path,
			OFONO_VC_INTERFACE,
			"Answer", NULL,
			NULL, DBUS_TYPE_INVALID);

	if (ret < 0) {
		telephony_answer_call_rsp(telephony_device,
					CME_ERROR_AG_FAILURE);
		return;
	}

	telephony_answer_call_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_dial_number_req(void *telephony_device, const char *number)
{
	const char *clir;
	int ret;

	DBG("telephony-ofono: dial request to %s", number);

	if (!modem_obj_path) {
		telephony_dial_number_rsp(telephony_device,
					CME_ERROR_AG_FAILURE);
		return;
	}

	if (!strncmp(number, "*31#", 4)) {
		number += 4;
		clir = "enabled";
	} else if (!strncmp(number, "#31#", 4)) {
		number += 4;
		clir =  "disabled";
	} else
		clir = "default";

	ret = send_method_call(OFONO_BUS_NAME, modem_obj_path,
			OFONO_VCMANAGER_INTERFACE,
                        "Dial", NULL, NULL,
			DBUS_TYPE_STRING, &number,
			DBUS_TYPE_STRING, &clir,
			DBUS_TYPE_INVALID);

	if (ret < 0)
		telephony_dial_number_rsp(telephony_device,
			CME_ERROR_AG_FAILURE);
	else
		telephony_dial_number_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_transmit_dtmf_req(void *telephony_device, char tone)
{
	char *tone_string;
	int ret;

	DBG("telephony-ofono: transmit dtmf: %c", tone);

	if (!modem_obj_path) {
		telephony_transmit_dtmf_rsp(telephony_device,
					CME_ERROR_AG_FAILURE);
		return;
	}

	tone_string = g_strdup_printf("%c", tone);
	ret = send_method_call(OFONO_BUS_NAME, modem_obj_path,
			OFONO_VCMANAGER_INTERFACE,
			"SendTones", NULL, NULL,
			DBUS_TYPE_STRING, &tone_string,
			DBUS_TYPE_INVALID);
	g_free(tone_string);

	if (ret < 0)
		telephony_transmit_dtmf_rsp(telephony_device,
			CME_ERROR_AG_FAILURE);
	else
		telephony_transmit_dtmf_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_subscriber_number_req(void *telephony_device)
{
	DBG("telephony-ofono: subscriber number request");

	if (subscriber_number)
		telephony_subscriber_number_ind(subscriber_number,
						NUMBER_TYPE_TELEPHONY,
						SUBSCRIBER_SERVICE_VOICE);
	telephony_subscriber_number_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_list_current_calls_req(void *telephony_device)
{
	GSList *l;
	int i;

	DBG("telephony-ofono: list current calls request");

	for (l = calls, i = 1; l != NULL; l = l->next, i++) {
		struct voice_call *vc = l->data;
		int direction;

		direction = vc->originating ?
				CALL_DIR_OUTGOING : CALL_DIR_INCOMING;

		telephony_list_current_call_ind(i, direction, vc->status,
					CALL_MODE_VOICE, CALL_MULTIPARTY_NO,
					vc->number, NUMBER_TYPE_TELEPHONY);
	}
	telephony_list_current_calls_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_operator_selection_req(void *telephony_device)
{
	DBG("telephony-ofono: operator selection request");

	telephony_operator_selection_ind(OPERATOR_MODE_AUTO,
				net.operator_name ? net.operator_name : "");
	telephony_operator_selection_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_call_hold_req(void *telephony_device, const char *cmd)
{
	DBG("telephony-ofono: got call hold request %s", cmd);
	telephony_call_hold_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_nr_and_ec_req(void *telephony_device, gboolean enable)
{
	DBG("telephony-ofono: got %s NR and EC request",
			enable ? "enable" : "disable");

	telephony_nr_and_ec_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_key_press_req(void *telephony_device, const char *keys)
{
	DBG("telephony-ofono: got key press request for %s", keys);
	telephony_key_press_rsp(telephony_device, CME_ERROR_NONE);
}

void telephony_voice_dial_req(void *telephony_device, gboolean enable)
{
	DBG("telephony-ofono: got %s voice dial request",
			enable ? "enable" : "disable");

	telephony_voice_dial_rsp(telephony_device, CME_ERROR_NOT_SUPPORTED);
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

static void handle_registration_property(const char *property, DBusMessageIter sub)
{
	const char *status, *operator;
	unsigned int signals_bar;

	if (g_str_equal(property, "Status")) {
		dbus_message_iter_get_basic(&sub, &status);
		DBG("Status is %s", status);
		if (g_str_equal(status, "registered")) {
			net.status = NETWORK_REG_STATUS_HOME;
			telephony_update_indicator(ofono_indicators,
						"roam", EV_ROAM_INACTIVE);
			telephony_update_indicator(ofono_indicators,
						"service", EV_SERVICE_PRESENT);
		} else if (g_str_equal(status, "roaming")) {
			net.status = NETWORK_REG_STATUS_ROAM;
			telephony_update_indicator(ofono_indicators,
						"roam", EV_ROAM_ACTIVE);
			telephony_update_indicator(ofono_indicators,
						"service", EV_SERVICE_PRESENT);
		} else {
			net.status = NETWORK_REG_STATUS_NOSERV;
			telephony_update_indicator(ofono_indicators,
						"roam", EV_ROAM_INACTIVE);
			telephony_update_indicator(ofono_indicators,
						"service", EV_SERVICE_NONE);
		}
	} else if (g_str_equal(property, "Operator")) {
		dbus_message_iter_get_basic(&sub, &operator);
		DBG("Operator is %s", operator);
		g_free(net.operator_name);
		net.operator_name = g_strdup(operator);
	} else if (g_str_equal(property, "SignalStrength")) {
		dbus_message_iter_get_basic(&sub, &signals_bar);
		DBG("SignalStrength is %d", signals_bar);
		net.signals_bar = signals_bar;
		telephony_update_indicator(ofono_indicators, "signal",
						(signals_bar + 20) / 21);
	}
}

static void get_registration_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	DBusMessageIter iter, iter_entry;
	uint32_t features = AG_FEATURE_EC_ANDOR_NR |
				AG_FEATURE_REJECT_A_CALL |
				AG_FEATURE_ENHANCED_CALL_STATUS |
				AG_FEATURE_EXTENDED_ERROR_RESULT_CODES;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("ofono replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_message_iter_init(reply, &iter);

	/* ARRAY -> ENTRY -> VARIANT */
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("Unexpected signature in GetProperties return");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &iter_entry);

	if (dbus_message_iter_get_arg_type(&iter_entry)
					!= DBUS_TYPE_DICT_ENTRY) {
		error("Unexpected signature in GetProperties return");
		goto done;
	}

	while (dbus_message_iter_get_arg_type(&iter_entry)
					!= DBUS_TYPE_INVALID) {
		DBusMessageIter iter_property, sub;
		char *property;

		dbus_message_iter_recurse(&iter_entry, &iter_property);
		if (dbus_message_iter_get_arg_type(&iter_property)
					!= DBUS_TYPE_STRING) {
			error("Unexpected signature in GetProperties return");
			goto done;
		}

		dbus_message_iter_get_basic(&iter_property, &property);

		dbus_message_iter_next(&iter_property);
		dbus_message_iter_recurse(&iter_property, &sub);

		handle_registration_property(property, sub);

                dbus_message_iter_next(&iter_entry);
        }

	telephony_ready_ind(features, ofono_indicators,
				response_and_hold, chld_str);

done:
	dbus_message_unref(reply);
}

static int get_registration_and_signal_status()
{
	if (!modem_obj_path)
		return -ENOENT;

	return send_method_call(OFONO_BUS_NAME, modem_obj_path,
			OFONO_NETWORKREG_INTERFACE,
			"GetProperties", get_registration_reply,
			NULL, DBUS_TYPE_INVALID);
}

static void list_modem_reply(DBusPendingCall *call, void *user_data)
{
	DBusError err;
	DBusMessage *reply;
	DBusMessageIter iter, iter_entry, iter_property, iter_arrary, sub;
	char *property, *modem_obj_path_local;
	int ret;

	DBG("list_modem_reply is called\n");
	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("ofono replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	dbus_message_iter_init(reply, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("Unexpected signature in ListModems return");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &iter_entry);

	if (dbus_message_iter_get_arg_type(&iter_entry)
					!= DBUS_TYPE_DICT_ENTRY) {
		error("Unexpected signature in ListModems return 2, %c",
				dbus_message_iter_get_arg_type(&iter_entry));
		goto done;
	}

	dbus_message_iter_recurse(&iter_entry, &iter_property);

	dbus_message_iter_get_basic(&iter_property, &property);

	dbus_message_iter_next(&iter_property);
	dbus_message_iter_recurse(&iter_property, &iter_arrary);
	dbus_message_iter_recurse(&iter_arrary, &sub);
	while (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_INVALID) {

		dbus_message_iter_get_basic(&sub, &modem_obj_path_local);
		modem_obj_path = g_strdup(modem_obj_path_local);
		if (modem_obj_path != NULL) {
			DBG("modem_obj_path is %p, %s\n", modem_obj_path,
							modem_obj_path);
			break;
		}
		dbus_message_iter_next(&sub);
	}

	ret = get_registration_and_signal_status();
	if (ret < 0)
		error("get_registration_and_signal_status() failed(%d)", ret);
done:
	dbus_message_unref(reply);
}

static gboolean handle_registration_property_changed(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter, sub;
	const char *property;

	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		error("Unexpected signature in networkregistration"
					" PropertyChanged signal");
		return TRUE;
	}
	dbus_message_iter_get_basic(&iter, &property);
	DBG("in handle_registration_property_changed(),"
					" the property is %s", property);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &sub);

	handle_registration_property(property, sub);

	return TRUE;
}

static void vc_getproperties_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError err;
	DBusMessageIter iter, iter_entry;
	const char *path = user_data;
	struct voice_call *vc;

	DBG("in vc_getproperties_reply");

	reply = dbus_pending_call_steal_reply(call);
	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("ofono replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto done;
	}

	vc = find_vc(path);
	if (!vc) {
		error("in vc_getproperties_reply, vc is NULL");
		goto done;
	}

	dbus_message_iter_init(reply, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("Unexpected signature in vc_getproperties_reply()");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &iter_entry);

	if (dbus_message_iter_get_arg_type(&iter_entry)
			!= DBUS_TYPE_DICT_ENTRY) {
		error("Unexpected signature in vc_getproperties_reply()");
		goto done;
	}

	while (dbus_message_iter_get_arg_type(&iter_entry)
			!= DBUS_TYPE_INVALID) {
		DBusMessageIter iter_property, sub;
		char *property, *cli, *state;

		dbus_message_iter_recurse(&iter_entry, &iter_property);
		if (dbus_message_iter_get_arg_type(&iter_property)
				!= DBUS_TYPE_STRING) {
			error("Unexpected signature in"
					" vc_getproperties_reply()");
			goto done;
		}

		dbus_message_iter_get_basic(&iter_property, &property);

		dbus_message_iter_next(&iter_property);
		dbus_message_iter_recurse(&iter_property, &sub);
		if (g_str_equal(property, "LineIdentification")) {
			dbus_message_iter_get_basic(&sub, &cli);
			DBG("in vc_getproperties_reply(), cli is %s", cli);
			vc->number = g_strdup(cli);
		} else if (g_str_equal(property, "State")) {
			dbus_message_iter_get_basic(&sub, &state);
			DBG("in vc_getproperties_reply(),"
					" state is %s", state);
			if (g_str_equal(state, "incoming"))
				vc->status = CALL_STATUS_INCOMING;
			else if (g_str_equal(state, "dialing"))
				vc->status = CALL_STATUS_DIALING;
			else if (g_str_equal(state, "alerting"))
				vc->status = CALL_STATUS_ALERTING;
			else if (g_str_equal(state, "waiting"))
				vc->status = CALL_STATUS_WAITING;
		}

		dbus_message_iter_next(&iter_entry);
	}

	switch (vc->status) {
	case CALL_STATUS_INCOMING:
		printf("in CALL_STATUS_INCOMING: case\n");
		vc->originating = FALSE;
		telephony_update_indicator(ofono_indicators, "callsetup",
					EV_CALLSETUP_INCOMING);
		telephony_incoming_call_ind(vc->number, NUMBER_TYPE_TELEPHONY);
		break;
	case CALL_STATUS_DIALING:
		printf("in CALL_STATUS_DIALING: case\n");
		vc->originating = TRUE;
		g_free(last_dialed_number);
		last_dialed_number = g_strdup(vc->number);
		telephony_update_indicator(ofono_indicators, "callsetup",
					EV_CALLSETUP_OUTGOING);
		break;
	case CALL_STATUS_ALERTING:
		printf("in CALL_STATUS_ALERTING: case\n");
		vc->originating = TRUE;
		g_free(last_dialed_number);
		last_dialed_number = g_strdup(vc->number);
		telephony_update_indicator(ofono_indicators, "callsetup",
					EV_CALLSETUP_ALERTING);
		break;
	case CALL_STATUS_WAITING:
		DBG("in CALL_STATUS_WAITING: case");
		vc->originating = FALSE;
		telephony_update_indicator(ofono_indicators, "callsetup",
					EV_CALLSETUP_INCOMING);
		telephony_call_waiting_ind(vc->number, NUMBER_TYPE_TELEPHONY);
		break;
	}
done:
	dbus_message_unref(reply);
}

static void vc_free(struct voice_call *vc)
{
	if (!vc)
		return;

	g_dbus_remove_watch(connection, vc->watch);
	g_free(vc->obj_path);
	g_free(vc->number);
	g_free(vc);
}

static gboolean handle_vc_property_changed(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct voice_call *vc = data;
	const char *obj_path = dbus_message_get_path(msg);
	DBusMessageIter iter, sub;
	const char *property, *state;

	DBG("in handle_vc_property_changed, obj_path is %s", obj_path);

	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		error("Unexpected signature in vc PropertyChanged signal");
		return TRUE;
	}

	dbus_message_iter_get_basic(&iter, &property);
	DBG("in handle_vc_property_changed(), the property is %s", property);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &sub);
	if (g_str_equal(property, "State")) {
		dbus_message_iter_get_basic(&sub, &state);
		DBG("in handle_vc_property_changed(), State is %s", state);
		if (g_str_equal(state, "disconnected")) {
			printf("in disconnected case\n");
			if (vc->status == CALL_STATUS_ACTIVE)
				telephony_update_indicator(ofono_indicators,
						"call", EV_CALL_INACTIVE);
			else
				telephony_update_indicator(ofono_indicators,
					"callsetup", EV_CALLSETUP_INACTIVE);
			if (vc->status == CALL_STATUS_INCOMING)
				telephony_calling_stopped_ind();
			calls = g_slist_remove(calls, vc);
			vc_free(vc);
		} else if (g_str_equal(state, "active")) {
			telephony_update_indicator(ofono_indicators,
							"call", EV_CALL_ACTIVE);
			telephony_update_indicator(ofono_indicators,
							"callsetup",
							EV_CALLSETUP_INACTIVE);
			if (vc->status == CALL_STATUS_INCOMING)
				telephony_calling_stopped_ind();
			vc->status = CALL_STATUS_ACTIVE;
			DBG("vc status is CALL_STATUS_ACTIVE");
		} else if (g_str_equal(state, "alerting")) {
			telephony_update_indicator(ofono_indicators,
					"callsetup", EV_CALLSETUP_ALERTING);
			vc->status = CALL_STATUS_ALERTING;
			DBG("vc status is CALL_STATUS_ALERTING");
		} else if (g_str_equal(state, "incoming")) {
			/* state change from waiting to incoming */
			telephony_update_indicator(ofono_indicators,
					"callsetup", EV_CALLSETUP_INCOMING);
			telephony_incoming_call_ind(vc->number,
						NUMBER_TYPE_TELEPHONY);
			vc->status = CALL_STATUS_INCOMING;
			DBG("vc status is CALL_STATUS_INCOMING");
		}
	}

	return TRUE;
}

static gboolean handle_vcmanager_property_changed(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter, sub, array;
	const char *property, *vc_obj_path = NULL;
	struct voice_call *vc, *vc_new = NULL;

	DBG("in handle_vcmanager_property_changed");

	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		error("Unexpected signature in vcmanager"
					" PropertyChanged signal");
		return TRUE;
	}

	dbus_message_iter_get_basic(&iter, &property);
	DBG("in handle_vcmanager_property_changed(),"
				" the property is %s", property);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &sub);
	if (dbus_message_iter_get_arg_type(&sub) != DBUS_TYPE_ARRAY) {
		error("Unexpected signature in vcmanager"
					" PropertyChanged signal");
		return TRUE;
	}
	dbus_message_iter_recurse(&sub, &array);
	while (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_INVALID) {
		dbus_message_iter_get_basic(&array, &vc_obj_path);
		vc = find_vc(vc_obj_path);
		if (vc) {
			DBG("in handle_vcmanager_property_changed,"
					" found an existing vc");
		} else {
			vc_new = g_new0(struct voice_call, 1);
			vc_new->obj_path = g_strdup(vc_obj_path);
			calls = g_slist_append(calls, vc_new);
			vc_new->watch = g_dbus_add_signal_watch(connection,
					NULL, vc_obj_path,
					OFONO_VC_INTERFACE,
					"PropertyChanged",
					handle_vc_property_changed,
					vc_new, NULL);
		}
		dbus_message_iter_next(&array);
	}

	if (!vc_new)
		return TRUE;

	send_method_call(OFONO_BUS_NAME, vc_new->obj_path,
				OFONO_VC_INTERFACE,
				"GetProperties", vc_getproperties_reply,
				vc_new->obj_path, DBUS_TYPE_INVALID);

	return TRUE;
}

static void hal_battery_level_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError err;
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
		DBG("telephony-ofono: battery.charge_level.last_full"
					" is %d", *value);
	else if (value == &battchg_design)
		DBG("telephony-ofono: battery.charge_level.design"
					" is %d", *value);
	else
		DBG("telephony-ofono: battery.charge_level.current"
					" is %d", *value);

	if ((battchg_design > 0 || battchg_last > 0) && battchg_cur >= 0) {
		int new, max;

		if (battchg_last > 0)
			max = battchg_last;
		else
			max = battchg_design;

		new = battchg_cur * 5 / max;

		telephony_update_indicator(ofono_indicators, "battchg", new);
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

static gboolean handle_hal_property_modified(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *path;
	DBusMessageIter iter, array;
	dbus_int32_t num_changes;

	path = dbus_message_get_path(msg);

	dbus_message_iter_init(msg, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32) {
		error("Unexpected signature in hal PropertyModified signal");
		return TRUE;
	}

	dbus_message_iter_get_basic(&iter, &num_changes);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		error("Unexpected signature in hal PropertyModified signal");
		return TRUE;
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

	return TRUE;
}

static void hal_find_device_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError err;
	DBusMessageIter iter, sub;
	int type;
	const char *path;

	DBG("begin of hal_find_device_reply()");
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
		error("Unexpected signature in hal_find_device_reply()");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &sub);

	type = dbus_message_iter_get_arg_type(&sub);

	if (type != DBUS_TYPE_OBJECT_PATH && type != DBUS_TYPE_STRING) {
		error("No hal device with battery capability found");
		goto done;
	}

	dbus_message_iter_get_basic(&sub, &path);

	DBG("telephony-ofono: found battery device at %s", path);

	device_watch = g_dbus_add_signal_watch(connection, NULL, path,
					"org.freedesktop.Hal.Device",
					"PropertyModified",
					handle_hal_property_modified,
					NULL, NULL);

	hal_get_integer(path, "battery.charge_level.last_full", &battchg_last);
	hal_get_integer(path, "battery.charge_level.current", &battchg_cur);
	hal_get_integer(path, "battery.charge_level.design", &battchg_design);
done:
	dbus_message_unref(reply);
}

int telephony_init(void)
{
	const char *battery_cap = "battery";
	int ret;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	registration_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
					OFONO_NETWORKREG_INTERFACE,
					"PropertyChanged",
					handle_registration_property_changed,
					NULL, NULL);

	voice_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
					OFONO_VCMANAGER_INTERFACE,
					"PropertyChanged",
					handle_vcmanager_property_changed,
					NULL, NULL);

	ret = send_method_call(OFONO_BUS_NAME, OFONO_PATH,
				OFONO_MANAGER_INTERFACE, "GetProperties",
				list_modem_reply, NULL, DBUS_TYPE_INVALID);
	if (ret < 0)
		return ret;

	ret = send_method_call("org.freedesktop.Hal",
				"/org/freedesktop/Hal/Manager",
				"org.freedesktop.Hal.Manager",
				"FindDeviceByCapability",
				hal_find_device_reply, NULL,
				DBUS_TYPE_STRING, &battery_cap,
				DBUS_TYPE_INVALID);
	if (ret < 0)
		return ret;

	DBG("telephony_init() successfully");

	return ret;
}

void telephony_exit(void)
{
	g_free(net.operator_name);

	g_free(modem_obj_path);
	g_free(last_dialed_number);

	g_slist_foreach(calls, (GFunc) vc_free, NULL);
	g_slist_free(calls);
	calls = NULL;

	g_dbus_remove_watch(connection, registration_watch);
	g_dbus_remove_watch(connection, voice_watch);
	g_dbus_remove_watch(connection, device_watch);

	dbus_connection_unref(connection);
	connection = NULL;
}
