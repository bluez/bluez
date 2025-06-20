/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *  Copyright © 2025 Collabora Ltd.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>

#include <stdint.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"
#include "lib/uuid.h"

#include "gdbus/gdbus.h"

#include "btio/btio.h"
#include "src/adapter.h"
#include "src/btd.h"
#include "src/dbus-common.h"
#include "src/device.h"
#include "src/error.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/shared/hfp.h"

#include "telephony.h"

#define HFP_HF_VERSION		0x0109
#define HFP_HF_DEFAULT_CHANNEL	7

#define CALL_IND_NO_CALL_IN_PROGRESS	0x00
#define CALL_IND_CALL_IN_PROGRESS	0x01

#define CHLD_FEAT_REL		0x00000001
#define CHLD_FEAT_REL_ACC	0x00000002
#define CHLD_FEAT_REL_X		0x00000004
#define CHLD_FEAT_HOLD_ACC	0x00000008
#define CHLD_FEAT_PRIV_X	0x00000010
#define CHLD_FEAT_MERGE		0x00000020
#define CHLD_FEAT_MERGE_DETACH	0x00000040

#define HFP_HF_SDP_ECNR					0x0001
#define HFP_HF_SDP_3WAY					0x0002
#define HFP_HF_SDP_CLIP					0x0004
#define HFP_HF_SDP_VOICE_RECOGNITION			0x0008
#define HFP_HF_SDP_REMOTE_VOLUME_CONTROL		0x0010
#define HFP_HF_SDP_WIDE_BAND_SPEECH			0x0020
#define HFP_HF_SDP_ENHANCED_VOICE_RECOGNITION_STATUS	0x0040
#define HFP_HF_SDP_VOICE_RECOGNITION_TEXT		0x0080
#define HFP_HF_SDP_SUPER_WIDE_BAND_SPEECH		0x0100

#define HFP_HF_FEAT_ECNR				0x00000001
#define HFP_HF_FEAT_3WAY				0x00000002
#define HFP_HF_FEAT_CLIP				0x00000004
#define HFP_HF_FEAT_VOICE_RECOGNITION			0x00000008
#define HFP_HF_FEAT_REMOTE_VOLUME_CONTROL		0x00000010
#define HFP_HF_FEAT_ENHANCED_CALL_STATUS		0x00000020
#define HFP_HF_FEAT_ENHANCED_CALL_CONTROL		0x00000040
#define HFP_HF_FEAT_CODEC_NEGOTIATION			0x00000080
#define HFP_HF_FEAT_HF_INDICATORS			0x00000100
#define HFP_HF_FEAT_ESCO_S4_T2				0x00000200
#define HFP_HF_FEAT_ENHANCED_VOICE_RECOGNITION_STATUS	0x00000400
#define HFP_HF_FEAT_VOICE_RECOGNITION_TEXT		0x00000800

#define HFP_AG_FEAT_3WAY				0x00000001
#define HFP_AG_FEAT_ECNR				0x00000002
#define HFP_AG_FEAT_VOICE_RECOGNITION			0x00000004
#define HFP_AG_FEAT_IN_BAND_RING_TONE			0x00000008
#define HFP_AG_FEAT_ATTACH_VOICE_TAG			0x00000010
#define HFP_AG_FEAT_REJECT_CALL				0x00000020
#define HFP_AG_FEAT_ENHANCED_CALL_STATUS		0x00000040
#define HFP_AG_FEAT_ENHANCED_CALL_CONTROL		0x00000080
#define HFP_AG_FEAT_EXTENDED_RES_CODE			0x00000100
#define HFP_AG_FEAT_CODEC_NEGOTIATION			0x00000200
#define HFP_AG_FEAT_HF_INDICATORS			0x00000400
#define HFP_AG_FEAT_ESCO_S4_T2				0x00000800
#define HFP_AG_FEAT_ENHANCED_VOICE_RECOGNITION_STATUS	0x00001000
#define HFP_AG_FEAT_VOICE_RECOGNITION_TEXT		0x00001000

#define HFP_HF_SDP_FEATURES	(HFP_HF_SDP_ECNR | HFP_HF_SDP_3WAY |\
				HFP_HF_SDP_CLIP |\
				HFP_HF_SDP_REMOTE_VOLUME_CONTROL)

#define HFP_HF_FEATURES		(HFP_HF_FEAT_ECNR | HFP_HF_FEAT_3WAY |\
				HFP_HF_FEAT_CLIP |\
				HFP_HF_FEAT_REMOTE_VOLUME_CONTROL |\
				HFP_HF_FEAT_ENHANCED_CALL_STATUS |\
				HFP_HF_FEAT_ESCO_S4_T2)

#define CHLD_3WAY_FEATURES	(CHLD_FEAT_REL | CHLD_FEAT_REL_ACC |\
				CHLD_FEAT_HOLD_ACC | CHLD_FEAT_MERGE)

#define MAX_NUMBER_LEN 33
#define MAX_OPERATOR_NAME_LEN 17

enum hfp_indicator {
	HFP_INDICATOR_SERVICE = 0,
	HFP_INDICATOR_CALL,
	HFP_INDICATOR_CALLSETUP,
	HFP_INDICATOR_CALLHELD,
	HFP_INDICATOR_SIGNAL,
	HFP_INDICATOR_ROAM,
	HFP_INDICATOR_BATTCHG,
	HFP_INDICATOR_LAST
};

enum call_setup {
	CIND_CALLSETUP_NONE = 0,
	CIND_CALLSETUP_INCOMING,
	CIND_CALLSETUP_DIALING,
	CIND_CALLSETUP_ALERTING
};

enum call_held {
	CIND_CALLHELD_NONE = 0,
	CIND_CALLHELD_HOLD_AND_ACTIVE,
	CIND_CALLHELD_HOLD
};

typedef void (*ciev_func_t)(uint8_t val, void *user_data);

struct indicator {
	uint8_t index;
	uint32_t min;
	uint32_t max;
	uint32_t val;
	ciev_func_t cb;
};

struct hfp_device {
	struct telephony	*telephony;
	uint16_t		version;
	GIOChannel		*io;
	enum connection_state	state;
	uint32_t		hfp_hf_features;
	uint32_t		features;
	struct hfp_hf		*hf;
	struct indicator	ag_ind[HFP_INDICATOR_LAST];
	uint32_t		chld_features;
	bool			call;
	enum call_setup		call_setup;
	enum call_held		call_held;
	GSList			*calls;
};

struct hfp_server {
	struct btd_adapter	*adapter;
	GIOChannel		*io;
	uint32_t		record_id;
};

static GSList *servers;

static struct hfp_server *find_server(GSList *list, struct btd_adapter *a)
{
	for (; list; list = list->next) {
		struct hfp_server *server = list->data;

		if (server->adapter == a)
			return server;
	}

	return NULL;
}

static void device_destroy(struct hfp_device *dev)
{
	DBG("%s", telephony_get_path(dev->telephony));

	telephony_set_state(dev->telephony, DISCONNECTING);

	if (dev->hf) {
		hfp_hf_unref(dev->hf);
		dev->hf = NULL;
	}

	if (dev->io) {
		g_io_channel_unref(dev->io);
		dev->io = NULL;
	}

	telephony_unregister_interface(dev->telephony);
}

static void slc_error(struct hfp_device *dev)
{
	error("Could not create SLC - dropping connection");
	hfp_hf_disconnect(dev->hf);
}

static void set_chld_feat(struct hfp_device *dev, char *feat)
{
	DBG(" %s", feat);

	if (strcmp(feat, "0") == 0)
		dev->chld_features |= CHLD_FEAT_REL;
	else if (strcmp(feat, "1") == 0)
		dev->chld_features |= CHLD_FEAT_REL_ACC;
	else if (strcmp(feat, "1x") == 0)
		dev->chld_features |= CHLD_FEAT_REL_X;
	else if (strcmp(feat, "2") == 0)
		dev->chld_features |= CHLD_FEAT_HOLD_ACC;
	else if (strcmp(feat, "2x") == 0)
		dev->chld_features |= CHLD_FEAT_PRIV_X;
	else if (strcmp(feat, "3") == 0)
		dev->chld_features |= CHLD_FEAT_MERGE;
	else if (strcmp(feat, "4") == 0)
		dev->chld_features |= CHLD_FEAT_MERGE_DETACH;
}

static const char *cme_error_to_string(uint8_t cme_error)
{
	switch (cme_error) {
	case 0: return "AG failure";
	case 1: return "no connection to phone";
	case 3: return "operation not allowed";
	case 4: return "operation not supported";
	case 5: return "PH-SIM PIN required";
	case 10: return "SIM not inserted";
	case 11: return "SIM PIN required";
	case 12: return "SIM PUK required";
	case 13: return "SIM failure";
	case 14: return "SIM busy";
	case 16: return "incorrect password";
	case 17: return "SIM PIN2 required";
	case 18: return "SIM PUK2 required";
	case 20: return "memory full";
	case 21: return "invalid index";
	case 23: return "memory failure";
	case 24: return "text string too long";
	case 25: return "invalid characters in text string";
	case 26: return "dial string too long";
	case 27: return "invalid characters in dial string";
	case 30: return "no network service";
	case 31: return "network Timeout";
	case 32: return "network not allowed - Emergency calls only";
	default: return "Unknown CME error";
	}
}

static void cmd_complete_cb(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	DBusMessage *msg = user_data;
	DBusMessage *reply = NULL;

	DBG("%u", result);

	if (msg == NULL)
		return;

	switch (result) {
	case HFP_RESULT_OK:
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
		break;
	case HFP_RESULT_NO_CARRIER:
		reply = btd_error_failed(msg, "no-carrier");
		break;
	case HFP_RESULT_ERROR:
		reply = btd_error_failed(msg, "unknown");
		break;
	case HFP_RESULT_BUSY:
		reply = btd_error_busy(msg);
		break;
	case HFP_RESULT_NO_ANSWER:
		reply = btd_error_failed(msg, "no-answer");
		break;
	case HFP_RESULT_DELAYED:
		reply = btd_error_failed(msg, "delayed");
		break;
	case HFP_RESULT_REJECTED:
		reply = btd_error_failed(msg, "rejected");
		break;
	case HFP_RESULT_CME_ERROR:
		reply = btd_error_failed(msg, cme_error_to_string(cme_err));
		break;
	case HFP_RESULT_CONNECT:
	case HFP_RESULT_RING:
	case HFP_RESULT_NO_DIALTONE:
	default:
		reply = btd_error_failed(msg, "unknown");
		error("hf-client: Unknown error code %d", result);
		break;
	}

	if (reply) {
		g_dbus_send_message(btd_get_dbus_connection(), reply);
		dbus_message_unref(msg);
	}
}

static uint8_t next_index(struct hfp_device *dev)
{
	uint8_t i;

	for (i = 1; i != 0; i++) {
		GSList *l;
		bool found = false;

		for (l = dev->calls; l; l = l->next) {
			struct call *call = l->data;

			if (call->idx == i) {
				found = true;
				break;
			}
		}

		if (!found)
			return i;
	}

	error("hf-client: No free call index found");
	return 0;
}

static void ccwa_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_device *dev = user_data;
	char number[MAX_NUMBER_LEN];
	GSList *l;
	bool found = false;

	DBG("");

	if (!hfp_context_get_string(context, number, MAX_NUMBER_LEN)) {
		error("hf-client: incorrect +CCWA event");
		return;
	}

	for (l = dev->calls; l; l = l->next) {
		struct call *call = l->data;

		if (call->state == CALL_STATE_WAITING) {
			info("hf-client: waiting call in progress (id: %d)",
				call->idx);
			found = true;
			break;
		}
	}

	if (!found) {
		struct call *call;
		uint8_t idx = next_index(dev);

		call = telephony_new_call(dev->telephony, idx,
						CALL_STATE_WAITING, NULL);
		call->line_id = g_strdup(number);
		if (telephony_call_register_interface(call)) {
			telephony_free_call(call);
			return;
		}
		dev->calls = g_slist_append(dev->calls, call);
	}
}

static void ciev_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_device *dev = user_data;
	unsigned int index, val;
	int i;

	DBG("");

	if (!hfp_context_get_number(context, &index))
		return;

	if (!hfp_context_get_number(context, &val))
		return;

	for (i = 0; i < HFP_INDICATOR_LAST; i++) {
		if (dev->ag_ind[i].index != index)
			continue;

		if (dev->ag_ind[i].cb) {
			dev->ag_ind[i].val = val;
			dev->ag_ind[i].cb(val, dev);
			return;
		}
	}
}

static void clip_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_device *dev = user_data;
	char number[MAX_NUMBER_LEN];
	GSList *l;

	DBG("");

	if (!hfp_context_get_string(context, number, MAX_NUMBER_LEN)) {
		error("hf-client: incorrect +CLIP event");
		return;
	}

	for (l = dev->calls; l; l = l->next) {
		struct call *call = l->data;

		if (call->state == CALL_STATE_INCOMING) {
			telephony_call_set_line_id(call, number);
			break;
		}
	}
}

static void cops_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_device *dev = user_data;
	unsigned int format;
	char name[MAX_OPERATOR_NAME_LEN];

	DBG("");

	/* Not interested in mode */
	hfp_context_skip_field(context);

	if (!hfp_context_get_number(context, &format))
		return;

	if (format != 0) {
		warn("hf-client: Not correct string format in +COPS");
		return;
	}

	if (!hfp_context_get_string(context, name, MAX_OPERATOR_NAME_LEN)) {
		error("hf-client: incorrect +COPS response");
		return;
	}

	telephony_set_operator_name(dev->telephony, name);
}

static void nrec_resp(enum hfp_result result, enum hfp_error cme_err,
							void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (result != HFP_RESULT_OK) {
		error("hf-client: CLIP error: %d", result);
		return;
	}

	if ((dev->chld_features & CHLD_3WAY_FEATURES) == CHLD_3WAY_FEATURES) {
		if (!hfp_hf_send_command(dev->hf, cmd_complete_cb, dev,
								"AT+CCWA=1"))
			info("hf-client: Could not send AT+CCWA=1");
	}
}

static void clip_resp(enum hfp_result result, enum hfp_error cme_err,
							void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (result != HFP_RESULT_OK) {
		error("hf-client: CLIP error: %d", result);
		return;
	}

	if ((dev->hfp_hf_features & HFP_HF_FEAT_ECNR) &&
			(dev->features & HFP_AG_FEAT_ECNR)) {
		if (!hfp_hf_send_command(dev->hf, nrec_resp, dev, "AT+NREC=0"))
			info("hf-client: Could not send AT+NREC=0");
	} else if ((dev->chld_features & CHLD_3WAY_FEATURES) ==
			CHLD_3WAY_FEATURES) {
		if (!hfp_hf_send_command(dev->hf, cmd_complete_cb, dev,
								"AT+CCWA=1"))
			info("hf-client: Could not send AT+CCWA=1");
	}
}

static void cops_status_resp(enum hfp_result result, enum hfp_error cme_err,
							void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (result != HFP_RESULT_OK) {
		error("hf-client: COPS? error: %d", result);
		return;
	}

	if (!hfp_hf_send_command(dev->hf, clip_resp, dev, "AT+CLIP=1"))
		info("hf-client: Could not send AT+CLIP=1");
}

static void cops_resp(enum hfp_result result, enum hfp_error cme_err,
							void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (result != HFP_RESULT_OK) {
		error("hf-client: COPS error: %d", result);
		return;
	}

	if (!hfp_hf_send_command(dev->hf, cops_status_resp, dev, "AT+COPS?"))
		info("hf-client: Could not send AT+COPS?");
}

static void slc_completed(struct hfp_device *dev)
{
	int i;
	struct indicator *ag_ind;

	DBG("");

	ag_ind = dev->ag_ind;

	telephony_set_state(dev->telephony, CONNECTED);

	/* Notify Android with indicators */
	for (i = 0; i < HFP_INDICATOR_LAST; i++) {
		if (!ag_ind[i].cb)
			continue;

		ag_ind[i].cb(ag_ind[i].val, dev);
	}

	/* TODO: register unsolicited results handlers */

	hfp_hf_register(dev->hf, ccwa_cb, "+CCWA", dev, NULL);
	hfp_hf_register(dev->hf, ciev_cb, "+CIEV", dev, NULL);
	hfp_hf_register(dev->hf, clip_cb, "+CLIP", dev, NULL);
	hfp_hf_register(dev->hf, cops_cb, "+COPS", dev, NULL);

	if (!hfp_hf_send_command(dev->hf, cops_resp, dev, "AT+COPS=3,0"))
		info("hf-client: Could not send AT+COPS=3,0");
}

static void slc_chld_resp(enum hfp_result result, enum hfp_error cme_err,
							void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	hfp_hf_unregister(dev->hf, "+CHLD");

	if (result != HFP_RESULT_OK) {
		error("hf-client: CHLD error: %d", result);
		slc_error(dev);
		return;
	}

	slc_completed(dev);
}

static void slc_chld_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_device *dev = user_data;
	char feat[3];

	if (!hfp_context_open_container(context))
		goto failed;

	while (hfp_context_get_unquoted_string(context, feat, sizeof(feat)))
		set_chld_feat(dev, feat);

	if (!hfp_context_close_container(context))
		goto failed;

	return;

failed:
	error("hf-client: Error on CHLD response");
	slc_error(dev);
}

static void slc_cmer_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (result != HFP_RESULT_OK) {
		error("hf-client: CMER error: %d", result);
		goto failed;
	}

	/* Continue with SLC creation */
	if (!(dev->features & HFP_AG_FEAT_3WAY)) {
		slc_completed(dev);
		return;
	}

	if (!hfp_hf_register(dev->hf, slc_chld_cb, "+CHLD", dev, NULL)) {
		error("hf-client: Could not register +CHLD");
		goto failed;
	}

	if (!hfp_hf_send_command(dev->hf, slc_chld_resp, dev, "AT+CHLD=?")) {
		error("hf-client: Could not send AT+CHLD");
		goto failed;
	}

	return;

failed:
	slc_error(dev);
}

static void slc_cind_status_resp(enum hfp_result result,
	enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	hfp_hf_unregister(dev->hf, "+CIND");

	if (result != HFP_RESULT_OK) {
		error("hf-client: CIND error: %d", result);
		goto failed;
	}

	/* Continue with SLC creation */
	if (!hfp_hf_send_command(dev->hf, slc_cmer_resp, dev,
		"AT+CMER=3,0,0,1")) {
		error("hf-client: Counld not send AT+CMER");
		goto failed;
	}

	return;

failed:
	slc_error(dev);
}

static void set_indicator_value(uint8_t index, unsigned int val,
	struct indicator *ag_ind, struct hfp_device *dev)
{
	int i;

	for (i = 0; i < HFP_INDICATOR_LAST; i++) {
		if (index != ag_ind[i].index)
			continue;

		ag_ind[i].val = val;
		ag_ind[i].cb(val, dev);
		return;
	}
}

static void slc_cind_status_cb(struct hfp_context *context,
	void *user_data)
{
	struct hfp_device *dev = user_data;
	uint8_t index = 1;

	DBG("");

	while (hfp_context_has_next(context)) {
		uint32_t val;

		if (!hfp_context_get_number(context, &val)) {
			error("hf-client: Error on CIND status response");
			return;
		}

		set_indicator_value(index++, val, dev->ag_ind, dev);
	}
}

static void slc_cind_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	hfp_hf_unregister(dev->hf, "+CIND");

	if (result != HFP_RESULT_OK) {
		error("hf-client: CIND error: %d", result);
		goto failed;
	}

	/* Continue with SLC creation */
	if (!hfp_hf_register(dev->hf, slc_cind_status_cb, "+CIND", dev,
			NULL)) {
		error("hf-client: Counld not register +CIND");
		goto failed;
	}

	if (!hfp_hf_send_command(dev->hf, slc_cind_status_resp, dev,
			"AT+CIND?")) {
		error("hf-client: Counld not send AT+CIND?");
		goto failed;
	}

	return;

failed:
	slc_error(dev);
}

static void ciev_service_cb(uint8_t val, void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (val > 1) {
		error("hf-client: Incorrect state %u:", val);
		return;
	}

	telephony_set_network_service(dev->telephony, val);
}

static void activate_calls(gpointer data, gpointer user_data)
{
	struct call *call = data;

	if (call->state == CALL_STATE_DIALING ||
			call->state == CALL_STATE_ALERTING ||
			call->state == CALL_STATE_INCOMING)
		telephony_call_set_state(call, CALL_STATE_ACTIVE);
}

static void deactivate_active_calls(gpointer data, gpointer user_data)
{
	struct call *call = data;
	struct hfp_device *dev = user_data;

	if (call->state == CALL_STATE_ACTIVE) {
		telephony_call_set_state(call, CALL_STATE_DISCONNECTED);
		dev->calls = g_slist_remove(dev->calls, call);
		telephony_call_unregister_interface(call);
	}
}

static void ciev_call_cb(uint8_t val, void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (val > CALL_IND_CALL_IN_PROGRESS) {
		error("hf-client: Incorrect call state %u:", val);
		return;
	}

	if (dev->call == val)
		return;

	dev->call = !!val;

	if (dev->call == TRUE) {
		if (dev->calls == NULL) {
			/* Create already active call during SLC */
			struct call *call;
			uint8_t idx = next_index(dev);

			call = telephony_new_call(dev->telephony, idx,
							CALL_STATE_ACTIVE,
							NULL);
			if (telephony_call_register_interface(call)) {
				telephony_free_call(call);
				return;
			}
			dev->calls = g_slist_append(dev->calls, call);
		} else {
			g_slist_foreach(dev->calls, activate_calls, dev);
		}
	} else {
		g_slist_foreach(dev->calls, deactivate_active_calls, dev);
	}
}

static void callsetup_deactivate(gpointer data, gpointer user_data)
{
	struct call *call = data;
	struct hfp_device *dev = user_data;

	if (call->state == CALL_STATE_DIALING ||
			call->state == CALL_STATE_ALERTING ||
			call->state == CALL_STATE_INCOMING ||
			call->state == CALL_STATE_WAITING) {
		telephony_call_set_state(call, CALL_STATE_DISCONNECTED);
		dev->calls = g_slist_remove(dev->calls, call);
		telephony_call_unregister_interface(call);
	}
}

static void callsetup_alerting(gpointer data, gpointer user_data)
{
	struct call *call = data;

	if (call->state == CALL_STATE_DIALING)
		telephony_call_set_state(call, CALL_STATE_ALERTING);
}

static void ciev_callsetup_cb(uint8_t val, void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (val > CIND_CALLSETUP_ALERTING) {
		error("hf-client: Incorrect call setup state %u:", val);
		return;
	}

	if (dev->call_setup == val)
		return;

	dev->call_setup = val;

	if (dev->call_setup == CIND_CALLSETUP_NONE) {
		g_slist_foreach(dev->calls, callsetup_deactivate, dev);
	} else if (dev->call_setup == CIND_CALLSETUP_INCOMING) {
		bool found = FALSE;
		GSList *l;

		for (l = dev->calls; l; l = l->next) {
			struct call *call = l->data;

			if (call->state == CALL_STATE_INCOMING ||
				call->state == CALL_STATE_WAITING) {
				DBG("incoming call already in progress (%d)",
								 call->state);
				found = TRUE;
				break;
			}
		}

		if (!found) {
			struct call *call;
			uint8_t idx = next_index(dev);

			call = telephony_new_call(dev->telephony, idx,
							CALL_STATE_INCOMING,
							NULL);
			if (telephony_call_register_interface(call)) {
				telephony_free_call(call);
				return;
			}
			dev->calls = g_slist_append(dev->calls, call);
		}
	} else if (dev->call_setup == CIND_CALLSETUP_DIALING) {
		bool found = FALSE;
		GSList *l;

		for (l = dev->calls; l; l = l->next) {
			struct call *call = l->data;

			if (call->state == CALL_STATE_DIALING ||
				call->state == CALL_STATE_ALERTING) {
				DBG("dialing call already in progress (%d)",
								call->state);
				found = TRUE;
				break;
			}
		}

		if (!found) {
			struct call *call;
			uint8_t idx = next_index(dev);

			call = telephony_new_call(dev->telephony, idx,
							CALL_STATE_DIALING,
							NULL);
			if (telephony_call_register_interface(call)) {
				telephony_free_call(call);
				return;
			}
			dev->calls = g_slist_append(dev->calls, call);
		}
	} else if (dev->call_setup == CIND_CALLSETUP_ALERTING) {
		g_slist_foreach(dev->calls, callsetup_alerting, dev);
	}
}

static void ciev_callheld_cb(uint8_t val, void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (val > CIND_CALLHELD_HOLD) {
		error("hf-client: Incorrect call held state %u:", val);
		return;
	}

	dev->call_held = val;

	if (dev->call_held == CIND_CALLHELD_NONE) {
		GSList *l;
		bool found_waiting = FALSE;

		for (l = dev->calls; l; l = l->next) {
			struct call *call = l->data;

			if (call->state != CALL_STATE_WAITING)
				continue;

			telephony_call_set_state(call,
					CALL_STATE_DISCONNECTED);
			found_waiting = TRUE;
			dev->calls = g_slist_remove(dev->calls, call);
			telephony_call_unregister_interface(call);
		}

		if (!found_waiting) {
			for (l = dev->calls; l; l = l->next) {
				struct call *call = l->data;

				if (call->state != CALL_STATE_HELD)
					continue;

				telephony_call_set_state(call,
						CALL_STATE_DISCONNECTED);
				dev->calls = g_slist_remove(dev->calls, call);
				telephony_call_unregister_interface(call);
			}
		}
	} else if (dev->call_held == CIND_CALLHELD_HOLD_AND_ACTIVE) {
		GSList *l;

		for (l = dev->calls; l; l = l->next) {
			struct call *call = l->data;

			if (call->state == CALL_STATE_ACTIVE)
				telephony_call_set_state(call,
							CALL_STATE_HELD);
			else if (call->state == CALL_STATE_HELD)
				telephony_call_set_state(call,
							CALL_STATE_ACTIVE);
		}
	} else if (dev->call_held == CIND_CALLHELD_HOLD) {
		GSList *l;

		for (l = dev->calls; l; l = l->next) {
			struct call *call = l->data;

			if (call->state == CALL_STATE_ACTIVE ||
					call->state == CALL_STATE_WAITING)
				telephony_call_set_state(call, CALL_STATE_HELD);
		}
	}
}

static void ciev_signal_cb(uint8_t val, void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (val > 5) {
		error("hf-client: Incorrect signal value %u:", val);
		return;
	}

	telephony_set_signal(dev->telephony, val);
}

static void ciev_roam_cb(uint8_t val, void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (val > 1) {
		error("hf-client: Incorrect roaming state %u:", val);
		return;
	}

	telephony_set_roaming(dev->telephony, val);
}

static void ciev_battchg_cb(uint8_t val, void *user_data)
{
	struct hfp_device *dev = user_data;

	DBG("");

	if (val > 5) {
		error("hf-client: Incorrect battery charge value %u:", val);
		return;
	}

	telephony_set_battchg(dev->telephony, val);
}

static void set_indicator_parameters(uint8_t index, const char *indicator,
	unsigned int min,
	unsigned int max,
	struct indicator *ag_ind)
{
	DBG("%s, %i", indicator, index);

	/* TODO: Verify min/max values ? */

	if (strcmp("service", indicator) == 0) {
		ag_ind[HFP_INDICATOR_SERVICE].index = index;
		ag_ind[HFP_INDICATOR_SERVICE].min = min;
		ag_ind[HFP_INDICATOR_SERVICE].max = max;
		ag_ind[HFP_INDICATOR_SERVICE].cb = ciev_service_cb;
		return;
	}

	if (strcmp("call", indicator) == 0) {
		ag_ind[HFP_INDICATOR_CALL].index = index;
		ag_ind[HFP_INDICATOR_CALL].min = min;
		ag_ind[HFP_INDICATOR_CALL].max = max;
		ag_ind[HFP_INDICATOR_CALL].cb = ciev_call_cb;
		return;
	}

	if (strcmp("callsetup", indicator) == 0) {
		ag_ind[HFP_INDICATOR_CALLSETUP].index = index;
		ag_ind[HFP_INDICATOR_CALLSETUP].min = min;
		ag_ind[HFP_INDICATOR_CALLSETUP].max = max;
		ag_ind[HFP_INDICATOR_CALLSETUP].cb = ciev_callsetup_cb;
		return;
	}

	if (strcmp("callheld", indicator) == 0) {
		ag_ind[HFP_INDICATOR_CALLHELD].index = index;
		ag_ind[HFP_INDICATOR_CALLHELD].min = min;
		ag_ind[HFP_INDICATOR_CALLHELD].max = max;
		ag_ind[HFP_INDICATOR_CALLHELD].cb = ciev_callheld_cb;
		return;
	}

	if (strcmp("signal", indicator) == 0) {
		ag_ind[HFP_INDICATOR_SIGNAL].index = index;
		ag_ind[HFP_INDICATOR_SIGNAL].min = min;
		ag_ind[HFP_INDICATOR_SIGNAL].max = max;
		ag_ind[HFP_INDICATOR_SIGNAL].cb = ciev_signal_cb;
		return;
	}

	if (strcmp("roam", indicator) == 0) {
		ag_ind[HFP_INDICATOR_ROAM].index = index;
		ag_ind[HFP_INDICATOR_ROAM].min = min;
		ag_ind[HFP_INDICATOR_ROAM].max = max;
		ag_ind[HFP_INDICATOR_ROAM].cb = ciev_roam_cb;
		return;
	}

	if (strcmp("battchg", indicator) == 0) {
		ag_ind[HFP_INDICATOR_BATTCHG].index = index;
		ag_ind[HFP_INDICATOR_BATTCHG].min = min;
		ag_ind[HFP_INDICATOR_BATTCHG].max = max;
		ag_ind[HFP_INDICATOR_BATTCHG].cb = ciev_battchg_cb;
		return;
	}

	error("hf-client: Unknown indicator: %s", indicator);
}

static void slc_cind_cb(struct hfp_context *context, void *user_data)
{
	struct hfp_device *dev = user_data;
	int index = 1;

	DBG("");

	while (hfp_context_has_next(context)) {
		char name[255];
		unsigned int min, max;

		/* e.g ("callsetup",(0-3)) */
		if (!hfp_context_open_container(context))
			break;

		if (!hfp_context_get_string(context, name, sizeof(name))) {
			error("hf-client: Could not get string");
			goto failed;
		}

		if (!hfp_context_open_container(context)) {
			error("hf-client: Could not open container");
			goto failed;
		}

		if (!hfp_context_get_range(context, &min, &max)) {
			if (!hfp_context_get_number(context, &min)) {
				error("hf-client: Could not get number");
				goto failed;
			}

			if (!hfp_context_get_number(context, &max)) {
				error("hf-client: Could not get number");
				goto failed;
			}
		}

		if (!hfp_context_close_container(context)) {
			error("hf-client: Could not close container");
			goto failed;
		}

		if (!hfp_context_close_container(context)) {
			error("hf-client: Could not close container");
			goto failed;
		}

		set_indicator_parameters(index, name, min, max, dev->ag_ind);
		index++;
	}

	return;

failed:
	error("hf-client: Error on CIND response");
	slc_error(dev);
}

static void slc_brsf_cb(struct hfp_context *context, void *user_data)
{
	unsigned int feat;
	struct hfp_device *dev = user_data;

	DBG("");

	if (hfp_context_get_number(context, &feat))
		dev->features = feat;
}

static void slc_brsf_resp(enum hfp_result result, enum hfp_error cme_err,
	void *user_data)
{
	struct hfp_device *dev = user_data;

	hfp_hf_unregister(dev->hf, "+BRSF");

	if (result != HFP_RESULT_OK) {
		error("BRSF error: %d", result);
		goto failed;
	}

	/* Continue with SLC creation */
	if (!hfp_hf_register(dev->hf, slc_cind_cb, "+CIND", dev, NULL)) {
		error("hf-client: Could not register for +CIND");
		goto failed;
	}

	if (!hfp_hf_send_command(dev->hf, slc_cind_resp, dev, "AT+CIND=?")) {
		error("hf-client: Could not send AT+CIND command");
		goto failed;
	}

	return;

failed:
	slc_error(dev);
}

static bool create_slc(struct hfp_device *dev)
{
	DBG("");

	if (!hfp_hf_register(dev->hf, slc_brsf_cb, "+BRSF", dev, NULL))
		return false;

	return hfp_hf_send_command(dev->hf, slc_brsf_resp, dev, "AT+BRSF=%u",
							dev->hfp_hf_features);
}

static void hfp_disconnect_watch(void *user_data)
{
	DBG("");

	device_destroy(user_data);
}

static void connect_cb(GIOChannel *chan, GError *err, gpointer user_data)
{
	struct hfp_device *dev = user_data;
	struct btd_service *service = telephony_get_service(dev->telephony);

	DBG("");

	if (err) {
		error("%s", err->message);
		goto failed;
	}

	dev->hf = hfp_hf_new(g_io_channel_unix_get_fd(chan));
	if (!dev->hf) {
		error("Could not create hfp io");
		goto failed;
	}

	g_io_channel_set_close_on_unref(chan, FALSE);

	hfp_hf_set_close_on_unref(dev->hf, true);
	hfp_hf_set_disconnect_handler(dev->hf, hfp_disconnect_watch,
					dev, NULL);

	if (!create_slc(dev)) {
		error("Could not start SLC creation");
		hfp_hf_disconnect(dev->hf);
		goto failed;
	}

	telephony_set_state(dev->telephony, SLC_CONNECTING);
	btd_service_connecting_complete(service, 0);

	return;

failed:
	g_io_channel_shutdown(chan, TRUE, NULL);
	device_destroy(dev);
}

static void hfp_dial_cb(enum hfp_result result, enum hfp_error cme_err,
							void *user_data)
{
	struct call *call = user_data;
	DBusMessage *msg = call->pending_msg;
	DBusMessage *reply;
	struct hfp_device *dev = telephony_get_profile_data(call->device);

	DBG("");

	call->pending_msg = NULL;

	if (result != HFP_RESULT_OK) {
		error("Dialing error: %d", result);
		reply = g_dbus_create_error(msg, ERROR_INTERFACE
					".Failed",
					"Dial command failed: %d", result);
		g_dbus_send_message(btd_get_dbus_connection(), reply);
		dbus_message_unref(msg);
		telephony_free_call(call);
		return;
	}

	if (telephony_call_register_interface(call)) {
		telephony_free_call(call);
		return;
	}

	dev->calls = g_slist_append(dev->calls, call);

	g_dbus_send_reply(btd_get_dbus_connection(), msg, DBUS_TYPE_INVALID);
	dbus_message_unref(msg);
}

static DBusMessage *hfp_dial(DBusConnection *conn, DBusMessage *msg,
				void *profile_data)
{
	struct hfp_device *dev = profile_data;
	const char *number;
	struct call *call;
	uint8_t idx = next_index(dev);

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &number,
					DBUS_TYPE_INVALID)) {
		return btd_error_invalid_args(msg);
	}

	call = telephony_new_call(dev->telephony, idx, CALL_STATE_DIALING,
					NULL);
	call->pending_msg = dbus_message_ref(msg);

	if (number != NULL && number[0] != '\0') {
		DBG("Dialing %s", number);

		call->line_id = g_strdup(number);

		if (!hfp_hf_send_command(dev->hf, hfp_dial_cb, call,
							"ATD%s;", number))
			goto failed;
	} else {
		DBG("Redialing");

		if (!hfp_hf_send_command(dev->hf, hfp_dial_cb, call,
							"AT+BLDN"))
			goto failed;
	}

	return NULL;

failed:
	telephony_free_call(call);
	return btd_error_failed(msg, "Dial command failed");
}

static DBusMessage *hfp_hangup_all(DBusConnection *conn, DBusMessage *msg,
				void *profile_data)
{
	struct hfp_device *dev = profile_data;
	bool found_active = FALSE;
	bool found_held = FALSE;
	GSList *l;

	DBG("");

	for (l = dev->calls; l; l = l->next) {
		struct call *call = l->data;

		switch (call->state) {
		case CALL_STATE_ACTIVE:
		case CALL_STATE_DIALING:
		case CALL_STATE_ALERTING:
		case CALL_STATE_INCOMING:
			found_active = TRUE;
			break;
		case CALL_STATE_HELD:
		case CALL_STATE_WAITING:
			found_held = TRUE;
			break;
		case CALL_STATE_DISCONNECTED:
			break;
		}
	}

	if (!found_active && !found_held)
		return btd_error_failed(msg, "No call to hang up");

	if (found_held) {
		if (!hfp_hf_send_command(dev->hf, cmd_complete_cb,
				found_active ? NULL : dbus_message_ref(msg),
				"AT+CHLD=0")) {
			warn("Failed to hangup held calls");
			goto failed;
		}
	}

	if (found_active) {
		if (!hfp_hf_send_command(dev->hf, cmd_complete_cb,
				dbus_message_ref(msg),
				"AT+CHUP")) {
			warn("Failed to hangup active calls");
			goto failed;
		}
	}

	return NULL;

failed:
	return btd_error_failed(msg, "Hang up all command failed");
}

static DBusMessage *hfp_hangup_active(DBusConnection *conn, DBusMessage *msg,
				void *profile_data)
{
	struct hfp_device *dev = profile_data;
	bool found_active = FALSE;
	GSList *l;

	DBG("");

	for (l = dev->calls; l; l = l->next) {
		struct call *call = l->data;

		switch (call->state) {
		case CALL_STATE_ACTIVE:
		case CALL_STATE_DIALING:
		case CALL_STATE_ALERTING:
		case CALL_STATE_INCOMING:
			found_active = TRUE;
			break;
		case CALL_STATE_HELD:
		case CALL_STATE_WAITING:
		case CALL_STATE_DISCONNECTED:
			break;
		}
	}

	if (!found_active)
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".InvalidState",
					"No active call to hang up");

	if (!hfp_hf_send_command(dev->hf, cmd_complete_cb,
			dbus_message_ref(msg),
			"AT+CHUP")) {
		warn("Failed to hangup active calls");
		return btd_error_failed(msg, "Hang up active command failed");
	}

	return NULL;
}

static DBusMessage *hfp_hangup_held(DBusConnection *conn, DBusMessage *msg,
				void *profile_data)
{
	struct hfp_device *dev = profile_data;
	bool found_held = FALSE;
	GSList *l;

	DBG("");

	if (!(dev->chld_features & CHLD_FEAT_REL))
		return btd_error_not_supported(msg);

	for (l = dev->calls; l; l = l->next) {
		struct call *call = l->data;

		switch (call->state) {
		case CALL_STATE_HELD:
		case CALL_STATE_WAITING:
			found_held = TRUE;
			break;
		case CALL_STATE_ACTIVE:
		case CALL_STATE_DIALING:
		case CALL_STATE_ALERTING:
		case CALL_STATE_INCOMING:
		case CALL_STATE_DISCONNECTED:
			break;
		}
	}

	if (!found_held)
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".InvalidState",
					"No held call to hang up");

	if (!hfp_hf_send_command(dev->hf, cmd_complete_cb,
			dbus_message_ref(msg),
			"AT+CHLD=0")) {
		warn("Failed to hangup held calls");
		return btd_error_failed(msg, "Hang up held command failed");
	}

	return NULL;
}

static DBusMessage *hfp_send_tones(DBusConnection *conn, DBusMessage *msg,
				void *profile_data)
{
	struct hfp_device *dev = profile_data;
	const char *tones;
	bool found_active = FALSE;
	GSList *l;

	DBG("");

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &tones,
					DBUS_TYPE_INVALID)) {
		return btd_error_invalid_args(msg);
	}

	for (l = dev->calls; l; l = l->next) {
		struct call *call = l->data;

		if (call->state == CALL_STATE_ACTIVE) {
			found_active = TRUE;
			break;
		}
	}

	if (!found_active)
		return g_dbus_create_error(msg, ERROR_INTERFACE
					".InvalidState",
					"No active call to send tones");

	if (!hfp_hf_send_command(dev->hf, cmd_complete_cb,
			dbus_message_ref(msg),
			"AT+VTS=%s", tones)) {
		warn("Failed to send tones: %s", tones);
		return btd_error_failed(msg, "Failed to send tones");
	}

	return NULL;
}

static DBusMessage *call_answer(DBusConnection *conn, DBusMessage *msg,
	void *call_data)
{
	struct call *call = call_data;
	struct hfp_device *dev = telephony_get_profile_data(call->device);

	DBG("");

	if (call->state != CALL_STATE_INCOMING)
		return btd_error_failed(msg, "Invalid state call");

	if (!hfp_hf_send_command(dev->hf, cmd_complete_cb,
			dbus_message_ref(msg), "ATA"))
		goto failed;

	return NULL;

failed:
	return btd_error_failed(msg, "Answer command failed");
}

struct telephony_callbacks hfp_callbacks = {
	.dial = hfp_dial,
	.hangup_all = hfp_hangup_all,
	.hangup_active = hfp_hangup_active,
	.hangup_held = hfp_hangup_held,
	.send_tones = hfp_send_tones,
	.call_answer = call_answer,
};

static int hfp_connect(struct btd_service *service)
{
	struct hfp_device *dev;
	struct btd_profile *p;
	const sdp_record_t *rec;
	sdp_list_t *list, *protos;
	sdp_profile_desc_t *desc;
	int channel;
	bdaddr_t src, dst;
	GError *err = NULL;

	DBG("");

	dev = btd_service_get_user_data(service);

	p = btd_service_get_profile(service);
	rec = btd_device_get_record(telephony_get_device(dev->telephony),
					p->remote_uuid);
	if (!rec)
		return -EIO;

	if (sdp_get_profile_descs(rec, &list) == 0) {
		desc = list->data;
		dev->version = desc->version;
	}
	sdp_list_free(list, free);

	if (sdp_get_access_protos(rec, &protos) < 0) {
		error("unable to get access protocols from record");
		return -EIO;
	}

	channel = sdp_get_proto_port(protos, RFCOMM_UUID);
	sdp_list_foreach(protos, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(protos, NULL);
	if (channel <= 0) {
		error("unable to get RFCOMM channel from record");
		return -EIO;
	}

	src = telephony_get_src(dev->telephony);
	dst = telephony_get_dst(dev->telephony);
	dev->io = bt_io_connect(connect_cb, dev,
		NULL, &err,
		BT_IO_OPT_SOURCE_BDADDR, &src,
		BT_IO_OPT_DEST_BDADDR, &dst,
		BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
		BT_IO_OPT_CHANNEL, channel,
		BT_IO_OPT_INVALID);
	if (dev->io == NULL) {
		error("unable to start connection");
		return -EIO;
	}

	return telephony_register_interface(dev->telephony);
}

static void remove_calls(gpointer data, gpointer user_data)
{
	struct call *call = data;
	struct hfp_device *dev = user_data;

	dev->calls = g_slist_remove(dev->calls, call);
	telephony_call_unregister_interface(call);
}

static int hfp_disconnect(struct btd_service *service)
{
	struct hfp_device *dev;

	DBG("");

	dev = btd_service_get_user_data(service);

	g_slist_foreach(dev->calls, remove_calls, dev);

	if (dev->hf)
		hfp_hf_disconnect(dev->hf);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static int hfp_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	struct hfp_device *dev;

	DBG("%s", path);

	dev = g_new0(struct hfp_device, 1);
	if (!dev)
		return -EINVAL;

	dev->telephony = telephony_new(service, dev, &hfp_callbacks);
	dev->hfp_hf_features = HFP_HF_FEATURES;
	btd_service_set_user_data(service, dev);

	return 0;
}

static void hfp_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	const char *path = device_get_path(device);
	struct hfp_device *dev;

	DBG("%s", path);

	dev = btd_service_get_user_data(service);

	telephony_free(dev->telephony);
	g_free(dev);
}

static sdp_record_t *hfp_record(void)
{
	sdp_record_t *record;
	uuid_t root_uuid, hfphf, genericaudio, l2cap, rfcomm;
	sdp_list_t *root, *svclass_id, *aproto, *proto[2], *apseq, *pfseq;
	sdp_data_t *channel, *features;
	uint8_t hf_channel = HFP_HF_DEFAULT_CHANNEL;
	sdp_profile_desc_t profile;
	uint16_t feat = HFP_HF_SDP_FEATURES;

	record = sdp_record_alloc();
	if (!record) {
		error("Unable to allocate new service record");
		return NULL;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&hfphf, HANDSFREE_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &hfphf);
	sdp_uuid16_create(&genericaudio, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &genericaudio);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm);
	channel = sdp_data_alloc(SDP_UINT8, &hf_channel);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = HFP_HF_VERSION;
	pfseq = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_set_info_attr(record, "Hands-Free unit", NULL, NULL);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	free(channel);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(svclass_id, NULL);
	sdp_list_free(root, NULL);

	return record;
}

static void server_connect_cb(GIOChannel *chan, GError *err, gpointer data)
{
	uint8_t channel;
	bdaddr_t src, dst;
	char address[18];
	GError *gerr = NULL;
	struct btd_device *device;
	struct btd_service *service;
	struct hfp_device *dev;
	const sdp_record_t *rec;
	sdp_list_t *list;
	sdp_profile_desc_t *desc;

	if (err) {
		error("%s", err->message);
		return;
	}

	bt_io_get(chan, &gerr,
			BT_IO_OPT_SOURCE_BDADDR, &src,
			BT_IO_OPT_DEST_BDADDR, &dst,
			BT_IO_OPT_CHANNEL, &channel,
			BT_IO_OPT_INVALID);
	if (gerr) {
		error("%s", gerr->message);
		g_error_free(gerr);
		g_io_channel_shutdown(chan, TRUE, NULL);
		return;
	}

	ba2str(&dst, address);
	DBG("Incoming connection from %s on Channel %d", address, channel);

	device = btd_adapter_find_device(adapter_find(&src), &dst,
							BDADDR_BREDR);
	if (!device)
		return;

	service = btd_device_get_service(device, HFP_AG_UUID);
	if (!service)
		return;

	dev = btd_service_get_user_data(service);

	rec = btd_device_get_record(telephony_get_device(dev->telephony),
					HFP_AG_UUID);
	if (!rec)
		return;

	if (sdp_get_profile_descs(rec, &list) == 0) {
		desc = list->data;
		dev->version = desc->version;
	}
	sdp_list_free(list, free);

	telephony_register_interface(dev->telephony);

	connect_cb(chan, err, dev);
}

static GIOChannel *server_socket(struct btd_adapter *adapter)
{
	GIOChannel *io;
	GError *err = NULL;

	io = bt_io_listen(server_connect_cb, NULL, NULL, NULL, &err,
		BT_IO_OPT_SOURCE_BDADDR,
		btd_adapter_get_address(adapter),
		BT_IO_OPT_CHANNEL, HFP_HF_DEFAULT_CHANNEL,
		BT_IO_OPT_SEC_LEVEL, BT_IO_SEC_MEDIUM,
		BT_IO_OPT_INVALID);
	if (!io) {
		error("%s", err->message);
		g_error_free(err);
	}

	return io;
}

static int hfp_adapter_probe(struct btd_profile *p,
				struct btd_adapter *adapter)
{
	struct hfp_server *server;
	sdp_record_t *record;

	DBG("path %s", adapter_get_path(adapter));

	server = find_server(servers, adapter);
	if (server != NULL)
		goto done;

	server = g_new0(struct hfp_server, 1);

	server->io = server_socket(adapter);
	if (!server->io) {
		g_free(server);
		return -1;
	}

done:
	record = hfp_record();
	if (!record) {
		error("Unable to allocate new service record");
		g_free(server);
		return -1;
	}

	if (adapter_service_add(adapter, record) < 0) {
		error("Unable to register HFP HF service record");
		sdp_record_free(record);
		g_free(server);
		return -1;
	}
	server->record_id = record->handle;

	server->adapter = btd_adapter_ref(adapter);

	servers = g_slist_append(servers, server);

	return 0;
}

static void hfp_adapter_remove(struct btd_profile *p,
				struct btd_adapter *adapter)
{
	struct hfp_server *server;

	DBG("path %s", adapter_get_path(adapter));

	server = find_server(servers, adapter);
	if (!server)
		return;

	if (server->io) {
		g_io_channel_shutdown(server->io, TRUE, NULL);
		g_io_channel_unref(server->io);
	}

	if (server->record_id != 0) {
		adapter_service_remove(adapter, server->record_id);
		server->record_id = 0;
	}

	servers = g_slist_remove(servers, server);

	btd_adapter_unref(server->adapter);
	g_free(server);
}

static struct btd_profile hfp_hf_profile = {
	.name		= "hfp",
	.priority	= BTD_PROFILE_PRIORITY_MEDIUM,

	.remote_uuid	= HFP_AG_UUID,
	.device_probe	= hfp_probe,
	.device_remove	= hfp_remove,

	.auto_connect	= true,
	.connect	= hfp_connect,
	.disconnect	= hfp_disconnect,

	.adapter_probe  = hfp_adapter_probe,
	.adapter_remove = hfp_adapter_remove,

	.experimental	= true,
};

static int hfp_init(void)
{
	btd_profile_register(&hfp_hf_profile);

	return 0;
}

static void hfp_exit(void)
{
	btd_profile_unregister(&hfp_hf_profile);
}

BLUETOOTH_PLUGIN_DEFINE(hfp, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
		hfp_init, hfp_exit)
