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

#include <stdint.h>
#include <errno.h>
#include <glib.h>

/* HFP feature bits */
#define AG_FEATURE_THREE_WAY_CALLING		0x0001
#define AG_FEATURE_EC_ANDOR_NR			0x0002
#define AG_FEATURE_VOICE_RECOGNITION		0x0004
#define AG_FEATURE_INBAND_RINGTONE		0x0008
#define AG_FEATURE_ATTACH_NUMBER_TO_VOICETAG	0x0010
#define AG_FEATURE_REJECT_A_CALL		0x0020
#define AG_FEATURE_ENHANCED_CALL_STATUS		0x0040
#define AG_FEATURE_ENHANCED_CALL_CONTROL	0x0080
#define AG_FEATURE_EXTENDED_ERROR_RESULT_CODES	0x0100

#define HF_FEATURE_EC_ANDOR_NR			0x0001
#define HF_FEATURE_CALL_WAITING_AND_3WAY	0x0002
#define HF_FEATURE_CLI_PRESENTATION		0x0004
#define HF_FEATURE_VOICE_RECOGNITION		0x0008
#define HF_FEATURE_REMOTE_VOLUME_CONTROL	0x0010
#define HF_FEATURE_ENHANCED_CALL_STATUS		0x0020
#define HF_FEATURE_ENHANCED_CALL_CONTROL	0x0040

/* Indicator event values */
#define EV_SERVICE_NONE			0
#define EV_SERVICE_PRESENT		1

#define EV_CALL_INACTIVE		0
#define EV_CALL_ACTIVE			1

#define EV_CALLSETUP_INACTIVE		0
#define EV_CALLSETUP_INCOMING		1
#define EV_CALLSETUP_OUTGOING		2
#define EV_CALLSETUP_ALERTING		3

#define EV_CALLHELD_NONE		0
#define EV_CALLHELD_MULTIPLE		1
#define EV_CALLHELD_ON_HOLD		2

#define EV_ROAM_INACTIVE		0
#define EV_ROAM_ACTIVE			1

/* Call parameters */
#define CALL_DIR_OUTGOING		0
#define CALL_DIR_INCOMING		1

#define CALL_STATUS_ACTIVE		0
#define CALL_STATUS_HELD		1
#define CALL_STATUS_DIALING		2
#define CALL_STATUS_ALERTING		3
#define CALL_STATUS_INCOMING		4
#define CALL_STATUS_WAITING		5

#define CALL_MODE_VOICE			0
#define CALL_MODE_DATA			1
#define CALL_MODE_FAX			2

#define CALL_MULTIPARTY_NO		0
#define CALL_MULTIPARTY_YES		1

/* Subscriber number parameters */
#define SUBSCRIBER_SERVICE_VOICE	4
#define SUBSCRIBER_SERVICE_FAX		5

/* Operator selection mode values */
#define OPERATOR_MODE_AUTO		0
#define OPERATOR_MODE_MANUAL		1
#define OPERATOR_MODE_DEREGISTER	2
#define OPERATOR_MODE_MANUAL_AUTO	4

/* Some common number types */
#define NUMBER_TYPE_UNKNOWN		128
#define NUMBER_TYPE_TELEPHONY		129
#define NUMBER_TYPE_INTERNATIONAL	145
#define NUMBER_TYPE_NATIONAL		161
#define NUMBER_TYPE_VOIP		255

/* Extended Audio Gateway Error Result Codes */
typedef enum {
	CME_ERROR_NONE			= -1,
	CME_ERROR_AG_FAILURE		= 0,
	CME_ERROR_NO_PHONE_CONNECTION	= 1,
	CME_ERROR_NOT_ALLOWED		= 3,
	CME_ERROR_NOT_SUPPORTED		= 4,
	CME_ERROR_PH_SIM_PIN_REQUIRED	= 5,
	CME_ERROR_SIM_NOT_INSERTED	= 10,
	CME_ERROR_SIM_PIN_REQUIRED	= 11,
	CME_ERROR_SIM_PUK_REQUIRED	= 12,
	CME_ERROR_SIM_FAILURE		= 13,
	CME_ERROR_SIM_BUSY		= 14,
	CME_ERROR_INCORRECT_PASSWORD	= 16,
	CME_ERROR_SIM_PIN2_REQUIRED	= 17,
	CME_ERROR_SIM_PUK2_REQUIRED	= 18,
	CME_ERROR_MEMORY_FULL		= 20,
	CME_ERROR_INVALID_INDEX		= 21,
	CME_ERROR_MEMORY_FAILURE	= 23,
	CME_ERROR_TEXT_STRING_TOO_LONG	= 24,
	CME_ERROR_INVALID_TEXT_STRING	= 25,
	CME_ERROR_DIAL_STRING_TOO_LONG	= 26,
	CME_ERROR_INVALID_DIAL_STRING	= 27,
	CME_ERROR_NO_NETWORK_SERVICE	= 30,
	CME_ERROR_NETWORK_TIMEOUT	= 31,
	CME_ERROR_NETWORK_NOT_ALLOWED	= 32,
} cme_error_t;

struct indicator {
	const char *desc;
	const char *range;
	int val;
	gboolean ignore_redundant;
};

/* Notify telephony-*.c of connected/disconnected devices. Implemented by
 * telephony-*.c
 */
void telephony_device_connected(void *telephony_device);
void telephony_device_disconnected(void *telephony_device);

/* HF requests (sent by the handsfree device). These are implemented by
 * telephony-*.c
 */
void telephony_event_reporting_req(void *telephony_device, int ind);
void telephony_response_and_hold_req(void *telephony_device, int rh);
void telephony_last_dialed_number_req(void *telephony_device);
void telephony_terminate_call_req(void *telephony_device);
void telephony_answer_call_req(void *telephony_device);
void telephony_dial_number_req(void *telephony_device, const char *number);
void telephony_transmit_dtmf_req(void *telephony_device, char tone);
void telephony_subscriber_number_req(void *telephony_device);
void telephony_list_current_calls_req(void *telephony_device);
void telephony_operator_selection_req(void *telephony_device);
void telephony_call_hold_req(void *telephony_device, const char *cmd);
void telephony_nr_and_ec_req(void *telephony_device, gboolean enable);
void telephony_voice_dial_req(void *telephony_device, gboolean enable);
void telephony_key_press_req(void *telephony_device, const char *keys);

/* AG responses to HF requests. These are implemented by headset.c */
int telephony_event_reporting_rsp(void *telephony_device, cme_error_t err);
int telephony_response_and_hold_rsp(void *telephony_device, cme_error_t err);
int telephony_last_dialed_number_rsp(void *telephony_device, cme_error_t err);
int telephony_terminate_call_rsp(void *telephony_device, cme_error_t err);
int telephony_answer_call_rsp(void *telephony_device, cme_error_t err);
int telephony_dial_number_rsp(void *telephony_device, cme_error_t err);
int telephony_transmit_dtmf_rsp(void *telephony_device, cme_error_t err);
int telephony_subscriber_number_rsp(void *telephony_device, cme_error_t err);
int telephony_list_current_calls_rsp(void *telephony_device, cme_error_t err);
int telephony_operator_selection_rsp(void *telephony_device, cme_error_t err);
int telephony_call_hold_rsp(void *telephony_device, cme_error_t err);
int telephony_nr_and_ec_rsp(void *telephony_device, cme_error_t err);
int telephony_voice_dial_rsp(void *telephony_device, cme_error_t err);
int telephony_key_press_rsp(void *telephony_device, cme_error_t err);

/* Event indications by AG. These are implemented by headset.c */
int telephony_event_ind(int index);
int telephony_response_and_hold_ind(int rh);
int telephony_incoming_call_ind(const char *number, int type);
int telephony_calling_stopped_ind(void);
int telephony_ready_ind(uint32_t features, const struct indicator *indicators,
			int rh, const char *chld);
int telephony_list_current_call_ind(int idx, int dir, int status, int mode,
					int mprty, const char *number,
					int type);
int telephony_subscriber_number_ind(const char *number, int type,
					int service);
int telephony_call_waiting_ind(const char *number, int type);
int telephony_operator_selection_ind(int mode, const char *oper);

/* Helper function for quick indicator updates */
static inline int telephony_update_indicator(struct indicator *indicators,
						const char *desc,
						int new_val)
{
	int i;
	struct indicator *ind = NULL;

	for (i = 0; indicators[i].desc != NULL; i++) {
		if (g_str_equal(indicators[i].desc, desc)) {
			ind = &indicators[i];
			break;
		}
	}

	if (!ind)
		return -ENOENT;

	DBG("Telephony indicator \"%s\" %d->%d", desc, ind->val, new_val);

	if (ind->ignore_redundant && ind->val == new_val) {
		DBG("Ignoring no-change indication");
		return 0;
	}

	ind->val = new_val;

	return telephony_event_ind(i);
}

static inline int telephony_get_indicator(const struct indicator *indicators,
						const char *desc)
{
	int i;

	for (i = 0; indicators[i].desc != NULL; i++) {
		if (g_str_equal(indicators[i].desc, desc))
			return indicators[i].val;
	}

	return -ENOENT;
}

int telephony_init(void);
void telephony_exit(void);
