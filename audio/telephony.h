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

struct indicator {
	const char *desc;
	const char *range;
	int val;
};

int telephony_event_reporting_req(int ind);

int telephony_event_ind(int index);

int telephony_response_and_hold_req(int rh);

int telephony_response_and_hold_ind(int rh);

int telephony_last_dialed_number_req(void);

int telephony_terminate_call_req(void);

int telephony_answer_call_req(void);

int telephony_dial_number_req(const char *number);

int telephony_calling_started_ind(const char *number);

int telephony_calling_stopped_ind(void);

int telephony_ready_ind(uint32_t features, const struct indicator *indicators,
			int rh);

int telephony_transmit_dtmf_req(char tone);

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
