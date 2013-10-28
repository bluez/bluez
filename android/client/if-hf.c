/*
 * Copyright (C) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "if-main.h"

const bthf_interface_t *if_hf = NULL;

SINTMAP(bthf_at_response_t, -1, "(unknown)")
	DELEMENT(BTHF_AT_RESPONSE_ERROR),
	DELEMENT(BTHF_AT_RESPONSE_OK),
ENDMAP

SINTMAP(bthf_connection_state_t, -1, "(unknown)")
	DELEMENT(BTHF_CONNECTION_STATE_DISCONNECTED),
	DELEMENT(BTHF_CONNECTION_STATE_CONNECTING),
	DELEMENT(BTHF_CONNECTION_STATE_CONNECTED),
	DELEMENT(BTHF_CONNECTION_STATE_SLC_CONNECTED),
	DELEMENT(BTHF_CONNECTION_STATE_DISCONNECTING),
ENDMAP

SINTMAP(bthf_audio_state_t, -1, "(unknown)")
	DELEMENT(BTHF_AUDIO_STATE_DISCONNECTED),
	DELEMENT(BTHF_AUDIO_STATE_CONNECTING),
	DELEMENT(BTHF_AUDIO_STATE_CONNECTED),
	DELEMENT(BTHF_AUDIO_STATE_DISCONNECTING),
ENDMAP

SINTMAP(bthf_vr_state_t, -1, "(unknown)")
	DELEMENT(BTHF_VR_STATE_STOPPED),
	DELEMENT(BTHF_VR_STATE_STARTED),
ENDMAP

SINTMAP(bthf_volume_type_t, -1, "(unknown)")
	DELEMENT(BTHF_VOLUME_TYPE_SPK),
	DELEMENT(BTHF_VOLUME_TYPE_MIC),
ENDMAP

SINTMAP(bthf_nrec_t, -1, "(unknown)")
	DELEMENT(BTHF_NREC_STOP),
	DELEMENT(BTHF_NREC_START),
ENDMAP

SINTMAP(bthf_chld_type_t, -1, "(unknown)")
	DELEMENT(BTHF_CHLD_TYPE_RELEASEHELD),
	DELEMENT(BTHF_CHLD_TYPE_RELEASEACTIVE_ACCEPTHELD),
	DELEMENT(BTHF_CHLD_TYPE_HOLDACTIVE_ACCEPTHELD),
	DELEMENT(BTHF_CHLD_TYPE_ADDHELDTOCONF),
ENDMAP

/* Network Status */
SINTMAP(bthf_network_state_t, -1, "(unknown)")
	DELEMENT(BTHF_NETWORK_STATE_NOT_AVAILABLE),
	DELEMENT(BTHF_NETWORK_STATE_AVAILABLE),
ENDMAP

/* Service type */
SINTMAP(bthf_service_type_t, -1, "(unknown)")
	DELEMENT(BTHF_SERVICE_TYPE_HOME),
	DELEMENT(BTHF_SERVICE_TYPE_ROAMING),
ENDMAP

SINTMAP(bthf_call_state_t, -1, "(unknown)")
	DELEMENT(BTHF_CALL_STATE_ACTIVE),
	DELEMENT(BTHF_CALL_STATE_HELD),
	DELEMENT(BTHF_CALL_STATE_DIALING),
	DELEMENT(BTHF_CALL_STATE_ALERTING),
	DELEMENT(BTHF_CALL_STATE_INCOMING),
	DELEMENT(BTHF_CALL_STATE_WAITING),
	DELEMENT(BTHF_CALL_STATE_IDLE),
ENDMAP

SINTMAP(bthf_call_direction_t, -1, "(unknown)")
	DELEMENT(BTHF_CALL_DIRECTION_OUTGOING),
	DELEMENT(BTHF_CALL_DIRECTION_INCOMING),
ENDMAP

SINTMAP(bthf_call_mode_t, -1, "(unknown)")
	DELEMENT(BTHF_CALL_TYPE_VOICE),
	DELEMENT(BTHF_CALL_TYPE_DATA),
	DELEMENT(BTHF_CALL_TYPE_FAX),
ENDMAP

SINTMAP(bthf_call_mpty_type_t, -1, "(unknown)")
	DELEMENT(BTHF_CALL_MPTY_TYPE_SINGLE),
	DELEMENT(BTHF_CALL_MPTY_TYPE_MULTI),
ENDMAP

SINTMAP(bthf_call_addrtype_t, -1, "(unknown)")
	DELEMENT(BTHF_CALL_ADDRTYPE_UNKNOWN),
	DELEMENT(BTHF_CALL_ADDRTYPE_INTERNATIONAL),
ENDMAP

/* Callbacks */

static char last_addr[MAX_ADDR_STR_LEN];

/*
 * Callback for connection state change.
 * state will have one of the values from BtHfConnectionState
 */
static void connection_state_cb(bthf_connection_state_t state,
							bt_bdaddr_t *bd_addr)
{
	haltest_info("%s: state=%s bd_addr=%s\n", __func__,
					bthf_connection_state_t2str(state),
					bt_bdaddr_t2str(bd_addr, last_addr));
}

/*
 * Callback for audio connection state change.
 * state will have one of the values from BtHfAudioState
 */
static void audio_state_cb(bthf_audio_state_t state, bt_bdaddr_t *bd_addr)
{
	haltest_info("%s: state=%s bd_addr=%s\n", __func__,
					bthf_audio_state_t2str(state),
					bt_bdaddr_t2str(bd_addr, last_addr));
}

/*
 * Callback for VR connection state change.
 * state will have one of the values from BtHfVRState
 */
static void vr_cmd_cb(bthf_vr_state_t state)
{
	haltest_info("%s: state=%s\n", __func__, bthf_vr_state_t2str(state));
}

/* Callback for answer incoming call (ATA) */
static void answer_call_cmd_cb(void)
{
	haltest_info("%s\n", __func__);
}

/* Callback for disconnect call (AT+CHUP) */
static void hangup_call_cmd_cb(void)
{
	haltest_info("%s\n", __func__);
}

/*
 * Callback for disconnect call (AT+CHUP)
 * type will denote Speaker/Mic gain (BtHfVolumeControl).
 */
static void volume_cmd_cb(bthf_volume_type_t type, int volume)
{
	haltest_info("%s: type=%s volume=%d\n", __func__,
					bthf_volume_type_t2str(type), volume);
}

/*
 * Callback for dialing an outgoing call
 * If number is NULL, redial
 */
static void dial_call_cmd_cb(char *number)
{
	haltest_info("%s: number=%s\n", __func__, number);
}

/*
 * Callback for sending DTMF tones
 * tone contains the dtmf character to be sent
 */
static void dtmf_cmd_cb(char tone)
{
	haltest_info("%s: tone=%d\n", __func__, tone);
}

/*
 * Callback for enabling/disabling noise reduction/echo cancellation
 * value will be 1 to enable, 0 to disable
 */
static void nrec_cmd_cb(bthf_nrec_t nrec)
{
	haltest_info("%s: nrec=%s\n", __func__, bthf_nrec_t2str(nrec));
}

/*
 * Callback for call hold handling (AT+CHLD)
 * value will contain the call hold command (0, 1, 2, 3)
 */
static void chld_cmd_cb(bthf_chld_type_t chld)
{
	haltest_info("%s: chld=%s\n", __func__, bthf_chld_type_t2str(chld));
}

/* Callback for CNUM (subscriber number) */
static void cnum_cmd_cb(void)
{
	haltest_info("%s\n", __func__);
}

/* Callback for indicators (CIND) */
static void cind_cmd_cb(void)
{
	haltest_info("%s\n", __func__);
}

/* Callback for operator selection (COPS) */
static void cops_cmd_cb(void)
{
	haltest_info("%s\n", __func__);
}

/* Callback for call list (AT+CLCC) */
static void clcc_cmd_cb(void)
{
	haltest_info("%s\n", __func__);
}

/*
 * Callback for unknown AT command recd from HF
 * at_string will contain the unparsed AT string
 */
static void unknown_at_cmd_cb(char *at_string)
{
	haltest_info("%s: at_string=%s\n", __func__, at_string);
}

/* Callback for keypressed (HSP) event. */
static void key_pressed_cmd_cb(void)
{
	haltest_info("%s\n", __func__);
}

static bthf_callbacks_t hf_cbacks = {

	.size = sizeof(hf_cbacks),
	.connection_state_cb = connection_state_cb,
	.audio_state_cb = audio_state_cb,
	.vr_cmd_cb = vr_cmd_cb,
	.answer_call_cmd_cb = answer_call_cmd_cb,
	.hangup_call_cmd_cb = hangup_call_cmd_cb,
	.volume_cmd_cb = volume_cmd_cb,
	.dial_call_cmd_cb = dial_call_cmd_cb,
	.dtmf_cmd_cb = dtmf_cmd_cb,
	.nrec_cmd_cb = nrec_cmd_cb,
	.chld_cmd_cb = chld_cmd_cb,
	.cnum_cmd_cb = cnum_cmd_cb,
	.cind_cmd_cb = cind_cmd_cb,
	.cops_cmd_cb = cops_cmd_cb,
	.clcc_cmd_cb = clcc_cmd_cb,
	.unknown_at_cmd_cb = unknown_at_cmd_cb,
	.key_pressed_cmd_cb = key_pressed_cmd_cb,
};

/* init */

static void init_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_hf);

	EXEC(if_hf->init, &hf_cbacks);
}

/* connect */


static void connect_p(int argc, const char **argv)
{
}

/* disconnect */

static void disconnect_p(int argc, const char **argv)
{
}

/* create an audio connection */

static void connect_audio_p(int argc, const char **argv)
{
}

/* close the audio connection */

static void disconnect_audio_p(int argc, const char **argv)
{
}

/* start voice recognition */

static void start_voice_recognition_p(int argc, const char **argv)
{
}

/* stop voice recognition */

static void stop_voice_recognition_p(int argc, const char **argv)
{
}

/* volume control */

static void volume_control_p(int argc, const char **argv)
{
}

/* Combined device status change notification */

static void device_status_notification_p(int argc, const char **argv)
{
}

/* Response for COPS command */

static void cops_response_p(int argc, const char **argv)
{
}

/* Response for CIND command */

static void cind_response_p(int argc, const char **argv)
{
}

/* Pre-formatted AT response, typically in response to unknown AT cmd */

static void formatted_at_response_p(int argc, const char **argv)
{
}

/* at_response */

static void at_response_p(int argc, const char **argv)
{
}

/* response for CLCC command */

static void clcc_response_p(int argc, const char **argv)
{
}

/* phone state change */
static void phone_state_change_p(int argc, const char **argv)
{
}

/* cleanup */

static void cleanup_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_hf);

	EXECV(if_hf->cleanup);
	if_hf = NULL;
}

static struct method methods[] = {
	STD_METHOD(init),
	STD_METHODH(connect, "<addr>"),
	STD_METHODH(disconnect, "<addr>"),
	STD_METHODH(connect_audio, "<addr>"),
	STD_METHODH(disconnect_audio, "<addr>"),
	STD_METHOD(start_voice_recognition),
	STD_METHOD(stop_voice_recognition),
	STD_METHODH(volume_control, "<vol_type> <volume>"),
	STD_METHODH(device_status_notification,
			"<ntk_state> <svt_type> <signal> <batt_chg>"),
	STD_METHODH(cops_response, "<cops string>"),
	STD_METHODH(cind_response,
			"<svc> <num_active> <num_held> <setup_state> <signal> <roam> <batt_chg>"),
	STD_METHODH(formatted_at_response, "<at_response>"),
	STD_METHODH(at_response, "<response_code> [<error_code>]"),
	STD_METHODH(clcc_response,
			"<index> <direction> <state> <mode> <mpty> <number> <type>"),
	STD_METHODH(phone_state_change,
			"<num_active> <num_held> <setup_state> <number> <type>"),
	STD_METHOD(cleanup),
	END_METHOD
};

const struct interface hf_if = {
	.name = "handsfree",
	.methods = methods
};
