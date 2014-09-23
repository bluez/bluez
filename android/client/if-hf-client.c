/*
 * Copyright (C) 2014 Intel Corporation
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
#include "../hal-utils.h"

const bthf_client_interface_t *if_hf_client = NULL;

static char last_addr[MAX_ADDR_STR_LEN];

SINTMAP(bthf_client_connection_state_t, -1, "(unknown)")
	DELEMENT(BTHF_CLIENT_CONNECTION_STATE_DISCONNECTED),
	DELEMENT(BTHF_CLIENT_CONNECTION_STATE_CONNECTING),
	DELEMENT(BTHF_CLIENT_CONNECTION_STATE_CONNECTED),
	DELEMENT(BTHF_CLIENT_CONNECTION_STATE_SLC_CONNECTED),
	DELEMENT(BTHF_CLIENT_CONNECTION_STATE_DISCONNECTING),
ENDMAP

/* Callbacks */

static char features_str[512];

static const char *pear_features_t2str(int feat)
{
	memset(features_str, 0, sizeof(features_str));

	sprintf(features_str, "BTHF_CLIENT_PEER_FEAT_3WAY: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_ECNR: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_VREC: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_INBAND: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_VTAG: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_REJECT: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_ECS: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_ECC: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_EXTERR: %s,\n"
			"BTHF_CLIENT_PEER_FEAT_CODEC: %s,\n",
			feat & BTHF_CLIENT_PEER_FEAT_3WAY ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_ECNR ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_VREC ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_INBAND ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_VTAG ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_REJECT ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_ECS ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_ECC ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_EXTERR ? "True" : "False",
			feat & BTHF_CLIENT_PEER_FEAT_CODEC ? "True" : "False");

	return features_str;
}

static const char *chld_features_t2str(int feat)
{
	memset(features_str, 0, sizeof(features_str));

	sprintf(features_str,
		"BTHF_CLIENT_CHLD_FEAT_REL: %s,\n"
		"BTHF_CLIENT_CHLD_FEAT_REL_ACC: %s,\n"
		"BTHF_CLIENT_CHLD_FEAT_REL_X: %s,\n"
		"BTHF_CLIENT_CHLD_FEAT_HOLD_ACC: %s,\n"
		"BTHF_CLIENT_CHLD_FEAT_PRIV_X: %s,\n"
		"BTHF_CLIENT_CHLD_FEAT_MERGE: %s,\n"
		"BTHF_CLIENT_CHLD_FEAT_MERGE_DETACH: %s,\n",
		feat & BTHF_CLIENT_CHLD_FEAT_REL ? "True" : "False",
		feat & BTHF_CLIENT_CHLD_FEAT_REL_ACC ? "True" : "False",
		feat & BTHF_CLIENT_CHLD_FEAT_REL_X ? "True" : "False",
		feat & BTHF_CLIENT_CHLD_FEAT_HOLD_ACC ? "True" : "False",
		feat & BTHF_CLIENT_CHLD_FEAT_PRIV_X ? "True" : "False",
		feat & BTHF_CLIENT_CHLD_FEAT_MERGE ? "True" : "False",
		feat & BTHF_CLIENT_CHLD_FEAT_MERGE_DETACH ? "True" : "False");

	return features_str;
}

/* Callback for connection state change. */
static void hf_client_connection_state_callback(
					bthf_client_connection_state_t state,
					unsigned int peer_feat,
					unsigned int chld_feat,
					bt_bdaddr_t *bd_addr)
{
	haltest_info("%s: state=%s bd_addr=%s\n", __func__,
				bthf_client_connection_state_t2str(state),
				bt_bdaddr_t2str(bd_addr, last_addr));
	haltest_info("\tpeer_features%s\n", pear_features_t2str(peer_feat));
	haltest_info("\tchld_feat=%s\n", chld_features_t2str(chld_feat));
}

/* Callback for audio connection state change. */
static void hf_client_audio_state_callback(bthf_client_audio_state_t state,
							bt_bdaddr_t *bd_addr)
{
	haltest_info("%s\n", __func__);
}

/* Callback for VR connection state change. */
static void hf_client_vr_cmd_callback(bthf_client_vr_state_t state)
{
	haltest_info("%s\n", __func__);
}

/* Callback for network state change */
static void hf_client_network_state_callback(bthf_client_network_state_t state)
{
	haltest_info("%s\n", __func__);
}

/* Callback for network roaming status change */
static void hf_client_network_roaming_callback(bthf_client_service_type_t type)
{
	haltest_info("%s\n", __func__);
}

/* Callback for signal strength indication */
static void hf_client_network_signal_callback(int signal_strength)
{
	haltest_info("%s\n", __func__);
}

/* Callback for battery level indication */
static void hf_client_battery_level_callback(int battery_level)
{
	haltest_info("%s\n", __func__);
}

/* Callback for current operator name */
static void hf_client_current_operator_callback(const char *name)
{
	haltest_info("%s\n", __func__);
}

/* Callback for call indicator */
static void hf_client_call_callback(bthf_client_call_t call)
{
	haltest_info("%s\n", __func__);
}

/* Callback for callsetup indicator */
static void hf_client_callsetup_callback(bthf_client_callsetup_t callsetup)
{
	haltest_info("%s\n", __func__);
}

/* Callback for callheld indicator */
static void hf_client_callheld_callback(bthf_client_callheld_t callheld)
{
	haltest_info("%s\n", __func__);
}

/* Callback for response and hold */
static void hf_client_resp_and_hold_callback(
				bthf_client_resp_and_hold_t resp_and_hold)
{
	haltest_info("%s\n", __func__);
}

/* Callback for Calling Line Identification notification */
static void hf_client_clip_callback(const char *number)
{
	haltest_info("%s\n", __func__);
}

/* Callback for Call Waiting notification */
static void hf_client_call_waiting_callback(const char *number)
{
	haltest_info("%s\n", __func__);
}

/* Callback for listing current calls. Can be called multiple time. */
static void hf_client_current_calls_callback(int index,
					bthf_client_call_direction_t dir,
					bthf_client_call_state_t state,
					bthf_client_call_mpty_type_t mpty,
					const char *number)
{
	haltest_info("%s\n", __func__);
}

/* Callback for audio volume change */
static void hf_client_volume_change_callback(bthf_client_volume_type_t type,
								int volume)
{
	haltest_info("%s\n", __func__);
}

/* Callback for command complete event */
static void hf_client_cmd_complete_callback(bthf_client_cmd_complete_t type,
									int cme)
{
	haltest_info("%s\n", __func__);
}

/* Callback for subscriber information */
static void hf_client_subscriber_info_callback(const char *name,
				bthf_client_subscriber_service_type_t type)
{
	haltest_info("%s\n", __func__);
}

/* Callback for in-band ring tone settings */
static void hf_client_in_band_ring_tone_callback(
				bthf_client_in_band_ring_state_t state)
{
	haltest_info("%s\n", __func__);
}

/* Callback for requested number from AG */
static void hf_client_last_voice_tag_number_callback(const char *number)
{
	haltest_info("%s\n", __func__);
}

/* Callback for sending ring indication to app */
static void hf_client_ring_indication_callback(void)
{
	haltest_info("%s\n", __func__);
}

static bthf_client_callbacks_t hf_client_cbacks = {
	.size = sizeof(hf_client_cbacks),
	.connection_state_cb = hf_client_connection_state_callback,
	.audio_state_cb = hf_client_audio_state_callback,
	.vr_cmd_cb = hf_client_vr_cmd_callback,
	.network_state_cb = hf_client_network_state_callback,
	.network_roaming_cb = hf_client_network_roaming_callback,
	.network_signal_cb = hf_client_network_signal_callback,
	.battery_level_cb = hf_client_battery_level_callback,
	.current_operator_cb = hf_client_current_operator_callback,
	.call_cb = hf_client_call_callback,
	.callsetup_cb = hf_client_callsetup_callback,
	.callheld_cb = hf_client_callheld_callback,
	.resp_and_hold_cb = hf_client_resp_and_hold_callback,
	.clip_cb = hf_client_clip_callback,
	.call_waiting_cb = hf_client_call_waiting_callback,
	.current_calls_cb = hf_client_current_calls_callback,
	.volume_change_cb = hf_client_volume_change_callback,
	.cmd_complete_cb = hf_client_cmd_complete_callback,
	.subscriber_info_cb = hf_client_subscriber_info_callback,
	.in_band_ring_tone_cb = hf_client_in_band_ring_tone_callback,
	.last_voice_tag_number_callback =
				hf_client_last_voice_tag_number_callback,
	.ring_indication_cb = hf_client_ring_indication_callback,
};

/* init */
static void init_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_hf_client);

	EXEC(if_hf_client->init, &hf_client_cbacks);
}

static void connect_c(int argc, const char **argv, enum_func *enum_func,
								void **user)
{
}

/* connect to audio gateway */
static void connect_p(int argc, const char **argv)
{
}

/*
 * This completion function will be used for several methods
 * returning recently connected address
 */
static void connected_addr_c(int argc, const char **argv, enum_func *enum_func,
								void **user)
{
	if (argc == 3) {
		*user = last_addr;
		*enum_func = enum_one_string;
	}
}

/* Map completion to connected_addr_c */
#define disconnect_c connected_addr_c

/* disconnect from audio gateway */
static void disconnect_p(int argc, const char **argv)
{
}

static void connect_audio_c(int argc, const char **argv, enum_func *enum_func,
								void **user)
{
}

/* create an audio connection */
static void connect_audio_p(int argc, const char **argv)
{
}

/* Map completion to connected_addr_c */
#define disconnect_audio_c connected_addr_c

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

static void volume_control_c(int argc, const char **argv, enum_func *enum_func,
								void **user)
{
}

/* volume control */
static void volume_control_p(int argc, const char **argv)
{
}

/* place a call with number a number */
static void dial_p(int argc, const char **argv)
{
}

/* place a call with number specified by location (speed dial) */
static void dial_memory_p(int argc, const char **argv)
{
}

static void handle_call_action_c(int argc, const char **argv,
					enum_func *enum_func, void **user)
{
}

/* perform specified call related action */
static void handle_call_action_p(int argc, const char **argv)
{
}

/* query list of current calls */
static void query_current_calls_p(int argc, const char **argv)
{
}

/* query name of current selected operator */
static void query_current_operator_name_p(int argc, const char **argv)
{
}

/* Retrieve subscriber information */
static void retrieve_subscriber_info_p(int argc, const char **argv)
{
}

/* Send DTMF code*/
static void send_dtmf_p(int argc, const char **argv)
{
}

/* Request a phone number from AG corresponding to last voice tag recorded */
static void request_last_voice_tag_number_p(int argc, const char **argv)
{
}

/* Closes the interface. */
static void cleanup_p(int argc, const char **argv)
{
}

static struct method methods[] = {
	STD_METHOD(init),
	STD_METHODCH(connect, "<addr>"),
	STD_METHODCH(disconnect, "<addr>"),
	STD_METHODCH(connect_audio, "<addr>"),
	STD_METHODCH(disconnect_audio, "<addr>"),
	STD_METHOD(start_voice_recognition),
	STD_METHOD(stop_voice_recognition),
	STD_METHODCH(volume_control, "<volume_type> <value>"),
	STD_METHODH(dial, "<destination_number>"),
	STD_METHODH(dial_memory, "<memory_location>"),
	STD_METHODCH(handle_call_action, "<call_action> <call_index>"),
	STD_METHOD(query_current_calls),
	STD_METHOD(query_current_operator_name),
	STD_METHOD(retrieve_subscriber_info),
	STD_METHODH(send_dtmf, "<code>"),
	STD_METHOD(request_last_voice_tag_number),
	STD_METHOD(cleanup),
	END_METHOD
};

const struct interface hf_client_if = {
	.name = "handsfree_client",
	.methods = methods
};
