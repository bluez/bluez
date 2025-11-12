/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 */

#include <stdbool.h>

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
#define HFP_AG_FEAT_VOICE_RECOGNITION_TEXT		0x00002000

#define HFP_CHLD_0	1 << 0
#define HFP_CHLD_1	1 << 1
#define HFP_CHLD_2	1 << 2
#define HFP_CHLD_3	1 << 3
#define HFP_CHLD_4	1 << 4
#define HFP_CHLD_1x	1 << 5
#define HFP_CHLD_2x	1 << 6

enum hfp_result {
	HFP_RESULT_OK		= 0,
	HFP_RESULT_CONNECT	= 1,
	HFP_RESULT_RING		= 2,
	HFP_RESULT_NO_CARRIER	= 3,
	HFP_RESULT_ERROR	= 4,
	HFP_RESULT_NO_DIALTONE	= 6,
	HFP_RESULT_BUSY		= 7,
	HFP_RESULT_NO_ANSWER	= 8,
	HFP_RESULT_DELAYED	= 9,
	HFP_RESULT_REJECTED	= 10,
	HFP_RESULT_CME_ERROR	= 11,
};

enum hfp_error {
	HFP_ERROR_AG_FAILURE			= 0,
	HFP_ERROR_NO_CONNECTION_TO_PHONE	= 1,
	HFP_ERROR_OPERATION_NOT_ALLOWED		= 3,
	HFP_ERROR_OPERATION_NOT_SUPPORTED	= 4,
	HFP_ERROR_PH_SIM_PIN_REQUIRED		= 5,
	HFP_ERROR_SIM_NOT_INSERTED		= 10,
	HFP_ERROR_SIM_PIN_REQUIRED		= 11,
	HFP_ERROR_SIM_PUK_REQUIRED		= 12,
	HFP_ERROR_SIM_FAILURE			= 13,
	HFP_ERROR_SIM_BUSY			= 14,
	HFP_ERROR_INCORRECT_PASSWORD		= 16,
	HFP_ERROR_SIM_PIN2_REQUIRED		= 17,
	HFP_ERROR_SIM_PUK2_REQUIRED		= 18,
	HFP_ERROR_MEMORY_FULL			= 20,
	HFP_ERROR_INVALID_INDEX			= 21,
	HFP_ERROR_MEMORY_FAILURE		= 23,
	HFP_ERROR_TEXT_STRING_TOO_LONG		= 24,
	HFP_ERROR_INVALID_CHARS_IN_TEXT_STRING	= 25,
	HFP_ERROR_DIAL_STRING_TO_LONG		= 26,
	HFP_ERROR_INVALID_CHARS_IN_DIAL_STRING	= 27,
	HFP_ERROR_NO_NETWORK_SERVICE		= 30,
	HFP_ERROR_NETWORK_TIMEOUT		= 31,
	HFP_ERROR_NETWORK_NOT_ALLOWED		= 32,
};

enum hfp_gw_cmd_type {
	HFP_GW_CMD_TYPE_READ,
	HFP_GW_CMD_TYPE_SET,
	HFP_GW_CMD_TYPE_TEST,
	HFP_GW_CMD_TYPE_COMMAND
};

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

enum hfp_call {
	CIND_CALL_NONE = 0,
	CIND_CALL_IN_PROGRESS
};

enum hfp_call_setup {
	CIND_CALLSETUP_NONE = 0,
	CIND_CALLSETUP_INCOMING,
	CIND_CALLSETUP_DIALING,
	CIND_CALLSETUP_ALERTING
};

enum hfp_call_held {
	CIND_CALLHELD_NONE = 0,
	CIND_CALLHELD_HOLD_AND_ACTIVE,
	CIND_CALLHELD_HOLD
};

enum hfp_call_status {
	CALL_STATUS_ACTIVE = 0,
	CALL_STATUS_HELD,
	CALL_STATUS_DIALING,
	CALL_STATUS_ALERTING,
	CALL_STATUS_INCOMING,
	CALL_STATUS_WAITING,
	CALL_STATUS_RESPONSE_AND_HOLD
};

struct hfp_context;

typedef void (*hfp_result_func_t)(struct hfp_context *context,
				enum hfp_gw_cmd_type type, void *user_data);

typedef void (*hfp_destroy_func_t)(void *user_data);
typedef void (*hfp_debug_func_t)(const char *str, void *user_data);

typedef void (*hfp_command_func_t)(const char *command, void *user_data);
typedef void (*hfp_disconnect_func_t)(void *user_data);

struct hfp_gw;

struct hfp_gw *hfp_gw_new(int fd);

struct hfp_gw *hfp_gw_ref(struct hfp_gw *hfp);
void hfp_gw_unref(struct hfp_gw *hfp);

bool hfp_gw_set_debug(struct hfp_gw *hfp, hfp_debug_func_t callback,
				void *user_data, hfp_destroy_func_t destroy);

bool hfp_gw_set_close_on_unref(struct hfp_gw *hfp, bool do_close);
bool hfp_gw_set_permissive_syntax(struct hfp_gw *hfp, bool permissive);

bool hfp_gw_send_result(struct hfp_gw *hfp, enum hfp_result result);
bool hfp_gw_send_error(struct hfp_gw *hfp, enum hfp_error error);
bool hfp_gw_send_info(struct hfp_gw *hfp, const char *format, ...)
					__attribute__((format(printf, 2, 3)));

bool hfp_gw_set_command_handler(struct hfp_gw *hfp,
				hfp_command_func_t callback,
				void *user_data, hfp_destroy_func_t destroy);

bool hfp_gw_set_disconnect_handler(struct hfp_gw *hfp,
					hfp_disconnect_func_t callback,
					void *user_data,
					hfp_destroy_func_t destroy);

bool hfp_gw_disconnect(struct hfp_gw *hfp);

bool hfp_gw_register(struct hfp_gw *hfp, hfp_result_func_t callback,
						const char *prefix,
						void *user_data,
						hfp_destroy_func_t destroy);
bool hfp_gw_unregister(struct hfp_gw *hfp, const char *prefix);

bool hfp_context_get_number(struct hfp_context *context,
							unsigned int *val);
bool hfp_context_get_number_default(struct hfp_context *context,
						unsigned int *val,
						unsigned int default_val);
bool hfp_context_open_container(struct hfp_context *context);
bool hfp_context_close_container(struct hfp_context *context);
bool hfp_context_is_container_close(struct hfp_context *context);
bool hfp_context_get_string(struct hfp_context *context, char *buf,
								uint8_t len);
bool hfp_context_get_unquoted_string(struct hfp_context *context,
						char *buf, uint8_t len);
bool hfp_context_get_range(struct hfp_context *context, unsigned int *min,
							unsigned int *max);
bool hfp_context_has_next(struct hfp_context *context);
void hfp_context_skip_field(struct hfp_context *context);

typedef void (*hfp_hf_result_func_t)(struct hfp_context *context,
							void *user_data);

typedef void (*hfp_response_func_t)(enum hfp_result result,
							enum hfp_error cme_err,
							void *user_data);

struct hfp_hf;

struct hfp_hf_callbacks {
	void (*session_ready)(enum hfp_result result, enum hfp_error cme_err,
							void *user_data);
	void (*update_indicator)(enum hfp_indicator indicator, uint32_t val,
							void *user_data);
	void (*update_operator)(const char *operator_name, void *user_data);
	void (*update_inband_ring)(bool enabled, void *user_data);

	void (*call_added)(uint id, enum hfp_call_status status,
							void *user_data);
	void (*call_removed)(uint id, void *user_data);
	void (*call_status_updated)(uint id, enum hfp_call_status status,
							void *user_data);
	void (*call_line_id_updated)(uint id, const char *number, uint type,
							void *user_data);
	void (*call_mpty_updated)(uint id, bool mpty, void *user_data);
};

struct hfp_hf *hfp_hf_new(int fd);

struct hfp_hf *hfp_hf_ref(struct hfp_hf *hfp);
void hfp_hf_unref(struct hfp_hf *hfp);
bool hfp_hf_set_debug(struct hfp_hf *hfp, hfp_debug_func_t callback,
				void *user_data, hfp_destroy_func_t destroy);
bool hfp_hf_set_close_on_unref(struct hfp_hf *hfp, bool do_close);
bool hfp_hf_set_disconnect_handler(struct hfp_hf *hfp,
					hfp_disconnect_func_t callback,
					void *user_data,
					hfp_destroy_func_t destroy);
bool hfp_hf_disconnect(struct hfp_hf *hfp);
bool hfp_hf_register(struct hfp_hf *hfp, hfp_hf_result_func_t callback,
					const char *prefix, void *user_data,
					hfp_destroy_func_t destroy);
bool hfp_hf_unregister(struct hfp_hf *hfp, const char *prefix);
bool hfp_hf_send_command(struct hfp_hf *hfp, hfp_response_func_t resp_cb,
				void *user_data, const char *format, ...);

bool hfp_hf_session_register(struct hfp_hf *hfp,
				struct hfp_hf_callbacks *callbacks,
				void *callbacks_data);
bool hfp_hf_session(struct hfp_hf *hfp);

const char *hfp_hf_call_get_number(struct hfp_hf *hfp, uint id);

bool hfp_hf_dial(struct hfp_hf *hfp, const char *number,
				hfp_response_func_t resp_cb,
				void *user_data);
bool hfp_hf_release_and_accept(struct hfp_hf *hfp,
				hfp_response_func_t resp_cb,
				void *user_data);
bool hfp_hf_swap_calls(struct hfp_hf *hfp,
				hfp_response_func_t resp_cb,
				void *user_data);
bool hfp_hf_call_answer(struct hfp_hf *hfp, uint id,
				hfp_response_func_t resp_cb,
				void *user_data);
bool hfp_hf_call_hangup(struct hfp_hf *hfp, uint id,
				hfp_response_func_t resp_cb,
				void *user_data);
