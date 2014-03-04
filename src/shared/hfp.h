/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012-2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdbool.h>

enum hfp_result {
	HFP_RESULT_OK		= 0,
	HFP_RESULT_CONNECT	= 1,
	HFP_RESULT_RING		= 2,
	HFP_RESULT_NO_CARRIER	= 3,
	HFP_RESULT_ERROR	= 4,
	HFP_RESULT_NO_DIALTONE	= 6,
	HFP_RESULT_BUSY		= 7,
	HFP_RESULT_NO_ANSWER	= 8,
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

struct hfp_gw_result;

typedef void (*hfp_result_func_t)(struct hfp_gw_result *result,
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

bool hfp_gw_result_get_number(struct hfp_gw_result *result, unsigned int *val);
bool hfp_gw_result_get_number_default(struct hfp_gw_result *result,
						unsigned int *val,
						unsigned int default_val);
bool hfp_gw_result_open_container(struct hfp_gw_result *result);
bool hfp_gw_result_close_container(struct hfp_gw_result *result);
bool hfp_gw_result_get_string(struct hfp_gw_result *result, char *buf,
								uint8_t len);
bool hfp_gw_result_get_unquoted_string(struct hfp_gw_result *result, char *buf,
								uint8_t len);
bool hfp_gw_result_has_next(struct hfp_gw_result *result);
