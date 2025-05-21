/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025 Bastien Nocera <hadess@hadess.net>
 *
 *
 */

#include <stddef.h>
#include <glib.h>
#include "src/error.h"
#include "error-parse.h"

const char *error_codes[] = {
	ERR_BREDR_CONN_ALREADY_CONNECTED,
	ERR_BREDR_CONN_PAGE_TIMEOUT,
	ERR_BREDR_CONN_PROFILE_UNAVAILABLE,
	ERR_BREDR_CONN_SDP_SEARCH,
	ERR_BREDR_CONN_CREATE_SOCKET,
	ERR_BREDR_CONN_INVALID_ARGUMENTS,
	ERR_BREDR_CONN_ADAPTER_NOT_POWERED,
	ERR_BREDR_CONN_NOT_SUPPORTED,
	ERR_BREDR_CONN_BAD_SOCKET,
	ERR_BREDR_CONN_MEMORY_ALLOC,
	ERR_BREDR_CONN_BUSY,
	ERR_BREDR_CONN_CNCR_CONNECT_LIMIT,
	ERR_BREDR_CONN_TIMEOUT,
	ERR_BREDR_CONN_REFUSED,
	ERR_BREDR_CONN_ABORT_BY_REMOTE,
	ERR_BREDR_CONN_ABORT_BY_LOCAL,
	ERR_BREDR_CONN_LMP_PROTO_ERROR,
	ERR_BREDR_CONN_CANCELED,
	ERR_BREDR_CONN_KEY_MISSING,
	ERR_BREDR_CONN_UNKNOWN,
	ERR_LE_CONN_INVALID_ARGUMENTS,
	ERR_LE_CONN_ADAPTER_NOT_POWERED,
	ERR_LE_CONN_NOT_SUPPORTED,
	ERR_LE_CONN_ALREADY_CONNECTED,
	ERR_LE_CONN_BAD_SOCKET,
	ERR_LE_CONN_MEMORY_ALLOC,
	ERR_LE_CONN_BUSY,
	ERR_LE_CONN_REFUSED,
	ERR_LE_CONN_CREATE_SOCKET,
	ERR_LE_CONN_TIMEOUT,
	ERR_LE_CONN_SYNC_CONNECT_LIMIT,
	ERR_LE_CONN_ABORT_BY_REMOTE,
	ERR_LE_CONN_ABORT_BY_LOCAL,
	ERR_LE_CONN_LL_PROTO_ERROR,
	ERR_LE_CONN_GATT_BROWSE,
	ERR_LE_CONN_KEY_MISSING,
	ERR_LE_CONN_UNKNOWN
};

#define MIN_ERROR_MSG_LEN 4

/* Parse formatted combined error code + user-readable error
 * string into its components.
 * Format is ":code:message" */
const char *detailed_error_parse(const char  *error_msg,
				 const char **error_code)
{
	const char *second_colon;
	unsigned int i;

	if (error_msg == NULL)
		goto out;

	if (*error_msg != ':')
		goto out;
	if (strlen(error_msg) < MIN_ERROR_MSG_LEN)
		goto out;

	second_colon = strchr(error_msg + 1, ':');
	if (second_colon == NULL)
		goto out;

	for (i = 0; i < G_N_ELEMENTS(error_codes); i++) {
		if (strncmp(error_codes[i], error_msg + 1, (size_t)(second_colon - 1 - error_msg)) == 0) {
			if (error_code != NULL)
				*error_code = error_codes[i];
			return second_colon + 1;
		}
	}

out:
	return error_msg;
}
