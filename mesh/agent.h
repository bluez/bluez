/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#define MAX_HEXADECIMAL_OOB_LEN	128
#define DECIMAL_OOB_LEN		4
#define MAX_ASCII_OOB_LEN		16

typedef enum {
	NONE,
	HEXADECIMAL,
	DECIMAL,
	ASCII,
	OUTPUT,
} oob_type_t;

typedef void (*agent_input_cb)(oob_type_t type, void *input, uint16_t len,
					void *user_data);
bool agent_input_request(oob_type_t type, uint16_t max_len, agent_input_cb cb,
				void *user_data);

bool agent_output_request(const char* str);
void agent_output_request_cancel(void);
bool agent_completion(void);
bool agent_input(const char *input);
void agent_release(void);
