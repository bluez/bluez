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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <readline/readline.h>

#include <glib.h>

#include <lib/bluetooth.h>
#include "client/display.h"
#include "mesh/util.h"
#include "mesh/agent.h"

#define AGENT_PROMPT	COLOR_RED "[agent]" COLOR_OFF " "

static char *agent_saved_prompt = NULL;
static int agent_saved_point = 0;

struct input_request {
	oob_type_t type;
	uint16_t len;
	agent_input_cb cb;
	void *user_data;
};

static struct input_request pending_request = {NONE, 0, NULL, NULL};

static void agent_prompt(const char *msg)
{
	char *prompt;

	/* Normal use should not prompt for user input to the agent a second
	 * time before it releases the prompt, but we take a safe action. */
	if (agent_saved_prompt)
		return;

	agent_saved_point = rl_point;
	agent_saved_prompt = g_strdup(rl_prompt);

	rl_set_prompt("");
	rl_redisplay();

	prompt = g_strdup_printf(AGENT_PROMPT "%s", msg);
	rl_set_prompt(prompt);
	g_free(prompt);

	rl_replace_line("", 0);
	rl_redisplay();
}

static void agent_release_prompt(void)
{
	if (!agent_saved_prompt)
		return;

	/* This will cause rl_expand_prompt to re-run over the last prompt, but
	 * our prompt doesn't expand anyway. */
	rl_set_prompt(agent_saved_prompt);
	rl_replace_line("", 0);
	rl_point = agent_saved_point;
	rl_redisplay();

	g_free(agent_saved_prompt);
	agent_saved_prompt = NULL;
}

bool agent_completion(void)
{
	if (pending_request.type == NONE)
		return false;

	return true;
}

static bool response_hexadecimal(const char *input)
{
	uint8_t buf[MAX_HEXADECIMAL_OOB_LEN];

	if (!str2hex(input, strlen(input), buf, pending_request.len) ) {
		rl_printf("Incorrect input: expecting %d hex octets\n",
			  pending_request.len);
		return false;
	}

	if (pending_request.cb)
		pending_request.cb(HEXADECIMAL, buf, pending_request.len,
					pending_request.user_data);
	return true;
}

static bool response_decimal(const char *input)
{
	uint8_t buf[DECIMAL_OOB_LEN];

	if (strlen(input) > pending_request.len)
		return false;

	bt_put_be32(atoi(input), buf);

	if (pending_request.cb)
		pending_request.cb(DECIMAL, buf, DECIMAL_OOB_LEN,
					pending_request.user_data);

	return true;
}

static void response_ascii(const char *input)
{
	if (pending_request.cb)
		pending_request.cb(ASCII, (uint8_t *) input, strlen(input),
					pending_request.user_data);
}

bool agent_input(const char *input)
{
	bool repeat = false;

	if (pending_request.type == NONE)
		return false;

	switch (pending_request.type) {
	case HEXADECIMAL:
		if (!response_hexadecimal(input))
			repeat = true;
		break;
	case DECIMAL:
		if (!response_decimal(input))
			repeat = true;
		break;
	case ASCII:
		response_ascii(input);
		break;
	case OUTPUT:
		repeat = true;
	case NONE:
	default:
		break;
	};

	if (!repeat) {
		pending_request.type = NONE;
		pending_request.len = 0;
		pending_request.cb = NULL;
		pending_request.user_data = NULL;

		agent_release_prompt();
	}

	return true;
}

void agent_release(void)
{
	agent_release_prompt();
}

static bool request_hexadecimal(uint16_t len)
{
	if (len > MAX_HEXADECIMAL_OOB_LEN)
		return false;

	rl_printf("Request hexadecimal key (hex %d octets)\n", len);
	agent_prompt("Enter key (hex number): ");

	return true;
}

static uint32_t power_ten(uint8_t power)
{
	uint32_t ret = 1;

	while (power--)
		ret *= 10;

	return ret;
}

static bool request_decimal(uint16_t len)
{
	rl_printf("Request decimal key (0 - %d)\n", power_ten(len) - 1);
	agent_prompt("Enter Numeric key: ");

	return true;
}

static bool request_ascii(uint16_t len)
{
	if (len != MAX_ASCII_OOB_LEN)
		return false;

	rl_printf("Request ASCII key (max characters %d)\n", len);
	agent_prompt("Enter key (ascii string): ");

	return true;
}

bool agent_input_request(oob_type_t type, uint16_t max_len, agent_input_cb cb,
				void *user_data)
{
	bool result;

	if (pending_request.type != NONE)
		return FALSE;

	switch (type) {
	case HEXADECIMAL:
		result = request_hexadecimal(max_len);
		break;
	case DECIMAL:
		result = request_decimal(max_len);
		break;
	case ASCII:
		result = request_ascii(max_len);
		break;
	case NONE:
	case OUTPUT:
	default:
		return false;
	};

	if (result) {
		pending_request.type = type;
		pending_request.len = max_len;
		pending_request.cb = cb;
		pending_request.user_data = user_data;

		return true;
	}

	return false;
}

bool agent_output_request(const char* str)
{
	if (pending_request.type != NONE)
		return false;

	pending_request.type = OUTPUT;
	agent_prompt(str);
	return true;
}

void agent_output_request_cancel(void)
{
	if (pending_request.type != OUTPUT)
		return;
	pending_request.type = NONE;
	agent_release_prompt();
}
