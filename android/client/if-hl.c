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

#include<stdio.h>
#include<ctype.h>

#include<hardware/bluetooth.h>
#include<hardware/bt_hl.h>

#include "if-main.h"
#include "pollhandler.h"
#include "../hal-utils.h"

const bthl_interface_t *if_hl = NULL;

static bthl_callbacks_t hl_cbacks = {
	.size = sizeof(hl_cbacks),
	.app_reg_state_cb = NULL,
	.channel_state_cb = NULL,
};

/* init */

static void init_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_hl);

	EXEC(if_hl->init, &hl_cbacks);
}

/* cleanup */

static void cleanup_p(int argc, const char **argv)
{
	RETURN_IF_NULL(if_hl);

	EXECV(if_hl->cleanup);
	if_hl = NULL;
}

static struct method methods[] = {
	STD_METHOD(init),
	STD_METHOD(cleanup),
	END_METHOD
};

const struct interface hl_if = {
	.name = "hl",
	.methods = methods
};
