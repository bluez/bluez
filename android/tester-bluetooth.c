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

#include "tester-main.h"

static struct queue *list; /* List of bluetooth test cases */

static struct step dummy_steps[] = {
	{
		.action = dummy_action,
	},
};
static struct test_case bluetooth_init = {
	.step = dummy_steps,
	.title = "Bluetooth Init",
	.step_num = get_test_case_step_num(dummy_steps),
};

static struct step bluetooth_enable_success_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
};
static struct test_case bluetooth_enable_success_tc = {
	.step = bluetooth_enable_success_steps,
	.title = "Bluetooth Enable - Success",
	.step_num = get_test_case_step_num(bluetooth_enable_success_steps),
};

struct queue *get_bluetooth_tests(void)
{
	list = queue_new();

	if (!queue_push_tail(list, &bluetooth_init))
		return NULL;

	if (!queue_push_tail(list, &bluetooth_enable_success_tc))
		return NULL;

	return list;
}

void remove_bluetooth_tests(void)
{
	queue_destroy(list, NULL);
}
