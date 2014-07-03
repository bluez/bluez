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

static struct queue *list; /* List of socket test cases */

static struct step dummy_steps[] = {
	{
		.action = dummy_action,
	},
};
static struct test_case socket_init = {
	.step = dummy_steps,
	.title = "Socket Init",
	.step_num = get_test_case_step_num(dummy_steps),
};

struct queue *get_socket_tests(void)
{
	list = queue_new();

	if (!queue_push_tail(list, &socket_init))
		return NULL;

	return list;
}

void remove_socket_tests(void)
{
	queue_destroy(list, NULL);
}
