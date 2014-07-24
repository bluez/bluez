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

#include <fcntl.h>

#include "tester-main.h"

#include "src/shared/util.h"

static struct queue *list; /* List of socket test cases */

static bt_bdaddr_t bdaddr_dummy = {
	.address = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
};

static int got_fd_result = -1;

static struct bt_action_data btsock_param_socktype_0 = {
	.addr = &bdaddr_dummy,
	.sock_type = 0,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.fd = &got_fd_result,
};

static struct bt_action_data btsock_param_socktype_l2cap = {
	.addr = &bdaddr_dummy,
	.sock_type = BTSOCK_L2CAP,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.fd = &got_fd_result,
};

static struct bt_action_data btsock_param_channel_0 = {
	.addr = &bdaddr_dummy,
	.sock_type = BTSOCK_RFCOMM,
	.channel = 0,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.fd = &got_fd_result,
};

static struct bt_action_data btsock_param = {
	.addr = &bdaddr_dummy,
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.fd = &got_fd_result,
};

static void socket_listen_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct bt_action_data *action_data = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	*action_data->fd = -1;

	step->action_status = data->if_sock->listen(action_data->sock_type,
						action_data->service_name,
						action_data->service_uuid,
						action_data->channel,
						action_data->fd,
						action_data->flags);

	schedule_action_verification(step);
}

static void socket_verify_fd_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct bt_action_data *action_data = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	if (!*action_data->fd) {
		step->action_status = BT_STATUS_FAIL;
		goto done;
	}

	step->action_status = (fcntl(*action_data->fd, F_GETFD) < 0) ?
					BT_STATUS_FAIL : BT_STATUS_SUCCESS;

done:
	schedule_action_verification(step);
}

static void socket_verify_channel_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct bt_action_data *action_data = current_data_step->set_data;
	int channel, len;
	struct step *step = g_new(struct step, 1);

	if (!*action_data->fd) {
		tester_warn("Ups no action_data->fd");

		step->action_status = BT_STATUS_FAIL;
		goto done;
	}

	len = read(*action_data->fd, &channel, sizeof(channel));
	if (len != sizeof(channel) || channel != action_data->channel) {
		tester_warn("Ups bad channel");

		step->action_status = BT_STATUS_FAIL;
		goto done;
	}

	step->action_status = BT_STATUS_SUCCESS;

done:
	schedule_action_verification(step);
}

static void socket_close_channel_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct bt_action_data *action_data = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	if (!*action_data->fd) {
		tester_warn("Ups no action_data->fd");

		step->action_status = BT_STATUS_FAIL;
		goto done;
	}

	close(*action_data->fd);
	*action_data->fd = -1;

	step->action_status = BT_STATUS_SUCCESS;

done:
	schedule_action_verification(step);
}

static struct test_case test_cases[] = {
	TEST_CASE_BREDRLE("Socket Init",
		ACTION_SUCCESS(dummy_action, NULL),
	),
	TEST_CASE_BREDRLE("Socket Listen - Invalid: sock_type 0",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION(BT_STATUS_PARM_INVALID, socket_listen_action,
						&btsock_param_socktype_0),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Socket Listen - Invalid: sock_type L2CAP",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION(BT_STATUS_UNSUPPORTED, socket_listen_action,
						&btsock_param_socktype_l2cap),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Socket Listen - Invalid: chan, uuid",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION(BT_STATUS_PARM_INVALID, socket_listen_action,
						&btsock_param_channel_0),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Socket Listen - Check returned fd valid",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(socket_listen_action, &btsock_param),
		ACTION_SUCCESS(socket_verify_fd_action, &btsock_param),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Socket Listen - Check returned channel",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(socket_listen_action, &btsock_param),
		ACTION_SUCCESS(socket_verify_fd_action, &btsock_param),
		ACTION_SUCCESS(socket_verify_channel_action, &btsock_param),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Socket Listen - Close and Listen again",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(socket_listen_action, &btsock_param),
		ACTION_SUCCESS(socket_verify_fd_action, &btsock_param),
		ACTION_SUCCESS(socket_verify_channel_action, &btsock_param),
		ACTION_SUCCESS(socket_close_channel_action, &btsock_param),
		ACTION_SUCCESS(socket_listen_action, &btsock_param),
		ACTION_SUCCESS(socket_verify_fd_action, &btsock_param),
		ACTION_SUCCESS(socket_verify_channel_action, &btsock_param),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
};

struct queue *get_socket_tests(void)
{
	uint16_t i = 0;

	list = queue_new();

	for (; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		if (!queue_push_tail(list, &test_cases[i]))
			return NULL;

	return list;
}

void remove_socket_tests(void)
{
	queue_destroy(list, NULL);
}
