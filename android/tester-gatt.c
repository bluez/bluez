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

#include <stdbool.h>

#include "emulator/bthost.h"
#include "tester-main.h"
#include "src/shared/util.h"

#define CLIENT1_ID	1

static struct queue *list; /* List of gatt test cases */

static bt_uuid_t client_app_uuid = {
	.uu = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
};

static bt_bdaddr_t emu_remote_bdaddr_val = {
	.address = { 0x00, 0xaa, 0x01, 0x01, 0x00, 0x00 },
};
static bt_property_t prop_emu_remotes_default_set[] = {
	{ BT_PROPERTY_BDADDR, sizeof(emu_remote_bdaddr_val),
						&emu_remote_bdaddr_val },
};

static void gatt_client_register_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	bt_uuid_t *app_uuid = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	if (!app_uuid) {
		tester_warn("No app uuid provided for register action.");
		return;
	}

	step->action_status = data->if_gatt->client->register_client(app_uuid);

	schedule_action_verification(step);
}

static void gatt_client_unregister_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	int32_t cl_id = PTR_TO_INT(current_data_step->set_data);
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->unregister_client(cl_id);

	schedule_action_verification(step);
}

static void gatt_client_start_scan_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	int32_t cl_id = PTR_TO_INT(current_data_step->set_data);
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->scan(cl_id, TRUE);

	schedule_action_verification(step);
}

static void gatt_client_stop_scan_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	int32_t cl_id = PTR_TO_INT(current_data_step->set_data);
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->scan(cl_id, FALSE);

	schedule_action_verification(step);
}

static struct test_case test_cases[] = {
	TEST_CASE_BREDRLE("Gatt Init",
		ACTION_SUCCESS(dummy_action, NULL),
	),
	TEST_CASE_BREDRLE("Gatt Client - Register",
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
	),
	TEST_CASE_BREDRLE("Gatt Client - Unregister",
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_unregister_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
	),
	TEST_CASE_BREDRLE("Gatt Client - Scan",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
};

struct queue *get_gatt_tests(void)
{
	uint16_t i = 0;

	list = queue_new();

	for (; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		if (!queue_push_tail(list, &test_cases[i]))
			return NULL;

	return list;
}

void remove_gatt_tests(void)
{
	queue_destroy(list, NULL);
}
