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
#include "android/utils.h"

typedef enum {
	HDP_APP_SINK_RELIABLE,
	HDP_APP_SINK_STREAM,
	HDP_APP_SOURCE_RELIABLE,
	HDP_APP_SOURCE_STREAM,
} hdp_app_reg_type;

static struct queue *list; /* List of hdp test cases */

static bthl_reg_param_t *create_app(hdp_app_reg_type type)
{
	bthl_reg_param_t *reg;
	bthl_mdep_cfg_t mdep1, mdep2;

	reg = malloc(sizeof(bthl_reg_param_t));
	reg->application_name = "bluez-android";
	reg->provider_name = "Bluez";
	reg->srv_name = "bluez-hdp";
	reg->srv_desp = "health-device-profile";

	mdep1.data_type = 4100;
	mdep1.mdep_description = "pulse-oximeter";

	mdep2.data_type = 4100;
	mdep2.mdep_description = "pulse-oximeter";

	switch (type) {
	case HDP_APP_SINK_RELIABLE:
		reg->number_of_mdeps = 1;
		mdep1.mdep_role = BTHL_MDEP_ROLE_SINK;
		mdep1.channel_type = BTHL_CHANNEL_TYPE_RELIABLE;
		reg->mdep_cfg = malloc(reg->number_of_mdeps *
						sizeof(bthl_mdep_cfg_t));
		reg->mdep_cfg[0] = mdep1;
		break;

	case HDP_APP_SINK_STREAM:
		reg->number_of_mdeps = 2;

		mdep1.mdep_role = BTHL_MDEP_ROLE_SINK;
		mdep1.channel_type = BTHL_CHANNEL_TYPE_RELIABLE;

		mdep2.mdep_role = BTHL_MDEP_ROLE_SINK;
		mdep2.channel_type = BTHL_CHANNEL_TYPE_STREAMING;

		reg->mdep_cfg = malloc(reg->number_of_mdeps *
						sizeof(bthl_mdep_cfg_t));
		reg->mdep_cfg[0] = mdep1;
		reg->mdep_cfg[1] = mdep2;
		break;

	case HDP_APP_SOURCE_RELIABLE:
		reg->number_of_mdeps = 1;

		mdep1.mdep_role = BTHL_MDEP_ROLE_SOURCE;
		mdep1.channel_type = BTHL_CHANNEL_TYPE_RELIABLE;

		reg->mdep_cfg = malloc(reg->number_of_mdeps *
						sizeof(bthl_mdep_cfg_t));
		reg->mdep_cfg[0] = mdep1;
		break;

	case HDP_APP_SOURCE_STREAM:
		reg->number_of_mdeps = 2;

		mdep1.mdep_role = BTHL_MDEP_ROLE_SOURCE;
		mdep1.channel_type = BTHL_CHANNEL_TYPE_RELIABLE;

		mdep2.mdep_role = BTHL_MDEP_ROLE_SOURCE;
		mdep2.channel_type = BTHL_CHANNEL_TYPE_STREAMING;

		reg->mdep_cfg = malloc(reg->number_of_mdeps *
						sizeof(bthl_mdep_cfg_t));
		reg->mdep_cfg[0] = mdep1;
		reg->mdep_cfg[1] = mdep2;
		break;
	}


	return reg;
}

static void hdp_register_sink_reliable_app_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *step = g_new0(struct step, 1);
	int app_id = 0;
	bthl_reg_param_t *reg;

	reg = create_app(HDP_APP_SINK_RELIABLE);
	step->action_status = data->if_hdp->register_application(reg, &app_id);

	schedule_action_verification(step);
	free(reg->mdep_cfg);
	free(reg);
}

static void hdp_register_sink_stream_app_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *step = g_new0(struct step, 1);
	int app_id = 0;
	bthl_reg_param_t *reg;

	reg = create_app(HDP_APP_SINK_STREAM);
	step->action_status = data->if_hdp->register_application(reg, &app_id);

	schedule_action_verification(step);
	free(reg->mdep_cfg);
	free(reg);
}

static void hdp_register_source_reliable_app_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *step = g_new0(struct step, 1);
	int app_id = 0;
	bthl_reg_param_t *reg;

	reg = create_app(HDP_APP_SOURCE_RELIABLE);
	step->action_status = data->if_hdp->register_application(reg, &app_id);

	schedule_action_verification(step);
	free(reg->mdep_cfg);
	free(reg);
}

static void hdp_register_source_stream_app_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *step = g_new0(struct step, 1);
	int app_id = 0;
	bthl_reg_param_t *reg;

	reg = create_app(HDP_APP_SOURCE_STREAM);
	step->action_status = data->if_hdp->register_application(reg, &app_id);

	schedule_action_verification(step);
	free(reg->mdep_cfg);
	free(reg);
}

static void hdp_unregister_app_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_hdp->unregister_application(1);

	schedule_action_verification(step);
}

static struct test_case test_cases[] = {
	TEST_CASE_BREDRLE("HDP Init",
		ACTION_SUCCESS(dummy_action, NULL),
	),
	TEST_CASE_BREDRLE("HDP Register Sink Reliable Application",
		ACTION_SUCCESS(hdp_register_sink_reliable_app_action, NULL),
		CALLBACK_HDP_APP_REG_STATE(CB_HDP_APP_REG_STATE, 1,
					BTHL_APP_REG_STATE_REG_SUCCESS),
	),
	TEST_CASE_BREDRLE("HDP Register Sink Stream Application",
		ACTION_SUCCESS(hdp_register_sink_stream_app_action, NULL),
		CALLBACK_HDP_APP_REG_STATE(CB_HDP_APP_REG_STATE, 1,
					BTHL_APP_REG_STATE_REG_SUCCESS),
	),
	TEST_CASE_BREDRLE("HDP Register Source Reliable Application",
		ACTION_SUCCESS(hdp_register_source_reliable_app_action, NULL),
		CALLBACK_HDP_APP_REG_STATE(CB_HDP_APP_REG_STATE, 1,
					BTHL_APP_REG_STATE_REG_SUCCESS),
	),
	TEST_CASE_BREDRLE("HDP Register Source Stream Application",
		ACTION_SUCCESS(hdp_register_source_stream_app_action, NULL),
		CALLBACK_HDP_APP_REG_STATE(CB_HDP_APP_REG_STATE, 1,
					BTHL_APP_REG_STATE_REG_SUCCESS),
	),
	TEST_CASE_BREDRLE("HDP Unegister Application",
		ACTION_SUCCESS(hdp_register_source_stream_app_action, NULL),
		CALLBACK_HDP_APP_REG_STATE(CB_HDP_APP_REG_STATE, 1,
					BTHL_APP_REG_STATE_REG_SUCCESS),
		ACTION_SUCCESS(hdp_unregister_app_action, NULL),
		CALLBACK_HDP_APP_REG_STATE(CB_HDP_APP_REG_STATE, 1,
					BTHL_APP_REG_STATE_DEREG_SUCCESS),
	),
};

struct queue *get_hdp_tests(void)
{
	uint16_t i = 0;

	list = queue_new();

	for (; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		if (!queue_push_tail(list, &test_cases[i]))
			return NULL;

	return list;
}

void remove_hdp_tests(void)
{
	queue_destroy(list, NULL);
}
