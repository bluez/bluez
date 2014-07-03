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

static bt_bdaddr_t enable_bdaddr_val = {
	.address = { 0x00, 0xaa, 0x01, 0x00, 0x00, 0x00 },
};
static const char enable_bdname_val[] = "BlueZ for Android";
static const char enable_uuids_val[] = {
	/* Multi profile UUID */
	0x00, 0x00, 0x11, 0x3b, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
					0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
	/* Device identification profile UUID */
	0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
					0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
};
static bt_device_type_t enable_tod_val = BT_DEVICE_DEVTYPE_DUAL;
static bt_scan_mode_t enable_scanmode_val = BT_SCAN_MODE_NONE;
static uint32_t enable_disctimeout_val = 120;

static bt_property_t enable_props[] = {
	{ BT_PROPERTY_BDADDR, sizeof(enable_bdaddr_val), NULL },
	{ BT_PROPERTY_BDNAME, sizeof(enable_bdname_val) - 1,
						&enable_bdname_val },
	{ BT_PROPERTY_CLASS_OF_DEVICE, sizeof(uint32_t), NULL },
	{ BT_PROPERTY_TYPE_OF_DEVICE, sizeof(enable_tod_val),
						&enable_tod_val },
	{ BT_PROPERTY_ADAPTER_SCAN_MODE, sizeof(enable_scanmode_val),
						&enable_scanmode_val },
	{ BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
						sizeof(enable_disctimeout_val),
						&enable_disctimeout_val },
	{ BT_PROPERTY_ADAPTER_BONDED_DEVICES, 0, NULL },
	{ BT_PROPERTY_UUIDS, sizeof(enable_uuids_val), &enable_uuids_val },
};

static struct step bluetooth_enable_success_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_PROPERTIES,
		.callback_result.properties = enable_props,
		.callback_result.num_properties = 8,
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

static struct step bluetooth_enable_success2_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_PROPERTIES,
		.callback_result.properties = enable_props,
		.callback_result.num_properties = 8,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
};
static struct test_case bluetooth_enable_success2_tc = {
	.step = bluetooth_enable_success2_steps,
	.title = "Bluetooth Enable - Success 2",
	.step_num = get_test_case_step_num(bluetooth_enable_success2_steps),
};

static struct step bluetooth_disable_success_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_disable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_OFF,
	},
};
static struct test_case bluetooth_disable_success_tc = {
	.step = bluetooth_disable_success_steps,
	.title = "Bluetooth Disable - Success",
	.step_num = get_test_case_step_num(bluetooth_disable_success_steps),
};

static char test_set_bdname[] = "test_bdname_set";

static bt_property_t setprop_bdname_prop = {
	.type = BT_PROPERTY_BDNAME,
	.val = test_set_bdname,
	.len = sizeof(test_set_bdname) - 1,
};

static struct step bluetooth_setprop_bdname_success_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.set_data = &setprop_bdname_prop,
		.action = bt_set_property_action,
	},
	{
		.callback = CB_BT_ADAPTER_PROPERTIES,
		.callback_result.properties = &setprop_bdname_prop,
	}
};
static struct test_case bluetooth_setprop_bdname_success_tc = {
	.step = bluetooth_setprop_bdname_success_steps,
	.title = "Bluetooth Set BDNAME - Success",
	.step_num =
		get_test_case_step_num(bluetooth_setprop_bdname_success_steps),
};

static bt_scan_mode_t test_setprop_scanmode_val =
					BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;

static bt_property_t setprop_scanmode_prop = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &test_setprop_scanmode_val,
	.len = sizeof(bt_scan_mode_t),
};

static struct step bluetooth_setprop_scanmode_success_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.set_data = &setprop_scanmode_prop,
		.action = bt_set_property_action,
	},
	{
		.callback = CB_BT_ADAPTER_PROPERTIES,
		.callback_result.properties = &setprop_scanmode_prop,
	},
};
static struct test_case bluetooth_setprop_scanmode_success_tc = {
	.step = bluetooth_setprop_scanmode_success_steps,
	.title = "Bluetooth Set SCAN_MODE - Success",
	.step_num = get_test_case_step_num(
				bluetooth_setprop_scanmode_success_steps),
};

static uint32_t test_setprop_disctimeout_val = 600;

static bt_property_t setprop_disctimeout_prop = {
	.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.val = &test_setprop_disctimeout_val,
	.len = sizeof(test_setprop_disctimeout_val),
};

static struct step bluetooth_setprop_disctimeout_success_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.set_data = &setprop_disctimeout_prop,
		.action = bt_set_property_action,
	},
	{
		.callback = CB_BT_ADAPTER_PROPERTIES,
		.callback_result.properties = NULL,
	},
};
static struct test_case bluetooth_setprop_disctimeout_success_tc = {
	.step = bluetooth_setprop_disctimeout_success_steps,
	.title = "Bluetooth Set DISCOVERY_TIMEOUT - Success",
	.step_num = get_test_case_step_num(
				bluetooth_setprop_disctimeout_success_steps),
};

struct queue *get_bluetooth_tests(void)
{
	list = queue_new();

	if (!queue_push_tail(list, &bluetooth_init))
		return NULL;

	if (!queue_push_tail(list, &bluetooth_enable_success_tc))
		return NULL;

	if (!queue_push_tail(list, &bluetooth_enable_success2_tc))
		return NULL;

	if (!queue_push_tail(list, &bluetooth_disable_success_tc))
		return NULL;

	if (!queue_push_tail(list, &bluetooth_setprop_bdname_success_tc))
		return NULL;

	if (!queue_push_tail(list, &bluetooth_setprop_scanmode_success_tc))
		return NULL;

	if (!queue_push_tail(list, &bluetooth_setprop_disctimeout_success_tc))
		return NULL;

	return list;
}

void remove_bluetooth_tests(void)
{
	queue_destroy(list, NULL);
}
