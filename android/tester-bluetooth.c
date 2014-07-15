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
		.callback_result.num_properties = 1,
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
		.callback_result.num_properties = 1,
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

static bt_bdaddr_t test_getprop_bdaddr_val = {
	{0x00, 0xaa, 0x01, 0x00, 0x00, 0x00},
};

static bt_property_t getprop_bdaddr_prop = {
	.type = BT_PROPERTY_BDADDR,
	.val = &test_getprop_bdaddr_val,
	.len = sizeof(test_getprop_bdaddr_val),
};

static struct step bluetooth_getprop_bdaddr_success_steps[] = {
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
		.set_data = &getprop_bdaddr_prop,
		.action = bt_get_property_action,
	},
	{
		.callback = CB_BT_ADAPTER_PROPERTIES,
		.callback_result.properties = &getprop_bdaddr_prop,
		.callback_result.num_properties = 1,
	},
};
static struct test_case bluetooth_getprop_bdaddr_success_tc = {
	.step = bluetooth_getprop_bdaddr_success_steps,
	.title = "Bluetooth Get BDADDR - Success",
	.step_num = get_test_case_step_num(
					bluetooth_getprop_bdaddr_success_steps),
};

static const char test_getprop_bdname_val[] = "BlueZ for Android";

static bt_property_t getprop_bdname_prop = {
	.type = BT_PROPERTY_BDNAME,
	.val = &test_getprop_bdname_val,
	.len = sizeof(test_getprop_bdname_val) - 1,
};

static struct step bluetooth_getprop_bdname_success_steps[] = {
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
		.set_data = &getprop_bdname_prop,
		.action = bt_get_property_action,
	},
	{
		.callback = CB_BT_ADAPTER_PROPERTIES,
		.callback_result.properties = &getprop_bdname_prop,
		.callback_result.num_properties = 1,
	},
};
static struct test_case bluetooth_getprop_bdname_success_tc = {
	.step = bluetooth_getprop_bdname_success_steps,
	.title = "Bluetooth Get BDNAME - Success",
	.step_num = get_test_case_step_num(
					bluetooth_getprop_bdname_success_steps),
};


static unsigned char setprop_uuids[] = { 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00,
			0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00 };

static bt_property_t setprop_uuid_prop = {
	.type = BT_PROPERTY_UUIDS,
	.val = &setprop_uuids,
	.len = sizeof(setprop_uuids),
};

static struct step bluetooth_setprop_uuid_fail_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_FAIL,
		.set_data = &setprop_uuid_prop,
		.action = bt_set_property_action,
	},
};
static struct test_case bluetooth_setprop_uuid_fail_tc = {
	.step = bluetooth_setprop_uuid_fail_steps,
	.title = "Bluetooth Set UUID - Fail",
	.step_num = get_test_case_step_num(bluetooth_setprop_uuid_fail_steps),
};

static uint32_t setprop_cod_val = 0;

static bt_property_t setprop_cod_prop = {
	.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.val = &setprop_cod_val,
	.len = sizeof(setprop_cod_val),
};

static struct step bluetooth_setprop_cod_fail_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_FAIL,
		.set_data = &setprop_cod_prop,
		.action = bt_set_property_action,
	},
};
static struct test_case bluetooth_setprop_cod_fail_tc = {
	.step = bluetooth_setprop_cod_fail_steps,
	.title = "Bluetooth Set CLASS_OF_DEVICE - Fail",
	.step_num = get_test_case_step_num(bluetooth_setprop_cod_fail_steps),
};

static uint32_t setprop_tod_val = BT_DEVICE_DEVTYPE_DUAL;

static bt_property_t setprop_tod_prop = {
	.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.val = &setprop_tod_val,
	.len = sizeof(setprop_tod_val),
};

static struct step bluetooth_setprop_tod_fail_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_FAIL,
		.set_data = &setprop_tod_prop,
		.action = bt_set_property_action,
	},
};
static struct test_case bluetooth_setprop_tod_fail_tc = {
	.step = bluetooth_setprop_tod_fail_steps,
	.title = "Bluetooth Set TYPE_OF_DEVICE - Fail",
	.step_num = get_test_case_step_num(bluetooth_setprop_tod_fail_steps),
};

static int32_t setprop_remote_rssi_val = -9;

static bt_property_t setprop_remote_rssi_prop = {
	.type = BT_PROPERTY_REMOTE_RSSI,
	.val = &setprop_remote_rssi_val,
	.len = sizeof(setprop_remote_rssi_val),
};

static struct step bluetooth_setprop_remote_rssi_fail_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_FAIL,
		.set_data = &setprop_remote_rssi_prop,
		.action = bt_set_property_action,
	},
};
static struct test_case bluetooth_setprop_remote_rssi_fail_tc = {
	.step = bluetooth_setprop_remote_rssi_fail_steps,
	.title = "Bluetooth Set REMOTE_RSSI - Fail",
	.step_num = get_test_case_step_num(
				bluetooth_setprop_remote_rssi_fail_steps),
};

static bt_service_record_t setprop_srvc_record_val =  {
	.uuid = { {0x00} },
	.channel = 12,
	.name = "bt_name",
};

static bt_property_t setprop_srvc_record_prop = {
	.type = BT_PROPERTY_SERVICE_RECORD,
	.val = &setprop_srvc_record_val,
	.len = sizeof(setprop_srvc_record_val),
};

static struct step bluetooth_setprop_srvc_record_fail_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_FAIL,
		.set_data = &setprop_srvc_record_prop,
		.action = bt_set_property_action,
	},
};
static struct test_case bluetooth_setprop_srvc_record_fail_tc = {
	.step = bluetooth_setprop_srvc_record_fail_steps,
	.title = "Bluetooth Set SERVICE_RECORD - Fail",
	.step_num = get_test_case_step_num(
				bluetooth_setprop_srvc_record_fail_steps),
};

static bt_bdaddr_t setprop_bdaddr_val = {
	.address = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

static bt_property_t setprop_bdaddr_prop = {
	.type = BT_PROPERTY_BDADDR,
	.val = &setprop_bdaddr_val,
	.len = sizeof(setprop_bdaddr_val),
};

static struct step bluetooth_setprop_bdaddr_fail_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_FAIL,
		.set_data = &setprop_bdaddr_prop,
		.action = bt_set_property_action,
	},
};
static struct test_case bluetooth_setprop_bdaddr_fail_tc = {
	.step = bluetooth_setprop_bdaddr_fail_steps,
	.title = "Bluetooth Set BDADDR - Fail",
	.step_num = get_test_case_step_num(
				bluetooth_setprop_bdaddr_fail_steps),
};

static bt_bdaddr_t setprop_bonded_dev_val = {
	.address = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
};

static bt_property_t setprop_bonded_dev_prop = {
	.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.val = &setprop_bonded_dev_val,
	.len = sizeof(setprop_bonded_dev_val),
};

static struct step bluetooth_setprop_bonded_dev_fail_steps[] = {
	{
		.action_result.status = BT_STATUS_SUCCESS,
		.action = bluetooth_enable_action,
	},
	{
		.callback = CB_BT_ADAPTER_STATE_CHANGED,
		.callback_result.state = BT_STATE_ON,
	},
	{
		.action_result.status = BT_STATUS_FAIL,
		.set_data = &setprop_bonded_dev_prop,
		.action = bt_set_property_action,
	},
};
static struct test_case bluetooth_setprop_bonded_dev_fail_tc = {
	.step = bluetooth_setprop_bonded_dev_fail_steps,
	.title = "Bluetooth Set BONDED_DEVICES - Fail",
	.step_num = get_test_case_step_num(
				bluetooth_setprop_bonded_dev_fail_steps),
};

static bt_scan_mode_t setprop_scan_mode_conn_val = BT_SCAN_MODE_CONNECTABLE;

static bt_property_t setprop_scan_mode_conn_prop = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &setprop_scan_mode_conn_val,
	.len = sizeof(setprop_scan_mode_conn_val),
};

static struct step bluetooth_setprop_scan_mode_conn_success_steps[] = {
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
		.set_data = &setprop_scan_mode_conn_prop,
		.action = bt_set_property_action,
	},
	{
		.callback = CB_BT_ADAPTER_PROPERTIES,
		.callback_result.properties = &setprop_scan_mode_conn_prop,
		.callback_result.num_properties = 1,
	},
};
static struct test_case bluetooth_setprop_scan_mode_conn_success_tc = {
	.step = bluetooth_setprop_scan_mode_conn_success_steps,
	.title = "Bluetooth Set SCAN_MODE_CONNECTABLE - SUCCESS",
	.step_num = get_test_case_step_num(
				bluetooth_setprop_scan_mode_conn_success_steps),
};

static struct test_case *test_cases[] = {
	&bluetooth_init,
	&bluetooth_enable_success_tc,
	&bluetooth_enable_success2_tc,
	&bluetooth_disable_success_tc,
	&bluetooth_setprop_bdname_success_tc,
	&bluetooth_setprop_scanmode_success_tc,
	&bluetooth_setprop_disctimeout_success_tc,
	&bluetooth_getprop_bdaddr_success_tc,
	&bluetooth_getprop_bdname_success_tc,
	&bluetooth_setprop_uuid_fail_tc,
	&bluetooth_setprop_cod_fail_tc,
	&bluetooth_setprop_tod_fail_tc,
	&bluetooth_setprop_remote_rssi_fail_tc,
	&bluetooth_setprop_srvc_record_fail_tc,
	&bluetooth_setprop_bdaddr_fail_tc,
	&bluetooth_setprop_bonded_dev_fail_tc,
	&bluetooth_setprop_scan_mode_conn_success_tc,
};

struct queue *get_bluetooth_tests(void)
{
	uint16_t i = 0;

	list = queue_new();

	for (; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		if (!queue_push_tail(list, test_cases[i]))
			return NULL;

	return list;
}

void remove_bluetooth_tests(void)
{
	queue_destroy(list, NULL);
}
