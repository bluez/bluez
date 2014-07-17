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

static char test_set_bdname[] = "test_bdname_set";

static bt_property_t setprop_bdname_prop = {
	.type = BT_PROPERTY_BDNAME,
	.val = test_set_bdname,
	.len = sizeof(test_set_bdname) - 1,
};

static bt_scan_mode_t test_setprop_scanmode_val =
					BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;

static bt_property_t setprop_scanmode_prop = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &test_setprop_scanmode_val,
	.len = sizeof(bt_scan_mode_t),
};

static uint32_t test_setprop_disctimeout_val = 600;

static bt_property_t setprop_disctimeout_prop = {
	.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.val = &test_setprop_disctimeout_val,
	.len = sizeof(test_setprop_disctimeout_val),
};

static bt_bdaddr_t test_getprop_bdaddr_val = {
	{0x00, 0xaa, 0x01, 0x00, 0x00, 0x00},
};

static bt_property_t getprop_bdaddr_prop = {
	.type = BT_PROPERTY_BDADDR,
	.val = &test_getprop_bdaddr_val,
	.len = sizeof(test_getprop_bdaddr_val),
};

static const char test_getprop_bdname_val[] = "BlueZ for Android";

static bt_property_t getprop_bdname_prop = {
	.type = BT_PROPERTY_BDNAME,
	.val = &test_getprop_bdname_val,
	.len = sizeof(test_getprop_bdname_val) - 1,
};

static unsigned char setprop_uuids[] = { 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00,
			0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00 };

static bt_property_t setprop_uuid_prop = {
	.type = BT_PROPERTY_UUIDS,
	.val = &setprop_uuids,
	.len = sizeof(setprop_uuids),
};

static uint32_t setprop_cod_val = 0;

static bt_property_t setprop_cod_prop = {
	.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.val = &setprop_cod_val,
	.len = sizeof(setprop_cod_val),
};

static uint32_t setprop_tod_val = BT_DEVICE_DEVTYPE_DUAL;

static bt_property_t setprop_tod_prop = {
	.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.val = &setprop_tod_val,
	.len = sizeof(setprop_tod_val),
};

static int32_t setprop_remote_rssi_val = -9;

static bt_property_t setprop_remote_rssi_prop = {
	.type = BT_PROPERTY_REMOTE_RSSI,
	.val = &setprop_remote_rssi_val,
	.len = sizeof(setprop_remote_rssi_val),
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

static bt_bdaddr_t setprop_bdaddr_val = {
	.address = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

static bt_property_t setprop_bdaddr_prop = {
	.type = BT_PROPERTY_BDADDR,
	.val = &setprop_bdaddr_val,
	.len = sizeof(setprop_bdaddr_val),
};

static bt_bdaddr_t setprop_bonded_dev_val = {
	.address = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
};

static bt_property_t setprop_bonded_dev_prop = {
	.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.val = &setprop_bonded_dev_val,
	.len = sizeof(setprop_bonded_dev_val),
};

static bt_scan_mode_t setprop_scan_mode_conn_val = BT_SCAN_MODE_CONNECTABLE;

static bt_property_t setprop_scan_mode_conn_prop = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &setprop_scan_mode_conn_val,
	.len = sizeof(setprop_scan_mode_conn_val),
};

static uint32_t test_getprop_cod_val = 0x00020c;

static bt_property_t getprop_cod_prop = {
	.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.val = &test_getprop_cod_val,
	.len = sizeof(test_getprop_cod_val),
};

static bt_device_type_t test_getprop_tod_val = BT_DEVICE_DEVTYPE_DUAL;

static bt_property_t getprop_tod_prop = {
	.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.val = &test_getprop_tod_val,
	.len = sizeof(test_getprop_tod_val),
};

static bt_scan_mode_t test_getprop_scan_mode_val = BT_SCAN_MODE_NONE;

static bt_property_t getprop_scan_mode_prop = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &test_getprop_scan_mode_val,
	.len = sizeof(test_getprop_scan_mode_val),
};

static uint32_t test_getprop_disc_timeout_val = 120;

static bt_property_t getprop_disc_timeout_prop = {
	.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.val = &test_getprop_disc_timeout_val,
	.len = sizeof(test_getprop_disc_timeout_val),
};

static const char test_getprop_uuids_val[] = {
	/* Multi profile UUID */
	0x00, 0x00, 0x11, 0x3b, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
					0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
	/* Device identification profile UUID */
	0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
					0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
};

static bt_property_t getprop_uuids_prop = {
	.type = BT_PROPERTY_UUIDS,
	.val = &test_getprop_uuids_val,
	.len = sizeof(test_getprop_uuids_val),
};

static bt_property_t getprop_bonded_devs_prop = {
	.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.val = NULL,
	.len = 0,
};

static bt_scan_mode_t test_setprop_scanmode_val2 = BT_SCAN_MODE_NONE;

static bt_property_t setprop_scan_mode2_prop = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &test_setprop_scanmode_val2,
	.len = sizeof(test_setprop_scanmode_val2),
};

static struct test_case test_cases[] = {
	TEST_CASE("Bluetooth Init",
		ACTION_SUCCESS(dummy_action, NULL),
	),
	TEST_CASE("Bluetooth Enable - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_ADAPTER_PROPS(enable_props, 8),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
	),
	TEST_CASE("Bluetooth Enable - Success 2",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_ADAPTER_PROPS(enable_props, 8),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
	),
	TEST_CASE("Bluetooth Disable - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE("Bluetooth Set BDNAME - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action, &setprop_bdname_prop),
		CALLBACK_ADAPTER_PROPS(&setprop_bdname_prop, 1),
	),
	TEST_CASE("Bluetooth Set SCAN_MODE - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action, &setprop_scanmode_prop),
		CALLBACK_ADAPTER_PROPS(&setprop_scanmode_prop, 1),
	),
	TEST_CASE("Bluetooth Set DISCOVERY_TIMEOUT - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action,
						&setprop_disctimeout_prop),
		CALLBACK_ADAPTER_PROPS(&setprop_disctimeout_prop, 1),
	),
	TEST_CASE("Bluetooth Get BDADDR - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &getprop_bdaddr_prop),
		CALLBACK_ADAPTER_PROPS(&getprop_bdaddr_prop, 1),
	),
	TEST_CASE("Bluetooth Get BDNAME - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &getprop_bdname_prop),
		CALLBACK_ADAPTER_PROPS(&getprop_bdname_prop, 1),
	),
	TEST_CASE("Bluetooth Set UUID - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &setprop_uuid_prop),
	),
	TEST_CASE("Bluetooth Set CLASS_OF_DEVICE - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &setprop_cod_prop),
	),
	TEST_CASE("Bluetooth Set TYPE_OF_DEVICE - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &setprop_tod_prop),
	),
	TEST_CASE("Bluetooth Set REMOTE_RSSI - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &setprop_remote_rssi_prop),
	),
	TEST_CASE("Bluetooth Set SERVICE_RECORD - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &setprop_srvc_record_prop),
	),
	TEST_CASE("Bluetooth Set BDADDR - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &setprop_bdaddr_prop),
	),
	TEST_CASE("Bluetooth Set SCAN_MODE_CONNECTABLE - SUCCESS",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action,
						&setprop_scan_mode_conn_prop),
		CALLBACK_ADAPTER_PROPS(&setprop_scan_mode_conn_prop, 1),
	),
	TEST_CASE("Bluetooth Set BONDED_DEVICES - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &setprop_bonded_dev_prop),
	),
	TEST_CASE("Bluetooth Get CLASS_OF_DEVICE - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &getprop_cod_prop),
		CALLBACK_ADAPTER_PROPS(&getprop_cod_prop, 1),
	),
	TEST_CASE("Bluetooth Get TYPE_OF_DEVICE - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &getprop_tod_prop),
		CALLBACK_ADAPTER_PROPS(&getprop_tod_prop, 1),
	),
	TEST_CASE("Bluetooth Get SCAN_MODE - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &getprop_scan_mode_prop),
		CALLBACK_ADAPTER_PROPS(&getprop_scan_mode_prop, 1),
	),
	TEST_CASE("Bluetooth Get DISCOVERY_TIMEOUT - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action,
						&getprop_disc_timeout_prop),
		CALLBACK_ADAPTER_PROPS(&getprop_disc_timeout_prop, 1),
	),
	TEST_CASE("Bluetooth Get BONDED_DEVICES - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &getprop_uuids_prop),
		CALLBACK_ADAPTER_PROPS(&getprop_uuids_prop, 1),
	),
	TEST_CASE("Bluetooth Get BONDED_DEVICES - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action,
						&getprop_bonded_devs_prop),
		CALLBACK_ADAPTER_PROPS(&getprop_bonded_devs_prop, 1),
	),
	TEST_CASE("Bluetooth Set SCAN_MODE - Success 2",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action,
						&setprop_scan_mode2_prop),
		CALLBACK_ADAPTER_PROPS(&setprop_scan_mode2_prop, 1),
	),
};

struct queue *get_bluetooth_tests(void)
{
	uint16_t i = 0;

	list = queue_new();

	for (; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		if (!queue_push_tail(list, &test_cases[i]))
			return NULL;

	return list;
}

void remove_bluetooth_tests(void)
{
	queue_destroy(list, NULL);
}
