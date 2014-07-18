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

static bt_bdaddr_t emu_bdaddr_val = {
	.address = { 0x00, 0xaa, 0x01, 0x00, 0x00, 0x00 },
};
static bt_property_t prop_emu_bdaddr = {
	.type = BT_PROPERTY_BDADDR,
	.val = &emu_bdaddr_val,
	.len = sizeof(emu_bdaddr_val),
};

static const char emu_bdname_val[] = "BlueZ for Android";
static bt_property_t prop_emu_bdname = {
	.type = BT_PROPERTY_BDNAME,
	.val = &emu_bdname_val,
	.len = sizeof(emu_bdname_val) - 1,
};

static const char emu_uuids_val[] = {
	/* Multi profile UUID */
	0x00, 0x00, 0x11, 0x3b, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
					0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
	/* Device identification profile UUID */
	0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
					0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB,
};
static bt_property_t prop_emu_uuids = {
	.type = BT_PROPERTY_UUIDS,
	.val = &emu_uuids_val,
	.len = sizeof(emu_uuids_val),
};

static uint32_t emu_cod_val = 0x00020c;
static bt_property_t prop_emu_cod = {
	.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.val = &emu_cod_val,
	.len = sizeof(emu_cod_val),
};

static bt_device_type_t emu_tod_val = BT_DEVICE_DEVTYPE_DUAL;
static bt_property_t prop_emu_tod = {
	.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.val = &emu_tod_val,
	.len = sizeof(emu_tod_val),
};

static bt_scan_mode_t emu_scan_mode_val = BT_SCAN_MODE_NONE;
static bt_property_t prop_emu_scan_mode = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &emu_scan_mode_val,
	.len = sizeof(emu_scan_mode_val),
};

static uint32_t emu_disc_timeout_val = 120;
static bt_property_t prop_emu_disc_timeout = {
	.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.val = &emu_disc_timeout_val,
	.len = sizeof(emu_disc_timeout_val),
};

static bt_property_t prop_emu_bonded_devs = {
	.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.val = NULL,
	.len = 0,
};

static uint32_t emu_remote_type_val = BT_DEVICE_DEVTYPE_BLE;
static int32_t emu_remote_rssi_val = 127;
static bt_bdaddr_t emu_remote_bdaddr_val = {
	.address = { 0x00, 0xaa, 0x01, 0x01, 0x00, 0x00 },
};
static const char emu_remote_bdname_val[] = "00:AA:01:01:00:00";
static uint32_t emu_remote_cod_val = 0;

static bt_property_t prop_emu_default_set[] = {
	{ BT_PROPERTY_BDADDR, sizeof(emu_bdaddr_val), NULL },
	{ BT_PROPERTY_BDNAME, sizeof(emu_bdname_val) - 1, &emu_bdname_val },
	{ BT_PROPERTY_CLASS_OF_DEVICE, sizeof(uint32_t), NULL },
	{ BT_PROPERTY_TYPE_OF_DEVICE, sizeof(emu_tod_val), &emu_tod_val },
	{ BT_PROPERTY_ADAPTER_SCAN_MODE, sizeof(emu_scan_mode_val),
							&emu_scan_mode_val },
	{ BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT, sizeof(emu_disc_timeout_val),
							&emu_disc_timeout_val},
	{ BT_PROPERTY_ADAPTER_BONDED_DEVICES, 0, NULL },
	{ BT_PROPERTY_UUIDS, sizeof(emu_uuids_val), &emu_uuids_val },
};

static bt_property_t prop_emu_ble_remotes_default_set[] = {
	{ BT_PROPERTY_BDADDR, sizeof(emu_remote_bdaddr_val),
						&emu_remote_bdaddr_val },
	{ BT_PROPERTY_TYPE_OF_DEVICE, sizeof(emu_remote_type_val),
							&emu_remote_type_val },
	{ BT_PROPERTY_REMOTE_RSSI, sizeof(emu_remote_rssi_val),
							&emu_remote_rssi_val },
};

static bt_property_t prop_emu_ble_remotes_query_set[] = {
	{ BT_PROPERTY_TYPE_OF_DEVICE, sizeof(emu_remote_type_val),
							&emu_remote_type_val },
	{ BT_PROPERTY_CLASS_OF_DEVICE, sizeof(emu_remote_cod_val),
							&emu_remote_cod_val },
	{ BT_PROPERTY_REMOTE_RSSI, sizeof(emu_remote_rssi_val),
							&emu_remote_rssi_val },
	{ BT_PROPERTY_BDNAME, sizeof(emu_remote_bdname_val) - 1,
						&emu_remote_bdname_val },
	{ BT_PROPERTY_UUIDS, 0, NULL },
	{ BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP, 4, NULL },
};

static char test_bdname[] = "test_bdname";
static bt_property_t prop_test_bdname = {
	.type = BT_PROPERTY_BDNAME,
	.val = test_bdname,
	.len = sizeof(test_bdname) - 1,
};

static bt_scan_mode_t test_scan_mode_connectable_discoverable =
					BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
static bt_property_t prop_test_scanmode_conn_discov = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &test_scan_mode_connectable_discoverable,
	.len = sizeof(bt_scan_mode_t),
};

static uint32_t test_disctimeout_val = 600;
static bt_property_t prop_test_disctimeout = {
	.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.val = &test_disctimeout_val,
	.len = sizeof(test_disctimeout_val),
};

static unsigned char test_uuids_val[] = { 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00,
			0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00 };
static bt_property_t prop_test_uuid = {
	.type = BT_PROPERTY_UUIDS,
	.val = &test_uuids_val,
	.len = sizeof(test_uuids_val),
};

static uint32_t test_cod_val = 0;
static bt_property_t prop_test_cod = {
	.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.val = &test_cod_val,
	.len = sizeof(test_cod_val),
};

static uint32_t test_tod_val = BT_DEVICE_DEVTYPE_BLE;
static bt_property_t prop_test_tod = {
	.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.val = &test_tod_val,
	.len = sizeof(test_tod_val),
};

static int32_t test_remote_rssi_val = -9;
static bt_property_t prop_test_remote_rssi = {
	.type = BT_PROPERTY_REMOTE_RSSI,
	.val = &test_remote_rssi_val,
	.len = sizeof(test_remote_rssi_val),
};

static bt_service_record_t test_srvc_record_val =  {
	.uuid = { {0x00} },
	.channel = 12,
	.name = "bt_name",
};
static bt_property_t prop_test_srvc_record = {
	.type = BT_PROPERTY_SERVICE_RECORD,
	.val = &test_srvc_record_val,
	.len = sizeof(test_srvc_record_val),
};

static bt_bdaddr_t test_bdaddr_val = {
	.address = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};
static bt_property_t prop_test_bdaddr = {
	.type = BT_PROPERTY_BDADDR,
	.val = &test_bdaddr_val,
	.len = sizeof(test_bdaddr_val),
};

static bt_scan_mode_t setprop_scan_mode_conn_val = BT_SCAN_MODE_CONNECTABLE;

static bt_property_t prop_test_scan_mode_conn = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &setprop_scan_mode_conn_val,
	.len = sizeof(setprop_scan_mode_conn_val),
};

static bt_scan_mode_t test_scan_mode_none_val = BT_SCAN_MODE_NONE;
static bt_property_t prop_test_scan_mode_none = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &test_scan_mode_none_val,
	.len = sizeof(test_scan_mode_none_val),
};

static bt_bdaddr_t test_bonded_dev_addr_val = {
	.address = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
};
static bt_property_t prop_test_bonded_dev_addr = {
	.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.val = &test_bonded_dev_addr_val,
	.len = sizeof(test_bonded_dev_addr_val),
};

static struct test_case test_cases[] = {
	TEST_CASE("Bluetooth Init",
		ACTION_SUCCESS(dummy_action, NULL),
	),
	TEST_CASE("Bluetooth Enable - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_ADAPTER_PROPS(prop_emu_default_set, 8),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
	),
	TEST_CASE("Bluetooth Enable - Success 2",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_ADAPTER_PROPS(prop_emu_default_set, 8),
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
		ACTION_SUCCESS(bt_set_property_action, &prop_test_bdname),
		CALLBACK_ADAPTER_PROPS(&prop_test_bdname, 1),
	),
	TEST_CASE("Bluetooth Set SCAN_MODE - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action,
					&prop_test_scanmode_conn_discov),
		CALLBACK_ADAPTER_PROPS(&prop_test_scanmode_conn_discov, 1),
	),
	TEST_CASE("Bluetooth Set DISCOVERY_TIMEOUT - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action, &prop_test_disctimeout),
		CALLBACK_ADAPTER_PROPS(&prop_test_disctimeout, 1),
	),
	TEST_CASE("Bluetooth Get BDADDR - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &prop_emu_bdaddr),
		CALLBACK_ADAPTER_PROPS(&prop_emu_bdaddr, 1),
	),
	TEST_CASE("Bluetooth Get BDNAME - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &prop_emu_bdname),
		CALLBACK_ADAPTER_PROPS(&prop_emu_bdname, 1),
	),
	TEST_CASE("Bluetooth Set UUID - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &prop_test_uuid),
	),
	TEST_CASE("Bluetooth Set CLASS_OF_DEVICE - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &prop_test_cod),
	),
	TEST_CASE("Bluetooth Set TYPE_OF_DEVICE - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &prop_test_tod),
	),
	TEST_CASE("Bluetooth Set REMOTE_RSSI - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &prop_test_remote_rssi),
	),
	TEST_CASE("Bluetooth Set SERVICE_RECORD - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &prop_test_srvc_record),
	),
	TEST_CASE("Bluetooth Set BDADDR - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &prop_test_bdaddr),
	),
	TEST_CASE("Bluetooth Set SCAN_MODE_CONNECTABLE - SUCCESS",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action,
						&prop_test_scan_mode_conn),
		CALLBACK_ADAPTER_PROPS(&prop_test_scan_mode_conn, 1),
	),
	TEST_CASE("Bluetooth Set BONDED_DEVICES - Fail",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_FAIL(bt_set_property_action, &prop_test_bonded_dev_addr),
	),
	TEST_CASE("Bluetooth Get CLASS_OF_DEVICE - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &prop_emu_cod),
		CALLBACK_ADAPTER_PROPS(&prop_emu_cod, 1),
	),
	TEST_CASE("Bluetooth Get TYPE_OF_DEVICE - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &prop_emu_tod),
		CALLBACK_ADAPTER_PROPS(&prop_emu_tod, 1),
	),
	TEST_CASE("Bluetooth Get SCAN_MODE - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &prop_emu_scan_mode),
		CALLBACK_ADAPTER_PROPS(&prop_emu_scan_mode, 1),
	),
	TEST_CASE("Bluetooth Get DISCOVERY_TIMEOUT - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &prop_emu_disc_timeout),
		CALLBACK_ADAPTER_PROPS(&prop_emu_disc_timeout, 1),
	),
	TEST_CASE("Bluetooth Get UUIDS - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &prop_emu_uuids),
		CALLBACK_ADAPTER_PROPS(&prop_emu_uuids, 1),
	),
	TEST_CASE("Bluetooth Get BONDED_DEVICES - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_get_property_action, &prop_emu_bonded_devs),
		CALLBACK_ADAPTER_PROPS(&prop_emu_bonded_devs, 1),
	),
	TEST_CASE("Bluetooth Set SCAN_MODE - Success 2",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_set_property_action,
						&prop_test_scan_mode_none),
		CALLBACK_ADAPTER_PROPS(&prop_test_scan_mode_none, 1),
	),
	TEST_CASE("Bluetooth BR/EDR Discovery Start - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_start_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STARTED),
	),
	TEST_CASE("Bluetooth BR/EDR Discovery Start - Done",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_start_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STARTED),
		ACTION_SUCCESS(bt_start_discovery_action, NULL),
	),
	TEST_CASE("Bluetooth BR/EDR Discovery Stop - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_start_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STARTED),
		ACTION_SUCCESS(bt_cancel_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STOPPED),
	),
	TEST_CASE("Bluetooth BR/EDR Discovery Stop - Done",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(bt_start_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STARTED),
		ACTION_SUCCESS(bt_cancel_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STOPPED),
		ACTION_SUCCESS(bt_start_discovery_action, NULL),
	),
	TEST_CASE("Bluetooth BR/EDR Discovery Device Found",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(bt_start_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STARTED),
		CALLBACK_DEVICE_FOUND(prop_emu_ble_remotes_default_set, 3),
		ACTION_SUCCESS(bt_cancel_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STOPPED),
	),
	TEST_CASE("Bluetooth Device Get Props - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(bt_start_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STARTED),
		ACTION_SUCCESS(bt_cancel_discovery_action, NULL),
		CALLBACK_STATE(CB_BT_DISCOVERY_STATE_CHANGED,
							BT_DISCOVERY_STOPPED),
		ACTION_SUCCESS(bt_get_device_props_action,
							&emu_remote_bdaddr_val),
		CALLBACK_DEVICE_PROPS(prop_emu_ble_remotes_query_set, 6),
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
