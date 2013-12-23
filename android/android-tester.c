/*
 * Copyright (C) 2013 Intel Corporation
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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <libgen.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

#include "emulator/bthost.h"
#include "monitor/bt.h"

#include <hardware/hardware.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>

#include "utils.h"

struct generic_data {
	int expected_adapter_status;
	uint32_t expect_settings_set;
	int expected_cb_count;
	bt_property_t set_property;
	bt_property_t expected_property;
	bt_callbacks_t expected_hal_cb;
};

struct socket_data {
	btsock_type_t sock_type;
	const char *service_name;
	const uint8_t *service_uuid;
	const bt_bdaddr_t *bdaddr;
	int channel;
	int flags;
	bt_status_t expected_status;
	bool test_channel;
};

#define WAIT_FOR_SIGNAL_TIME 2 /* in seconds */
#define EMULATOR_SIGNAL "emulator_started"

#define BT_STATUS_NOT_EXPECTED	-1

struct test_data {
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	unsigned int mgmt_settings_id;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	const void *test_data;
	pid_t bluetoothd_pid;

	struct hw_device_t *device;
	const bt_interface_t *if_bluetooth;
	const btsock_interface_t *if_sock;

	bool mgmt_settings_set;
	bool cb_count_checked;
	bool status_checked;
	bool property_checked;

	/* Set to true if test conditions are initialized */
	bool test_init_done;

	int cb_count;
};

static char exec_dir[PATH_MAX + 1];

static void test_update_state(void)
{
	struct test_data *data = tester_get_data();

	if (!(data->cb_count_checked))
		return;
	if (!(data->mgmt_settings_set))
		return;
	if (!(data->status_checked))
		return;
	if (!(data->property_checked))
		return;
	tester_test_passed();
}

static void test_device_property(bt_property_t *property,
			bt_property_type_t type, const void *value, int len)
{
	if (value == NULL) {
		tester_warn("NULL property passed");
		tester_test_failed();
		return;
	}

	if (property->type != type) {
		tester_warn("Wrong remote property type %d, expected %d",
							type, property->type);
		tester_test_failed();
		return;
	}

	if (property->len != len) {
		tester_warn("Wrong remote property len %d, expected %d",
							len, property->len);
		tester_test_failed();
		return;
	}

	if (memcmp(property->val, value, len)) {
		tester_warn("Wrong remote property value");
		tester_test_failed();
	}
}

static void test_mgmt_settings_set(struct test_data *data)
{
	data->mgmt_settings_set = true;

	test_update_state();
}

static void command_generic_new_settings(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test_data = data->test_data;
	uint32_t settings;

	if (length != 4) {
		tester_warn("Invalid parameter size for new settings event");
		tester_test_failed();
		return;
	}

	settings = bt_get_le32(param);

	if ((settings & test_data->expect_settings_set) !=
					test_data->expect_settings_set)
		return;

	test_mgmt_settings_set(data);
	mgmt_unregister(data->mgmt, data->mgmt_settings_id);
}

static void check_cb_count(void)
{
	struct test_data *data = tester_get_data();

	if (!data->test_init_done)
		return;

	if (data->cb_count == 0)
		data->cb_count_checked = true;

	test_update_state();
}

static void expected_cb_count_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;

	data->cb_count = test_data->expected_cb_count;

	check_cb_count();

}

static void mgmt_cb_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;

	if (!test_data->expect_settings_set)
		test_mgmt_settings_set(data);
	else
		data->mgmt_settings_id = mgmt_register(data->mgmt,
				MGMT_EV_NEW_SETTINGS, data->mgmt_index,
				command_generic_new_settings, NULL, NULL);
}

static void expected_status_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;

	if (test_data->expected_adapter_status == BT_STATUS_NOT_EXPECTED)
		data->status_checked = true;
}

static void test_property_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;

	if (!test_data->expected_property.type)
		data->property_checked = true;
}

static void init_test_conditions(struct test_data *data)
{
	data->test_init_done = true;

	expected_cb_count_init(data);
	mgmt_cb_init(data);
	expected_status_init(data);
	test_property_init(data);
}

static void check_expected_status(uint8_t status)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test_data = data->test_data;

	if (test_data->expected_adapter_status == status)
		data->status_checked = true;
	else
		tester_test_failed();

	test_update_state();
}

static bool check_test_property(bt_property_t received_prop,
						bt_property_t expected_prop)
{
	struct test_data *data = tester_get_data();

	if (expected_prop.type && (expected_prop.type != received_prop.type))
		return false;
	if (expected_prop.len && (expected_prop.len != received_prop.len))
		return false;
	if (expected_prop.val && memcmp(expected_prop.val, received_prop.val,
							expected_prop.len))
		return false;

	return data->property_checked = true;
}

static void read_info_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_info *rp = param;
	char addr[18];
	uint16_t manufacturer;
	uint32_t supported_settings, current_settings;

	tester_print("Read Info callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	ba2str(&rp->bdaddr, addr);
	manufacturer = btohs(rp->manufacturer);
	supported_settings = btohl(rp->supported_settings);
	current_settings = btohl(rp->current_settings);

	tester_print("  Address: %s", addr);
	tester_print("  Version: 0x%02x", rp->version);
	tester_print("  Manufacturer: 0x%04x", manufacturer);
	tester_print("  Supported settings: 0x%08x", supported_settings);
	tester_print("  Current settings: 0x%08x", current_settings);
	tester_print("  Class: 0x%02x%02x%02x",
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	tester_print("  Name: %s", rp->name);
	tester_print("  Short name: %s", rp->short_name);

	if (strcmp(hciemu_get_address(data->hciemu), addr)) {
		tester_pre_setup_failed();
		return;
	}

	tester_pre_setup_complete();
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Added callback");
	tester_print("  Index: 0x%04x", index);

	data->mgmt_index = index;

	mgmt_send(data->mgmt, MGMT_OP_READ_INFO, data->mgmt_index, 0, NULL,
					read_info_callback, NULL, NULL);
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Removed callback");
	tester_print("  Index: 0x%04x", index);

	if (index != data->mgmt_index)
		return;

	mgmt_unregister_index(data->mgmt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	tester_post_teardown_complete();
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Read Index List callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new(data->hciemu_type);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
		return;
	}

	tester_print("New hciemu instance created");
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (!tester_use_debug())
		fclose(stderr);

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0,
				NULL, read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void bluetoothd_start(int hci_index)
{
	char prg_name[PATH_MAX + 1];
	char index[8];
	char *prg_argv[4];

	snprintf(prg_name, sizeof(prg_name), "%s/%s", exec_dir, "bluetoothd");
	snprintf(index, sizeof(index), "%d", hci_index);

	prg_argv[0] = prg_name;
	prg_argv[1] = "-i";
	prg_argv[2] = index;
	prg_argv[3] = NULL;

	if (!tester_use_debug())
		fclose(stderr);

	execve(prg_argv[0], prg_argv, NULL);
}

static void emulator(int pipe, int hci_index)
{
	static const char SYSTEM_SOCKET_PATH[] = "\0android_system";
	char buf[1024];
	struct sockaddr_un addr;
	struct timeval tv;
	int fd;
	ssize_t len;

	fd = socket(PF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		goto failed;

	tv.tv_sec = WAIT_FOR_SIGNAL_TIME;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SYSTEM_SOCKET_PATH, sizeof(SYSTEM_SOCKET_PATH));

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind system socket");
		goto failed;
	}

	len = write(pipe, EMULATOR_SIGNAL, sizeof(EMULATOR_SIGNAL));
	if (len != sizeof(EMULATOR_SIGNAL))
		goto failed;

	memset(buf, 0, sizeof(buf));

	len = read(fd, buf, sizeof(buf));
	if (len <= 0 || (strcmp(buf, "ctl.start=bluetoothd")))
		goto failed;

	close(pipe);
	close(fd);
	bluetoothd_start(hci_index);

failed:
	close(pipe);

	if (fd >= 0)
		close(fd);
}

static void emu_connectable_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	switch (opcode) {
	case BT_HCI_CMD_WRITE_SCAN_ENABLE:
	case BT_HCI_CMD_LE_SET_ADV_ENABLE:
		break;
	default:
		return;
	}

	tester_print("Emulated remote set connectable status 0x%02x", status);

	if (status)
		tester_setup_failed();
	else
		tester_setup_complete();
}

static void setup_powered_emulated_remote(void)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	tester_print("Controller powered on");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_cmd_complete_cb(bthost, emu_connectable_complete, data);

	if (data->hciemu_type == HCIEMU_TYPE_LE)
		bthost_set_adv_enable(bthost, 0x01);
	else
		bthost_write_scan_enable(bthost, 0x03);
}

static void enable_success_cb(bt_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_STATE_ON) {
		setup_powered_emulated_remote();
		data->cb_count--;
	}
}

static void disable_success_cb(bt_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_STATE_OFF)
		data->cb_count--;
}

static void adapter_state_changed_cb(bt_state_t state)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (data->test_init_done &&
			test->expected_hal_cb.adapter_state_changed_cb) {
		test->expected_hal_cb.adapter_state_changed_cb(state);
		check_cb_count();
		return;
	}

	if (!data->test_init_done && state == BT_STATE_ON)
		setup_powered_emulated_remote();
}

static void discovery_start_success_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_DISCOVERY_STARTED)
		data->cb_count--;
}

static void discovery_start_done_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	status = data->if_bluetooth->start_discovery();
	data->cb_count--;
	check_expected_status(status);
}

static void discovery_stop_success_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	if (state == BT_DISCOVERY_STARTED && data->cb_count == 2) {
		status = data->if_bluetooth->cancel_discovery();
		check_expected_status(status);
		data->cb_count--;
		return;
	}
	if (state == BT_DISCOVERY_STOPPED && data->cb_count == 1)
		data->cb_count--;
}

static void discovery_device_found_state_changed_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_DISCOVERY_STARTED && data->cb_count == 3) {
		data->cb_count--;
		return;
	}
	if (state == BT_DISCOVERY_STOPPED && data->cb_count == 1)
		data->cb_count--;
}

static void discovery_state_changed_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (test && test->expected_hal_cb.discovery_state_changed_cb) {
		test->expected_hal_cb.discovery_state_changed_cb(state);
		check_cb_count();
	}
}

static void discovery_device_found_cb(int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	const uint8_t *remote_bdaddr =
					hciemu_get_client_bdaddr(data->hciemu);
	const uint32_t emu_remote_type = BT_DEVICE_DEVTYPE_BREDR;
	const int32_t emu_remote_rssi = -60;
	bt_bdaddr_t emu_remote_bdaddr;
	int i;

	data->cb_count--;

	if (num_properties < 1)
		tester_test_failed();

	bdaddr2android((const bdaddr_t *) remote_bdaddr, &emu_remote_bdaddr);

	for (i = 0; i < num_properties; i++) {
		int prop_len;
		const void *prop_data;

		switch (properties[i].type) {
		case BT_PROPERTY_BDADDR:
			prop_len = sizeof(emu_remote_bdaddr);
			prop_data = &emu_remote_bdaddr;

			break;
		case BT_PROPERTY_TYPE_OF_DEVICE:
			prop_len = sizeof(emu_remote_type);
			prop_data = &emu_remote_type;

			break;
		case BT_PROPERTY_REMOTE_RSSI:
			prop_len = sizeof(emu_remote_rssi);
			prop_data = &emu_remote_rssi;

			break;
		default:
			prop_len = 0;
			prop_data = NULL;

			break;
		}

		test_device_property(&properties[i], properties[i].type,
							prop_data, prop_len);
	}
}

static void device_found_cb(int num_properties, bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (data->test_init_done && test->expected_hal_cb.device_found_cb) {
		test->expected_hal_cb.device_found_cb(num_properties,
								properties);
		check_cb_count();
	}
}

static void check_count_properties_cb(bt_status_t status, int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();

	data->cb_count--;
}

static void getprop_success_cb(bt_status_t status, int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (check_test_property(properties[0], test->expected_property))
		data->cb_count--;
}

static void adapter_properties_cb(bt_status_t status, int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (data->test_init_done &&
				test->expected_hal_cb.adapter_properties_cb) {
		test->expected_hal_cb.adapter_properties_cb(
							status, num_properties,
							properties);
		check_cb_count();
	}
}

static const struct generic_data bluetooth_enable_success_test = {
	.expected_hal_cb.adapter_state_changed_cb = enable_success_cb,
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_cb_count = 9,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bluetooth_enable_done_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_cb_count = 8,
	.expected_adapter_status = BT_STATUS_DONE,
};

static const struct generic_data bluetooth_disable_success_test = {
	.expected_hal_cb.adapter_state_changed_cb = disable_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static char test_set_bdname[] = "test_bdname_set";

static const struct generic_data bluetooth_setprop_bdname_success_test = {
	.expected_hal_cb.adapter_properties_cb = getprop_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_BDNAME,
	.expected_property.val = test_set_bdname,
	.expected_property.len = sizeof(test_set_bdname) - 1,
};

static bt_scan_mode_t test_setprop_scanmode_val =
					BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;

static const struct generic_data bluetooth_setprop_scanmode_success_test = {
	.expected_hal_cb.adapter_properties_cb = getprop_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.expected_property.val = &test_setprop_scanmode_val,
	.expected_property.len = sizeof(bt_scan_mode_t),
};

static uint32_t test_setprop_disctimeout_val = 120;

static const struct generic_data bluetooth_setprop_disctimeout_success_test = {
	.expected_hal_cb.adapter_properties_cb = getprop_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.expected_property.val = &test_setprop_disctimeout_val,
	.expected_property.len = sizeof(test_setprop_disctimeout_val),
};

static const struct generic_data bluetooth_getprop_bdaddr_success_test = {
	.expected_hal_cb.adapter_properties_cb = getprop_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_BDADDR,
	.expected_property.val = NULL,
	.expected_property.len = sizeof(bt_bdaddr_t),
};

static char test_bdname[] = "test_bdname_setget";

static const struct generic_data bluetooth_getprop_bdname_success_test = {
	.expected_hal_cb.adapter_properties_cb = getprop_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_BDNAME,
	.expected_property.val = test_bdname,
	.expected_property.len = sizeof(test_bdname) - 1,
};

static unsigned char setprop_uuids[] = { 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00,
			0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00 };

static const struct generic_data bluetooth_setprop_uuid_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
	.set_property.type = BT_PROPERTY_UUIDS,
	.set_property.val = &setprop_uuids,
	.set_property.len = sizeof(setprop_uuids),
};

static uint32_t setprop_class_of_device = 0;

static const struct generic_data bluetooth_setprop_cod_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
	.set_property.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.set_property.val = &setprop_class_of_device,
	.set_property.len = sizeof(setprop_class_of_device),
};

static bt_device_type_t setprop_type_of_device = BT_DEVICE_DEVTYPE_BREDR;

static const struct generic_data bluetooth_setprop_tod_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
	.set_property.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.set_property.val = &setprop_type_of_device,
	.set_property.len = sizeof(setprop_type_of_device),
};

static int32_t setprop_remote_rssi = 0;

static const struct generic_data bluetooth_setprop_remote_rssi_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
	.set_property.type = BT_PROPERTY_REMOTE_RSSI,
	.set_property.val = &setprop_remote_rssi,
	.set_property.len = sizeof(setprop_remote_rssi),
};

static bt_service_record_t setprop_remote_service = {
	.uuid = { {0x00} },
	.channel = 12,
	.name = "bt_name",
};

static const struct generic_data
			bluetooth_setprop_service_record_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
	.set_property.type = BT_PROPERTY_SERVICE_RECORD,
	.set_property.val = &setprop_remote_service,
	.set_property.len = sizeof(setprop_remote_service),
};

static const struct generic_data bluetooth_discovery_start_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
						discovery_start_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bluetooth_discovery_start_done_test = {
	.expected_hal_cb.discovery_state_changed_cb = discovery_start_done_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_DONE,
};

static const struct generic_data bluetooth_discovery_stop_done_test = {
	.expected_adapter_status = BT_STATUS_DONE,
};

static const struct generic_data bluetooth_discovery_stop_success_test = {
	.expected_hal_cb.discovery_state_changed_cb = discovery_stop_success_cb,
	.expected_cb_count = 2,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bluetooth_discovery_device_found_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					discovery_device_found_state_changed_cb,
	.expected_hal_cb.device_found_cb = discovery_device_found_cb,
	.expected_cb_count = 3,
	.expected_adapter_status = BT_STATUS_NOT_EXPECTED,
};

static bt_callbacks_t bt_callbacks = {
	.size = sizeof(bt_callbacks),
	.adapter_state_changed_cb = adapter_state_changed_cb,
	.adapter_properties_cb = adapter_properties_cb,
	.remote_device_properties_cb = NULL,
	.device_found_cb = device_found_cb,
	.discovery_state_changed_cb = discovery_state_changed_cb,
	.pin_request_cb = NULL,
	.ssp_request_cb = NULL,
	.bond_state_changed_cb = NULL,
	.acl_state_changed_cb = NULL,
	.thread_evt_cb = NULL,
	.dut_mode_recv_cb = NULL,
	.le_test_mode_cb = NULL
};

static void setup(struct test_data *data)
{
	const hw_module_t *module;
	hw_device_t *device;
	int signal_fd[2];
	char buf[1024];
	pid_t pid;
	int len;
	int err;

	if (pipe(signal_fd)) {
		tester_setup_failed();
		return;
	}

	pid = fork();

	if (pid < 0) {
		close(signal_fd[0]);
		close(signal_fd[1]);
		tester_setup_failed();
		return;
	}

	if (pid == 0) {
		if (!tester_use_debug())
			fclose(stderr);

		close(signal_fd[0]);
		emulator(signal_fd[1], data->mgmt_index);
		exit(0);
	}

	close(signal_fd[1]);
	data->bluetoothd_pid = pid;

	len = read(signal_fd[0], buf, sizeof(buf));
	if (len <= 0 || (strcmp(buf, EMULATOR_SIGNAL))) {
		close(signal_fd[0]);
		tester_setup_failed();
		return;
	}

	close(signal_fd[0]);

	err = hw_get_module(BT_HARDWARE_MODULE_ID, &module);
	if (err) {
		tester_setup_failed();
		return;
	}

	err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
	if (err) {
		tester_setup_failed();
		return;
	}

	data->device = device;

	data->if_bluetooth = ((bluetooth_device_t *)
					device)->get_bluetooth_interface();
	if (!data->if_bluetooth) {
		tester_setup_failed();
		return;
	}
}

static void setup_base(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	setup(data);

	status = data->if_bluetooth->init(&bt_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
	}

	tester_setup_complete();
}

static void setup_enabled_adapter(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	setup(data);

	status = data->if_bluetooth->init(&bt_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
	}
	status = data->if_bluetooth->enable();
	if (status != BT_STATUS_SUCCESS)
		tester_setup_failed();
}

static void teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (data->if_bluetooth) {
		data->if_bluetooth->cleanup();
		data->if_bluetooth = NULL;
	}

	data->device->close(data->device);

	if (data->bluetoothd_pid)
		waitpid(data->bluetoothd_pid, NULL, 0);

	tester_teardown_complete();
}

static void test_dummy(const void *test_data)
{
	tester_test_passed();
}

static void test_enable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->enable();
	check_expected_status(adapter_status);
}

static void test_enable_done(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->enable();
	check_expected_status(adapter_status);
}

static void test_disable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->disable();
	check_expected_status(adapter_status);
}

static void test_setprop_bdname_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);

	check_expected_status(adapter_status);
}

static void test_setprop_scanmode_succes(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_disctimeout_succes(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_getprop_bdaddr_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t prop = test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->get_adapter_property(prop.type);
	check_expected_status(adapter_status);
}

static void test_getprop_bdname_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);

	adapter_status = data->if_bluetooth->get_adapter_property((*prop).type);
	check_expected_status(adapter_status);
}

static void test_setprop_uuid_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_cod_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_tod_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->set_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_rssi_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_service_record_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->expected_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_discovery_start_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	init_test_conditions(data);

	status = data->if_bluetooth->start_discovery();
	check_expected_status(status);
}

static void test_discovery_stop_done(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	init_test_conditions(data);

	status = data->if_bluetooth->cancel_discovery();
	check_expected_status(status);
}

static bool pre_inq_compl_hook(const void *dummy, uint16_t len, void *user_data)
{
	struct test_data *data = tester_get_data();

	/* Make sure Inquiry Command Complete is not called */

	hciemu_del_hook(data->hciemu, HCIEMU_HOOK_PRE_EVT, BT_HCI_CMD_INQUIRY);

	return false;
}

static void test_discovery_stop_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	init_test_conditions(data);

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_EVT, BT_HCI_CMD_INQUIRY,
					pre_inq_compl_hook, data);

	status = data->if_bluetooth->start_discovery();
	check_expected_status(status);
}

static void test_discovery_start_done(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_EVT, BT_HCI_CMD_INQUIRY,
					pre_inq_compl_hook, data);

	data->if_bluetooth->start_discovery();
}

static void test_discovery_device_found(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

/* Test Socket HAL */

static void adapter_socket_state_changed_cb(bt_state_t state)
{
	switch (state) {
	case BT_STATE_ON:
		setup_powered_emulated_remote();
		break;
	case BT_STATE_OFF:
		tester_setup_failed();
		break;
	default:
		break;
	}
}

const bt_bdaddr_t bdaddr_dummy = {
	.address = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
};

static const struct socket_data btsock_inv_param_socktype = {
	.bdaddr = &bdaddr_dummy,
	.sock_type = 0,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_PARM_INVALID,
};

static const struct socket_data btsock_inv_param_socktype_l2cap = {
	.bdaddr = &bdaddr_dummy,
	.sock_type = BTSOCK_L2CAP,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_UNSUPPORTED,
};

/* Test invalid: channel & uuid are both zeroes */
static const struct socket_data btsock_inv_params_chan_uuid = {
	.bdaddr = &bdaddr_dummy,
	.sock_type = BTSOCK_RFCOMM,
	.channel = 0,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_PARM_INVALID,
};

static const struct socket_data btsock_success = {
	.bdaddr = &bdaddr_dummy,
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_SUCCESS,
	.test_channel = false
};

static const struct socket_data btsock_success_check_chan = {
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_SUCCESS,
	.test_channel = true,
};

static const struct socket_data btsock_inv_param_bdaddr = {
	.bdaddr = NULL,
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_PARM_INVALID,
};

static const struct socket_data btsock_inv_listen_listen = {
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_FAIL,
	.test_channel = true,
};

static bt_callbacks_t bt_socket_callbacks = {
	.size = sizeof(bt_callbacks),
	.adapter_state_changed_cb = adapter_socket_state_changed_cb,
	.adapter_properties_cb = NULL,
	.remote_device_properties_cb = NULL,
	.device_found_cb = NULL,
	.discovery_state_changed_cb = NULL,
	.pin_request_cb = NULL,
	.ssp_request_cb = NULL,
	.bond_state_changed_cb = NULL,
	.acl_state_changed_cb = NULL,
	.thread_evt_cb = NULL,
	.dut_mode_recv_cb = NULL,
	.le_test_mode_cb = NULL
};

static void setup_socket_interface(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;
	const void *sock;

	setup(data);

	status = data->if_bluetooth->init(&bt_socket_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
	}

	sock = data->if_bluetooth->get_profile_interface(BT_PROFILE_SOCKETS_ID);
	if (!sock) {
		tester_setup_failed();
		return;
	}

	data->if_sock = sock;

	tester_setup_complete();
}

static void setup_socket_interface_enabled(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;
	const void *sock;

	setup(data);

	status = data->if_bluetooth->init(&bt_socket_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
	}

	sock = data->if_bluetooth->get_profile_interface(BT_PROFILE_SOCKETS_ID);
	if (!sock) {
		tester_setup_failed();
		return;
	}

	data->if_sock = sock;

	status = data->if_bluetooth->enable();
	if (status != BT_STATUS_SUCCESS)
		tester_setup_failed();
}

static void test_generic_listen(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	bt_status_t status;
	int sock_fd = -1;

	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_test_failed();
		return;
	}

	if (status == BT_STATUS_SUCCESS && test->test_channel) {
		int channel, len;

		len = read(sock_fd, &channel, sizeof(channel));
		if (len != sizeof(channel) || channel != test->channel) {
			tester_test_failed();
			goto clean;
		}

		tester_print("read correct channel: %d", channel);
	}

	tester_test_passed();

clean:
	if (sock_fd >= 0)
		close(sock_fd);
}

static void test_listen_close(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	bt_status_t status;
	int sock_fd = -1;

	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_warn("sock->listen() failed");
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_warn("sock_fd %d is not valid", sock_fd);
		tester_test_failed();
		return;
	}

	tester_print("Got valid sock_fd: %d", sock_fd);

	/* Now close sock_fd */
	close(sock_fd);
	sock_fd = -1;

	/* Try to listen again */
	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_warn("sock->listen() failed");
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_warn("sock_fd %d is not valid", sock_fd);
		tester_test_failed();
		return;
	}

	tester_print("Got valid sock_fd: %d", sock_fd);

	tester_test_passed();

clean:
	if (sock_fd >= 0)
		close(sock_fd);
}

static void test_listen_listen(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	bt_status_t status;
	int sock_fd1 = -1, sock_fd2 = -1;

	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd1, test->flags);
	if (status != BT_STATUS_SUCCESS) {
		tester_warn("sock->listen() failed");
		tester_test_failed();
		goto clean;
	}

	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd2, test->flags);
	if (status != test->expected_status) {
		tester_warn("sock->listen() failed, status %d", status);
		tester_test_failed();
		goto clean;
	}

	tester_print("status after second listen(): %d", status);

	tester_test_passed();

clean:
	if (sock_fd1 >= 0)
		close(sock_fd1);

	if (sock_fd2 >= 0)
		close(sock_fd2);
}

static void test_generic_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	bt_status_t status;
	int sock_fd = -1;

	status = data->if_sock->connect(test->bdaddr, test->sock_type,
					test->service_uuid, test->channel,
					&sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_test_failed();
		return;
	}

	tester_test_passed();

clean:
	if (sock_fd >= 0)
		close(sock_fd);
}

static gboolean socket_chan_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	int sock_fd = g_io_channel_unix_get_fd(io);
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	int channel, len;

	tester_print("%s", __func__);

	if (cond & G_IO_HUP) {
		tester_warn("Socket %d hang up", sock_fd);
		goto failed;
	}

	if (cond & (G_IO_ERR | G_IO_NVAL)) {
		tester_warn("Socket error: sock %d cond %d", sock_fd, cond);
		goto failed;
	}

	if (test->test_channel) {
		len = read(sock_fd, &channel, sizeof(channel));
		if (len != sizeof(channel) || channel != test->channel)
			goto failed;

		tester_print("read correct channel: %d", channel);
		tester_test_passed();
		return FALSE;
	}

failed:
	tester_test_failed();
	return FALSE;
}

static void test_socket_real_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	const uint8_t *client_bdaddr;
	bt_bdaddr_t emu_bdaddr;
	bt_status_t status;
	int sock_fd = -1;

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (!client_bdaddr) {
		tester_warn("No client bdaddr");
		tester_test_failed();
		return;
	}

	bdaddr2android((bdaddr_t *) client_bdaddr, &emu_bdaddr);

	bthost_add_l2cap_server(bthost, 0x0003, NULL, NULL);

	status = data->if_sock->connect(&emu_bdaddr, test->sock_type,
					test->service_uuid, test->channel,
					&sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_test_failed();
		return;
	}

	tester_print("status %d sock_fd %d", status, sock_fd);

	if (status == BT_STATUS_SUCCESS) {
		GIOChannel *io;

		io = g_io_channel_unix_new(sock_fd);
		g_io_channel_set_close_on_unref(io, TRUE);

		g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				socket_chan_cb, NULL);

		g_io_channel_unref(io);
	}

	return;

clean:
	if (sock_fd >= 0)
		close(sock_fd);
}

#define test_bredrle(name, data, test_setup, test, test_teardown) \
	do { \
		struct test_data *user; \
		user = g_malloc0(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDRLE; \
		user->test_data = data; \
		tester_add_full(name, data, test_pre_setup, test_setup, \
				test, test_teardown, test_post_teardown, \
							3, user, g_free); \
	} while (0)

int main(int argc, char *argv[])
{
	snprintf(exec_dir, sizeof(exec_dir), "%s", dirname(argv[0]));

	tester_init(&argc, &argv);

	test_bredrle("Bluetooth Init", NULL, setup_base, test_dummy, teardown);

	test_bredrle("Bluetooth Enable - Success", &bluetooth_enable_success_test,
					setup_base, test_enable, teardown);

	test_bredrle("Bluetooth Enable - Done", &bluetooth_enable_done_test,
			setup_enabled_adapter, test_enable_done, teardown);

	test_bredrle("Bluetooth Disable - Success", &bluetooth_disable_success_test,
			setup_enabled_adapter, test_disable, teardown);

	test_bredrle("Bluetooth Set BDNAME - Success",
					&bluetooth_setprop_bdname_success_test,
					setup_enabled_adapter,
					test_setprop_bdname_success, teardown);

	test_bredrle("Bluetooth Set SCAN_MODE - Success",
				&bluetooth_setprop_scanmode_success_test,
				setup_enabled_adapter,
				test_setprop_scanmode_succes, teardown);

	test_bredrle("Bluetooth Set DISCOVERY_TIMEOUT - Success",
				&bluetooth_setprop_disctimeout_success_test,
				setup_enabled_adapter,
				test_setprop_disctimeout_succes, teardown);

	test_bredrle("Bluetooth Get BDADDR - Success",
					&bluetooth_getprop_bdaddr_success_test,
					setup_enabled_adapter,
					test_getprop_bdaddr_success, teardown);

	test_bredrle("Bluetooth Get BDNAME - Success",
					&bluetooth_getprop_bdname_success_test,
					setup_enabled_adapter,
					test_getprop_bdname_success, teardown);

	test_bredrle("Bluetooth Set UUID - Invalid",
					&bluetooth_setprop_uuid_invalid_test,
					setup_enabled_adapter,
					test_setprop_uuid_invalid, teardown);

	test_bredrle("Bluetooth Set CLASS_OF_DEVICE - Invalid",
					&bluetooth_setprop_cod_invalid_test,
					setup_enabled_adapter,
					test_setprop_cod_invalid, teardown);

	test_bredrle("Bluetooth Set TYPE_OF_DEVICE - Invalid",
					&bluetooth_setprop_tod_invalid_test,
					setup_enabled_adapter,
					test_setprop_tod_invalid, teardown);

	test_bredrle("Bluetooth Set REMOTE_RSSI - Invalid",
				&bluetooth_setprop_remote_rssi_invalid_test,
				setup_enabled_adapter,
				test_setprop_rssi_invalid, teardown);

	test_bredrle("Bluetooth Set SERVICE_RECORD - Invalid",
				&bluetooth_setprop_service_record_invalid_test,
				setup_enabled_adapter,
				test_setprop_service_record_invalid, teardown);

	test_bredrle("Bluetooth BREDR Discovery Start - Success",
				&bluetooth_discovery_start_success_test,
				setup_enabled_adapter,
				test_discovery_start_success, teardown);

	test_bredrle("Bluetooth BREDR Discovery Start - Done",
				&bluetooth_discovery_start_done_test,
				setup_enabled_adapter,
				test_discovery_start_done, teardown);

	test_bredrle("Bluetooth BREDR Discovery Stop - Success",
				&bluetooth_discovery_stop_success_test,
				setup_enabled_adapter,
				test_discovery_stop_success, teardown);

	test_bredrle("Bluetooth BREDR Discovery Stop - Done",
				&bluetooth_discovery_stop_done_test,
				setup_enabled_adapter,
				test_discovery_stop_done, teardown);

	test_bredrle("Bluetooth BREDR Discovery Device Found",
				&bluetooth_discovery_device_found_test,
				setup_enabled_adapter,
				test_discovery_device_found, teardown);

	test_bredrle("Socket Init", NULL, setup_socket_interface,
						test_dummy, teardown);

	test_bredrle("Socket Listen - Invalid: sock_type 0",
			&btsock_inv_param_socktype, setup_socket_interface,
			test_generic_listen, teardown);

	test_bredrle("Socket Listen - Invalid: sock_type L2CAP",
			&btsock_inv_param_socktype_l2cap,
			setup_socket_interface, test_generic_listen, teardown);

	test_bredrle("Socket Listen - Invalid: chan, uuid",
			&btsock_inv_params_chan_uuid,
			setup_socket_interface, test_generic_listen, teardown);

	test_bredrle("Socket Listen - Check returned fd valid",
			&btsock_success,
			setup_socket_interface, test_generic_listen, teardown);

	test_bredrle("Socket Listen - Check returned channel",
			&btsock_success_check_chan,
			setup_socket_interface, test_generic_listen, teardown);

	test_bredrle("Socket Listen - Close and Listen again",
			&btsock_success_check_chan,
			setup_socket_interface, test_listen_close, teardown);

	test_bredrle("Socket Listen - Invalid: double Listen",
			&btsock_inv_listen_listen,
			setup_socket_interface, test_listen_listen, teardown);

	test_bredrle("Socket Connect - Check returned fd valid",
			&btsock_success, setup_socket_interface,
			test_generic_connect, teardown);

	test_bredrle("Socket Connect - Invalid: sock_type 0",
			&btsock_inv_param_socktype, setup_socket_interface,
			test_generic_connect, teardown);

	test_bredrle("Socket Connect - Invalid: sock_type L2CAP",
			&btsock_inv_param_socktype_l2cap,
			setup_socket_interface, test_generic_connect, teardown);

	test_bredrle("Socket Connect - Invalid: chan, uuid",
			&btsock_inv_params_chan_uuid,
			setup_socket_interface, test_generic_connect, teardown);

	test_bredrle("Socket Connect - Invalid: bdaddr",
			&btsock_inv_param_bdaddr,
			setup_socket_interface, test_generic_connect, teardown);

	test_bredrle("Socket Connect - Check returned chan",
			&btsock_success_check_chan,
			setup_socket_interface_enabled,
			test_socket_real_connect, teardown);

	return tester_run();
}
