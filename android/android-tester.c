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

#define ADAPTER_PROPS ADAPTER_PROP_BDADDR, ADAPTER_PROP_BDNAME, \
			ADAPTER_PROP_UUIDS, ADAPTER_PROP_COD, \
			ADAPTER_PROP_TYPE, ADAPTER_PROP_SCAN_MODE, \
			ADAPTER_PROP_BONDED_DEVICES, ADAPTER_PROP_DISC_TIMEOUT

static bt_scan_mode_t test_setprop_scanmode_val =
					BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
static uint32_t test_setprop_disctimeout_val = 120;

/*
 * those are assigned to HAL methods and callbacks, we use ID later
 * on mapped in switch-case due to different functions prototypes.
 */

enum hal_bluetooth_callbacks_id {
	ADAPTER_TEST_END,
	ADAPTER_STATE_CHANGED_ON,
	ADAPTER_STATE_CHANGED_OFF,
	ADAPTER_PROP_BDADDR,
	ADAPTER_PROP_BDNAME,
	ADAPTER_PROP_UUIDS,
	ADAPTER_PROP_COD,
	ADAPTER_PROP_TYPE,
	ADAPTER_PROP_SCAN_MODE,
	ADAPTER_PROP_DISC_TIMEOUT,
	ADAPTER_PROP_SERVICE_RECORD,
	ADAPTER_PROP_BONDED_DEVICES
};

struct generic_data {
	uint8_t expected_adapter_status;
	uint32_t expect_settings_set;
	bt_property_t expected_property;
	uint8_t expected_hal_callbacks[];
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

struct test_data {
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	unsigned int mgmt_settings_id;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	const void *test_data;
	pid_t bluetoothd_pid;

	const bt_interface_t *if_bluetooth;
	const btsock_interface_t *if_sock;

	bool mgmt_settings_set;
	bool hal_cb_called;
	bool status_checked;
	bool property_checked;

	bt_property_t test_property;
	GSList *expected_callbacks;
};

static char exec_dir[PATH_MAX + 1];

static void test_update_state(void)
{
	struct test_data *data = tester_get_data();

	if (!(data->mgmt_settings_set))
		return;
	if (!(data->hal_cb_called))
		return;
	if (!(data->status_checked))
		return;
	if (!(data->property_checked))
		return;
	tester_test_passed();
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

static bool is_empty_halcb_list(void)
{
	struct test_data *data = tester_get_data();

	return !(g_slist_length(data->expected_callbacks));
}

static void hal_cb_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;
	unsigned int i = 0;

	while (test_data->expected_hal_callbacks[i]) {
		data->expected_callbacks =
			g_slist_append(data->expected_callbacks,
		GINT_TO_POINTER(test_data->expected_hal_callbacks[i]));
		i++;
	}

	if (is_empty_halcb_list())
		data->hal_cb_called = true;
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

	if (!(test_data->expected_adapter_status))
		data->status_checked = true;
}

static void test_property_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;

	if (is_empty_halcb_list() || !(test_data->expected_property.type))
		data->property_checked = true;
}

static void init_test_conditions(struct test_data *data)
{
	hal_cb_init(data);
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

static void check_test_property(void)
{
	struct test_data *data = tester_get_data();
	bt_property_t expected_prop = data->test_property;
	const struct generic_data *test_data = data->test_data;
	bt_property_t test_prop = test_data->expected_property;

	if (test_prop.type && (expected_prop.type != test_prop.type)) {
		tester_test_failed();
		return;
	}

	if (test_prop.len && (expected_prop.len != test_prop.len)) {
		tester_test_failed();
		return;
	}

	if (test_prop.val && memcmp(expected_prop.val, test_prop.val,
							expected_prop.len)) {
		tester_test_failed();
		return;
	}

	data->property_checked = true;
	test_update_state();
}

static void update_hal_cb_list(enum hal_bluetooth_callbacks_id
							expected_callback)
{
	struct test_data *data = tester_get_data();

	if (is_empty_halcb_list())
		return;

	data->expected_callbacks = g_slist_remove(data->expected_callbacks,
					GINT_TO_POINTER(expected_callback));

	if (!data->expected_callbacks)
		data->hal_cb_called = true;

	test_update_state();
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

static void adapter_state_changed_cb(bt_state_t state)
{
	switch (state) {
	case BT_STATE_ON:
		if (is_empty_halcb_list())
			setup_powered_emulated_remote();
		update_hal_cb_list(ADAPTER_STATE_CHANGED_ON);
		break;
	case BT_STATE_OFF:
		if (is_empty_halcb_list())
			tester_setup_failed();
		update_hal_cb_list(ADAPTER_STATE_CHANGED_OFF);
		break;
	default:
		break;
	}
}

static void adapter_properties_cb(bt_status_t status, int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	int i;

	if (is_empty_halcb_list())
		return;

	for (i = 0; i < num_properties; i++) {

		data->test_property = properties[i];

		if (g_slist_length(data->expected_callbacks) == 1)
			check_test_property();

		switch (properties[i].type) {
		case BT_PROPERTY_BDADDR:
			update_hal_cb_list(ADAPTER_PROP_BDADDR);
			break;
		case BT_PROPERTY_BDNAME:
			update_hal_cb_list(ADAPTER_PROP_BDNAME);
			break;
		case BT_PROPERTY_UUIDS:
			update_hal_cb_list(ADAPTER_PROP_UUIDS);
			break;
		case BT_PROPERTY_CLASS_OF_DEVICE:
			update_hal_cb_list(ADAPTER_PROP_COD);
			break;
		case BT_PROPERTY_TYPE_OF_DEVICE:
			update_hal_cb_list(ADAPTER_PROP_TYPE);
			break;
		case BT_PROPERTY_SERVICE_RECORD:
			update_hal_cb_list(ADAPTER_PROP_SERVICE_RECORD);
			break;
		case BT_PROPERTY_ADAPTER_SCAN_MODE:
			update_hal_cb_list(ADAPTER_PROP_SCAN_MODE);
			break;
		case BT_PROPERTY_ADAPTER_BONDED_DEVICES:
			update_hal_cb_list(ADAPTER_PROP_BONDED_DEVICES);
			break;
		case BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT:
			update_hal_cb_list(ADAPTER_PROP_DISC_TIMEOUT);
			break;
		default:
			goto fail;
		}
	}
	return;

fail:
	tester_print("Unexpected property: %u", properties[i].type);
	tester_test_failed();
	return;
}

static const struct generic_data bluetooth_enable_success_test = {
	.expected_hal_callbacks = { ADAPTER_PROPS, ADAPTER_STATE_CHANGED_ON,
							ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_SUCCESS
};

static const struct generic_data bluetooth_enable_done_test = {
	.expected_hal_callbacks = { ADAPTER_PROPS, ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_DONE
};

static const struct generic_data bluetooth_disable_success_test = {
	.expected_hal_callbacks = { ADAPTER_STATE_CHANGED_OFF,
							ADAPTER_TEST_END }
};

static const struct generic_data bluetooth_setprop_bdname_success_test = {
	.expected_hal_callbacks = { ADAPTER_PROP_BDNAME, ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_BDNAME,
	.expected_property.val = "test_bdname",
	.expected_property.len = 11
};

static const struct generic_data bluetooth_setprop_scanmode_success_test = {
	.expected_hal_callbacks = { ADAPTER_PROP_SCAN_MODE,
						ADAPTER_PROP_SCAN_MODE,
						ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.expected_property.val = &test_setprop_scanmode_val,
	.expected_property.len = sizeof(bt_scan_mode_t)
};

static const struct generic_data bluetooth_setprop_disctimeout_success_test = {
	.expected_hal_callbacks = { ADAPTER_PROP_DISC_TIMEOUT, ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.expected_property.val = &test_setprop_disctimeout_val,
	.expected_property.len = sizeof(test_setprop_disctimeout_val)
};

static const struct generic_data bluetooth_getprop_bdaddr_success_test = {
	.expected_hal_callbacks = { ADAPTER_PROP_BDADDR, ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_BDADDR,
	.expected_property.val = NULL,
	.expected_property.len = sizeof(bt_bdaddr_t)
};

static const struct generic_data bluetooth_getprop_bdname_success_test = {
	.expected_hal_callbacks = { ADAPTER_PROP_BDNAME, ADAPTER_PROP_BDNAME,
							ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_property.type = BT_PROPERTY_BDNAME,
	.expected_property.val = "test_bdname_setget",
	.expected_property.len = 17
};

static unsigned char setprop_uuids[] = { 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00,
			0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00 };

static const struct generic_data bluetooth_setprop_uuid_invalid_test = {
	.expected_hal_callbacks = { ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_FAIL,
	.expected_property.type = BT_PROPERTY_UUIDS,
	.expected_property.val = &setprop_uuids,
	.expected_property.len = sizeof(setprop_uuids)
};

static uint32_t setprop_class_of_device = 0;

static const struct generic_data bluetooth_setprop_cod_invalid_test = {
	.expected_hal_callbacks = { ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_FAIL,
	.expected_property.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.expected_property.val = &setprop_class_of_device,
	.expected_property.len = sizeof(setprop_class_of_device)
};

static bt_device_type_t setprop_type_of_device = BT_DEVICE_DEVTYPE_BREDR;

static const struct generic_data bluetooth_setprop_tod_invalid_test = {
	.expected_hal_callbacks = { ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_FAIL,
	.expected_property.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.expected_property.val = &setprop_type_of_device,
	.expected_property.len = sizeof(setprop_type_of_device)
};

static int32_t setprop_remote_rssi = 0;

static const struct generic_data bluetooth_setprop_remote_rssi_invalid_test = {
	.expected_hal_callbacks = { ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_FAIL,
	.expected_property.type = BT_PROPERTY_REMOTE_RSSI,
	.expected_property.val = &setprop_remote_rssi,
	.expected_property.len = sizeof(setprop_remote_rssi)
};

static bt_service_record_t setprop_remote_service = {
	.uuid = { {0x00} },
	.channel = 12,
	.name = "bt_name"
};

static const struct generic_data
			bluetooth_setprop_service_record_invalid_test = {
	.expected_hal_callbacks = { ADAPTER_TEST_END },
	.expected_adapter_status = BT_STATUS_FAIL,
	.expected_property.type = BT_PROPERTY_SERVICE_RECORD,
	.expected_property.val = &setprop_remote_service,
	.expected_property.len = sizeof(setprop_remote_service)
};

static bt_callbacks_t bt_callbacks = {
	.size = sizeof(bt_callbacks),
	.adapter_state_changed_cb = adapter_state_changed_cb,
	.adapter_properties_cb = adapter_properties_cb,
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

static void setup(struct test_data *data)
{
	const hw_module_t *module;
	hw_device_t *device;
	bt_status_t status;
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

	data->if_bluetooth = ((bluetooth_device_t *)
					device)->get_bluetooth_interface();
	if (!data->if_bluetooth) {
		tester_setup_failed();
		return;
	}

	status = data->if_bluetooth->init(&bt_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
	}
}

static void setup_base(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup(data);

	tester_setup_complete();
}

static void setup_enabled_adapter(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	setup(data);

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

	if (data->bluetoothd_pid)
		waitpid(data->bluetoothd_pid, NULL, 0);

	if (data->expected_callbacks)
		g_slist_free(data->expected_callbacks);

	tester_teardown_complete();
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

	init_test_conditions(data);

	data->if_bluetooth->disable();
}

static void test_dummy(const void *test_data)
{
	tester_test_passed();
}

/* Test Socket HAL */

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
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_SUCCESS,
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

static void setup_socket_interface(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const void *sock;

	setup(data);

	sock = data->if_bluetooth->get_profile_interface(BT_PROFILE_SOCKETS_ID);
	if (!sock) {
		tester_setup_failed();
		return;
	}

	data->if_sock = sock;

	tester_setup_complete();
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
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) == -1) {
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
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) == -1) {
		tester_test_failed();
		return;
	}

	tester_test_passed();

clean:
	if (sock_fd >= 0)
		close(sock_fd);
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
	const bt_property_t *prop = &test->expected_property;
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

	test_bredrle("Init", NULL, setup_base, test_dummy, teardown);

	test_bredrle("Enable - Success", &bluetooth_enable_success_test,
					setup_base, test_enable, teardown);

	test_bredrle("Enable - Done", &bluetooth_enable_done_test,
			setup_enabled_adapter, test_enable_done, teardown);

	test_bredrle("Disable - Success", &bluetooth_disable_success_test,
			setup_enabled_adapter, test_disable, teardown);

	test_bredrle("Set BDNAME - Success",
					&bluetooth_setprop_bdname_success_test,
					setup_enabled_adapter,
					test_setprop_bdname_success, teardown);

	test_bredrle("Set SCAN_MODE - Success",
				&bluetooth_setprop_scanmode_success_test,
				setup_enabled_adapter,
				test_setprop_scanmode_succes, teardown);

	test_bredrle("Set DISCOVERY_TIMEOUT - Success",
				&bluetooth_setprop_disctimeout_success_test,
				setup_enabled_adapter,
				test_setprop_disctimeout_succes, teardown);

	test_bredrle("Get BDADDR - Success",
					&bluetooth_getprop_bdaddr_success_test,
					setup_enabled_adapter,
					test_getprop_bdaddr_success, teardown);

	test_bredrle("Get BDNAME - Success",
					&bluetooth_getprop_bdname_success_test,
					setup_enabled_adapter,
					test_getprop_bdname_success, teardown);

	test_bredrle("Set UUID - Invalid",
					&bluetooth_setprop_uuid_invalid_test,
					setup_enabled_adapter,
					test_setprop_uuid_invalid, teardown);

	test_bredrle("Set CLASS_OF_DEVICE - Invalid",
					&bluetooth_setprop_cod_invalid_test,
					setup_enabled_adapter,
					test_setprop_cod_invalid, teardown);

	test_bredrle("Set TYPE_OF_DEVICE - Invalid",
					&bluetooth_setprop_tod_invalid_test,
					setup_enabled_adapter,
					test_setprop_tod_invalid, teardown);

	test_bredrle("Set REMOTE_RSSI - Invalid",
				&bluetooth_setprop_remote_rssi_invalid_test,
				setup_enabled_adapter,
				test_setprop_rssi_invalid, teardown);

	test_bredrle("Set SERVICE_RECORD - Invalid",
				&bluetooth_setprop_service_record_invalid_test,
				setup_enabled_adapter,
				test_setprop_service_record_invalid, teardown);

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

	return tester_run();
}
