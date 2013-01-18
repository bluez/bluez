/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

struct test_data {
	const void *test_data;
	uint8_t expected_version;
	uint16_t expected_manufacturer;
	uint32_t expected_supported_settings;
	uint32_t initial_settings;
	struct mgmt *mgmt;
	struct mgmt *mgmt_alt;
	unsigned int mgmt_settings_id;
	unsigned int mgmt_alt_settings_id;
	unsigned int mgmt_alt_class_id;
	uint8_t mgmt_version;
	uint16_t mgmt_revision;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	int unmet_conditions;
};

static void mgmt_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
}

static void read_version_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_version *rp = param;

	tester_print("Read Version callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	data->mgmt_version = rp->version;
	data->mgmt_revision = btohs(rp->revision);

	tester_print("  Version %u.%u",
				data->mgmt_version, data->mgmt_revision);
}

static void read_commands_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	tester_print("Read Commands callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}
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

	if (rp->version != data->expected_version) {
		tester_pre_setup_failed();
		return;
	}

	if (manufacturer != data->expected_manufacturer) {
		tester_pre_setup_failed();
		return;
	}

	if (supported_settings != data->expected_supported_settings) {
		tester_pre_setup_failed();
		return;
	}

	if (current_settings != data->initial_settings) {
		tester_pre_setup_failed();
		return;
	}

	if (rp->dev_class[0] != 0x00 || rp->dev_class[1] != 0x00 ||
						rp->dev_class[2] != 0x00) {
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
	mgmt_unregister_index(data->mgmt_alt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	mgmt_unref(data->mgmt_alt);
	data->mgmt_alt = NULL;

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

	data->hciemu = hciemu_new();
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	data->mgmt_alt = mgmt_new_default();
	if (!data->mgmt_alt) {
		tester_warn("Failed to setup alternate management interface");
		tester_pre_setup_failed();

		mgmt_unref(data->mgmt);
		data->mgmt = NULL;
		return;
	}

	if (tester_use_debug()) {
		mgmt_set_debug(data->mgmt, mgmt_debug, "mgmt: ", NULL);
		mgmt_set_debug(data->mgmt_alt, mgmt_debug, "mgmt-alt: ", NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, 0, NULL,
					read_version_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_COMMANDS, MGMT_INDEX_NONE, 0, NULL,
					read_commands_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void test_add_condition(struct test_data *data)
{
	data->unmet_conditions++;

	tester_print("Test condition added, total %d", data->unmet_conditions);
}

static void test_condition_complete(struct test_data *data)
{
	data->unmet_conditions--;

	tester_print("Test condition complete, %d left",
						data->unmet_conditions);

	if (data->unmet_conditions > 0)
		return;

	tester_test_passed();
}

#define test_bredr(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->test_data = data; \
		user->expected_version = 0x06; \
		user->expected_manufacturer = 0x003f; \
		user->expected_supported_settings = 0x000002ff; \
		user->initial_settings = 0x00000080; \
		user->unmet_conditions = 0; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, free); \
	} while (0)

static void controller_setup(const void *test_data)
{
	tester_test_passed();
}

struct generic_data {
	bool send_index_none;
	uint16_t send_opcode;
	const void *send_param;
	uint16_t send_len;
	uint8_t expect_status;
	const void *expect_param;
	uint16_t expect_len;
	uint32_t expect_settings_set;
	uint32_t expect_settings_unset;
	const void *expect_class_of_dev;
	uint16_t expect_hci_command;
	const void *expect_hci_param;
	uint8_t expect_hci_len;
};

static const char dummy_data[] = { 0x00 };

static const struct generic_data invalid_command_test = {
	.send_opcode = 0xffff,
	.expect_status = MGMT_STATUS_UNKNOWN_COMMAND,
};

static const struct generic_data read_version_invalid_param_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_VERSION,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_version_invalid_index_test = {
	.send_opcode = MGMT_OP_READ_VERSION,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_commands_invalid_param_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_COMMANDS,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_commands_invalid_index_test = {
	.send_opcode = MGMT_OP_READ_COMMANDS,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_index_list_invalid_param_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_INDEX_LIST,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_index_list_invalid_index_test = {
	.send_opcode = MGMT_OP_READ_INDEX_LIST,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_info_invalid_param_test = {
	.send_opcode = MGMT_OP_READ_INFO,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_info_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_INFO,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_powered_on_param[] = { 0x01 };
static const char set_powered_invalid_param[] = { 0x02 };
static const char set_powered_garbage_param[] = { 0x01, 0x00 };
static const char set_powered_settings_param[] = { 0x81, 0x00, 0x00, 0x00 };

static const struct generic_data set_powered_on_success_test = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_settings_param,
	.expect_len = sizeof(set_powered_settings_param),
	.expect_settings_set = MGMT_SETTING_POWERED,
};

static const struct generic_data set_powered_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_invalid_param,
	.send_len = sizeof(set_powered_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_garbage_param,
	.send_len = sizeof(set_powered_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_powered_off_param[] = { 0x00 };
static const char set_powered_off_settings_param[] = { 0x80, 0x00, 0x00, 0x00 };
static const char set_powered_off_class_of_dev[] = { 0x00, 0x00, 0x00 };

static const struct generic_data set_powered_off_success_test = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_off_param,
	.send_len = sizeof(set_powered_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_off_settings_param,
	.expect_len = sizeof(set_powered_off_settings_param),
	.expect_settings_unset = MGMT_SETTING_POWERED,
};

static const struct generic_data set_powered_off_class_test = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_off_param,
	.send_len = sizeof(set_powered_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_off_settings_param,
	.expect_len = sizeof(set_powered_off_settings_param),
	.expect_settings_unset = MGMT_SETTING_POWERED,
	.expect_class_of_dev = set_powered_off_class_of_dev,
};

static const char set_connectable_on_param[] = { 0x01 };
static const char set_connectable_invalid_param[] = { 0x02 };
static const char set_connectable_garbage_param[] = { 0x01, 0x00 };
static const char set_connectable_settings_param_1[] = { 0x82, 0x00, 0x00, 0x00 };
static const char set_connectable_settings_param_2[] = { 0x83, 0x00, 0x00, 0x00 };
static const char set_connectable_scan_enable_param[] = { 0x02 };

static const struct generic_data set_connectable_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_settings_param_1,
	.expect_len = sizeof(set_connectable_settings_param_1),
	.expect_settings_set = MGMT_SETTING_CONNECTABLE,
};

static const struct generic_data set_connectable_on_success_test_2 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_settings_param_2,
	.expect_len = sizeof(set_connectable_settings_param_2),
	.expect_settings_set = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_connectable_scan_enable_param,
	.expect_hci_len = sizeof(set_connectable_scan_enable_param),
};

static const struct generic_data set_connectable_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_connectable_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_invalid_param,
	.send_len = sizeof(set_connectable_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_connectable_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_garbage_param,
	.send_len = sizeof(set_connectable_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_connectable_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char set_pairable_on_param[] = { 0x01 };
static const char set_pairable_invalid_param[] = { 0x02 };
static const char set_pairable_garbage_param[] = { 0x01, 0x00 };
static const char set_pairable_settings_param[] = { 0x90, 0x00, 0x00, 0x00 };

static const struct generic_data set_pairable_on_success_test = {
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.send_param = set_pairable_on_param,
	.send_len = sizeof(set_pairable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_pairable_settings_param,
	.expect_len = sizeof(set_pairable_settings_param),
	.expect_settings_set = MGMT_SETTING_PAIRABLE,
};

static const struct generic_data set_pairable_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_pairable_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.send_param = set_pairable_invalid_param,
	.send_len = sizeof(set_pairable_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_pairable_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.send_param = set_pairable_garbage_param,
	.send_len = sizeof(set_pairable_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_pairable_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_PAIRABLE,
	.send_param = set_pairable_on_param,
	.send_len = sizeof(set_pairable_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const uint8_t set_discoverable_on_param[] = { 0x01, 0x00, 0x00 };
static const uint8_t set_discoverable_timeout_param[] = { 0x01, 0x0a, 0x00 };
static const uint8_t set_discoverable_invalid_param[] = { 0x02, 0x00, 0x00 };
static const uint8_t set_discoverable_off_param[] = { 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_offtimeout_param[] = { 0x00, 0x01, 0x00 };
static const uint8_t set_discoverable_garbage_param[] = { 0x01, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_on_settings_param_1[] = { 0x8a, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_on_settings_param_2[] = { 0x8b, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_off_settings_param_1[] = { 0x82, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_off_settings_param_2[] = { 0x83, 0x00, 0x00, 0x00 };
static const uint8_t set_discoverable_on_scan_enable_param[] = { 0x03 };
static const uint8_t set_discoverable_off_scan_enable_param[] = { 0x02 };

static const struct generic_data set_discoverable_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_discoverable_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_invalid_param,
	.send_len = sizeof(set_discoverable_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_discoverable_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_garbage_param,
	.send_len = sizeof(set_discoverable_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_discoverable_on_invalid_param_test_4 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_offtimeout_param,
	.send_len = sizeof(set_discoverable_offtimeout_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_discoverable_on_not_powered_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_timeout_param,
	.send_len = sizeof(set_discoverable_timeout_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
};

static const struct generic_data set_discoverable_on_rejected_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_rejected_test_2 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_rejected_test_3 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_timeout_param,
	.send_len = sizeof(set_discoverable_timeout_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_on_settings_param_1,
	.expect_len = sizeof(set_discoverable_on_settings_param_1),
	.expect_settings_set = MGMT_SETTING_DISCOVERABLE,
};

static const struct generic_data set_discoverable_on_success_test_2 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_on_settings_param_2,
	.expect_len = sizeof(set_discoverable_on_settings_param_2),
	.expect_settings_set = MGMT_SETTING_DISCOVERABLE,
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_discoverable_on_scan_enable_param,
	.expect_hci_len = sizeof(set_discoverable_on_scan_enable_param),
};

static const struct generic_data set_discoverable_off_success_test_1 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_off_param,
	.send_len = sizeof(set_discoverable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_off_settings_param_1,
	.expect_len = sizeof(set_discoverable_off_settings_param_1),
};

static const struct generic_data set_discoverable_off_success_test_2 = {
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_off_param,
	.send_len = sizeof(set_discoverable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_off_settings_param_2,
	.expect_len = sizeof(set_discoverable_off_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_discoverable_off_scan_enable_param,
	.expect_hci_len = sizeof(set_discoverable_off_scan_enable_param),
};

static const char set_link_sec_on_param[] = { 0x01 };
static const char set_link_sec_invalid_param[] = { 0x02 };
static const char set_link_sec_garbage_param[] = { 0x01, 0x00 };
static const char set_link_sec_settings_param_1[] = { 0xa0, 0x00, 0x00, 0x00 };
static const char set_link_sec_settings_param_2[] = { 0xa1, 0x00, 0x00, 0x00 };
static const char set_link_sec_auth_enable_param[] = { 0x01 };

static const struct generic_data set_link_sec_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_on_param,
	.send_len = sizeof(set_link_sec_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_settings_param_1,
	.expect_len = sizeof(set_link_sec_settings_param_1),
	.expect_settings_set = MGMT_SETTING_LINK_SECURITY,
};

static const struct generic_data set_link_sec_on_success_test_2 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_on_param,
	.send_len = sizeof(set_link_sec_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_settings_param_2,
	.expect_len = sizeof(set_link_sec_settings_param_2),
	.expect_settings_set = MGMT_SETTING_LINK_SECURITY,
	.expect_hci_command = BT_HCI_CMD_WRITE_AUTH_ENABLE,
	.expect_hci_param = set_link_sec_auth_enable_param,
	.expect_hci_len = sizeof(set_link_sec_auth_enable_param),
};

static const struct generic_data set_link_sec_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_link_sec_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_invalid_param,
	.send_len = sizeof(set_link_sec_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_link_sec_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_garbage_param,
	.send_len = sizeof(set_link_sec_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_link_sec_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_on_param,
	.send_len = sizeof(set_link_sec_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const char start_discovery_invalid_param[] = { 0x00 };
static const char start_discovery_bredr_param[] = { 0x01 };
static const char start_discovery_le_param[] = { 0x06 };

static const struct generic_data start_discovery_not_powered_test_1 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredr_param,
	.send_len = sizeof(start_discovery_bredr_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
};

static const struct generic_data start_discovery_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_invalid_param,
	.send_len = sizeof(start_discovery_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data start_discovery_not_supported_test_1 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const char set_dev_class_valid_param[] = { 0x01, 0x0c };
static const char set_dev_class_zero_rsp[] = { 0x00, 0x00, 0x00 };
static const char set_dev_class_valid_rsp[] = { 0x0c, 0x01, 0x00 };
static const char set_dev_class_valid_hci[] = { 0x0c, 0x01, 0x00 };
static const char set_dev_class_invalid_param[] = { 0x01, 0x01 };

static const struct generic_data set_dev_class_valid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_DEV_CLASS,
	.send_param = set_dev_class_valid_param,
	.send_len = sizeof(set_dev_class_valid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
};

static const struct generic_data set_dev_class_valid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_DEV_CLASS,
	.send_param = set_dev_class_valid_param,
	.send_len = sizeof(set_dev_class_valid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_valid_rsp,
	.expect_len = sizeof(set_dev_class_valid_rsp),
	.expect_class_of_dev = set_dev_class_valid_rsp,
	.expect_hci_command = BT_HCI_CMD_WRITE_CLASS_OF_DEV,
	.expect_hci_param = set_dev_class_valid_hci,
	.expect_hci_len = sizeof(set_dev_class_valid_hci),
};

static const struct generic_data set_dev_class_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_DEV_CLASS,
	.send_param = set_dev_class_invalid_param,
	.send_len = sizeof(set_dev_class_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char add_spp_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00,
			0x00 };
static const char add_dun_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x03, 0x11, 0x00, 0x00,
			0x00 };
static const char write_eir_uuid16_hci[] = { 0x00,
			0x02, 0x0a, 0x00, 0x03, 0x03, 0x01, 0x11, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const char write_eir_multi_uuid16_hci[] = { 0x00,
			0x02, 0x0a, 0x00, 0x05, 0x03, 0x03, 0x11, 0x01,
			0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const char add_uuid32_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
			0x00 };
static const char write_eir_uuid32_hci[] = { 0x00,
			0x02, 0x0a, 0x00, 0x05, 0x05, 0x78, 0x56, 0x34,
			0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const struct generic_data add_uuid16_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_spp_uuid_param,
	.send_len = sizeof(add_spp_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid16_hci,
	.expect_hci_len = sizeof(write_eir_uuid16_hci),
};

static const struct generic_data add_multi_uuid16_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_dun_uuid_param,
	.send_len = sizeof(add_dun_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_multi_uuid16_hci,
	.expect_hci_len = sizeof(write_eir_multi_uuid16_hci),
};

static const struct generic_data add_uuid32_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid32_param,
	.send_len = sizeof(add_uuid32_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid32_hci,
	.expect_hci_len = sizeof(write_eir_uuid32_hci),
};

static const char load_link_keys_valid_param_1[] = { 0x00, 0x00, 0x00 };
static const char load_link_keys_valid_param_2[] = { 0x01, 0x00, 0x00 };
static const char load_link_keys_invalid_param_1[] = { 0x02, 0x00, 0x00 };
static const char load_link_keys_invalid_param_2[] = { 0x00, 0x01, 0x00 };
/* Invalid bdaddr type */
static const char load_link_keys_invalid_param_3[] = { 0x00, 0x01, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* addr */
	0x01,						/* addr type */
	0x00,						/* key type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* value (2/2) */
	0x04,						/* PIN length */
};

static const struct generic_data load_link_keys_success_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_valid_param_1,
	.send_len = sizeof(load_link_keys_valid_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_link_keys_success_test_2 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_valid_param_2,
	.send_len = sizeof(load_link_keys_valid_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_link_keys_invalid_params_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_invalid_param_1,
	.send_len = sizeof(load_link_keys_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_link_keys_invalid_params_test_2 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_invalid_param_2,
	.send_len = sizeof(load_link_keys_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_link_keys_invalid_params_test_3 = {
	.send_opcode = MGMT_OP_LOAD_LINK_KEYS,
	.send_param = load_link_keys_invalid_param_3,
	.send_len = sizeof(load_link_keys_invalid_param_3),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char load_ltks_valid_param_1[] = { 0x00, 0x00 };
/* Invalid key count */
static const char load_ltks_invalid_param_1[] = { 0x01, 0x00 };
/* Invalid addr type */
static const char load_ltks_invalid_param_2[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x00,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2 */
};
/* Invalid authenticated value */
static const char load_ltks_invalid_param_3[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x02,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2 */
};
/* Invalid master value */
static const char load_ltks_invalid_param_4[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authunticated */
	0x02,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2 */
};

static const struct generic_data load_ltks_success_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_valid_param_1,
	.send_len = sizeof(load_ltks_valid_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_ltks_invalid_params_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_1,
	.send_len = sizeof(load_ltks_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_ltks_invalid_params_test_2 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_2,
	.send_len = sizeof(load_ltks_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_ltks_invalid_params_test_3 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_3,
	.send_len = sizeof(load_ltks_invalid_param_3),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_ltks_invalid_params_test_4 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_4,
	.send_len = sizeof(load_ltks_invalid_param_4),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char pair_device_param[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00 };
static const char pair_device_rsp[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00 };
static const char pair_device_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff, 0x00 };
static const char pair_device_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };

static const struct generic_data pair_device_not_powered_test_1 = {
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_param = pair_device_param,
	.send_len = sizeof(pair_device_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.expect_param = pair_device_rsp,
	.expect_len = sizeof(pair_device_rsp),
};

static const struct generic_data pair_device_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_param = pair_device_invalid_param_1,
	.send_len = sizeof(pair_device_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = pair_device_invalid_param_rsp_1,
	.expect_len = sizeof(pair_device_invalid_param_rsp_1),
};

static const char unpair_device_param[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00 };
static const char unpair_device_rsp[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00 };
static const char unpair_device_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff, 0x00 };
static const char unpair_device_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
static const char unpair_device_invalid_param_2[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x02 };
static const char unpair_device_invalid_param_rsp_2[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00 };

static const struct generic_data unpair_device_not_powered_test_1 = {
	.send_opcode = MGMT_OP_UNPAIR_DEVICE,
	.send_param = unpair_device_param,
	.send_len = sizeof(unpair_device_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.expect_param = unpair_device_rsp,
	.expect_len = sizeof(unpair_device_rsp),
};

static const struct generic_data unpair_device_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_UNPAIR_DEVICE,
	.send_param = unpair_device_invalid_param_1,
	.send_len = sizeof(unpair_device_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = unpair_device_invalid_param_rsp_1,
	.expect_len = sizeof(unpair_device_invalid_param_rsp_1),
};

static const struct generic_data unpair_device_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_UNPAIR_DEVICE,
	.send_param = unpair_device_invalid_param_2,
	.send_len = sizeof(unpair_device_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = unpair_device_invalid_param_rsp_2,
	.expect_len = sizeof(unpair_device_invalid_param_rsp_2),
};

static const char disconnect_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
static const char disconnect_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };

static const struct generic_data disconnect_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_DISCONNECT,
	.send_param = disconnect_invalid_param_1,
	.send_len = sizeof(disconnect_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = disconnect_invalid_param_rsp_1,
	.expect_len = sizeof(disconnect_invalid_param_rsp_1),
};

static const char block_device_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
static const char block_device_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };

static const struct generic_data block_device_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_BLOCK_DEVICE,
	.send_param = block_device_invalid_param_1,
	.send_len = sizeof(block_device_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = block_device_invalid_param_rsp_1,
	.expect_len = sizeof(block_device_invalid_param_rsp_1),
};

static const char unblock_device_invalid_param_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };
static const char unblock_device_invalid_param_rsp_1[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff };

static const struct generic_data unblock_device_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_UNBLOCK_DEVICE,
	.send_param = unblock_device_invalid_param_1,
	.send_len = sizeof(unblock_device_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = unblock_device_invalid_param_rsp_1,
	.expect_len = sizeof(unblock_device_invalid_param_rsp_1),
};

static void powered_delay(void *user_data)
{
	tester_setup_complete();
}

static void setup_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	/* FIXME: Delay here to not get confused by existing kernel bug
	 * with missing synchronization of some HCI commands */
	tester_wait(1, powered_delay, NULL);
}

static void setup_powered_discoverable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char discov_param[] = { 0x01, 0x00, 0x00 };

	tester_print("Powering on connectable controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_DISCOVERABLE, data->mgmt_index,
					sizeof(discov_param), discov_param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_powered_connectable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on connectable controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_class(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char class_param[] = { 0x01, 0x0c };

	tester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_DEV_CLASS, data->mgmt_index,
				sizeof(class_param), class_param,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_ssp(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with SSP enabled)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid16(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with SPP UUID)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_spp_uuid_param), add_spp_uuid_param,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_connectable_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller connectable on");

	tester_setup_complete();
}

static void setup_connectable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Setting controller connectable");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					setup_connectable_callback, NULL, NULL);
}

static void command_generic_new_settings(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("New settings event received");

	mgmt_unregister(data->mgmt, data->mgmt_settings_id);

	tester_test_failed();
}

static void command_generic_new_settings_alt(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	uint32_t settings;

	if (length != 4) {
		tester_warn("Invalid parameter size for new settings event");
		tester_test_failed();
		return;
	}

	settings = bt_get_le32(param);

	tester_print("New settings 0x%08x received", settings);

	if (test->expect_settings_unset) {
		if ((settings & test->expect_settings_unset) != 0)
			return;
		goto done;
	}

	if (!test->expect_settings_set)
		return;

	if ((settings & test->expect_settings_set) != test->expect_settings_set)
		return;

done:
	tester_print("Unregistering new settings notification");

	mgmt_unregister(data->mgmt_alt, data->mgmt_alt_settings_id);

	test_condition_complete(data);
}

static void command_generic_class_changed_alt(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const struct mgmt_ev_class_of_dev_changed *ev = param;

	if (length != sizeof(*ev)) {
		tester_warn("Invalid length Class of Device changed event");
		tester_test_failed();
		return;
	}

	tester_print("New Class of Device 0x%02x%02x%02x received",
				ev->class_of_dev[2], ev->class_of_dev[1],
				ev->class_of_dev[0]);

	if (!test->expect_class_of_dev)
		return;

	if (memcmp(ev->class_of_dev, test->expect_class_of_dev, 3) != 0)
		return;

	tester_print("Unregistering Class of Device notification");

	mgmt_unregister(data->mgmt_alt, data->mgmt_alt_class_id);

	test_condition_complete(data);
}

static void command_generic_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	tester_print("Command 0x%04x finished with status 0x%02x",
						test->send_opcode, status);

	if (status != test->expect_status) {
		tester_test_failed();
		return;
	}

	if (length != test->expect_len) {
		tester_test_failed();
		return;
	}

	if (test->expect_param && test->expect_len > 0 &&
				memcmp(param, test->expect_param, length)) {
		tester_test_failed();
		return;
	}

	test_condition_complete(data);
}

static void command_hci_callback(uint16_t opcode, const void *param,
					uint8_t length, void *user_data)
{
	struct test_data *data = user_data;
	const struct generic_data *test = data->test_data;

	tester_print("HCI Command 0x%04x length %u", opcode, length);

	if (opcode != test->expect_hci_command)
		return;

	if (length != test->expect_hci_len) {
		tester_warn("Invalid parameter size for HCI command");
		tester_test_failed();
		return;
	}

	if (memcmp(param, test->expect_hci_param, length) != 0) {
		tester_warn("Unexpected HCI command parameter value");
		tester_test_failed();
		return;
	}

	test_condition_complete(data);
}

static void test_command_generic(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	unsigned int id;
	uint16_t index;

	index = test->send_index_none ? MGMT_INDEX_NONE : data->mgmt_index;

	if (test->expect_settings_set || test->expect_settings_unset) {
		tester_print("Registering new settings notification");

		id = mgmt_register(data->mgmt, MGMT_EV_NEW_SETTINGS, index,
				command_generic_new_settings, NULL, NULL);
		data->mgmt_settings_id = id;

		id = mgmt_register(data->mgmt_alt, MGMT_EV_NEW_SETTINGS, index,
				command_generic_new_settings_alt, NULL, NULL);
		data->mgmt_alt_settings_id = id;
		test_add_condition(data);
	}

	if (test->expect_class_of_dev) {
		tester_print("Registering Class of Device notification");
		id = mgmt_register(data->mgmt_alt,
					MGMT_EV_CLASS_OF_DEV_CHANGED, index,
					command_generic_class_changed_alt,
					NULL, NULL);
		data->mgmt_alt_class_id = id;
		test_add_condition(data);
	}

	if (test->expect_hci_command) {
		tester_print("Registering HCI command callback");
		hciemu_add_master_post_command_hook(data->hciemu,
						command_hci_callback, data);
		test_add_condition(data);
	}

	tester_print("Sending command 0x%04x", test->send_opcode);

	mgmt_send(data->mgmt, test->send_opcode, index,
					test->send_len, test->send_param,
					command_generic_callback, NULL, NULL);
	test_add_condition(data);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_bredr("Controller setup", NULL, NULL, controller_setup);
	test_bredr("Invalid command", &invalid_command_test,
					NULL, test_command_generic);

	test_bredr("Read version - Invalid parameters",
					&read_version_invalid_param_test,
					NULL, test_command_generic);
	test_bredr("Read version - Invalid index",
					&read_version_invalid_index_test,
					NULL, test_command_generic);
	test_bredr("Read commands - Invalid parameters",
					&read_commands_invalid_param_test,
					NULL, test_command_generic);
	test_bredr("Read commands - Invalid index",
					&read_commands_invalid_index_test,
					NULL, test_command_generic);
	test_bredr("Read index list - Invalid parameters",
					&read_index_list_invalid_param_test,
					NULL, test_command_generic);
	test_bredr("Read index list - Invalid index",
					&read_index_list_invalid_index_test,
					NULL, test_command_generic);
	test_bredr("Read info - Invalid parameters",
					&read_info_invalid_param_test,
					NULL, test_command_generic);
	test_bredr("Read info - Invalid index",
					&read_info_invalid_index_test,
					NULL, test_command_generic);

	test_bredr("Set powered on - Success",
					&set_powered_on_success_test,
					NULL, test_command_generic);
	test_bredr("Set powered on - Invalid parameters 1",
					&set_powered_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredr("Set powered on - Invalid parameters 2",
					&set_powered_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredr("Set powered on - Invalid parameters 3",
					&set_powered_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredr("Set powered on - Invalid index",
					&set_powered_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredr("Set powered off - Success", &set_powered_off_success_test,
					setup_powered, test_command_generic);
	test_bredr("Set powered off - Class of Device",
					&set_powered_off_class_test,
					setup_class, test_command_generic);

	test_bredr("Set connectable on - Success 1",
					&set_connectable_on_success_test_1,
					NULL, test_command_generic);
	test_bredr("Set connectable on - Success 2",
					&set_connectable_on_success_test_2,
					setup_powered, test_command_generic);
	test_bredr("Set connectable on - Invalid parameters 1",
					&set_connectable_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredr("Set connectable on - Invalid parameters 2",
					&set_connectable_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredr("Set connectable on - Invalid parameters 3",
					&set_connectable_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredr("Set connectable on - Invalid index",
					&set_connectable_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredr("Set pairable on - Success",
					&set_pairable_on_success_test,
					NULL, test_command_generic);
	test_bredr("Set pairable on - Invalid parameters 1",
					&set_pairable_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredr("Set pairable on - Invalid parameters 2",
					&set_pairable_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredr("Set pairable on - Invalid parameters 3",
					&set_pairable_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredr("Set pairable on - Invalid index",
					&set_pairable_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredr("Set discoverable on - Invalid parameters 1",
				&set_discoverable_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredr("Set discoverable on - Invalid parameters 2",
				&set_discoverable_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredr("Set discoverable on - Invalid parameters 3",
				&set_discoverable_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredr("Set discoverable on - Invalid parameters 4",
				&set_discoverable_on_invalid_param_test_4,
				NULL, test_command_generic);
	test_bredr("Set discoverable on - Not powered 1",
				&set_discoverable_on_not_powered_test_1,
				NULL, test_command_generic);
	test_bredr("Set discoverable on - Not powered 1",
				&set_discoverable_on_not_powered_test_1,
				NULL, test_command_generic);
	test_bredr("Set discoverable on - Not powered 2",
				&set_discoverable_on_not_powered_test_1,
				setup_connectable, test_command_generic);
	test_bredr("Set discoverable on - Rejected 1",
				&set_discoverable_on_rejected_test_1,
				setup_powered, test_command_generic);
	test_bredr("Set discoverable on - Rejected 2",
				&set_discoverable_on_rejected_test_2,
				setup_powered, test_command_generic);
	test_bredr("Set discoverable on - Rejected 3",
				&set_discoverable_on_rejected_test_3,
				setup_powered, test_command_generic);
	test_bredr("Set discoverable on - Success 1",
				&set_discoverable_on_success_test_1,
				setup_connectable, test_command_generic);
	test_bredr("Set discoverable on - Success 2",
				&set_discoverable_on_success_test_2,
				setup_powered_connectable, test_command_generic);
	test_bredr("Set discoverable off - Success 1",
				&set_discoverable_off_success_test_1,
				setup_connectable, test_command_generic);
	test_bredr("Set discoverable off - Success 2",
				&set_discoverable_off_success_test_2,
				setup_powered_discoverable,
				test_command_generic);

	test_bredr("Set link security on - Success 1",
					&set_link_sec_on_success_test_1,
					NULL, test_command_generic);
	test_bredr("Set link security on - Success 2",
					&set_link_sec_on_success_test_2,
					setup_powered, test_command_generic);
	test_bredr("Set link security on - Invalid parameters 1",
					&set_link_sec_on_invalid_param_test_1,
					NULL, test_command_generic);
	test_bredr("Set link security on - Invalid parameters 2",
					&set_link_sec_on_invalid_param_test_2,
					NULL, test_command_generic);
	test_bredr("Set link security on - Invalid parameters 3",
					&set_link_sec_on_invalid_param_test_3,
					NULL, test_command_generic);
	test_bredr("Set link security on - Invalid index",
					&set_link_sec_on_invalid_index_test,
					NULL, test_command_generic);

	test_bredr("Start Discovery - Not powered 1",
				&start_discovery_not_powered_test_1,
				NULL, test_command_generic);
	test_bredr("Start Discovery - Invalid parameters 1",
				&start_discovery_invalid_param_test_1,
				setup_powered, test_command_generic);
	test_bredr("Start Discovery - Not supported 1",
				&start_discovery_not_supported_test_1,
				setup_powered, test_command_generic);

	test_bredr("Set Device Class - Success 1",
				&set_dev_class_valid_param_test_1,
				NULL, test_command_generic);
	test_bredr("Set Device Class - Success 2",
				&set_dev_class_valid_param_test_2,
				setup_powered, test_command_generic);
	test_bredr("Set Device Class - Invalid parameters 1",
				&set_dev_class_invalid_param_test_1,
				NULL, test_command_generic);

	test_bredr("Add UUID - UUID-16 1", &add_uuid16_test_1,
				setup_ssp, test_command_generic);
	test_bredr("Add UUID - UUID-16 multiple 1", &add_multi_uuid16_test_1,
				setup_multi_uuid16, test_command_generic);
	test_bredr("Add UUID - UUID-32 1", &add_uuid32_test_1, setup_ssp,
				test_command_generic);

	test_bredr("Load Link Keys - Empty List Success 1",
			&load_link_keys_success_test_1, NULL,
			test_command_generic);
	test_bredr("Load Link Keys - Empty List Success 2",
			&load_link_keys_success_test_2, NULL,
			test_command_generic);
	test_bredr("Load Link Keys - Invalid Parameters 1",
			&load_link_keys_invalid_params_test_1, NULL,
			test_command_generic);
	test_bredr("Load Link Keys - Invalid Parameters 2",
			&load_link_keys_invalid_params_test_2, NULL,
			test_command_generic);
	test_bredr("Load Link Keys - Invalid Parameters 3",
			&load_link_keys_invalid_params_test_3, NULL,
			test_command_generic);

	test_bredr("Load Long Term Keys - Success 1",
			&load_ltks_success_test_1, NULL, test_command_generic);
	test_bredr("Load Long Term Keys - Invalid Parameters 1",
			&load_ltks_invalid_params_test_1, NULL,
			test_command_generic);
	test_bredr("Load Long Term Keys - Invalid Parameters 2",
			&load_ltks_invalid_params_test_2, NULL,
			test_command_generic);
	test_bredr("Load Long Term Keys - Invalid Parameters 3",
			&load_ltks_invalid_params_test_3, NULL,
			test_command_generic);
	test_bredr("Load Long Term Keys - Invalid Parameters 4",
			&load_ltks_invalid_params_test_4, NULL,
			test_command_generic);

	test_bredr("Pair Device - Not Powered 1",
			&pair_device_not_powered_test_1, NULL,
			test_command_generic);
	test_bredr("Pair Device - Invalid Parameters 1",
			&pair_device_invalid_param_test_1, NULL,
			test_command_generic);

	test_bredr("Unpair Device - Not Powered 1",
			&unpair_device_not_powered_test_1, NULL,
			test_command_generic);
	test_bredr("Unpair Device - Invalid Parameters 1",
			&unpair_device_invalid_param_test_1, NULL,
			test_command_generic);
	test_bredr("Unpair Device - Invalid Parameters 2",
			&unpair_device_invalid_param_test_2, NULL,
			test_command_generic);

	test_bredr("Disconnect - Invalid Parameters 1",
			&disconnect_invalid_param_test_1, NULL,
			test_command_generic);

	test_bredr("Block Device - Invalid Parameters 1",
			&block_device_invalid_param_test_1, NULL,
			test_command_generic);

	test_bredr("Unblock Device - Invalid Parameters 1",
			&unblock_device_invalid_param_test_1, NULL,
			test_command_generic);

	return tester_run();
}
