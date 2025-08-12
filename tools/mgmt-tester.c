// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"
#include "bluetooth/hci_lib.h"
#include "bluetooth/mgmt.h"
#include "bluetooth/l2cap.h"

#include "monitor/bt.h"
#include "emulator/vhci.h"
#include "emulator/bthost.h"
#include "emulator/hciemu.h"
#include "emulator/btdev.h"

#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/queue.h"

struct test_data {
	tester_data_func_t test_setup;
	const void *test_data;
	uint8_t expected_version;
	uint16_t expected_manufacturer;
	uint32_t expected_supported_settings;
	uint32_t initial_settings;
	struct mgmt *mgmt;
	struct mgmt *mgmt_alt;
	unsigned int mgmt_settings_id;
	unsigned int mgmt_alt_settings_id;
	unsigned int mgmt_alt_ev_id;
	unsigned int mgmt_discov_ev_id;
	uint8_t mgmt_version;
	uint16_t mgmt_revision;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	bool expect_hci_command_done;
	struct queue *expect_hci_q;
	int unmet_conditions;
	int unmet_setup_conditions;
	int sk;
};

static void print_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (data->sk >= 0)
		close(data->sk);

	queue_destroy(data->expect_hci_q, NULL);

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void test_pre_setup_failed(void)
{
	test_post_teardown(NULL);
	tester_pre_setup_failed();
}

static void read_version_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_version *rp = param;

	tester_print("Read Version callback");
	tester_print("  Status: %s (0x%02x)", mgmt_errstr(status), status);

	if (status || !param) {
		test_pre_setup_failed();
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
	tester_print("  Status: %s (0x%02x)", mgmt_errstr(status), status);

	if (status || !param) {
		test_pre_setup_failed();
		return;
	}
}

static bool check_settings(uint32_t supported, uint32_t expected)
{
	int i;

	if (supported == expected)
		return true;

	for (i = 0; i < 17; i++) {
		if (supported & BIT(i))
			continue;

		if (expected & BIT(i)) {
			tester_warn("Expected bit %u not supported", i);
			return false;
		}
	}

	return true;
}

static void read_info_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_info *rp = param;
	char addr[18];
	uint16_t manufacturer;
	uint32_t supported_settings, current_settings;
	struct bthost *bthost;

	tester_print("Read Info callback");
	tester_print("  Status: %s (0x%02x)", mgmt_errstr(status), status);

	if (status || !param) {
		test_pre_setup_failed();
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
		test_pre_setup_failed();
		return;
	}

	if (rp->version != data->expected_version) {
		tester_warn("Expected version: 0x%02x != 0x%02x",
				rp->version, data->expected_version);
		test_pre_setup_failed();
		return;
	}

	if (manufacturer != data->expected_manufacturer) {
		tester_warn("Expected manufacturer: 0x%04x != 0x%04x",
				manufacturer, data->expected_manufacturer);
		test_pre_setup_failed();
		return;
	}

	if (!check_settings(supported_settings,
				data->expected_supported_settings)) {
		tester_warn("Expected supported settings: 0x%08x != 0x%08x",
				supported_settings,
				data->expected_supported_settings);
		test_pre_setup_failed();
		return;
	}

	if (!check_settings(current_settings, data->initial_settings)) {
		tester_warn("Initial settings: 0x%08x != 0x%08x",
				current_settings, data->initial_settings);
		test_pre_setup_failed();
		return;
	}

	if (rp->dev_class[0] != 0x00 || rp->dev_class[1] != 0x00 ||
						rp->dev_class[2] != 0x00) {
		test_pre_setup_failed();
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_notify_ready(bthost, tester_pre_setup_complete);
}

static const uint8_t set_exp_feat_param_mesh[] = {
	0x76, 0x6e, 0xf3, 0xe8, 0x24, 0x5f, 0x05, 0xbf, /* UUID - Mesh */
	0x8d, 0x4d, 0x03, 0x7a, 0xd7, 0x63, 0xe4, 0x2c,
	0x01,						/* Action - enable */
};

static void mesh_exp_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_print("Mesh feature could not be enabled");
		return;
	}

	tester_print("Mesh feature is enabled");
}

static void mesh_exp_feature(struct test_data *data, uint16_t index)
{
	tester_print("Enabling Mesh feature");

	mgmt_send(data->mgmt, MGMT_OP_SET_EXP_FEATURE, index,
		  sizeof(set_exp_feat_param_mesh), set_exp_feat_param_mesh,
		  mesh_exp_callback, NULL, NULL);
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

	tester_warn("Enable management Mesh interface");
	mesh_exp_feature(data, data->mgmt_index);

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

#define MAX_COREDUMP_LINE_LEN	40

struct devcoredump_test_data {
	enum devcoredump_state {
		HCI_DEVCOREDUMP_IDLE,
		HCI_DEVCOREDUMP_ACTIVE,
		HCI_DEVCOREDUMP_DONE,
		HCI_DEVCOREDUMP_ABORT,
		HCI_DEVCOREDUMP_TIMEOUT,
	} state;
	unsigned int timeout;
	char data[MAX_COREDUMP_LINE_LEN];
};

struct hci_cmd_data {
	uint16_t opcode;
	uint8_t len;
	const void *param;
};

struct hci_entry {
	const struct hci_cmd_data *cmd_data;
};

struct generic_data {
	bdaddr_t *setup_bdaddr;
	bool setup_le_states;
	const uint8_t *le_states;
	const uint16_t *setup_settings;
	bool setup_nobredr;
	bool setup_limited_discov;
	const void *setup_exp_feat_param;
	uint16_t setup_expect_hci_command;
	const void *setup_expect_hci_param;
	uint8_t setup_expect_hci_len;
	uint16_t setup_send_opcode;
	const void *setup_send_param;
	uint16_t setup_send_len;
	const struct setup_mgmt_cmd *setup_mgmt_cmd_arr;
	size_t setup_mgmt_cmd_arr_size;
	bool send_index_none;
	const void *setup_discovery_param;
	uint16_t send_opcode;
	const void *send_param;
	uint16_t send_len;
	const void * (*send_func)(uint16_t *len);
	uint8_t expect_status;
	bool expect_ignore_param;
	const void *expect_param;
	uint16_t expect_len;
	const void * (*expect_func)(uint16_t *len);
	uint32_t expect_settings_set;
	uint32_t expect_settings_unset;
	uint16_t expect_alt_ev;
	const void *expect_alt_ev_param;
	bool (*verify_alt_ev_func)(const void *param, uint16_t length);
	uint16_t expect_alt_ev_len;
	uint16_t expect_hci_command;
	const void *expect_hci_param;
	int (*expect_hci_param_check_func)(const void *param, uint16_t length);
	uint8_t expect_hci_len;
	const void * (*expect_hci_func)(uint8_t *len);
	const struct hci_cmd_data *expect_hci_list;
	bool expect_pin;
	uint8_t pin_len;
	const void *pin;
	uint8_t client_pin_len;
	const void *client_pin;
	bool client_enable_ssp;
	uint8_t io_cap;
	uint8_t client_io_cap;
	uint8_t client_auth_req;
	bool reject_confirm;
	bool client_reject_confirm;
	bool just_works;
	bool client_enable_le;
	bool client_enable_sc;
	bool client_enable_adv;
	bool expect_sc_key;
	bool force_power_off;
	bool addr_type_avail;
	bool fail_tolerant;
	uint8_t addr_type;
	bool set_adv;
	const uint8_t *adv_data;
	uint8_t adv_data_len;
	const struct devcoredump_test_data *dump_data;
	const char (*expect_dump_data)[MAX_COREDUMP_LINE_LEN];
};

static const uint8_t set_exp_feat_param_debug[] = {
	0x1c, 0xda, 0x47, 0x1c, 0x48, 0x6c, 0x01, 0xab, /* UUID - Debug */
	0x9f, 0x46, 0xec, 0xb9, 0x30, 0x25, 0x99, 0xd4,
	0x01,						/* Action - enable */
};

static void debug_exp_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_print("Debug feature could not be enabled");
		return;
	}

	tester_print("Debug feature is enabled");
}

static void debug_exp_feature(struct test_data *data)
{
	tester_print("Enabling Debug feature");

	mgmt_send(data->mgmt, MGMT_OP_SET_EXP_FEATURE, MGMT_INDEX_NONE,
		  sizeof(set_exp_feat_param_debug), set_exp_feat_param_debug,
		  debug_exp_callback, NULL, NULL);
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	tester_print("Read Index List callback");
	tester_print("  Status: %s (0x%02x)", mgmt_errstr(status), status);

	if (status || !param) {
		test_pre_setup_failed();
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new(data->hciemu_type);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		test_pre_setup_failed();
	}

	if (tester_use_debug())
		hciemu_set_debug(data->hciemu, print_debug, "hciemu: ", NULL);

	if (test && test->setup_bdaddr) {
		struct vhci *vhci = hciemu_get_vhci(data->hciemu);
		struct btdev *btdev = vhci_get_btdev(vhci);

		if (!btdev_set_bdaddr(btdev, test->setup_bdaddr->b)) {
			tester_warn("btdev_set_bdaddr failed");
			tester_pre_setup_failed();
		}
	}

	if (test && test->setup_le_states)
		hciemu_set_central_le_states(data->hciemu, test->le_states);

}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		test_pre_setup_failed();
		return;
	}

	data->mgmt_alt = mgmt_new_default();
	if (!data->mgmt_alt) {
		tester_warn("Failed to setup alternate management interface");
		test_pre_setup_failed();

		mgmt_unref(data->mgmt);
		data->mgmt = NULL;
		return;
	}

	if (tester_use_debug()) {
		mgmt_set_debug(data->mgmt, print_debug, "mgmt: ", NULL);
		mgmt_set_debug(data->mgmt_alt, print_debug, "mgmt-alt: ", NULL);
		debug_exp_feature(data);
	}

	mgmt_send(data->mgmt, MGMT_OP_READ_VERSION, MGMT_INDEX_NONE, 0, NULL,
					read_version_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_COMMANDS, MGMT_INDEX_NONE, 0, NULL,
					read_commands_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);

	data->sk = -1;
}

static void test_add_condition(struct test_data *data)
{
	data->unmet_conditions++;

	tester_print("Test condition added, total %d", data->unmet_conditions);
}

static void test_add_setup_condition(struct test_data *data)
{
	data->unmet_setup_conditions++;

	tester_print("Test setup condition added, total %d",
		     data->unmet_setup_conditions);
}

static void test_setup_condition_complete(struct test_data *data)
{
	data->unmet_setup_conditions--;

	tester_print("Test setup condition complete, %d left",
		     data->unmet_setup_conditions);

	if (data->unmet_setup_conditions > 0)
		return;

	tester_setup_complete();
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

#define test_full(name, data, setup, func, timeout, type, version, \
			expected_settings, settings) \
	do { \
		struct test_data *user; \
		user = new0(struct test_data, 1); \
		user->hciemu_type = type; \
		user->test_setup = setup; \
		user->test_data = data; \
		user->expected_version = version; \
		user->expected_manufacturer = 0x05f1; \
		user->expected_supported_settings = expected_settings; \
		user->initial_settings = settings; \
		tester_add_full(name, data, \
				test_pre_setup, test_setup, func, NULL, \
				test_post_teardown, timeout, user, free); \
	} while (0)

#define test_bredrle_full(name, data, setup, func, timeout) \
	test_full(name, data, setup, func, timeout, HCIEMU_TYPE_BREDRLE, \
					0x09, 0x0001beff, 0x00000080)

#define test_bredrle(name, data, setup, func) \
	test_bredrle_full(name, data, setup, func, 2)

#define test_bredr20(name, data, setup, func) \
	test_full(name, data, setup, func, 2, HCIEMU_TYPE_LEGACY, \
					0x03, 0x000110bf, 0x00000080)

#define test_bredr(name, data, setup, func) \
	test_full(name, data, setup, func, 2, HCIEMU_TYPE_BREDR, \
					0x05, 0x000110ff, 0x00000080)

#define test_le_full(name, data, setup, func, timeout) \
	test_full(name, data, setup, func, timeout, HCIEMU_TYPE_LE, \
					0x09, 0x0001be1b, 0x00000200)

#define test_le(name, data, setup, func) \
	test_le_full(name, data, setup, func, 2)

#define test_bredrle50_full(name, data, setup, func, timeout) \
	test_full(name, data, setup, func, timeout, HCIEMU_TYPE_BREDRLE50, \
					0x09, 0x0001beff, 0x00000080)

#define test_bredrle50(name, data, setup, func) \
	test_bredrle50_full(name, data, setup, func, 2)

#define test_hs_full(name, data, setup, func, timeout) \
	test_full(name, data, setup, func, timeout, HCIEMU_TYPE_BREDRLE, \
					0x09, 0x0001bfff, 0x00000080)

#define test_hs(name, data, setup, func) \
	test_hs_full(name, data, setup, func, 2)

static void controller_setup(const void *test_data)
{
	tester_test_passed();
}

struct setup_mgmt_cmd {
	uint8_t send_opcode;
	const void *send_param;
	uint16_t send_len;
};

static const char dummy_data[] = { 0x00 };

static const struct generic_data invalid_command_test = {
	.send_opcode = 0xffff,
	.expect_status = MGMT_STATUS_UNKNOWN_COMMAND,
};

static const struct generic_data read_version_success_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_VERSION,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_len = 3,
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

static const struct generic_data read_unconf_index_list_invalid_param_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_UNCONF_INDEX_LIST,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_unconf_index_list_invalid_index_test = {
	.send_opcode = MGMT_OP_READ_UNCONF_INDEX_LIST,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_config_info_invalid_param_test = {
	.send_opcode = MGMT_OP_READ_CONFIG_INFO,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_config_info_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_CONFIG_INFO,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_ext_index_list_invalid_param_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_EXT_INDEX_LIST,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_ext_index_list_invalid_index_test = {
	.send_opcode = MGMT_OP_READ_EXT_INDEX_LIST,
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

static uint16_t settings_powered_advertising_privacy[] = {
						MGMT_OP_SET_PRIVACY,
						MGMT_OP_SET_ADVERTISING,
						MGMT_OP_SET_POWERED, 0 };

static const char set_adv_off_param[] = { 0x00 };

static const struct generic_data set_powered_on_privacy_adv_test = {
	.setup_settings = settings_powered_advertising_privacy,
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_off_param,
	.send_len = sizeof(set_adv_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_ignore_param = true,
};

static const uint16_t settings_powered[] = { MGMT_OP_SET_POWERED, 0 };

static const char set_powered_off_param[] = { 0x00 };
static const char set_powered_off_settings_param[] = { 0x80, 0x00, 0x00, 0x00 };
static const char set_powered_off_class_of_dev[] = { 0x00, 0x00, 0x00 };

static const struct generic_data set_powered_off_success_test = {
	.setup_settings = settings_powered,
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
	.expect_alt_ev = MGMT_EV_CLASS_OF_DEV_CHANGED,
	.expect_alt_ev_param = set_powered_off_class_of_dev,
	.expect_alt_ev_len = sizeof(set_powered_off_class_of_dev),
};

static const struct generic_data set_powered_off_invalid_param_test_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_POWERED,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_off_invalid_param_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_invalid_param,
	.send_len = sizeof(set_powered_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_powered_off_invalid_param_test_3 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_garbage_param,
	.send_len = sizeof(set_powered_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
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
	.setup_settings = settings_powered,
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

static uint16_t settings_powered_advertising[] = { MGMT_OP_SET_ADVERTISING,
						MGMT_OP_SET_POWERED, 0 };

static const char set_connectable_le_settings_param_1[] = { 0x02, 0x02, 0x00, 0x00 };
static const char set_connectable_le_settings_param_2[] = { 0x03, 0x02, 0x00, 0x00 };
static const char set_connectable_le_settings_param_3[] = { 0x03, 0x06, 0x00, 0x00 };

static const struct generic_data set_connectable_on_le_test_1 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_le_settings_param_1,
	.expect_len = sizeof(set_connectable_le_settings_param_1),
	.expect_settings_set = MGMT_SETTING_CONNECTABLE,
};

static const struct generic_data set_connectable_on_le_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_le_settings_param_2,
	.expect_len = sizeof(set_connectable_le_settings_param_2),
	.expect_settings_set = MGMT_SETTING_CONNECTABLE,
};

static uint8_t set_connectable_on_adv_param[] = {
		0x00, 0x08,				/* min_interval */
		0x00, 0x08,				/* max_interval */
		0x00,					/* type */
		0x00,					/* own_addr_type */
		0x00,					/* direct_addr_type */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* direct_addr */
		0x07,					/* channel_map */
		0x00,					/* filter_policy */
};

static const struct generic_data set_connectable_on_le_test_3 = {
	.setup_settings = settings_powered_advertising,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_le_settings_param_3,
	.expect_len = sizeof(set_connectable_le_settings_param_3),
	.expect_settings_set = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_on_adv_param,
	.expect_hci_len = sizeof(set_connectable_on_adv_param),
};

static const uint16_t settings_connectable[] = { MGMT_OP_SET_CONNECTABLE, 0 };
static const uint16_t settings_powered_connectable[] = {
						MGMT_OP_SET_CONNECTABLE,
						MGMT_OP_SET_POWERED, 0 };
static const uint16_t settings_powered_discoverable[] = {
						MGMT_OP_SET_CONNECTABLE,
						MGMT_OP_SET_DISCOVERABLE,
						MGMT_OP_SET_POWERED, 0 };

static const char set_connectable_off_param[] = { 0x00 };
static const char set_connectable_off_settings_1[] = { 0x80, 0x00, 0x00, 0x00 };
static const char set_connectable_off_settings_2[] = { 0x81, 0x00, 0x00, 0x00 };
static const char set_connectable_off_scan_enable_param[] = { 0x00 };

static const struct generic_data set_connectable_off_success_test_1 = {
	.setup_settings = settings_connectable,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_settings_1,
	.expect_len = sizeof(set_connectable_off_settings_1),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
};

static const struct generic_data set_connectable_off_success_test_2 = {
	.setup_settings = settings_powered_connectable,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_settings_2,
	.expect_len = sizeof(set_connectable_off_settings_2),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_connectable_off_scan_enable_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_enable_param),
};

static const struct generic_data set_connectable_off_success_test_3 = {
	.setup_settings = settings_powered_discoverable,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_settings_2,
	.expect_len = sizeof(set_connectable_off_settings_2),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_connectable_off_scan_enable_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_enable_param),
};

static const struct generic_data set_connectable_off_success_test_4 = {
	.setup_settings = settings_powered_discoverable,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_settings_2,
	.expect_len = sizeof(set_connectable_off_settings_2),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_connectable_scan_enable_param,
	.expect_hci_len = sizeof(set_connectable_scan_enable_param),
};

static const char set_connectable_off_le_settings_1[] = { 0x00, 0x02, 0x00, 0x00 };
static const char set_connectable_off_le_settings_2[] = { 0x01, 0x06, 0x00, 0x00 };

static uint16_t settings_le_connectable[] = { MGMT_OP_SET_LE,
						MGMT_OP_SET_CONNECTABLE, 0 };

static const struct generic_data set_connectable_off_le_test_1 = {
	.setup_settings = settings_le_connectable,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_le_settings_1,
	.expect_len = sizeof(set_connectable_off_le_settings_1),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
};

static uint16_t settings_powered_le_connectable_advertising[] = {
					MGMT_OP_SET_LE,
					MGMT_OP_SET_CONNECTABLE,
					MGMT_OP_SET_ADVERTISING,
					MGMT_OP_SET_POWERED, 0 };

static uint8_t set_connectable_off_scan_adv_param[] = {
		0x64, 0x00,				/* min_interval */
		0x96, 0x00,				/* max_interval */
		0x02,					/* type */
		0x01,					/* own_addr_type */
		0x00,					/* direct_addr_type */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* direct_addr */
		0x07,					/* channel_map */
		0x00,					/* filter_policy */
};

static int set_connectable_off_scan_adv_check_func(const void *param,
								uint16_t length)
{
	const uint8_t *received = param;
	uint8_t *expected = set_connectable_off_scan_adv_param;

	/* Compare the received param with expected param, but ignore the
	 * min_internal and max_interval since these values are turned often
	 * in the kernel and we don't want to update the expected value every
	 * time.
	 */
	return memcmp(&received[4], &expected[4], length - 4);
}

static const struct generic_data set_connectable_off_le_test_2 = {
	.setup_settings = settings_powered_le_connectable_advertising,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_le_settings_2,
	.expect_len = sizeof(set_connectable_off_le_settings_2),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_off_scan_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_adv_param),
	.expect_hci_param_check_func = set_connectable_off_scan_adv_check_func
};

static uint16_t settings_powered_le_discoverable[] = {
					MGMT_OP_SET_LE,
					MGMT_OP_SET_CONNECTABLE,
					MGMT_OP_SET_POWERED,
					MGMT_OP_SET_DISCOVERABLE, 0 };

static uint16_t settings_powered_le_discoverable_advertising[] = {
					MGMT_OP_SET_LE,
					MGMT_OP_SET_CONNECTABLE,
					MGMT_OP_SET_ADVERTISING,
					MGMT_OP_SET_POWERED,
					MGMT_OP_SET_DISCOVERABLE, 0 };

static const struct generic_data set_connectable_off_le_test_3 = {
	.setup_settings = settings_powered_le_discoverable_advertising,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_le_settings_2,
	.expect_len = sizeof(set_connectable_off_le_settings_2),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_off_scan_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_adv_param),
	.expect_hci_param_check_func = set_connectable_off_scan_adv_check_func
};

static const struct generic_data set_connectable_off_le_test_4 = {
	.setup_settings = settings_powered_le_discoverable_advertising,
	.setup_limited_discov = true,
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_off_le_settings_2,
	.expect_len = sizeof(set_connectable_off_le_settings_2),
	.expect_settings_unset = MGMT_SETTING_CONNECTABLE,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_off_scan_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_adv_param),
	.expect_hci_param_check_func = set_connectable_off_scan_adv_check_func
};

static const char set_fast_conn_on_param[] = { 0x01 };
static const char set_fast_conn_on_settings_1[] = { 0x87, 0x00, 0x00, 0x00 };
static const char set_fast_conn_on_settings_2[] = { 0x85, 0x00, 0x00, 0x00 };
static const char set_fast_conn_on_settings_3[] = { 0x84, 0x00, 0x00, 0x00 };

static const struct generic_data set_fast_conn_on_success_test_1 = {
	.setup_settings = settings_powered_connectable,
	.send_opcode = MGMT_OP_SET_FAST_CONNECTABLE,
	.send_param = set_fast_conn_on_param,
	.send_len = sizeof(set_fast_conn_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_fast_conn_on_settings_1,
	.expect_len = sizeof(set_fast_conn_on_settings_1),
	.expect_settings_set = MGMT_SETTING_FAST_CONNECTABLE,
};

static const struct generic_data set_fast_conn_on_success_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_FAST_CONNECTABLE,
	.send_param = set_fast_conn_on_param,
	.send_len = sizeof(set_fast_conn_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_fast_conn_on_settings_2,
	.expect_len = sizeof(set_fast_conn_on_settings_2),
	.expect_settings_set = MGMT_SETTING_FAST_CONNECTABLE,
};

static const struct generic_data set_fast_conn_on_success_test_3 = {
	.send_opcode = MGMT_OP_SET_FAST_CONNECTABLE,
	.send_param = set_fast_conn_on_param,
	.send_len = sizeof(set_fast_conn_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_fast_conn_on_settings_3,
	.expect_len = sizeof(set_fast_conn_on_settings_3),
	.expect_settings_set = MGMT_SETTING_FAST_CONNECTABLE,
};

static const struct generic_data set_fast_conn_on_not_supported_test_1 = {
	.setup_settings = settings_powered_connectable,
	.send_opcode = MGMT_OP_SET_FAST_CONNECTABLE,
	.send_param = set_fast_conn_on_param,
	.send_len = sizeof(set_fast_conn_on_param),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const char set_fast_conn_nval_param[] = { 0xff };

static const struct generic_data set_fast_conn_nval_param_test_1 = {
	.send_opcode = MGMT_OP_SET_FAST_CONNECTABLE,
	.send_param = set_fast_conn_nval_param,
	.send_len = sizeof(set_fast_conn_nval_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char set_bondable_on_param[] = { 0x01 };
static const char set_bondable_invalid_param[] = { 0x02 };
static const char set_bondable_garbage_param[] = { 0x01, 0x00 };
static const char set_bondable_settings_param[] = { 0x90, 0x00, 0x00, 0x00 };

static const struct generic_data set_bondable_on_success_test = {
	.send_opcode = MGMT_OP_SET_BONDABLE,
	.send_param = set_bondable_on_param,
	.send_len = sizeof(set_bondable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_bondable_settings_param,
	.expect_len = sizeof(set_bondable_settings_param),
	.expect_settings_set = MGMT_SETTING_BONDABLE,
};

static const struct generic_data set_bondable_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_BONDABLE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_bondable_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_BONDABLE,
	.send_param = set_bondable_invalid_param,
	.send_len = sizeof(set_bondable_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_bondable_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_BONDABLE,
	.send_param = set_bondable_garbage_param,
	.send_len = sizeof(set_bondable_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_bondable_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_BONDABLE,
	.send_param = set_bondable_on_param,
	.send_len = sizeof(set_bondable_on_param),
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

static const struct generic_data set_discoverable_on_not_powered_test_2 = {
	.setup_settings = settings_connectable,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_timeout_param,
	.send_len = sizeof(set_discoverable_timeout_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
};

static const struct generic_data set_discoverable_on_rejected_test_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_rejected_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_rejected_test_3 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_timeout_param,
	.send_len = sizeof(set_discoverable_timeout_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_discoverable_on_success_test_1 = {
	.setup_settings = settings_connectable,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_on_settings_param_1,
	.expect_len = sizeof(set_discoverable_on_settings_param_1),
	.expect_settings_set = MGMT_SETTING_DISCOVERABLE,
};

static const struct generic_data set_discoverable_on_success_test_2 = {
	.setup_settings = settings_powered_connectable,
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

static uint8_t set_discov_on_le_param[] = { 0x0b, 0x06, 0x00, 0x00 };
static uint8_t set_discov_adv_data[32] = { 0x06, 0x02, 0x01, 0x06,
								0x02, 0x0a, };

static const struct generic_data set_discov_on_le_success_1 = {
	.setup_settings = settings_powered_le_connectable_advertising,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_on_param,
	.send_len = sizeof(set_discoverable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discov_on_le_param,
	.expect_len = sizeof(set_discov_on_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_discov_adv_data,
	.expect_hci_len = sizeof(set_discov_adv_data),
};

static const struct generic_data set_discoverable_off_success_test_1 = {
	.setup_settings = settings_connectable,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_discoverable_off_param,
	.send_len = sizeof(set_discoverable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_off_settings_param_1,
	.expect_len = sizeof(set_discoverable_off_settings_param_1),
};

static const struct generic_data set_discoverable_off_success_test_2 = {
	.setup_settings = settings_powered_discoverable,
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

static const uint8_t set_limited_discov_on_param[] = { 0x02, 0x01, 0x00 };

static const struct generic_data set_limited_discov_on_success_1 = {
	.setup_settings = settings_powered_connectable,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_limited_discov_on_param,
	.send_len = sizeof(set_limited_discov_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_on_settings_param_2,
	.expect_len = sizeof(set_discoverable_on_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_discoverable_on_scan_enable_param,
	.expect_hci_len = sizeof(set_discoverable_on_scan_enable_param),
};

static uint8_t write_current_iac_lap_limited[] = { 0x01, 0x00, 0x8b, 0x9e };

static const struct generic_data set_limited_discov_on_success_2 = {
	.setup_settings = settings_powered_connectable,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_limited_discov_on_param,
	.send_len = sizeof(set_limited_discov_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_on_settings_param_2,
	.expect_len = sizeof(set_discoverable_on_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_WRITE_CURRENT_IAC_LAP,
	.expect_hci_param = write_current_iac_lap_limited,
	.expect_hci_len = sizeof(write_current_iac_lap_limited),
};

static uint8_t write_cod_limited[] = { 0x00, 0x20, 0x00 };

static const struct generic_data set_limited_discov_on_success_3 = {
	.setup_settings = settings_powered_connectable,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_limited_discov_on_param,
	.send_len = sizeof(set_limited_discov_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discoverable_on_settings_param_2,
	.expect_len = sizeof(set_discoverable_on_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_WRITE_CLASS_OF_DEV,
	.expect_hci_param = write_cod_limited,
	.expect_hci_len = sizeof(write_cod_limited),
};

static uint8_t set_limited_discov_adv_data[32] = { 0x06, 0x02, 0x01, 0x05,
								0x02, 0x0a, };

static const struct generic_data set_limited_discov_on_le_success_1 = {
	.setup_settings = settings_powered_le_connectable_advertising,
	.send_opcode = MGMT_OP_SET_DISCOVERABLE,
	.send_param = set_limited_discov_on_param,
	.send_len = sizeof(set_limited_discov_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_discov_on_le_param,
	.expect_len = sizeof(set_discov_on_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_limited_discov_adv_data,
	.expect_hci_len = sizeof(set_limited_discov_adv_data),
};

static uint16_t settings_link_sec[] = { MGMT_OP_SET_LINK_SECURITY, 0 };

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
	.setup_settings = settings_powered,
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

static const struct generic_data set_link_sec_on_success_test_3 = {
	.setup_settings = settings_link_sec,
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
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

static const uint16_t settings_powered_link_sec[] = {
						MGMT_OP_SET_LINK_SECURITY,
						MGMT_OP_SET_POWERED, 0 };

static const char set_link_sec_off_param[] = { 0x00 };
static const char set_link_sec_off_settings_1[] = { 0x80, 0x00, 0x00, 0x00 };
static const char set_link_sec_off_settings_2[] = { 0x81, 0x00, 0x00, 0x00 };
static const char set_link_sec_off_auth_enable_param[] = { 0x00 };

static const struct generic_data set_link_sec_off_success_test_1 = {
	.setup_settings = settings_link_sec,
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_off_param,
	.send_len = sizeof(set_link_sec_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_off_settings_1,
	.expect_len = sizeof(set_link_sec_off_settings_1),
	.expect_settings_unset = MGMT_SETTING_LINK_SECURITY,
};

static const struct generic_data set_link_sec_off_success_test_2 = {
	.setup_settings = settings_powered_link_sec,
	.send_opcode = MGMT_OP_SET_LINK_SECURITY,
	.send_param = set_link_sec_off_param,
	.send_len = sizeof(set_link_sec_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_link_sec_off_settings_2,
	.expect_len = sizeof(set_link_sec_off_settings_2),
	.expect_settings_unset = MGMT_SETTING_LINK_SECURITY,
	.expect_hci_command = BT_HCI_CMD_WRITE_AUTH_ENABLE,
	.expect_hci_param = set_link_sec_off_auth_enable_param,
	.expect_hci_len = sizeof(set_link_sec_off_auth_enable_param),
};

static uint16_t settings_ssp[] = { MGMT_OP_SET_SSP, 0 };

static const char set_ssp_on_param[] = { 0x01 };
static const char set_ssp_invalid_param[] = { 0x02 };
static const char set_ssp_garbage_param[] = { 0x01, 0x00 };
static const char set_ssp_settings_param_1[] = { 0xc0, 0x00, 0x00, 0x00 };
static const char set_ssp_settings_param_2[] = { 0xc1, 0x00, 0x00, 0x00 };
static const char set_ssp_on_write_ssp_mode_param[] = { 0x01 };

static const struct generic_data set_ssp_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_on_param,
	.send_len = sizeof(set_ssp_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_1,
	.expect_len = sizeof(set_ssp_settings_param_1),
	.expect_settings_set = MGMT_SETTING_SSP,
};

static const struct generic_data set_ssp_on_success_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_on_param,
	.send_len = sizeof(set_ssp_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_2,
	.expect_len = sizeof(set_ssp_settings_param_2),
	.expect_settings_set = MGMT_SETTING_SSP,
	.expect_hci_command = BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE,
	.expect_hci_param = set_ssp_on_write_ssp_mode_param,
	.expect_hci_len = sizeof(set_ssp_on_write_ssp_mode_param),
};

static const struct generic_data set_ssp_on_success_test_3 = {
	.setup_settings = settings_ssp,
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_2,
	.expect_len = sizeof(set_ssp_settings_param_2),
	.expect_settings_set = MGMT_SETTING_SSP,
	.expect_hci_command = BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE,
	.expect_hci_param = set_ssp_on_write_ssp_mode_param,
	.expect_hci_len = sizeof(set_ssp_on_write_ssp_mode_param),
};

static const struct generic_data set_ssp_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_ssp_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_invalid_param,
	.send_len = sizeof(set_ssp_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_ssp_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_garbage_param,
	.send_len = sizeof(set_ssp_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_ssp_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_on_param,
	.send_len = sizeof(set_ssp_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static uint16_t settings_powered_ssp[] = { MGMT_OP_SET_SSP,
						MGMT_OP_SET_POWERED, 0 };

static uint16_t settings_powered_sc[] = { MGMT_OP_SET_SSP,
						MGMT_OP_SET_SECURE_CONN,
						MGMT_OP_SET_POWERED, 0 };

static const char set_sc_on_param[] = { 0x01 };
static const char set_sc_only_on_param[] = { 0x02 };
static const char set_sc_invalid_param[] = { 0x03 };
static const char set_sc_garbage_param[] = { 0x01, 0x00 };
static const char set_sc_settings_param_1[] = { 0xc0, 0x08, 0x00, 0x00 };
static const char set_sc_settings_param_2[] = { 0xc1, 0x08, 0x00, 0x00 };
static const char set_sc_on_write_sc_support_param[] = { 0x01 };

static const struct generic_data set_sc_on_success_test_1 = {
	.setup_settings = settings_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_on_param,
	.send_len = sizeof(set_sc_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_sc_settings_param_1,
	.expect_len = sizeof(set_sc_settings_param_1),
	.expect_settings_set = MGMT_SETTING_SECURE_CONN,
};

static const struct generic_data set_sc_on_success_test_2 = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_on_param,
	.send_len = sizeof(set_sc_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_sc_settings_param_2,
	.expect_len = sizeof(set_sc_settings_param_2),
	.expect_settings_set = MGMT_SETTING_SECURE_CONN,
	.expect_hci_command = BT_HCI_CMD_WRITE_SECURE_CONN_SUPPORT,
	.expect_hci_param = set_sc_on_write_sc_support_param,
	.expect_hci_len = sizeof(set_sc_on_write_sc_support_param),
};

static const struct generic_data set_sc_on_invalid_param_test_1 = {
	.setup_settings = settings_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_sc_on_invalid_param_test_2 = {
	.setup_settings = settings_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_invalid_param,
	.send_len = sizeof(set_sc_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_sc_on_invalid_param_test_3 = {
	.setup_settings = settings_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_garbage_param,
	.send_len = sizeof(set_sc_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_sc_on_invalid_index_test = {
	.setup_settings = settings_ssp,
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_on_param,
	.send_len = sizeof(set_sc_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data set_sc_on_not_supported_test_1 = {
	.setup_settings = settings_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_on_param,
	.send_len = sizeof(set_sc_on_param),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const struct generic_data set_sc_on_not_supported_test_2 = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_on_param,
	.send_len = sizeof(set_sc_on_param),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const struct generic_data set_sc_only_on_success_test_1 = {
	.setup_settings = settings_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_only_on_param,
	.send_len = sizeof(set_sc_only_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_sc_settings_param_1,
	.expect_len = sizeof(set_sc_settings_param_1),
	.expect_settings_set = MGMT_SETTING_SECURE_CONN,
};

static const struct generic_data set_sc_only_on_success_test_2 = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_SET_SECURE_CONN,
	.send_param = set_sc_only_on_param,
	.send_len = sizeof(set_sc_only_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_sc_settings_param_2,
	.expect_len = sizeof(set_sc_settings_param_2),
	.expect_settings_set = MGMT_SETTING_SECURE_CONN,
	.expect_hci_command = BT_HCI_CMD_WRITE_SECURE_CONN_SUPPORT,
	.expect_hci_param = set_sc_on_write_sc_support_param,
	.expect_hci_len = sizeof(set_sc_on_write_sc_support_param),
};

static uint16_t settings_le[] = { MGMT_OP_SET_LE, 0 };

static const char set_le_on_param[] = { 0x01 };
static const char set_le_off_param[] = { 0x00 };
static const char set_le_invalid_param[] = { 0x02 };
static const char set_le_garbage_param[] = { 0x01, 0x00 };
static const char set_le_settings_param_1[] = { 0x80, 0x02, 0x00, 0x00 };
static const char set_le_settings_param_2[] = { 0x81, 0x02, 0x00, 0x00 };
static const char set_le_on_write_le_host_param[] = { 0x01, 0x00 };

static const struct generic_data set_le_on_success_test_1 = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_on_param,
	.send_len = sizeof(set_le_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_1,
	.expect_len = sizeof(set_le_settings_param_1),
	.expect_settings_set = MGMT_SETTING_LE,
};

static const struct generic_data set_le_on_success_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_on_param,
	.send_len = sizeof(set_le_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_2,
	.expect_len = sizeof(set_le_settings_param_2),
	.expect_settings_set = MGMT_SETTING_LE,
	.expect_hci_command = BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED,
	.expect_hci_param = set_le_on_write_le_host_param,
	.expect_hci_len = sizeof(set_le_on_write_le_host_param),
};

static const struct generic_data set_le_on_success_test_3 = {
	.setup_settings = settings_le,
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_2,
	.expect_len = sizeof(set_le_settings_param_2),
	.expect_settings_set = MGMT_SETTING_LE,
	.expect_hci_command = BT_HCI_CMD_WRITE_LE_HOST_SUPPORTED,
	.expect_hci_param = set_le_on_write_le_host_param,
	.expect_hci_len = sizeof(set_le_on_write_le_host_param),
};

static const struct generic_data set_le_on_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_LE,
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_le_on_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_invalid_param,
	.send_len = sizeof(set_le_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_le_on_invalid_param_test_3 = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_garbage_param,
	.send_len = sizeof(set_le_garbage_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data set_le_on_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_on_param,
	.send_len = sizeof(set_le_on_param),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static uint16_t settings_powered_le[] = { MGMT_OP_SET_LE,
					MGMT_OP_SET_POWERED, 0 };

static const char set_adv_on_param[] = { 0x01 };
static const char set_adv_on_param2[] = { 0x02 };
static const char set_adv_settings_param_1[] = { 0x80, 0x06, 0x00, 0x00 };
static const char set_adv_settings_param_2[] = { 0x81, 0x06, 0x00, 0x00 };
static const char set_adv_on_set_adv_enable_param[] = { 0x01 };
static const char set_adv_on_set_adv_disable_param[] = { 0x00 };

static const struct generic_data set_adv_on_success_test_1 = {
	.setup_settings = settings_le,
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param,
	.send_len = sizeof(set_adv_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_adv_settings_param_1,
	.expect_len = sizeof(set_adv_settings_param_1),
	.expect_settings_set = MGMT_SETTING_ADVERTISING,
};

static const struct generic_data set_adv_on_success_test_2 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param,
	.send_len = sizeof(set_adv_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_adv_settings_param_2,
	.expect_len = sizeof(set_adv_settings_param_2),
	.expect_settings_set = MGMT_SETTING_ADVERTISING,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_ENABLE,
	.expect_hci_param = set_adv_on_set_adv_enable_param,
	.expect_hci_len = sizeof(set_adv_on_set_adv_enable_param),
};

static const struct generic_data set_adv_on_rejected_test_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param,
	.send_len = sizeof(set_adv_on_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const uint8_t set_adv_set_appearance_param[2] = { 0x54, 0x65 };

static const uint8_t set_adv_scan_rsp_data_appear_1[] = {
	0x04, /* Scan rsp data len */
	0x03, /* Local name data len */
	0x19, /* Complete name */
	0x54, 0x65,
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct generic_data set_adv_on_appearance_test_1 = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_APPEARANCE,
	.setup_send_param = set_adv_set_appearance_param,
	.setup_send_len = sizeof(set_adv_set_appearance_param),
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param,
	.expect_param = set_adv_settings_param_2,
	.expect_len = sizeof(set_adv_settings_param_2),
	.send_len = sizeof(set_adv_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_adv_scan_rsp_data_appear_1,
	.expect_hci_len = sizeof(set_adv_scan_rsp_data_appear_1),
};

static const char set_adv_set_local_name_param[260] = { 'T', 'e', 's', 't', ' ',
							'n', 'a', 'm', 'e' };

static const uint8_t set_adv_scan_rsp_data_name_1[] = {
	0x0b, /* Scan rsp data len */
	0x0a, /* Local name data len */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, /* "Test name" */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct generic_data set_adv_on_local_name_test_1 = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = set_adv_set_local_name_param,
	.setup_send_len = sizeof(set_adv_set_local_name_param),
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param,
	.expect_param = set_adv_settings_param_2,
	.expect_len = sizeof(set_adv_settings_param_2),
	.send_len = sizeof(set_adv_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_adv_scan_rsp_data_name_1,
	.expect_hci_len = sizeof(set_adv_scan_rsp_data_name_1),
};

static const struct setup_mgmt_cmd set_advertising_mgmt_cmd_arr[] = {
	{
		.send_opcode = MGMT_OP_SET_APPEARANCE,
		.send_param = set_adv_set_appearance_param,
		.send_len = sizeof(set_adv_set_appearance_param),
	},
	{
		.send_opcode = MGMT_OP_SET_LOCAL_NAME,
		.send_param = set_adv_set_local_name_param,
		.send_len = sizeof(set_adv_set_local_name_param),
	}
};

static const uint8_t set_adv_scan_rsp_data_name_and_appearance[] = {
	0x0f, /* scan rsp data len */
	0x03, /* appearance data len */
	0x19, /* eir_appearance */
	0x54, 0x65, /* appearance value */
	0x0a, /* local name data len */
	0x09, /* complete name */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, /* "test name" */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


static const struct generic_data set_adv_on_local_name_appear_test_1 = {
	.setup_settings = settings_powered_le,
	.setup_mgmt_cmd_arr = set_advertising_mgmt_cmd_arr,
	.setup_mgmt_cmd_arr_size = ARRAY_SIZE(set_advertising_mgmt_cmd_arr),
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param,
	.expect_param = set_adv_settings_param_2,
	.expect_len = sizeof(set_adv_settings_param_2),
	.send_len = sizeof(set_adv_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_adv_scan_rsp_data_name_and_appearance,
	.expect_hci_len = sizeof(set_adv_scan_rsp_data_name_and_appearance),
};

static const char set_bredr_off_param[] = { 0x00 };
static const char set_bredr_on_param[] = { 0x01 };
static const char set_bredr_invalid_param[] = { 0x02 };
static const char set_bredr_settings_param_1[] = { 0x00, 0x02, 0x00, 0x00 };
static const char set_bredr_settings_param_2[] = { 0x80, 0x02, 0x00, 0x00 };
static const char set_bredr_settings_param_3[] = { 0x81, 0x02, 0x00, 0x00 };

static const struct generic_data set_bredr_off_success_test_1 = {
	.setup_settings = settings_le,
	.send_opcode = MGMT_OP_SET_BREDR,
	.send_param = set_bredr_off_param,
	.send_len = sizeof(set_bredr_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_bredr_settings_param_1,
	.expect_len = sizeof(set_bredr_settings_param_1),
	.expect_settings_unset = MGMT_SETTING_BREDR,
};

static const struct generic_data set_bredr_on_success_test_1 = {
	.setup_settings = settings_le,
	.setup_nobredr = true,
	.send_opcode = MGMT_OP_SET_BREDR,
	.send_param = set_bredr_on_param,
	.send_len = sizeof(set_bredr_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_bredr_settings_param_2,
	.expect_len = sizeof(set_bredr_settings_param_2),
	.expect_settings_set = MGMT_SETTING_BREDR,
};

static const struct generic_data set_bredr_on_success_test_2 = {
	.setup_settings = settings_powered_le,
	.setup_nobredr = true,
	.send_opcode = MGMT_OP_SET_BREDR,
	.send_param = set_bredr_on_param,
	.send_len = sizeof(set_bredr_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_bredr_settings_param_3,
	.expect_len = sizeof(set_bredr_settings_param_3),
	.expect_settings_set = MGMT_SETTING_BREDR,
};

static const struct generic_data set_bredr_off_notsupp_test = {
	.send_opcode = MGMT_OP_SET_BREDR,
	.send_param = set_bredr_off_param,
	.send_len = sizeof(set_bredr_off_param),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const struct generic_data set_bredr_off_failure_test_1 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_SET_BREDR,
	.send_param = set_bredr_off_param,
	.send_len = sizeof(set_bredr_off_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_bredr_off_failure_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_BREDR,
	.send_param = set_bredr_off_param,
	.send_len = sizeof(set_bredr_off_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_bredr_off_failure_test_3 = {
	.setup_settings = settings_le,
	.send_opcode = MGMT_OP_SET_BREDR,
	.send_param = set_bredr_invalid_param,
	.send_len = sizeof(set_bredr_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char set_local_name_param[260] = { 'T', 'e', 's', 't', ' ',
						'n', 'a', 'm', 'e' };
static const char write_local_name_hci[248] = { 'T', 'e', 's', 't', ' ',
						'n', 'a', 'm', 'e' };
static const char write_eir_local_name_hci_1[241] = { 0x00,
		0x0a, 0x09, 'T', 'e', 's', 't', ' ', 'n', 'a', 'm', 'e',
		0x02, 0x0a, 0x00, };

static const struct mgmt_cp_set_local_name set_local_name_cp = {
	.name = {'T', 'e', 's', 't', ' ', 'n', 'a', 'm', 'e'},
	.short_name = {'T', 'e', 's', 't'},
};

static const struct mgmt_cp_set_local_name set_local_name_longer_cp = {
	.name = {'T', 'e', 's', 't', ' ', 'n', 'a', 'm', 'e', '1', '2', '3'},
};

static const struct mgmt_cp_set_local_name set_local_name_long_short_cp = {
	.name = {'T', 'e', 's', 't', ' ', 'n', 'a', 'm', 'e', '1', '2', '3'},
	.short_name = {'T', 'e', 's', 't'},
};

static const struct generic_data set_local_name_test_1 = {
	.send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.send_param = set_local_name_param,
	.send_len = sizeof(set_local_name_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_local_name_param,
	.expect_len = sizeof(set_local_name_param),
	.expect_alt_ev = MGMT_EV_LOCAL_NAME_CHANGED,
	.expect_alt_ev_param = set_local_name_param,
	.expect_alt_ev_len = sizeof(set_local_name_param),
};

static const struct generic_data set_local_name_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.send_param = set_local_name_param,
	.send_len = sizeof(set_local_name_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_local_name_param,
	.expect_len = sizeof(set_local_name_param),
	.expect_hci_command = BT_HCI_CMD_WRITE_LOCAL_NAME,
	.expect_hci_param = write_local_name_hci,
	.expect_hci_len = sizeof(write_local_name_hci),
	.expect_alt_ev = MGMT_EV_LOCAL_NAME_CHANGED,
	.expect_alt_ev_param = set_local_name_param,
	.expect_alt_ev_len = sizeof(set_local_name_param),
};

static const struct generic_data set_local_name_test_3 = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.send_param = set_local_name_param,
	.send_len = sizeof(set_local_name_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_local_name_param,
	.expect_len = sizeof(set_local_name_param),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_local_name_hci_1,
	.expect_hci_len = sizeof(write_eir_local_name_hci_1),
	.expect_alt_ev = MGMT_EV_LOCAL_NAME_CHANGED,
	.expect_alt_ev_param = set_local_name_param,
	.expect_alt_ev_len = sizeof(set_local_name_param),
};

static const char start_discovery_invalid_param[] = { 0x00 };
static const char start_discovery_bredr_param[] = { 0x01 };
static const char start_discovery_le_param[] = { 0x06 };
static const char start_discovery_bredrle_param[] = { 0x07 };
static const char start_discovery_valid_hci[] = { 0x01, 0x01 };
static const char start_discovery_evt[] = { 0x07, 0x01 };
static const char start_discovery_le_evt[] = { 0x06, 0x01 };

static const struct generic_data start_discovery_not_powered_test_1 = {
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredr_param,
	.send_len = sizeof(start_discovery_bredr_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.expect_param = start_discovery_bredr_param,
	.expect_len = sizeof(start_discovery_bredr_param),
};

static const struct generic_data start_discovery_invalid_param_test_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_invalid_param,
	.send_len = sizeof(start_discovery_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = start_discovery_invalid_param,
	.expect_len = sizeof(start_discovery_invalid_param),
};

static const struct generic_data start_discovery_not_supported_test_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_REJECTED,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
};

static const struct generic_data start_discovery_valid_param_test_1 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredrle_param,
	.send_len = sizeof(start_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_bredrle_param,
	.expect_len = sizeof(start_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_hci,
	.expect_hci_len = sizeof(start_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_evt,
	.expect_alt_ev_len = sizeof(start_discovery_evt),
};

static const struct generic_data start_discovery_valid_param_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_hci,
	.expect_hci_len = sizeof(start_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_le_evt,
	.expect_alt_ev_len = sizeof(start_discovery_le_evt),
};

static const struct generic_data start_discovery_valid_param_power_off_1 = {
	.setup_settings = settings_le,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredrle_param,
	.send_len = sizeof(start_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.force_power_off = true,
	.expect_param = start_discovery_bredrle_param,
	.expect_len = sizeof(start_discovery_bredrle_param),
};

static const char stop_discovery_bredrle_param[] = { 0x07 };
static const char stop_discovery_bredrle_invalid_param[] = { 0x06 };
static const char stop_discovery_valid_hci[] = { 0x00, 0x00 };
static const char stop_discovery_evt[] = { 0x07, 0x00 };
static const char stop_discovery_bredr_param[] = { 0x01 };
static const char stop_discovery_bredr_discovering[] = { 0x01, 0x00 };

static const struct generic_data stop_discovery_success_test_1 = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_START_DISCOVERY,
	.setup_send_param = start_discovery_bredrle_param,
	.setup_send_len = sizeof(start_discovery_bredrle_param),
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredrle_param,
	.send_len = sizeof(stop_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = stop_discovery_bredrle_param,
	.expect_len = sizeof(stop_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = stop_discovery_valid_hci,
	.expect_hci_len = sizeof(stop_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = stop_discovery_evt,
	.expect_alt_ev_len = sizeof(stop_discovery_evt),
};

static const struct generic_data stop_discovery_bredr_success_test_1 = {
	.setup_settings = settings_powered,
	.setup_send_opcode = MGMT_OP_START_DISCOVERY,
	.setup_send_param = start_discovery_bredr_param,
	.setup_send_len = sizeof(start_discovery_bredr_param),
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredr_param,
	.send_len = sizeof(stop_discovery_bredr_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = stop_discovery_bredr_param,
	.expect_len = sizeof(stop_discovery_bredr_param),
	.expect_hci_command = BT_HCI_CMD_INQUIRY_CANCEL,
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = stop_discovery_bredr_discovering,
	.expect_alt_ev_len = sizeof(stop_discovery_bredr_discovering),
};

static const struct generic_data stop_discovery_rejected_test_1 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredrle_param,
	.send_len = sizeof(stop_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_REJECTED,
	.expect_param = stop_discovery_bredrle_param,
	.expect_len = sizeof(stop_discovery_bredrle_param),
};

static const struct generic_data stop_discovery_invalid_param_test_1 = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_START_DISCOVERY,
	.setup_send_param = start_discovery_bredrle_param,
	.setup_send_len = sizeof(start_discovery_bredrle_param),
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredrle_invalid_param,
	.send_len = sizeof(stop_discovery_bredrle_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = stop_discovery_bredrle_invalid_param,
	.expect_len = sizeof(stop_discovery_bredrle_invalid_param),
};

static const char start_service_discovery_invalid_param[] = { 0x00, 0x00, 0x00, 0x00 };
static const char start_service_discovery_invalid_resp[] = { 0x00 };
static const char start_service_discovery_bredr_param[] = { 0x01, 0x00, 0x00, 0x00};
static const char start_service_discovery_bredr_resp[] = { 0x01 };
static const char start_service_discovery_le_param[] = { 0x06, 0x00, 0x01, 0x00,
			0xfa, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00,
			0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const char start_service_discovery_le_resp[] = { 0x06 };
static const char start_service_discovery_bredrle_param[] = { 0x07, 0x00, 0x01, 0x00,
			0xfa, 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00,
			0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const char start_service_discovery_bredrle_resp[] = { 0x07 };
static const char start_service_discovery_valid_hci[] = { 0x01, 0x01 };
static const char start_service_discovery_evt[] = { 0x07, 0x01 };
static const char start_service_discovery_le_evt[] = { 0x06, 0x01 };

static const struct generic_data start_service_discovery_not_powered_test_1 = {
	.send_opcode = MGMT_OP_START_SERVICE_DISCOVERY,
	.send_param = start_service_discovery_bredr_param,
	.send_len = sizeof(start_service_discovery_bredr_param),
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.expect_param = start_service_discovery_bredr_resp,
	.expect_len = sizeof(start_service_discovery_bredr_resp),
};

static const struct generic_data start_service_discovery_invalid_param_test_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_START_SERVICE_DISCOVERY,
	.send_param = start_service_discovery_invalid_param,
	.send_len = sizeof(start_service_discovery_invalid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = start_service_discovery_invalid_resp,
	.expect_len = sizeof(start_service_discovery_invalid_resp),
};

static const struct generic_data start_service_discovery_not_supported_test_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_START_SERVICE_DISCOVERY,
	.send_param = start_service_discovery_le_param,
	.send_len = sizeof(start_service_discovery_le_param),
	.expect_status = MGMT_STATUS_REJECTED,
	.expect_param = start_service_discovery_le_resp,
	.expect_len = sizeof(start_service_discovery_le_resp),
};

static const struct generic_data start_service_discovery_valid_param_test_1 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_START_SERVICE_DISCOVERY,
	.send_param = start_service_discovery_bredrle_param,
	.send_len = sizeof(start_service_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_service_discovery_bredrle_resp,
	.expect_len = sizeof(start_service_discovery_bredrle_resp),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = start_service_discovery_valid_hci,
	.expect_hci_len = sizeof(start_service_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_service_discovery_evt,
	.expect_alt_ev_len = sizeof(start_service_discovery_evt),
};

static const struct generic_data start_service_discovery_valid_param_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_START_SERVICE_DISCOVERY,
	.send_param = start_service_discovery_le_param,
	.send_len = sizeof(start_service_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_service_discovery_le_resp,
	.expect_len = sizeof(start_service_discovery_le_resp),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = start_service_discovery_valid_hci,
	.expect_hci_len = sizeof(start_service_discovery_valid_hci),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_service_discovery_le_evt,
	.expect_alt_ev_len = sizeof(start_service_discovery_le_evt),
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
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_DEV_CLASS,
	.send_param = set_dev_class_valid_param,
	.send_len = sizeof(set_dev_class_valid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_valid_rsp,
	.expect_len = sizeof(set_dev_class_valid_rsp),
	.expect_alt_ev = MGMT_EV_CLASS_OF_DEV_CHANGED,
	.expect_alt_ev_param = set_dev_class_valid_rsp,
	.expect_alt_ev_len = sizeof(set_dev_class_valid_rsp),
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
static const char add_sync_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x04, 0x11, 0x00, 0x00,
			0x00 };
static const char add_opp_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x05, 0x11, 0x00, 0x00,
			0x00 };
static const char write_eir_uuid16_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x03, 0x03, 0x01, 0x11 };
static const char write_eir_multi_uuid16_hci_1[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x09, 0x03, 0x01, 0x11, 0x03,
			0x11, 0x04, 0x11, 0x05, 0x11 };
static const char write_eir_multi_uuid16_hci_2[241] = { 0x00,
			0x02, 0x0a, 0x00, 0xeb, 0x02, 0x00, 0x20, 0x01,
			0x20, 0x02, 0x20, 0x03, 0x20, 0x04, 0x20, 0x05,
			0x20, 0x06, 0x20, 0x07, 0x20, 0x08, 0x20, 0x09,
			0x20, 0x0a, 0x20, 0x0b, 0x20, 0x0c, 0x20, 0x0d,
			0x20, 0x0e, 0x20, 0x0f, 0x20, 0x10, 0x20, 0x11,
			0x20, 0x12, 0x20, 0x13, 0x20, 0x14, 0x20, 0x15,
			0x20, 0x16, 0x20, 0x17, 0x20, 0x18, 0x20, 0x19,
			0x20, 0x1a, 0x20, 0x1b, 0x20, 0x1c, 0x20, 0x1d,
			0x20, 0x1e, 0x20, 0x1f, 0x20, 0x20, 0x20, 0x21,
			0x20, 0x22, 0x20, 0x23, 0x20, 0x24, 0x20, 0x25,
			0x20, 0x26, 0x20, 0x27, 0x20, 0x28, 0x20, 0x29,
			0x20, 0x2a, 0x20, 0x2b, 0x20, 0x2c, 0x20, 0x2d,
			0x20, 0x2e, 0x20, 0x2f, 0x20, 0x30, 0x20, 0x31,
			0x20, 0x32, 0x20, 0x33, 0x20, 0x34, 0x20, 0x35,
			0x20, 0x36, 0x20, 0x37, 0x20, 0x38, 0x20, 0x39,
			0x20, 0x3a, 0x20, 0x3b, 0x20, 0x3c, 0x20, 0x3d,
			0x20, 0x3e, 0x20, 0x3f, 0x20, 0x40, 0x20, 0x41,
			0x20, 0x42, 0x20, 0x43, 0x20, 0x44, 0x20, 0x45,
			0x20, 0x46, 0x20, 0x47, 0x20, 0x48, 0x20, 0x49,
			0x20, 0x4a, 0x20, 0x4b, 0x20, 0x4c, 0x20, 0x4d,
			0x20, 0x4e, 0x20, 0x4f, 0x20, 0x50, 0x20, 0x51,
			0x20, 0x52, 0x20, 0x53, 0x20, 0x54, 0x20, 0x55,
			0x20, 0x56, 0x20, 0x57, 0x20, 0x58, 0x20, 0x59,
			0x20, 0x5a, 0x20, 0x5b, 0x20, 0x5c, 0x20, 0x5d,
			0x20, 0x5e, 0x20, 0x5f, 0x20, 0x60, 0x20, 0x61,
			0x20, 0x62, 0x20, 0x63, 0x20, 0x64, 0x20, 0x65,
			0x20, 0x66, 0x20, 0x67, 0x20, 0x68, 0x20, 0x69,
			0x20, 0x6a, 0x20, 0x6b, 0x20, 0x6c, 0x20, 0x6d,
			0x20, 0x6e, 0x20, 0x6f, 0x20, 0x70, 0x20, 0x71,
			0x20, 0x72, 0x20, 0x73, 0x20, 0x74, 0x20, 0x00 };
static const char add_uuid32_param_1[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
			0x00 };
static const char add_uuid32_param_2[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0xef, 0xcd, 0xbc, 0x9a,
			0x00 };
static const char add_uuid32_param_3[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0xff, 0xee, 0xdd, 0xcc,
			0x00 };
static const char add_uuid32_param_4[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44,
			0x00 };
static const char write_eir_uuid32_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x05, 0x05, 0x78, 0x56, 0x34,
			0x12 };
static const char write_eir_uuid32_multi_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x11, 0x05, 0x78, 0x56, 0x34,
			0x12, 0xef, 0xcd, 0xbc, 0x9a, 0xff, 0xee, 0xdd,
			0xcc, 0x11, 0x22, 0x33, 0x44 };
static const char write_eir_uuid32_multi_hci_2[] = { 0x00,
			0x02, 0x0a, 0x00, 0xe9, 0x04, 0xff, 0xff, 0xff,
			0xff, 0xfe, 0xff, 0xff, 0xff, 0xfd, 0xff, 0xff,
			0xff, 0xfc, 0xff, 0xff, 0xff, 0xfb, 0xff, 0xff,
			0xff, 0xfa, 0xff, 0xff, 0xff, 0xf9, 0xff, 0xff,
			0xff, 0xf8, 0xff, 0xff, 0xff, 0xf7, 0xff, 0xff,
			0xff, 0xf6, 0xff, 0xff, 0xff, 0xf5, 0xff, 0xff,
			0xff, 0xf4, 0xff, 0xff, 0xff, 0xf3, 0xff, 0xff,
			0xff, 0xf2, 0xff, 0xff, 0xff, 0xf1, 0xff, 0xff,
			0xff, 0xf0, 0xff, 0xff, 0xff, 0xef, 0xff, 0xff,
			0xff, 0xee, 0xff, 0xff, 0xff, 0xed, 0xff, 0xff,
			0xff, 0xec, 0xff, 0xff, 0xff, 0xeb, 0xff, 0xff,
			0xff, 0xea, 0xff, 0xff, 0xff, 0xe9, 0xff, 0xff,
			0xff, 0xe8, 0xff, 0xff, 0xff, 0xe7, 0xff, 0xff,
			0xff, 0xe6, 0xff, 0xff, 0xff, 0xe5, 0xff, 0xff,
			0xff, 0xe4, 0xff, 0xff, 0xff, 0xe3, 0xff, 0xff,
			0xff, 0xe2, 0xff, 0xff, 0xff, 0xe1, 0xff, 0xff,
			0xff, 0xe0, 0xff, 0xff, 0xff, 0xdf, 0xff, 0xff,
			0xff, 0xde, 0xff, 0xff, 0xff, 0xdd, 0xff, 0xff,
			0xff, 0xdc, 0xff, 0xff, 0xff, 0xdb, 0xff, 0xff,
			0xff, 0xda, 0xff, 0xff, 0xff, 0xd9, 0xff, 0xff,
			0xff, 0xd8, 0xff, 0xff, 0xff, 0xd7, 0xff, 0xff,
			0xff, 0xd6, 0xff, 0xff, 0xff, 0xd5, 0xff, 0xff,
			0xff, 0xd4, 0xff, 0xff, 0xff, 0xd3, 0xff, 0xff,
			0xff, 0xd2, 0xff, 0xff, 0xff, 0xd1, 0xff, 0xff,
			0xff, 0xd0, 0xff, 0xff, 0xff, 0xcf, 0xff, 0xff,
			0xff, 0xce, 0xff, 0xff, 0xff, 0xcd, 0xff, 0xff,
			0xff, 0xcc, 0xff, 0xff, 0xff, 0xcb, 0xff, 0xff,
			0xff, 0xca, 0xff, 0xff, 0xff, 0xc9, 0xff, 0xff,
			0xff, 0xc8, 0xff, 0xff, 0xff, 0xc7, 0xff, 0xff,
			0xff, 0xc6, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 };
static const char add_uuid128_param_1[] = {
			0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
			0x00 };
static const char add_uuid128_param_2[] = {
			0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
			0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
			0x00 };
static const char write_eir_uuid128_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x11, 0x07, 0x00, 0x11, 0x22,
			0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
			0xbb, 0xcc, 0xdd, 0xee, 0xff };
static const char write_eir_uuid128_multi_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x21, 0x07, 0x00, 0x11, 0x22,
			0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
			0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xee, 0xdd,
			0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
			0x44, 0x33, 0x22, 0x11 };
static const char write_eir_uuid128_multi_hci_2[] = { 0x00,
			0x02, 0x0a, 0x00, 0xe1, 0x07, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x01, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x02, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x03, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x04, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x05, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x06, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x07, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x08, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x09, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x0a, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x0b, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff, 0x0c, 0xff, 0xee, 0xdd,
			0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
			0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const char write_eir_uuid_mix_hci[241] = { 0x00,
			0x02, 0x0a, 0x00, 0x05, 0x03, 0x01, 0x11, 0x03,
			0x11, 0x09, 0x05, 0x78, 0x56, 0x34, 0x12, 0xef,
			0xcd, 0xbc, 0x9a, 0x21, 0x07, 0x00, 0x11, 0x22,
			0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
			0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xff, 0xee, 0xdd,
			0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55,
			0x44, 0x33, 0x22, 0x11 };

static const struct generic_data add_uuid16_test_1 = {
	.setup_settings = settings_powered_ssp,
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
	.send_param = add_opp_uuid_param,
	.send_len = sizeof(add_opp_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_multi_uuid16_hci_1,
	.expect_hci_len = sizeof(write_eir_multi_uuid16_hci_1),
};

static const struct generic_data add_multi_uuid16_test_2 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_opp_uuid_param,
	.send_len = sizeof(add_opp_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_multi_uuid16_hci_2,
	.expect_hci_len = sizeof(write_eir_multi_uuid16_hci_2),
};

static const struct generic_data add_uuid32_test_1 = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid32_param_1,
	.send_len = sizeof(add_uuid32_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid32_hci,
	.expect_hci_len = sizeof(write_eir_uuid32_hci),
};

static const struct generic_data add_uuid32_multi_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid32_param_4,
	.send_len = sizeof(add_uuid32_param_4),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid32_multi_hci,
	.expect_hci_len = sizeof(write_eir_uuid32_multi_hci),
};

static const struct generic_data add_uuid32_multi_test_2 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid32_param_4,
	.send_len = sizeof(add_uuid32_param_4),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid32_multi_hci_2,
	.expect_hci_len = sizeof(write_eir_uuid32_multi_hci_2),
};

static const struct generic_data add_uuid128_test_1 = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid128_param_1,
	.send_len = sizeof(add_uuid128_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid128_hci,
	.expect_hci_len = sizeof(write_eir_uuid128_hci),
};

static const struct generic_data add_uuid128_multi_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid128_param_2,
	.send_len = sizeof(add_uuid32_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid128_multi_hci,
	.expect_hci_len = sizeof(write_eir_uuid128_multi_hci),
};

static const struct generic_data add_uuid128_multi_test_2 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid128_param_2,
	.send_len = sizeof(add_uuid128_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid128_multi_hci_2,
	.expect_hci_len = sizeof(write_eir_uuid128_multi_hci_2),
};

static const struct generic_data add_uuid_mix_test_1 = {
	.send_opcode = MGMT_OP_ADD_UUID,
	.send_param = add_uuid128_param_2,
	.send_len = sizeof(add_uuid128_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_uuid_mix_hci,
	.expect_hci_len = sizeof(write_eir_uuid_mix_hci),
};

static const char remove_dun_uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x03, 0x11, 0x00, 0x00 };

static const char write_eir_remove_dun_hci[241] = {
			0x00, 0x02, 0x0a, 0x00, 0x05, 0x03, 0x01, 0x11, 0x04,
			0x11 };

static const struct generic_data remove_uuid_success_1 = {
	.send_opcode = MGMT_OP_REMOVE_UUID,
	.send_param = remove_dun_uuid_param,
	.send_len = sizeof(remove_dun_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_remove_dun_hci,
	.expect_hci_len = sizeof(write_eir_remove_dun_hci),
};

static const char remove_all_uuid_param[16] = { 0x00 };

static const struct generic_data remove_uuid_all_success_2 = {
	.send_opcode = MGMT_OP_REMOVE_UUID,
	.send_param = remove_all_uuid_param,
	.send_len = sizeof(remove_all_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
};

static const struct generic_data remove_uuid_power_off_success_3 = {
	.send_opcode = MGMT_OP_REMOVE_UUID,
	.send_param = remove_dun_uuid_param,
	.send_len = sizeof(remove_dun_uuid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_class_zero_rsp,
	.expect_len = sizeof(set_dev_class_zero_rsp),
};

static const struct generic_data remove_uuid_power_off_on_success_4 = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_2,
	.expect_len = sizeof(set_ssp_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_remove_dun_hci,
	.expect_hci_len = sizeof(write_eir_remove_dun_hci),
};

static const struct generic_data remove_uuid_invalid_params_1 = {
	.send_opcode = MGMT_OP_REMOVE_UUID,
	.send_param = add_opp_uuid_param,
	.send_len = sizeof(add_opp_uuid_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
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

static const char load_ltks_valid_param_2[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */
};

/* 20 keys at once */
static const char load_ltks_valid_param_20[] = {
	0x14, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x01, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x02, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x03, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x04, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x05, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x06, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x07, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x08, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x09, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x0a, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x0b, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x0c, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x0d, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x0e, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x0f, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x10, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x11, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x12, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */

	0x13, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* master */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */
};

/* Invalid key count */
static const char load_ltks_invalid_param_1[] = { 0x01, 0x00 };
/* Invalid addr type */
static const char load_ltks_invalid_param_2[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x00,						/* addr type */
	0x00,						/* authenticated */
	0x00,						/* central */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */
};
/* Invalid central value */
static const char load_ltks_invalid_param_3[] = {
	0x01, 0x00,					/* count */
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,		/* bdaddr */
	0x01,						/* addr type */
	0x00,						/* authenticated */
	0x02,						/* central */
	0x00,						/* encryption size */
	0x00, 0x00,					/* diversifier */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* rand */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (1/2) */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* value (2/2) */
};

static const struct generic_data load_ltks_success_test_1 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_valid_param_1,
	.send_len = sizeof(load_ltks_valid_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_ltks_success_test_2 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_valid_param_2,
	.send_len = sizeof(load_ltks_valid_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_ltks_success_test_3 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_valid_param_2,
	.send_len = sizeof(load_ltks_valid_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_ltks_success_test_4 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_valid_param_20,
	.send_len = sizeof(load_ltks_valid_param_20),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data load_ltks_success_test_5 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_valid_param_20,
	.send_len = sizeof(load_ltks_valid_param_20),
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

static const char load_ltks_invalid_param_4[22] = { 0x1d, 0x07 };
static const struct generic_data load_ltks_invalid_params_test_4 = {
	.send_opcode = MGMT_OP_LOAD_LONG_TERM_KEYS,
	.send_param = load_ltks_invalid_param_4,
	.send_len = sizeof(load_ltks_invalid_param_4),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char set_io_cap_invalid_param_1[] = { 0xff };

static const struct generic_data set_io_cap_invalid_param_test_1 = {
	.send_opcode = MGMT_OP_SET_IO_CAPABILITY,
	.send_param = set_io_cap_invalid_param_1,
	.send_len = sizeof(set_io_cap_invalid_param_1),
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
static const char pair_device_invalid_param_2[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x05 };
static const char pair_device_invalid_param_rsp_2[] = {
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00 };

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

static const struct generic_data pair_device_invalid_param_test_2 = {
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_param = pair_device_invalid_param_2,
	.send_len = sizeof(pair_device_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = pair_device_invalid_param_rsp_2,
	.expect_len = sizeof(pair_device_invalid_param_rsp_2),
};

static const void *pair_device_send_param_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	static uint8_t param[8];

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);

	if (test->addr_type_avail)
		param[6] = test->addr_type;
	else if (data->hciemu_type == HCIEMU_TYPE_LE)
		param[6] = 0x01; /* Address type */
	else
		param[6] = 0x00; /* Address type */
	param[7] = test->io_cap;

	*len = sizeof(param);

	return param;
}

static const void *pair_device_expect_param_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	static uint8_t param[7];

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);

	if (test->addr_type_avail)
		param[6] = test->addr_type;
	else if (data->hciemu_type == HCIEMU_TYPE_LE)
		param[6] = 0x01; /* Address type */
	else
		param[6] = 0x00; /* Address type */

	*len = sizeof(param);

	return param;
}

static uint16_t settings_powered_bondable[] = { MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_POWERED, 0 };
static uint8_t auth_req_param[] = { 0x2a, 0x00 };
static uint8_t pair_device_pin[] = { 0x30, 0x30, 0x30, 0x30 }; /* "0000" */

static const struct generic_data pair_device_success_test_1 = {
	.setup_settings = settings_powered_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_AUTH_REQUESTED,
	.expect_hci_param = auth_req_param,
	.expect_hci_len = sizeof(auth_req_param),
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
};

static uint16_t settings_powered_bondable_linksec[] = { MGMT_OP_SET_BONDABLE,
							MGMT_OP_SET_POWERED,
							MGMT_OP_SET_LINK_SECURITY,
							0 };

static const struct generic_data pair_device_success_test_2 = {
	.setup_settings = settings_powered_bondable_linksec,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_AUTH_REQUESTED,
	.expect_hci_param = auth_req_param,
	.expect_hci_len = sizeof(auth_req_param),
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
};

static const struct generic_data pair_device_legacy_nonbondable_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
};

static const struct generic_data pair_device_power_off_test_1 = {
	.setup_settings = settings_powered_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.force_power_off = true,
	.expect_status = MGMT_STATUS_DISCONNECTED,
	.expect_func = pair_device_expect_param_func,
};

static const void *client_bdaddr_param_func(uint8_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t bdaddr[6];

	memcpy(bdaddr, hciemu_get_client_bdaddr(data->hciemu), 6);

	*len = sizeof(bdaddr);

	return bdaddr;
}

static const struct generic_data pair_device_not_supported_test_1 = {
	.setup_settings = settings_powered_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
	.expect_func = pair_device_expect_param_func,
	.addr_type_avail = true,
	.addr_type = BDADDR_BREDR,
};

static const struct generic_data pair_device_not_supported_test_2 = {
	.setup_settings = settings_powered_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
	.expect_func = pair_device_expect_param_func,
	.addr_type_avail = true,
	.addr_type = BDADDR_LE_PUBLIC,
};

static uint16_t settings_powered_bondable_le[] = { MGMT_OP_SET_LE,
							MGMT_OP_SET_BONDABLE,
							MGMT_OP_SET_POWERED,
							0 };

static const struct generic_data pair_device_reject_transport_not_enabled_1 = {
	.setup_settings = settings_powered_bondable_le,
	.setup_nobredr = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_REJECTED,
	.expect_func = pair_device_expect_param_func,
	.addr_type_avail = true,
	.addr_type = BDADDR_BREDR,
};

static const struct generic_data pair_device_reject_transport_not_enabled_2 = {
	.setup_settings = settings_powered_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_REJECTED,
	.expect_func = pair_device_expect_param_func,
	.addr_type_avail = true,
	.addr_type = BDADDR_LE_PUBLIC,
};

static const struct generic_data pair_device_reject_test_1 = {
	.setup_settings = settings_powered_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_AUTH_FAILED,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = 8,
	.expect_hci_command = BT_HCI_CMD_PIN_CODE_REQUEST_NEG_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.expect_pin = true,
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
};

static const struct generic_data pair_device_reject_test_2 = {
	.setup_settings = settings_powered_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_AUTH_FAILED,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = 8,
	.expect_hci_command = BT_HCI_CMD_AUTH_REQUESTED,
	.expect_hci_param = auth_req_param,
	.expect_hci_len = sizeof(auth_req_param),
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
};

static const struct generic_data pair_device_reject_test_3 = {
	.setup_settings = settings_powered_bondable_linksec,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_AUTH_FAILED,
	.expect_func = pair_device_expect_param_func,
	.expect_hci_command = BT_HCI_CMD_PIN_CODE_REQUEST_NEG_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.expect_pin = true,
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
};

static const struct generic_data pair_device_reject_test_4 = {
	.setup_settings = settings_powered_bondable_linksec,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_AUTH_FAILED,
	.expect_func = pair_device_expect_param_func,
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
};

static uint16_t settings_powered_bondable_ssp[] = {	MGMT_OP_SET_BONDABLE,
							MGMT_OP_SET_SSP,
							MGMT_OP_SET_POWERED,
							0 };

static const struct generic_data pair_device_ssp_test_1 = {
	.setup_settings = settings_powered_bondable_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x03, /* NoInputNoOutput */
	.client_io_cap = 0x03, /* NoInputNoOutput */
};

static const void *client_io_cap_param_func(uint8_t *len)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	static uint8_t param[9];

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	memcpy(&param[6], test->expect_hci_param, 3);

	*len = sizeof(param);

	return param;
}

const uint8_t no_bonding_io_cap[] = { 0x03, 0x00, 0x00 };
static const struct generic_data pair_device_ssp_test_2 = {
	.setup_settings = settings_powered_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_IO_CAPABILITY_REQUEST_REPLY,
	.expect_hci_func = client_io_cap_param_func,
	.expect_hci_param = no_bonding_io_cap,
	.expect_hci_len = sizeof(no_bonding_io_cap),
	.io_cap = 0x03, /* NoInputNoOutput */
	.client_io_cap = 0x03, /* NoInputNoOutput */
};

const uint8_t bonding_io_cap[] = { 0x03, 0x00, 0x02 };
static const struct generic_data pair_device_ssp_test_3 = {
	.setup_settings = settings_powered_bondable_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_IO_CAPABILITY_REQUEST_REPLY,
	.expect_hci_func = client_io_cap_param_func,
	.expect_hci_param = bonding_io_cap,
	.expect_hci_len = sizeof(bonding_io_cap),
	.io_cap = 0x03, /* NoInputNoOutput */
	.client_io_cap = 0x03, /* NoInputNoOutput */
};

static const struct generic_data pair_device_ssp_test_4 = {
	.setup_settings = settings_powered_bondable_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
};

const uint8_t mitm_no_bonding_io_cap[] = { 0x01, 0x00, 0x01 };
static const struct generic_data pair_device_ssp_test_5 = {
	.setup_settings = settings_powered_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_IO_CAPABILITY_REQUEST_REPLY,
	.expect_hci_func = client_io_cap_param_func,
	.expect_hci_param = mitm_no_bonding_io_cap,
	.expect_hci_len = sizeof(mitm_no_bonding_io_cap),
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
};

const uint8_t mitm_bonding_io_cap[] = { 0x01, 0x00, 0x03 };
static const struct generic_data pair_device_ssp_test_6 = {
	.setup_settings = settings_powered_bondable_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_IO_CAPABILITY_REQUEST_REPLY,
	.expect_hci_func = client_io_cap_param_func,
	.expect_hci_param = mitm_bonding_io_cap,
	.expect_hci_len = sizeof(mitm_bonding_io_cap),
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
};

static const struct generic_data pair_device_ssp_reject_1 = {
	.setup_settings = settings_powered_bondable_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_AUTH_FAILED,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = 8,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_NEG_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
	.client_auth_req = 0x01, /* No Bonding - MITM */
	.reject_confirm = true,
};

static const struct generic_data pair_device_ssp_reject_2 = {
	.setup_settings = settings_powered_bondable_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_AUTH_FAILED,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = 8,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
	.client_reject_confirm = true,
};

static const struct generic_data pair_device_ssp_nonbondable_1 = {
	.setup_settings = settings_powered_ssp,
	.client_enable_ssp = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
};

static const struct generic_data pair_device_le_success_test_1 = {
	.setup_settings = settings_powered_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.just_works = true,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
};

static bool ltk_is_authenticated(const struct mgmt_ltk_info *ltk)
{
	switch (ltk->type) {
	case 0x01:
	case 0x03:
		return true;
	default:
		return false;
	}
}

static bool ltk_is_sc(const struct mgmt_ltk_info *ltk)
{
	switch (ltk->type) {
	case 0x02:
	case 0x03:
	case 0x04:
		return true;
	default:
		return false;
	}
}

static bool verify_ltk(const void *param, uint16_t length)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const struct mgmt_ev_new_long_term_key *ev = param;

	if (length != sizeof(struct mgmt_ev_new_long_term_key)) {
		tester_warn("Invalid new ltk length %u != %zu", length,
				sizeof(struct mgmt_ev_new_long_term_key));
		return false;
	}

	if (test->just_works && ltk_is_authenticated(&ev->key)) {
		tester_warn("Authenticated key for just-works");
		return false;
	}

	if (!test->just_works && !ltk_is_authenticated(&ev->key)) {
		tester_warn("Unauthenticated key for MITM");
		return false;
	}

	if (test->expect_sc_key && !ltk_is_sc(&ev->key)) {
		tester_warn("Non-LE SC key for SC pairing");
		return false;
	}

	if (!test->expect_sc_key && ltk_is_sc(&ev->key)) {
		tester_warn("SC key for Non-SC pairing");
		return false;
	}

	return true;
}

static const struct generic_data pair_device_le_success_test_2 = {
	.setup_settings = settings_powered_bondable,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x04, /* KeyboardDisplay */
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static uint16_t settings_powered_sc_bondable_le_ssp[] = {
						MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_LE,
						MGMT_OP_SET_SSP,
						MGMT_OP_SET_SECURE_CONN,
						MGMT_OP_SET_POWERED,
						0 };

static const struct generic_data pair_device_smp_bredr_test_1 = {
	.setup_settings = settings_powered_sc_bondable_le_ssp,
	.client_enable_ssp = true,
	.client_enable_le = true,
	.client_enable_sc = true,
	.expect_sc_key = true,
	.just_works = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x03, /* NoInputNoOutput */
	.client_io_cap = 0x03, /* NoInputNoOutput */
};

static const struct generic_data pair_device_smp_bredr_test_2 = {
	.setup_settings = settings_powered_sc_bondable_le_ssp,
	.client_enable_ssp = true,
	.client_enable_le = true,
	.client_enable_sc = true,
	.expect_sc_key = true,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
};

static const struct generic_data pair_device_le_reject_test_1 = {
	.setup_settings = settings_powered_bondable,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x04, /* KeyboardDisplay */
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.expect_status = MGMT_STATUS_AUTH_FAILED,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_auth_failed),
	.reject_confirm = true,
};

static uint16_t settings_powered_sc_bondable[] = { MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_SECURE_CONN,
						MGMT_OP_SET_POWERED, 0 };

static const struct generic_data pair_device_le_sc_legacy_test_1 = {
	.setup_settings = settings_powered_sc_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.just_works = true,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static const struct generic_data pair_device_le_sc_success_test_1 = {
	.setup_settings = settings_powered_sc_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.just_works = true,
	.client_enable_sc = true,
	.expect_sc_key = true,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static const struct generic_data pair_device_le_sc_success_test_2 = {
	.setup_settings = settings_powered_sc_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.client_enable_sc = true,
	.expect_sc_key = true,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x02, /* KeyboardOnly */
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static bool lk_is_authenticated(const struct mgmt_link_key_info *lk)
{
	switch (lk->type) {
	case 0x00: /* Combination Key */
	case 0x01: /* Local Unit Key */
	case 0x02: /* Remote Unit Key */
	case 0x03: /* Debug Combination Key */
		if (lk->pin_len == 16)
			return true;
		return false;
	case 0x05: /* Authenticated Combination Key generated from P-192 */
	case 0x08: /* Authenticated Combination Key generated from P-256 */
		return true;
	default:
		return false;
	}
}

static bool lk_is_sc(const struct mgmt_link_key_info *lk)
{
	switch (lk->type) {
	case 0x07: /* Unauthenticated Combination Key generated from P-256 */
	case 0x08: /* Authenticated Combination Key generated from P-256 */
		return true;
	default:
		return false;
	}
}

static bool verify_link_key(const void *param, uint16_t length)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const struct mgmt_ev_new_link_key *ev = param;

	if (length != sizeof(struct mgmt_ev_new_link_key)) {
		tester_warn("Invalid new Link Key length %u != %zu", length,
				sizeof(struct mgmt_ev_new_link_key));
		return false;
	}

	if (test->just_works && lk_is_authenticated(&ev->key)) {
		tester_warn("Authenticated key for just-works");
		return false;
	}

	if (!test->just_works && !lk_is_authenticated(&ev->key)) {
		tester_warn("Unauthenticated key for MITM");
		return false;
	}

	if (test->expect_sc_key && !lk_is_sc(&ev->key)) {
		tester_warn("Non-LE SC key for SC pairing");
		return false;
	}

	if (!test->expect_sc_key && lk_is_sc(&ev->key)) {
		tester_warn("SC key for Non-SC pairing");
		return false;
	}

	return true;
}

static uint16_t settings_powered_le_sc_bondable[] = {
						MGMT_OP_SET_LE,
						MGMT_OP_SET_SSP,
						MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_SECURE_CONN,
						MGMT_OP_SET_POWERED, 0 };

static const struct generic_data pair_device_le_sc_success_test_3 = {
	.setup_settings = settings_powered_le_sc_bondable,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.addr_type_avail = true,
	.addr_type = 0x01,
	.client_enable_sc = true,
	.client_enable_ssp = true,
	.client_enable_adv = true,
	.expect_sc_key = true,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x02, /* KeyboardOnly */
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.verify_alt_ev_func = verify_link_key,
};

static uint16_t settings_powered_connectable_bondable[] = {
						MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_CONNECTABLE,
						MGMT_OP_SET_POWERED, 0 };

static const struct generic_data pairing_acceptor_legacy_1 = {
	.setup_settings = settings_powered_connectable_bondable,
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
};

static const struct generic_data pairing_acceptor_legacy_2 = {
	.setup_settings = settings_powered_connectable_bondable,
	.expect_pin = true,
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
	.expect_alt_ev = MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = 8,
};

static const struct generic_data pairing_acceptor_legacy_3 = {
	.setup_settings = settings_powered_connectable,
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
	.expect_alt_ev = MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = 8,
	.expect_hci_command = BT_HCI_CMD_PIN_CODE_REQUEST_NEG_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
};

static uint16_t settings_powered_connectable_bondable_linksec[] = {
						MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_CONNECTABLE,
						MGMT_OP_SET_LINK_SECURITY,
						MGMT_OP_SET_POWERED, 0 };

static const struct generic_data pairing_acceptor_linksec_1 = {
	.setup_settings = settings_powered_connectable_bondable_linksec,
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
};

static const struct generic_data pairing_acceptor_linksec_2 = {
	.setup_settings = settings_powered_connectable_bondable_linksec,
	.expect_pin = true,
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
	.expect_alt_ev = MGMT_EV_CONNECT_FAILED,
	.expect_alt_ev_len = 8,
};

static uint16_t settings_powered_connectable_bondable_ssp[] = {
						MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_CONNECTABLE,
						MGMT_OP_SET_SSP,
						MGMT_OP_SET_POWERED, 0 };

static const struct generic_data pairing_acceptor_ssp_1 = {
	.setup_settings = settings_powered_connectable_bondable_ssp,
	.client_enable_ssp = true,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x03, /* NoInputNoOutput */
	.client_io_cap = 0x03, /* NoInputNoOutput */
	.just_works = true,
};

static const struct generic_data pairing_acceptor_ssp_2 = {
	.setup_settings = settings_powered_connectable_bondable_ssp,
	.client_enable_ssp = true,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
};

static const struct generic_data pairing_acceptor_ssp_3 = {
	.setup_settings = settings_powered_connectable_bondable_ssp,
	.client_enable_ssp = true,
	.expect_alt_ev = MGMT_EV_NEW_LINK_KEY,
	.expect_alt_ev_len = 26,
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
	.just_works = true,
};

static const void *client_io_cap_reject_param_func(uint8_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t param[7];

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	param[6] = 0x18; /* Pairing Not Allowed */

	*len = sizeof(param);

	return param;
}

static uint16_t settings_powered_connectable_ssp[] = {
						MGMT_OP_SET_CONNECTABLE,
						MGMT_OP_SET_SSP,
						MGMT_OP_SET_POWERED, 0 };

static const struct generic_data pairing_acceptor_ssp_4 = {
	.setup_settings = settings_powered_connectable_ssp,
	.client_enable_ssp = true,
	.expect_alt_ev = MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = 8,
	.expect_hci_command = BT_HCI_CMD_IO_CAPABILITY_REQUEST_NEG_REPLY,
	.expect_hci_func = client_io_cap_reject_param_func,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
	.client_auth_req = 0x02, /* Dedicated Bonding - No MITM */
};

static uint16_t settings_powered_sc_bondable_connectable_le_ssp[] = {
						MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_CONNECTABLE,
						MGMT_OP_SET_LE,
						MGMT_OP_SET_SSP,
						MGMT_OP_SET_SECURE_CONN,
						MGMT_OP_SET_POWERED,
						0 };

static const struct generic_data pairing_acceptor_smp_bredr_1 = {
	.setup_settings = settings_powered_sc_bondable_connectable_le_ssp,
	.client_enable_ssp = true,
	.client_enable_le = true,
	.client_enable_sc = true,
	.expect_sc_key = true,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
	.just_works = true,
	.io_cap = 0x03, /* NoInputNoOutput */
	.client_io_cap = 0x03, /* No InputNoOutput */
	.client_auth_req = 0x00, /* No Bonding - No MITM */
};

static const struct generic_data pairing_acceptor_smp_bredr_2 = {
	.setup_settings = settings_powered_sc_bondable_connectable_le_ssp,
	.client_enable_ssp = true,
	.client_enable_le = true,
	.client_enable_sc = true,
	.expect_sc_key = true,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
	.io_cap = 0x01, /* DisplayYesNo */
	.client_io_cap = 0x01, /* DisplayYesNo */
	.client_auth_req = 0x02, /* Dedicated Bonding - No MITM */
};

static uint16_t settings_powered_bondable_connectable_advertising[] = {
					MGMT_OP_SET_BONDABLE,
					MGMT_OP_SET_CONNECTABLE,
					MGMT_OP_SET_ADVERTISING,
					MGMT_OP_SET_POWERED, 0 };

static const struct generic_data pairing_acceptor_le_1 = {
	.setup_settings = settings_powered_bondable_connectable_advertising,
	.io_cap = 0x03, /* NoInputNoOutput */
	.client_io_cap = 0x03, /* NoInputNoOutput */
	.just_works = true,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static const struct generic_data pairing_acceptor_le_2 = {
	.setup_settings = settings_powered_bondable_connectable_advertising,
	.io_cap = 0x04, /* KeyboardDisplay */
	.client_io_cap = 0x04, /* KeyboardDisplay */
	.client_auth_req = 0x05, /* Bonding - MITM */
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static const struct generic_data pairing_acceptor_le_3 = {
	.setup_settings = settings_powered_bondable_connectable_advertising,
	.io_cap = 0x04, /* KeyboardDisplay */
	.client_io_cap = 0x04, /* KeyboardDisplay */
	.expect_alt_ev =  MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_auth_failed),
	.reject_confirm = true,
};

static const struct generic_data pairing_acceptor_le_4 = {
	.setup_settings = settings_powered_bondable_connectable_advertising,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x04, /* KeyboardDisplay */
	.client_auth_req = 0x05, /* Bonding - MITM */
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static const struct generic_data pairing_acceptor_le_5 = {
	.setup_settings = settings_powered_bondable_connectable_advertising,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x04, /* KeyboardDisplay */
	.client_auth_req = 0x05, /* Bonding - MITM */
	.reject_confirm = true,
	.expect_alt_ev =  MGMT_EV_AUTH_FAILED,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_auth_failed),
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

static const char set_static_addr_valid_param[] = {
			0x11, 0x22, 0x33, 0x44, 0x55, 0xc0 };
static const char set_static_addr_settings_param[] = { 0x01, 0x82, 0x00, 0x00 };

static const struct generic_data set_static_addr_success_test = {
	.setup_bdaddr = BDADDR_ANY,
	.setup_send_opcode = MGMT_OP_SET_STATIC_ADDRESS,
	.setup_send_param = set_static_addr_valid_param,
	.setup_send_len = sizeof(set_static_addr_valid_param),
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_static_addr_settings_param,
	.expect_len = sizeof(set_static_addr_settings_param),
	.expect_settings_set = MGMT_SETTING_STATIC_ADDRESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_RANDOM_ADDRESS,
	.expect_hci_param = set_static_addr_valid_param,
	.expect_hci_len = sizeof(set_static_addr_valid_param),
};

static const char set_static_addr_settings_dual[] = { 0x81, 0x80, 0x00, 0x00 };

static const struct generic_data set_static_addr_success_test_2 = {
	.setup_send_opcode = MGMT_OP_SET_STATIC_ADDRESS,
	.setup_send_param = set_static_addr_valid_param,
	.setup_send_len = sizeof(set_static_addr_valid_param),
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_static_addr_settings_dual,
	.expect_len = sizeof(set_static_addr_settings_dual),
	.expect_settings_set = MGMT_SETTING_STATIC_ADDRESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_RANDOM_ADDRESS,
	.expect_hci_param = set_static_addr_valid_param,
	.expect_hci_len = sizeof(set_static_addr_valid_param),
};

static const struct generic_data set_static_addr_failure_test = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_STATIC_ADDRESS,
	.send_param = set_static_addr_valid_param,
	.send_len = sizeof(set_static_addr_valid_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data set_static_addr_failure_test_2 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_STATIC_ADDRESS,
	.send_param = set_static_addr_valid_param,
	.send_len = sizeof(set_static_addr_valid_param),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const char set_scan_params_valid_param[] = { 0x60, 0x00, 0x30, 0x00 };

static const struct generic_data set_scan_params_success_test = {
	.send_opcode = MGMT_OP_SET_SCAN_PARAMS,
	.send_param = set_scan_params_valid_param,
	.send_len = sizeof(set_scan_params_valid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const char load_irks_empty_list[] = { 0x00, 0x00 };

static const struct generic_data load_irks_success1_test = {
	.send_opcode = MGMT_OP_LOAD_IRKS,
	.send_param = load_irks_empty_list,
	.send_len = sizeof(load_irks_empty_list),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const char load_irks_one_irk[] = { 0x01, 0x00,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x01,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static const struct generic_data load_irks_success2_test = {
	.send_opcode = MGMT_OP_LOAD_IRKS,
	.send_param = load_irks_one_irk,
	.send_len = sizeof(load_irks_one_irk),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const char load_irks_nval_addr_type[] = { 0x01, 0x00,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static const struct generic_data load_irks_nval_param1_test = {
	.send_opcode = MGMT_OP_LOAD_IRKS,
	.send_param = load_irks_nval_addr_type,
	.send_len = sizeof(load_irks_nval_addr_type),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char load_irks_nval_rand_addr[] = { 0x01, 0x00,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x02,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static const struct generic_data load_irks_nval_param2_test = {
	.send_opcode = MGMT_OP_LOAD_IRKS,
	.send_param = load_irks_nval_rand_addr,
	.send_len = sizeof(load_irks_nval_rand_addr),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char load_irks_nval_len[] = { 0x02, 0x00, 0xff, 0xff };

static const struct generic_data load_irks_nval_param3_test = {
	.send_opcode = MGMT_OP_LOAD_IRKS,
	.send_param = load_irks_nval_len,
	.send_len = sizeof(load_irks_nval_len),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data load_irks_not_supported_test = {
	.send_opcode = MGMT_OP_LOAD_IRKS,
	.send_param = load_irks_empty_list,
	.send_len = sizeof(load_irks_empty_list),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const char set_privacy_1_valid_param[] = { 0x01,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
static const char set_privacy_settings_param[] = { 0x80, 0x20, 0x00, 0x00 };

static const struct generic_data set_privacy_success_1_test = {
	.send_opcode = MGMT_OP_SET_PRIVACY,
	.send_param = set_privacy_1_valid_param,
	.send_len = sizeof(set_privacy_1_valid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_privacy_settings_param,
	.expect_len = sizeof(set_privacy_settings_param),
	.expect_settings_set = MGMT_SETTING_PRIVACY,
};

static const char set_privacy_2_valid_param[] = { 0x02,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

static const struct generic_data set_privacy_success_2_test = {
	.send_opcode = MGMT_OP_SET_PRIVACY,
	.send_param = set_privacy_2_valid_param,
	.send_len = sizeof(set_privacy_2_valid_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_privacy_settings_param,
	.expect_len = sizeof(set_privacy_settings_param),
	.expect_settings_set = MGMT_SETTING_PRIVACY,
};

static const struct generic_data set_privacy_powered_test = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_SET_PRIVACY,
	.send_param = set_privacy_1_valid_param,
	.send_len = sizeof(set_privacy_1_valid_param),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const char set_privacy_nval_param[] = { 0xff,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
static const struct generic_data set_privacy_nval_param_test = {
	.send_opcode = MGMT_OP_SET_PRIVACY,
	.send_param = set_privacy_nval_param,
	.send_len = sizeof(set_privacy_nval_param),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const void *get_clock_info_send_param_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t param[7];

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	param[6] = 0x00; /* Address type */

	*len = sizeof(param);

	return param;
}

static const void *get_clock_info_expect_param_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t param[17];
	struct mgmt_rp_get_clock_info *rp;

	rp = (struct mgmt_rp_get_clock_info *)param;
	memset(param, 0, sizeof(param));
	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	param[6] = 0x00; /* Address type */

	rp->local_clock = 0x11223344;
	rp->piconet_clock = 0x11223344;
	rp->accuracy = 0x5566;

	*len = sizeof(param);

	return param;
}

static const void *get_clock_info_expect_param_not_powered_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t param[17];

	memset(param, 0, sizeof(param));
	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	param[6] = 0x00; /* Address type */

	*len = sizeof(param);

	return param;
}

static const void *get_conn_info_send_param_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t param[7];

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	param[6] = 0x00; /* Address type */

	*len = sizeof(param);

	return param;
}

static const void *get_conn_info_expect_param_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t param[10];

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	param[6] = 0x00; /* Address type */
	param[7] = 0xff; /* RSSI (= -1) */
	param[8] = 0xff; /* TX power (= -1) */
	param[9] = 0x04; /* max TX power */

	*len = sizeof(param);

	return param;
}

static const void *get_conn_info_error_expect_param_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t param[10];

	/* All unset parameters shall be 0 in case of error */
	memset(param, 0, sizeof(param));

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	param[6] = 0x00; /* Address type */

	*len = sizeof(param);

	return param;
}

static const struct generic_data get_clock_info_succes1_test = {
	.setup_settings = settings_powered_connectable_bondable_ssp,
	.send_opcode = MGMT_OP_GET_CLOCK_INFO,
	.send_func = get_clock_info_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = get_clock_info_expect_param_func,
};

static const struct generic_data get_clock_info_fail1_test = {
	.send_opcode = MGMT_OP_GET_CLOCK_INFO,
	.send_func = get_clock_info_send_param_func,
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.expect_func = get_clock_info_expect_param_not_powered_func,
};

static const struct generic_data get_conn_info_succes1_test = {
	.setup_settings = settings_powered_connectable_bondable_ssp,
	.send_opcode = MGMT_OP_GET_CONN_INFO,
	.send_func = get_conn_info_send_param_func,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = get_conn_info_expect_param_func,
};

static const struct generic_data get_conn_info_ncon_test = {
	.setup_settings = settings_powered_connectable_bondable_ssp,
	.send_opcode = MGMT_OP_GET_CONN_INFO,
	.send_func = get_conn_info_send_param_func,
	.expect_status = MGMT_STATUS_NOT_CONNECTED,
	.expect_func = get_conn_info_error_expect_param_func,
};

static const void *get_conn_info_expect_param_power_off_func(uint16_t *len)
{
	struct test_data *data = tester_get_data();
	static uint8_t param[10];

	memcpy(param, hciemu_get_client_bdaddr(data->hciemu), 6);
	param[6] = 0x00; /* Address type */
	param[7] = 127; /* RSSI */
	param[8] = 127; /* TX power */
	param[9] = 127; /* max TX power */

	*len = sizeof(param);

	return param;
}

static const struct generic_data get_conn_info_power_off_test = {
	.setup_settings = settings_powered_connectable_bondable_ssp,
	.send_opcode = MGMT_OP_GET_CONN_INFO,
	.send_func = get_conn_info_send_param_func,
	.force_power_off = true,
	.expect_status = MGMT_STATUS_NOT_POWERED,
	.expect_func = get_conn_info_expect_param_power_off_func,
	.fail_tolerant = true,
};

static const uint8_t load_conn_param_nval_1[16] = { 0x12, 0x11 };
static const struct generic_data load_conn_params_fail_1 = {
	.send_opcode = MGMT_OP_LOAD_CONN_PARAM,
	.send_param = load_conn_param_nval_1,
	.send_len = sizeof(load_conn_param_nval_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t add_device_nval_1[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x00,
					0x00,
};
static const uint8_t add_device_rsp[] =  {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x00,
};
static const struct generic_data add_device_fail_1 = {
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_nval_1,
	.send_len = sizeof(add_device_nval_1),
	.expect_param = add_device_rsp,
	.expect_len = sizeof(add_device_rsp),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t add_device_nval_2[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x00,
					0x02,
};
static const struct generic_data add_device_fail_2 = {
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_nval_2,
	.send_len = sizeof(add_device_nval_2),
	.expect_param = add_device_rsp,
	.expect_len = sizeof(add_device_rsp),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t add_device_nval_3[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x00,
					0xff,
};
static const struct generic_data add_device_fail_3 = {
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_nval_3,
	.send_len = sizeof(add_device_nval_3),
	.expect_param = add_device_rsp,
	.expect_len = sizeof(add_device_rsp),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t add_device_nval_4[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x02,
					0x02,
};
static const uint8_t add_device_rsp_4[] =  {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x02,
};
static const struct generic_data add_device_fail_4 = {
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_nval_4,
	.send_len = sizeof(add_device_nval_4),
	.expect_param = add_device_rsp_4,
	.expect_len = sizeof(add_device_rsp_4),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t add_device_success_param_1[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x00,
					0x01,
};
static const struct generic_data add_device_success_1 = {
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_success_param_1,
	.send_len = sizeof(add_device_success_param_1),
	.expect_param = add_device_rsp,
	.expect_len = sizeof(add_device_rsp),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_success_param_1,
	.expect_alt_ev_len = sizeof(add_device_success_param_1),
};

static const uint8_t add_device_success_param_2[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x01,
					0x00,
};
static const uint8_t add_device_rsp_le[] =  {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x01,
};
static const struct generic_data add_device_success_2 = {
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_success_param_2,
	.send_len = sizeof(add_device_success_param_2),
	.expect_param = add_device_rsp_le,
	.expect_len = sizeof(add_device_rsp_le),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_success_param_2,
	.expect_alt_ev_len = sizeof(add_device_success_param_2),
};

static const uint8_t add_device_success_param_3[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x01,
					0x02,
};
static const struct generic_data add_device_success_3 = {
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_success_param_3,
	.send_len = sizeof(add_device_success_param_3),
	.expect_param = add_device_rsp_le,
	.expect_len = sizeof(add_device_rsp_le),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_success_param_3,
	.expect_alt_ev_len = sizeof(add_device_success_param_3),
};

static const struct generic_data add_device_success_4 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_success_param_1,
	.send_len = sizeof(add_device_success_param_1),
	.expect_param = add_device_rsp,
	.expect_len = sizeof(add_device_rsp),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_success_param_1,
	.expect_alt_ev_len = sizeof(add_device_success_param_1),
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_connectable_scan_enable_param,
	.expect_hci_len = sizeof(set_connectable_scan_enable_param),
};

static const uint8_t le_scan_enable[] = { 0x01, 0x01 };
static const struct generic_data add_device_success_5 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_success_param_2,
	.send_len = sizeof(add_device_success_param_2),
	.expect_param = add_device_rsp_le,
	.expect_len = sizeof(add_device_rsp_le),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_success_param_2,
	.expect_alt_ev_len = sizeof(add_device_success_param_2),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_ENABLE,
	.expect_hci_param = le_scan_enable,
	.expect_hci_len = sizeof(le_scan_enable),
};

static const uint8_t remove_device_nval_1[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0xff,
};
static const struct generic_data remove_device_fail_1 = {
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_nval_1,
	.send_len = sizeof(remove_device_nval_1),
	.expect_param = remove_device_nval_1,
	.expect_len = sizeof(remove_device_nval_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t remove_device_param_1[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x00,
};
static const struct generic_data remove_device_fail_2 = {
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_1,
	.send_len = sizeof(remove_device_param_1),
	.expect_param = remove_device_param_1,
	.expect_len = sizeof(remove_device_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t remove_device_param_3[] = {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x02,
};
static const struct generic_data remove_device_fail_3 = {
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_3,
	.send_len = sizeof(remove_device_param_3),
	.expect_param = remove_device_param_3,
	.expect_len = sizeof(remove_device_param_3),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data remove_device_success_1 = {
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_1,
	.send_len = sizeof(remove_device_param_1),
	.expect_param = remove_device_param_1,
	.expect_len = sizeof(remove_device_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_1,
	.expect_alt_ev_len = sizeof(remove_device_param_1),
};

static const struct generic_data remove_device_success_2 = {
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_1,
	.send_len = sizeof(remove_device_param_1),
	.expect_param = remove_device_param_1,
	.expect_len = sizeof(remove_device_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_1,
	.expect_alt_ev_len = sizeof(remove_device_param_1),
	.expect_hci_command = BT_HCI_CMD_WRITE_SCAN_ENABLE,
	.expect_hci_param = set_connectable_off_scan_enable_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_enable_param),
};

static const struct generic_data remove_device_success_3 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_1,
	.send_len = sizeof(remove_device_param_1),
	.expect_param = remove_device_param_1,
	.expect_len = sizeof(remove_device_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_1,
	.expect_alt_ev_len = sizeof(remove_device_param_1),
};

static const uint8_t remove_device_param_2[] =  {
					0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
					0x01,
};
static const struct generic_data remove_device_success_4 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_2,
	.send_len = sizeof(remove_device_param_2),
	.expect_param = remove_device_param_2,
	.expect_len = sizeof(remove_device_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_2,
	.expect_alt_ev_len = sizeof(remove_device_param_2),
};

static const struct generic_data remove_device_success_5 = {
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_2,
	.send_len = sizeof(remove_device_param_2),
	.expect_param = remove_device_param_2,
	.expect_len = sizeof(remove_device_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_2,
	.expect_alt_ev_len = sizeof(remove_device_param_2),
};

static const uint8_t remove_device_param_all[7] =  { 0x00 };

static const struct generic_data remove_device_success_6 = {
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_all,
	.send_len = sizeof(remove_device_param_all),
	.expect_param = remove_device_param_all,
	.expect_len = sizeof(remove_device_param_all),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data add_remove_device_nowait = {
	.setup_settings = settings_powered_le,
	.expect_param = remove_device_param_2,
	.expect_len = sizeof(remove_device_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_2,
	.expect_alt_ev_len = sizeof(remove_device_param_2),
};

static const struct generic_data read_adv_features_invalid_param_test = {
	.send_opcode = MGMT_OP_READ_ADV_FEATURES,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_adv_features_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_ADV_FEATURES,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const uint8_t read_adv_features_rsp_1[] =  {
	0x7f, 0xf0, 0x01, 0x00,	/* supported flags */
	0x1f,			/* max_adv_data_len */
	0x1f,			/* max_scan_rsp_len */
	0x05,			/* max_instances */
	0x00,			/* num_instances */
};

static const struct generic_data read_adv_features_success_1 = {
	.send_opcode = MGMT_OP_READ_ADV_FEATURES,
	.expect_param = read_adv_features_rsp_1,
	.expect_len = sizeof(read_adv_features_rsp_1),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const uint8_t read_adv_features_rsp_2[] =  {
	0x7f, 0xf0, 0x01, 0x00,	/* supported flags */
	0x1f,			/* max_adv_data_len */
	0x1f,			/* max_scan_rsp_len */
	0x05,			/* max_instances */
	0x01,			/* num_instances */
	0x01,			/* instance identifiers */
};

static const struct generic_data read_adv_features_success_2 = {
	.send_opcode = MGMT_OP_READ_ADV_FEATURES,
	.expect_param = read_adv_features_rsp_2,
	.expect_len = sizeof(read_adv_features_rsp_2),
	.expect_status = MGMT_STATUS_SUCCESS,
};

/* simple add advertising command */
static const uint8_t add_advertising_param_uuid[] = {
	0x01,			/* adv instance */
	0x00, 0x00, 0x00, 0x00,	/* flags: none */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x09,			/* adv data len */
	0x00,			/* scan rsp len */
	/* adv data: */
	0x03,			/* AD len */
	0x02,			/* AD type: some 16 bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x04,			/* AD len */
	0xff,			/* AD type: manufacturer specific data */
	0x01, 0x02, 0x03,	/* custom advertising data */
};

/* add advertising with scan response data */
static const uint8_t add_advertising_param_scanrsp[] = {
	/* instance, flags, duration, timeout, adv data len: same as before */
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
	0x0a,			/* scan rsp len */
	/* adv data: same as before */
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
	/* scan rsp data: */
	0x03,			/* AD len */
	0x19,			/* AD type: external appearance */
	0x40, 0x03,		/* some custom appearance */
	0x05,			/* AD len */
	0x03,			/* AD type: all 16 bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x0f, 0x18,		/* battery service */
};

/* add advertising with timeout */
static const uint8_t add_advertising_param_timeout[] = {
	/* instance, flags, duration: same as before */
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x05, 0x00,		/* timeout: 5 seconds */
	/* adv data: same as before */
	0x09, 0x00, 0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

/* add advertising with connectable flag */
static const uint8_t add_advertising_param_connectable[] = {
	0x01,			/* adv instance */
	0x01, 0x00, 0x00, 0x00,	/* flags: connectable*/
	/* duration, timeout, adv/scan data: same as before */
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

/* add advertising with general discoverable flag */
static const uint8_t add_advertising_param_general_discov[] = {
	0x01,			/* adv instance */
	0x02, 0x00, 0x00, 0x00,	/* flags: general discoverable*/
	/* duration, timeout, adv/scan data: same as before */
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

/* add advertising with limited discoverable flag */
static const uint8_t add_advertising_param_limited_discov[] = {
	0x01,			/* adv instance */
	0x04, 0x00, 0x00, 0x00,	/* flags: limited discoverable */
	/* duration, timeout, adv/scan data: same as before */
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

/* add advertising with managed flags */
static const uint8_t add_advertising_param_managed[] = {
	0x01,			/* adv instance */
	0x08, 0x00, 0x00, 0x00,	/* flags: managed flags */
	/* duration, timeout, adv/scan data: same as before */
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

/* add advertising with tx power flag */
static const uint8_t add_advertising_param_txpwr[] = {
	0x01,			/* adv instance */
	0x10, 0x00, 0x00, 0x00,	/* flags: tx power */
	/* duration, timeout, adv/scan data: same as before */
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

/* add advertising command for a second instance */
static const uint8_t add_advertising_param_test2[] = {
	0x02,				/* adv instance */
	0x00, 0x00, 0x00, 0x00,		/* flags: none */
	0x00, 0x00,			/* duration: default */
	0x01, 0x00,			/* timeout: 1 second */
	0x07,				/* adv data len */
	0x00,				/* scan rsp len */
	/* adv data: */
	0x06,				/* AD len */
	0x08,				/* AD type: shortened local name */
	0x74, 0x65, 0x73, 0x74, 0x32,	/* "test2" */
};

static const uint8_t advertising_instance1_param[] = {
	0x01,
};

static const uint8_t advertising_instance2_param[] = {
	0x02,
};

static const uint8_t set_adv_data_uuid[] = {
	/* adv data len */
	0x09,
	/* advertise heart rate monitor and manufacturer specific data */
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
};

static const uint8_t set_adv_data_test1[] = {
	0x07,				/* adv data len */
	0x06,				/* AD len */
	0x08,				/* AD type: shortened local name */
	0x74, 0x65, 0x73, 0x74, 0x31,	/* "test1" */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static const uint8_t set_adv_data_test2[] = {
	0x07,				/* adv data len */
	0x06,				/* AD len */
	0x08,				/* AD type: shortened local name */
	0x74, 0x65, 0x73, 0x74, 0x32,	/* "test2" */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static const uint8_t set_adv_data_txpwr[] = {
	0x03,			/* adv data len */
	0x02, 			/* AD len */
	0x0a,			/* AD type: tx power */
	0x00,			/* tx power */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t set_adv_data_general_discov[] = {
	0x0c,			/* adv data len */
	0x02,			/* AD len */
	0x01,			/* AD type: flags */
	0x02,			/* general discoverable */
	0x03,			/* AD len */
	0x02,			/* AD type: some 16bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x04,			/* AD len */
	0xff,			/* AD type: manufacturer specific data */
	0x01, 0x02, 0x03,	/* custom advertising data */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t set_adv_data_limited_discov[] = {
	0x0c,			/* adv data len */
	0x02,			/* AD len */
	0x01,			/* AD type: flags */
	0x01,			/* limited discoverable */
	/* rest: same as before */
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t set_adv_data_uuid_txpwr[] = {
	0x0c,			/* adv data len */
	0x03,			/* AD len */
	0x02,			/* AD type: some 16bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x04,			/* AD len */
	0xff,			/* AD type: manufacturer specific data */
	0x01, 0x02, 0x03,	/* custom advertising data */
	0x02,			/* AD len */
	0x0a,			/* AD type: tx power */
	0x00,			/* tx power */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t set_scan_rsp_uuid[] = {
	0x0a,			/* scan rsp data len */
	0x03,			/* AD len */
	0x19,			/* AD type: external appearance */
	0x40, 0x03,		/* some custom appearance */
	0x05,			/* AD len */
	0x03,			/* AD type: all 16 bit service class UUIDs */
	0x0d, 0x18, 0x0f, 0x18,	/* heart rate monitor, battery service */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00,
};

static const uint8_t add_advertising_invalid_param_1[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
	0x03, 0x03, 0x0d, 0x18,
	0x19, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
};

static const uint8_t add_advertising_invalid_param_2[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x04, 0x03, 0x0d, 0x18,
	0x04, 0xff, 0x01, 0x02, 0x03,
};

static const uint8_t add_advertising_invalid_param_3[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x03, 0x0d, 0x18,
	0x02, 0xff, 0x01, 0x02, 0x03,
};

static const uint8_t add_advertising_invalid_param_4[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x03, 0x0d, 0x18,
	0x05, 0xff, 0x01, 0x02, 0x03,
};

static const uint8_t add_advertising_invalid_param_5[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1D, 0x00,
	0x03, 0x03, 0x0d, 0x18,
	0x19, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18,
};

static const uint8_t add_advertising_invalid_param_6[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
	0x03, 0x03, 0x0d, 0x18,
	0x19, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
};

static const uint8_t add_advertising_invalid_param_7[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
	0x04, 0x03, 0x0d, 0x18,
	0x04, 0xff, 0x01, 0x02, 0x03,
};

static const uint8_t add_advertising_invalid_param_8[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
	0x03, 0x03, 0x0d, 0x18,
	0x02, 0xff, 0x01, 0x02, 0x03,
};

static const uint8_t add_advertising_invalid_param_9[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
	0x03, 0x03, 0x0d, 0x18,
	0x05, 0xff, 0x01, 0x02, 0x03,
};

static const uint8_t add_advertising_invalid_param_10[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1D,
	0x03, 0x03, 0x0d, 0x18,
	0x19, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
	0x15, 0x16, 0x17, 0x18,
};

static const struct generic_data add_advertising_fail_1 = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data add_advertising_fail_2 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_1,
	.send_len = sizeof(add_advertising_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_3 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_2,
	.send_len = sizeof(add_advertising_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_4 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_3,
	.send_len = sizeof(add_advertising_invalid_param_3),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_5 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_4,
	.send_len = sizeof(add_advertising_invalid_param_4),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_6 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_5,
	.send_len = sizeof(add_advertising_invalid_param_5),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_7 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_6,
	.send_len = sizeof(add_advertising_invalid_param_6),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_8 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_7,
	.send_len = sizeof(add_advertising_invalid_param_7),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_9 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_8,
	.send_len = sizeof(add_advertising_invalid_param_8),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_10 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_9,
	.send_len = sizeof(add_advertising_invalid_param_9),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_11 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_invalid_param_10,
	.send_len = sizeof(add_advertising_invalid_param_10),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data add_advertising_fail_12 = {
	.setup_settings = settings_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_timeout,
	.send_len = sizeof(add_advertising_param_timeout),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data add_advertising_success_1 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_uuid,
	.expect_hci_len = sizeof(set_adv_data_uuid),
};

static const char set_powered_adv_instance_settings_param[] = {
	0x81, 0x02, 0x00, 0x00,
};

static const struct generic_data add_advertising_success_pwron_data = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_adv_instance_settings_param,
	.expect_len = sizeof(set_powered_adv_instance_settings_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_test1,
	.expect_hci_len = sizeof(set_adv_data_test1),
};

static const struct generic_data add_advertising_success_pwron_enabled = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_adv_instance_settings_param,
	.expect_len = sizeof(set_powered_adv_instance_settings_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_ENABLE,
	.expect_hci_param = set_adv_on_set_adv_enable_param,
	.expect_hci_len = sizeof(set_adv_on_set_adv_enable_param),
};

static const struct generic_data add_advertising_success_4 = {
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param,
	.send_len = sizeof(set_adv_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_adv_settings_param_2,
	.expect_len = sizeof(set_adv_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_txpwr,
	.expect_hci_len = sizeof(set_adv_data_txpwr),
};

static const struct generic_data add_advertising_success_5 = {
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_off_param,
	.send_len = sizeof(set_adv_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_adv_instance_settings_param,
	.expect_len = sizeof(set_powered_adv_instance_settings_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_test1,
	.expect_hci_len = sizeof(set_adv_data_test1),
};

static const struct generic_data add_advertising_success_6 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scanrsp,
	.send_len = sizeof(add_advertising_param_scanrsp),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_uuid,
	.expect_hci_len = sizeof(set_adv_data_uuid),
};

static const struct generic_data add_advertising_success_7 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scanrsp,
	.send_len = sizeof(add_advertising_param_scanrsp),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_scan_rsp_uuid,
	.expect_hci_len = sizeof(set_scan_rsp_uuid),
};

static const struct generic_data add_advertising_success_8 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_connectable,
	.send_len = sizeof(add_advertising_param_connectable),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_on_adv_param,
	.expect_hci_len = sizeof(set_connectable_on_adv_param),
};

static const struct generic_data add_advertising_success_9 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_general_discov,
	.send_len = sizeof(add_advertising_param_general_discov),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_general_discov,
	.expect_hci_len = sizeof(set_adv_data_general_discov),
};

static const struct generic_data add_advertising_success_10 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_limited_discov,
	.send_len = sizeof(add_advertising_param_limited_discov),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_limited_discov,
	.expect_hci_len = sizeof(set_adv_data_limited_discov),
};

static const struct generic_data add_advertising_success_11 = {
	.setup_settings = settings_powered_le_discoverable,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_managed,
	.send_len = sizeof(add_advertising_param_managed),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_general_discov,
	.expect_hci_len = sizeof(set_adv_data_general_discov),
};

static const struct generic_data add_advertising_success_12 = {
	.setup_settings = settings_powered_le_discoverable,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_txpwr,
	.send_len = sizeof(add_advertising_param_txpwr),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_uuid_txpwr,
	.expect_hci_len = sizeof(set_adv_data_uuid_txpwr),
};

static uint16_t settings_powered_le_connectable[] = {
						MGMT_OP_SET_POWERED,
						MGMT_OP_SET_LE,
						MGMT_OP_SET_CONNECTABLE, 0 };

static const struct generic_data add_advertising_success_13 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scanrsp,
	.send_len = sizeof(add_advertising_param_scanrsp),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_off_scan_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_adv_param),
	.expect_hci_param_check_func = set_connectable_off_scan_adv_check_func
};

static uint8_t set_connectable_off_adv_param[] = {
		0x64, 0x00,				/* min_interval */
		0x96, 0x00,				/* max_interval */
		0x03,					/* type */
		0x01,					/* own_addr_type */
		0x00,					/* direct_addr_type */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* direct_addr */
		0x07,					/* channel_map */
		0x00,					/* filter_policy */
};

static int set_connectable_off_adv_check_func(const void *param,
								uint16_t length)
{
	const uint8_t *received = param;
	uint8_t *expected = set_connectable_off_adv_param;

	/* Compare the received param with expected param, but ignore the
	 * min_internal and max_interval since these values are turned often
	 * in the kernel and we don't want to update the expected value every
	 * time.
	 */
	return memcmp(&received[4], &expected[4], length - 4);
}

static const struct generic_data add_advertising_success_14 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_off_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_adv_param),
	.expect_hci_param_check_func = set_connectable_off_adv_check_func
};

static const struct generic_data add_advertising_success_15 = {
	.setup_settings = settings_powered_le_connectable,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_on_adv_param,
	.expect_hci_len = sizeof(set_connectable_on_adv_param),
};

static const char set_connectable_settings_param_3[] = {
						0x83, 0x02, 0x00, 0x00 };

static const struct generic_data add_advertising_success_16 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_settings_param_3,
	.expect_len = sizeof(set_connectable_settings_param_3),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_on_adv_param,
	.expect_hci_len = sizeof(set_connectable_on_adv_param),
};

static const struct generic_data add_advertising_success_17 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_2,
	.expect_len = sizeof(set_le_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_PARAMETERS,
	.expect_hci_param = set_connectable_off_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_adv_param),
	.expect_hci_param_check_func = set_connectable_off_adv_check_func
};

static const char set_powered_off_le_settings_param[] = {
	0x80, 0x02, 0x00, 0x00
};

static const struct generic_data add_advertising_power_off = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_off_param,
	.send_len = sizeof(set_powered_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_off_le_settings_param,
	.expect_len = sizeof(set_powered_off_le_settings_param),
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
};

static const char set_le_settings_param_off[] = { 0x81, 0x00, 0x00, 0x00 };

static const struct generic_data add_advertising_le_off = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_off_param,
	.send_len = sizeof(set_le_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_off,
	.expect_len = sizeof(set_le_settings_param_off),
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
};

static const struct generic_data add_advertising_success_18 = {
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_uuid,
	.expect_hci_len = sizeof(set_adv_data_uuid),
};

static const struct generic_data add_advertising_timeout_expired = {
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_ENABLE,
	.expect_hci_param = set_adv_on_set_adv_disable_param,
	.expect_hci_len = sizeof(set_adv_on_set_adv_disable_param),
};

static const uint8_t remove_advertising_param_1[] = {
	0x01,
};

static const uint8_t remove_advertising_param_2[] = {
	0x00,
};

static const struct generic_data remove_advertising_fail_1 = {
	.send_opcode = MGMT_OP_REMOVE_ADVERTISING,
	.send_param = remove_advertising_param_1,
	.send_len = sizeof(remove_advertising_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data remove_advertising_success_1 = {
	.send_opcode = MGMT_OP_REMOVE_ADVERTISING,
	.send_param = remove_advertising_param_1,
	.send_len = sizeof(remove_advertising_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = remove_advertising_param_1,
	.expect_len = sizeof(remove_advertising_param_1),
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_ENABLE,
	.expect_hci_param = set_adv_off_param,
	.expect_hci_len = sizeof(set_adv_off_param),
};

static const struct generic_data remove_advertising_success_2 = {
	.send_opcode = MGMT_OP_REMOVE_ADVERTISING,
	.send_param = remove_advertising_param_2,
	.send_len = sizeof(remove_advertising_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = remove_advertising_param_2,
	.expect_len = sizeof(remove_advertising_param_2),
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_ENABLE,
	.expect_hci_param = set_adv_off_param,
	.expect_hci_len = sizeof(set_adv_off_param),
};

static const struct generic_data multi_advertising_switch = {
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_test2,
	.expect_hci_len = sizeof(set_adv_data_test2),
};

static const struct generic_data multi_advertising_add_second = {
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_test2,
	.send_len = sizeof(add_advertising_param_test2),
	.expect_param = advertising_instance2_param,
	.expect_len = sizeof(advertising_instance2_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance2_param,
	.expect_alt_ev_len = sizeof(advertising_instance2_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_DATA,
	.expect_hci_param = set_adv_data_test2,
	.expect_hci_len = sizeof(set_adv_data_test2),
};

/* based on G-Tag ADV_DATA */
static const uint8_t adv_data_invalid_significant_len[] = { 0x02, 0x01, 0x06,
		0x0d, 0xff, 0x80, 0x01, 0x02, 0x15, 0x12, 0x34, 0x80, 0x91,
		0xd0, 0xf2, 0xbb, 0xc5, 0x03, 0x02, 0x0f, 0x18, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const char device_found_valid[] = { 0x00, 0x00, 0x01, 0x01, 0xaa, 0x00,
		0x01, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x02, 0x01,
		0x06, 0x0d, 0xff, 0x80, 0x01, 0x02, 0x15, 0x12, 0x34, 0x80,
		0x91, 0xd0, 0xf2, 0xbb, 0xc5, 0x03, 0x02, 0x0f, 0x18 };

static const struct generic_data device_found_gtag = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_alt_ev = MGMT_EV_DEVICE_FOUND,
	.expect_alt_ev_param = device_found_valid,
	.expect_alt_ev_len = sizeof(device_found_valid),
	.set_adv = true,
	.adv_data_len = sizeof(adv_data_invalid_significant_len),
	.adv_data = adv_data_invalid_significant_len,
};

static const uint8_t adv_data_invalid_field_len[] = { 0x02, 0x01, 0x01,
		0x05, 0x09, 0x74, 0x65, 0x73, 0x74,
		0xa0, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05};

static const char device_found_valid2[] = { 0x00, 0x00, 0x01, 0x01, 0xaa, 0x00,
		0x01, 0x7f, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 0x02, 0x01,
		0x01, 0x05, 0x09, 0x74, 0x65, 0x73, 0x74};

static const struct generic_data device_found_invalid_field = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_alt_ev = MGMT_EV_DEVICE_FOUND,
	.expect_alt_ev_param = device_found_valid2,
	.expect_alt_ev_len = sizeof(device_found_valid2),
	.set_adv = true,
	.adv_data_len = sizeof(adv_data_invalid_field_len),
	.adv_data = adv_data_invalid_field_len,
};

static const struct generic_data read_local_oob_not_powered_test = {
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_DATA,
	.expect_status = MGMT_STATUS_NOT_POWERED,
};

static const struct generic_data read_local_oob_invalid_param_test = {
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_DATA,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_local_oob_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_DATA,
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_local_oob_legacy_pairing_test = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_DATA,
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const struct generic_data read_local_oob_success_ssp_test = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_DATA,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_ignore_param = true,
	.expect_hci_command = BT_HCI_CMD_READ_LOCAL_OOB_DATA,
};

static const struct generic_data read_local_oob_success_sc_test = {
	.setup_settings = settings_powered_sc,
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_DATA,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_ignore_param = true,
	.expect_hci_command = BT_HCI_CMD_READ_LOCAL_OOB_EXT_DATA,
};

static const uint8_t oob_type_bredr[] = { 0x01 };
static const struct generic_data read_local_oob_ext_invalid_index_test = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_EXT_DATA,
	.send_param = oob_type_bredr,
	.send_len = sizeof(oob_type_bredr),
	.expect_status = MGMT_STATUS_INVALID_INDEX,
};

static const struct generic_data read_local_oob_ext_legacy_pairing_test = {
	.setup_settings = settings_powered,
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_EXT_DATA,
	.send_param = oob_type_bredr,
	.send_len = sizeof(oob_type_bredr),
	.expect_ignore_param = true,
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const struct generic_data read_local_oob_ext_success_ssp_test = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_EXT_DATA,
	.send_param = oob_type_bredr,
	.send_len = sizeof(oob_type_bredr),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_ignore_param = true,
	.expect_hci_command = BT_HCI_CMD_READ_LOCAL_OOB_DATA,
};

static const struct generic_data read_local_oob_ext_success_sc_test = {
	.setup_settings = settings_powered_sc,
	.send_opcode = MGMT_OP_READ_LOCAL_OOB_EXT_DATA,
	.send_param = oob_type_bredr,
	.send_len = sizeof(oob_type_bredr),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_ignore_param = true,
	.expect_hci_command = BT_HCI_CMD_READ_LOCAL_OOB_EXT_DATA,
};

static const uint8_t le_states_conn_peripheral_adv_connectable[] = {
			0x00, 0x00, 0x20, 0x00, 0x40, 0x00, 0x00, 0x00};
static const uint8_t le_states_conn_peripheral_adv_non_connectable[] = {
			0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t le_states_conn_central_adv_connectable[] = {
			0x00, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00};
static const uint8_t le_states_conn_central_adv_non_connectable[] = {
			0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00};

static const struct generic_data conn_peripheral_adv_connectable_test = {
	.setup_le_states = true,
	.le_states = le_states_conn_peripheral_adv_connectable,
	.setup_settings = settings_powered_le,
	.client_enable_le = true
};

static const struct generic_data conn_peripheral_adv_non_connectable_test = {
	.setup_le_states = true,
	.le_states = le_states_conn_peripheral_adv_non_connectable,
	.setup_settings = settings_powered_le,
	.client_enable_le = true
};

static const struct generic_data conn_central_adv_connectable_test = {
	.setup_le_states = true,
	.le_states = le_states_conn_central_adv_connectable,
	.setup_settings = settings_powered_le,
	.client_enable_le = true,
	.client_enable_adv = 1
};

static const struct generic_data conn_central_adv_non_connectable_test = {
	.setup_le_states = true,
	.le_states = le_states_conn_central_adv_non_connectable,
	.setup_settings = settings_powered_le,
	.client_enable_le = true,
	.client_enable_adv = 1
};

static const char ext_ctrl_info1[] = {
	0x00, 0x00, 0x00, 0x01, 0xaa, 0x00, /* btaddr */
	0x09, /* version */
	0xf1, 0x05, /* manufacturer */
	0xff, 0xbe, 0x01, 0x00, /* supported settings */
	0x80, 0x00, 0x00, 0x00, /* current settings */
	0x09, 0x00, /* eir length */
	0x04, /* dev class length */
	0x0d, /* dev class info */
	0x00, /* minor */
	0x00, /* major */
	0x00, /* service classes */
	0x01, /* complete name data length */
	0x09, /* complete name flag */
	0x01, /* short name data length */
	0x08, /* short name flag */
};

static const struct generic_data read_ext_ctrl_info1 = {
	.send_opcode = MGMT_OP_READ_EXT_INFO,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_ctrl_info1,
	.expect_len = sizeof(ext_ctrl_info1),
};

static const char set_dev_class1[] = { 0x03, 0xe0 };

static const struct setup_mgmt_cmd set_dev_class_cmd_arr1[] = {
	{
		.send_opcode = MGMT_OP_SET_DEV_CLASS,
		.send_param = set_dev_class1,
		.send_len = sizeof(set_dev_class1),
	},
	{
		.send_opcode = MGMT_OP_ADD_UUID,
		.send_param = add_spp_uuid_param,
		.send_len = sizeof(add_spp_uuid_param),
	}
};

static const char ext_ctrl_info2[] = {
	0x00, 0x00, 0x00, 0x01, 0xaa, 0x00, /* btaddr */
	0x09, /* version */
	0xf1, 0x05, /* manufacturer */
	0xff, 0xbe, 0x01, 0x00, /* supported settings */
	0x81, 0x02, 0x00, 0x00, /* current settings */
	0x0D, 0x00, /* eir length */
	0x04, /* dev class length */
	0x0d, /* dev class info */
	0xe0, /* minor */
	0x03, /* major */
	0x00, /* service classes */
	0x03, /* appearance length */
	0x19, /* EIR_APPEARANCE */
	0x00, /* Appearance value */
	0x00,
	0x01, /* complete name data length */
	0x09, /* complete name flag */
	0x01, /* short name data length */
	0x08, /* short name flag */
};

static const struct generic_data read_ext_ctrl_info2 = {
	.setup_settings = settings_powered_le,
	.setup_mgmt_cmd_arr = set_dev_class_cmd_arr1,
	.setup_mgmt_cmd_arr_size = ARRAY_SIZE(set_dev_class_cmd_arr1),
	.send_opcode = MGMT_OP_READ_EXT_INFO,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_ctrl_info2,
	.expect_len = sizeof(ext_ctrl_info2),
};

static const char ext_ctrl_info3[] = {
	0x00, 0x00, 0x00, 0x01, 0xaa, 0x00, /* btaddr */
	0x09, /* version */
	0xf1, 0x05, /* manufacturer */
	0xff, 0xbe, 0x01, 0x00, /* supported settings */
	0x80, 0x02, 0x00, 0x00, /* current settings */
	0x16, 0x00, /* eir length */
	0x04, /* dev class length */
	0x0d, /* dev class info */
	0x00, /* minor */
	0x00, /* major */
	0x00, /* service classes */
	0x03, /* appearance length */
	0x19, /* EIR_APPEARANCE */
	0x00, /* Appearance value */
	0x00,
	0x0A, /* Local name length */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74,
	0x20, 0x6E, 0x61, 0x6D, 0x65, /* "Test name" */
	0x01, /* short name data length */
	0x08, /* short name flag */
};

static const struct generic_data read_ext_ctrl_info3 = {
	.setup_settings = settings_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = set_local_name_param,
	.setup_send_len = sizeof(set_local_name_param),
	.send_opcode = MGMT_OP_READ_EXT_INFO,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_ctrl_info3,
	.expect_len = sizeof(ext_ctrl_info3),
};

static const char ext_ctrl_info4[] = {
	0x00, 0x00, 0x00, 0x01, 0xaa, 0x00, /* btaddr */
	0x09, /* version */
	0xf1, 0x05, /* manufacturer */
	0xff, 0xbe, 0x01, 0x00, /* supported settings */
	0x80, 0x02, 0x00, 0x00, /* current settings */
	0x1a, 0x00, /* eir length */
	0x04, /* dev class length */
	0x0d, /* dev class info */
	0x00, /* minor */
	0x00, /* major */
	0x00, /* service classes */
	0x03, /* appearance length */
	0x19, /* EIR_APPEARANCE */
	0x00, /* Appearance value */
	0x00,
	0x0A, /* Complete Local name len */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74,
	0x20, 0x6E, 0x61, 0x6D, 0x65, /* "Test name" */
	0x05, /* Short Local name len */
	0x08, /* Short name */
	0x54, 0x65, 0x73, 0x74, /* "Test" */
};

static const struct generic_data read_ext_ctrl_info4 = {
	.setup_settings = settings_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_cp,
	.setup_send_len = sizeof(set_local_name_cp),
	.send_opcode = MGMT_OP_READ_EXT_INFO,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_ctrl_info4,
	.expect_len = sizeof(ext_ctrl_info4),
};

static const struct setup_mgmt_cmd set_dev_class_cmd_arr2[] = {
	{
		.send_opcode = MGMT_OP_SET_DEV_CLASS,
		.send_param = set_dev_class1,
		.send_len = sizeof(set_dev_class1),
	},
	{
		.send_opcode = MGMT_OP_ADD_UUID,
		.send_param = add_spp_uuid_param,
		.send_len = sizeof(add_spp_uuid_param),
	},
	{
		.send_opcode = MGMT_OP_SET_LOCAL_NAME,
		.send_param = &set_local_name_cp,
		.send_len = sizeof(set_local_name_cp),
	}
};

static const char ext_ctrl_info5[] = {
	0x00, 0x00, 0x00, 0x01, 0xaa, 0x00, /* btaddr */
	0x09, /* version */
	0xf1, 0x05, /* manufacturer */
	0xff, 0xbe, 0x01, 0x00, /* supported settings */
	0x81, 0x02, 0x00, 0x00, /* current settings */
	0x1a, 0x00, /* eir len */
	0x04, /* dev class len */
	0x0d, /* dev class info */
	0xe0, /* minor */
	0x03, /* major */
	0x00, /* service classes */
	0x03, /* appearance length */
	0x19, /* EIR_APPEARANCE */
	0x00, /* Appearance value */
	0x00,
	0x0A, /* Complete Local name len */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74,
	0x20, 0x6E, 0x61, 0x6D, 0x65, /* "Test name" */
	0x05, /* Short Local name len */
	0x08, /* Short name */
	0x54, 0x65, 0x73, 0x74, /* "Test" */
};

static const struct generic_data read_ext_ctrl_info5 = {
	.setup_settings = settings_powered_le,
	.setup_mgmt_cmd_arr = set_dev_class_cmd_arr2,
	.setup_mgmt_cmd_arr_size = ARRAY_SIZE(set_dev_class_cmd_arr2),
	.send_opcode = MGMT_OP_READ_EXT_INFO,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_ctrl_info5,
	.expect_len = sizeof(ext_ctrl_info5),
};

static const struct generic_data read_controller_cap_invalid_param_test = {
	.send_opcode = MGMT_OP_READ_CONTROLLER_CAP,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data read_controller_cap_success = {
	.send_opcode = MGMT_OP_READ_CONTROLLER_CAP,
	.expect_ignore_param = true,
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const char ext_adv_params_valid[] = {
	0x01, /* instance */
	0x00, 0xC0, 0x00, 0x00, /* flags, use tx power and intervals */
	0x00, 0x00, /* duration */
	0x00, 0x00, /* timeout */
	0xA0, 0x00, 0x00, 0x00, /* min_interval */
	0xA0, 0x00, 0x00, 0x00, /* max_interval */
	0x7f, /* tx_power */
};

static const char ext_adv_hci_params_valid[] = {
	0x01, /* handle */
	0x10, 0x00, /* evt_properties */
	0xA0, 0x00, 0x00, /* min_interval */
	0xA0, 0x00, 0x00, /* max_interval */
	0x07, /* channel_map */
	0x01, /* own_addr_type */
	0x00, /* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* peer_addr */
	0x00, /* filter_policy */
	0x7f, /* tx_power */
	0x01, /* primary_phy */
	0x00, /* secondary_max_skip */
	0x01, /* secondary_phy */
	0x00, /* sid */
	0x00, /* notif_enable */
};

static const char ext_adv_params_mgmt_rsp_valid_50[] = {
	0x01, /* instance */
	0x00, /* tx_power defaults to 0 on BT5 platform*/
	0xfb, /* max_adv_data_len */
	0xfb, /* max_scan_rsp_len */
};

static const char ext_adv_params_mgmt_rsp_valid[] = {
	0x01, /* instance */
	0x7f, /* tx_power */
	0x1f, /* max_adv_data_len */
	0x1f, /* max_scan_rsp_len */
};

static const char ext_adv_data_mgmt_rsp_valid[] = {
	0x01, /* instance */
};

static const uint8_t ext_adv_data_valid[] = {
	0x01, /* instance */
	0x04, /* Ad data len */
	0x06, /* Scan response data len */
	0x03, /* Section length */
	0x19, /* GAP Appearance */
	0x01,
	0x23,
	0x05, /* Section length */
	0x08, /* ad type Short Name */
	't',
	'e',
	's',
	't',
};

static const char ext_adv_hci_ad_data_valid[] = {
	0x01, /* handle */
	0x03, /* operation */
	0x01, /* minimize fragmentation */
	0x04, /* data length */
	0x03, /* Section length */
	0x19, /* GAP Appearance */
	0x01,
	0x23,
};

static const char ext_adv_hci_scan_rsp_data_valid[] = {
	0x01, /* handle */
	0x03, /* operation */
	0x01, /* minimize fragmentation */
	0x06,
	0x05, /* Section length */
	0x08, /* ad type Short Name */
	't',
	'e',
	's',
	't',
};

static const uint8_t ext_adv_data_invalid[] = {
	0x01, /* instance */
	0x04, /* Ad data len */
	0x06, /* Scan response data len */
	0x03, /* Section length */
	0x19, /* GAP Appearance */
	0x01,
	0x23,
	0x07, /* Section length purposefully two octets too long */
	0x08, /* ad type Short Name */
	't',
	'e',
	's',
	't',
};

static const struct generic_data adv_params_fail_unpowered = {
	.setup_settings = settings_le, /* Unpowered */
	.send_opcode = MGMT_OP_ADD_EXT_ADV_PARAMS,
	.send_param = ext_adv_params_valid,
	.send_len = sizeof(ext_adv_params_valid),
	.expect_status = MGMT_STATUS_REJECTED,
};

static const struct generic_data adv_params_fail_invalid_params = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_EXT_ADV_PARAMS,
	.send_param = dummy_data,
	.send_len = sizeof(dummy_data),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data adv_params_success = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_EXT_ADV_PARAMS,
	.send_param = ext_adv_params_valid,
	.send_len = sizeof(ext_adv_params_valid),
	.expect_param = ext_adv_params_mgmt_rsp_valid,
	.expect_len = sizeof(ext_adv_params_mgmt_rsp_valid),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data adv_params_success_50 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_EXT_ADV_PARAMS,
	.send_param = ext_adv_params_valid,
	.send_len = sizeof(ext_adv_params_valid),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_adv_params_mgmt_rsp_valid_50,
	.expect_len = sizeof(ext_adv_params_mgmt_rsp_valid_50),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = ext_adv_hci_params_valid,
	.expect_hci_len = sizeof(ext_adv_hci_params_valid),
};

static const struct generic_data adv_data_fail_no_params = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_EXT_ADV_DATA,
	.send_param = ext_adv_data_valid,
	.send_len = sizeof(ext_adv_data_valid),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data adv_data_success = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_EXT_ADV_DATA,
	.send_param = ext_adv_data_valid,
	.send_len = sizeof(ext_adv_data_valid),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_adv_data_mgmt_rsp_valid,
	.expect_len = sizeof(ext_adv_data_mgmt_rsp_valid),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = ext_adv_hci_ad_data_valid,
	.expect_hci_len = sizeof(ext_adv_hci_ad_data_valid),
};

static const struct generic_data adv_scan_rsp_success = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_EXT_ADV_DATA,
	.send_param = ext_adv_data_valid,
	.send_len = sizeof(ext_adv_data_valid),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_adv_data_mgmt_rsp_valid,
	.expect_len = sizeof(ext_adv_data_mgmt_rsp_valid),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA,
	.expect_hci_param = ext_adv_hci_scan_rsp_data_valid,
	.expect_hci_len = sizeof(ext_adv_hci_scan_rsp_data_valid),
};

static const struct generic_data adv_data_invalid_params = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_EXT_ADV_DATA,
	.send_param = ext_adv_data_invalid,
	.send_len = sizeof(ext_adv_data_invalid),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t set_dev_id_param_success_1[] = {
	0x01, /* Source - 0x0001 (Bluetooth SIG) */
	0x00,
	0x02, /* Vendor */
	0x00,
	0xcd, /* Product */
	0xab,
	0x34,
	0x12, /* Version */
};

static const char write_eir_set_dev_id_success_1[241] = {
			0x00, 0x02, 0x0a, 0x00, 0x09, 0x10, 0x01, 0x00,
			0x02, 0x00, 0xcd, 0xab, 0x34, 0x12 };

static const struct generic_data set_dev_id_success_1 = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_SET_DEVICE_ID,
	.send_param = set_dev_id_param_success_1,
	.send_len = sizeof(set_dev_id_param_success_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_set_dev_id_success_1,
	.expect_hci_len = sizeof(write_eir_set_dev_id_success_1),
};

static const uint8_t set_dev_id_param_success_2[] = {
	0x02, /* Source - 0x0001 (Bluetooth SIG) */
	0x00,
	0x02, /* Vendor */
	0x00,
	0xcd, /* Product */
	0xab,
	0x34,
	0x12, /* Version */
};
static const char write_eir_set_dev_id_success_2[241] = {
			0x00, 0x02, 0x0a, 0x00, 0x09, 0x10, 0x02, 0x00,
			0x02, 0x00, 0xcd, 0xab, 0x34, 0x12 };

static const struct generic_data set_dev_id_success_2 = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_SET_DEVICE_ID,
	.send_param = set_dev_id_param_success_2,
	.send_len = sizeof(set_dev_id_param_success_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_set_dev_id_success_2,
	.expect_hci_len = sizeof(write_eir_set_dev_id_success_2),
};

static const uint8_t set_dev_id_param_disable[8] = { 0x00 };

static const struct generic_data set_dev_id_disable = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_SET_DEVICE_ID,
	.send_param = set_dev_id_param_disable,
	.send_len = sizeof(set_dev_id_param_disable),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data set_dev_id_power_off_on = {
	.setup_settings = settings_ssp,
	.setup_send_opcode = MGMT_OP_SET_DEVICE_ID,
	.setup_send_param = set_dev_id_param_success_1,
	.setup_send_len = sizeof(set_dev_id_param_success_1),
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_2,
	.expect_len = sizeof(set_ssp_settings_param_2),
	.expect_settings_set = MGMT_SETTING_POWERED,
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_set_dev_id_success_1,
	.expect_hci_len = sizeof(write_eir_set_dev_id_success_1),
};

static const struct generic_data set_dev_id_ssp_off_on = {
	.setup_settings = settings_powered,
	.setup_send_opcode = MGMT_OP_SET_DEVICE_ID,
	.setup_send_param = set_dev_id_param_success_1,
	.setup_send_len = sizeof(set_dev_id_param_success_1),
	.send_opcode = MGMT_OP_SET_SSP,
	.send_param = set_ssp_on_param,
	.send_len = sizeof(set_ssp_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ssp_settings_param_2,
	.expect_len = sizeof(set_ssp_settings_param_2),
	.expect_hci_command = BT_HCI_CMD_WRITE_EXT_INQUIRY_RESPONSE,
	.expect_hci_param = write_eir_set_dev_id_success_1,
	.expect_hci_len = sizeof(write_eir_set_dev_id_success_1),
};

static const uint8_t set_dev_id_invalid_1[] = {
	0x03, /* Source */
	0x00,
	0x02, /* Vendor */
	0x00,
	0xcd, /* Product */
	0xab,
	0x34,
	0x12, /* Version */
};

static const struct generic_data set_dev_id_invalid_param = {
	.setup_settings = settings_powered_ssp,
	.send_opcode = MGMT_OP_SET_DEVICE_ID,
	.send_param = set_dev_id_invalid_1,
	.send_len = sizeof(set_dev_id_invalid_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static void client_cmd_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bthost *bthost;

	bthost = hciemu_client_get_host(data->hciemu);

	switch (opcode) {
	case BT_HCI_CMD_WRITE_SCAN_ENABLE:
	case BT_HCI_CMD_LE_SET_ADV_ENABLE:
	case BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE:
		tester_print("Client set connectable: %s (0x%02x)",
						mgmt_errstr(status), status);
		if (!status && test->client_enable_ssp) {
			bthost_write_ssp_mode(bthost, 0x01);
			return;
		}
		break;
	case BT_HCI_CMD_WRITE_SIMPLE_PAIRING_MODE:
		tester_print("Client enable SSP: %s (0x%02x)",
						mgmt_errstr(status), status);
		break;
	default:
		return;
	}

	if (status)
		tester_setup_failed();
	else
		test_setup_condition_complete(data);
}

static void setup_bthost(void)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bthost *bthost;

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_cmd_complete_cb(bthost, client_cmd_complete, data);
	test_add_setup_condition(data);

	if (data->hciemu_type == HCIEMU_TYPE_LE ||
		test->client_enable_adv) {
		if (data->hciemu_type >= HCIEMU_TYPE_BREDRLE50) {
			bthost_set_ext_adv_params(bthost, 0x00);
			bthost_set_ext_adv_enable(bthost, 0x01);
		} else
			bthost_set_adv_enable(bthost, 0x01);
	} else
		bthost_write_scan_enable(bthost, 0x03);
}

static void setup_pairing_acceptor(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (!test->io_cap)
		return;

	mgmt_send(data->mgmt, MGMT_OP_SET_IO_CAPABILITY, data->mgmt_index,
					sizeof(test->io_cap), &test->io_cap,
					NULL, NULL, NULL);

	setup_bthost();
}

/* Generic callback for checking the mgmt event status
 */
static void generic_mgmt_status_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	bool bthost = PTR_TO_INT(user_data);

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	if (bthost)
		setup_bthost();
}


static void setup_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	setup_bthost();
}

static void setup_class(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char class_param[] = { 0x01, 0x0c };

	tester_print("Setting device class and powering on");

	mgmt_send(data->mgmt, MGMT_OP_SET_DEV_CLASS, data->mgmt_index,
				sizeof(class_param), class_param,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void discovering_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_ev_discovering *ev = param;

	mgmt_unregister(data->mgmt, data->mgmt_discov_ev_id);

	if (length != sizeof(*ev)) {
		tester_warn("Incorrect discovering event length");
		tester_setup_failed();
		return;
	}

	if (!ev->discovering) {
		tester_warn("Unexpected discovery stopped event");
		tester_setup_failed();
		return;
	}

	tester_setup_complete();
}

static void setup_discovery_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Discovery started");
}

static void setup_start_discovery(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const void *send_param = test->setup_send_param;
	uint16_t send_len = test->setup_send_len;
	unsigned int id;

	id = mgmt_register(data->mgmt, MGMT_EV_DISCOVERING, data->mgmt_index,
			   discovering_event, NULL, NULL);
	data->mgmt_discov_ev_id = id;

	mgmt_send(data->mgmt, test->setup_send_opcode, data->mgmt_index,
				send_len, send_param, setup_discovery_callback,
				NULL, NULL);
}

static void setup_multi_uuid32(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with 32-bit UUID)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_1), add_uuid32_param_1,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_2), add_uuid32_param_2,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_3), add_uuid32_param_3,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid32_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00 };
	int i;

	tester_print("Powering on controller (with many 32-bit UUIDs)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	for (i = 0; i < 58; i++) {
		uint32_t val = htobl(0xffffffff - i);
		memcpy(&uuid_param[12], &val, sizeof(val));
		mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(uuid_param), uuid_param,
				NULL, NULL, NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid128(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with 128-bit UUID)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
			sizeof(add_uuid128_param_1), add_uuid128_param_1,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid128_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char uuid_param[] = {
			0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
			0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
			0x00 };
	int i;

	tester_print("Powering on controller (with many 128-bit UUIDs)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	for (i = 0; i < 13; i++) {
		uuid_param[15] = i;
		mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(uuid_param), uuid_param,
				NULL, NULL, NULL);
	}

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
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_dun_uuid_param), add_dun_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
			sizeof(add_sync_uuid_param), add_sync_uuid_param,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_multi_uuid16_power_off(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Adding UUIDs without powering on");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_spp_uuid_param), add_spp_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_dun_uuid_param), add_dun_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
			sizeof(add_sync_uuid_param), add_sync_uuid_param,
			NULL, NULL, NULL);

	setup_bthost();
}

static void setup_multi_uuid16_power_off_remove(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Adding UUIDs without powering on and remove UUID");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_spp_uuid_param), add_spp_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_dun_uuid_param), add_dun_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
			sizeof(add_sync_uuid_param), add_sync_uuid_param,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_REMOVE_UUID, data->mgmt_index,
			sizeof(remove_dun_uuid_param), remove_dun_uuid_param,
			NULL, NULL, NULL);

	setup_bthost();
}

static void setup_multi_uuid16_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	unsigned char uuid_param[] = {
			0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00 };
	int i;

	tester_print("Powering on controller (with many 16-bit UUIDs)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	for (i = 0; i < 117; i++) {
		uint16_t val = htobs(i + 0x2000);
		memcpy(&uuid_param[12], &val, sizeof(val));
		mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(uuid_param), uuid_param,
				NULL, NULL, NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_uuid_mix(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller (with mixed UUIDs)");

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_spp_uuid_param), add_spp_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_1), add_uuid32_param_1,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
			sizeof(add_uuid128_param_1), add_uuid128_param_1,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_dun_uuid_param), add_dun_uuid_param,
				NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_ADD_UUID, data->mgmt_index,
				sizeof(add_uuid32_param_2), add_uuid32_param_2,
				NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_load_ltks_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Loaded Long Term Key");
}

static void setup_load_ltks_20_by_1(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_load_long_term_keys *cp;
	struct mgmt_ltk_info *info;
	unsigned char param[sizeof(*cp) + sizeof(*info)] = { 0x00 };
	unsigned char param_on[] = { 0x01 };
	int i;

	cp = (struct mgmt_cp_load_long_term_keys *)param;
	cp->key_count = 1;

	info = (struct mgmt_ltk_info *)cp->keys;
	info->addr.type = 0x01;		/* LE Public */

	for (i = 0; i < 20; i++) {
		/* Update BDADDR */
		info->addr.bdaddr.b[0] = i + 1;

		mgmt_send(data->mgmt, MGMT_OP_LOAD_LONG_TERM_KEYS,
			  data->mgmt_index, sizeof(param), param,
			  setup_load_ltks_callback, NULL, NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param_on), param_on,
					setup_powered_callback, NULL, NULL);
}

static void setup_add_device(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	const unsigned char *add_param;
	size_t add_param_len;

	tester_print("Powering on controller (with added device)");

	if (data->hciemu_type == HCIEMU_TYPE_LE) {
		add_param = add_device_success_param_2;
		add_param_len = sizeof(add_device_success_param_2);
	} else {
		add_param = add_device_success_param_1;
		add_param_len = sizeof(add_device_success_param_1);
	}

	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
			add_param_len, add_param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_add_advertising_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct mgmt_rp_add_advertising *rp =
				(struct mgmt_rp_add_advertising *) param;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Add Advertising setup complete (instance %d)",
								rp->instance);

	setup_bthost();
}

#define TESTER_ADD_ADV_DATA_LEN 7

static void setup_add_adv_param(struct mgmt_cp_add_advertising *cp,
							uint8_t instance)
{
	memset(cp, 0, sizeof(*cp));
	cp->instance = instance;
	cp->adv_data_len = TESTER_ADD_ADV_DATA_LEN;
	cp->data[0] = TESTER_ADD_ADV_DATA_LEN - 1; /* AD len */
	cp->data[1] = 0x08; /* AD type: shortened local name */
	cp->data[2] = 't';  /* adv data ... */
	cp->data[3] = 'e';
	cp->data[4] = 's';
	cp->data[5] = 't';
	cp->data[6] = '0' + instance;
}

static void setup_add_advertising_not_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding advertising instance while unpowered");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static void setup_add_advertising(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding advertising instance while powered");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static void setup_add_advertising_connectable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding advertising instance while connectable");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static int create_le_att_sock(struct test_data *data)
{
	struct sockaddr_l2 addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK,
							BTPROTO_L2CAP);
	if (sk < 0) {
		err = -errno;
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	addr.l2_psm = 0;
	addr.l2_cid = htobs(0x0004);
	addr.l2_bdaddr_type = BDADDR_LE_PUBLIC;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		tester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(sk);
		return err;
	}

	if (listen(sk, 1) < 0) {
		err = -errno;
		tester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(sk);
		return err;
	}

	data->sk = sk;

	return sk;
}

static void setup_advertise_while_connected(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	uint8_t adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];

	tester_print("Adding advertising instances");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	cp->flags |= MGMT_ADV_FLAG_CONNECTABLE;
	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						NULL, NULL, NULL);

	cp->flags &= ~MGMT_ADV_FLAG_CONNECTABLE;
	cp->instance = 2;

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);

	/* Listen on the socket so Kernel does not drop connection just after
	 * connect. Socket is closed in test_post_teardown
	 */
	if (create_le_att_sock(data) < 0)
		tester_test_failed();
}

static void setup_add_advertising_timeout(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding advertising instance with timeout");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);
	cp->timeout = 1;

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static void setup_add_advertising_duration(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding instance with long timeout/short duration");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);
	cp->duration = 1;
	cp->timeout = 30;

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static void setup_power_cycle_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param_off[] = { 0x00 };

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param_off), &param_off,
						NULL, NULL, NULL);

	setup_bthost();
}

static void setup_add_advertising_power_cycle(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param_on[] = { 0x01 };

	tester_print("Adding instance without timeout and power cycle");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param_on), &param_on,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param_on), &param_on,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_power_cycle_callback,
						NULL, NULL);
}

static void setup_set_and_add_advertising(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Set and add advertising instance");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_ADVERTISING, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static void setup_multi_adv_second_instance(uint8_t status, uint16_t length,
		const void *param, void *user_data) {
	struct mgmt_rp_add_advertising *rp =
				(struct mgmt_rp_add_advertising *) param;
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Add Advertising setup complete (instance %d)",
								rp->instance);

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 2);
	cp->timeout = 1;
	cp->duration = 1;

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static void setup_multi_adv(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding two instances with timeout 1 and duration 1");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);
	cp->timeout = 1;
	cp->duration = 1;

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_multi_adv_second_instance,
						NULL, NULL);
}

static void setup_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Initial settings completed");

	if (data->test_setup)
		data->test_setup(data);
	else
		setup_bthost();
}

static void setup_set_unpowered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	setup_bthost();
}

static void setup_set_le_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	unsigned char power_param[] = { 0x00 };

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Disabling power");

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(power_param),
						&power_param,
						setup_set_unpowered_callback,
						NULL, NULL);
}

static void setup_ext_adv_not_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Enabling LE");

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						setup_set_le_callback,
						NULL, NULL);
}

static void setup_set_ext_adv_params_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	setup_bthost();
}

static void setup_ext_adv_params(const void *test_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Setting Extended Adv Params");

	mgmt_send(data->mgmt, MGMT_OP_ADD_EXT_ADV_PARAMS, data->mgmt_index,
					sizeof(ext_adv_params_valid),
					&ext_adv_params_valid,
					setup_set_ext_adv_params_callback,
					NULL, NULL);
}

static const uint8_t hci_set_ext_adv_data_name[] = {
	0x01, /* Handle */
	0x03, /* Operation */
	0x01, /* Complete name */
	0x06, 0x05, 0x08, 0x74, 0x65, 0x73, 0x74
};

static const struct generic_data add_ext_adv_scan_resp_off_on = {
	.send_opcode = MGMT_OP_ADD_EXT_ADV_DATA,
	.send_param = ext_adv_data_valid,
	.send_len = sizeof(ext_adv_data_valid),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = ext_adv_data_mgmt_rsp_valid,
	.expect_len = sizeof(ext_adv_data_mgmt_rsp_valid),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA,
	.expect_hci_param = hci_set_ext_adv_data_name,
	.expect_hci_len = sizeof(hci_set_ext_adv_data_name),
};

static void setup_add_ext_adv_on_off(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	int enable_bthost = 1;

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
					sizeof(param), &param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), &param,
					generic_mgmt_status_callback,
					NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_EXT_ADV_PARAMS, data->mgmt_index,
					sizeof(ext_adv_params_valid),
					&ext_adv_params_valid,
					generic_mgmt_status_callback,
					NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_EXT_ADV_DATA, data->mgmt_index,
					sizeof(ext_adv_data_valid),
					&ext_adv_data_valid,
					generic_mgmt_status_callback,
					NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_REMOVE_ADVERTISING, data->mgmt_index,
					sizeof(remove_advertising_param_1),
					&remove_advertising_param_1,
					generic_mgmt_status_callback,
					NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_EXT_ADV_PARAMS, data->mgmt_index,
					sizeof(ext_adv_params_valid),
					&ext_adv_params_valid,
					generic_mgmt_status_callback,
					INT_TO_PTR(enable_bthost), NULL);

}

static void pin_code_request_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_ev_pin_code_request *ev = param;
	struct test_data *data = user_data;
	const struct generic_data *test = data->test_data;
	struct mgmt_cp_pin_code_reply cp;

	test_condition_complete(data);

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, &ev->addr, sizeof(cp.addr));

	if (!test->pin) {
		mgmt_reply(data->mgmt, MGMT_OP_PIN_CODE_NEG_REPLY,
				data->mgmt_index, sizeof(cp.addr), &cp.addr,
				NULL, NULL, NULL);
		return;
	}

	cp.pin_len = test->pin_len;
	memcpy(cp.pin_code, test->pin, test->pin_len);

	mgmt_reply(data->mgmt, MGMT_OP_PIN_CODE_REPLY, data->mgmt_index,
			sizeof(cp), &cp, NULL, NULL, NULL);
}

static void user_confirm_request_callback(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	const struct mgmt_ev_user_confirm_request *ev = param;
	struct test_data *data = user_data;
	const struct generic_data *test = data->test_data;
	struct mgmt_cp_user_confirm_reply cp;
	uint16_t opcode;

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, &ev->addr, sizeof(cp.addr));

	if (test->reject_confirm)
		opcode = MGMT_OP_USER_CONFIRM_NEG_REPLY;
	else
		opcode = MGMT_OP_USER_CONFIRM_REPLY;

	mgmt_reply(data->mgmt, opcode, data->mgmt_index, sizeof(cp), &cp,
							NULL, NULL, NULL);
}

static void user_passkey_request_callback(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	const struct mgmt_ev_user_passkey_request *ev = param;
	struct test_data *data = user_data;
	const struct generic_data *test = data->test_data;
	struct mgmt_cp_user_passkey_reply cp;

	if (test->just_works) {
		tester_warn("User Passkey Request for just-works case");
		tester_test_failed();
		return;
	}

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr, &ev->addr, sizeof(cp.addr));

	if (test->reject_confirm) {
		mgmt_reply(data->mgmt, MGMT_OP_USER_PASSKEY_NEG_REPLY,
				data->mgmt_index, sizeof(cp.addr), &cp.addr,
				NULL, NULL, NULL);
		return;
	}

	mgmt_reply(data->mgmt, MGMT_OP_USER_PASSKEY_REPLY, data->mgmt_index,
					sizeof(cp), &cp, NULL, NULL, NULL);
}

static void test_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	const uint16_t *cmd;

	if (!test)
		goto proceed;

	if (test->pin || test->expect_pin) {
		mgmt_register(data->mgmt, MGMT_EV_PIN_CODE_REQUEST,
				data->mgmt_index, pin_code_request_callback,
				data, NULL);
		test_add_condition(data);
	}

	mgmt_register(data->mgmt, MGMT_EV_USER_CONFIRM_REQUEST,
			data->mgmt_index, user_confirm_request_callback,
			data, NULL);

	mgmt_register(data->mgmt, MGMT_EV_USER_PASSKEY_REQUEST,
			data->mgmt_index, user_passkey_request_callback,
			data, NULL);

	if (test->client_pin)
		bthost_set_pin_code(bthost, test->client_pin,
							test->client_pin_len);

	if (test->client_io_cap)
		bthost_set_io_capability(bthost, test->client_io_cap);

	if (test->client_auth_req)
		bthost_set_auth_req(bthost, test->client_auth_req);
	else if (!test->just_works)
		bthost_set_auth_req(bthost, 0x01);

	if (test->client_reject_confirm)
		bthost_set_reject_user_confirm(bthost, true);

	if (test->client_enable_le)
		bthost_write_le_host_supported(bthost, 0x01);

	if (test->client_enable_sc)
		bthost_set_sc_support(bthost, 0x01);

proceed:
	if (!test || !test->setup_settings) {
		if (data->test_setup)
			data->test_setup(data);
		else
			tester_setup_complete();
		return;
	}

	for (cmd = test->setup_settings; *cmd; cmd++) {
		unsigned char simple_param[] = { 0x01 };
		unsigned char discov_param[] = { 0x01, 0x00, 0x00 };
		unsigned char privacy_param[] = { 0x01,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
		unsigned char set_exp_feat_param[17] = { 0x00 };
		unsigned char *param = simple_param;
		size_t param_size = sizeof(simple_param);
		mgmt_request_func_t func = NULL;

		/* If this is the last command (next one is 0) request
		 * for a callback. */
		if (!cmd[1])
			func = setup_complete;

		if (*cmd == MGMT_OP_SET_DISCOVERABLE) {
			if (test->setup_limited_discov) {
				discov_param[0] = 0x02;
				discov_param[1] = 0x01;
			}
			param_size = sizeof(discov_param);
			param = discov_param;
		}

		if (*cmd == MGMT_OP_SET_PRIVACY) {
			param_size = sizeof(privacy_param);
			param = privacy_param;
		}

		if (*cmd == MGMT_OP_START_DISCOVERY) {
			if (test->setup_discovery_param)
				memcpy(param, test->setup_discovery_param, 1);
		}

		if (*cmd == MGMT_OP_SET_EXP_FEATURE) {
			if (test->setup_exp_feat_param) {
				memcpy(set_exp_feat_param,
				       test->setup_exp_feat_param, 17);
				param_size = sizeof(set_exp_feat_param);
				param = set_exp_feat_param;
			}
		}

		if (*cmd == MGMT_OP_SET_LE && test->setup_nobredr) {
			unsigned char off[] = { 0x00 };
			tester_print("Setup sending %s (0x%04x)",
							mgmt_opstr(*cmd), *cmd);
			mgmt_send(data->mgmt, *cmd, data->mgmt_index,
					param_size, param, NULL, NULL, NULL);
			tester_print("Setup sending %s (0x%04x)",
					mgmt_opstr(MGMT_OP_SET_BREDR),
					MGMT_OP_SET_BREDR);
			mgmt_send(data->mgmt, MGMT_OP_SET_BREDR,
					data->mgmt_index, sizeof(off), off,
					func, data, NULL);
		} else {
			tester_print("Setup sending %s (0x%04x)",
							mgmt_opstr(*cmd), *cmd);
			mgmt_send(data->mgmt, *cmd, data->mgmt_index,
					param_size, param, func, data, NULL);
		}
	}
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

	settings = get_le32(param);

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

static bool verify_alt_ev(const void *param, uint16_t length)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;

	if (length != test->expect_alt_ev_len) {
		tester_warn("Invalid length %u != %u", length,
						test->expect_alt_ev_len);
		return false;
	}

	if (test->expect_alt_ev_param &&
			memcmp(test->expect_alt_ev_param, param, length)) {
		tester_warn("Event parameters do not match");
		util_hexdump('>', param, length, print_debug, "");
		util_hexdump('!', test->expect_alt_ev_param, length,
							print_debug, "");
		return false;
	}

	return true;
}

static void command_generic_event_alt(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	bool (*verify)(const void *param, uint16_t length);

	tester_print("New %s event received", mgmt_evstr(test->expect_alt_ev));

	mgmt_unregister(data->mgmt_alt, data->mgmt_alt_ev_id);

	if (test->verify_alt_ev_func)
		verify = test->verify_alt_ev_func;
	else
		verify = verify_alt_ev;

	if (!verify(param, length)) {
		tester_warn("Incorrect %s event parameters",
					mgmt_evstr(test->expect_alt_ev));
		tester_test_failed();
		return;
	}

	test_condition_complete(data);
}

static void command_generic_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const void *expect_param = test->expect_param;
	uint16_t expect_len = test->expect_len;

	tester_print("%s (0x%04x): %s (0x%02x)", mgmt_opstr(test->send_opcode),
			test->send_opcode, mgmt_errstr(status), status);

	if (status != test->expect_status) {
		if (!test->fail_tolerant || !!status != !!test->expect_status) {
			tester_test_abort();
			return;
		}

		tester_warn("Unexpected status got %d expected %d",
						status, test->expect_status);
	}

	if (!test->expect_ignore_param) {
		if (test->expect_func)
			expect_param = test->expect_func(&expect_len);

		if (length != expect_len) {
			tester_warn("Invalid cmd response parameter size %d %d",
					length, expect_len);
			tester_test_failed();
			return;
		}

		if (expect_param && expect_len > 0 &&
					memcmp(param, expect_param, length)) {
			tester_warn("Unexpected cmd response parameter value");
			util_hexdump('>', param, length, print_debug, "");
			util_hexdump('!', expect_param, length, print_debug,
								"");
			tester_test_failed();
			return;
		}
	}

	test_condition_complete(data);
}

static void command_setup_hci_callback(uint16_t opcode, const void *param,
					uint8_t length, void *user_data)
{
	struct test_data *data = user_data;
	const struct generic_data *test = data->test_data;
	const void *setup_expect_hci_param = test->setup_expect_hci_param;
	uint8_t setup_expect_hci_len = test->setup_expect_hci_len;

	tester_print("HCI Command 0x%04x length %u", opcode, length);

	if (opcode != test->setup_expect_hci_command)
		return;

	if (length != setup_expect_hci_len) {
		tester_warn("Invalid parameter size for HCI command");
		tester_test_failed();
		return;
	}

	if (memcmp(param, setup_expect_hci_param, length) != 0) {
		tester_warn("Unexpected HCI command parameter value");
		tester_test_failed();
		return;
	}

	hciemu_clear_central_post_command_hooks(data->hciemu);
	test_setup_condition_complete(data);
}

static void command_hci_callback(uint16_t opcode, const void *param,
					uint8_t length, void *user_data)
{
	struct test_data *data = user_data;
	const struct generic_data *test = data->test_data;
	const void *expect_hci_param = test->expect_hci_param;
	uint8_t expect_hci_len = test->expect_hci_len;
	int ret;

	tester_print("HCI Command 0x%04x length %u", opcode, length);

	if (opcode != test->expect_hci_command || data->expect_hci_command_done)
		return;

	data->expect_hci_command_done = true;

	if (test->expect_hci_func)
		expect_hci_param = test->expect_hci_func(&expect_hci_len);

	if (length != expect_hci_len) {
		tester_warn("Invalid parameter size for HCI command");
		tester_test_failed();
		return;
	}

	if (test->expect_hci_param_check_func)
		ret = test->expect_hci_param_check_func(param, length);
	else
		ret = memcmp(param, expect_hci_param, length);
	if (ret != 0) {
		tester_warn("Unexpected HCI command parameter value:");
		util_hexdump('>', param, length, print_debug, "");
		util_hexdump('!', expect_hci_param, length, print_debug, "");
		tester_test_failed();
		return;
	}

	test_condition_complete(data);
}

static bool match_hci_cmd_opcode(const void *data, const void *match_data)
{
	const struct hci_entry *entry = data;
	uint16_t opcode = PTR_TO_UINT(match_data);

	return entry->cmd_data->opcode == opcode;
}

static void command_hci_list_callback(uint16_t opcode, const void *param,
					uint8_t length, void *user_data)
{
	struct test_data *data = user_data;
	const struct hci_cmd_data *hci_cmd_data;
	struct hci_entry *entry;
	int ret;

	tester_print("HCI Command 0x%04x length %u", opcode, length);

	entry = queue_find(data->expect_hci_q, match_hci_cmd_opcode,
							UINT_TO_PTR(opcode));
	if (!entry)
		return;

	/* Save the hci cmd data before removing the queue entry */
	hci_cmd_data = entry->cmd_data;

	/* Remove the entry from the queue and free the entry */
	queue_remove(data->expect_hci_q, entry);
	free(entry);

	if (length != hci_cmd_data->len) {
		tester_warn("Invalid parameter size for HCI command");
		tester_test_failed();
		return;
	}

	ret = memcmp(param, hci_cmd_data->param, length);
	if (ret != 0) {
		tester_warn("Unexpected HCI command parameter value:");
		util_hexdump('>', param, length, print_debug, "");
		util_hexdump('!', hci_cmd_data->param, length, print_debug, "");
		tester_test_failed();
		return;
	}

	test_condition_complete(data);
}

static void setup_mgmt_cmd_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}
	test_setup_condition_complete(user_data);
}

static void setup_command_generic(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const void *send_param = test->setup_send_param;
	uint16_t send_len = test->setup_send_len;
	size_t i;

	if (test->setup_expect_hci_command) {
		tester_print("Registering setup expected HCI command callback");
		tester_print("Setup expected HCI command 0x%04x",
					 test->setup_expect_hci_command);
		hciemu_add_central_post_command_hook(data->hciemu,
					command_setup_hci_callback, data);
		test_add_setup_condition(data);
	}

	if (test->setup_send_opcode) {
		tester_print("Setup sending %s (0x%04x)",
				mgmt_opstr(test->setup_send_opcode),
				test->setup_send_opcode);
		mgmt_send(data->mgmt, test->setup_send_opcode, data->mgmt_index,
					send_len, send_param,
					setup_mgmt_cmd_callback,
					data, NULL);
		test_add_setup_condition(data);
		return;
	}

	tester_print("Sending setup opcode array");
	for (i = 0; i < test->setup_mgmt_cmd_arr_size; ++i) {
		const struct setup_mgmt_cmd *cmd = &test->setup_mgmt_cmd_arr[i];

		tester_print("Setup sending %s (0x%04x)",
				mgmt_opstr(cmd->send_opcode),
				cmd->send_opcode);

		mgmt_send(data->mgmt, cmd->send_opcode, data->mgmt_index,
				cmd->send_len, cmd->send_param,
				setup_mgmt_cmd_callback,
				data, NULL);
		test_add_setup_condition(data);
	}
}

static const uint8_t add_advertising_param_empty[] = {
	0x01,			/* adv instance */
	0x00, 0x00, 0x00, 0x00,	/* flags: none */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x00,			/* scan rsp len */
};

static const struct generic_data add_advertising_empty_scrsp = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = set_local_name_param,
	.setup_send_len = sizeof(set_local_name_param),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_empty,
	.send_len = sizeof(add_advertising_param_empty),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
};

static const uint8_t add_advertising_param_scrsp_data_only_ok[] = {
	0x01,			/* adv instance */
	0x00, 0x00, 0x00, 0x00,	/* flags: none */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x1f,			/* scan rsp len */
	/* adv data: */
	/* scan rsp data: */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00,
};

static const struct generic_data add_advertising_scrsp_data_only_ok = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_data_only_ok,
	.send_len = sizeof(add_advertising_param_scrsp_data_only_ok),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
};

static const uint8_t add_advertising_param_scrsp_data_only_too_long[] = {
	0x01,			/* adv instance */
	0x00, 0x00, 0x00, 0x00,	/* flags: none */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x20,			/* scan rsp len */
	/* adv data: */
	/* scan rsp data: */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
};

static const struct generic_data add_advertising_scrsp_data_only_too_long = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_data_only_too_long,
	.send_len = sizeof(add_advertising_param_scrsp_data_only_too_long),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = NULL,
	.expect_len = 0,
};

static const uint8_t set_appearance_param[2] = { 0x54, 0x65 };

static const uint8_t add_advertising_param_scrsp_appear_data_ok[] = {
	0x01,			/* adv instance */
	0x20, 0x00, 0x00, 0x00,	/* flags: appearance */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x1b,			/* scan rsp len */
	/* adv data: */
	/* scan rsp data: */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct generic_data add_advertising_scrsp_appear_data_ok = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_APPEARANCE,
	.setup_send_param = set_appearance_param,
	.setup_send_len = sizeof(set_appearance_param),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_appear_data_ok,
	.send_len = sizeof(add_advertising_param_scrsp_appear_data_ok),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
};

static const uint8_t add_advertising_param_scrsp_appear_data_too_long[] = {
	0x01,			/* adv instance */
	0x20, 0x00, 0x00, 0x00,	/* flags: appearance */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x1c,			/* scan rsp len */
	/* adv data: */
	/* scan rsp data: */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct generic_data add_advertising_scrsp_appear_data_too_long = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_APPEARANCE,
	.setup_send_param = set_appearance_param,
	.setup_send_len = sizeof(set_appearance_param),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_appear_data_too_long,
	.send_len = sizeof(add_advertising_param_scrsp_appear_data_too_long),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = NULL,
	.expect_len = 0,
};

static const uint8_t add_advertising_param_scrsp_appear_null[] = {
	0x01,			/* adv instance */
	0x20, 0x00, 0x00, 0x00,	/* flags: appearance */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x01,			/* scan rsp len */
	/* adv data: */
	/* scan rsp data: */
	0x00,
};

static const struct generic_data add_advertising_scrsp_appear_null = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_appear_null,
	.send_len = sizeof(add_advertising_param_scrsp_appear_null),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
};

static const uint8_t add_advertising_empty_param[] = {
	0x01,			/* adv instance */
	0x40, 0x00, 0x00, 0x00,	/* flags: local name*/
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x01,			/* scan rsp len */
	/* scan rsp data: */
	0x00,
};

static const uint8_t scan_rsp_data_empty[] = {
	0x01, /* scan rsp data len */
	0x00, /* scan rsp data */
	/* placeholder data */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct generic_data add_advertising_no_name_set = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_empty_param,
	.send_len = sizeof(add_advertising_empty_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = scan_rsp_data_empty,
	.expect_hci_len = sizeof(scan_rsp_data_empty),
};

static const uint8_t add_advertising_param_name[] = {
	0x01,			/* adv instance */
	0x40, 0x00, 0x00, 0x00,	/* flags: Add local name to scan_rsp */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x00,			/* scan rsp len */
};

static const uint8_t set_scan_rsp_data_name_fits_in_scrsp[] = {
	0x0b, /* Scan rsp data len */
	0x0a, /* Local name data len */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, /* "Test name" */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct generic_data add_advertising_name_fits_in_scrsp = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_cp,
	.setup_send_len = sizeof(set_local_name_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name,
	.send_len = sizeof(add_advertising_param_name),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_scan_rsp_data_name_fits_in_scrsp,
	.expect_hci_len = sizeof(set_scan_rsp_data_name_fits_in_scrsp),
};

static const uint8_t set_scan_rsp_data_shortened_name_fits[] = {
	0x0c, /* Scan rsp data len */
	0x0b, /* Local name data len */
	0x08, /* Short name */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x31,
	/* "Test name1" */
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct generic_data add_advertising_shortened_name_in_scrsp = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_longer_cp,
	.setup_send_len = sizeof(set_local_name_longer_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name,
	.send_len = sizeof(add_advertising_param_name),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_scan_rsp_data_shortened_name_fits,
	.expect_hci_len = sizeof(set_scan_rsp_data_shortened_name_fits),
};

static const uint8_t set_scan_rsp_data_short_name_fits[] = {
	0x06, /* Scan rsp data len */
	0x05, /* Local name data len */
	0x08, /* Short name */
	0x54, 0x65, 0x73, 0x74,
	/* "Test*/
	/* padding */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00,
};

static const struct generic_data add_advertising_short_name_in_scrsp = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_long_short_cp,
	.setup_send_len = sizeof(set_local_name_long_short_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name,
	.send_len = sizeof(add_advertising_param_name),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_scan_rsp_data_short_name_fits,
	.expect_hci_len = sizeof(set_scan_rsp_data_short_name_fits),
};

static const uint8_t add_advertising_param_name_data_ok[] = {
	0x01,			/* adv instance */
	0x40, 0x00, 0x00, 0x00,	/* flags: local name */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x12,			/* scan rsp len */
	/* adv data: */
	/* scan rsp data: */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t set_scan_rsp_data_param_name_data_ok[] = {
	0x1d, /* Scan rsp data len */
	/* scan rsp data */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0a, /* Local name data len */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65,
	/* "Test name" */
	/* padding */
	0x00, 0x00,
};

static const struct generic_data add_advertising_name_data_ok = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_cp,
	.setup_send_len = sizeof(set_local_name_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name_data_ok,
	.send_len = sizeof(add_advertising_param_name_data_ok),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_scan_rsp_data_param_name_data_ok,
	.expect_hci_len = sizeof(set_scan_rsp_data_param_name_data_ok),
};

static const uint8_t add_advertising_param_name_data_inv[] = {
	0x01,			/* adv instance */
	0x40, 0x00, 0x00, 0x00,	/* flags: local name */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x14,			/* scan rsp len */
	/* adv data: */
	/* scan rsp data: */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const struct generic_data add_advertising_name_data_inv = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_cp,
	.setup_send_len = sizeof(set_local_name_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name_data_inv,
	.send_len = sizeof(add_advertising_param_name_data_inv),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = NULL,
	.expect_len = 0,
};

static const uint8_t add_advertising_param_name_data_appear[] = {
	0x01,			/* adv instance */
	0x60, 0x00, 0x00, 0x00,	/* flags: local name + appearance */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x00,			/* adv data len */
	0x0e,			/* scan rsp len */
	/* adv data: */
	/* scan rsp data: */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static const struct setup_mgmt_cmd add_advertising_mgmt_cmd_arr[] = {
	{
		.send_opcode = MGMT_OP_SET_APPEARANCE,
		.send_param = set_appearance_param,
		.send_len = sizeof(set_appearance_param),
	},
	{
		.send_opcode = MGMT_OP_SET_LOCAL_NAME,
		.send_param = &set_local_name_cp,
		.send_len = sizeof(set_local_name_cp),
	}
};

static const uint8_t set_scan_rsp_data_name_data_appear[] = {
	0x1d, /* Scan rsp data len */
	0x03, /* appearance len */
	0x19, /* EIR_APPEARANCE */
	0x54, 0x65, /* appearance value */
	/* scan rsp data */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x0a, /* Local name data len */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65,
	/* "Test name" */
	/* padding */
	0x00, 0x00,
};

static const struct generic_data add_advertising_name_data_appear = {
	.setup_settings = settings_powered_le,
	.setup_mgmt_cmd_arr = add_advertising_mgmt_cmd_arr,
	.setup_mgmt_cmd_arr_size = ARRAY_SIZE(add_advertising_mgmt_cmd_arr),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name_data_appear,
	.send_len = sizeof(add_advertising_param_name_data_appear),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_SCAN_RSP_DATA,
	.expect_hci_param = set_scan_rsp_data_name_data_appear,
	.expect_hci_len = sizeof(set_scan_rsp_data_name_data_appear),
};

static const struct generic_data set_appearance_not_supported = {
	.send_opcode = MGMT_OP_SET_APPEARANCE,
	.send_param = set_appearance_param,
	.send_len = sizeof(set_appearance_param),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
	.expect_param = NULL,
	.expect_len = 0,
};

static const struct generic_data set_appearance_success = {
	.send_opcode = MGMT_OP_SET_APPEARANCE,
	.send_param = set_appearance_param,
	.send_len = sizeof(set_appearance_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = NULL,
	.expect_len = 0,
};

static const uint8_t read_adv_features_rsp_3[] =  {
	0xff, 0xff, 0x01, 0x00,	/* supported flags */
	0xfb,			/* max_adv_data_len */
	0xfb,			/* max_scan_rsp_len */
	0x03,			/* max_instances */
	0x00,			/* num_instances */
};

static const struct generic_data read_adv_features_success_3 = {
	.send_opcode = MGMT_OP_READ_ADV_FEATURES,
	.expect_param = read_adv_features_rsp_3,
	.expect_len = sizeof(read_adv_features_rsp_3),
	.expect_status = MGMT_STATUS_SUCCESS,
};

/* add advertising with multiple phy flags */
static const uint8_t add_ext_advertising_invalid_param_1[] = {
	0x01,			/* adv instance */
	0x80, 0x01, 0x00, 0x00,	/* flags: 1m and 2m*/
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

static const struct generic_data add_ext_advertising_fail_1 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_ext_advertising_invalid_param_1,
	.send_len = sizeof(add_ext_advertising_invalid_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

/* add advertising with multiple phy flags */
static const uint8_t add_ext_advertising_invalid_param_2[] = {
	0x01,			/* adv instance */
	0x00, 0x03, 0x00, 0x00,	/* flags: 2m and coded*/
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

static const struct generic_data add_ext_advertising_fail_2 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_ext_advertising_invalid_param_2,
	.send_len = sizeof(add_ext_advertising_invalid_param_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

/* add advertising with multiple phy flags */
static const uint8_t add_ext_advertising_invalid_param_3[] = {
	0x01,			/* adv instance */
	0x80, 0x02, 0x00, 0x00,	/* flags: 1m and coded*/
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

static const struct generic_data add_ext_advertising_fail_3 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_ext_advertising_invalid_param_3,
	.send_len = sizeof(add_ext_advertising_invalid_param_3),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

/* add advertising with multiple phy flags */
static const uint8_t add_ext_advertising_invalid_param_4[] = {
	0x01,			/* adv instance */
	0x80, 0x03, 0x00, 0x00,	/* flags: 1m, 2m and coded*/
	0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

static const struct generic_data add_ext_advertising_fail_4 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_ext_advertising_invalid_param_4,
	.send_len = sizeof(add_ext_advertising_invalid_param_4),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t set_ext_adv_data_uuid[] = {
	/* handle */
	0x01,
	/* complete data */
	0x03,
	/* controller should not fragment */
	0x01,
	/* adv data len */
	0x09,
	/* advertise heart rate monitor and manufacturer specific data */
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

static const struct generic_data add_ext_advertising_success_1 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_uuid,
	.expect_hci_len = sizeof(set_ext_adv_data_uuid),
};

static const uint8_t set_ext_adv_data_test1[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x07,				/* adv data len */
	0x06,				/* AD len */
	0x08,				/* AD type: shortened local name */
	0x74, 0x65, 0x73, 0x74, 0x31,	/* "test1" */
};

static const char set_powered_ext_adv_instance_settings_param[] = {
	0x81, 0x02, 0x40, 0x00,
};

static const struct generic_data add_ext_advertising_success_pwron_data = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_ext_adv_instance_settings_param,
	.expect_len = sizeof(set_powered_ext_adv_instance_settings_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_test1,
	.expect_hci_len = sizeof(set_ext_adv_data_test1),
};

static const char set_ext_adv_on_set_adv_enable_param[] = {
	0x01,		/* Enable */
	0x01,		/* No of sets */
	0x01,		/* Handle */
	0x00, 0x00,		/* Duration */
	0x00,		/* Max events */
};

static const struct generic_data add_ext_advertising_success_pwron_enabled = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_ext_adv_instance_settings_param,
	.expect_len = sizeof(set_powered_adv_instance_settings_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
	.expect_hci_param = set_ext_adv_on_set_adv_enable_param,
	.expect_hci_len = sizeof(set_ext_adv_on_set_adv_enable_param),
};

static const uint8_t set_ext_adv_data_txpwr[] = {
	0x00,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x03,			/* adv data len */
	0x02, 			/* AD len */
	0x0a,			/* AD type: tx power */
	0x00,			/* tx power */
};

static const char set_ext_adv_settings_param[] = { 0x81, 0x06, 0x40, 0x00 };

static const struct generic_data add_ext_advertising_success_4 = {
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param,
	.send_len = sizeof(set_adv_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_ext_adv_settings_param,
	.expect_len = sizeof(set_ext_adv_settings_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_txpwr,
	.expect_hci_len = sizeof(set_ext_adv_data_txpwr),
};

static const struct generic_data add_ext_advertising_success_5 = {
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_off_param,
	.send_len = sizeof(set_adv_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_ext_adv_instance_settings_param,
	.expect_len = sizeof(set_powered_ext_adv_instance_settings_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_test1,
	.expect_hci_len = sizeof(set_ext_adv_data_test1),
};

static const struct generic_data add_ext_advertising_success_6 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scanrsp,
	.send_len = sizeof(add_advertising_param_scanrsp),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_uuid,
	.expect_hci_len = sizeof(set_ext_adv_data_uuid),
};

static const uint8_t set_ext_scan_rsp_uuid[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x0a,			/* scan rsp data len */
	0x03,			/* AD len */
	0x19,			/* AD type: external appearance */
	0x40, 0x03,		/* some custom appearance */
	0x05,			/* AD len */
	0x03,			/* AD type: all 16 bit service class UUIDs */
	0x0d, 0x18, 0x0f, 0x18,	/* heart rate monitor, battery service */
};

static const struct generic_data add_ext_advertising_success_7 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scanrsp,
	.send_len = sizeof(add_advertising_param_scanrsp),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA,
	.expect_hci_param = set_ext_scan_rsp_uuid,
	.expect_hci_len = sizeof(set_ext_scan_rsp_uuid),
};

static uint8_t set_connectable_on_ext_adv_param[] = {
	0x01,					/* Handle */
	0x13, 0x00, 			/* Event type */
	0x00, 0x08, 0x00,		/* min_interval */
	0x00, 0x08, 0x00,		/* max_interval */
	0x07,					/* channel_map */
	0x00,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* peer_addr */
	0x00,					/* filter_policy */
	127,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_success_8 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_connectable,
	.send_len = sizeof(add_advertising_param_connectable),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_on_ext_adv_param,
	.expect_hci_len = sizeof(set_connectable_on_ext_adv_param),
};

static const uint8_t set_ext_adv_data_general_discov[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x0c,			/* adv data len */
	0x02,			/* AD len */
	0x01,			/* AD type: flags */
	0x02,			/* general discoverable */
	0x03,			/* AD len */
	0x02,			/* AD type: some 16bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x04,			/* AD len */
	0xff,			/* AD type: manufacturer specific data */
	0x01, 0x02, 0x03,	/* custom advertising data */
};

static const uint8_t set_ext_adv_data_limited_discov[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x0c,			/* adv data len */
	0x02,			/* AD len */
	0x01,			/* AD type: flags */
	0x01,			/* limited discoverable */
	/* rest: same as before */
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
};

static const uint8_t set_ext_adv_data_uuid_txpwr[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x0c,			/* adv data len */
	0x03,			/* AD len */
	0x02,			/* AD type: some 16bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x04,			/* AD len */
	0xff,			/* AD type: manufacturer specific data */
	0x01, 0x02, 0x03,	/* custom advertising data */
	0x02,			/* AD len */
	0x0a,			/* AD type: tx power */
	0x00,			/* tx power */
};

static const struct generic_data add_ext_advertising_success_9 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_general_discov,
	.send_len = sizeof(add_advertising_param_general_discov),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_general_discov,
	.expect_hci_len = sizeof(set_ext_adv_data_general_discov),
};

static const struct generic_data add_ext_advertising_success_10 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_limited_discov,
	.send_len = sizeof(add_advertising_param_limited_discov),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_limited_discov,
	.expect_hci_len = sizeof(set_ext_adv_data_limited_discov),
};

static const struct generic_data add_ext_advertising_success_11 = {
	.setup_settings = settings_powered_le_discoverable,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_managed,
	.send_len = sizeof(add_advertising_param_managed),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_general_discov,
	.expect_hci_len = sizeof(set_ext_adv_data_general_discov),
};

static const struct generic_data add_ext_advertising_success_12 = {
	.setup_settings = settings_powered_le_discoverable,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_txpwr,
	.send_len = sizeof(add_advertising_param_txpwr),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_uuid_txpwr,
	.expect_hci_len = sizeof(set_ext_adv_data_uuid_txpwr),
};

static uint8_t set_connectable_off_scan_ext_adv_param[] = {
	0x01,					/* Handle */
	0x12, 0x00,				/* Event type */
	0x00, 0x08, 0x00,		/* min_interval */
	0x00, 0x08,	0x00,		/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	127,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_success_13 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scanrsp,
	.send_len = sizeof(add_advertising_param_scanrsp),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_off_scan_ext_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_ext_adv_param),
};

static uint8_t set_connectable_off_ext_adv_param[] = {
	0x01,					/* Handle */
	0x10, 0x00, 			/* Event type */
	0x00, 0x08, 0x00,		/* min_interval */
	0x00, 0x08, 0x00,		/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* peer_addr */
	0x00,					/* filter_policy */
	127,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_success_14 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_off_ext_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_ext_adv_param),
};

static const struct generic_data add_ext_advertising_success_15 = {
	.setup_settings = settings_powered_le_connectable,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_on_ext_adv_param,
	.expect_hci_len = sizeof(set_connectable_on_ext_adv_param),
};

static uint8_t preset_connectable_on_ext_adv_param[] = {
	0x01,					/* Handle */
	0x13, 0x00,				/* Event type */
	0x00, 0x08, 0x00,			/* min_interval */
	0x00, 0x08, 0x00,			/* max_interval */
	0x07,					/* channel_map */
	0x00,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	0x00,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const char set_connectable_settings_param_4[] = {
						0x83, 0x02, 0x40, 0x00 };

static const struct generic_data add_ext_advertising_success_16 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_settings_param_4,
	.expect_len = sizeof(set_connectable_settings_param_4),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = preset_connectable_on_ext_adv_param,
	.expect_hci_len = sizeof(preset_connectable_on_ext_adv_param),
};

static uint8_t preset_connectable_off_ext_adv_param[] = {
	0x01,					/* Handle */
	0x10, 0x00,				/* Event type */
	0x00, 0x08, 0x00,			/* min_interval */
	0x00, 0x08, 0x00,			/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	0x00,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const char set_le_settings_param_3[] = { 0x81, 0x02, 0x40, 0x00 };

static const struct generic_data add_ext_advertising_success_17 = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_3,
	.expect_len = sizeof(set_le_settings_param_3),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = preset_connectable_off_ext_adv_param,
	.expect_hci_len = sizeof(preset_connectable_off_ext_adv_param),
};

static const struct generic_data add_ext_advertising_le_off = {
	.send_opcode = MGMT_OP_SET_LE,
	.send_param = set_le_off_param,
	.send_len = sizeof(set_le_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_off,
	.expect_len = sizeof(set_le_settings_param_off),
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
};

static const struct generic_data add_ext_advertising_success_18 = {
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_uuid,
	.send_len = sizeof(add_advertising_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_uuid,
	.expect_hci_len = sizeof(set_ext_adv_data_uuid),
};

static const char set_ext_adv_disable_param[] = {
	0x00, 0x00,
};

static const char set_ext_adv_disable_param_1[] = {
	0x00, 0x01, 0x01, 0x00, 0x00, 0x00
};

static const struct generic_data add_ext_advertising_timeout_expired = {
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
};

static const struct generic_data remove_ext_advertising_fail_1 = {
	.send_opcode = MGMT_OP_REMOVE_ADVERTISING,
	.send_param = remove_advertising_param_1,
	.send_len = sizeof(remove_advertising_param_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct generic_data remove_ext_advertising_success_1 = {
	.send_opcode = MGMT_OP_REMOVE_ADVERTISING,
	.send_param = remove_advertising_param_1,
	.send_len = sizeof(remove_advertising_param_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = remove_advertising_param_1,
	.expect_len = sizeof(remove_advertising_param_1),
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
	.expect_hci_param = set_ext_adv_disable_param_1,
	.expect_hci_len = sizeof(set_ext_adv_disable_param_1),
};

static const struct generic_data remove_ext_advertising_success_2 = {
	.send_opcode = MGMT_OP_REMOVE_ADVERTISING,
	.send_param = remove_advertising_param_2,
	.send_len = sizeof(remove_advertising_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = remove_advertising_param_2,
	.expect_len = sizeof(remove_advertising_param_2),
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
	.expect_hci_param = set_ext_adv_disable_param,
	.expect_hci_len = sizeof(set_ext_adv_disable_param),
};

static const uint8_t set_ext_adv_data_test2[] = {
	0x02,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x07,				/* adv data len */
	0x06,				/* AD len */
	0x08,				/* AD type: shortened local name */
	0x74, 0x65, 0x73, 0x74, 0x32,	/* "test2" */
};

static const struct generic_data multi_ext_advertising = {
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
};

static const struct generic_data multi_ext_advertising_add_second = {
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_test2,
	.send_len = sizeof(add_advertising_param_test2),
	.expect_param = advertising_instance2_param,
	.expect_len = sizeof(advertising_instance2_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance2_param,
	.expect_alt_ev_len = sizeof(advertising_instance2_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
	.expect_hci_param = set_ext_adv_data_test2,
	.expect_hci_len = sizeof(set_ext_adv_data_test2),
};

static const char multi_ext_adv_hci_params_1[] = {
	0x01,					/* handle */
	0x10, 0x00,				/* evt_properties */
	0x00, 0x08, 0x00,			/* min_interval */
	0x00, 0x08, 0x00,			/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	0x7f,					/* tx_power */
	0x01,					/* primary_phy */
	0x00,					/* secondary_max_skip */
	0x01,					/* secondary_phy */
	0x00,					/* sid */
	0x00,					/* notif_enable */
};

static const char multi_ext_adv_hci_params_2[] = {
	0x02,					/* handle */
	0x10, 0x00,				/* evt_properties */
	0x00, 0x08, 0x00,			/* min_interval */
	0x00, 0x08, 0x00,			/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	0x7f,					/* tx_power */
	0x01,					/* primary_phy */
	0x00,					/* secondary_max_skip */
	0x01,					/* secondary_phy */
	0x00,					/* sid */
	0x00,					/* notif_enable */
};

static const uint8_t le_set_ext_adv_enable_inst_2[] = {
	0x01, 0x01, 0x02, 0x64, 0x00, 0x00,
};

static const struct hci_cmd_data multi_ext_adv_add_second_hci_cmds[] = {
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
		.len = sizeof(multi_ext_adv_hci_params_2),
		.param = multi_ext_adv_hci_params_2,
	},
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
		.len = sizeof(set_ext_adv_data_test2),
		.param = set_ext_adv_data_test2,
	},
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
		.len = sizeof(le_set_ext_adv_enable_inst_2),
		.param = le_set_ext_adv_enable_inst_2,
	},
	{},
};

static const struct generic_data multi_ext_advertising_add_second_2 = {
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_test2,
	.send_len = sizeof(add_advertising_param_test2),
	.expect_param = advertising_instance2_param,
	.expect_len = sizeof(advertising_instance2_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_ADDED,
	.expect_alt_ev_param = advertising_instance2_param,
	.expect_alt_ev_len = sizeof(advertising_instance2_param),
	.expect_hci_list = multi_ext_adv_add_second_hci_cmds,
};

/* add advertising command for a second instance */
static const uint8_t add_advertising_param_test4[] = {
	0x04,				/* adv instance */
	0x00, 0x00, 0x00, 0x00,		/* flags: none */
	0x00, 0x00,			/* duration: default */
	0x01, 0x00,			/* timeout: 1 second */
	0x07,				/* adv data len */
	0x00,				/* scan rsp len */
	/* adv data: */
	0x06,				/* AD len */
	0x08,				/* AD type: shortened local name */
	0x74, 0x65, 0x73, 0x74, 0x32,	/* "test2" */
};

static const struct generic_data multi_ext_advertising_add_adv_4 = {
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_test4,
	.send_len = sizeof(add_advertising_param_test4),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const struct hci_cmd_data multi_ext_adv_remove_adv_hci_cmds[] = {
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
		.len = sizeof(set_ext_adv_disable_param_1),
		.param = set_ext_adv_disable_param_1,
	},
	{
		.opcode = BT_HCI_CMD_LE_REMOVE_ADV_SET,
		.len = sizeof(advertising_instance1_param),
		.param = advertising_instance1_param,
	},
	{},
};

static const struct generic_data multi_ext_advertising_remove = {
	.send_opcode = MGMT_OP_REMOVE_ADVERTISING,
	.send_param = advertising_instance1_param,
	.send_len = sizeof(advertising_instance1_param),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance1_param,
	.expect_alt_ev_len = sizeof(advertising_instance1_param),
	.expect_hci_list = multi_ext_adv_remove_adv_hci_cmds,
};

static const uint8_t advertising_instance0_param[] = {
	0x00,
};

static const uint8_t set_ext_adv_remove_all_param[] = {
	0x00, 0x00,
};

static const struct hci_cmd_data multi_ext_adv_remove_all_adv_hci_cmds[] = {
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
		.len = sizeof(set_ext_adv_remove_all_param),
		.param = set_ext_adv_remove_all_param,
	},
	{
		.opcode = BT_HCI_CMD_LE_CLEAR_ADV_SETS,
	},
	{},
};

static const struct generic_data multi_ext_advertising_remove_all = {
	.send_opcode = MGMT_OP_REMOVE_ADVERTISING,
	.send_param = advertising_instance0_param,
	.send_len = sizeof(advertising_instance0_param),
	.expect_param = advertising_instance0_param,
	.expect_len = sizeof(advertising_instance0_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_ADVERTISING_REMOVED,
	.expect_alt_ev_param = advertising_instance2_param,
	.expect_alt_ev_len = sizeof(advertising_instance2_param),
	.expect_hci_list = multi_ext_adv_remove_all_adv_hci_cmds,
};

static const struct hci_cmd_data multi_ext_adv_add_2_advs_hci_cmds[] = {
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
		.len = sizeof(multi_ext_adv_hci_params_2),
		.param = multi_ext_adv_hci_params_2,
	},
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
		.len = sizeof(set_ext_adv_data_test2),
		.param = set_ext_adv_data_test2,
	},
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
		.len = sizeof(multi_ext_adv_hci_params_1),
		.param = multi_ext_adv_hci_params_1,
	},
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_DATA,
		.len = sizeof(set_ext_adv_data_test1),
		.param = set_ext_adv_data_test1,
	},
	{},
};

static const struct generic_data multi_ext_advertising_add_no_power = {
	.send_opcode = MGMT_OP_SET_POWERED,
	.send_param = set_powered_on_param,
	.send_len = sizeof(set_powered_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_powered_ext_adv_instance_settings_param,
	.expect_len = sizeof(set_powered_ext_adv_instance_settings_param),
	.expect_hci_list = multi_ext_adv_add_2_advs_hci_cmds,
};

static const struct generic_data add_ext_advertising_empty_scrsp = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = set_local_name_param,
	.setup_send_len = sizeof(set_local_name_param),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_empty,
	.send_len = sizeof(add_advertising_param_empty),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
};

static const struct generic_data add_ext_advertising_scrsp_data_only_ok = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_data_only_ok,
	.send_len = sizeof(add_advertising_param_scrsp_data_only_ok),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
};

static const struct generic_data add_ext_advertising_scrsp_data_only_too_long = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_data_only_too_long,
	.send_len = sizeof(add_advertising_param_scrsp_data_only_too_long),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = NULL,
	.expect_len = 0,
};

static const struct generic_data add_ext_advertising_scrsp_appear_data_ok = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_APPEARANCE,
	.setup_send_param = set_appearance_param,
	.setup_send_len = sizeof(set_appearance_param),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_appear_data_ok,
	.send_len = sizeof(add_advertising_param_scrsp_appear_data_ok),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
};

static const struct generic_data add_ext_advertising_scrsp_appear_data_too_long = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_APPEARANCE,
	.setup_send_param = set_appearance_param,
	.setup_send_len = sizeof(set_appearance_param),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_appear_data_too_long,
	.send_len = sizeof(add_advertising_param_scrsp_appear_data_too_long),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = NULL,
	.expect_len = 0,
};

static const struct generic_data add_ext_advertising_scrsp_appear_null = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scrsp_appear_null,
	.send_len = sizeof(add_advertising_param_scrsp_appear_null),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
};

static const uint8_t ext_scan_rsp_data_empty[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x01, /* scan rsp data len */
	0x00, /* scan rsp data */
};

static const struct generic_data add_ext_advertising_no_name_set = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_empty_param,
	.send_len = sizeof(add_advertising_empty_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA,
	.expect_hci_param = ext_scan_rsp_data_empty,
	.expect_hci_len = sizeof(ext_scan_rsp_data_empty),
};

static const uint8_t set_ext_scan_rsp_data_name_fits_in_scrsp[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x0b, /* Scan rsp data len */
	0x0a, /* Local name data len */
	0x09, /* Complete name */
	/* "Test name" */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65,
};

static const struct generic_data add_ext_advertising_name_fits_in_scrsp = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_cp,
	.setup_send_len = sizeof(set_local_name_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name,
	.send_len = sizeof(add_advertising_param_name),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA,
	.expect_hci_param = set_ext_scan_rsp_data_name_fits_in_scrsp,
	.expect_hci_len = sizeof(set_ext_scan_rsp_data_name_fits_in_scrsp),
};

static const uint8_t set_ext_scan_rsp_data_shortened_name_fits[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x0c, /* Scan rsp data len */
	0x0b, /* Local name data len */
	0x08, /* Short name */
	/* "Test name1" */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65, 0x31,
};

static const struct generic_data add_ext_advertising_shortened_name_in_scrsp = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_longer_cp,
	.setup_send_len = sizeof(set_local_name_longer_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name,
	.send_len = sizeof(add_advertising_param_name),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA,
	.expect_hci_param = set_ext_scan_rsp_data_shortened_name_fits,
	.expect_hci_len = sizeof(set_ext_scan_rsp_data_shortened_name_fits),
};

static const uint8_t set_ext_scan_rsp_data_param_name_data_ok[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x1d, /* Scan rsp data len */
	/* scan rsp data */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0a, /* Local name data len */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65,
	/* "Test name" */
};

static const struct generic_data add_ext_advertising_name_data_ok = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_cp,
	.setup_send_len = sizeof(set_local_name_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name_data_ok,
	.send_len = sizeof(add_advertising_param_name_data_ok),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA,
	.expect_hci_param = set_ext_scan_rsp_data_param_name_data_ok,
	.expect_hci_len = sizeof(set_ext_scan_rsp_data_param_name_data_ok),
};

static const struct generic_data add_ext_advertising_name_data_inv = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_LOCAL_NAME,
	.setup_send_param = &set_local_name_cp,
	.setup_send_len = sizeof(set_local_name_cp),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name_data_inv,
	.send_len = sizeof(add_advertising_param_name_data_inv),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = NULL,
	.expect_len = 0,
};

static const uint8_t set_ext_scan_rsp_data_name_data_appear[] = {
	0x01,				/* handle */
	0x03,				/* complete data */
	0x01,				/* controller should not fragment */
	0x1d, /* Scan rsp data len */
	0x03, /* appearance len */
	0x19, /* EIR_APPEARANCE */
	0x54, 0x65, /* appearance value */
	/* scan rsp data */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x0a, /* Local name data len */
	0x09, /* Complete name */
	0x54, 0x65, 0x73, 0x74, 0x20, 0x6e, 0x61, 0x6d, 0x65,
	/* "Test name" */
};

static const struct generic_data add_ext_advertising_name_data_appear = {
	.setup_settings = settings_powered_le,
	.setup_mgmt_cmd_arr = add_advertising_mgmt_cmd_arr,
	.setup_mgmt_cmd_arr_size = ARRAY_SIZE(add_advertising_mgmt_cmd_arr),
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_name_data_appear,
	.send_len = sizeof(add_advertising_param_name_data_appear),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_RSP_DATA,
	.expect_hci_param = set_ext_scan_rsp_data_name_data_appear,
	.expect_hci_len = sizeof(set_ext_scan_rsp_data_name_data_appear),
};

/* simple add advertising command */
static const uint8_t add_advertising_1m_param_uuid[] = {
	0x01,			/* adv instance */
	0x80, 0x00, 0x00, 0x00,	/* flags: 1m */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x09,			/* adv data len */
	0x00,			/* scan rsp len */
	/* adv data: */
	0x03,			/* AD len */
	0x02,			/* AD type: some 16 bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x04,			/* AD len */
	0xff,			/* AD type: manufacturer specific data */
	0x01, 0x02, 0x03,	/* custom advertising data */
};

static uint8_t set_connectable_off_ext_1m_adv_param[] = {
	0x01,					/* Handle */
	0x00, 0x00, 			/* Event type */
	0x00, 0x08, 0x00,		/* min_interval */
	0x00, 0x08, 0x00,		/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* peer_addr */
	0x00,					/* filter_policy */
	127,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_success_1m = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_1m_param_uuid,
	.send_len = sizeof(add_advertising_1m_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_off_ext_1m_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_ext_1m_adv_param),
};

/* simple add advertising command */
static const uint8_t add_advertising_2m_param_uuid[] = {
	0x01,			/* adv instance */
	0x00, 0x01, 0x00, 0x00,	/* flags: 2m */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x09,			/* adv data len */
	0x00,			/* scan rsp len */
	/* adv data: */
	0x03,			/* AD len */
	0x02,			/* AD type: some 16 bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x04,			/* AD len */
	0xff,			/* AD type: manufacturer specific data */
	0x01, 0x02, 0x03,	/* custom advertising data */
};

static uint8_t set_connectable_off_ext_2m_adv_param[] = {
	0x01,					/* Handle */
	0x00, 0x00, 			/* Event type */
	0x00, 0x08, 0x00,		/* min_interval */
	0x00, 0x08, 0x00,		/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* peer_addr */
	0x00,					/* filter_policy */
	127,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x02,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_success_2m = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_2m_param_uuid,
	.send_len = sizeof(add_advertising_2m_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_off_ext_2m_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_ext_2m_adv_param),
};

/* simple add advertising command */
static const uint8_t add_advertising_coded_param_uuid[] = {
	0x01,			/* adv instance */
	0x00, 0x02, 0x00, 0x00,	/* flags: coded */
	0x00, 0x00,		/* duration: default */
	0x00, 0x00,		/* timeout: none */
	0x09,			/* adv data len */
	0x00,			/* scan rsp len */
	/* adv data: */
	0x03,			/* AD len */
	0x02,			/* AD type: some 16 bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x04,			/* AD len */
	0xff,			/* AD type: manufacturer specific data */
	0x01, 0x02, 0x03,	/* custom advertising data */
};

static uint8_t set_connectable_off_ext_coded_adv_param[] = {
	0x01,					/* Handle */
	0x00, 0x00, 			/* Event type */
	0x00, 0x08, 0x00,		/* min_interval */
	0x00, 0x08, 0x00,		/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* peer_addr */
	0x00,					/* filter_policy */
	127,					/* Tx power */
	0x03,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x03,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_success_coded = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_coded_param_uuid,
	.send_len = sizeof(add_advertising_coded_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_off_ext_coded_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_ext_coded_adv_param),
};

/* add advertising with scan response data */
static const uint8_t add_advertising_param_scanrsp_1m[] = {
	0x01,					/* Instance */
	0x80, 0x00, 0x00, 0x00, /* Flags: 1m*/
	0x00, 0x00,				/* Duration */
	0x00, 0x00,				/* Timeout */
	0x09,					/* Adv data len */
	0x0a,			/* scan rsp len */
	/* adv data: same as before */
	0x03, 0x02, 0x0d, 0x18, 0x04, 0xff, 0x01, 0x02, 0x03,
	/* scan rsp data: */
	0x03,			/* AD len */
	0x19,			/* AD type: external appearance */
	0x40, 0x03,		/* some custom appearance */
	0x05,			/* AD len */
	0x03,			/* AD type: all 16 bit service class UUIDs */
	0x0d, 0x18,		/* heart rate monitor */
	0x0f, 0x18,		/* battery service */
};

static uint8_t set_connectable_off_scan_ext_pdu_adv_param[] = {
	0x01,					/* Handle */
	0x02, 0x00,				/* Event type */
	0x00, 0x08, 0x00,		/* min_interval */
	0x00, 0x08,	0x00,		/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	127,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_success_scannable = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scanrsp_1m,
	.send_len = sizeof(add_advertising_param_scanrsp_1m),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_off_scan_ext_pdu_adv_param,
	.expect_hci_len = sizeof(set_connectable_off_scan_ext_pdu_adv_param),
};

static uint8_t set_connectable_on_ext_pdu_adv_param[] = {
	0x01,					/* Handle */
	0x01, 0x00,				/* Event type */
	0x00, 0x08, 0x00,		/* min_interval */
	0x00, 0x08,	0x00,		/* max_interval */
	0x07,					/* channel_map */
	0x00,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	127,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_success_connectable = {
	.setup_settings = settings_powered_le_connectable,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_1m_param_uuid,
	.send_len = sizeof(add_advertising_1m_param_uuid),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_on_ext_pdu_adv_param,
	.expect_hci_len = sizeof(set_connectable_on_ext_pdu_adv_param),
};

static const struct generic_data add_ext_advertising_success_conn_scan = {
	.setup_settings = settings_powered_le_connectable,
	.send_opcode = MGMT_OP_ADD_ADVERTISING,
	.send_param = add_advertising_param_scanrsp_1m,
	.send_len = sizeof(add_advertising_param_scanrsp_1m),
	.expect_param = advertising_instance1_param,
	.expect_len = sizeof(advertising_instance1_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = set_connectable_on_ext_pdu_adv_param,
	.expect_hci_len = sizeof(set_connectable_on_ext_pdu_adv_param),
};

static void setup_add_adv_param_1m(struct mgmt_cp_add_advertising *cp,
							uint8_t instance)
{
	memset(cp, 0, sizeof(*cp));
	cp->instance = instance;
	cp->flags = cpu_to_le32(MGMT_ADV_FLAG_SEC_1M);
	cp->adv_data_len = TESTER_ADD_ADV_DATA_LEN;
	cp->data[0] = TESTER_ADD_ADV_DATA_LEN - 1; /* AD len */
	cp->data[1] = 0x08; /* AD type: shortened local name */
	cp->data[2] = 't';  /* adv data ... */
	cp->data[3] = 'e';
	cp->data[4] = 's';
	cp->data[5] = 't';
	cp->data[6] = '0' + instance;
}

static void setup_add_advertising_1m(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding advertising instance while powered");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param_1m(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static uint8_t preset_connectable_on_ext_pdu_adv_param[] = {
	0x01,					/* Handle */
	0x01, 0x00,				/* Event type */
	0x00, 0x08, 0x00,			/* min_interval */
	0x00, 0x08, 0x00,			/* max_interval */
	0x07,					/* channel_map */
	0x00,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	0x00,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_conn_on_1m = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_on_param,
	.send_len = sizeof(set_connectable_on_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_connectable_settings_param_4,
	.expect_len = sizeof(set_connectable_settings_param_4),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = preset_connectable_on_ext_pdu_adv_param,
	.expect_hci_len = sizeof(preset_connectable_on_ext_pdu_adv_param),
};

static void setup_add_advertising_connectable_1m(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding advertising instance while connectable");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param_1m(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_advertising_callback,
						NULL, NULL);
}

static uint8_t preset_connectable_off_ext_1m_adv_param[] = {
	0x01,					/* Handle */
	0x00, 0x00,				/* Event type */
	0x00, 0x08, 0x00,			/* min_interval */
	0x00, 0x08, 0x00,			/* max_interval */
	0x07,					/* channel_map */
	0x01,					/* own_addr_type */
	0x00,					/* peer_addr_type */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* peer_addr */
	0x00,					/* filter_policy */
	0x00,					/* Tx power */
	0x01,					/* Primary PHY */
	0x00,					/* primary adv max skip */
	0x01,					/* Secondary PHY */
	0x00,					/* adv sid*/
	0x00,					/* Scan req notification */
};

static const struct generic_data add_ext_advertising_conn_off_1m = {
	.send_opcode = MGMT_OP_SET_CONNECTABLE,
	.send_param = set_connectable_off_param,
	.send_len = sizeof(set_connectable_off_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_le_settings_param_3,
	.expect_len = sizeof(set_le_settings_param_3),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_PARAMS,
	.expect_hci_param = preset_connectable_off_ext_1m_adv_param,
	.expect_hci_len = sizeof(preset_connectable_off_ext_1m_adv_param),
};

static const uint8_t get_phy_param[] = {
	0xff, 0x7f, 0x00, 0x00,	/* All PHYs */
	0xfe, 0x79,	0x00, 0x00, /* All PHYs except BR 1M 1SLOT, LE 1M TX & LE 1M RX */
	0xff, 0x7f, 0x00, 0x00, /* All PHYs */
};

static const struct generic_data get_phy_success = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_GET_PHY_CONFIGURATION,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = get_phy_param,
	.expect_len = sizeof(get_phy_param),
};

static const uint8_t set_phy_2m_param[] = {
	0xff, 0x1f,	0x00, 0x00	/* 1mtxrx 2mtxrx */
};

static const uint8_t set_default_phy_2m_param[] = {
	0x00, 		/* preference is there for tx and rx */
	0x03,		/* 1mtx, 2mtx */
	0x03,		/* 1mrx, 2mrx */
};

static const struct generic_data set_phy_2m_success = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_SET_PHY_CONFIGURATION,
	.send_param = set_phy_2m_param,
	.send_len = sizeof(set_phy_2m_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_DEFAULT_PHY,
	.expect_hci_param = set_default_phy_2m_param,
	.expect_hci_len = sizeof(set_default_phy_2m_param),
	.expect_alt_ev = MGMT_EV_PHY_CONFIGURATION_CHANGED,
	.expect_alt_ev_param = set_phy_2m_param,
	.expect_alt_ev_len = sizeof(set_phy_2m_param),
};

static const uint8_t set_phy_coded_param[] = {
	0xff, 0x67,	0x00, 0x00	/* 1mtx, 1m rx, codedtx codedrx */
};

static const uint8_t set_default_phy_coded_param[] = {
	0x00, 		/* preference is there for tx and rx */
	0x05,		/* 1mtx, codedtx */
	0x05,		/* 1mrx, codedrx */
};

static const struct generic_data set_phy_coded_success = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_SET_PHY_CONFIGURATION,
	.send_param = set_phy_coded_param,
	.send_len = sizeof(set_phy_coded_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_DEFAULT_PHY,
	.expect_hci_param = set_default_phy_coded_param,
	.expect_hci_len = sizeof(set_default_phy_coded_param),
	.expect_alt_ev = MGMT_EV_PHY_CONFIGURATION_CHANGED,
	.expect_alt_ev_param = set_phy_coded_param,
	.expect_alt_ev_len = sizeof(set_phy_coded_param),
};

static const uint8_t set_phy_all_param[] = {
	0xff, 0x7f,	0x00, 0x00	/* All PHYs */
};

static const uint8_t set_phy_2m_tx_param[] = {
	0xff, 0x0f,	0x00, 0x00	/* 1mtxrx, 2m tx */
};

static const uint8_t set_default_phy_2m_tx_param[] = {
	0x00,
	0x03,		/* 1m, 2m tx */
	0x01,		/* 1m rx */
};

static const uint8_t set_phy_2m_tx_evt_param[] = {
	0xff, 0x0f,	0x00, 0x00		/*  2m tx  1m rx */
};

static const struct generic_data set_phy_2m_tx_success = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_SET_PHY_CONFIGURATION,
	.send_param = set_phy_2m_tx_param,
	.send_len = sizeof(set_phy_2m_tx_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_DEFAULT_PHY,
	.expect_hci_param = set_default_phy_2m_tx_param,
	.expect_hci_len = sizeof(set_default_phy_2m_tx_param),
	.expect_alt_ev = MGMT_EV_PHY_CONFIGURATION_CHANGED,
	.expect_alt_ev_param = set_phy_2m_tx_evt_param,
	.expect_alt_ev_len = sizeof(set_phy_2m_tx_evt_param),
};

static const uint8_t set_phy_2m_rx_param[] = {
	0xff, 0x17,	0x00, 0x00	/* 1mtxrx, 2m rx */
};

static const uint8_t set_default_phy_2m_rx_param[] = {
	0x00,
	0x01,
	0x03,		/* 2m rx */
};

static const uint8_t set_phy_2m_rx_evt_param[] = {
	0xff, 0x17,	0x00, 0x00		/*  2m rx  1m tx */
};

static const struct generic_data set_phy_2m_rx_success = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_SET_PHY_CONFIGURATION,
	.send_param = set_phy_2m_rx_param,
	.send_len = sizeof(set_phy_2m_rx_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_DEFAULT_PHY,
	.expect_hci_param = set_default_phy_2m_rx_param,
	.expect_hci_len = sizeof(set_default_phy_2m_rx_param),
	.expect_alt_ev = MGMT_EV_PHY_CONFIGURATION_CHANGED,
	.expect_alt_ev_param = set_phy_2m_rx_evt_param,
	.expect_alt_ev_len = sizeof(set_phy_2m_rx_evt_param),
};

static const uint8_t set_phy_param_invalid[] = {
	0x79, 0xfe,	0x00, 0x00	/* Set unconfigurable phy*/
};

static const struct generic_data set_phy_invalid_param = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_SET_PHY_CONFIGURATION,
	.send_param = set_phy_param_invalid,
	.send_len = sizeof(set_phy_param_invalid),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const char start_discovery_valid_ext_scan_enable[] = {
	0x01,
	0x01,
	0x00, 0x00,
	0x00, 0x00
};

static const struct generic_data start_discovery_bredrle_ext_scan_enable = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredrle_param,
	.send_len = sizeof(start_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_bredrle_param,
	.expect_len = sizeof(start_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_ext_scan_enable,
	.expect_hci_len = sizeof(start_discovery_valid_ext_scan_enable),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_evt,
	.expect_alt_ev_len = sizeof(start_discovery_evt),
};

static const struct generic_data start_discovery_le_ext_scan_enable = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_ext_scan_enable,
	.expect_hci_len = sizeof(start_discovery_valid_ext_scan_enable),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_le_evt,
	.expect_alt_ev_len = sizeof(start_discovery_le_evt),
};

static const char start_discovery_ext_scan_param[] = {
	0x01,			/* Own Addr type*/
	0x00,			/* Scan filter policy*/
	0x05,			/* Phys - 1m and Coded*/
	0x01,			/* Type */
	0x12, 0x00,		/* Interval */
	0x12, 0x00,		/* Window */
	0x01,			/* Type */
	0x36, 0x00,		/* Interval */
	0x36, 0x00,		/* Window */
};

static const struct generic_data start_discovery_le_ext_scan_param = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_PARAMS,
	.expect_hci_param = start_discovery_ext_scan_param,
	.expect_hci_len = sizeof(start_discovery_ext_scan_param),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_le_evt,
	.expect_alt_ev_len = sizeof(start_discovery_le_evt),
};

static const char stop_discovery_valid_ext_scan_disable[] = {
	0x00,
	0x00,
	0x00, 0x00,
	0x00, 0x00
};

static const struct generic_data stop_discovery_le_ext_scan_disable = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_START_DISCOVERY,
	.setup_send_param = start_discovery_bredrle_param,
	.setup_send_len = sizeof(start_discovery_bredrle_param),
	.send_opcode = MGMT_OP_STOP_DISCOVERY,
	.send_param = stop_discovery_bredrle_param,
	.send_len = sizeof(stop_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = stop_discovery_bredrle_param,
	.expect_len = sizeof(stop_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE,
	.expect_hci_param = stop_discovery_valid_ext_scan_disable,
	.expect_hci_len = sizeof(stop_discovery_valid_ext_scan_disable),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = stop_discovery_evt,
	.expect_alt_ev_len = sizeof(stop_discovery_evt),
};

static const char start_discovery_2m_ext_scan_param[] = {
	0x01,			/* Own Addr type*/
	0x00,			/* Scan filter policy*/
	0x01,			/* Phys - 1m and Coded*/
	0x01,			/* Type */
	0x12, 0x00,		/* Interval */
	0x12, 0x00,		/* Window */
};

static const struct generic_data start_discovery_le_2m_scan_param = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_PHY_CONFIGURATION,
	.setup_send_param = set_phy_2m_param,
	.setup_send_len = sizeof(set_phy_2m_param),
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredrle_param,
	.send_len = sizeof(start_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_bredrle_param,
	.expect_len = sizeof(start_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_PARAMS,
	.expect_hci_param = start_discovery_2m_ext_scan_param,
	.expect_hci_len = sizeof(start_discovery_2m_ext_scan_param),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_evt,
	.expect_alt_ev_len = sizeof(start_discovery_evt),
};

static const char start_discovery_valid_coded_scan_param[] = {
	0x01,			/* Own Addr type*/
	0x00,			/* Scan filter policy*/
	0x05,			/*Phys - 1m & coded */
	0x01,			/* Type */
	0x12, 0x00,		/* Interval */
	0x12, 0x00,		/* Window */
	0x01,			/* Type */
	0x36, 0x00,		/* Interval */
	0x36, 0x00,		/* Window */
};

static const struct generic_data start_discovery_le_coded_scan_param = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_PHY_CONFIGURATION,
	.setup_send_param = set_phy_coded_param,
	.setup_send_len = sizeof(set_phy_coded_param),
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredrle_param,
	.send_len = sizeof(start_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_bredrle_param,
	.expect_len = sizeof(start_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_PARAMS,
	.expect_hci_param = start_discovery_valid_coded_scan_param,
	.expect_hci_len = sizeof(start_discovery_valid_coded_scan_param),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_evt,
	.expect_alt_ev_len = sizeof(start_discovery_evt),
};

static const char start_discovery_valid_1m_2m_coded_scan_param[] = {
	0x01,			/* Own Addr type*/
	0x00,			/* Scan filter policy*/
	0x05,			/*Phys - 1m, coded */
	0x01,			/* Type */
	0x12, 0x00,		/* Interval */
	0x12, 0x00,		/* Window */
	0x01,			/* Type */
	0x36, 0x00,		/* Interval */
	0x36, 0x00,		/* Window */
};

static const struct generic_data start_discovery_le_1m_coded_scan_param = {
	.setup_settings = settings_powered_le,
	.setup_send_opcode = MGMT_OP_SET_PHY_CONFIGURATION,
	.setup_send_param = set_phy_all_param,
	.setup_send_len = sizeof(set_phy_all_param),
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_bredrle_param,
	.send_len = sizeof(start_discovery_bredrle_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_bredrle_param,
	.expect_len = sizeof(start_discovery_bredrle_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_PARAMS,
	.expect_hci_param = start_discovery_valid_1m_2m_coded_scan_param,
	.expect_hci_len = sizeof(start_discovery_valid_1m_2m_coded_scan_param),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_evt,
	.expect_alt_ev_len = sizeof(start_discovery_evt),
};


static void set_phy_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Set PHY Success");

	tester_setup_complete();
}

static void setup_phy_configuration(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const void *send_param = test->setup_send_param;
	uint16_t send_len = test->setup_send_len;
	unsigned int id;

	id = mgmt_register(data->mgmt, MGMT_EV_DISCOVERING, data->mgmt_index,
			   discovering_event, NULL, NULL);
	data->mgmt_discov_ev_id = id;

	mgmt_send(data->mgmt, test->setup_send_opcode, data->mgmt_index,
				send_len, send_param, set_phy_callback,
				NULL, NULL);
}

static const uint8_t get_dev_flags_param[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
};

static const uint8_t get_dev_flags_rsp_param[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
	0x07, 0x00, 0x00, 0x00,			/* Supported Flags */
	0x00, 0x00, 0x00, 0x00,			/* Current Flags */
};

static const struct generic_data get_dev_flags_success = {
	.send_opcode = MGMT_OP_GET_DEVICE_FLAGS,
	.send_param = get_dev_flags_param,
	.send_len = sizeof(get_dev_flags_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = get_dev_flags_rsp_param,
	.expect_len = sizeof(get_dev_flags_rsp_param),
};

static const uint8_t get_dev_flags_param_fail_1[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
};

static const struct generic_data get_dev_flags_fail_1 = {
	.send_opcode = MGMT_OP_GET_DEVICE_FLAGS,
	.send_param = get_dev_flags_param_fail_1,
	.send_len = sizeof(get_dev_flags_param_fail_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static void setup_get_dev_flags(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	const unsigned char *add_param;
	size_t add_param_len;

	tester_print("Powering on controller (with added device)");

	if (data->hciemu_type == HCIEMU_TYPE_LE) {
		add_param = add_device_success_param_2;
		add_param_len = sizeof(add_device_success_param_2);
	} else {
		add_param = add_device_success_param_1;
		add_param_len = sizeof(add_device_success_param_1);
	}

	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
			add_param_len, add_param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static const uint8_t set_dev_flags_param[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
	0x01, 0x00, 0x00, 0x00,			/* Current Flags */
};

static const uint8_t set_dev_flags_rsp_param[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
};

static const uint8_t dev_flags_changed_param[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
	0x07, 0x00, 0x00, 0x00,			/* Supported Flags */
	0x01, 0x00, 0x00, 0x00,			/* Current Flags */
};

static const struct generic_data set_dev_flags_success = {
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_dev_flags_param,
	.send_len = sizeof(set_dev_flags_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_dev_flags_rsp_param,
	.expect_len = sizeof(set_dev_flags_rsp_param),
	.expect_alt_ev = MGMT_EV_DEVICE_FLAGS_CHANGED,
	.expect_alt_ev_param = dev_flags_changed_param,
	.expect_alt_ev_len = sizeof(dev_flags_changed_param),
};

static const uint8_t set_dev_flags_param_fail_1[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
};

static const struct generic_data set_dev_flags_fail_1 = {
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_dev_flags_param_fail_1,
	.send_len = sizeof(set_dev_flags_param_fail_1),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t set_dev_flags_param_fail_2[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
	0xff, 0x00, 0x00, 0x00,			/* Current Flags */
};

static const struct generic_data set_dev_flags_fail_2 = {
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_dev_flags_param_fail_2,
	.send_len = sizeof(set_dev_flags_param_fail_2),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = set_dev_flags_rsp_param,
	.expect_len = sizeof(set_dev_flags_rsp_param),
};

static const uint8_t set_dev_flags_param_fail_3[] = {
	0x11, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
	0x01, 0x00, 0x00, 0x00,			/* Current Flags */
};

static const uint8_t set_dev_flags_rsp_param_fail_3[] = {
	0x11, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
	0x00,					/* Type */
};

static const struct generic_data set_dev_flags_fail_3 = {
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_dev_flags_param_fail_3,
	.send_len = sizeof(set_dev_flags_param_fail_3),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
	.expect_param = set_dev_flags_rsp_param_fail_3,
	.expect_len = sizeof(set_dev_flags_rsp_param_fail_3),
};

static const uint8_t read_exp_feat_param_success[] = {
	0x04, 0x00,				/* Feature Count */
	0xd6, 0x49, 0xb0, 0xd1, 0x28, 0xeb,	/* UUID - Simultaneous */
	0x27, 0x92, 0x96, 0x46, 0xc0, 0x42,	/* Central Peripheral */
	0xb5, 0x10, 0x1b, 0x67,
	0x00, 0x00, 0x00, 0x00,			/* Flags */
	0xaf, 0x29, 0xc6, 0x66, 0xac, 0x5f,	/* UUID - Codec Offload */
	0x1a, 0x88, 0xb9, 0x4f, 0x7f, 0xee,
	0xce, 0x5a, 0x69, 0xa6,
	0x00, 0x00, 0x00, 0x00,			/* Flags */
	0x3e, 0xe0, 0xb4, 0xfd, 0xdd, 0xd6,	/* UUID - ISO Socket */
	0x85, 0x98, 0x6a, 0x49, 0xe0, 0x05,
	0x88, 0xf1, 0xba, 0x6f,
	0x00, 0x00, 0x00, 0x00,			/* Flags */
	0x76, 0x6e, 0xf3, 0xe8, 0x24, 0x5f,	/* UUID - Mesh support */
	0x05, 0xbf, 0x8d, 0x4d, 0x03, 0x7a,
	0xd7, 0x63, 0xe4, 0x2c,
	0x01, 0x00, 0x00, 0x00,			/* Flags */
};

static const struct generic_data read_exp_feat_success = {
	.send_opcode = MGMT_OP_READ_EXP_FEATURES_INFO,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = read_exp_feat_param_success,
	.expect_len = sizeof(read_exp_feat_param_success),
};


static const uint8_t read_exp_feat_param_success_index_none[] = {
	0x02, 0x00,				/* Feature Count */
	0x1c, 0xda, 0x47, 0x1c, 0x48, 0x6c,	/* UUID - Debug */
	0x01, 0xab, 0x9f, 0x46, 0xec, 0xb9,
	0x30, 0x25, 0x99, 0xd4,
	0x00, 0x00, 0x00, 0x00,			/* Flags */
	0x3e, 0xe0, 0xb4, 0xfd, 0xdd, 0xd6,	/* UUID - ISO Socket */
	0x85, 0x98, 0x6a, 0x49, 0xe0, 0x05,
	0x88, 0xf1, 0xba, 0x6f,
	0x00, 0x00, 0x00, 0x00,			/* Flags */
};

static const struct generic_data read_exp_feat_success_index_none = {
	.send_index_none = true,
	.send_opcode = MGMT_OP_READ_EXP_FEATURES_INFO,
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = read_exp_feat_param_success_index_none,
	.expect_len = sizeof(read_exp_feat_param_success_index_none),
};

static const uint8_t set_exp_feat_param_offload_codec[] = {
	0xaf, 0x29, 0xc6, 0x66, 0xac, 0x5f,	/* UUID - Codec Offload */
	0x1a, 0x88, 0xb9, 0x4f, 0x7f, 0xee,
	0xce, 0x5a, 0x69, 0xa6,
	0x01,					/* Action - enable */
};

static const uint8_t set_exp_feat_rsp_param_offload_codec[] = {
	0xaf, 0x29, 0xc6, 0x66, 0xac, 0x5f,	/* UUID - Codec Offload */
	0x1a, 0x88, 0xb9, 0x4f, 0x7f, 0xee,
	0xce, 0x5a, 0x69, 0xa6,
	0x01, 0x00, 0x00, 0x00,			/* Action - enable */
};

static void read_exp_feature_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Received Read Experimental Features Info");

	tester_setup_complete();
}

static void setup_set_exp_feature_alt(const void *test_data)
{
	struct test_data *data = tester_get_data();

	/* Send the Read Experimental Features Information command to receive
	 * the Experimental Feature Changed event
	 */
	mgmt_send(data->mgmt_alt, MGMT_OP_READ_EXP_FEATURES_INFO,
			data->mgmt_index, 0, NULL,
			read_exp_feature_callback, NULL, NULL);
}

static const struct generic_data set_exp_feat_offload_codec = {
	.send_opcode = MGMT_OP_SET_EXP_FEATURE,
	.send_param = set_exp_feat_param_offload_codec,
	.send_len = sizeof(set_exp_feat_param_offload_codec),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_exp_feat_rsp_param_offload_codec,
	.expect_len = sizeof(set_exp_feat_rsp_param_offload_codec),
	.expect_alt_ev = MGMT_EV_EXP_FEATURE_CHANGE,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_exp_feature_changed),
};

static const uint8_t set_exp_feat_param_disable[17] = { 0x00 };
static const uint8_t set_exp_feat_rsp_param_disable[20] = { 0x00 };

static const struct generic_data set_exp_feat_disable = {
	.send_opcode = MGMT_OP_SET_EXP_FEATURE,
	.send_param = set_exp_feat_param_disable,
	.send_len = sizeof(set_exp_feat_param_disable),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = set_exp_feat_rsp_param_disable,
	.expect_len = sizeof(set_exp_feat_rsp_param_disable),
};

static const uint8_t set_exp_feat_param_invalid[] = {
	0xaf, 0x29, 0xc6, 0x66, 0xac, 0x5f,	/* UUID - Codec Offload */
	0x1a, 0x88, 0xb9, 0x4f, 0x7f, 0xee,
	0xce, 0x5a, 0x69, 0xa6,
	0xff,					/* Action - invalid */
};

static const struct generic_data set_exp_feat_invalid = {
	.send_opcode = MGMT_OP_SET_EXP_FEATURE,
	.send_param = set_exp_feat_param_invalid,
	.send_len = sizeof(set_exp_feat_param_invalid),
	.expect_status = MGMT_STATUS_INVALID_PARAMS,
};

static const uint8_t set_exp_feat_param_unknown[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,	/* UUID - Unknown */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff,
	0x01,					/* Action - enable */
};

static const struct generic_data set_exp_feat_unknown = {
	.send_opcode = MGMT_OP_SET_EXP_FEATURE,
	.send_param = set_exp_feat_param_unknown,
	.send_len = sizeof(set_exp_feat_param_unknown),
	.expect_status = MGMT_STATUS_NOT_SUPPORTED,
};

static const uint8_t add_device_le_public_param_1[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x02,					/* Action - Auto-Connect */
};

static const uint8_t add_device_rsp_le_public[] =  {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* BDADDR */
	0x01,					/* Type - LE Public */
};
static const char load_irks_le_public_param_1[] = {
	0x01, 0x00,					/* Key Count */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,		/* Key 1 - BDADDR */
	0x01,						/* Key 1 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, /* Key 1 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
};

static const uint8_t add_device_le_public_param_2[] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x00,					/* Action - Background scan */
};

static const uint8_t add_device_rsp_le_public_2[] =  {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
};

static const uint8_t add_device_le_public_param_3[] = {
	0x33, 0x33, 0x33, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x00,					/* Action - Background scan */
};

static const uint8_t add_device_rsp_le_public_3[] =  {
	0x33, 0x33, 0x33, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
};

static const uint8_t add_device_le_public_param_4[] = {
	0x44, 0x44, 0x44, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x00,					/* Action - Background scan */
};

static const char load_irks_2_devices_param[] = {
	0x02, 0x00,					/* Key Count */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,		/* Key 1 - BDADDR */
	0x01,						/* Key 1 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, /* Key 1 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,		/* Key 2 - BDADDR */
	0x01,						/* Key 2 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Key 2 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
};

static const char load_irks_3_devices_param[] = {
	0x03, 0x00,					/* Key Count */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,		/* Key 1 - BDADDR */
	0x01,						/* Key 1 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, /* Key 1 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,		/* Key 2 - BDADDR */
	0x01,						/* Key 2 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Key 2 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x33, 0x33, 0x33, 0x44, 0x55, 0x66,		/* Key 3 - BDADDR */
	0x01,						/* Key 3 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Key 3 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
};

static const char load_irks_4_devices_param[] = {
	0x04, 0x00,					/* Key Count */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,		/* Key 1 - BDADDR */
	0x01,						/* Key 1 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, /* Key 1 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,		/* Key 2 - BDADDR */
	0x01,						/* Key 2 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Key 2 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x33, 0x33, 0x33, 0x44, 0x55, 0x66,		/* Key 3 - BDADDR */
	0x01,						/* Key 3 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Key 3 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x44, 0x44, 0x44, 0x44, 0x55, 0x66,		/* Key 4 - BDADDR */
	0x01,						/* Key 4 - Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Key 4 - Value */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
};

static const uint8_t le_add_to_accept_list_param[] = {
	0x00,					/* Type */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* Address */
};

static const uint8_t le_add_to_white_list_param_2[] = {
	0x00,					/* Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* Address */
};

static const uint8_t le_add_to_white_list_param_3[] = {
	0x00,					/* Type */
	0x33, 0x33, 0x33, 0x44, 0x55, 0x66,	/* Address */
};

static const uint8_t le_add_to_resolv_list_param[] = {
	0x00,						/* Type */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,		/* BDADDR */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Peer IRK */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	/* Local IRK */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static const uint8_t le_add_to_resolv_list_param_2[] = {
	0x00,						/* Type */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,		/* BDADDR */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Peer IRK */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	/* Local IRK */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static const uint8_t le_add_to_resolv_list_param_4[] = {
	0x00,						/* Type */
	0x44, 0x44, 0x44, 0x44, 0x55, 0x66,		/* BDADDR */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,	/* Peer IRK */
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,	/* Local IRK */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

static const char set_resolv_off_param[] = { 0x00 };
static const char set_resolv_on_param[] = { 0x01 };

static const struct generic_data ll_privacy_add_device_1 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_le_public_param_1,
	.send_len = sizeof(add_device_le_public_param_1),
	.expect_param = add_device_rsp_le,
	.expect_len = sizeof(add_device_rsp_le),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_le_public_param_1,
	.expect_alt_ev_len = sizeof(add_device_le_public_param_1),
	.expect_hci_command = BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST,
	.expect_hci_param = le_add_to_accept_list_param,
	.expect_hci_len = sizeof(le_add_to_accept_list_param),
};

static uint16_t settings_le_privacy_ll_privacy[] = { MGMT_OP_SET_LE,
					MGMT_OP_SET_PRIVACY, 0 };

static const uint8_t set_device_flags_param_1[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x06, 0x00, 0x00, 0x00			/* Flags -
						 * Device Privacy
						 * Address Resolution
						 */
};

static const uint8_t set_device_flags_rsp[] =  {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* BDADDR */
	0x01					/* Type - LE Public */
};

static const uint8_t device_flags_changed_params_1[] = {
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x07, 0x00, 0x00, 0x00,			/* Supported Flags */
	0x06, 0x00, 0x00, 0x00			/* Current Flags */
};

static const struct generic_data ll_privacy_set_flags_1 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_device_flags_param_1,
	.send_len = sizeof(set_device_flags_param_1),
	.expect_param = set_device_flags_rsp,
	.expect_len = sizeof(set_device_flags_rsp),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_FLAGS_CHANGED,
	.expect_alt_ev_param = device_flags_changed_params_1,
	.expect_alt_ev_len = sizeof(device_flags_changed_params_1),
	.expect_hci_command = BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST,
	.expect_hci_param = le_add_to_resolv_list_param,
	.expect_hci_len = sizeof(le_add_to_resolv_list_param),
};

static const struct hci_cmd_data ll_privacy_add_device_3_hci_list[] = {
	{
		.opcode = BT_HCI_CMD_LE_SET_RESOLV_ENABLE,
		.param = set_resolv_off_param,
		.len = sizeof(set_resolv_off_param),
	},
	{
		.opcode = BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST,
		.param = le_add_to_resolv_list_param,
		.len = sizeof(le_add_to_resolv_list_param),
	},
	{
		.opcode = BT_HCI_CMD_LE_SET_RESOLV_ENABLE,
		.param = set_resolv_on_param,
		.len = sizeof(set_resolv_on_param),
	},
	{},
};

static const struct generic_data ll_privacy_set_flags_2 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_device_flags_param_1,
	.send_len = sizeof(set_device_flags_param_1),
	.expect_param = set_device_flags_rsp,
	.expect_len = sizeof(set_device_flags_rsp),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_FLAGS_CHANGED,
	.expect_alt_ev_param = device_flags_changed_params_1,
	.expect_alt_ev_len = sizeof(device_flags_changed_params_1),
	.expect_hci_list = ll_privacy_add_device_3_hci_list,
};

static const struct generic_data ll_privacy_add_device_2 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_le_public_param_2,
	.send_len = sizeof(add_device_le_public_param_2),
	.expect_param = add_device_rsp_le_public_2,
	.expect_len = sizeof(add_device_rsp_le_public_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_le_public_param_2,
	.expect_alt_ev_len = sizeof(add_device_le_public_param_2),
	.expect_hci_command = BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST,
	.expect_hci_param = le_add_to_white_list_param_2,
	.expect_hci_len = sizeof(le_add_to_white_list_param_2),
};

static const uint8_t set_device_flags_param_2[] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x06, 0x00, 0x00, 0x00			/* Flags -
						 * Device Privacy
						 * Address Resolution
						 */
};

static const uint8_t device_flags_changed_params_2[] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x07, 0x00, 0x00, 0x00,			/* Supported Flags */
	0x06, 0x00, 0x00, 0x00			/* Current Flags */
};

static const uint8_t set_device_flags_rsp_2[] =  {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01					/* Type - LE Public */
};

static const struct generic_data ll_privacy_set_flags_3 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_device_flags_param_2,
	.send_len = sizeof(set_device_flags_param_2),
	.expect_param = set_device_flags_rsp_2,
	.expect_len = sizeof(set_device_flags_rsp_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_FLAGS_CHANGED,
	.expect_alt_ev_param = device_flags_changed_params_2,
	.expect_alt_ev_len = sizeof(device_flags_changed_params_2),
	.expect_hci_command = BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST,
	.expect_hci_param = le_add_to_resolv_list_param_2,
	.expect_hci_len = sizeof(le_add_to_resolv_list_param_2),
};

static const uint8_t set_device_flags_param_4[] = {
	0x44, 0x44, 0x44, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x06, 0x00, 0x00, 0x00			/* Flags -
						 * Device Privacy
						 * Address Resolution
						 */
};

static const uint8_t device_flags_changed_params_4[] = {
	0x44, 0x44, 0x44, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x07, 0x00, 0x00, 0x00,			/* Supported Flags */
	0x06, 0x00, 0x00, 0x00			/* Current Flags */
};

static const uint8_t set_device_flags_rsp_4[] =  {
	0x44, 0x44, 0x44, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01					/* Type - LE Public */
};

static const struct generic_data ll_privacy_set_flags_4 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_device_flags_param_4,
	.send_len = sizeof(set_device_flags_param_4),
	.expect_param = set_device_flags_rsp_4,
	.expect_len = sizeof(set_device_flags_rsp_4),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_FLAGS_CHANGED,
	.expect_alt_ev_param = device_flags_changed_params_4,
	.expect_alt_ev_len = sizeof(device_flags_changed_params_4),
	.expect_hci_command = BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST,
	.expect_hci_param = le_add_to_resolv_list_param_4,
	.expect_hci_len = sizeof(le_add_to_resolv_list_param_4),
};

static const struct generic_data ll_privacy_add_device_3 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_le_public_param_3,
	.send_len = sizeof(add_device_le_public_param_3),
	.expect_param = add_device_rsp_le_public_3,
	.expect_len = sizeof(add_device_rsp_le_public_3),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_le_public_param_3,
	.expect_alt_ev_len = sizeof(add_device_le_public_param_3),
	.expect_hci_command = BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST,
	.expect_hci_param = le_add_to_white_list_param_3,
	.expect_hci_len = sizeof(le_add_to_white_list_param_3),
};

static const char set_ext_adv_disable[] = {
	0x00, 0x00,
};

static const struct generic_data ll_privacy_add_4 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_ADD_DEVICE,
	.send_param = add_device_le_public_param_3,
	.send_len = sizeof(add_device_le_public_param_3),
	.expect_param = add_device_rsp_le_public_3,
	.expect_len = sizeof(add_device_rsp_le_public_3),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_ADDED,
	.expect_alt_ev_param = add_device_le_public_param_3,
	.expect_alt_ev_len = sizeof(add_device_le_public_param_3),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
	.expect_hci_param = set_ext_adv_disable,
	.expect_hci_len = sizeof(set_ext_adv_disable),
};

static const struct hci_cmd_data ll_privacy_set_flags_5_hci_list[] = {
	{
		.opcode = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
		.len = sizeof(set_ext_adv_disable),
		.param = set_ext_adv_disable,
	},
	{
		.opcode = BT_HCI_CMD_LE_ADD_TO_RESOLV_LIST,
		.len = sizeof(le_add_to_resolv_list_param),
		.param = le_add_to_resolv_list_param
	},
	{},
};

static const struct generic_data ll_privacy_set_flags_5 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_device_flags_param_1,
	.send_len = sizeof(set_device_flags_param_1),
	.expect_param = set_device_flags_rsp,
	.expect_len = sizeof(set_device_flags_rsp),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_FLAGS_CHANGED,
	.expect_alt_ev_param = device_flags_changed_params_1,
	.expect_alt_ev_len = sizeof(device_flags_changed_params_1),
	.expect_hci_list = ll_privacy_set_flags_5_hci_list,
};

static const struct generic_data ll_privacy_remove_device_1 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_2,
	.send_len = sizeof(remove_device_param_2),
	.expect_param = remove_device_param_2,
	.expect_len = sizeof(remove_device_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_REMOVE_FROM_ACCEPT_LIST,
	.expect_hci_param = le_add_to_accept_list_param,
	.expect_hci_len = sizeof(le_add_to_accept_list_param),
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_2,
	.expect_alt_ev_len = sizeof(remove_device_param_2),
};

static const struct generic_data ll_privacy_remove_device_2 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_2,
	.send_len = sizeof(remove_device_param_2),
	.expect_param = remove_device_param_2,
	.expect_len = sizeof(remove_device_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_REMOVE_FROM_RESOLV_LIST,
	.expect_hci_param = le_add_to_accept_list_param,
	.expect_hci_len = sizeof(le_add_to_accept_list_param),
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_2,
	.expect_alt_ev_len = sizeof(remove_device_param_2),
};

static const struct generic_data ll_privacy_remove_device_3 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_2,
	.send_len = sizeof(remove_device_param_2),
	.expect_param = remove_device_param_2,
	.expect_len = sizeof(remove_device_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_SET_RESOLV_ENABLE,
	.expect_hci_param = set_resolv_off_param,
	.expect_hci_len = sizeof(set_resolv_off_param),
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_2,
	.expect_alt_ev_len = sizeof(remove_device_param_2),
};

static const struct generic_data ll_privacy_remove_device_4 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_2,
	.send_len = sizeof(remove_device_param_2),
	.expect_param = remove_device_param_2,
	.expect_len = sizeof(remove_device_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_REMOVE_FROM_RESOLV_LIST,
	.expect_hci_param = le_add_to_accept_list_param,
	.expect_hci_len = sizeof(le_add_to_accept_list_param),
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_2,
	.expect_alt_ev_len = sizeof(remove_device_param_2),
};

static const struct generic_data ll_privacy_remove_device_5 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_REMOVE_DEVICE,
	.send_param = remove_device_param_2,
	.send_len = sizeof(remove_device_param_2),
	.expect_param = remove_device_param_2,
	.expect_len = sizeof(remove_device_param_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_hci_command = BT_HCI_CMD_LE_REMOVE_FROM_RESOLV_LIST,
	.expect_hci_param = le_add_to_accept_list_param,
	.expect_hci_len = sizeof(le_add_to_accept_list_param),
	.expect_alt_ev = MGMT_EV_DEVICE_REMOVED,
	.expect_alt_ev_param = remove_device_param_2,
	.expect_alt_ev_len = sizeof(remove_device_param_2),
};

static const struct generic_data ll_privacy_start_discovery_ll_privacy_1 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.setup_expect_hci_command = BT_HCI_CMD_LE_SET_RESOLV_ENABLE,
	.setup_expect_hci_param = set_resolv_on_param,
	.setup_expect_hci_len = sizeof(set_resolv_on_param),
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_RESOLV_ENABLE,
	.expect_hci_param = set_resolv_off_param,
	.expect_hci_len = sizeof(set_resolv_off_param),
};

static const struct generic_data ll_privacy_start_discovery_ll_privacy_2 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.setup_expect_hci_command = BT_HCI_CMD_LE_REMOVE_FROM_RESOLV_LIST,
	.setup_expect_hci_param = le_add_to_accept_list_param,
	.setup_expect_hci_len = sizeof(le_add_to_accept_list_param),
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_RESOLV_ENABLE,
	.expect_hci_param = set_resolv_off_param,
	.expect_hci_len = sizeof(set_resolv_off_param),
	.expect_alt_ev = MGMT_EV_DISCOVERING,
	.expect_alt_ev_param = start_discovery_le_evt,
	.expect_alt_ev_len = sizeof(start_discovery_le_evt),
};

static const struct generic_data ll_privacy_advertising_1 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_SET_ADVERTISING,
	.send_param = set_adv_on_param2,
	.send_len = sizeof(set_adv_on_param2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_ignore_param = true,
};

static const struct generic_data ll_privacy_acceptor_1 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.io_cap = 0x04, /* KeyboardDisplay */
	.client_io_cap = 0x04, /* KeyboardDisplay */
	.client_auth_req = 0x05, /* Bonding - MITM */
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static const struct generic_data ll_privacy_acceptor_2 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.io_cap = 0x04, /* KeyboardDisplay */
	.client_io_cap = 0x04, /* KeyboardDisplay */
	.just_works = true,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static const uint8_t unpair_client_1[] = {
	0x00, 0x00, 0x01, 0x01, 0xaa, 0x00,	/* Address */
	0x01,					/* Type */
	0x01,					/* Disconnect */
};

static const uint8_t unpair_resp_param_1[] = {
	0x00, 0x00, 0x01, 0x01, 0xaa, 0x00,	/* Address */
	0x01,					/* Type */
};

static const uint8_t add_paired_client_1[] = {
	0x00, 0x00, 0x01, 0x01, 0xaa, 0x00,	/* Address */
	0x01,					/* Type */
	0x00,
};

static const uint8_t remove_paired_device_1[] = {
	0x00, 0x00, 0x01, 0x01, 0xaa, 0x00,	/* Address */
	0x01,					/* Type */
};

static const uint8_t add_to_al_client[] = {
	0x00,					/* Address Type */
	0x00, 0x00, 0x01, 0x01, 0xaa, 0x00,	/* Address */
};

static uint16_t settings_powered_le_sc_bondable_privacy_ll_privacy[] = {
						MGMT_OP_SET_LE,
						MGMT_OP_SET_SSP,
						MGMT_OP_SET_BONDABLE,
						MGMT_OP_SET_SECURE_CONN,
						MGMT_OP_SET_PRIVACY,
						MGMT_OP_SET_EXP_FEATURE,
						MGMT_OP_SET_POWERED, 0 };

static const struct generic_data ll_privacy_pair_1 = {
	.setup_settings = settings_powered_le_sc_bondable_privacy_ll_privacy,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.addr_type_avail = true,
	.addr_type = 0x01,
	.client_enable_sc = true,
	.client_enable_ssp = true,
	.client_enable_adv = true,
	.expect_sc_key = true,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x02, /* KeyboardOnly */
	.client_auth_req = 0x05, /* Bonding - MITM */
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
};

static const struct generic_data ll_privacy_pair_2 = {
	.setup_settings = settings_powered_le_sc_bondable_privacy_ll_privacy,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.addr_type_avail = true,
	.addr_type = 0x01,
	.client_enable_sc = true,
	.client_enable_ssp = true,
	.client_enable_adv = true,
	.expect_sc_key = true,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x02, /* KeyboardOnly */
	.client_auth_req = 0x05, /* Bonding - MITM */
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev =  MGMT_EV_NEW_LONG_TERM_KEY,
	.expect_alt_ev_len = sizeof(struct mgmt_ev_new_long_term_key),
	.verify_alt_ev_func = verify_ltk,
	.expect_hci_command = BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST,
	.expect_hci_param = add_to_al_client,
	.expect_hci_len = sizeof(add_to_al_client),
};

static const struct generic_data ll_privacy_unpair_1 = {
	.setup_settings = settings_powered_le_sc_bondable_privacy_ll_privacy,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.addr_type_avail = true,
	.addr_type = 0x01,
	.client_enable_sc = true,
	.client_enable_ssp = true,
	.client_enable_adv = true,
	.expect_sc_key = true,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x02, /* KeyboardOnly */
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_DEVICE_UNPAIRED,
	.expect_alt_ev_param = unpair_resp_param_1,
	.expect_alt_ev_len = sizeof(unpair_resp_param_1),
};

static const struct generic_data ll_privacy_unpair_2 = {
	.setup_settings = settings_powered_le_sc_bondable_privacy_ll_privacy,
	.send_opcode = MGMT_OP_PAIR_DEVICE,
	.send_func = pair_device_send_param_func,
	.addr_type_avail = true,
	.addr_type = 0x01,
	.client_enable_sc = true,
	.client_enable_ssp = true,
	.client_enable_adv = true,
	.expect_sc_key = true,
	.io_cap = 0x02, /* KeyboardOnly */
	.client_io_cap = 0x02, /* KeyboardOnly */
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_func = pair_device_expect_param_func,
	.expect_alt_ev = MGMT_EV_DEVICE_UNPAIRED,
	.expect_alt_ev_param = unpair_resp_param_1,
	.expect_alt_ev_len = sizeof(unpair_resp_param_1),
	.expect_hci_command = BT_HCI_CMD_LE_REMOVE_FROM_ACCEPT_LIST,
	.expect_hci_param = add_to_al_client,
	.expect_hci_len = sizeof(add_to_al_client),
};

static const uint8_t le_set_priv_mode_param[] = {
	0x00,					/* Type */
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,	/* BDADDR */
	0x01					/* Privacy Mode */
};

static const struct hci_cmd_data ll_privacy_set_device_flags_1_hci_list[] = {
	{
		.opcode = BT_HCI_CMD_LE_SET_RESOLV_ENABLE,
		.param = set_resolv_off_param,
		.len = sizeof(set_resolv_off_param),
	},
	{
		.opcode = BT_HCI_CMD_LE_SET_PRIV_MODE,
		.param = le_set_priv_mode_param,
		.len = sizeof(le_set_priv_mode_param),
	},
	{
		.opcode = BT_HCI_CMD_LE_SET_RESOLV_ENABLE,
		.param = set_resolv_on_param,
		.len = sizeof(set_resolv_on_param),
	},
	{},
};

static const struct generic_data ll_privacy_set_device_flag_1 = {
	.setup_settings = settings_le_privacy_ll_privacy,
	.send_opcode = MGMT_OP_SET_DEVICE_FLAGS,
	.send_param = set_device_flags_param_1,
	.send_len = sizeof(set_device_flags_param_1),
	.expect_param = set_device_flags_rsp,
	.expect_len = sizeof(set_device_flags_rsp),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_DEVICE_FLAGS_CHANGED,
	.expect_alt_ev_param = device_flags_changed_params_1,
	.expect_alt_ev_len = sizeof(device_flags_changed_params_1),
	.expect_hci_list = ll_privacy_set_device_flags_1_hci_list,
};

static void setup_load_irks_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Load IRK completed");
}

static void setup_add_device_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("New Device is Added");
}

static void setup_remove_device_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	bool bthost = PTR_TO_INT(user_data);

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Device is Removed");

	if (bthost)
		setup_bthost();
}

static void setup_add_adv_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct mgmt_rp_add_advertising *rp =
				(struct mgmt_rp_add_advertising *) param;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Add Advertising setup complete (instance %d)",
								rp->instance);
}

static void setup_add_adv_callback_adv(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	struct mgmt_rp_add_advertising *rp =
				(struct mgmt_rp_add_advertising *) param;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Add Advertising setup complete (instance %d)",
								rp->instance);

	/* Add another advertising */
	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 2);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
					sizeof(adv_param), adv_param,
					setup_add_advertising_callback,
					NULL, NULL);
}

static void setup_ll_privacy_set_flags_1(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_le_public_param_1),
					load_irks_le_public_param_1,
					setup_load_irks_callback, NULL, NULL);

	/* Set Powered On */
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);
}

static void setup_set_device_flags_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Device Flags are set");
}

static void setup_ll_privacy_add_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	/* Add IRKs of Device1 and Device2 */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_2_devices_param),
					load_irks_2_devices_param,
					setup_load_irks_callback, NULL, NULL);

	/* Set Powered On */
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);
	/* Device 1 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_1),
					set_device_flags_param_1,
					setup_set_device_flags_callback, NULL,
					NULL);
}

static void setup_ll_privacy_set_flags_3(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	/* Add IRKs of Device1 and Device2 */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_2_devices_param),
					load_irks_2_devices_param,
					setup_load_irks_callback, NULL, NULL);

	/* Set Powered On */
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);

	/* Device 1 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_1),
					set_device_flags_param_1,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 2 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_2),
					add_device_le_public_param_2,
					setup_add_device_callback, NULL, NULL);
}

static const uint8_t set_device_flags_param_3[] = {
	0x33, 0x33, 0x33, 0x44, 0x55, 0x66,	/* BDADDR */
	0x01,					/* Type - LE Public */
	0x06, 0x00, 0x00, 0x00			/* Flags -
						 * Device Privacy
						 * Address Resolution
						 */
};

static void setup_ll_privacy_3_devices(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	/* Add IRKs of 4 Devices */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_4_devices_param),
					load_irks_4_devices_param,
					setup_load_irks_callback, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);

	/* Device 1 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_1),
					set_device_flags_param_1,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 2 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_2),
					add_device_le_public_param_2,
					setup_add_device_callback, NULL, NULL);

	/* Device 2 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_2),
					set_device_flags_param_2,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 3 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_3),
					add_device_le_public_param_3,
					setup_add_device_callback, NULL, NULL);

	/* Device 3 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_3),
					set_device_flags_param_3,
					setup_set_device_flags_callback, NULL,
					NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_ll_privacy_set_flags_4(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	hciemu_set_central_le_rl_len(data->hciemu, 4);

	/* Add IRKs of 4 Devices */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_4_devices_param),
					load_irks_4_devices_param,
					setup_load_irks_callback, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);

	/* Device 1 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_1),
					set_device_flags_param_1,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 2 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_2),
					add_device_le_public_param_2,
					setup_add_device_callback, NULL, NULL);

	/* Device 2 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_2),
					set_device_flags_param_2,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 3 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_3),
					add_device_le_public_param_3,
					setup_add_device_callback, NULL, NULL);

	/* Device 3 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_3),
					set_device_flags_param_3,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 4 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_4),
					add_device_le_public_param_4,
					setup_add_device_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_ll_privacy_add_3(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	hciemu_set_central_le_al_len(data->hciemu, 2);

	/* Add IRKs of 3 Devices */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_3_devices_param),
					load_irks_3_devices_param,
					setup_load_irks_callback, NULL, NULL);

	/* Set Powered On */
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);

	/* Device 1 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_1),
					set_device_flags_param_1,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 2 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_2),
					add_device_le_public_param_2,
					setup_add_device_callback, NULL, NULL);

	/* Device 2 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_2),
					set_device_flags_param_2,
					setup_set_device_flags_callback, NULL,
					NULL);
}

/* Enable LL Privacy and Add 2 devices */
static void setup_ll_privacy_device2_discovry(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	uint8_t disc_param[] = { 0x06 };

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
	/* Load IRKs */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_2_devices_param),
					load_irks_2_devices_param,
					setup_load_irks_callback, NULL, NULL);

	/* Load Device1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_2),
					add_device_le_public_param_2,
					setup_add_device_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_START_DISCOVERY, data->mgmt_index,
					sizeof(disc_param), disc_param,
					setup_discovery_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_STOP_DISCOVERY, data->mgmt_index,
					sizeof(disc_param), disc_param,
					setup_discovery_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_REMOVE_DEVICE, data->mgmt_index,
					sizeof(add_device_rsp_le_public),
					add_device_rsp_le_public,
					setup_remove_device_callback,
					NULL, NULL);
}

/* Enable LL Privacy and Add Advertising */
static void setup_ll_privacy_add_4(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char param[] = { 0x01 };
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
					sizeof(adv_param), adv_param,
					setup_add_adv_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

/* Enable LL Privacy and Add Advertising */
static void setup_ll_privacy_set_flags_5(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char param[] = { 0x01 };
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	/* Add IRKs of Device1 */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_le_public_param_1),
					load_irks_le_public_param_1,
					setup_load_irks_callback, NULL, NULL);

	/* Set Powered On */
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	/* Add Advertising Instance */
	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
					sizeof(adv_param), adv_param,
					setup_add_adv_callback_adv, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);
}

static void setup_ll_privacy_set_flags_6(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char param[] = { 0x01 };
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	/* Add IRKs of Device1 and Device2 */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_2_devices_param),
					load_irks_2_devices_param,
					setup_load_irks_callback, NULL, NULL);

	/* Set Powered On */
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	/* Add Advertising Instance 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
					sizeof(adv_param), adv_param,
					setup_add_adv_callback_adv, NULL, NULL);

	/* Add Device 2 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_2),
					add_device_le_public_param_2,
					setup_add_device_callback, NULL, NULL);

	/* Device 2 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_2),
					set_device_flags_param_2,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);
}

static void setup_ll_privacy_adv_3_devices(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char param[] = { 0x01 };
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
					sizeof(adv_param), adv_param,
					setup_add_adv_callback, NULL, NULL);

	/* Add IRKs of 4 Devices */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_4_devices_param),
					load_irks_4_devices_param,
					setup_load_irks_callback, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);

	/* Device 1 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_1),
					set_device_flags_param_1,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 2 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_2),
					add_device_le_public_param_2,
					setup_add_device_callback, NULL, NULL);

	/* Device 2 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_2),
					set_device_flags_param_2,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 3 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_3),
					add_device_le_public_param_3,
					setup_add_device_callback, NULL, NULL);

	/* Device 3 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_3),
					set_device_flags_param_3,
					setup_set_device_flags_callback, NULL,
					NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_ll_privacy_adv_1_device_2_advs(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char param[] = { 0x01 };
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	/* Add IRKs of 4 Devices */
	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_4_devices_param),
					load_irks_4_devices_param,
					setup_load_irks_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);

	/* Device 1 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_1),
					set_device_flags_param_1,
					setup_set_device_flags_callback, NULL,
					NULL);

	/* Add Device 2 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_2),
					add_device_le_public_param_2,
					setup_add_device_callback, NULL, NULL);

	/* Device 2 Flags */
	mgmt_send(data->mgmt, MGMT_OP_SET_DEVICE_FLAGS, data->mgmt_index,
					sizeof(set_device_flags_param_2),
					set_device_flags_param_2,
					setup_set_device_flags_callback, NULL,
					NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
					sizeof(adv_param), adv_param,
					setup_add_adv_callback_adv, NULL, NULL);
}

static void setup_add_2_advertisings(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding advertising instance while powered");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_adv_callback_adv,
						NULL, NULL);
}

static void setup_add_2_advertisings_no_power(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	tester_print("Adding advertising instance while not powered");

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
						sizeof(adv_param), adv_param,
						setup_add_adv_callback_adv,
						NULL, NULL);
}

static void setup_ll_privacy_enable_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };
	struct bthost *bthost;

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_scan_params(bthost, 0x01, 0x00, 0x00);
	bthost_set_scan_enable(bthost, 0x01);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_ll_privacy_add_adv(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	unsigned char param[] = { 0x01 };
	unsigned char set_adv_param[] = { 0x02 };
	struct bthost *bthost;

	/* Setup bthost to enable the scan */
	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_scan_params(bthost, 0x01, 0x00, 0x00);
	bthost_set_scan_enable(bthost, 0x01);

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_BONDABLE, data->mgmt_index,
						sizeof(param), &param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_IO_CAPABILITY, data->mgmt_index,
					sizeof(test->io_cap), &test->io_cap,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_ADVERTISING, data->mgmt_index,
						sizeof(set_adv_param),
						&set_adv_param,
						NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void setup_ll_privacy_add_device(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	mgmt_send(data->mgmt, MGMT_OP_LOAD_IRKS, data->mgmt_index,
					sizeof(load_irks_le_public_param_1),
					load_irks_le_public_param_1,
					setup_load_irks_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_le_public_param_1),
					add_device_le_public_param_1,
					setup_add_device_callback, NULL, NULL);

}

static bool power_off(uint16_t index)
{
	int sk, err;

	sk = hci_open_dev(index);
	if (sk < 0)
		return false;

	err = ioctl(sk, HCIDEVDOWN, index);

	hci_close_dev(sk);

	if (err < 0)
		return false;

	return true;
}

/* Read HCI commands in the expect_hci_list and add it to the queue
 */
static void add_expect_hci_list(struct test_data *data)
{
	const struct generic_data *test = data->test_data;
	const struct hci_cmd_data *hci_cmd_data;

	/* Initialize the queue */
	data->expect_hci_q = queue_new();

	hci_cmd_data = test->expect_hci_list;
	for (; hci_cmd_data->opcode; hci_cmd_data++) {
		struct hci_entry *entry;

		entry = new0(struct hci_entry, 1);
		entry->cmd_data = hci_cmd_data;
		queue_push_tail(data->expect_hci_q, entry);

		test_add_condition(data);
	}
}

static void test_command_generic(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const void *send_param = test->send_param;
	uint16_t send_len = test->send_len;
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

	if (test->expect_alt_ev) {
		tester_print("Registering %s notification",
					mgmt_evstr(test->expect_alt_ev));
		id = mgmt_register(data->mgmt_alt, test->expect_alt_ev, index,
					command_generic_event_alt, NULL, NULL);
		data->mgmt_alt_ev_id = id;
		test_add_condition(data);
	}

	if (test->expect_hci_command) {
		tester_print("Registering HCI command callback");
		hciemu_add_central_post_command_hook(data->hciemu,
						command_hci_callback, data);
		test_add_condition(data);
	} else if (test->expect_hci_list) {
		/* Use this when it needs to check more than 1 hci command.
		 * However, it cannot be used with expect_hci_command.
		 */
		tester_print("Registering HCI command list callback");
		hciemu_add_central_post_command_hook(data->hciemu,
					command_hci_list_callback, data);
		add_expect_hci_list(data);
	}

	if (test->send_opcode == 0x0000) {
		tester_print("Executing no-op test");
		return;
	}

	tester_print("Sending %s (0x%04x)", mgmt_opstr(test->send_opcode),
							test->send_opcode);

	if (test->send_func)
		send_param = test->send_func(&send_len);

	if (test->force_power_off) {
		mgmt_send_nowait(data->mgmt, test->send_opcode, index,
					send_len, send_param,
					command_generic_callback, NULL, NULL);
		power_off(data->mgmt_index);
	} else {
		mgmt_send(data->mgmt, test->send_opcode, index, send_len,
					send_param, command_generic_callback,
					NULL, NULL);
	}

	test_add_condition(data);
}

static void setup_set_static_addr_success_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	/* Force use of static address */
	err = vhci_set_force_static_address(vhci, true);
	if (err) {
		tester_warn("Unable to set force_static_address: %s (%d)",
					strerror(-err), -err);
		tester_test_failed();
		return;
	}
	setup_command_generic(test_data);
}

static void check_scan(void *user_data)
{
	struct test_data *data = tester_get_data();

	if (hciemu_get_central_le_scan_enable(data->hciemu)) {
		tester_warn("LE scan still enabled");
		tester_test_failed();
		return;
	}

	if (hciemu_get_central_scan_enable(data->hciemu)) {
		tester_warn("BR/EDR scan still enabled");
		tester_test_failed();
		return;
	}

	test_condition_complete(data);
}

static void test_remove_device(const void *test_data)
{
	struct test_data *data = tester_get_data();

	test_command_generic(test_data);
	tester_wait(1, check_scan, NULL);
	test_add_condition(data);
}

static bool hook_delay_cmd(const void *data, uint16_t len, void *user_data)
{
	tester_print("Delaying emulator response...");
	g_usleep(250000);
	tester_print("Delaying emulator response... Done.");
	return true;
}

static void test_add_remove_device_nowait(const void *test_data)
{
	struct test_data *data = tester_get_data();

	/* Add and remove LE device with autoconnect without waiting for reply,
	 * while delaying emulator response to better hit a race condition.
	 * This shall not crash the kernel (but eg Linux 6.4-rc4 crashes).
	 */

	tester_print("Adding and removing a device");

	test_add_condition(data);

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_CMD,
					BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST,
					hook_delay_cmd, NULL);

	mgmt_send_nowait(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
				sizeof(add_device_success_param_3),
				add_device_success_param_3, NULL, NULL, NULL);

	mgmt_send_nowait(data->mgmt, MGMT_OP_REMOVE_DEVICE, data->mgmt_index,
				sizeof(remove_device_param_2),
				remove_device_param_2,
				command_generic_callback, NULL, NULL);
}

static void trigger_device_found(void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bthost *bthost;

	bthost = hciemu_client_get_host(data->hciemu);

	if ((data->hciemu_type == HCIEMU_TYPE_LE) ||
				(data->hciemu_type == HCIEMU_TYPE_BREDRLE)) {
		if (test->set_adv)
			bthost_set_adv_data(bthost, test->adv_data,
							test->adv_data_len);

		bthost_set_adv_enable(bthost, 0x01);
	} else if (data->hciemu_type >= HCIEMU_TYPE_BREDRLE50) {
		bthost_set_ext_adv_params(bthost, 0x00);
		if (test->set_adv)
			bthost_set_ext_adv_data(bthost, test->adv_data,
							test->adv_data_len);

		bthost_set_ext_adv_enable(bthost, 0x01);
	}

	if (data->hciemu_type != HCIEMU_TYPE_LE)
		bthost_write_scan_enable(bthost, 0x03);

	test_condition_complete(data);
}

static void test_device_found(const void *test_data)
{
	struct test_data *data = tester_get_data();

	test_command_generic(test_data);

	/* Make sure discovery is enabled before enabling advertising. */
	tester_wait(1, trigger_device_found, NULL);
	test_add_condition(data);
}

static void pairing_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	tester_print("New connection with handle 0x%04x", handle);

	bthost = hciemu_client_get_host(data->hciemu);

	bthost_request_auth(bthost, handle);
}

static void test_pairing_acceptor(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const uint8_t *central_bdaddr;
	struct bthost *bthost;
	uint8_t addr_type;

	if (test->expect_alt_ev) {
		unsigned int id;

		tester_print("Registering %s notification",
					mgmt_evstr(test->expect_alt_ev));
		id = mgmt_register(data->mgmt_alt, test->expect_alt_ev,
					data->mgmt_index,
					command_generic_event_alt, NULL, NULL);
		data->mgmt_alt_ev_id = id;
		test_add_condition(data);
	}

	central_bdaddr = hciemu_get_central_bdaddr(data->hciemu);
	if (!central_bdaddr) {
		tester_warn("No central bdaddr");
		tester_test_failed();
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_connect_cb(bthost, pairing_new_conn, data);

	if (data->hciemu_type == HCIEMU_TYPE_BREDRLE)
		addr_type = BDADDR_BREDR;
	else
		addr_type = BDADDR_LE_PUBLIC;

	bthost_hci_connect(bthost, central_bdaddr, addr_type);
}


static void check_le_ext_adv_discovery(void *user_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *adv_addr;
	struct bthost *bthost;

	adv_addr = hciemu_get_central_adv_addr(data->hciemu, 0x00);
	if (!adv_addr) {
		tester_warn("No EXT ADV Address");
		tester_test_failed();
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);
	if (bthost_search_ext_adv_addr(bthost, adv_addr))
		tester_test_passed();
	else
		tester_test_failed();

	test_condition_complete(data);
}

static void test_ll_privacy_bthost_scan_report(const void *test_data)
{
	struct test_data *data = tester_get_data();

	test_command_generic(test_data);
	tester_wait(1, check_le_ext_adv_discovery, NULL);
	test_add_condition(data);
}

static void test_pairing_acceptor_ll_privacy_le_random(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const uint8_t *adv_addr;
	struct bthost *bthost;

	if (test->expect_alt_ev) {
		unsigned int id;

		tester_print("Registering %s notification",
					mgmt_evstr(test->expect_alt_ev));
		id = mgmt_register(data->mgmt_alt, test->expect_alt_ev,
					data->mgmt_index,
					command_generic_event_alt, NULL, NULL);
		data->mgmt_alt_ev_id = id;
		test_add_condition(data);
	}

	adv_addr = hciemu_get_central_adv_addr(data->hciemu, 0x00);
	if (!adv_addr) {
		tester_warn("No EXT ADV Address");
		tester_test_failed();
		return;
	}

	tester_print("Ext Adv Address: %02x:%02x:%02x:%02x:%02x:%02x",
			adv_addr[0], adv_addr[1], adv_addr[2],
			adv_addr[3], adv_addr[4], adv_addr[5]);

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_connect_cb(bthost, pairing_new_conn, data);

	bthost_hci_ext_connect(bthost, adv_addr, BDADDR_LE_RANDOM);
}

static void new_link_key_evt_pair_2_callback(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("New %s event received", mgmt_evstr(MGMT_EV_NEW_LINK_KEY));

	mgmt_unregister(data->mgmt, data->mgmt_discov_ev_id);

	/* TODO: validate the event */
	test_condition_complete(data);
}

static void test_ll_privacy_pair_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned int id;

	test_command_generic(test_data);

	tester_print("Registering New Link Key notification");
	id = mgmt_register(data->mgmt, MGMT_EV_NEW_LINK_KEY,
			   data->mgmt_index, new_link_key_evt_pair_2_callback,
			   NULL, NULL);
	/* Reuse the variable */
	data->mgmt_discov_ev_id = id;
	test_add_condition(data);
}

static void unpair_device_command_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("%s (0x%04x): %s (0x%02x)",
		     mgmt_opstr(MGMT_OP_UNPAIR_DEVICE),
		     MGMT_OP_UNPAIR_DEVICE, mgmt_errstr(status), status);

	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Unexpected status got %d expected %d",
						status, MGMT_STATUS_SUCCESS);
		tester_test_failed();
		return;
	}
	test_condition_complete(data);
}

static void unpair_device(void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Sending %s (0x%04x)", mgmt_opstr(MGMT_OP_UNPAIR_DEVICE),
							MGMT_OP_UNPAIR_DEVICE);

	/* Send Unpair command */
	mgmt_send(data->mgmt, MGMT_OP_UNPAIR_DEVICE, data->mgmt_index,
		  sizeof(unpair_client_1), unpair_client_1,
		  unpair_device_command_callback, NULL, NULL);
	test_add_condition(data);
}

static void disconnect_device_command_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("%s (0x%04x): %s (0x%02x)",
		     mgmt_opstr(MGMT_OP_DISCONNECT),
		     MGMT_OP_DISCONNECT, mgmt_errstr(status), status);

	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Unexpected status got %d expected %d",
						status, MGMT_STATUS_SUCCESS);
		tester_test_failed();
		return;
	}
	test_condition_complete(data);

	unpair_device(NULL);
}

static void unpair_disconnect_device(void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Sending %s (0x%04x)", mgmt_opstr(MGMT_OP_DISCONNECT),
							MGMT_OP_DISCONNECT);

	/* Send Unpair command */
	mgmt_send(data->mgmt, MGMT_OP_DISCONNECT, data->mgmt_index,
		  sizeof(remove_paired_device_1), remove_paired_device_1,
		  disconnect_device_command_callback, NULL, NULL);

	test_add_condition(data);
}

static void new_link_key_evt_unpair_callback(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("New %s event received", mgmt_evstr(MGMT_EV_NEW_LINK_KEY));

	mgmt_unregister(data->mgmt, data->mgmt_discov_ev_id);

	/* TODO: validate the event */
	test_condition_complete(data);

	/* Wait 1 sec for pairing command complete event */
	tester_wait(1, unpair_disconnect_device, NULL);
}

static void test_ll_privacy_unpair(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned int id;

	test_command_generic(test_data);

	tester_print("Registering New Link Key notification");
	id = mgmt_register(data->mgmt, MGMT_EV_NEW_LINK_KEY,
			   data->mgmt_index, new_link_key_evt_unpair_callback,
			   NULL, NULL);
	/* Reuse the variable */
	data->mgmt_discov_ev_id = id;
	test_add_condition(data);
}

static void remove_device_command_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("%s (0x%04x): %s (0x%02x)",
		     mgmt_opstr(MGMT_OP_REMOVE_DEVICE),
		     MGMT_OP_REMOVE_DEVICE, mgmt_errstr(status), status);

	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Unexpected status got %d expected %d",
						status, MGMT_STATUS_SUCCESS);
		tester_test_failed();
		return;
	}
	test_condition_complete(data);

	unpair_device(NULL);
}

static void remove_device(void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Sending %s (0x%04x)", mgmt_opstr(MGMT_OP_REMOVE_DEVICE),
							MGMT_OP_REMOVE_DEVICE);

	/* Send Unpair command */
	mgmt_send(data->mgmt, MGMT_OP_REMOVE_DEVICE, data->mgmt_index,
		  sizeof(remove_paired_device_1), remove_paired_device_1,
		  remove_device_command_callback, NULL, NULL);
	test_add_condition(data);
}

static void add_device_2_command_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("%s (0x%04x): %s (0x%02x)",
		     mgmt_opstr(MGMT_OP_ADD_DEVICE),
		     MGMT_OP_ADD_DEVICE, mgmt_errstr(status), status);

	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Unexpected status got %d expected %d",
						status, MGMT_STATUS_SUCCESS);
		tester_test_failed();
		return;
	}

	test_condition_complete(data);

	remove_device(NULL);
}

static void add_device_2(void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Sending %s (0x%04x)", mgmt_opstr(MGMT_OP_ADD_DEVICE),
							MGMT_OP_ADD_DEVICE);

	/* Send Add Device command */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
		  sizeof(add_device_le_public_param_1),
		  add_device_le_public_param_1,
		  add_device_2_command_callback, NULL, NULL);

	test_add_condition(data);
}

static void add_device_command_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("%s (0x%04x): %s (0x%02x)",
		     mgmt_opstr(MGMT_OP_ADD_DEVICE),
		     MGMT_OP_ADD_DEVICE, mgmt_errstr(status), status);

	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Unexpected status got %d expected %d",
						status, MGMT_STATUS_SUCCESS);
		tester_test_failed();
		return;
	}
	test_condition_complete(data);

	add_device_2(NULL);
}

static void add_device(void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Sending %s (0x%04x)", mgmt_opstr(MGMT_OP_ADD_DEVICE),
							MGMT_OP_ADD_DEVICE);

	/* Send Unpair command */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
		  sizeof(add_paired_client_1), add_paired_client_1,
		  add_device_command_callback, NULL, NULL);
	test_add_condition(data);
}

static void unpair_2_disconnect_command_callback(uint8_t status,
						 uint16_t length,
						 const void *param,
						 void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("%s (0x%04x): %s (0x%02x)",
		     mgmt_opstr(MGMT_OP_DISCONNECT),
		     MGMT_OP_DISCONNECT, mgmt_errstr(status), status);

	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Unexpected status got %d expected %d",
						status, MGMT_STATUS_SUCCESS);
		tester_test_failed();
		return;
	}
	test_condition_complete(data);

	add_device(NULL);
}

static void unpair_2_disconnect_device(void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Sending %s (0x%04x)", mgmt_opstr(MGMT_OP_DISCONNECT),
							MGMT_OP_DISCONNECT);

	/* Send Unpair command */
	mgmt_send(data->mgmt, MGMT_OP_DISCONNECT, data->mgmt_index,
		  sizeof(remove_paired_device_1), remove_paired_device_1,
		  unpair_2_disconnect_command_callback, NULL, NULL);

	test_add_condition(data);
}

static void new_link_key_evt_add_dev_callback(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("New %s event received", mgmt_evstr(MGMT_EV_NEW_LINK_KEY));

	mgmt_unregister(data->mgmt, data->mgmt_discov_ev_id);

	/* TODO: validate the event */
	test_condition_complete(data);

	/* Wait 1 sec for pairing command complete event */
	tester_wait(1, unpair_2_disconnect_device, NULL);
}

static void test_ll_privacy_unpair_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned int id;

	test_command_generic(test_data);

	tester_print("Registering New Link Key notification");
	id = mgmt_register(data->mgmt, MGMT_EV_NEW_LINK_KEY,
			   data->mgmt_index, new_link_key_evt_add_dev_callback,
			   NULL, NULL);
	/* Reuse the variable */
	data->mgmt_discov_ev_id = id;
	test_add_condition(data);
}

static void connected_event(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const void *send_param = test->send_param;
	uint16_t send_len = test->send_len;

	tester_print("Sending %s 0x%04x", mgmt_opstr(test->send_opcode),
							test->send_opcode);

	if (test->send_func)
		send_param = test->send_func(&send_len);

	if (test->force_power_off) {
		mgmt_send_nowait(data->mgmt, test->send_opcode, index,
					send_len, send_param,
					command_generic_callback, NULL, NULL);
		power_off(data->mgmt_index);
	} else {
		mgmt_send(data->mgmt, test->send_opcode, index, send_len,
					send_param, command_generic_callback,
					NULL, NULL);
	}

	test_add_condition(data);

	/* Complete MGMT_EV_DEVICE_CONNECTED *after* adding new one */
	test_condition_complete(data);
}

static void test_command_generic_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned int id;
	const uint8_t *central_bdaddr;
	uint8_t addr_type;
	struct bthost *bthost;

	tester_print("Registering %s notification",
					mgmt_evstr(MGMT_EV_DEVICE_CONNECTED));
	id = mgmt_register(data->mgmt_alt, MGMT_EV_DEVICE_CONNECTED,
				data->mgmt_index, connected_event,
				NULL, NULL);
	data->mgmt_alt_ev_id = id;
	test_add_condition(data);

	central_bdaddr = hciemu_get_central_bdaddr(data->hciemu);
	if (!central_bdaddr) {
		tester_warn("No central bdaddr");
		tester_test_failed();
		return;
	}

	addr_type = data->hciemu_type == HCIEMU_TYPE_BREDRLE ? BDADDR_BREDR :
							BDADDR_LE_PUBLIC;
	tester_print("ADDR TYPE: %d", addr_type);
	bthost = hciemu_client_get_host(data->hciemu);
	bthost_hci_connect(bthost, central_bdaddr, addr_type);
}

static bool test_adv_enable_hook(const void *data, uint16_t len,
								void *user_data)
{
	struct test_data *test_data = user_data;
	const uint8_t *status = data;

	if (*status == 0) {
		tester_print("Advertising enabled");
		test_condition_complete(test_data);
	} else {
		tester_print("Advertising enabled error 0x%02x", *status);
	}

	return true;
}

static void disconnected_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	tester_test_failed();
}

static void le_connected_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Device connected");

	if (data->hciemu_type < HCIEMU_TYPE_BREDRLE50) {
		test_add_condition(data);
		hciemu_add_hook(data->hciemu, HCIEMU_HOOK_POST_CMD,
					BT_HCI_CMD_LE_SET_ADV_ENABLE,
					test_adv_enable_hook, data);
	}

	/* Make sure we get not disconnected during the testaces */
	mgmt_register(data->mgmt_alt, MGMT_EV_DEVICE_DISCONNECTED,
				data->mgmt_index, disconnected_event,
				NULL, NULL);

	test_condition_complete(data);
}

static void add_device_callback(uint8_t status, uint16_t len, const void *param,
							void *user_data)
{
	struct test_data *data = user_data;
	const struct generic_data *test = data->test_data;
	struct bthost *bthost;
	const uint8_t *central_bdaddr;

	if (status != 0) {
		tester_test_failed();
		return;
	}

	tester_print("Device added");

	/* If advertising is enabled on client that means we can stop here and
	 * just wait for connection
	 */
	if (test->client_enable_adv)
		return;

	central_bdaddr = hciemu_get_central_bdaddr(data->hciemu);
	if (!central_bdaddr) {
		tester_warn("No central bdaddr");
		tester_test_failed();
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);
	if (data->hciemu_type >= HCIEMU_TYPE_BREDRLE50)
		bthost_hci_ext_connect(bthost, central_bdaddr,
		BDADDR_LE_PUBLIC);
	else
		bthost_hci_connect(bthost, central_bdaddr, BDADDR_LE_PUBLIC);
}

static void test_connected_and_advertising(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const uint8_t *client_bdaddr;
	struct mgmt_cp_add_device cp;

	tester_print("Registering %s notification",
					mgmt_evstr(MGMT_EV_DEVICE_CONNECTED));

	test_add_condition(data);
	mgmt_register(data->mgmt_alt, MGMT_EV_DEVICE_CONNECTED,
				data->mgmt_index, le_connected_event,
				NULL, NULL);

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (!client_bdaddr) {
		tester_warn("No client bdaddr");
		tester_test_failed();
		return;
	}

	memset(&cp, 0, sizeof(cp));
	memcpy(&cp.addr.bdaddr, client_bdaddr, 6);
	cp.addr.type = BDADDR_LE_PUBLIC;

	if (test->client_enable_adv)
		cp.action = 0x02; /* Auto connect */
	else
		cp.action = 0x01; /* Allow incoming connection */

	mgmt_send(data->mgmt_alt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
						sizeof(cp), &cp,
						add_device_callback,
						data, NULL);
}

static void read_50_controller_cap_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = user_data;
	const struct mgmt_rp_read_controller_cap *rp = param;
	const uint8_t *ptr = rp->cap;
	size_t offset = 0;
	uint8_t tag_len;
	uint8_t tag_type;

	if (status || !param) {
		tester_warn("Failed to read advertising features: %s (0x%02x)",
						mgmt_errstr(status), status);
		tester_test_failed();
		return;
	}

	if (sizeof(rp->cap_len) + rp->cap_len != length) {
		tester_warn("Controller capabilities malformed, size %zu != %u",
				sizeof(rp->cap_len) + rp->cap_len, length);
		tester_test_failed();
		return;
	}

	while (offset < rp->cap_len) {
		tag_len = ptr[offset++];
		tag_type = ptr[offset++];

		switch (tag_type) {
		case MGMT_CAP_LE_TX_PWR:
			if ((tag_len - sizeof(tag_type)) != 2) {
				tester_warn("TX power had unexpected length %d",
					tag_len);
				break;
			}
			tester_print("Expected Tx Power discovered: %d-%d",
					ptr[offset], ptr[offset+1]);
			test_condition_complete(data);
		}

		/* Step to the next entry */
		offset += (tag_len - sizeof(tag_type));
	}
}

static void test_50_controller_cap_response(const void *test_data)
{
	struct test_data *data = tester_get_data();

	test_add_condition(data);

	mgmt_send(data->mgmt_alt, MGMT_OP_READ_CONTROLLER_CAP, data->mgmt_index,
						0, NULL,
						read_50_controller_cap_complete,
						data, NULL);
}

static const uint8_t suspend_state_param_disconnect[] = {
	0x01,
};

static const uint8_t suspend_state_param_page_scan[] = {
	0x02,
};

static const uint8_t resume_state_param_non_bt_wake[] = {
	0x00,
	0x00, 0x00, 0x0, 0x00, 0x00, 0x00,
	0x00
};

static const struct generic_data suspend_resume_success_1 = {
	.setup_settings = settings_powered,
	.expect_alt_ev = MGMT_EV_CONTROLLER_SUSPEND,
	.expect_alt_ev_param = suspend_state_param_disconnect,
	.expect_alt_ev_len = sizeof(suspend_state_param_disconnect),
};

static void test_suspend_resume_success_1(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	/* Triggers the suspend */
	err = vhci_set_force_suspend(vhci, true);
	if (err) {
		tester_warn("Unable to enable the force_suspend");
		tester_test_failed();
		return;
	}
	test_command_generic(test_data);
}

static const struct generic_data suspend_resume_success_2 = {
	.setup_settings = settings_powered,
	.expect_alt_ev = MGMT_EV_CONTROLLER_RESUME,
	.expect_alt_ev_param = resume_state_param_non_bt_wake,
	.expect_alt_ev_len = sizeof(resume_state_param_non_bt_wake),
};

static void test_suspend_resume_success_2(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	/* Triggers the suspend */
	err = vhci_set_force_suspend(vhci, true);
	if (err) {
		tester_warn("Unable to enable the force_suspend");
		tester_test_failed();
		return;
	}

	/* Triggers the resume */
	err = vhci_set_force_suspend(vhci, false);
	if (err) {
		tester_warn("Unable to enable the force_suspend");
		tester_test_failed();
		return;
	}
	test_command_generic(test_data);
}

static const struct generic_data suspend_resume_success_3 = {
	.setup_expect_hci_command = BT_HCI_CMD_LE_ADD_TO_ACCEPT_LIST,
	.setup_expect_hci_param = le_add_to_accept_list_param,
	.setup_expect_hci_len = sizeof(le_add_to_accept_list_param),
	.expect_alt_ev = MGMT_EV_CONTROLLER_SUSPEND,
	.expect_alt_ev_param = suspend_state_param_disconnect,
	.expect_alt_ev_len = sizeof(suspend_state_param_disconnect),
};

static void setup_suspend_resume_success_3(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	/* Add Device 1 */
	mgmt_send(data->mgmt, MGMT_OP_ADD_DEVICE, data->mgmt_index,
					sizeof(add_device_success_param_3),
					add_device_success_param_3,
					setup_add_device_callback,
					NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void test_suspend_resume_success_3(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	/* Triggers the suspend */
	err = vhci_set_force_suspend(vhci, true);
	if (err) {
		tester_warn("Unable to enable the force_suspend");
		tester_test_failed();
		return;
	}
	test_command_generic(test_data);
}

static const struct generic_data suspend_resume_success_4 = {
	.setup_expect_hci_command = BT_HCI_CMD_LE_SET_EXT_ADV_ENABLE,
	.setup_expect_hci_param = set_ext_adv_on_set_adv_enable_param,
	.setup_expect_hci_len = sizeof(set_ext_adv_on_set_adv_enable_param),
	.expect_alt_ev = MGMT_EV_CONTROLLER_SUSPEND,
	.expect_alt_ev_param = suspend_state_param_disconnect,
	.expect_alt_ev_len = sizeof(suspend_state_param_disconnect),
};

static void setup_suspend_resume_success_4(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_add_advertising *cp;
	unsigned char adv_param[sizeof(*cp) + TESTER_ADD_ADV_DATA_LEN];
	unsigned char param[] = { 0x01 };

	cp = (struct mgmt_cp_add_advertising *) adv_param;
	setup_add_adv_param(cp, 1);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
					sizeof(param), &param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_ADD_ADVERTISING, data->mgmt_index,
					sizeof(adv_param), adv_param,
					setup_add_advertising_callback,
					NULL, NULL);
}

static void test_suspend_resume_success_4(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	test_command_generic(test_data);

	/* Triggers the suspend */
	tester_print("Set the system into Suspend via force_suspend");
	err = vhci_set_force_suspend(vhci, true);
	if (err) {
		tester_warn("Unable to enable the force_suspend");
		tester_test_failed();
		return;
	}
}

static const struct generic_data suspend_resume_success_5 = {
	.setup_settings = settings_powered_connectable_bondable,
	.pin = pair_device_pin,
	.pin_len = sizeof(pair_device_pin),
	.client_pin = pair_device_pin,
	.client_pin_len = sizeof(pair_device_pin),
	.expect_alt_ev = MGMT_EV_CONTROLLER_SUSPEND,
	.expect_alt_ev_param = suspend_state_param_disconnect,
	.expect_alt_ev_len = sizeof(suspend_state_param_disconnect),
};

static void trigger_force_suspend(void *user_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	/* Triggers the suspend */
	tester_print("Set the system into Suspend via force_suspend");
	err = vhci_set_force_suspend(vhci, true);
	if (err) {
		tester_warn("Unable to enable the force_suspend");
		return;
	}
}

static void trigger_force_resume(void *user_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	/* Triggers the suspend */
	tester_print("Set the system into Resume via force_suspend");
	err = vhci_set_force_suspend(vhci, false);
	if (err) {
		tester_warn("Unable to disable the force_suspend");
		return;
	}
}

static void test_suspend_resume_success_5(const void *test_data)
{
	test_pairing_acceptor(test_data);
	tester_wait(1, trigger_force_suspend, NULL);
}

static const struct generic_data suspend_resume_success_6 = {
	.setup_settings = settings_powered_connectable_bondable_ssp,
	.client_enable_ssp = true,
	.expect_alt_ev = MGMT_EV_CONTROLLER_SUSPEND,
	.expect_alt_ev_param = suspend_state_param_disconnect,
	.expect_alt_ev_len = sizeof(suspend_state_param_disconnect),
	.expect_hci_command = BT_HCI_CMD_USER_CONFIRM_REQUEST_REPLY,
	.expect_hci_func = client_bdaddr_param_func,
	.io_cap = 0x03, /* NoInputNoOutput */
	.client_io_cap = 0x03, /* NoInputNoOutput */
	.just_works = true,
};

static const struct generic_data suspend_resume_success_7 = {
	.setup_settings = settings_powered,
	.expect_alt_ev = MGMT_EV_CONTROLLER_SUSPEND,
	.expect_alt_ev_param = suspend_state_param_page_scan,
	.expect_alt_ev_len = sizeof(suspend_state_param_page_scan),
};

static void test_suspend_resume_success_7(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	int err;

	/* Set Force Wakeup */
	err = vhci_set_force_wakeup(vhci, true);
	if (err) {
		tester_warn("Unable to enable the force_wakeup");
		tester_test_failed();
		return;
	}

	/* Triggers the suspend */
	err = vhci_set_force_suspend(vhci, true);
	if (err) {
		tester_warn("Unable to enable the force_suspend");
		tester_test_failed();
		return;
	}
	test_command_generic(test_data);
}

static const struct generic_data suspend_resume_success_8 = {
	.setup_settings = settings_powered_le,
	.send_opcode = MGMT_OP_START_DISCOVERY,
	.send_param = start_discovery_le_param,
	.send_len = sizeof(start_discovery_le_param),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_param = start_discovery_le_param,
	.expect_len = sizeof(start_discovery_le_param),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_ext_scan_enable,
	.expect_hci_len = sizeof(start_discovery_valid_ext_scan_enable),
	.expect_alt_ev = MGMT_EV_CONTROLLER_SUSPEND,
	.expect_alt_ev_param = suspend_state_param_disconnect,
	.expect_alt_ev_len = sizeof(suspend_state_param_disconnect),
};

static void test_suspend_resume_success_8(const void *test_data)
{
	test_command_generic(test_data);
	tester_wait(1, trigger_force_suspend, NULL);
}

static uint16_t settings_powered_le_discovery[] = { MGMT_OP_SET_LE,
						    MGMT_OP_SET_POWERED,
						    MGMT_OP_START_DISCOVERY,
						    0 };

static const struct generic_data suspend_resume_success_9 = {
	.setup_settings = settings_powered_le_discovery,
	.setup_discovery_param = start_discovery_bredrle_param,
	.setup_expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE,
	.setup_expect_hci_param = stop_discovery_valid_ext_scan_disable,
	.setup_expect_hci_len = sizeof(stop_discovery_valid_ext_scan_disable),
	.expect_hci_command = BT_HCI_CMD_LE_SET_EXT_SCAN_ENABLE,
	.expect_hci_param = start_discovery_valid_ext_scan_enable,
	.expect_hci_len = sizeof(start_discovery_valid_ext_scan_enable),
	.expect_alt_ev = MGMT_EV_CONTROLLER_RESUME,
	.expect_alt_ev_param = resume_state_param_non_bt_wake,
	.expect_alt_ev_len = sizeof(resume_state_param_non_bt_wake),
};

static void trigger_force_suspend_9(void *user_data)
{
	trigger_force_suspend(user_data);
}

static void setup_suspend_resume_success_9(const void *test_data)
{
	setup_command_generic(test_data);
	tester_wait(1, trigger_force_suspend_9, NULL);
}

static void test_suspend_resume_success_9(const void *test_data)
{
	test_command_generic(test_data);
	tester_wait(2, trigger_force_resume, NULL);
}

static const struct generic_data suspend_resume_success_10 = {
	.setup_settings = settings_powered_le,
	.expect_alt_ev = MGMT_EV_CONTROLLER_RESUME,
	.expect_alt_ev_param = resume_state_param_non_bt_wake,
	.expect_alt_ev_len = sizeof(resume_state_param_non_bt_wake),
};

static void resume_event(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_ev_controller_resume *ev = param;

	mgmt_unregister(data->mgmt, data->mgmt_discov_ev_id);

	if (length != sizeof(*ev)) {
		tester_warn("Incorrect resume event length");
		tester_setup_failed();
		return;
	}

	tester_print("New Controller Resume event received");
	test_condition_complete(data);
	tester_setup_complete();
}


static void setup_suspend_resume_success_10(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned int id;

	tester_print("Registering Controller Resume notification");
	id = mgmt_register(data->mgmt, MGMT_EV_CONTROLLER_RESUME,
			   data->mgmt_index, resume_event, NULL, NULL);
	/* Reuse the variable */
	data->mgmt_discov_ev_id = id;
	test_add_condition(data);

	tester_wait(1, trigger_force_suspend, NULL);
	tester_wait(2, trigger_force_resume, NULL);
}

static void test_suspend_resume_success_10(const void *test_data)
{
	test_command_generic(test_data);
	tester_wait(1, trigger_force_suspend, NULL);
	tester_wait(2, trigger_force_resume, NULL);
}

#define MAX_COREDUMP_BUF_LEN	512

static const struct devcoredump_test_data data_complete_dump = {
	.state = HCI_DEVCOREDUMP_DONE,
	.data = "test data",
};

static const char expected_complete_dump[][MAX_COREDUMP_LINE_LEN] = {
	"Bluetooth devcoredump",
	"State: 2",
	"Controller Name: vhci_ctrl",
	"Firmware Version: vhci_fw",
	"Driver: vhci_drv",
	"Vendor: vhci",
	"--- Start dump ---",
	"", /* end of header data */
};

static const struct generic_data dump_complete = {
	.dump_data = &data_complete_dump,
	.expect_dump_data = expected_complete_dump,
};

static const struct devcoredump_test_data data_abort_dump = {
	.state = HCI_DEVCOREDUMP_ABORT,
	.data = "test data",
};

static const char expected_abort_dump[][MAX_COREDUMP_LINE_LEN] = {
	"Bluetooth devcoredump",
	"State: 3",
	"Controller Name: vhci_ctrl",
	"Firmware Version: vhci_fw",
	"Driver: vhci_drv",
	"Vendor: vhci",
	"--- Start dump ---",
	"", /* end of header data */
};

static const struct generic_data dump_abort = {
	.dump_data = &data_abort_dump,
	.expect_dump_data = expected_abort_dump,
};

static const struct devcoredump_test_data data_timeout_dump = {
	.state = HCI_DEVCOREDUMP_TIMEOUT,
	.timeout = 1,
	.data = "test data",
};

static const char expected_timeout_dump[][MAX_COREDUMP_LINE_LEN] = {
	"Bluetooth devcoredump",
	"State: 4",
	"Controller Name: vhci_ctrl",
	"Firmware Version: vhci_fw",
	"Driver: vhci_drv",
	"Vendor: vhci",
	"--- Start dump ---",
	"", /* end of header data */
};

static const struct generic_data dump_timeout = {
	.dump_data = &data_timeout_dump,
	.expect_dump_data = expected_timeout_dump,
};

static void verify_devcd(void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);
	char buf[MAX_COREDUMP_BUF_LEN + 1] = {0};
	int read;
	char delim[] = "\n";
	char *line;
	char *saveptr;
	int i = 0;

	/* Read the generated devcoredump file */
	read = vhci_read_devcd(vhci, buf, MAX_COREDUMP_BUF_LEN);
	if (read <= 0) {
		tester_warn("Unable to read devcoredump");
		tester_test_failed();
		return;
	}
	/* Make sure buf is nul-terminated */
	buf[read] = '\0';

	/* Verify if all devcoredump header fields are present */
	line = strtok_r(buf, delim, &saveptr);
	while (strlen(test->expect_dump_data[i])) {
		if (!line || strcmp(line, test->expect_dump_data[i])) {
			tester_warn("Incorrect coredump data: %s (expected %s)",
					line, test->expect_dump_data[i]);
			tester_test_failed();
			return;
		}

		if (!strcmp(strtok(line, ":"), "State")) {
			/* After updating the devcoredump state, the HCI
			 * devcoredump API adds a `\0` at the end. Skip it
			 * before reading the next line.
			 */
			saveptr++;
		}

		line = strtok_r(NULL, delim, &saveptr);
		i++;
	}

	/* Verify the devcoredump data */
	if (!line || strcmp(line, test->dump_data->data)) {
		tester_warn("Incorrect coredump data: %s (expected %s)", line,
				test->dump_data->data);
		tester_test_failed();
		return;
	}

	tester_test_passed();
}

static void test_hci_devcd(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct vhci *vhci = hciemu_get_vhci(data->hciemu);

	/* Triggers the devcoredump */
	if (vhci_force_devcd(vhci, test->dump_data, sizeof(*test->dump_data))) {
		tester_warn("Unable to set force_devcoredump");
		tester_test_abort();
		return;
	}

	tester_wait(test->dump_data->timeout + 1, verify_devcd, NULL);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_bredrle("Controller setup",
				NULL, NULL, controller_setup);
	test_bredr("Controller setup (BR/EDR-only)",
				NULL, NULL, controller_setup);
	test_le("Controller setup (LE)",
				NULL, NULL, controller_setup);

	test_bredrle("Invalid command",
				&invalid_command_test,
				NULL, test_command_generic);

	test_bredrle("Read version - Success",
				&read_version_success_test,
				NULL, test_command_generic);
	test_bredrle("Read version - Invalid parameters",
				&read_version_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read version - Invalid index",
				&read_version_invalid_index_test,
				NULL, test_command_generic);
	test_bredrle("Read commands - Invalid parameters",
				&read_commands_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read commands - Invalid index",
				&read_commands_invalid_index_test,
				NULL, test_command_generic);
	test_bredrle("Read index list - Invalid parameters",
				&read_index_list_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read index list - Invalid index",
				&read_index_list_invalid_index_test,
				NULL, test_command_generic);
	test_bredrle("Read info - Invalid parameters",
				&read_info_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read info - Invalid index",
				&read_info_invalid_index_test,
				NULL, test_command_generic);
	test_bredrle("Read unconfigured index list - Invalid parameters",
				&read_unconf_index_list_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read unconfigured index list - Invalid index",
				&read_unconf_index_list_invalid_index_test,
				NULL, test_command_generic);
	test_bredrle("Read configuration info - Invalid parameters",
				&read_config_info_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read configuration info - Invalid index",
				&read_config_info_invalid_index_test,
				NULL, test_command_generic);
	test_bredrle("Read extended index list - Invalid parameters",
				&read_ext_index_list_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read extended index list - Invalid index",
				&read_ext_index_list_invalid_index_test,
				NULL, test_command_generic);

	test_bredrle("Set powered on - Success",
				&set_powered_on_success_test,
				NULL, test_command_generic);
	test_bredrle("Set powered on - Invalid parameters 1",
				&set_powered_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set powered on - Invalid parameters 2",
				&set_powered_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set powered on - Invalid parameters 3",
				&set_powered_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set powered on - Invalid index",
				&set_powered_on_invalid_index_test,
				NULL, test_command_generic);
	test_le("Set powered on - Privacy and Advertising",
				&set_powered_on_privacy_adv_test,
				NULL, test_command_generic);

	test_bredrle("Set powered off - Success",
				&set_powered_off_success_test,
				NULL, test_command_generic);
	test_bredrle("Set powered off - Class of Device",
				&set_powered_off_class_test,
				setup_class, test_command_generic);
	test_bredrle("Set powered off - Invalid parameters 1",
				&set_powered_off_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set powered off - Invalid parameters 2",
				&set_powered_off_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set powered off - Invalid parameters 3",
				&set_powered_off_invalid_param_test_3,
				NULL, test_command_generic);

	test_bredrle("Set connectable on - Success 1",
				&set_connectable_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set connectable on - Success 2",
				&set_connectable_on_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set connectable on - Invalid parameters 1",
				&set_connectable_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set connectable on - Invalid parameters 2",
				&set_connectable_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set connectable on - Invalid parameters 3",
				&set_connectable_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set connectable on - Invalid index",
				&set_connectable_on_invalid_index_test,
				NULL, test_command_generic);

	test_le("Set connectable on (LE) - Success 1",
				&set_connectable_on_le_test_1,
				NULL, test_command_generic);
	test_le("Set connectable on (LE) - Success 2",
				&set_connectable_on_le_test_2,
				NULL, test_command_generic);
	test_le("Set connectable on (LE) - Success 3",
				&set_connectable_on_le_test_3,
				NULL, test_command_generic);

	test_bredrle("Set connectable off - Success 1",
				&set_connectable_off_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set connectable off - Success 2",
				&set_connectable_off_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set connectable off - Success 3",
				&set_connectable_off_success_test_3,
				NULL, test_command_generic);
	test_bredrle("Set connectable off - Success 4",
				&set_connectable_off_success_test_4,
				setup_add_device, test_command_generic);

	test_le("Set connectable off (LE) - Success 1",
				&set_connectable_off_le_test_1,
				NULL, test_command_generic);
	test_le("Set connectable off (LE) - Success 2",
				&set_connectable_off_le_test_2,
				NULL, test_command_generic);
	test_le("Set connectable off (LE) - Success 3",
				&set_connectable_off_le_test_3,
				NULL, test_command_generic);
	test_le("Set connectable off (LE) - Success 4",
				&set_connectable_off_le_test_4,
				NULL, test_command_generic);

	test_bredrle("Set fast connectable on - Success 1",
				&set_fast_conn_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set fast connectable on - Success 2",
				&set_fast_conn_on_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set fast connectable on - Success 3",
				&set_fast_conn_on_success_test_3,
				NULL, test_command_generic);
	test_bredrle("Set fast connectable on - Invalid Params 1",
				&set_fast_conn_nval_param_test_1,
				NULL, test_command_generic);
	test_le("Set fast connectable on - Not Supported 1",
				&set_fast_conn_on_not_supported_test_1,
				NULL, test_command_generic);

	test_bredrle("Set bondable on - Success",
				&set_bondable_on_success_test,
				NULL, test_command_generic);
	test_bredrle("Set bondable on - Invalid parameters 1",
				&set_bondable_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set bondable on - Invalid parameters 2",
				&set_bondable_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set bondable on - Invalid parameters 3",
				&set_bondable_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set bondable on - Invalid index",
				&set_bondable_on_invalid_index_test,
				NULL, test_command_generic);

	test_bredrle("Set discoverable on - Invalid parameters 1",
				&set_discoverable_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Invalid parameters 2",
				&set_discoverable_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Invalid parameters 3",
				&set_discoverable_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Invalid parameters 4",
				&set_discoverable_on_invalid_param_test_4,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Not powered 1",
				&set_discoverable_on_not_powered_test_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Not powered 2",
				&set_discoverable_on_not_powered_test_2,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Rejected 1",
				&set_discoverable_on_rejected_test_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Rejected 2",
				&set_discoverable_on_rejected_test_2,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Rejected 3",
				&set_discoverable_on_rejected_test_3,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Success 1",
				&set_discoverable_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable on - Success 2",
				&set_discoverable_on_success_test_2,
				NULL, test_command_generic);
	test_le("Set discoverable on (LE) - Success 1",
				&set_discov_on_le_success_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable off - Success 1",
				&set_discoverable_off_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set discoverable off - Success 2",
				&set_discoverable_off_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set limited discoverable on - Success 1",
				&set_limited_discov_on_success_1,
				NULL, test_command_generic);
	test_bredrle("Set limited discoverable on - Success 2",
				&set_limited_discov_on_success_2,
				NULL, test_command_generic);
	test_bredrle("Set limited discoverable on - Success 3",
				&set_limited_discov_on_success_3,
				NULL, test_command_generic);
	test_le("Set limited discoverable on (LE) - Success 1",
				&set_limited_discov_on_le_success_1,
				NULL, test_command_generic);

	test_bredrle("Set link security on - Success 1",
				&set_link_sec_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set link security on - Success 2",
				&set_link_sec_on_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set link security on - Success 3",
				&set_link_sec_on_success_test_3,
				NULL, test_command_generic);
	test_bredrle("Set link security on - Invalid parameters 1",
				&set_link_sec_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set link security on - Invalid parameters 2",
				&set_link_sec_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set link security on - Invalid parameters 3",
				&set_link_sec_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set link security on - Invalid index",
				&set_link_sec_on_invalid_index_test,
				NULL, test_command_generic);

	test_bredrle("Set link security off - Success 1",
				&set_link_sec_off_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set link security off - Success 2",
				&set_link_sec_off_success_test_2,
				NULL, test_command_generic);

	test_bredrle("Set SSP on - Success 1",
				&set_ssp_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set SSP on - Success 2",
				&set_ssp_on_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set SSP on - Success 3",
				&set_ssp_on_success_test_3,
				NULL, test_command_generic);
	test_bredrle("Set SSP on - Invalid parameters 1",
				&set_ssp_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set SSP on - Invalid parameters 2",
				&set_ssp_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set SSP on - Invalid parameters 3",
				&set_ssp_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set SSP on - Invalid index",
				&set_ssp_on_invalid_index_test,
				NULL, test_command_generic);

	test_bredrle("Set Secure Connections on - Success 1",
				&set_sc_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set Secure Connections on - Success 2",
				&set_sc_on_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set Secure Connections on - Invalid params 1",
				&set_sc_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set Secure Connections on - Invalid params 2",
				&set_sc_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set Secure Connections on - Invalid params 3",
				&set_sc_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set Secure Connections on - Invalid index",
				&set_sc_on_invalid_index_test,
				NULL, test_command_generic);
	test_bredr("Set Secure Connections on - Not supported 1",
				&set_sc_on_not_supported_test_1,
				NULL, test_command_generic);
	test_bredr("Set Secure Connections on - Not supported 2",
				&set_sc_on_not_supported_test_2,
				NULL, test_command_generic);

	test_bredrle("Set Secure Connections Only on - Success 1",
				&set_sc_only_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set Secure Connections Only on - Success 2",
				&set_sc_only_on_success_test_2,
				NULL, test_command_generic);

	test_bredrle("Set Low Energy on - Success 1",
				&set_le_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Success 2",
				&set_le_on_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Success 3",
				&set_le_on_success_test_3,
				NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Invalid parameters 1",
				&set_le_on_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Invalid parameters 2",
				&set_le_on_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Invalid parameters 3",
				&set_le_on_invalid_param_test_3,
				NULL, test_command_generic);
	test_bredrle("Set Low Energy on - Invalid index",
				&set_le_on_invalid_index_test,
				NULL, test_command_generic);

	test_bredrle("Set Advertising on - Success 1",
				&set_adv_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set Advertising on - Success 2",
				&set_adv_on_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Set Advertising on - Rejected 1",
				&set_adv_on_rejected_test_1,
				NULL, test_command_generic);

	test_bredrle("Set Advertising on - Appearance 1",
				&set_adv_on_appearance_test_1,
				setup_command_generic, test_command_generic);

	test_bredrle("Set Advertising on - Local name 1",
				&set_adv_on_local_name_test_1,
				setup_command_generic, test_command_generic);

	test_bredrle("Set Advertising on - Name + Appear 1",
				&set_adv_on_local_name_appear_test_1,
				setup_command_generic, test_command_generic);

	test_bredrle("Set BR/EDR off - Success 1",
				&set_bredr_off_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set BR/EDR on - Success 1",
				&set_bredr_on_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Set BR/EDR on - Success 2",
				&set_bredr_on_success_test_2,
				NULL, test_command_generic);
	test_bredr("Set BR/EDR off - Not Supported 1",
				&set_bredr_off_notsupp_test,
				NULL, test_command_generic);
	test_le("Set BR/EDR off - Not Supported 2",
				&set_bredr_off_notsupp_test,
				NULL, test_command_generic);
	test_bredrle("Set BR/EDR off - Rejected 1",
				&set_bredr_off_failure_test_1,
				NULL, test_command_generic);
	test_bredrle("Set BR/EDR off - Rejected 2",
				&set_bredr_off_failure_test_2,
				NULL, test_command_generic);
	test_bredrle("Set BR/EDR off - Invalid Parameters 1",
				&set_bredr_off_failure_test_3,
				NULL, test_command_generic);

	test_bredr("Set Local Name - Success 1",
				&set_local_name_test_1,
				NULL, test_command_generic);
	test_bredr("Set Local Name - Success 2",
				&set_local_name_test_2,
				NULL, test_command_generic);
	test_bredr("Set Local Name - Success 3",
				&set_local_name_test_3,
				NULL, test_command_generic);

	test_bredrle("Start Discovery - Not powered 1",
				&start_discovery_not_powered_test_1,
				NULL, test_command_generic);
	test_bredrle("Start Discovery - Invalid parameters 1",
				&start_discovery_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Start Discovery - Not supported 1",
				&start_discovery_not_supported_test_1,
				NULL, test_command_generic);
	test_bredrle("Start Discovery - Success 1",
				&start_discovery_valid_param_test_1,
				NULL, test_command_generic);
	test_le("Start Discovery - Success 2",
				&start_discovery_valid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Start Discovery - Power Off 1",
				&start_discovery_valid_param_power_off_1,
				NULL, test_command_generic);

	test_bredrle("Stop Discovery - Success 1",
				&stop_discovery_success_test_1,
				setup_start_discovery, test_command_generic);
	test_bredr("Stop Discovery - BR/EDR (Inquiry) Success 1",
				&stop_discovery_bredr_success_test_1,
				setup_start_discovery, test_command_generic);
	test_bredrle("Stop Discovery - Rejected 1",
				&stop_discovery_rejected_test_1,
				NULL, test_command_generic);
	test_bredrle("Stop Discovery - Invalid parameters 1",
				&stop_discovery_invalid_param_test_1,
				setup_start_discovery, test_command_generic);

	test_bredrle("Start Service Discovery - Not powered 1",
				&start_service_discovery_not_powered_test_1,
				NULL, test_command_generic);
	test_bredrle("Start Service Discovery - Invalid parameters 1",
				&start_service_discovery_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Start Service Discovery - Not supported 1",
				&start_service_discovery_not_supported_test_1,
				NULL, test_command_generic);
	test_bredrle("Start Service Discovery - Success 1",
				&start_service_discovery_valid_param_test_1,
				NULL, test_command_generic);
	test_le("Start Service Discovery - Success 2",
				&start_service_discovery_valid_param_test_2,
				NULL, test_command_generic);

	test_bredrle("Set Device Class - Success 1",
				&set_dev_class_valid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Set Device Class - Success 2",
				&set_dev_class_valid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Set Device Class - Invalid parameters 1",
				&set_dev_class_invalid_param_test_1,
				NULL, test_command_generic);

	test_bredrle("Add UUID - UUID-16 1",
				&add_uuid16_test_1,
				NULL, test_command_generic);
	test_bredrle("Add UUID - UUID-16 multiple 1",
				&add_multi_uuid16_test_1,
				setup_multi_uuid16, test_command_generic);
	test_bredrle("Add UUID - UUID-16 partial 1",
				&add_multi_uuid16_test_2,
				setup_multi_uuid16_2, test_command_generic);
	test_bredrle("Add UUID - UUID-32 1",
				&add_uuid32_test_1,
				NULL, test_command_generic);
	test_bredrle("Add UUID - UUID-32 multiple 1",
				&add_uuid32_multi_test_1,
				setup_multi_uuid32, test_command_generic);
	test_bredrle("Add UUID - UUID-32 partial 1",
				&add_uuid32_multi_test_2,
				setup_multi_uuid32_2, test_command_generic);
	test_bredrle("Add UUID - UUID-128 1",
				&add_uuid128_test_1,
				NULL, test_command_generic);
	test_bredrle("Add UUID - UUID-128 multiple 1",
				&add_uuid128_multi_test_1,
				setup_multi_uuid128, test_command_generic);
	test_bredrle("Add UUID - UUID-128 partial 1",
				&add_uuid128_multi_test_2,
				setup_multi_uuid128_2, test_command_generic);
	test_bredrle("Add UUID - UUID mix",
				&add_uuid_mix_test_1,
				setup_uuid_mix, test_command_generic);

	/* MGMT_OP_REMOVE_UUID
	 * Remove existing UUID.
	 */
	test_bredrle("Remove UUID - Success 1",
				&remove_uuid_success_1,
				setup_multi_uuid16, test_command_generic);
	/* MGMT_OP_REMOVE_UUID
	 * Remove all UUID by sending zero filled UUID
	 */
	test_bredrle("Remove UUID - All UUID - Success 2",
				&remove_uuid_all_success_2,
				setup_multi_uuid16, test_command_generic);
	/* MGMT_OP_REMOVE_UUID
	 * Remove UUID while powering off
	 * Expect the 0x000000 for the class of device
	 */
	test_bredrle("Remove UUID - Power Off - Success 3",
				&remove_uuid_power_off_success_3,
				setup_multi_uuid16_power_off,
				test_command_generic);
	/* MGMT_OP_REMOVE_UUID
	 * Remove UUID while powering off and then powering on
	 */
	test_bredrle("Remove UUID - Power Off and On - Success 4",
				&remove_uuid_power_off_on_success_4,
				setup_multi_uuid16_power_off_remove,
				test_command_generic);
	/* MGMT_OP_REMOVE_UUID
	 * Remove UUID doesn't exist - Invalid parameter
	 */
	test_bredrle("Remove UUID - Not Exist - Invalid Params 1",
				&remove_uuid_invalid_params_1,
				setup_multi_uuid16, test_command_generic);

	test_bredrle("Load Link Keys - Empty List Success 1",
				&load_link_keys_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Load Link Keys - Empty List Success 2",
				&load_link_keys_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Load Link Keys - Invalid Parameters 1",
				&load_link_keys_invalid_params_test_1,
				NULL, test_command_generic);
	test_bredrle("Load Link Keys - Invalid Parameters 2",
				&load_link_keys_invalid_params_test_2,
				NULL, test_command_generic);
	test_bredrle("Load Link Keys - Invalid Parameters 3",
				&load_link_keys_invalid_params_test_3,
				NULL, test_command_generic);

	test_bredrle("Load Long Term Keys - Success 1",
				&load_ltks_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Load Long Term Keys - Success 2",
				&load_ltks_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Load Long Term Keys - Success 3 (20 with count 1)",
				&load_ltks_success_test_3,
				setup_load_ltks_20_by_1, test_command_generic);
	test_bredrle("Load Long Term Keys - Success 4 (20 with count 20)",
				&load_ltks_success_test_4,
				NULL, test_command_generic);
	test_bredrle("Load Long Term Keys - Success 5 (Power On and 20 keys)",
				&load_ltks_success_test_5,
				NULL, test_command_generic);
	test_bredrle("Load Long Term Keys - Invalid Parameters 1",
				&load_ltks_invalid_params_test_1,
				NULL, test_command_generic);
	test_bredrle("Load Long Term Keys - Invalid Parameters 2",
				&load_ltks_invalid_params_test_2,
				NULL, test_command_generic);
	test_bredrle("Load Long Term Keys - Invalid Parameters 3",
				&load_ltks_invalid_params_test_3,
				NULL, test_command_generic);
	test_bredrle("Load Long Term Keys - Invalid Parameters 4",
				&load_ltks_invalid_params_test_4,
				NULL, test_command_generic);

	test_bredrle("Set IO Capability - Invalid Params 1",
				&set_io_cap_invalid_param_test_1,
				NULL, test_command_generic);

	test_bredrle("Pair Device - Not Powered 1",
				&pair_device_not_powered_test_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Power off 1",
				&pair_device_power_off_test_1,
				NULL, test_command_generic);
	test_le("Pair Device - Incorrect transport reject 1",
				&pair_device_not_supported_test_1,
				NULL, test_command_generic);
	test_bredr("Pair Device - Incorrect transport reject 2",
				&pair_device_not_supported_test_2,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Reject on not enabled transport 1",
				&pair_device_reject_transport_not_enabled_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Reject on not enabled transport 2",
				&pair_device_reject_transport_not_enabled_2,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Invalid Parameters 1",
				&pair_device_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Invalid Parameters 2",
				&pair_device_invalid_param_test_2,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Legacy Success 1",
				&pair_device_success_test_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Legacy Non-bondable 1",
				&pair_device_legacy_nonbondable_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Sec Mode 3 Success 1",
				&pair_device_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Legacy Reject 1",
				&pair_device_reject_test_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Legacy Reject 2",
				&pair_device_reject_test_2,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Sec Mode 3 Reject 1",
				&pair_device_reject_test_3,
				NULL, test_command_generic);
	test_bredrle("Pair Device - Sec Mode 3 Reject 2",
				&pair_device_reject_test_4,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Just-Works Success 1",
				&pair_device_ssp_test_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Just-Works Success 2",
				&pair_device_ssp_test_2,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Just-Works Success 3",
				&pair_device_ssp_test_3,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Confirm Success 1",
				&pair_device_ssp_test_4,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Confirm Success 2",
				&pair_device_ssp_test_5,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Confirm Success 3",
				&pair_device_ssp_test_6,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Confirm Reject 1",
				&pair_device_ssp_reject_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Confirm Reject 2",
				&pair_device_ssp_reject_2,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SSP Non-bondable 1",
				&pair_device_ssp_nonbondable_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SMP over BR/EDR Success 1",
				&pair_device_smp_bredr_test_1,
				NULL, test_command_generic);
	test_bredrle("Pair Device - SMP over BR/EDR Success 2",
				&pair_device_smp_bredr_test_2,
				NULL, test_command_generic);
	test_le("Pair Device - LE Success 1",
				&pair_device_le_success_test_1,
				NULL, test_command_generic);
	test_le("Pair Device - LE Success 2",
				&pair_device_le_success_test_2,
				NULL, test_command_generic);
	test_le("Pair Device - LE Reject 1",
				&pair_device_le_reject_test_1,
				NULL, test_command_generic);
	test_le("Pair Device - LE SC Legacy 1",
				&pair_device_le_sc_legacy_test_1,
				NULL, test_command_generic);
	test_le("Pair Device - LE SC Success 1",
				&pair_device_le_sc_success_test_1,
				NULL, test_command_generic);
	test_le("Pair Device - LE SC Success 2",
				&pair_device_le_sc_success_test_2,
				NULL, test_command_generic);
	test_bredrle("Pair Device - LE SC Success 3",
				&pair_device_le_sc_success_test_3,
				NULL, test_command_generic);

	test_bredrle("Pairing Acceptor - Legacy 1",
				&pairing_acceptor_legacy_1, NULL,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - Legacy 2",
				&pairing_acceptor_legacy_2, NULL,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - Legacy 3",
				&pairing_acceptor_legacy_3, NULL,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - Link Sec 1",
				&pairing_acceptor_linksec_1, NULL,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - Link Sec 2",
				&pairing_acceptor_linksec_2, NULL,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - SSP 1",
				&pairing_acceptor_ssp_1, setup_pairing_acceptor,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - SSP 2",
				&pairing_acceptor_ssp_2, setup_pairing_acceptor,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - SSP 3",
				&pairing_acceptor_ssp_3, setup_pairing_acceptor,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - SSP 4",
				&pairing_acceptor_ssp_4, setup_pairing_acceptor,
				test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - SMP over BR/EDR 1",
				&pairing_acceptor_smp_bredr_1,
				setup_pairing_acceptor, test_pairing_acceptor);
	test_bredrle("Pairing Acceptor - SMP over BR/EDR 2",
				&pairing_acceptor_smp_bredr_2,
				setup_pairing_acceptor, test_pairing_acceptor);
	test_le("Pairing Acceptor - LE 1",
				&pairing_acceptor_le_1, setup_pairing_acceptor,
				test_pairing_acceptor);
	test_le("Pairing Acceptor - LE 2",
				&pairing_acceptor_le_2, setup_pairing_acceptor,
				test_pairing_acceptor);
	test_le("Pairing Acceptor - LE 3",
				&pairing_acceptor_le_3, setup_pairing_acceptor,
				test_pairing_acceptor);
	test_le("Pairing Acceptor - LE 4",
				&pairing_acceptor_le_4, setup_pairing_acceptor,
				test_pairing_acceptor);
	test_le("Pairing Acceptor - LE 5",
				&pairing_acceptor_le_5, setup_pairing_acceptor,
				test_pairing_acceptor);

	test_bredrle("Unpair Device - Not Powered 1",
				&unpair_device_not_powered_test_1,
				NULL, test_command_generic);
	test_bredrle("Unpair Device - Invalid Parameters 1",
				&unpair_device_invalid_param_test_1,
				NULL, test_command_generic);
	test_bredrle("Unpair Device - Invalid Parameters 2",
				&unpair_device_invalid_param_test_2,
				NULL, test_command_generic);

	test_bredrle("Disconnect - Invalid Parameters 1",
				&disconnect_invalid_param_test_1,
				NULL, test_command_generic);

	test_bredrle("Block Device - Invalid Parameters 1",
				&block_device_invalid_param_test_1,
				NULL, test_command_generic);

	test_bredrle("Unblock Device - Invalid Parameters 1",
				&unblock_device_invalid_param_test_1,
				NULL, test_command_generic);

	test_le("Set Static Address - Success 1",
				&set_static_addr_success_test,
				setup_command_generic, test_command_generic);
	test_bredrle("Set Static Address - Success 2",
				&set_static_addr_success_test_2,
				setup_set_static_addr_success_2,
				test_command_generic);
	test_bredrle("Set Static Address - Failure 1",
				&set_static_addr_failure_test,
				NULL, test_command_generic);
	test_bredr("Set Static Address - Failure 2",
				&set_static_addr_failure_test_2,
				NULL, test_command_generic);

	test_bredrle("Set Scan Parameters - Success",
				&set_scan_params_success_test,
				NULL, test_command_generic);

	test_bredrle("Load IRKs - Success 1",
				&load_irks_success1_test,
				NULL, test_command_generic);
	test_bredrle("Load IRKs - Success 2",
				&load_irks_success2_test,
				NULL, test_command_generic);
	test_bredrle("Load IRKs - Invalid Parameters 1",
				&load_irks_nval_param1_test,
				NULL, test_command_generic);
	test_bredrle("Load IRKs - Invalid Parameters 2",
				&load_irks_nval_param2_test,
				NULL, test_command_generic);
	test_bredrle("Load IRKs - Invalid Parameters 3",
				&load_irks_nval_param3_test,
				NULL, test_command_generic);
	test_bredr("Load IRKs - Not Supported",
				&load_irks_not_supported_test,
				NULL, test_command_generic);

	test_bredrle("Set Privacy - Success 1",
				&set_privacy_success_1_test,
				NULL, test_command_generic);
	test_bredrle("Set Privacy - Success 2 (Device Mode)",
				&set_privacy_success_2_test,
				NULL, test_command_generic);
	test_bredrle("Set Privacy - Rejected",
				&set_privacy_powered_test,
				NULL, test_command_generic);
	test_bredrle("Set Privacy - Invalid Parameters",
				&set_privacy_nval_param_test,
				NULL, test_command_generic);

	test_bredrle("Get Clock Info - Success",
				&get_clock_info_succes1_test, NULL,
				test_command_generic_connect);
	test_bredrle("Get Clock Info - Fail (Power Off)",
				&get_clock_info_fail1_test, NULL,
				test_command_generic);

	test_bredrle("Get Conn Info - Success",
				&get_conn_info_succes1_test, NULL,
				test_command_generic_connect);
	test_bredrle("Get Conn Info - Not Connected",
				&get_conn_info_ncon_test, NULL,
				test_command_generic);
	test_bredrle("Get Conn Info - Power off",
				&get_conn_info_power_off_test, NULL,
				test_command_generic_connect);

	test_bredrle("Load Connection Parameters - Invalid Params 1",
				&load_conn_params_fail_1,
				NULL, test_command_generic);

	test_bredrle("Add Device - Invalid Params 1",
				&add_device_fail_1,
				NULL, test_command_generic);
	test_bredrle("Add Device - Invalid Params 2",
				&add_device_fail_2,
				NULL, test_command_generic);
	test_bredrle("Add Device - Invalid Params 3",
				&add_device_fail_3,
				NULL, test_command_generic);
	test_bredrle("Add Device - Invalid Params 4",
				&add_device_fail_4,
				NULL, test_command_generic);
	test_bredrle("Add Device - Success 1",
				&add_device_success_1,
				NULL, test_command_generic);
	test_bredrle("Add Device - Success 2",
				&add_device_success_2,
				NULL, test_command_generic);
	test_bredrle("Add Device - Success 3",
				&add_device_success_3,
				NULL, test_command_generic);
	test_bredrle("Add Device - Success 4",
				&add_device_success_4,
				NULL, test_command_generic);
	test_bredrle("Add Device - Success 5",
				&add_device_success_5,
				NULL, test_command_generic);

	test_bredrle("Remove Device - Invalid Params 1",
				&remove_device_fail_1,
				NULL, test_command_generic);
	test_bredrle("Remove Device - Invalid Params 2",
				&remove_device_fail_2,
				NULL, test_command_generic);
	test_bredrle("Remove Device - Invalid Params 3",
				&remove_device_fail_3,
				NULL, test_command_generic);
	test_bredrle("Remove Device - Success 1",
				&remove_device_success_1,
				setup_add_device, test_command_generic);
	test_bredrle("Remove Device - Success 2",
				&remove_device_success_2,
				setup_add_device, test_command_generic);
	test_bredrle("Remove Device - Success 3",
				&remove_device_success_3,
				setup_add_device, test_remove_device);
	test_le("Remove Device - Success 4",
				&remove_device_success_4,
				setup_add_device, test_remove_device);
	test_le("Remove Device - Success 5",
				&remove_device_success_5,
				setup_add_device, test_remove_device);
	/* MGMT_OP_REMOVE_DEVICE
	 * Remove all devices
	 */
	test_bredrle50("Remove Device - Success 6 - All Devices",
				&remove_device_success_6,
				setup_add_device, test_remove_device);

	test_le("Add + Remove Device Nowait - Success",
				&add_remove_device_nowait,
				NULL, test_add_remove_device_nowait);

	test_bredrle("Read Advertising Features - Invalid parameters",
				&read_adv_features_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read Advertising Features - Invalid index",
				&read_adv_features_invalid_index_test,
				NULL, test_command_generic);
	test_bredrle("Read Advertising Features - Success 1 (No instance)",
				&read_adv_features_success_1,
				NULL, test_command_generic);
	test_bredrle("Read Advertising Features - Success 2 (One instance)",
				&read_adv_features_success_2,
				setup_add_advertising,
				test_command_generic);

	test_bredrle("Add Advertising - Failure: LE off",
					&add_advertising_fail_1,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Invalid Params 1 (AD too long)",
					&add_advertising_fail_2,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Invalid Params 2 (Malformed len)",
					&add_advertising_fail_3,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Invalid Params 3 (Malformed len)",
					&add_advertising_fail_4,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Invalid Params 4 (Malformed len)",
					&add_advertising_fail_5,
					NULL, test_command_generic);
	test_le("Add Advertising - Invalid Params 5 (AD too long)",
					&add_advertising_fail_6,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Invalid Params 6 (ScRsp too long)",
					&add_advertising_fail_7,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Invalid Params 7 (Malformed len)",
					&add_advertising_fail_8,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Invalid Params 8 (Malformed len)",
					&add_advertising_fail_9,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Invalid Params 9 (Malformed len)",
					&add_advertising_fail_10,
					NULL, test_command_generic);
	test_le("Add Advertising - Invalid Params 10 (ScRsp too long)",
					&add_advertising_fail_11,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Rejected (Timeout, !Powered)",
					&add_advertising_fail_12,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 1 (Powered, Add Adv Inst)",
					&add_advertising_success_1,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 2 (!Powered, Add Adv Inst)",
					&add_advertising_success_pwron_data,
					setup_add_advertising_not_powered,
					test_command_generic);
	test_bredrle("Add Advertising - Success 3 (!Powered, Adv Enable)",
					&add_advertising_success_pwron_enabled,
					setup_add_advertising_not_powered,
					test_command_generic);
	test_bredrle("Add Advertising - Success 4 (Set Adv on override)",
					&add_advertising_success_4,
					setup_add_advertising,
					test_command_generic);
	test_bredrle("Add Advertising - Success 5 (Set Adv off override)",
					&add_advertising_success_5,
					setup_set_and_add_advertising,
					test_command_generic);
	test_bredrle("Add Advertising - Success 6 (Scan Rsp Dta, Adv ok)",
					&add_advertising_success_6,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 7 (Scan Rsp Dta, Scan ok) ",
					&add_advertising_success_7,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 8 (Connectable Flag)",
					&add_advertising_success_8,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 9 (General Discov Flag)",
					&add_advertising_success_9,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 10 (Limited Discov Flag)",
					&add_advertising_success_10,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 11 (Managed Flags)",
					&add_advertising_success_11,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 12 (TX Power Flag)",
					&add_advertising_success_12,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 13 (ADV_SCAN_IND)",
					&add_advertising_success_13,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 14 (ADV_NONCONN_IND)",
					&add_advertising_success_14,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 15 (ADV_IND)",
					&add_advertising_success_15,
					NULL, test_command_generic);
	test_bredrle("Add Advertising - Success 16 (Connectable -> on)",
					&add_advertising_success_16,
					setup_add_advertising,
					test_command_generic);
	test_bredrle("Add Advertising - Success 17 (Connectable -> off)",
					&add_advertising_success_17,
					setup_add_advertising_connectable,
					test_command_generic);
	/* Adv instances with a timeout do NOT survive a power cycle. */
	test_bredrle("Add Advertising - Success 18 (Power -> off, Remove)",
					&add_advertising_power_off,
					setup_add_advertising_timeout,
					test_command_generic);
	/* Adv instances without timeout survive a power cycle. */
	test_bredrle("Add Advertising - Success 19 (Power -> off, Keep)",
					&add_advertising_success_pwron_data,
					setup_add_advertising_power_cycle,
					test_command_generic);
	/* Changing an advertising instance while it is still being
	 * advertised will immediately update the advertised data if
	 * there is no other instance to switch to.
	 */
	test_bredrle("Add Advertising - Success 20 (Add Adv override)",
					&add_advertising_success_18,
					setup_add_advertising,
					test_command_generic);
	/* An instance should be removed when its timeout has been reached.
	 * Advertising will also be disabled if this was the last instance.
	 */
	test_bredrle_full("Add Advertising - Success 21 (Timeout expires)",
					&add_advertising_timeout_expired,
					setup_add_advertising_timeout,
					test_command_generic, 3);
	/* LE off will clear (remove) all instances. */
	test_bredrle("Add Advertising - Success 22 (LE -> off, Remove)",
					&add_advertising_le_off,
					setup_add_advertising,
					test_command_generic);

	test_bredrle("Add Advertising - Success (Empty ScRsp)",
					 &add_advertising_empty_scrsp,
					 setup_command_generic,
					 test_command_generic);

	test_bredrle("Add Advertising - Success (ScRsp only)",
					&add_advertising_scrsp_data_only_ok,
						NULL, test_command_generic);

	test_bredrle("Add Advertising - Invalid Params (ScRsp too long)",
				&add_advertising_scrsp_data_only_too_long,
						NULL, test_command_generic);

	test_bredrle("Add Advertising - Success (ScRsp appear)",
					&add_advertising_scrsp_appear_data_ok,
				setup_command_generic, test_command_generic);

	test_bredrle("Add Advertising - Invalid Params (ScRsp appear long)",
				&add_advertising_scrsp_appear_data_too_long,
				setup_command_generic, test_command_generic);

	test_bredrle("Add Advertising - Success (Appear is null)",
					&add_advertising_scrsp_appear_null,
						NULL, test_command_generic);

	test_bredrle("Add Advertising - Success (Name is null)",
					 &add_advertising_no_name_set,
					 NULL, test_command_generic);

	test_bredrle("Add Advertising - Success (Complete name)",
					&add_advertising_name_fits_in_scrsp,
					setup_command_generic,
					test_command_generic);

	test_bredrle("Add Advertising - Success (Shortened name)",
				&add_advertising_shortened_name_in_scrsp,
					setup_command_generic,
					test_command_generic);

	test_bredrle("Add Advertising - Success (Short name)",
					&add_advertising_short_name_in_scrsp,
					setup_command_generic,
					test_command_generic);

	test_bredrle("Add Advertising - Success (Name + data)",
					 &add_advertising_name_data_ok,
					 setup_command_generic,
					 test_command_generic);

	test_bredrle("Add Advertising - Invalid Params (Name + data)",
					 &add_advertising_name_data_inv,
					 setup_command_generic,
					 test_command_generic);

	test_bredrle("Add Advertising - Success (Name+data+appear)",
					 &add_advertising_name_data_appear,
					 setup_command_generic,
					 test_command_generic);

	test_le_full("Adv. connectable & connected (peripheral) - Success",
					&conn_peripheral_adv_connectable_test,
					setup_advertise_while_connected,
					test_connected_and_advertising, 10);

	test_le_full("Adv. non-connectable & connected (peripheral) - Success",
				&conn_peripheral_adv_non_connectable_test,
				setup_advertise_while_connected,
				test_connected_and_advertising, 10);

	test_le_full("Adv. connectable & connected (central) - Success",
					&conn_central_adv_connectable_test,
					setup_advertise_while_connected,
					test_connected_and_advertising, 10);

	test_le_full("Adv. non-connectable & connected (central) - Success",
					&conn_central_adv_non_connectable_test,
					setup_advertise_while_connected,
					test_connected_and_advertising, 10);

	test_bredrle("Remove Advertising - Invalid Params 1",
					&remove_advertising_fail_1,
					NULL, test_command_generic);

	test_bredrle("Remove Advertising - Success 1",
						&remove_advertising_success_1,
						setup_add_advertising,
						test_command_generic);
	test_bredrle("Remove Advertising - Success 2",
						&remove_advertising_success_2,
						setup_add_advertising,
						test_command_generic);

	/* When advertising two instances, the instances should be
	 * advertised in a round-robin fashion.
	 */
	test_bredrle("Multi Advertising - Success 1 (Instance Switch)",
					&multi_advertising_switch,
					setup_multi_adv,
					test_command_generic);
	/* Adding a new instance when one is already being advertised
	 * will switch to the new instance after the first has reached
	 * its duration. A long timeout has been set to
	 */
	test_bredrle_full("Multi Advertising - Success 2 (Add Second Inst)",
					&multi_advertising_add_second,
					setup_add_advertising_duration,
					test_command_generic, 3);

	test_bredr("Set appearance - BR/EDR only",
					&set_appearance_not_supported,
					NULL,
					test_command_generic);

	test_bredrle("Set appearance - BR/EDR LE",
					&set_appearance_success,
					NULL,
					test_command_generic);

	test_le("Set appearance - LE only",
					&set_appearance_success,
					NULL,
					test_command_generic);

	test_bredrle("Read Ext Controller Info 1",
				&read_ext_ctrl_info1,
				NULL, test_command_generic);

	test_bredrle("Read Ext Controller Info 2",
				&read_ext_ctrl_info2,
				setup_command_generic, test_command_generic);

	test_bredrle("Read Ext Controller Info 3",
				&read_ext_ctrl_info3,
				setup_command_generic, test_command_generic);

	test_bredrle("Read Ext Controller Info 4",
				&read_ext_ctrl_info4,
				setup_command_generic, test_command_generic);

	test_bredrle("Read Ext Controller Info 5",
				&read_ext_ctrl_info5,
				setup_command_generic, test_command_generic);

	test_bredrle("Read Local OOB Data - Not powered",
				&read_local_oob_not_powered_test,
				NULL, test_command_generic);
	test_bredrle("Read Local OOB Data - Invalid parameters",
				&read_local_oob_invalid_param_test,
				NULL, test_command_generic);
	test_bredrle("Read Local OOB Data - Invalid index",
				&read_local_oob_invalid_index_test,
				NULL, test_command_generic);
	test_bredr20("Read Local OOB Data - Legacy pairing",
				&read_local_oob_legacy_pairing_test,
				NULL, test_command_generic);
	test_bredrle("Read Local OOB Data - Success SSP",
				&read_local_oob_success_ssp_test,
				NULL, test_command_generic);
	test_bredrle("Read Local OOB Data - Success SC",
				&read_local_oob_success_sc_test,
				NULL, test_command_generic);
	test_bredrle("Read Local OOB Ext Data - Invalid index",
				&read_local_oob_ext_invalid_index_test,
				NULL, test_command_generic);
	test_bredr20("Read Local OOB Ext Data - Legacy pairing",
				&read_local_oob_ext_legacy_pairing_test,
				NULL, test_command_generic);
	test_bredrle("Read Local OOB Ext Data - Success SSP",
				&read_local_oob_ext_success_ssp_test,
				NULL, test_command_generic);
	test_bredrle("Read Local OOB Ext Data - Success SC",
				&read_local_oob_ext_success_sc_test,
				NULL, test_command_generic);

	test_bredrle("Device Found - Advertising data - Zero padded",
				&device_found_gtag,
				NULL, test_device_found);
	test_bredrle("Device Found - Advertising data - Invalid field",
				&device_found_invalid_field,
				NULL, test_device_found);

	test_bredrle50("Read Ext Advertising Features - Success 3 (PHY flags)",
				&read_adv_features_success_3,
				NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Invalid Params 1 (Multiple Phys)",
					&add_ext_advertising_fail_1,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Invalid Params 2 (Multiple PHYs)",
					&add_ext_advertising_fail_2,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Invalid Params 3 (Multiple PHYs)",
					&add_ext_advertising_fail_3,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Invalid Params 4 (Multiple PHYs)",
					&add_ext_advertising_fail_4,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 1 (Powered, Add Adv Inst)",
						&add_ext_advertising_success_1,
						NULL, test_command_generic);


	test_bredrle50("Add Ext Advertising - Success 2 (!Powered, Add Adv Inst)",
					&add_ext_advertising_success_pwron_data,
					setup_add_advertising_not_powered,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 3 (!Powered, Adv Enable)",
					&add_ext_advertising_success_pwron_enabled,
					setup_add_advertising_not_powered,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 4 (Set Adv on override)",
					&add_ext_advertising_success_4,
					setup_add_advertising,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 5 (Set Adv off override)",
					&add_ext_advertising_success_5,
					setup_set_and_add_advertising,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 6 (Scan Rsp Dta, Adv ok)",
					&add_ext_advertising_success_6,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 7 (Scan Rsp Dta, Scan ok) ",
					&add_ext_advertising_success_7,
					NULL, test_command_generic);
	test_bredrle50("Add Ext Advertising - Success 8 (Connectable Flag)",
					&add_ext_advertising_success_8,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 9 (General Discov Flag)",
					&add_ext_advertising_success_9,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 10 (Limited Discov Flag)",
					&add_ext_advertising_success_10,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 11 (Managed Flags)",
					&add_ext_advertising_success_11,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 12 (TX Power Flag)",
					&add_ext_advertising_success_12,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 13 (ADV_SCAN_IND)",
					&add_ext_advertising_success_13,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 14 (ADV_NONCONN_IND)",
					&add_ext_advertising_success_14,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 15 (ADV_IND)",
					&add_ext_advertising_success_15,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 16 (Connectable -> on)",
					&add_ext_advertising_success_16,
					setup_add_advertising,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success 17 (Connectable -> off)",
					&add_ext_advertising_success_17,
					setup_add_advertising_connectable,
					test_command_generic);

	/* Changing an advertising instance while it is still being
	 * advertised will immediately update the advertised data if
	 * there is no other instance to switch to.
	 */
	test_bredrle50("Add Ext Advertising - Success 20 (Add Adv override)",
					&add_ext_advertising_success_18,
					setup_add_advertising,
					test_command_generic);

	/* An instance should be removed when its timeout has been reached.
	 * Advertising will also be disabled if this was the last instance.
	 */
	test_bredrle50_full("Add Ext Advertising - Success 21 (Timeout expires)",
					&add_ext_advertising_timeout_expired,
					setup_add_advertising_timeout,
					test_command_generic, 3);

	/* LE off will clear (remove) all instances. */
	test_bredrle50("Add Ext Advertising - Success 22 (LE -> off, Remove)",
					&add_ext_advertising_le_off,
					setup_add_advertising,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Empty ScRsp)",
					 &add_ext_advertising_empty_scrsp,
					 setup_command_generic,
					 test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (ScRsp only)",
					&add_ext_advertising_scrsp_data_only_ok,
						NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Invalid Params (ScRsp too long)",
				&add_ext_advertising_scrsp_data_only_too_long,
						NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (ScRsp appear)",
					&add_ext_advertising_scrsp_appear_data_ok,
				setup_command_generic, test_command_generic);

	test_bredrle50("Add Ext Advertising - Invalid Params (ScRsp appear long)",
				&add_ext_advertising_scrsp_appear_data_too_long,
				setup_command_generic, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Appear is null)",
					&add_ext_advertising_scrsp_appear_null,
						NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Name is null)",
					 &add_ext_advertising_no_name_set,
					 NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Complete name)",
					&add_ext_advertising_name_fits_in_scrsp,
					setup_command_generic,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Shortened name)",
				&add_ext_advertising_shortened_name_in_scrsp,
					setup_command_generic,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Short name)",
					&add_ext_advertising_shortened_name_in_scrsp,
					setup_command_generic,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Name + data)",
					 &add_ext_advertising_name_data_ok,
					 setup_command_generic,
					 test_command_generic);

	test_bredrle50("Add Ext Advertising - Invalid Params (Name + data)",
					 &add_ext_advertising_name_data_inv,
					 setup_command_generic,
					 test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Name+data+appear)",
					 &add_ext_advertising_name_data_appear,
					 setup_command_generic,
					 test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (PHY -> 1M)",
					&add_ext_advertising_success_1m,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (PHY -> 2M)",
					&add_ext_advertising_success_2m,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (PHY -> Coded)",
					&add_ext_advertising_success_coded,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Ext Pdu Scannable)",
					&add_ext_advertising_success_scannable,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (Ext Pdu Connectable)",
					&add_ext_advertising_success_connectable,
					NULL, test_command_generic);

	/* In Ext pdu it shall not be both scannable and connectable */
	test_bredrle50("Add Ext Advertising - Success (Ext Pdu Conn Scan)",
					&add_ext_advertising_success_conn_scan,
					NULL, test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (1m Connectable -> on)",
					&add_ext_advertising_conn_on_1m,
					setup_add_advertising_1m,
					test_command_generic);

	test_bredrle50("Add Ext Advertising - Success (1m Connectable -> off)",
					&add_ext_advertising_conn_off_1m,
					setup_add_advertising_connectable_1m,
					test_command_generic);

	test_bredrle50("Remove Ext Advertising - Invalid Params 1",
					&remove_ext_advertising_fail_1,
					NULL, test_command_generic);

	test_bredrle50("Remove Ext Advertising - Success 1",
						&remove_ext_advertising_success_1,
						setup_add_advertising,
						test_command_generic);

	test_bredrle50("Remove Ext Advertising - Success 2",
						&remove_ext_advertising_success_2,
						setup_add_advertising,
						test_command_generic);

	/* When advertising two instances, the instances should be
	 * advertised in a round-robin fashion.
	 */
	test_bredrle50("Multi Ext Advertising - Success 1",
					&multi_ext_advertising,
					setup_multi_adv,
					test_command_generic);

	/* Adding a new instance when one is already being advertised
	 * will switch to the new instance after the first has reached
	 * its duration. A long timeout has been set to
	 */
	test_bredrle50_full("Multi Ext Advertising - Success 2 (Add Second Inst)",
					&multi_ext_advertising_add_second,
					setup_add_advertising_duration,
					test_command_generic, 3);
	/* Multi Ext Advertising
	 * Setup: Power on and the first ext advertising
	 * Run: Add the second ext advertising
	 * Expect: The second ext advertising is added.
	 */
	test_bredrle50("Multi Ext Advertising - Success 3 (Add 2 Advs)",
					&multi_ext_advertising_add_second_2,
					setup_add_advertising,
					test_command_generic);

	/* Multi Ext Advertising
	 * Setup: Power on and add two ext advertising
	 * Run: Remove the advertising
	 * Expect: Received the removed event
	 */
	test_bredrle50("Multi Ext Advertising - Success 4 (Remove Adv)",
					&multi_ext_advertising_remove,
					setup_add_2_advertisings,
					test_command_generic);

	/* Multi Ext Advertising
	 * Setup: Power on and add max advertisings
	 * Run: Remove all advertisings
	 * Expect:
	 */
	test_bredrle50("Multi Ext Advertising - Success 5 (Remove all)",
					&multi_ext_advertising_remove_all,
					setup_add_2_advertisings,
					test_command_generic);

	/* Multi Ext Advertising
	 * Setup: Add multiple advertising before power on
	 * Run: Power on
	 * Expect: All advertising are set
	 */
	test_bredrle50("Multi Ext Advertising - Success 6 (Add w/o power on)",
					&multi_ext_advertising_add_no_power,
					setup_add_2_advertisings_no_power,
					test_command_generic);

	/* Multi Ext Advertising
	 * Setup: Power on and add max advertisings
	 * Run: Add another advertising
	 * Expect: Received error - Invalid Parameter
	 */
	test_bredrle50("Multi Ext Advertising - Fail (Add MAX)",
					&multi_ext_advertising_add_adv_4,
					setup_add_2_advertisings,
					test_command_generic);

	test_bredrle50("Get PHY Success", &get_phy_success,
					NULL, test_command_generic);

	test_bredrle50("Set PHY 2m Success", &set_phy_2m_success,
					NULL, test_command_generic);

	test_bredrle50("Set PHY coded Success", &set_phy_coded_success,
					NULL, test_command_generic);

	test_bredrle50("Set PHY 2m tx success", &set_phy_2m_tx_success,
					NULL, test_command_generic);

	test_bredrle50("Set PHY 2m rx success", &set_phy_2m_rx_success,
					NULL, test_command_generic);

	test_bredrle50("Set PHY Invalid Param", &set_phy_invalid_param,
					NULL, test_command_generic);

	test_bredrle50("Start Discovery BREDR LE - (Ext Scan Enable)",
					&start_discovery_bredrle_ext_scan_enable,
					NULL,
					test_command_generic);

	test_bredrle50("Start Discovery LE - (Ext Scan Enable)",
					&start_discovery_le_ext_scan_enable,
					NULL,
					test_command_generic);

	test_bredrle50("Start Discovery LE - (Ext Scan Param)",
					&start_discovery_le_ext_scan_param,
					NULL,
					test_command_generic);

	test_bredrle50("Stop Discovery - (Ext Scan Disable)",
				&stop_discovery_le_ext_scan_disable,
				setup_start_discovery, test_command_generic);

	test_bredrle50("Start Discovery - (2m, Scan Param)",
				&start_discovery_le_2m_scan_param,
				setup_phy_configuration, test_command_generic);

	test_bredrle50("Start Discovery - (coded, Scan Param)",
				&start_discovery_le_coded_scan_param,
				setup_phy_configuration, test_command_generic);

	test_bredrle50("Start Discovery - (1m, 2m, coded, Scan Param)",
				&start_discovery_le_1m_coded_scan_param,
				setup_phy_configuration, test_command_generic);

	test_bredrle50("Ext Device Found - Advertising data - Zero padded",
				&device_found_gtag,
				NULL, test_device_found);

	test_bredrle50("Ext Device Found - Advertising data - Invalid field",
				&device_found_invalid_field,
				NULL, test_device_found);

	test_bredrle50_full("Ext Adv. connectable & connected (peripheral)",
				&conn_peripheral_adv_connectable_test,
				setup_advertise_while_connected,
				test_connected_and_advertising, 10);

	test_bredrle50_full("Ext Adv. non-connectable & connected (peripheral)",
				&conn_peripheral_adv_non_connectable_test,
				setup_advertise_while_connected,
				test_connected_and_advertising, 10);

	test_bredrle50_full("Ext Adv. connectable & connected (central)",
				&conn_central_adv_connectable_test,
				setup_advertise_while_connected,
				test_connected_and_advertising, 10);

	test_bredrle50_full("Ext Adv. non-connectable & connected (central)",
				&conn_central_adv_non_connectable_test,
				setup_advertise_while_connected,
				test_connected_and_advertising, 10);

	test_bredrle("Read Controller Capabilities - Invalid parameters",
				&read_controller_cap_invalid_param_test,
				NULL, test_command_generic);

	test_bredrle50("Read Controller Capabilities - (5.0) Success",
				&read_controller_cap_success,
				NULL, test_50_controller_cap_response);

	test_bredrle("Ext Adv MGMT Params - Unpowered",
				&adv_params_fail_unpowered,
				setup_ext_adv_not_powered,
				test_command_generic);

	test_bredrle("Ext Adv MGMT Params - Invalid parameters",
				&adv_params_fail_invalid_params,
				NULL, test_command_generic);

	test_bredrle("Ext Adv MGMT Params - Success",
				&adv_params_success,
				NULL, test_command_generic);

	test_bredrle50("Ext Adv MGMT Params - (5.0) Success",
				&adv_params_success_50,
				NULL, test_command_generic);

	test_bredrle("Ext Adv MGMT - Data set without Params",
				&adv_data_fail_no_params,
				NULL, test_command_generic);

	test_bredrle50("Ext Adv MGMT - AD Data (5.0) Invalid parameters",
				&adv_data_invalid_params,
				setup_ext_adv_params,
				test_command_generic);

	test_bredrle50("Ext Adv MGMT - AD Data (5.0) Success",
				&adv_data_success,
				setup_ext_adv_params,
				test_command_generic);

	test_bredrle50("Ext Adv MGMT - AD Scan Response (5.0) Success",
				&adv_scan_rsp_success,
				setup_ext_adv_params,
				test_command_generic);

	test_bredrle50("Ext Adv MGMT - AD Scan Resp - Off and On",
				&add_ext_adv_scan_resp_off_on,
				setup_add_ext_adv_on_off,
				test_command_generic);


	/* MGMT_OP_SET_DEVICE_ID
	 * Using Bluetooth SIG for source.
	 */
	test_bredrle50("Set Device ID - Success 1",
				&set_dev_id_success_1,
				NULL,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_ID
	 * Using SB Implementer's Forum for source.
	 */
	test_bredrle50("Set Device ID - Success 2",
				&set_dev_id_success_2,
				NULL,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_ID
	 * Disable DID with disable flag for source.
	 */
	test_bredrle50("Set Device ID - Disable",
				&set_dev_id_disable,
				NULL,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_ID
	 * Power off, set device id, and power on.
	 * Expect Write_Extended_Inquiry with device id when power on.
	 */
	test_bredrle50("Set Device ID - Power off and Power on",
				&set_dev_id_power_off_on,
				setup_command_generic,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_ID
	 * SSP off, set device id, and SSP on.
	 * Expect Write_Extended_Inquiry with device id when SSP on.
	 */
	test_bredrle50("Set Device ID - SSP off and Power on",
				&set_dev_id_ssp_off_on,
				setup_command_generic,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_ID
	 * Invalid parameter
	 */
	test_bredrle50("Set Device ID - Invalid Parameter",
				&set_dev_id_invalid_param,
				NULL,
				test_command_generic);

	/* MGMT_OP_GET_DEVICE_FLAGS
	 * Success
	 */
	test_bredrle50("Get Device Flags - Success",
				&get_dev_flags_success,
				setup_get_dev_flags,
				test_command_generic);

	/* MGMT_OP_GET_DEVICE_FLAGS
	 * Fail - Invalid parameter
	 */
	test_bredrle50("Get Device Flags - Invalid Parameter",
				&get_dev_flags_fail_1,
				setup_get_dev_flags,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_FLAGS
	 * Success
	 */
	test_bredrle50("Set Device Flags - Success",
				&set_dev_flags_success,
				setup_get_dev_flags,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_FLAGS
	 * Invalid Parameter - Missing parameter
	 */
	test_bredrle50("Set Device Flags - Invalid Parameter 1",
				&set_dev_flags_fail_1,
				setup_get_dev_flags,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_FLAGS
	 * Invalid Parameter - Not supported value
	 */
	test_bredrle50("Set Device Flags - Invalid Parameter 2",
				&set_dev_flags_fail_2,
				setup_get_dev_flags,
				test_command_generic);

	/* MGMT_OP_SET_DEVICE_FLAGS
	 * Device not exist
	 */
	test_bredrle50("Set Device Flags - Device not found",
				&set_dev_flags_fail_3,
				setup_get_dev_flags,
				test_command_generic);

	/* Suspend/Resume
	 * Setup : Power on and register Suspend Event
	 * Run: Enable suspend via force_suspend
	 * Expect: Receive the Suspend Event
	 */
	test_bredrle50("Suspend - Success 1",
				&suspend_resume_success_1,
				NULL, test_suspend_resume_success_1);

	/* Suspend/Resume
	 * Setup : Power on and register Suspend Event
	 * Run: Enable suspend, and then resume via force_suspend
	 * Expect: Receive the Resume Event
	 */
	test_bredrle50("Resume - Success 2",
				&suspend_resume_success_2,
				NULL, test_suspend_resume_success_2);

	/* Suspend/Resume
	 * Setup: Enable LL Privacy and power on
	 * Run: Add new device, and enable suspend.
	 * Expect: Receive the Suspend Event
	 */
	test_bredrle50("Suspend - Success 3 (Device in WL)",
				&suspend_resume_success_3,
				setup_suspend_resume_success_3,
				test_suspend_resume_success_3);

	/* Suspend/Resume
	 * Setup: Start advertising and power on.
	 * Run: Enable suspend
	 * Expect: Receive the Suspend Event
	 */
	test_bredrle50("Suspend - Success 4 (Advertising)",
				&suspend_resume_success_4,
				setup_suspend_resume_success_4,
				test_suspend_resume_success_4);

	/* Suspend/Resume
	 * Setup: Pair.
	 * Run: Enable suspend
	 * Expect: Receive the Suspend Event
	 */
	test_bredrle("Suspend - Success 5 (Pairing - Legacy)",
				&suspend_resume_success_5, NULL,
				test_suspend_resume_success_5);

	/* Suspend/Resume
	 * Setup: Pair.
	 * Run: Enable suspend
	 * Expect: Receive the Suspend Event
	 */
	test_bredrle("Suspend - Success 6 (Pairing - SSP)",
				&suspend_resume_success_6,
				setup_pairing_acceptor,
				test_suspend_resume_success_5);

	/* Suspend/Resume
	 * Setup : Power on and register Suspend Event
	 * Run: Enable suspend via force_suspend
	 * Expect: Receive the Suspend Event
	 */
	test_bredrle50("Suspend - Success 7 (Suspend/Force Wakeup)",
				&suspend_resume_success_7,
				NULL, test_suspend_resume_success_7);

	/* Suspend/Resume
	 * Setup : Power on
	 * Run: Start discover and enable suspend
	 * Expect: Receive the Suspend Event
	 */
	test_bredrle50_full("Suspend - Success 8 (Discovery/Suspend)",
				&suspend_resume_success_8,
				NULL, test_suspend_resume_success_8, 4);

	/* Suspend/Resume
	 * Setup : Power on, start discovery
	 * Run: Start discover, enable suspend and resume.
	 * Expect: Receive the Resume Event
	 */
	test_bredrle50_full("Resume - Success 9 (Discovery/Suspend/Resume)",
				&suspend_resume_success_9,
				setup_suspend_resume_success_9,
				test_suspend_resume_success_9, 4);

	/* Suspend/Resume
	 * Setup : Power on
	 * Run: Suspend, Resume, Suspend, and Resume
	 * Expect:
	 */
	test_bredrle50_full("Resume - Success 10 (Multiple Suspend/Resume)",
				&suspend_resume_success_10,
				setup_suspend_resume_success_10,
				test_suspend_resume_success_10, 6);

	/* MGMT_OP_READ_EXP_FEATURE
	 * Read Experimental features - success
	 */
	test_bredrle50("Read Exp Feature - Success",
				&read_exp_feat_success,
				NULL, test_command_generic);

	/* MGMT_OP_READ_EXP_FEATURE
	 * Read Experimental features - success (Index None)
	 */
	test_bredrle50("Read Exp Feature - Success (Index None)",
				&read_exp_feat_success_index_none,
				NULL, test_command_generic);

	/* MGMT_OP_SET_EXP_FEATURE
	 * Offload Codec
	 */
	test_bredrle50("Set Exp Feature - Offload Codec",
				&set_exp_feat_offload_codec,
				setup_set_exp_feature_alt,
				test_command_generic);

	/* MGMT_OP_SET_EXP_FEATURE
	 * Disable all features by sending zero UUID
	 */
	test_bredrle50("Set Exp Feature - Disable all",
				&set_exp_feat_disable,
				NULL, test_command_generic);


	/* MGMT_OP_SET_EXP_FEATURE
	 * Invalid parameter
	 */
	test_bredrle50("Set Exp Feature - Invalid params",
				&set_exp_feat_invalid,
				NULL, test_command_generic);


	/* MGMT_OP_SET_EXP_FEATURE
	 * Not Supported UUID
	 */
	test_bredrle50("Set Exp Feature - Unknown feature",
				&set_exp_feat_unknown,
				NULL, test_command_generic);

	/* LL Privacy
	 * Setup: Enable LE and Power On
	 * Run: Add new device
	 * Expect: Device is added to the accept list
	 */
	test_bredrle50("LL Privacy - Add Device 1 (Add to AL)",
				&ll_privacy_add_device_1,
				NULL, test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, add device1 with IRK, and add IRK of
	 *        device2
	 * Run: Add new device2
	 * Expect: Device2 is added to the accept list
	 */
	test_bredrle50("LL Privacy - Add Device 2 (2 Devices to AL)",
				&ll_privacy_add_device_2,
				setup_ll_privacy_add_2,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, add 2 devices with IRKs and 1 device
	 *        without IRK, and add IRK for device4
	 * Run: Add new device4
	 * Expect: Device4 is added but failed to add to accept list, and it
	 *         is removed from the resolv list.
	 */
	test_bredrle50("LL Privacy - Add Device 3 (AL is full)",
				&ll_privacy_add_device_3,
				setup_ll_privacy_add_3,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, and add advertising
	 * Run: Add new device
	 * Expect: Disable the advertising before adding new device to the
	 *         accept list and resolving list
	 */
	test_bredrle50("LL Privacy - Add Device 4 (Disable Adv)",
				&ll_privacy_add_4,
				setup_ll_privacy_add_4,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy and add IRK of new device
	 * Run: Set Device Flags: DEVICE_FLAG_ADDRESS_RESOLUTION
	 * Expect: Device is added to the resolving list
	 */
	test_bredrle50("LL Privacy - Set Flags 1 (Add to RL)",
				&ll_privacy_set_flags_1,
				setup_ll_privacy_set_flags_1,
				test_command_generic);
	/* LL Privacy
	 * Setup: Enable LL Privacy and add IRK of new device
	 * Run: Set Device Flags: DEVICE_FLAG_ADDRESS_RESOLUTION
	 * Expect: Device is added to the resolving list and resolving list
	 *         is enabled
	 */
	test_bredrle50("LL Privacy - Set Flags 2 (Enable RL)",
				&ll_privacy_set_flags_2,
				setup_ll_privacy_set_flags_1,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, add device1 with IRK, and add IRK of
	 *        device2
	 * Run: Set Device Flags: DEVICE_FLAG_ADDRESS_RESOLUTION
	 * Expect: Device2 is added to the resolv list
	 */
	test_bredrle50("LL Privacy - Set Flags 3 (2 Devices to RL)",
				&ll_privacy_set_flags_3,
				setup_ll_privacy_set_flags_3,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, add 3 devices with IRKs, and add IRK of
	 *        device4
	 * Run: Set Device Flags: DEVICE_FLAG_ADDRESS_RESOLUTION
	 * Expect: Device4 is added but failed to add to resolv list because
	 *         btdev resolv list is full.
	 */
	test_bredrle50("LL Privacy - Set Flags 4 (RL is full)",
				&ll_privacy_set_flags_4,
				setup_ll_privacy_set_flags_4,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, and add 2 advertisings
	 * Run: Set Device Flags: DEVICE_FLAG_ADDRESS_RESOLUTION
	 * Expect: Disable the advertising before adding new device to the
	 *         accept list and resolving list
	 */
	test_bredrle50("LL Privacy - Set Flags 5 (Multi Adv)",
				&ll_privacy_set_flags_5,
				setup_ll_privacy_set_flags_5,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, and add 1 device and add 2 advertisings
	 * Run: Set Device Flags: DEVICE_FLAG_ADDRESS_RESOLUTION
	 * Expect: Disable the advertising before adding new device to the
	 *         accept list and resolving list
	 */
	test_bredrle50("LL Privacy - Set Flags 6 (Multi Dev and Multi Adv)",
				&ll_privacy_set_flags_5,
				setup_ll_privacy_set_flags_6,
				test_command_generic);


	/* LL Privacy
	 * Setup: Enable LL Privacy and add 2 devices and its IRK
	 * Run: Remove one of devices
	 * Expect: The device is removed from the accept list
	 */
	test_bredrle50("LL Privacy - Remove Device 1 (Remove from AL)",
				&ll_privacy_remove_device_1,
				setup_ll_privacy_3_devices,
				test_command_generic);
	/* LL Privacy
	 * Setup: Enable LL Privacy and add 2 devices and its IRK
	 * Run: Remove one of devices
	 * Expect: The device is removed from the resolving list
	 */
	test_bredrle50("LL Privacy - Remove Device 2 (Remove from RL)",
				&ll_privacy_remove_device_2,
				setup_ll_privacy_3_devices,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy and add a device and its IRK
	 * Run: Remove device
	 * Expect: Device is removed and disable the resolving list before
	 *         removing the device from the list.
	 */
	test_bredrle50("LL Privacy - Remove Device 3 (Disable RL)",
				&ll_privacy_remove_device_3,
				setup_ll_privacy_3_devices,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, add advertising and add device
	 * Run: Remove the device
	 * Expect: Disable the advertising before removing the device from the
	 *         accept list and resolving list
	 */
	test_bredrle50("LL Privacy - Remove Device 4 (Disable Adv)",
				&ll_privacy_remove_device_4,
				setup_ll_privacy_adv_3_devices,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, add advertisings and add device
	 * Run: Remove the device
	 * Expect: Disable the advertising before removing the device from the
	 *         accept list and resolving list
	 */
	test_bredrle50("LL Privacy - Remove Device 5 (Multi Adv)",
				&ll_privacy_remove_device_5,
				setup_ll_privacy_adv_1_device_2_advs,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy
	 * Check if the resolving list is disabled before the scan parameter is
	 * changed.
	 */
	test_bredrle50("LL Privacy - Start Discovery 1 (Disable RL)",
				&ll_privacy_start_discovery_ll_privacy_1,
				setup_ll_privacy_set_flags_3,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable LL Privacy, Add 2 devices with IRKs and remove one of
	 *        the device
	 * Run: Start Discovery
	 * Expect: Resolving list is disabled.
	 */
	test_bredrle50("LL Privacy - Start Discovery 2 (Disable RL)",
				&ll_privacy_start_discovery_ll_privacy_2,
				setup_ll_privacy_device2_discovry,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable Privacy, LL Privacy, and enable advertising
	 * Run: bthost scan the advertising
	 * Expect: bthost receives the advertising with random address
	 */
	test_bredrle50("LL Privacy - Advertising 1 (Scan Result)",
				&ll_privacy_advertising_1,
				setup_ll_privacy_enable_powered,
				test_ll_privacy_bthost_scan_report);

	/* LL Privacy
	 * Setup: Enable Privacy, LL Privacy, and enable advertising
	 * Run: Connect from bthost
	 * Expect: Pair success
	 */
	test_bredrle50("LL Privacy - Acceptor 1",
				&ll_privacy_acceptor_1,
				setup_ll_privacy_add_adv,
				test_pairing_acceptor_ll_privacy_le_random);

	/* LL Privacy
	 * Setup: Enable Privacy, LL Privacy, and enable advertising
	 * Run: Connect from bthost
	 * Expect: Pair success
	 */
	test_bredrle50("LL Privacy - Acceptor 2",
				&ll_privacy_acceptor_2,
				setup_ll_privacy_add_adv,
				test_pairing_acceptor_ll_privacy_le_random);

	/* LL Privacy
	 * Setup: Enable Privacy, LL Privacy
	 * Run: Pair device
	 * Expect: Pair success
	 */
	test_bredrle50("LL Privacy - Pair 1",
				&ll_privacy_pair_1,
				NULL,
				test_command_generic);

	/* LL Privacy
	 * Setup: Enable Privacy, LL Privacy
	 * Run: Pair device
	 * Expect: The device is added to Accept List
	 */
	test_bredrle50("LL Privacy - Pair 2 (Add to AL)",
				&ll_privacy_pair_2,
				NULL,
				test_ll_privacy_pair_2);

	/* LL Privacy
	 * Setup: Enable Privacy, LL Privacy
	 * Run: Pair device, wait for New Key Event and unpair.
	 * Expect: Receive Unpair event
	 */
	test_bredrle50("LL Privacy - Unpair 1",
				&ll_privacy_unpair_1,
				NULL,
				test_ll_privacy_unpair);

	/* LL Privacy
	 * Setup: Enable Privacy, LL Privacy
	 * Run: Pair device, disconnect, add device, add 2nd device, and
	 *      remove the client, then unpair.
	 * Expect: Expect the client is removed from the Accept List.
	 */
	test_bredrle50_full("LL Privacy - Unpair 2 (Remove from AL)",
				&ll_privacy_unpair_2,
				NULL,
				test_ll_privacy_unpair_2, 5);

	/* LL Privacy
	 * Setup: Enable LL Privacy, add IRK of new device, Add Device
	 * Run: Set Device Flags
	 * Expect: Device Privacy Mode is set.
	 */
	test_bredrle50("LL Privacy - Set Device Flag 1 (Device Privacy)",
				&ll_privacy_set_device_flag_1,
				setup_ll_privacy_add_device,
				test_command_generic);

	/* HCI Devcoredump
	 * Setup : Power on
	 * Run: Trigger devcoredump via force_devcoredump
	 * Expect: Devcoredump is generated with correct data
	 */
	test_bredrle("HCI Devcoredump - Dump Complete", &dump_complete, NULL,
			test_hci_devcd);

	/* HCI Devcoredump
	 * Setup : Power on
	 * Run: Trigger devcoredump via force_devcoredump
	 * Expect: Devcoredump is generated with correct data
	 */
	test_bredrle("HCI Devcoredump - Dump Abort", &dump_abort, NULL,
			test_hci_devcd);

	/* HCI Devcoredump
	 * Setup : Power on
	 * Run: Trigger devcoredump via force_devcoredump
	 * Expect: Devcoredump is generated with correct data
	 */
	test_bredrle_full("HCI Devcoredump - Dump Timeout", &dump_timeout, NULL,
				test_hci_devcd, 3);

	return tester_run();
}
