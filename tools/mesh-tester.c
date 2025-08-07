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

static const uint8_t set_exp_feat_rsp_param_mesh[] = {
	0x76, 0x6e, 0xf3, 0xe8, 0x24, 0x5f, 0x05, 0xbf, /* UUID - Mesh */
	0x8d, 0x4d, 0x03, 0x7a, 0xd7, 0x63, 0xe4, 0x2c,
	0x01, 0x00, 0x00, 0x00,			/* Action - enable */
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
			sizeof(set_exp_feat_param_mesh),
			set_exp_feat_param_mesh,
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

struct hci_cmd_data {
	uint16_t opcode;
	uint8_t len;
	const void *param;
};

struct hci_entry {
	const struct hci_cmd_data *cmd_data;
};

struct generic_data {
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
			sizeof(set_exp_feat_param_debug),
			set_exp_feat_param_debug,
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
					test_pre_setup, test_setup, func, \
					NULL, test_post_teardown, timeout, \
					user, free); \
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

static void test_condition_complete(struct test_data *data)
{
	data->unmet_conditions--;

	tester_print("Test condition complete, %d left",
			data->unmet_conditions);

	if (data->unmet_conditions > 0)
		return;

	tester_test_passed();
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

static void test_add_condition(struct test_data *data)
{
	data->unmet_conditions++;

	tester_print("Test condition added, total %d", data->unmet_conditions);
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
		 * for a callback.
		 */
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

static const struct generic_data enable_mesh_1 = {
	.send_opcode = MGMT_OP_SET_EXP_FEATURE,
	.send_param = set_exp_feat_param_mesh,
	.send_len = sizeof(set_exp_feat_param_mesh),
	.expect_param = set_exp_feat_rsp_param_mesh,
	.expect_len = sizeof(set_exp_feat_rsp_param_mesh),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const uint8_t set_mesh_receiver_1[] = {
	0x01,
	0x6e, 0x01,
	0xe8, 0x01,
	0x03,
	0x2a, 0x2b, 0x29
};

static const struct generic_data enable_mesh_2 = {
	.send_opcode = MGMT_OP_SET_MESH_RECEIVER,
	.send_param = set_mesh_receiver_1,
	.send_len = sizeof(set_mesh_receiver_1),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const uint8_t read_mesh_feat_rsp_param_mesh[] = {
	0x00, 0x00,
	0x03,
	0x00
};

static const uint8_t read_mesh_feat_rsp_param_mesh_disabled[] = {
	0x00, 0x00,
	0x00,
	0x00
};

static const struct generic_data read_mesh_features = {
	.send_opcode = MGMT_OP_MESH_READ_FEATURES,
	.expect_param = read_mesh_feat_rsp_param_mesh,
	.expect_len = sizeof(read_mesh_feat_rsp_param_mesh),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const struct generic_data read_mesh_features_disabled = {
	.send_opcode = MGMT_OP_MESH_READ_FEATURES,
	.expect_param = read_mesh_feat_rsp_param_mesh_disabled,
	.expect_len = sizeof(read_mesh_feat_rsp_param_mesh_disabled),
	.expect_status = MGMT_STATUS_SUCCESS,
};

static const uint8_t send_mesh_1[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	BDADDR_LE_RANDOM,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
	0x03,
	0x18,
	0x17, 0x2b, 0x01, 0x00, 0x2d, 0xda, 0x0c, 0x24,
	0x91, 0x53, 0x7a, 0xe2, 0x00, 0x00, 0x00, 0x00,
	0x9d, 0xe2, 0x12, 0x0a, 0x72, 0x50, 0x38, 0xb2
};

static const uint8_t send_mesh_too_long[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	BDADDR_LE_RANDOM,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00,
	0x03,
	0x28,
	0x17, 0x2b, 0x01, 0x00, 0x2d, 0xda, 0x0c, 0x24,
	0x91, 0x53, 0x7a, 0xe2, 0x00, 0x00, 0x00, 0x00,
	0x91, 0x53, 0x7a, 0xe2, 0x00, 0x00, 0x00, 0x00,
	0x91, 0x53, 0x7a, 0xe2, 0x00, 0x00, 0x00, 0x00,
	0x9d, 0xe2, 0x12, 0x0a, 0x72, 0x50, 0x38, 0xb2
};

static const uint8_t mesh_send_rsp_param_mesh[] = {
	0x01
};

static const struct generic_data mesh_send_mesh_1 = {
	.send_opcode = MGMT_OP_MESH_SEND,
	.send_param = send_mesh_1,
	.send_len = sizeof(send_mesh_1),
	.expect_param = mesh_send_rsp_param_mesh,
	.expect_len = sizeof(mesh_send_rsp_param_mesh),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_MESH_PACKET_CMPLT,
	.expect_alt_ev_param = mesh_send_rsp_param_mesh,
	.expect_alt_ev_len = sizeof(mesh_send_rsp_param_mesh),
	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_ENABLE,
	.expect_hci_param = mesh_send_rsp_param_mesh,
	.expect_hci_len = sizeof(mesh_send_rsp_param_mesh),
};

static const struct generic_data mesh_send_mesh_too_short = {
	.send_opcode = MGMT_OP_MESH_SEND,
	.send_param = send_mesh_1,
	.send_len = sizeof(send_mesh_1) - 30,
	.expect_status = MGMT_STATUS_INVALID_PARAMS
};

static const struct generic_data mesh_send_mesh_too_long = {
	.send_opcode = MGMT_OP_MESH_SEND,
	.send_param = send_mesh_too_long,
	.send_len = sizeof(send_mesh_too_long),
	.expect_status = MGMT_STATUS_REJECTED
};

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

static const char set_le_on_param[] = { 0x01 };

static void setup_enable_mesh(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param,
			setup_powered_callback, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
			sizeof(set_le_on_param), set_le_on_param,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_EXP_FEATURE, data->mgmt_index,
			sizeof(set_exp_feat_param_mesh),
			set_exp_feat_param_mesh,
			mesh_exp_callback, NULL, NULL);
}

static const uint8_t send_mesh_cancel_1[] = {
	0x01
};

static const uint8_t send_mesh_cancel_2[] = {
	0x02
};

static const uint8_t mesh_cancel_rsp_param_mesh[] = {
	0x00
};

static const struct generic_data mesh_send_mesh_cancel_1 = {
	.send_opcode = MGMT_OP_MESH_SEND_CANCEL,
	.send_param = send_mesh_cancel_1,
	.send_len = sizeof(send_mesh_cancel_1),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_MESH_PACKET_CMPLT,
	.expect_alt_ev_param = send_mesh_cancel_1,
	.expect_alt_ev_len = sizeof(send_mesh_cancel_1),

	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_ENABLE,
	.expect_hci_param = mesh_cancel_rsp_param_mesh,
	.expect_hci_len = sizeof(mesh_cancel_rsp_param_mesh),
};

static const struct generic_data mesh_send_mesh_cancel_2 = {
	.send_opcode = MGMT_OP_MESH_SEND_CANCEL,
	.send_param = send_mesh_cancel_2,
	.send_len = sizeof(send_mesh_cancel_2),
	.expect_status = MGMT_STATUS_SUCCESS,
	.expect_alt_ev = MGMT_EV_MESH_PACKET_CMPLT,
	.expect_alt_ev_param = send_mesh_cancel_2,
	.expect_alt_ev_len = sizeof(send_mesh_cancel_2),

	.expect_hci_command = BT_HCI_CMD_LE_SET_ADV_ENABLE,
	.expect_hci_param = mesh_cancel_rsp_param_mesh,
	.expect_hci_len = sizeof(mesh_cancel_rsp_param_mesh),
};

static void setup_multi_mesh_send(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_enable_mesh(test_data);

	mgmt_send(data->mgmt, MGMT_OP_MESH_SEND, data->mgmt_index,
			sizeof(send_mesh_1), send_mesh_1,
			NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_MESH_SEND, data->mgmt_index,
			sizeof(send_mesh_1), send_mesh_1,
			NULL, NULL, NULL);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_bredrle("Controller setup",
			NULL, NULL, controller_setup);

	/* LL Mesh Enable
	 * Setup: None
	 * Run: Send Enable Experimental Feature (mesh)
	 * Expect: Mesh feature enable success
	 */
	test_bredrle("Mesh - Enable 1",
			&enable_mesh_1,
			NULL,
			test_command_generic);

	test_bredrle("Mesh - Enable 2",
			&enable_mesh_2,
			setup_enable_mesh,
			test_command_generic);

	test_bredrle("Mesh - Read Mesh Features",
			&read_mesh_features,
			setup_enable_mesh,
			test_command_generic);

	test_bredrle("Mesh - Read Mesh Features - Disabled",
			&read_mesh_features_disabled,
			NULL,
			test_command_generic);

	test_bredrle("Mesh - Send",
			&mesh_send_mesh_1,
			setup_enable_mesh,
			test_command_generic);

	test_bredrle("Mesh - Send - too short",
			&mesh_send_mesh_too_short,
			setup_enable_mesh,
			test_command_generic);

	test_bredrle("Mesh - Send - too long",
			&mesh_send_mesh_too_long,
			setup_enable_mesh,
			test_command_generic);

	test_bredrle("Mesh - Send cancel - 1",
			&mesh_send_mesh_cancel_1,
			setup_multi_mesh_send,
			test_command_generic);

	test_bredrle("Mesh - Send cancel - 2",
			&mesh_send_mesh_cancel_2,
			setup_multi_mesh_send,
			test_command_generic);

	return tester_run();
}
