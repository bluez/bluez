/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include "monitor/bt.h"
#include "src/shared/hci.h"
#include "src/shared/tester.h"

struct test_data {
	const void *test_data;
	uint16_t index;
	struct bt_hci *hci;
};

static void test_pre_setup_reset_complete(const void *data, uint8_t size,
							void *user_data)
{
	uint8_t status = *((uint8_t *) data);

	if (status) {
		tester_warn("HCI Reset command failed (0x%02x)", status);
		tester_pre_setup_failed();
		return;
	}

	tester_pre_setup_complete();
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->hci = bt_hci_new_user_channel(data->index);
	if (!data->hci) {
		tester_warn("Failed to setup HCI user channel");
		tester_pre_setup_failed();
		return;
	}

	if (!bt_hci_send(data->hci, BT_HCI_CMD_RESET, NULL, 0,
				test_pre_setup_reset_complete, NULL, NULL)) {
		tester_warn("Failed to send HCI Reset command");
		tester_pre_setup_failed();
		return;
	}
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	bt_hci_unref(data->hci);
	data->hci = NULL;

	tester_post_teardown_complete();
}

static void test_data_free(void *test_data)
{
	struct test_data *data = test_data;

	free(data);
}

#define test_hci(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = calloc(1, sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->test_data = data; \
		user->index = 0; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, test_data_free); \
	} while (0)

static void setup_features_complete(const void *data, uint8_t size,
							void *user_data)
{
	const struct bt_hci_rsp_read_local_features *rsp = data;

	if (rsp->status) {
		tester_warn("Failed to get HCI features (0x%02x)", rsp->status);
		tester_setup_failed();
		return;
	}

	tester_setup_complete();
}

static void setup_features(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (!bt_hci_send(data->hci, BT_HCI_CMD_READ_LOCAL_FEATURES, NULL, 0,
					setup_features_complete, NULL, NULL)) {
		tester_warn("Failed to send HCI features command");
		tester_setup_failed();
		return;
	}
}

static void test_reset(const void *test_data)
{
	tester_test_passed();
}

static void test_command_complete(const void *data, uint8_t size,
							void *user_data)
{
	uint8_t status = *((uint8_t *) data);

	if (status) {
		tester_warn("HCI command failed (0x%02x)", status);
		tester_test_failed();
		return;
	}

	tester_test_passed();
}

static void test_command(uint16_t opcode)
{
	struct test_data *data = tester_get_data();

	if (!bt_hci_send(data->hci, opcode, NULL, 0,
					test_command_complete, NULL, NULL)) {
		tester_warn("Failed to send HCI command 0x%04x", opcode);
		tester_test_failed();
		return;
	}
}

static void test_read_local_version_information(const void *test_data)
{
	test_command(BT_HCI_CMD_READ_LOCAL_VERSION);
}

static void test_read_local_supported_commands(const void *test_data)
{
	test_command(BT_HCI_CMD_READ_LOCAL_COMMANDS);
}

static void test_read_local_supported_features(const void *test_data)
{
	test_command(BT_HCI_CMD_READ_LOCAL_FEATURES);
}

static void test_local_extended_features_complete(const void *data,
						uint8_t size, void *user_data)
{
	const struct bt_hci_rsp_read_local_ext_features *rsp = data;

	if (rsp->status) {
		tester_warn("Failed to get HCI extended features (0x%02x)",
								rsp->status);
		tester_test_failed();
		return;
	}

	tester_test_passed();
}

static void test_read_local_extended_features(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bt_hci_cmd_read_local_ext_features cmd;

	cmd.page = 0x00;

	if (!bt_hci_send(data->hci, BT_HCI_CMD_READ_LOCAL_EXT_FEATURES,
					&cmd, sizeof(cmd),
					test_local_extended_features_complete,
								NULL, NULL)) {
		tester_warn("Failed to send HCI extended features command");
		tester_test_failed();
		return;
	}
}

static void test_read_buffer_size(const void *test_data)
{
	test_command(BT_HCI_CMD_READ_BUFFER_SIZE);
}

static void test_read_country_code(const void *test_data)
{
	test_command(BT_HCI_CMD_READ_COUNTRY_CODE);
}

static void test_read_bd_addr(const void *test_data)
{
	test_command(BT_HCI_CMD_READ_BD_ADDR);
}

static void test_read_local_supported_codecs(const void *test_data)
{
	test_command(BT_HCI_CMD_READ_LOCAL_CODECS);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_hci("Reset", NULL, NULL, test_reset);

	test_hci("Read Local Version Information", NULL, NULL,
				test_read_local_version_information);
	test_hci("Read Local Supported Commands", NULL, NULL,
				test_read_local_supported_commands);
	test_hci("Read Local Supported Features", NULL, NULL,
				test_read_local_supported_features);
	test_hci("Read Local Extended Features", NULL,
				setup_features,
				test_read_local_extended_features);
	test_hci("Read Buffer Size", NULL, NULL,
				test_read_buffer_size);
	test_hci("Read Country Code", NULL, NULL,
				test_read_country_code);
	test_hci("Read BD_ADDR", NULL, NULL,
				test_read_bd_addr);
	test_hci("Read Local Supported Codecs", NULL, NULL,
				test_read_local_supported_codecs);

	return tester_run();
}
