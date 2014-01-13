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

static void dummy_test(const void *test_data)
{
	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_hci("User channel setup", NULL, NULL, dummy_test);

	return tester_run();
}
