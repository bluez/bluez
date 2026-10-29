// SPDX-License-Identifier: LGPL-2.1-or-later
#include <assert.h>

/* Redirect source-level calls so LTO cannot bypass the GATT mock. */
#define bt_gatt_client_write_without_response test_gatt_write
#include "src/shared/asha.c"
#undef bt_gatt_client_write_without_response
#include "src/shared/tester.h"

static unsigned int writes;
static struct bt_gatt_client *failed_client;
static uint8_t expected_interval;

void btd_error(uint16_t index, const char *format, ...)
{
}

void btd_debug(uint16_t index, const char *format, ...)
{
}

unsigned int test_gatt_write(
	struct bt_gatt_client *client, uint16_t handle, bool signed_write,
				const uint8_t *value, uint16_t length)
{
	assert(client);
	assert(handle == 0x79);
	assert(!signed_write);
	assert(length == 3);
	assert(value[0] == 0x03 && value[1] == 0x02);
	assert(value[2] == expected_interval);
	writes++;
	return client != failed_client;
}

static void test_interval(const void *user_data)
{
	struct bt_asha left = {
		.client = (void *) 1, .acp_handle = 0x79, .hisyncid = { 1 },
	};
	struct bt_asha right = {
		.client = (void *) 2, .acp_handle = 0x79, .hisyncid = { 1 },
		.right_side = true,
	};
	struct bt_asha unrelated = {
		.client = (void *) 3, .acp_handle = 0x79, .hisyncid = { 2 },
	};

	asha_devices = queue_new();
	update_asha_set(&left, true);
	update_asha_set(&right, true);
	update_asha_set(&unrelated, true);
	writes = 0;
	expected_interval = 16;

	/* Both attached sides, including a stopped peer, receive the update. */
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 2);
	assert(bt_asha_set_connection_interval(&right, expected_interval));
	assert(writes == 4);
	assert(bt_asha_set_connection_interval(&unrelated, expected_interval));
	assert(writes == 5);

	assert(!bt_asha_set_connection_interval(&left, 5));
	assert(!bt_asha_set_connection_interval(&left, 256));
	assert(!bt_asha_set_connection_interval(NULL, 16));
	assert(writes == 5);

	expected_interval = 6;
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 7);
	expected_interval = 255;
	assert(bt_asha_set_connection_interval(&right, expected_interval));
	assert(writes == 9);

	/* Failure on either side does not suppress the other side's attempt. */
	failed_client = left.client;
	assert(!bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 11);
	assert(!bt_asha_set_connection_interval(&right, expected_interval));
	assert(writes == 13);
	failed_client = NULL;

	right.client = NULL;
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 14);
	assert(!bt_asha_set_connection_interval(&right, expected_interval));
	assert(writes == 14);

	update_asha_set(&right, false);
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 15);
	update_asha_set(&left, false);
	update_asha_set(&unrelated, false);
	assert(!asha_devices);
	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	tester_add("ASHA/interval/pair", NULL, NULL, test_interval, NULL);
	return tester_run();
}
