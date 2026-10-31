// SPDX-License-Identifier: LGPL-2.1-or-later
#include <assert.h>

/* Source-level mocks remain effective with link-time optimization. */
#define bt_gatt_client_write_without_response test_write_command
#define bt_gatt_client_write_value test_write_request
#include "src/shared/asha.c"
#undef bt_gatt_client_write_without_response
#undef bt_gatt_client_write_value
#include "src/shared/tester.h"

static unsigned int commands, requests, peer_updates;
static bool command_ok;

void btd_error(uint16_t index, const char *format, ...)
{
}

void btd_debug(uint16_t index, const char *format, ...)
{
}

unsigned int test_write_command(struct bt_gatt_client *client, uint16_t handle,
					bool signed_write,
					const uint8_t *value, uint16_t length)
{
	assert(client && handle == 0x79 && !signed_write);

	if (value[0] == 0x02) {
		assert(length == 1);
		commands++;
		return command_ok;
	}

	assert(length == 2 && value[0] == 0x03 && value[1] == 0x00);
	peer_updates++;
	return 1;
}

unsigned int test_write_request(struct bt_gatt_client *client, uint16_t handle,
				const uint8_t *value, uint16_t length,
				bt_gatt_client_callback_t callback, void *data,
				bt_gatt_client_destroy_func_t destroy)
{
	requests++;
	return 1;
}

static void state_callback(int status, void *data)
{
	assert(false);
}

static void test_stop(const void *user_data)
{
	unsigned int fail;

	for (fail = 0; fail < 2; fail++) {
		struct bt_asha left = {
			.client = (void *) 1, .acp_handle = 0x79,
			.hisyncid = { 1 }, .state = ASHA_STARTED,
			.state_cb = state_callback, .state_cb_data = (void *) 1,
		};
		struct bt_asha right = {
			.client = (void *) 2, .acp_handle = 0x79,
			.hisyncid = { 1 }, .right_side = true,
			.state = ASHA_STARTED,
		};

		asha_devices = queue_new();
		update_asha_set(&left, true);
		update_asha_set(&right, true);
		commands = requests = peer_updates = 0;
		command_ok = !fail;
		assert(bt_asha_stop(&left) == (fail ? (unsigned int) -1 : 0));
		assert(commands == 1 && requests == 0 && peer_updates == 1);
		assert(left.state == ASHA_STOPPED);
		assert(right.state == ASHA_STARTED);
		assert(!left.state_cb && !left.state_cb_data);

		/* Repeated stop must not send another control command. */
		assert(bt_asha_stop(&left) == 0);
		assert(commands == 1 && requests == 0 && peer_updates == 1);
		update_asha_set(&left, false);
		update_asha_set(&right, false);
		assert(!asha_devices);
	}

	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	tester_add("ASHA/stop/command", NULL, NULL, test_stop, NULL);
	return tester_run();
}
