// SPDX-License-Identifier: LGPL-2.1-or-later
#include <assert.h>

/* Source-level mocks remain effective with link-time optimization. */
#define bt_gatt_client_write_without_response test_write_command
#define bt_gatt_client_write_value test_write_request
#include "src/shared/asha.c"
#undef bt_gatt_client_write_without_response
#undef bt_gatt_client_write_value
#include "src/shared/tester.h"

static unsigned int commands, requests;
static bool volume_ok, start_ok;
static int8_t selected_volume;

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
	assert(client && handle == 0x82 && !signed_write);
	assert(length == 1 && (int8_t) value[0] == selected_volume);
	assert(requests == 0);
	commands++;
	return volume_ok;
}

unsigned int test_write_request(struct bt_gatt_client *client, uint16_t handle,
				const uint8_t *value, uint16_t length,
				bt_gatt_client_callback_t callback, void *data,
				bt_gatt_client_destroy_func_t destroy)
{
	assert(client && handle == 0x79);
	assert(commands == 1 && requests == 0);
	assert(length == 5 && value[0] == 0x01 && value[1] == 0x01);
	assert((int8_t) value[3] == selected_volume);
	assert(callback && data && !destroy);
	requests++;
	return start_ok;
}

static void test_start(const void *user_data)
{
	const int8_t volumes[] = { -128, -127, -64, 0 };
	unsigned int i, fail;

	for (i = 0; i < ARRAY_SIZE(volumes); i++) {
		for (fail = 0; fail < 2; fail++) {
			struct bt_asha asha = {
				.client = (void *) 1, .acp_handle = 0x79,
				.volume_handle = 0x82, .volume = volumes[i],
			};

			selected_volume = volumes[i];
			commands = requests = 0;
			volume_ok = !fail;
			start_ok = true;
			assert(bt_asha_start(&asha, NULL, NULL) == 0);
			assert(commands == 1 && requests == 1);
			assert(asha.state == ASHA_STARTING);
			assert(asha.volume == selected_volume);

			/* A repeated start must not write the volume again. */
			bt_asha_start(&asha, NULL, NULL);
			assert(commands == 1 && requests == 1);
		}
	}

	{
		struct bt_asha asha = {
			.client = (void *) 1, .acp_handle = 0x79,
			.volume_handle = 0x82, .volume = -64,
		};

		commands = requests = 0;
		selected_volume = asha.volume;
		volume_ok = true;
		start_ok = false;
		assert(bt_asha_start(&asha, NULL, NULL) == (unsigned int) -1);
		assert(asha.state == ASHA_STOPPED);
		assert(commands == 1 && requests == 1);
	}

	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	tester_add("ASHA/start/volume", NULL, NULL, test_start, NULL);
	return tester_run();
}
