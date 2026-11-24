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

static void detach(struct bt_asha *asha)
{
	/* Fixtures mock client pointers instead of owning GATT clients. */
	asha->client = NULL;
	bt_asha_reset(asha);
}

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
		.psm = 0x25,
	};
	struct bt_asha right = {
		.client = (void *) 2, .acp_handle = 0x79, .hisyncid = { 1 },
		.right_side = true,
		.psm = 0x25,
	};
	struct bt_asha unrelated = {
		.client = (void *) 3, .acp_handle = 0x79, .hisyncid = { 2 },
		.psm = 0x25,
	};

	asha_devices = queue_new();
	check_probe_done(&left);
	check_probe_done(&right);
	check_probe_done(&unrelated);
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
	assert(!bt_asha_set_connection_interval(&left, 0));
	assert(!bt_asha_set_connection_interval(&left, 256));
	assert(!bt_asha_set_connection_interval(&left, UINT16_MAX));
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
	right.client = (void *) 2;
	right.acp_handle = 0;
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 15);
	assert(!bt_asha_set_connection_interval(&right, expected_interval));
	assert(writes == 15);

	detach(&right);
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 16);
	detach(&left);
	detach(&unrelated);
	assert(!asha_devices && !asha_attached);
	tester_test_passed();
}

/* How the object that leaves a pair is torn down, as the device code does. */
#define TEST_RIGHT	0x01	/* The leaving object is the right side */
#define TEST_RESET	0x02	/* Disconnect: reset, then reset again */
#define TEST_FREE	0x04	/* Device removal: free, after any reset */

static void test_leave(const void *user_data)
{
	unsigned int flags = PTR_TO_UINT(user_data);
	bool right = flags & TEST_RIGHT;
	struct bt_asha *leaving = bt_asha_new();
	struct bt_asha remaining = {
		.client = (void *) 1, .acp_handle = 0x79, .hisyncid = { 1 },
		.right_side = !right,
		.psm = 0x25,
	};
	struct bt_asha_set *set;

	leaving->hisyncid[0] = 1;
	leaving->right_side = right;
	leaving->psm = 0x25;
	asha_devices = queue_new();
	check_probe_done(leaving);
	check_probe_done(&remaining);
	update_asha_set(leaving, true);
	update_asha_set(&remaining, true);

	if (flags & TEST_RESET) {
		bt_asha_reset(leaving);
		bt_asha_reset(leaving);
	}

	if (flags & TEST_FREE) {
		bt_asha_free(leaving);
		leaving = NULL;
	}

	/* No slot may keep the object, so a freed one is never reached. */
	set = find_asha_set(&remaining);
	assert(set);
	assert(right ? !set->right : !set->left);
	assert(right ? set->left == &remaining : set->right == &remaining);

	writes = 0;
	expected_interval = 16;
	assert(bt_asha_set_connection_interval(&remaining, 16));
	assert(writes == 1);

	/* Releasing an object that is no longer in a set stays harmless. */
	if (leaving)
		bt_asha_free(leaving);

	detach(&remaining);
	assert(!asha_devices && !asha_attached);
	tester_test_passed();
}

/* A newer object for the same side must survive the older one's release. */
static void test_replace(const void *user_data)
{
	unsigned int flags = PTR_TO_UINT(user_data);
	bool right = flags & TEST_RIGHT;
	struct bt_asha *old = bt_asha_new();
	struct bt_asha *cur = bt_asha_new();
	struct bt_asha remaining = {
		.client = (void *) 1, .acp_handle = 0x79, .hisyncid = { 1 },
		.right_side = !right,
		.psm = 0x25,
	};
	struct bt_asha_set *set;

	old->hisyncid[0] = cur->hisyncid[0] = 1;
	old->right_side = cur->right_side = right;
	cur->client = (void *) 2;
	cur->acp_handle = 0x79;
	old->client = (void *) 3;
	old->acp_handle = 0x79;
	old->psm = cur->psm = 0x25;
	asha_devices = queue_new();
	check_probe_done(old);
	check_probe_done(&remaining);
	check_probe_done(cur);
	update_asha_set(old, true);
	update_asha_set(&remaining, true);
	update_asha_set(cur, true);
	writes = 0;
	expected_interval = 16;
	failed_client = old->client;
	assert(bt_asha_set_connection_interval(&remaining, expected_interval));
	assert(writes == 2);
	failed_client = NULL;
	old->client = NULL;

	if (flags & TEST_RESET)
		bt_asha_reset(old);
	else
		bt_asha_free(old);

	set = find_asha_set(&remaining);
	assert(set);
	assert(right ? set->right == cur : set->left == cur);

	writes = 0;
	expected_interval = 16;
	assert(bt_asha_set_connection_interval(&remaining, 16));
	assert(writes == 2);

	if (flags & TEST_RESET)
		bt_asha_free(old);

	cur->client = NULL;
	bt_asha_free(cur);
	detach(&remaining);
	assert(!asha_devices && !asha_attached);
	tester_test_passed();
}

static void attach_properties(struct bt_asha *asha, bool right, bool psm_first)
{
	uint8_t rops[] = {
		1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0,
	};
	uint8_t psm[] = { 0x25, 0 };

	rops[1] |= right;

	if (psm_first)
		read_psm(true, 0, psm, sizeof(psm), asha);

	read_rops(true, 0, rops, sizeof(rops), asha);

	if (!psm_first)
		read_psm(true, 0, psm, sizeof(psm), asha);
}

static void test_attach(const void *user_data)
{
	unsigned int flags = PTR_TO_UINT(user_data);
	struct bt_asha left = { .client = (void *) 1, .acp_handle = 0x79 };
	struct bt_asha right = { .client = (void *) 2, .acp_handle = 0x79 };
	struct bt_asha *sender = flags & 1 ? &right : &left;

	asha_devices = queue_new();
	attach_properties(&left, false, flags & 2);
	attach_properties(&right, true, flags & 2);
	assert(queue_length(asha_attached) == 2);
	check_probe_done(&right);
	assert(queue_length(asha_attached) == 2);
	/* Attachment must not change the existing START other-connected bit. */
	assert(!is_other_connected(&left) && !is_other_connected(&right));
	writes = 0;
	expected_interval = 16;
	assert(bt_asha_set_connection_interval(sender, expected_interval));
	assert(writes == 2);
	assert(left.state == ASHA_STOPPED && right.state == ASHA_STOPPED);
	detach(&left);
	detach(&right);
	assert(!asha_attached);
	queue_destroy(asha_devices, NULL);
	asha_devices = NULL;
	tester_test_passed();
}

static void test_incomplete_peer(const void *user_data)
{
	struct bt_asha left = { .client = (void *) 1, .acp_handle = 0x79 };
	struct bt_asha right = {
		.client = (void *) 2, .acp_handle = 0x79, .right_side = true,
		.hisyncid = { 1 },
	};

	asha_devices = queue_new();
	attach_properties(&left, false, false);
	check_probe_done(&right);
	writes = 0;
	expected_interval = 16;
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 1);
	right.psm = 0x25;
	memset(right.hisyncid, 0, sizeof(right.hisyncid));
	check_probe_done(&right);
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 2);
	attach_properties(&right, true, false);
	assert(bt_asha_set_connection_interval(&left, expected_interval));
	assert(writes == 4);
	detach(&left);
	detach(&right);
	assert(!asha_attached);
	queue_destroy(asha_devices, NULL);
	asha_devices = NULL;
	tester_test_passed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);
	tester_add("ASHA/interval/pair", NULL, NULL, test_interval, NULL);
	tester_add("ASHA/attach/left/rops-first", UINT_TO_PTR(0), NULL,
							test_attach, NULL);
	tester_add("ASHA/attach/right/rops-first", UINT_TO_PTR(1), NULL,
							test_attach, NULL);
	tester_add("ASHA/attach/left/psm-first", UINT_TO_PTR(2), NULL,
							test_attach, NULL);
	tester_add("ASHA/attach/right/psm-first", UINT_TO_PTR(3), NULL,
							test_attach, NULL);
	tester_add("ASHA/attach/incomplete", NULL, NULL,
						test_incomplete_peer, NULL);

	tester_add("ASHA/leave/reset/left", UINT_TO_PTR(TEST_RESET), NULL,
							test_leave, NULL);
	tester_add("ASHA/leave/reset/right",
			UINT_TO_PTR(TEST_RESET | TEST_RIGHT), NULL,
							test_leave, NULL);
	tester_add("ASHA/leave/free/left", UINT_TO_PTR(TEST_FREE), NULL,
							test_leave, NULL);
	tester_add("ASHA/leave/free/right",
			UINT_TO_PTR(TEST_FREE | TEST_RIGHT), NULL,
							test_leave, NULL);
	tester_add("ASHA/leave/reset-free/left",
			UINT_TO_PTR(TEST_RESET | TEST_FREE), NULL,
							test_leave, NULL);
	tester_add("ASHA/leave/reset-free/right",
		UINT_TO_PTR(TEST_RESET | TEST_FREE | TEST_RIGHT), NULL,
							test_leave, NULL);

	tester_add("ASHA/replace/free/left", UINT_TO_PTR(0), NULL,
							test_replace, NULL);
	tester_add("ASHA/replace/free/right", UINT_TO_PTR(TEST_RIGHT), NULL,
							test_replace, NULL);
	tester_add("ASHA/replace/reset/left", UINT_TO_PTR(TEST_RESET), NULL,
							test_replace, NULL);
	tester_add("ASHA/replace/reset/right",
			UINT_TO_PTR(TEST_RESET | TEST_RIGHT), NULL,
							test_replace, NULL);
	return tester_run();
}
