/*
 * Copyright (C) 2014 Intel Corporation
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

#include <stdbool.h>

#include "emulator/bthost.h"
#include "src/shared/util.h"

#include "tester-main.h"
#include "android/utils.h"

static struct queue *list;

struct emu_cid_data {
	uint16_t handle;
	uint16_t cid;
};

static struct emu_cid_data sdp_data;
static struct emu_cid_data a2dp_data;
static struct emu_cid_data avrcp_data;

static const uint8_t sdp_rsp_pdu[] = { 0x07, /* PDU id */
			0x00, 0x00, /* Transaction id */
			0x00, 0x7f, /* Response length */
			0x00, 0x7c, /* Attributes length */
			0x36, 0x00, 0x79, 0x36, 0x00, 0x3b, 0x09, 0x00, 0x00,
			0x0a, 0x00, 0x01, 0x00, 0x04, 0x09, 0x00, 0x01, 0x35,
			0x06, 0x19, 0x11, 0x0e, 0x19, 0x11, 0x0f, 0x09, 0x00,
			0x04, 0x35, 0x10, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09,
			0x00, 0x17, 0x35, 0x06, 0x19, 0x00, 0x17, 0x09, 0x01,
			0x03, 0x09, 0x00, 0x09, 0x35, 0x08, 0x35, 0x06, 0x19,
			0x11, 0x0e, 0x09, 0x01, 0x00, 0x09, 0x03, 0x11, 0x09,
			0x00, 0x01, 0x36, 0x00, 0x38, 0x09, 0x00, 0x00, 0x0a,
			0x00, 0x01, 0x00, 0x05, 0x09, 0x00, 0x01, 0x35, 0x03,
			0x19, 0x11, 0x0c, 0x09, 0x00, 0x04, 0x35, 0x10, 0x35,
			0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x17, 0x35, 0x06,
			0x19, 0x00, 0x17, 0x09, 0x01, 0x03, 0x09, 0x00, 0x09,
			0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0e, 0x09, 0x01,
			0x04, 0x09, 0x03, 0x11, 0x09, 0x00, 0x02,
			0x00}; /* no continuation */
static const uint8_t req_dsc[] = { 0x00, 0x01 };
static const uint8_t rsp_dsc[] = { 0x02, 0x01, 0x04, 0x08 };
static const uint8_t req_get[] = { 0x10, 0x02, 0x04 };
static const uint8_t rsp_get[] = { 0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00,
						0x00, 0xff, 0xff, 0x02, 0x40 };
static const uint8_t req_cfg[] = { 0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07,
					0x06, 0x00, 0x00, 0x21, 0x15, 0x02,
					0x40 };
static const uint8_t rsp_cfg[] = { 0x22, 0x03 };
static const uint8_t req_open[] = { 0x30, 0x06, 0x04 };
static const uint8_t rsp_open[] = { 0x32, 0x06 };
static const uint8_t req_close[] = { 0x40, 0x08, 0x04 };
static const uint8_t rsp_close[] = { 0x42, 0x08 };
static const uint8_t req_start[] = { 0x40, 0x07, 0x04 };
static const uint8_t rsp_start[] = { 0x42, 0x07 };
static const uint8_t req_suspend[] = { 0x50, 0x09, 0x04 };
static const uint8_t rsp_suspend[] = { 0x52, 0x09 };

static const struct pdu {
	const uint8_t *req;
	size_t req_len;
	const uint8_t *rsp;
	size_t rsp_len;
} pdus[] = {
	{ req_dsc, sizeof(req_dsc), rsp_dsc, sizeof(rsp_dsc) },
	{ req_get, sizeof(req_get), rsp_get, sizeof(rsp_get) },
	{ req_cfg, sizeof(req_cfg), rsp_cfg, sizeof(rsp_cfg) },
	{ req_open, sizeof(req_open), rsp_open, sizeof(rsp_open) },
	{ req_close, sizeof(req_close), rsp_close, sizeof(rsp_close) },
	{ req_start, sizeof(req_start), rsp_start, sizeof(rsp_start) },
	{ req_suspend, sizeof(req_suspend), rsp_suspend, sizeof(rsp_start) },
	{ },
};

static void print_avrcp(const char *str, void *user_data)
{
	tester_debug("avrcp: %s", str);
}

static void avrcp_cid_hook_cb(const void *data, uint16_t len, void *user_data)
{
	util_hexdump('>', data, len, print_avrcp, NULL);
}

static void avrcp_connect_request_cb(uint16_t handle, uint16_t cid,
							void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	struct emu_cid_data *cid_data = user_data;

	cid_data->handle = handle;
	cid_data->cid = cid;

	bthost_add_cid_hook(bthost, handle, cid, avrcp_cid_hook_cb, cid_data);
}

static struct emu_set_l2cap_data avrcp_setup_data = {
	.psm = 23,
	.func = avrcp_connect_request_cb,
	.user_data = &avrcp_data,
};

static void print_a2dp(const char *str, void *user_data)
{
	tester_debug("a2dp: %s", str);
}

static void a2dp_cid_hook_cb(const void *data, uint16_t len, void *user_data)
{
	struct emu_cid_data *cid_data = user_data;
	struct test_data *t_data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(t_data->hciemu);
	int i;

	util_hexdump('>', data, len, print_a2dp, NULL);

	for (i = 0; pdus[i].req; i++) {
		if (pdus[i].req_len != len)
			continue;

		if (memcmp(pdus[i].req, data, len))
			continue;

		util_hexdump('<', pdus[i].rsp, pdus[i].rsp_len, print_a2dp,
									NULL);

		bthost_send_cid(bthost, cid_data->handle, cid_data->cid,
						pdus[i].rsp, pdus[i].rsp_len);
	}
}

static void a2dp_connect_request_cb(uint16_t handle, uint16_t cid,
							void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	struct emu_cid_data *cid_data = user_data;

	if (cid_data->handle)
		return;

	cid_data->handle = handle;
	cid_data->cid = cid;

	bthost_add_cid_hook(bthost, handle, cid, a2dp_cid_hook_cb, cid_data);
}

static struct emu_set_l2cap_data a2dp_setup_data = {
	.psm = 25,
	.func = a2dp_connect_request_cb,
	.user_data = &a2dp_data,
};

static void sdp_cid_hook_cb(const void *data, uint16_t len, void *user_data)
{
	struct test_data *t_data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(t_data->hciemu);
	struct emu_cid_data *cid_data = user_data;

	bthost_send_cid(bthost, cid_data->handle, cid_data->cid,
					sdp_rsp_pdu, sizeof(sdp_rsp_pdu));
}
static void sdp_connect_request_cb(uint16_t handle, uint16_t cid,
							void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	struct emu_cid_data *cid_data = user_data;

	cid_data->handle = handle;
	cid_data->cid = cid;

	bthost_add_cid_hook(bthost, handle, cid, sdp_cid_hook_cb, cid_data);
}

static struct emu_set_l2cap_data sdp_setup_data = {
	.psm = 1,
	.func = sdp_connect_request_cb,
	.user_data = &sdp_data,
};

static void avrcp_connect_action(void)
{
	struct test_data *data = tester_get_data();
	const uint8_t *addr = hciemu_get_client_bdaddr(data->hciemu);
	struct step *step = g_new0(struct step, 1);
	bt_bdaddr_t bdaddr;

	sdp_data.handle = 0;
	sdp_data.cid = 0;

	a2dp_data.handle = 0;
	a2dp_data.cid = 0;

	avrcp_data.handle = 0;
	avrcp_data.cid = 0;

	bdaddr2android((const bdaddr_t *) addr, &bdaddr);

	step->action_status = data->if_a2dp->connect(&bdaddr);

	schedule_action_verification(step);
}

static void avrcp_disconnect_action(void)
{
	struct test_data *data = tester_get_data();
	const uint8_t *addr = hciemu_get_client_bdaddr(data->hciemu);
	struct step *step = g_new0(struct step, 1);
	bt_bdaddr_t bdaddr;

	bdaddr2android((const bdaddr_t *) addr, &bdaddr);

	step->action_status = data->if_a2dp->disconnect(&bdaddr);

	schedule_action_verification(step);
}

static struct test_case test_cases[] = {
	TEST_CASE_BREDRLE("AVRCP Init",
		ACTION_SUCCESS(dummy_action, NULL),
	),
	TEST_CASE_BREDRLE("AVRCP Connect - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_add_l2cap_server_action, &sdp_setup_data),
		ACTION_SUCCESS(emu_add_l2cap_server_action, &a2dp_setup_data),
		ACTION_SUCCESS(emu_add_l2cap_server_action, &avrcp_setup_data),
		ACTION_SUCCESS(avrcp_connect_action, NULL),
		CALLBACK_AV_CONN_STATE(CB_A2DP_CONN_STATE,
					BTAV_CONNECTION_STATE_CONNECTING),
		CALLBACK_AV_CONN_STATE(CB_A2DP_CONN_STATE,
					BTAV_CONNECTION_STATE_CONNECTED),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("AVRCP Disconnect - Success",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_add_l2cap_server_action, &sdp_setup_data),
		ACTION_SUCCESS(emu_add_l2cap_server_action, &a2dp_setup_data),
		ACTION_SUCCESS(emu_add_l2cap_server_action, &avrcp_setup_data),
		ACTION_SUCCESS(avrcp_connect_action, NULL),
		CALLBACK_AV_CONN_STATE(CB_A2DP_CONN_STATE,
					BTAV_CONNECTION_STATE_CONNECTING),
		CALLBACK_AV_CONN_STATE(CB_A2DP_CONN_STATE,
					BTAV_CONNECTION_STATE_CONNECTED),
		ACTION_SUCCESS(avrcp_disconnect_action, NULL),
		CALLBACK_AV_CONN_STATE(CB_A2DP_CONN_STATE,
					BTAV_CONNECTION_STATE_DISCONNECTING),
		CALLBACK_AV_CONN_STATE(CB_A2DP_CONN_STATE,
					BTAV_CONNECTION_STATE_DISCONNECTED),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
};

struct queue *get_avrcp_tests(void)
{
	uint16_t i = 0;

	list = queue_new();

	for (; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		if (!queue_push_tail(list, &test_cases[i]))
			return NULL;

	return list;
}

void remove_avrcp_tests(void)
{
	queue_destroy(list, NULL);
}
