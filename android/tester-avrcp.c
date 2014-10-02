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

#define sdp_rsp_pdu	0x07, \
			0x00, 0x00, \
			0x00, 0x7f, \
			0x00, 0x7c, \
			0x36, 0x00, 0x79, 0x36, 0x00, 0x3b, 0x09, 0x00, 0x00, \
			0x0a, 0x00, 0x01, 0x00, 0x04, 0x09, 0x00, 0x01, 0x35, \
			0x06, 0x19, 0x11, 0x0e, 0x19, 0x11, 0x0f, 0x09, 0x00, \
			0x04, 0x35, 0x10, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, \
			0x00, 0x17, 0x35, 0x06, 0x19, 0x00, 0x17, 0x09, 0x01, \
			0x03, 0x09, 0x00, 0x09, 0x35, 0x08, 0x35, 0x06, 0x19, \
			0x11, 0x0e, 0x09, 0x01, 0x00, 0x09, 0x03, 0x11, 0x09, \
			0x00, 0x01, 0x36, 0x00, 0x38, 0x09, 0x00, 0x00, 0x0a, \
			0x00, 0x01, 0x00, 0x05, 0x09, 0x00, 0x01, 0x35, 0x03, \
			0x19, 0x11, 0x0c, 0x09, 0x00, 0x04, 0x35, 0x10, 0x35, \
			0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x17, 0x35, 0x06, \
			0x19, 0x00, 0x17, 0x09, 0x01, 0x03, 0x09, 0x00, 0x09, \
			0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x0e, 0x09, 0x01, \
			0x04, 0x09, 0x03, 0x11, 0x09, 0x00, 0x02, \
			0x00

static const struct pdu_set sdp_pdus[] = {
	{ end_pdu, raw_pdu(sdp_rsp_pdu) },
	{ end_pdu, end_pdu },
};

static struct emu_l2cap_cid_data sdp_data = {
	.pdu = sdp_pdus,
	.is_sdp = TRUE,
};

#define req_dsc 0x00, 0x01
#define rsp_dsc 0x02, 0x01, 0x04, 0x08
#define req_get 0x10, 0x02, 0x04
#define rsp_get 0x12, 0x02, 0x01, 0x00, 0x07, 0x06, 0x00, \
						0x00, 0xff, 0xff, 0x02, 0x40
#define req_cfg 0x20, 0x03, 0x04, 0x04, 0x01, 0x00, 0x07, \
					0x06, 0x00, 0x00, 0x21, 0x15, 0x02, \
					0x40
#define rsp_cfg 0x22, 0x03
#define req_open 0x30, 0x06, 0x04
#define rsp_open 0x32, 0x06
#define req_close 0x40, 0x08, 0x04
#define rsp_close 0x42, 0x08
#define req_start 0x40, 0x07, 0x04
#define rsp_start 0x42, 0x07
#define req_suspend 0x50, 0x09, 0x04
#define rsp_suspend 0x52, 0x09

static const struct pdu_set pdus[] = {
	{ raw_pdu(req_dsc), raw_pdu(rsp_dsc) },
	{ raw_pdu(req_get), raw_pdu(rsp_get) },
	{ raw_pdu(req_cfg), raw_pdu(rsp_cfg) },
	{ raw_pdu(req_open), raw_pdu(rsp_open) },
	{ raw_pdu(req_close), raw_pdu(rsp_close) },
	{ raw_pdu(req_start), raw_pdu(rsp_start) },
	{ raw_pdu(req_suspend), raw_pdu(rsp_suspend) },
	{ end_pdu, end_pdu },
};

static struct emu_l2cap_cid_data a2dp_data = {
	.pdu = pdus,
};

static struct emu_l2cap_cid_data avrcp_data;

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
	struct emu_l2cap_cid_data *cid_data = user_data;

	cid_data->handle = handle;
	cid_data->cid = cid;

	bthost_add_cid_hook(bthost, handle, cid, avrcp_cid_hook_cb, cid_data);
}

static struct emu_set_l2cap_data avrcp_setup_data = {
	.psm = 23,
	.func = avrcp_connect_request_cb,
	.user_data = &avrcp_data,
};

static void a2dp_connect_request_cb(uint16_t handle, uint16_t cid,
							void *user_data)
{
	struct emu_l2cap_cid_data *cid_data = user_data;

	if (cid_data->handle)
		return;

	cid_data->handle = handle;
	cid_data->cid = cid;

	tester_handle_l2cap_data_exchange(cid_data);
}

static struct emu_set_l2cap_data a2dp_setup_data = {
	.psm = 25,
	.func = a2dp_connect_request_cb,
	.user_data = &a2dp_data,
};

static struct emu_set_l2cap_data sdp_setup_data = {
	.psm = 1,
	.func = tester_generic_connect_cb,
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
		ACTION_SUCCESS(set_default_ssp_request_handler, NULL),
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
		ACTION_SUCCESS(set_default_ssp_request_handler, NULL),
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
