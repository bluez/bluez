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
#include "tester-main.h"
#include "src/shared/util.h"

#define L2CAP_ATT_EXCHANGE_MTU_REQ		0x02
#define L2CAP_ATT_EXCHANGE_MTU_RSP		0x03

#define GATT_STATUS_SUCCESS	0x00000000
#define GATT_STATUS_FAILURE	0x00000101

#define CLIENT1_ID	1
#define CLIENT2_ID	2

#define CONN1_ID	1
#define CONN2_ID	2

#define data(args...) ((const unsigned char[]) { args })

#define raw_pdu(args...)					\
	{							\
		.data = data(args),				\
		.size = sizeof(data(args)),			\
	}

#define end_pdu { .data = NULL }

static struct queue *list; /* List of gatt test cases */

struct pdu {
	const uint8_t *data;
	uint16_t size;
};

static bt_uuid_t client_app_uuid = {
	.uu = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
};

struct emu_cid_data {
	const int pdu_len;
	const void *pdu;

	uint16_t handle;
	uint16_t cid;
};

struct gatt_connect_data {
	const int client_id;
	const int conn_id;
};

struct gatt_search_service_data {
	const int conn_id;
	bt_uuid_t *filter_uuid;
};

struct get_char_data {
	const int conn_id;
	btgatt_srvc_id_t *service;
};

static bt_uuid_t client2_app_uuid = {
	.uu = { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
				0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 },
};

static bt_bdaddr_t emu_remote_bdaddr_val = {
	.address = { 0x00, 0xaa, 0x01, 0x01, 0x00, 0x00 },
};
static bt_property_t prop_emu_remotes_default_set[] = {
	{ BT_PROPERTY_BDADDR, sizeof(emu_remote_bdaddr_val),
						&emu_remote_bdaddr_val },
};

static bt_scan_mode_t setprop_scan_mode_conn_val =
					BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;

static bt_property_t prop_test_scan_mode_conn = {
	.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.val = &setprop_scan_mode_conn_val,
	.len = sizeof(setprop_scan_mode_conn_val),
};

static struct emu_cid_data cid_data;

static struct gatt_connect_data client1_conn_req = {
	.client_id = CLIENT1_ID,
	.conn_id = CONN1_ID,
};

static struct gatt_connect_data client1_conn2_req = {
	.client_id = CLIENT1_ID,
	.conn_id = CONN2_ID,
};

static struct gatt_connect_data client2_conn_req = {
	.client_id = CLIENT2_ID,
	.conn_id = CONN2_ID,
};

static struct gatt_search_service_data search_services_1 = {
	.conn_id = CONN1_ID,
	.filter_uuid = NULL,
};

static const uint8_t exchange_mtu_req_pdu[] = { 0x02, 0xa0, 0x02 };
static const uint8_t exchange_mtu_resp_pdu[] = { 0x03, 0xa0, 0x02 };

static struct bt_action_data bearer_type = {
	.bearer_type = BDADDR_LE_PUBLIC,
};

static btgatt_srvc_id_t service_1 = {
	.is_primary = true,
	.id = {
		.inst_id = 0,
		.uuid.uu = {0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00,  0x00, 0x18, 0x00, 0x00}
	}
};

static btgatt_srvc_id_t service_2 = {
	.is_primary = true,
	.id = {
		.inst_id = 1,
		.uuid.uu = {0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00,  0x01, 0x18, 0x00, 0x00},
	}
};

static btgatt_gatt_id_t characteristic_1 = {
	.inst_id = 0,
	.uuid.uu = {0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00,  0x19, 0x00, 0x00, 0x00}
};

static struct get_char_data get_char_data_1 = {
	.conn_id = CONN1_ID,
	.service = &service_1
};

static struct pdu search_service[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x10, 0x11, 0x00, 0x0a),
	end_pdu
};

static struct pdu search_service_2[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x11, 0x00, 0x20, 0x00, 0x01, 0x18),
	raw_pdu(0x10, 0x21, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x10, 0x21, 0x00, 0x0a),
	end_pdu
};

static struct pdu search_service_3[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x08, 0x01, 0x00, 0x0a),
	end_pdu
};

static struct pdu get_characteristic_1[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	end_pdu
};

static void gatt_client_register_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	bt_uuid_t *app_uuid = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	if (!app_uuid) {
		tester_warn("No app uuid provided for register action.");
		return;
	}

	step->action_status = data->if_gatt->client->register_client(app_uuid);

	schedule_action_verification(step);
}

static void gatt_client_unregister_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	int32_t cl_id = PTR_TO_INT(current_data_step->set_data);
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->unregister_client(cl_id);

	schedule_action_verification(step);
}

static void gatt_client_start_scan_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	int32_t cl_id = PTR_TO_INT(current_data_step->set_data);
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->scan(cl_id, TRUE);

	schedule_action_verification(step);
}

static void gatt_client_stop_scan_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	int32_t cl_id = PTR_TO_INT(current_data_step->set_data);
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->scan(cl_id, FALSE);

	schedule_action_verification(step);
}

static void gatt_client_connect_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct gatt_connect_data *conn_data = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->connect(
							conn_data->client_id,
							&emu_remote_bdaddr_val,
							0);

	schedule_action_verification(step);
}

static void gatt_client_disconnect_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct gatt_connect_data *conn_data = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->disconnect(
							conn_data->client_id,
							&emu_remote_bdaddr_val,
							conn_data->conn_id);

	schedule_action_verification(step);
}

static void gatt_client_do_listen_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct gatt_connect_data *conn_data = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->listen(
							conn_data->client_id,
							1);

	schedule_action_verification(step);
}

static void gatt_client_stop_listen_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct gatt_connect_data *conn_data = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->client->listen(
							conn_data->client_id,
							0);

	schedule_action_verification(step);
}

static void gatt_client_get_characteristic_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct get_char_data *get_char = current_data_step->set_data;
	const btgatt_client_interface_t *client = data->if_gatt->client;
	struct step *step = g_new0(struct step, 1);
	int status;

	status = client->get_characteristic(get_char->conn_id,
						get_char->service, NULL);
	step->action_status = status;

	schedule_action_verification(step);
}

static void gatt_cid_hook_cb(const void *data, uint16_t len, void *user_data)
{
	struct test_data *t_data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(t_data->hciemu);
	struct emu_cid_data *cid_data = user_data;
	const uint8_t *pdu = data;
	struct pdu *gatt_pdu = queue_peek_head(t_data->pdus);

	switch (pdu[0]) {
	case L2CAP_ATT_EXCHANGE_MTU_REQ:
		tester_print("Exchange MTU request received.");

		if (!memcmp(exchange_mtu_req_pdu, pdu, len))
			bthost_send_cid(bthost, cid_data->handle, cid_data->cid,
						exchange_mtu_resp_pdu,
						sizeof(exchange_mtu_resp_pdu));

		break;
	case L2CAP_ATT_EXCHANGE_MTU_RSP:
		tester_print("Exchange MTU response received.");

		break;
	default:
		if (!gatt_pdu || !gatt_pdu->data) {
			tester_print("Unknown ATT packet.");
			break;
		}

		if (gatt_pdu->size != len) {
			tester_print("Size of incoming frame is not valid");
			tester_print("Expected size = %d incoming size = %d",
							gatt_pdu->size, len);
			break;
		}

		if (memcmp(gatt_pdu->data, data, len)) {
			tester_print("Incoming data mismatch");
			break;
		}
		queue_pop_head(t_data->pdus);
		gatt_pdu = queue_pop_head(t_data->pdus);
		if (!gatt_pdu->data)
			break;

		bthost_send_cid(bthost, cid_data->handle, cid_data->cid,
						gatt_pdu->data, gatt_pdu->size);

		break;
	}
}

static void gatt_conn_cb(uint16_t handle, void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	tester_print("New connection with handle 0x%04x", handle);

	if (data->hciemu_type == HCIEMU_TYPE_BREDR) {
		tester_warn("Not handled device type.");
		return;
	}

	cid_data.cid = 0x0004;
	cid_data.handle = handle;

	bthost_add_cid_hook(bthost, handle, cid_data.cid, gatt_cid_hook_cb,
								&cid_data);
}

static void gatt_client_search_services(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct step *step = g_new0(struct step, 1);
	struct gatt_search_service_data *search_data;
	int status;

	search_data = current_data_step->set_data;

	status = data->if_gatt->client->search_service(search_data->conn_id,
						search_data->filter_uuid);
	step->action_status = status;

	schedule_action_verification(step);
}

static void init_pdus(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct step *step = g_new0(struct step, 1);
	struct pdu *pdu = current_data_step->set_data;

	while (pdu->data) {
		queue_push_tail(data->pdus, pdu);
		pdu++;
	}

	step->action_status = BT_STATUS_SUCCESS;

	schedule_action_verification(step);
}

static struct test_case test_cases[] = {
	TEST_CASE_BREDRLE("Gatt Init",
		ACTION_SUCCESS(dummy_action, NULL),
	),
	TEST_CASE_BREDRLE("Gatt Client - Register",
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
	),
	TEST_CASE_BREDRLE("Gatt Client - Unregister",
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_unregister_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
	),
	TEST_CASE_BREDRLE("Gatt Client - Scan",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Connect",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action,
							&client1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Disconnect",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action,
							&client1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&client1_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Multiple Client Conn./Disc.",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_register_action, &client2_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &client1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_connect_action, &client2_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN2_ID, CLIENT2_ID),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&client2_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN2_ID, CLIENT2_ID),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&client1_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Listen and Disconnect",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(bt_set_property_action,
						&prop_test_scan_mode_conn),
		CALLBACK_ADAPTER_PROPS(&prop_test_scan_mode_conn, 1),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_do_listen_action, &client1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(emu_remote_connect_hci_action, &bearer_type),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_stop_listen_action,
							&client1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&client1_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Double Listen",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(bt_set_property_action,
						&prop_test_scan_mode_conn),
		CALLBACK_ADAPTER_PROPS(&prop_test_scan_mode_conn, 1),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_do_listen_action, &client1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(emu_remote_connect_hci_action, &bearer_type),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_stop_listen_action,
							&client1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&client1_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		/* Close ACL on emulated remotes side so it can reconnect */
		ACTION_SUCCESS(emu_remote_disconnect_hci_action,
							&cid_data.handle),
		CALLBACK_STATE(CB_BT_ACL_STATE_CHANGED,
						BT_ACL_STATE_DISCONNECTED),
		ACTION_SUCCESS(gatt_client_do_listen_action, &client1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(emu_remote_connect_hci_action, &bearer_type),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN2_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&client1_conn2_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN2_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_stop_listen_action,
							&client1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Search Service single",
		ACTION_SUCCESS(init_pdus, search_service),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action,
							&client1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_RESULT(CONN1_ID, &service_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Search Service multiple",
		ACTION_SUCCESS(init_pdus, search_service_2),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action,
							&client1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_RESULT(CONN1_ID, &service_1),
		CALLBACK_GATTC_SEARCH_RESULT(CONN1_ID, &service_2),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Search Service none",
		ACTION_SUCCESS(init_pdus, search_service_3),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action,
							&client1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Characteristic 1",
		ACTION_SUCCESS(init_pdus, get_characteristic_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &client_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(CLIENT1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action,
							&client1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, CLIENT1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
};

struct queue *get_gatt_tests(void)
{
	uint16_t i = 0;

	list = queue_new();

	for (; i < sizeof(test_cases) / sizeof(test_cases[0]); ++i)
		if (!queue_push_tail(list, &test_cases[i]))
			return NULL;

	return list;
}

void remove_gatt_tests(void)
{
	queue_destroy(list, NULL);
}
