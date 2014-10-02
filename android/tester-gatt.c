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

#define L2CAP_ATT_EXCHANGE_MTU_REQ	0x02
#define L2CAP_ATT_EXCHANGE_MTU_RSP	0x03

#define GATT_STATUS_SUCCESS	0x00000000
#define GATT_STATUS_FAILURE	0x00000101
#define GATT_STATUS_INS_AUTH	0x08

#define APP1_ID	1
#define APP2_ID	2

#define CONN1_ID	1
#define CONN2_ID	2

static struct queue *list; /* List of gatt test cases */

static bt_uuid_t app1_uuid = {
	.uu = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
				0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
};

struct gatt_connect_data {
	const int app_id;
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

struct get_desc_data {
	const int conn_id;
	btgatt_srvc_id_t *service;
	btgatt_gatt_id_t *characteristic;
	btgatt_gatt_id_t *desc;
};

struct get_incl_data {
	const int conn_id;
	btgatt_srvc_id_t *service;
	btgatt_srvc_id_t *start_service;
};

struct read_char_data {
	const int conn_id;
	btgatt_srvc_id_t *service;
	btgatt_gatt_id_t *characteristic;
	int auth_req;
};

struct read_desc_data {
	const int conn_id;
	btgatt_srvc_id_t *service;
	btgatt_gatt_id_t *characteristic;
	btgatt_gatt_id_t *descriptor;
	int auth_req;
};

struct write_char_data {
	int conn_id;
	btgatt_srvc_id_t *service;
	btgatt_gatt_id_t *characteristic;
	int write_type;
	int len;
	int auth_req;
	char *p_value;
};

struct notif_data {
	int conn_id;
	const bt_bdaddr_t *bdaddr;
	btgatt_srvc_id_t *service;
	btgatt_gatt_id_t *charac;
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

static struct emu_l2cap_cid_data cid_data;

static struct gatt_connect_data app1_conn_req = {
	.app_id = APP1_ID,
	.conn_id = CONN1_ID,
};

static struct gatt_connect_data app1_conn2_req = {
	.app_id = APP1_ID,
	.conn_id = CONN2_ID,
};

static struct gatt_connect_data app2_conn_req = {
	.app_id = APP2_ID,
	.conn_id = CONN2_ID,
};

static struct gatt_search_service_data search_services_1 = {
	.conn_id = CONN1_ID,
	.filter_uuid = NULL,
};

static const struct iovec exchange_mtu_req_pdu = raw_pdu(0x02, 0xa0, 0x02);
static const struct iovec exchange_mtu_resp_pdu = raw_pdu(0x03, 0xa0, 0x02);

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

static btgatt_srvc_id_t included_1 = {
	.is_primary = false,
	.id = {
		.inst_id = 1,
		.uuid.uu = {0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00,  0xff, 0xfe, 0x00, 0x00},
	}
};

static btgatt_srvc_id_t included_2 = {
	.is_primary = false,
	.id = {
		.inst_id = 1,
		.uuid.uu = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}
};

static btgatt_gatt_id_t characteristic_1 = {
	.inst_id = 1,
	.uuid.uu = {0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00,  0x19, 0x00, 0x00, 0x00}
};

static btgatt_gatt_id_t desc_1 = {
	.inst_id = 1,
	.uuid.uu = {0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00,  0x00, 0x29, 0x00, 0x00}
};

static btgatt_gatt_id_t desc_2 = {
	.inst_id = 2,
	.uuid.uu = {0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80,
			0x00, 0x10, 0x00, 0x00,  0x01, 0x29, 0x00, 0x00}
};

static btgatt_read_params_t read_params_1;
static btgatt_write_params_t write_params_1;
static btgatt_notify_params_t notify_params_1;

static struct get_char_data get_char_data_1 = {
	.conn_id = CONN1_ID,
	.service = &service_1
};

static struct get_char_data get_char_data_2 = {
	.conn_id = CONN1_ID,
	.service = &service_2
};

static struct get_desc_data get_desc_data_1 = {
	.conn_id = CONN1_ID,
	.service = &service_1,
	.characteristic = &characteristic_1,
};

static struct get_desc_data get_desc_data_2 = {
	.conn_id = CONN1_ID,
	.service = &service_1,
	.characteristic = &characteristic_1,
	.desc = &desc_1,
};

static struct read_char_data read_char_data_1 = {
	.conn_id = CONN1_ID,
	.service = &service_1,
	.characteristic = &characteristic_1,
};

static struct read_char_data read_char_data_2 = {
	.conn_id = CONN1_ID,
	.service = &service_2,
	.characteristic = &characteristic_1,
};

static struct read_desc_data read_desc_data_1 = {
	.conn_id = CONN1_ID,
	.service = &service_1,
	.characteristic = &characteristic_1,
	.descriptor = &desc_1,
};

static struct read_desc_data read_desc_data_2 = {
	.conn_id = CONN1_ID,
	.service = &service_1,
	.characteristic = &characteristic_1,
	.descriptor = &desc_2,
};

static struct get_incl_data get_incl_data_1 = {
	.conn_id = CONN1_ID,
	.service = &service_1
};

static char value_2[] = {0x00, 0x01, 0x02, 0x03};

static struct write_char_data write_char_data_1 = {
	.conn_id = CONN1_ID,
	.service = &service_1,
	.characteristic = &characteristic_1,
	.write_type = 1,
	.len = sizeof(value_2),
	.p_value = value_2,
	.auth_req = 0
};

static struct write_char_data write_char_data_2 = {
	.conn_id = CONN1_ID,
	.service = &service_1,
	.characteristic = &characteristic_1,
	.write_type = 2,
	.len = sizeof(value_2),
	.p_value = value_2,
	.auth_req = 0
};

static struct notif_data notif_data_1 = {
	.conn_id = CONN1_ID,
	.service = &service_1,
	.charac = &characteristic_1,
	.bdaddr = &emu_remote_bdaddr_val,
};

struct set_read_params {
	btgatt_read_params_t *params;
	btgatt_srvc_id_t *srvc_id;
	btgatt_gatt_id_t *char_id;
	btgatt_gatt_id_t *descr_id;
	uint8_t *value;
	uint16_t len;
	uint16_t value_type;
	uint8_t status;
};

struct set_write_params {
	btgatt_write_params_t *params;
	btgatt_srvc_id_t *srvc_id;
	btgatt_gatt_id_t *char_id;
	btgatt_gatt_id_t *descr_id;
	uint8_t status;
};

struct set_notify_params {
	btgatt_notify_params_t *params;
	uint8_t *value;
	uint16_t len;
	uint8_t is_notify;
	btgatt_srvc_id_t *srvc_id;
	btgatt_gatt_id_t *char_id;
	bt_bdaddr_t *bdaddr;
};

static uint8_t value_1[] = {0x01};

static struct set_read_params set_read_param_1 = {
	.params = &read_params_1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.value = value_1,
	.len = 1,
	.status = BT_STATUS_SUCCESS
};

static struct set_read_params set_read_param_2 = {
	.params = &read_params_1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.status = GATT_STATUS_INS_AUTH
};

static struct set_read_params set_read_param_3 = {
	.params = &read_params_1,
	.srvc_id = &service_2,
	.char_id = &characteristic_1,
	.status = 0x01,
};

static struct set_read_params set_read_param_4 = {
	.params = &read_params_1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.descr_id = &desc_1,
	.value = value_1,
	.len = 1,
	.status = BT_STATUS_SUCCESS
};

static struct set_read_params set_read_param_5 = {
	.params = &read_params_1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.descr_id = &desc_1,
	.status = GATT_STATUS_INS_AUTH
};

static struct set_read_params set_read_param_6 = {
	.params = &read_params_1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.descr_id = &desc_2,
	.status = 0x01
};

static struct set_write_params set_write_param_1 = {
	.params = &write_params_1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.status = BT_STATUS_SUCCESS
};

static struct set_write_params set_write_param_2 = {
	.params = &write_params_1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.status = GATT_STATUS_INS_AUTH
};

static struct set_write_params set_write_param_3 = {
	.params = &write_params_1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.status = 0x01
};

static struct set_notify_params set_notify_param_1 = {
	.params = &notify_params_1,
	.value = value_1,
	.len = sizeof(value_1),
	.is_notify = 0,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.bdaddr = &emu_remote_bdaddr_val
};

static struct set_notify_params set_notify_param_2 = {
	.params = &notify_params_1,
	.value = value_1,
	.len = sizeof(value_1),
	.is_notify = 1,
	.srvc_id = &service_1,
	.char_id = &characteristic_1,
	.bdaddr = &emu_remote_bdaddr_val
};

static struct iovec search_service[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x10, 0x11, 0x00, 0x0a),
	end_pdu
};

static struct iovec search_service_2[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x11, 0x00, 0x20, 0x00, 0x01, 0x18),
	raw_pdu(0x10, 0x21, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x10, 0x21, 0x00, 0x0a),
	end_pdu
};

static struct iovec search_service_3[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x08, 0x01, 0x00, 0x0a),
	end_pdu
};

static struct iovec get_characteristic_1[] = {
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

static struct iovec get_descriptor_1[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x04, 0x01, 0x00, 0x10, 0x00),
	raw_pdu(0x05, 0x01, 0x04, 0x00, 0x00, 0x29),
	raw_pdu(0x04, 0x05, 0x00, 0x10, 0x00),
	raw_pdu(0x01, 0x04, 0x05, 0x00, 0x0a),
	end_pdu
};

static struct iovec get_descriptor_2[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x04, 0x01, 0x00, 0x10, 0x00),
	raw_pdu(0x05, 0x01, 0x04, 0x00, 0x00, 0x29, 0x05, 0x00, 0x01, 0x29),
	raw_pdu(0x04, 0x06, 0x00, 0x10, 0x00),
	raw_pdu(0x01, 0x04, 0x06, 0x00, 0x0a),
	end_pdu
};

static struct iovec get_descriptor_3[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x04, 0x01, 0x00, 0x10, 0x00),
	raw_pdu(0x01, 0x04, 0x01, 0x00, 0x0a),
	end_pdu
};

static struct iovec get_included_1[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x02, 0x28),
	raw_pdu(0x09, 0x08, 0x02, 0x00, 0x15, 0x00, 0x19, 0x00, 0xff, 0xfe),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x02, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	end_pdu
};

static struct iovec get_included_2[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x02, 0x28),
	raw_pdu(0x09, 0x06, 0x02, 0x00, 0x15, 0x00, 0x19, 0x00),
	raw_pdu(0x0a, 0x15, 0x00),
	raw_pdu(0x0b, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x02, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	end_pdu
};

static struct iovec get_included_3[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x02, 0x28),
	raw_pdu(0x01, 0x08, 0x01, 0x00, 0x0a),
	end_pdu
};

static struct iovec read_characteristic_1[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x03, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x0a, 0x03, 0x00),
	raw_pdu(0x0b, 0x01),
	end_pdu
};

static struct iovec read_characteristic_2[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x03, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x0a, 0x03, 0x00),
	raw_pdu(0x01, 0x0a, 0x03, 0x00, 0x08),
	end_pdu
};

static struct iovec read_descriptor_1[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x04, 0x01, 0x00, 0x10, 0x00),
	raw_pdu(0x05, 0x01, 0x04, 0x00, 0x00, 0x29),
	raw_pdu(0x04, 0x05, 0x00, 0x10, 0x00),
	raw_pdu(0x01, 0x04, 0x05, 0x00, 0x0a),
	raw_pdu(0x0a, 0x04, 0x00),
	raw_pdu(0x0b, 0x01),
	end_pdu
};

static struct iovec read_descriptor_2[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x04, 0x01, 0x00, 0x10, 0x00),
	raw_pdu(0x05, 0x01, 0x04, 0x00, 0x00, 0x29),
	raw_pdu(0x04, 0x05, 0x00, 0x10, 0x00),
	raw_pdu(0x01, 0x04, 0x05, 0x00, 0x0a),
	raw_pdu(0x0a, 0x04, 0x00),
	raw_pdu(0x01, 0x0a, 0x04, 0x00, 0x08),
	end_pdu
};

static struct iovec write_characteristic_1[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x03, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x52, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03),
	end_pdu
};

static struct iovec write_characteristic_2[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x03, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x12, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03),
	raw_pdu(0x13),
	end_pdu
};

static struct iovec write_characteristic_3[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x03, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x12, 0x03, 0x00, 0x00, 0x01, 0x02, 0x03),
	raw_pdu(0x01, 0x12, 0x03, 0x00, 0x08),
	end_pdu
};

static struct iovec notification_1[] = {
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

static struct iovec notification_2[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x1d, 0x03, 0x00, 0x01),
	raw_pdu(0x1e),
	end_pdu
};

static struct iovec notification_3[] = {
	raw_pdu(0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x11, 0x06, 0x01, 0x00, 0x10, 0x00, 0x00, 0x18),
	raw_pdu(0x10, 0x11, 0x00, 0xff, 0xff, 0x00, 0x28),
	raw_pdu(0x01, 0x11, 0x11, 0x00, 0x0a),
	raw_pdu(0x08, 0x01, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x09, 0x07, 0x02, 0x00, 0x04, 0x00, 0x00, 0x19, 0x00),
	raw_pdu(0x08, 0x03, 0x00, 0x10, 0x00, 0x03, 0x28),
	raw_pdu(0x01, 0x08, 0x03, 0x00, 0x0a),
	raw_pdu(0x1b, 0x03, 0x00, 0x01),
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
							conn_data->app_id,
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
							conn_data->app_id,
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
							conn_data->app_id,
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
							conn_data->app_id,
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

static void gatt_client_get_descriptor_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct get_desc_data *get_desc = current_data_step->set_data;
	const btgatt_client_interface_t *client = data->if_gatt->client;
	struct step *step = g_new0(struct step, 1);
	int status;

	status = client->get_descriptor(get_desc->conn_id, get_desc->service,
						get_desc->characteristic,
						get_desc->desc);
	step->action_status = status;

	schedule_action_verification(step);
}

static void gatt_client_get_included_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct get_incl_data *get_incl = current_data_step->set_data;
	const btgatt_client_interface_t *client = data->if_gatt->client;
	struct step *step = g_new0(struct step, 1);
	int status;

	status = client->get_included_service(get_incl->conn_id,
				get_incl->service, get_incl->start_service);

	step->action_status = status;

	schedule_action_verification(step);
}

static void gatt_client_read_characteristic_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct read_char_data *read_char_data = current_data_step->set_data;
	const btgatt_client_interface_t *client = data->if_gatt->client;
	struct step *step = g_new0(struct step, 1);
	int status;

	status = client->read_characteristic(read_char_data->conn_id,
			read_char_data->service, read_char_data->characteristic,
			read_char_data->auth_req);

	step->action_status = status;

	schedule_action_verification(step);
}

static void gatt_client_read_descriptor_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct read_desc_data *read_desc_data = current_data_step->set_data;
	const btgatt_client_interface_t *client = data->if_gatt->client;
	struct step *step = g_new0(struct step, 1);
	int status;

	status = client->read_descriptor(read_desc_data->conn_id,
			read_desc_data->service, read_desc_data->characteristic,
			read_desc_data->descriptor,
			read_desc_data->auth_req);

	step->action_status = status;

	schedule_action_verification(step);
}

static void gatt_client_write_characteristic_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct write_char_data *write_char_data = current_data_step->set_data;
	const btgatt_client_interface_t *client = data->if_gatt->client;
	struct step *step = g_new0(struct step, 1);
	int status;

	status = client->write_characteristic(write_char_data->conn_id,
						write_char_data->service,
						write_char_data->characteristic,
						write_char_data->write_type,
						write_char_data->len,
						write_char_data->auth_req,
						write_char_data->p_value);

	step->action_status = status;

	schedule_action_verification(step);
}

static void gatt_client_register_for_notification_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct notif_data *notif_data = current_data_step->set_data;
	const btgatt_client_interface_t *client = data->if_gatt->client;
	struct step *step = g_new0(struct step, 1);
	int status;

	status = client->register_for_notification(notif_data->conn_id,
							notif_data->bdaddr,
							notif_data->service,
							notif_data->charac);
	step->action_status = status;

	schedule_action_verification(step);
}

static void gatt_client_deregister_for_notification_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct notif_data *notif_data = current_data_step->set_data;
	const btgatt_client_interface_t *client = data->if_gatt->client;
	struct step *step = g_new0(struct step, 1);
	int status;

	status = client->deregister_for_notification(notif_data->conn_id,
							notif_data->bdaddr,
							notif_data->service,
							notif_data->charac);
	step->action_status = status;

	schedule_action_verification(step);
}

static void gatt_server_register_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	bt_uuid_t *app_uuid = current_data_step->set_data;
	struct step *step = g_new0(struct step, 1);

	if (!app_uuid) {
		tester_warn("No app uuid provided for register action.");
		return;
	}

	step->action_status = data->if_gatt->server->register_server(app_uuid);

	schedule_action_verification(step);
}

static void gatt_server_unregister_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	int32_t sr_id = PTR_TO_INT(current_data_step->set_data);
	struct step *step = g_new0(struct step, 1);

	step->action_status = data->if_gatt->server->unregister_server(sr_id);

	schedule_action_verification(step);
}

static void gatt_cid_hook_cb(const void *data, uint16_t len, void *user_data)
{
	struct test_data *t_data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(t_data->hciemu);
	struct emu_l2cap_cid_data *cid_data = user_data;
	const uint8_t *pdu = data;
	struct iovec *gatt_pdu = queue_peek_head(t_data->pdus);

	switch (pdu[0]) {
	case L2CAP_ATT_EXCHANGE_MTU_REQ:
		tester_print("Exchange MTU request received.");

		if (!memcmp(exchange_mtu_req_pdu.iov_base, pdu, len))
			bthost_send_cid_v(bthost, cid_data->handle,
						cid_data->cid,
						&exchange_mtu_resp_pdu, 1);

		break;
	case L2CAP_ATT_EXCHANGE_MTU_RSP:
		tester_print("Exchange MTU response received.");

		break;
	default:
		if (!gatt_pdu || !gatt_pdu->iov_base) {
			tester_print("Unknown ATT packet.");
			break;
		}

		if (gatt_pdu->iov_len != len) {
			tester_print("Size of incoming frame is not valid");
			tester_print("Expected size = %zd incoming size = %d",
							gatt_pdu->iov_len, len);
			break;
		}

		if (memcmp(gatt_pdu->iov_base, data, len)) {
			tester_print("Incoming data mismatch");
			break;
		}
		queue_pop_head(t_data->pdus);
		gatt_pdu = queue_pop_head(t_data->pdus);
		if (!gatt_pdu || !gatt_pdu->iov_base)
			break;

		bthost_send_cid_v(bthost, cid_data->handle, cid_data->cid,
								gatt_pdu, 1);

		break;
	}
}

static void gatt_remote_send_frame_action(void)
{
	struct test_data *t_data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(t_data->hciemu);
	struct iovec *gatt_pdu = queue_pop_head(t_data->pdus);
	struct step *step = g_new0(struct step, 1);

	if (!gatt_pdu) {
		tester_print("No frame to send");
		step->action_status = BT_STATUS_FAIL;
	} else {
		bthost_send_cid_v(bthost, cid_data.handle, cid_data.cid,
								gatt_pdu, 1);
		step->action_status = BT_STATUS_SUCCESS;
	}

	schedule_action_verification(step);
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
	struct iovec *pdu = current_data_step->set_data;

	while (pdu->iov_base) {
		queue_push_tail(data->pdus, pdu);
		pdu++;
	}

	step->action_status = BT_STATUS_SUCCESS;

	schedule_action_verification(step);
}

static void init_read_params_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct step *step = g_new0(struct step, 1);
	struct set_read_params *set_param_data = current_data_step->set_data;
	btgatt_read_params_t *param = set_param_data->params;

	memset(param, 0, sizeof(*param));

	if (set_param_data->srvc_id)
		memcpy(&param->srvc_id, set_param_data->srvc_id,
						sizeof(btgatt_srvc_id_t));

	if (set_param_data->char_id)
		memcpy(&param->char_id, set_param_data->char_id,
						sizeof(btgatt_gatt_id_t));

	if (set_param_data->descr_id)
		memcpy(&param->descr_id, set_param_data->descr_id,
						sizeof(btgatt_gatt_id_t));

	param->value_type = set_param_data->value_type;
	param->status = set_param_data->status;
	param->value.len = set_param_data->len;

	if (param->value.len != 0)
		memcpy(&param->value.value, set_param_data->value,
							param->value.len);

	step->action_status = BT_STATUS_SUCCESS;

	schedule_action_verification(step);
}

static void init_write_params_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct step *step = g_new0(struct step, 1);
	struct set_write_params *set_param_data = current_data_step->set_data;
	btgatt_write_params_t *param = set_param_data->params;

	memset(param, 0, sizeof(*param));

	if (set_param_data->srvc_id)
		memcpy(&param->srvc_id, set_param_data->srvc_id,
						sizeof(btgatt_srvc_id_t));

	if (set_param_data->char_id)
		memcpy(&param->char_id, set_param_data->char_id,
						sizeof(btgatt_gatt_id_t));

	if (set_param_data->descr_id)
		memcpy(&param->descr_id, set_param_data->descr_id,
						sizeof(btgatt_gatt_id_t));

	param->status = set_param_data->status;

	step->action_status = BT_STATUS_SUCCESS;

	schedule_action_verification(step);
}

static void init_notify_params_action(void)
{
	struct test_data *data = tester_get_data();
	struct step *current_data_step = queue_peek_head(data->steps);
	struct step *step = g_new0(struct step, 1);
	struct set_notify_params *set_param_data = current_data_step->set_data;
	btgatt_notify_params_t *param = set_param_data->params;

	memset(param, 0, sizeof(*param));

	if (set_param_data->srvc_id)
		memcpy(&param->srvc_id, set_param_data->srvc_id,
						sizeof(btgatt_srvc_id_t));

	if (set_param_data->char_id)
		memcpy(&param->char_id, set_param_data->char_id,
						sizeof(btgatt_gatt_id_t));

	param->len = set_param_data->len;
	param->is_notify = set_param_data->is_notify;

	memcpy(&param->bda, set_param_data->bdaddr, sizeof(bt_bdaddr_t));
	if (param->len != 0)
		memcpy(&param->value, set_param_data->value, param->len);

	step->action_status = BT_STATUS_SUCCESS;

	schedule_action_verification(step);
}

static struct test_case test_cases[] = {
	TEST_CASE_BREDRLE("Gatt Init",
		ACTION_SUCCESS(dummy_action, NULL),
	),
	TEST_CASE_BREDRLE("Gatt Client - Register",
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
	),
	TEST_CASE_BREDRLE("Gatt Client - Unregister",
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_unregister_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
	),
	TEST_CASE_BREDRLE("Gatt Client - Scan",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Connect",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Disconnect",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&app1_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Multiple Client Conn./Disc.",
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_register_action, &client2_app_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_connect_action, &app2_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN2_ID, APP2_ID),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&app2_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN2_ID, APP2_ID),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&app1_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
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
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_do_listen_action, &app1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(emu_remote_connect_hci_action, &bearer_type),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_stop_listen_action,
							&app1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&app1_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
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
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_do_listen_action, &app1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(emu_remote_connect_hci_action, &bearer_type),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_stop_listen_action,
							&app1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&app1_conn_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		/* Close ACL on emulated remotes side so it can reconnect */
		ACTION_SUCCESS(emu_remote_disconnect_hci_action,
							&cid_data.handle),
		CALLBACK_STATE(CB_BT_ACL_STATE_CHANGED,
						BT_ACL_STATE_DISCONNECTED),
		ACTION_SUCCESS(gatt_client_do_listen_action, &app1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(emu_remote_connect_hci_action, &bearer_type),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN2_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_disconnect_action,
							&app1_conn2_req),
		CALLBACK_GATTC_DISCONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN2_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_stop_listen_action,
							&app1_conn_req),
		CALLBACK_STATUS(CB_GATTC_LISTEN, GATT_STATUS_SUCCESS),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Search Service - Single",
		ACTION_SUCCESS(init_pdus, search_service),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_RESULT(CONN1_ID, &service_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Search Service - Multiple",
		ACTION_SUCCESS(init_pdus, search_service_2),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_RESULT(CONN1_ID, &service_1),
		CALLBACK_GATTC_SEARCH_RESULT(CONN1_ID, &service_2),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Search Service - None",
		ACTION_SUCCESS(init_pdus, search_service_3),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Characteristic - Single",
		ACTION_SUCCESS(init_pdus, get_characteristic_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Characteristic - None",
		ACTION_SUCCESS(init_pdus, get_characteristic_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_FAIL(gatt_client_get_characteristic_action,
							&get_char_data_2),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_FAILURE,
							CONN1_ID, &service_2,
							NULL, 0),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Descriptor - Single",
		ACTION_SUCCESS(init_pdus, get_descriptor_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_get_descriptor_action,
							&get_desc_data_1),
		CALLBACK_GATTC_GET_DESCRIPTOR(GATT_STATUS_SUCCESS, CONN1_ID,
				&service_1, &characteristic_1, &desc_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Descriptor - Multiple",
		ACTION_SUCCESS(init_pdus, get_descriptor_2),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
							CONN1_ID, &service_1,
							&characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_get_descriptor_action,
							&get_desc_data_1),
		CALLBACK_GATTC_GET_DESCRIPTOR(GATT_STATUS_SUCCESS, CONN1_ID,
						&service_1, &characteristic_1,
						&desc_1),
		ACTION_SUCCESS(gatt_client_get_descriptor_action,
							&get_desc_data_2),
		CALLBACK_GATTC_GET_DESCRIPTOR(GATT_STATUS_SUCCESS, CONN1_ID,
						&service_1, &characteristic_1,
						&desc_2),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Descriptor - None",
		ACTION_SUCCESS(init_pdus, get_descriptor_3),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_get_descriptor_action,
							&get_desc_data_1),
		CALLBACK_GATTC_GET_DESCRIPTOR(GATT_STATUS_FAILURE, CONN1_ID,
				&service_1, &characteristic_1, NULL),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Included Service - 16 UUID",
		ACTION_SUCCESS(init_pdus, get_included_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_included_action,
							&get_incl_data_1),
		CALLBACK_GATTC_GET_INCLUDED(GATT_STATUS_SUCCESS, CONN1_ID,
						&service_1, &included_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Included Service - 128 UUID",
		ACTION_SUCCESS(init_pdus, get_included_2),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_included_action,
							&get_incl_data_1),
		CALLBACK_GATTC_GET_INCLUDED(GATT_STATUS_SUCCESS, CONN1_ID,
						&service_1, &included_2),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Get Included Service - None",
		ACTION_SUCCESS(init_pdus, get_included_3),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_included_action,
							&get_incl_data_1),
		CALLBACK_GATTC_GET_INCLUDED(GATT_STATUS_FAILURE, CONN1_ID,
							&service_1, NULL),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Read Characteristic - Success",
		ACTION_SUCCESS(init_pdus, read_characteristic_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(init_read_params_action, &set_read_param_1),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_read_characteristic_action,
							&read_char_data_1),
		CALLBACK_GATTC_READ_CHARACTERISTIC(GATT_STATUS_SUCCESS,
						CONN1_ID, &read_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),

	TEST_CASE_BREDRLE("Gatt Client - Read Characteristic - Insuf. Auth.",
		ACTION_SUCCESS(init_pdus, read_characteristic_2),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(init_read_params_action, &set_read_param_2),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_read_characteristic_action,
							&read_char_data_1),
		CALLBACK_GATTC_READ_CHARACTERISTIC(GATT_STATUS_INS_AUTH,
						CONN1_ID, &read_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Read Characteristic - Wrong params",
		ACTION_SUCCESS(init_pdus, read_characteristic_2),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(init_read_params_action, &set_read_param_3),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_FAIL(gatt_client_read_characteristic_action,
							&read_char_data_2),
		CALLBACK_GATTC_READ_CHARACTERISTIC(GATT_STATUS_FAILURE,
						CONN1_ID, &read_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Read Descriptor - Success",
		ACTION_SUCCESS(init_pdus, read_descriptor_1),
		ACTION_SUCCESS(init_read_params_action, &set_read_param_4),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_get_descriptor_action,
							&get_desc_data_1),
		CALLBACK_GATTC_GET_DESCRIPTOR(GATT_STATUS_SUCCESS, CONN1_ID,
				&service_1, &characteristic_1, &desc_1),
		ACTION_SUCCESS(gatt_client_read_descriptor_action,
							&read_desc_data_1),
		CALLBACK_GATTC_READ_DESCRIPTOR(GATT_STATUS_SUCCESS,
						CONN1_ID, &read_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Read Descriptor - Insuf. Auth.",
		ACTION_SUCCESS(init_pdus, read_descriptor_2),
		ACTION_SUCCESS(init_read_params_action, &set_read_param_5),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_get_descriptor_action,
							&get_desc_data_1),
		CALLBACK_GATTC_GET_DESCRIPTOR(GATT_STATUS_SUCCESS, CONN1_ID,
				&service_1, &characteristic_1, &desc_1),
		ACTION_SUCCESS(gatt_client_read_descriptor_action,
							&read_desc_data_1),
		CALLBACK_GATTC_READ_DESCRIPTOR(GATT_STATUS_INS_AUTH,
						CONN1_ID, &read_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Read Descriptor - Wrong params",
		ACTION_SUCCESS(init_pdus, read_descriptor_2),
		ACTION_SUCCESS(init_read_params_action, &set_read_param_6),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_get_descriptor_action,
							&get_desc_data_1),
		CALLBACK_GATTC_GET_DESCRIPTOR(GATT_STATUS_SUCCESS, CONN1_ID,
				&service_1, &characteristic_1, &desc_1),
		ACTION_FAIL(gatt_client_read_descriptor_action,
							&read_desc_data_2),
		CALLBACK_GATTC_READ_DESCRIPTOR(GATT_STATUS_FAILURE,
						CONN1_ID, &read_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Write Characteristic Cmd - Success",
		ACTION_SUCCESS(init_pdus, write_characteristic_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(init_write_params_action, &set_write_param_1),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_write_characteristic_action,
							&write_char_data_1),
		CALLBACK_GATTC_WRITE_CHARACTERISTIC(GATT_STATUS_SUCCESS,
						CONN1_ID, &write_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Write Characteristic Req - Success",
		ACTION_SUCCESS(init_pdus, write_characteristic_2),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(init_write_params_action, &set_write_param_1),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_write_characteristic_action,
							&write_char_data_2),
		CALLBACK_GATTC_WRITE_CHARACTERISTIC(GATT_STATUS_SUCCESS,
						CONN1_ID, &write_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Write Characteristic - Insuf. Auth.",
		ACTION_SUCCESS(init_pdus, write_characteristic_3),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(init_write_params_action, &set_write_param_2),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_write_characteristic_action,
							&write_char_data_2),
		CALLBACK_GATTC_WRITE_CHARACTERISTIC(GATT_STATUS_INS_AUTH,
						CONN1_ID, &write_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Write Characteristic - Wrong Params",
		ACTION_SUCCESS(init_pdus, write_characteristic_3),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(init_write_params_action, &set_write_param_3),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_FAIL(gatt_client_write_characteristic_action,
							&write_char_data_2),
		CALLBACK_GATTC_WRITE_CHARACTERISTIC(GATT_STATUS_FAILURE,
						CONN1_ID, &write_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Register For Notification - Success",
		ACTION_SUCCESS(init_pdus, notification_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_register_for_notification_action,
								&notif_data_1),
		CALLBACK_GATTC_REGISTER_FOR_NOTIF(GATT_STATUS_SUCCESS, CONN1_ID,
							&characteristic_1,
							&service_1, 1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Deregister For Notification - Success",
		ACTION_SUCCESS(init_pdus, notification_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_register_for_notification_action,
								&notif_data_1),
		CALLBACK_GATTC_REGISTER_FOR_NOTIF(GATT_STATUS_SUCCESS, CONN1_ID,
							&characteristic_1,
							&service_1, 1),
		ACTION_SUCCESS(gatt_client_deregister_for_notification_action,
								&notif_data_1),
		CALLBACK_GATTC_REGISTER_FOR_NOTIF(GATT_STATUS_SUCCESS, CONN1_ID,
							&characteristic_1,
							&service_1, 0),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Register For Notification - Indicate",
		ACTION_SUCCESS(init_pdus, notification_2),
		ACTION_SUCCESS(init_notify_params_action, &set_notify_param_1),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
							CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_register_for_notification_action,
								&notif_data_1),
		CALLBACK_GATTC_REGISTER_FOR_NOTIF(GATT_STATUS_SUCCESS, CONN1_ID,
							&characteristic_1,
							&service_1, 1),
		ACTION_SUCCESS(gatt_remote_send_frame_action, NULL),
		CALLBACK_GATTC_NOTIFY(CONN1_ID, &notify_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),
	TEST_CASE_BREDRLE("Gatt Client - Register For Notification - Notify",
		ACTION_SUCCESS(init_pdus, notification_3),
		ACTION_SUCCESS(init_notify_params_action, &set_notify_param_2),
		ACTION_SUCCESS(bluetooth_enable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_ON),
		ACTION_SUCCESS(emu_setup_powered_remote_action, NULL),
		ACTION_SUCCESS(emu_set_ssp_mode_action, NULL),
		ACTION_SUCCESS(emu_set_connect_cb_action, gatt_conn_cb),
		ACTION_SUCCESS(gatt_client_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTC_REGISTER_CLIENT, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_client_start_scan_action,
							INT_TO_PTR(APP1_ID)),
		CLLBACK_GATTC_SCAN_RES(prop_emu_remotes_default_set, 1, TRUE),
		ACTION_SUCCESS(gatt_client_stop_scan_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_client_connect_action, &app1_conn_req),
		CALLBACK_GATTC_CONNECT(GATT_STATUS_SUCCESS,
						prop_emu_remotes_default_set,
						CONN1_ID, APP1_ID),
		ACTION_SUCCESS(gatt_client_search_services, &search_services_1),
		CALLBACK_GATTC_SEARCH_COMPLETE(GATT_STATUS_SUCCESS, CONN1_ID),
		ACTION_SUCCESS(gatt_client_get_characteristic_action,
							&get_char_data_1),
		CALLBACK_GATTC_GET_CHARACTERISTIC_CB(GATT_STATUS_SUCCESS,
				CONN1_ID, &service_1, &characteristic_1, 4),
		ACTION_SUCCESS(gatt_client_register_for_notification_action,
								&notif_data_1),
		CALLBACK_GATTC_REGISTER_FOR_NOTIF(GATT_STATUS_SUCCESS, CONN1_ID,
							&characteristic_1,
							&service_1, 1),
		ACTION_SUCCESS(gatt_remote_send_frame_action, NULL),
		CALLBACK_GATTC_NOTIFY(CONN1_ID, &notify_params_1),
		ACTION_SUCCESS(bluetooth_disable_action, NULL),
		CALLBACK_STATE(CB_BT_ADAPTER_STATE_CHANGED, BT_STATE_OFF),
	),

	TEST_CASE_BREDRLE("Gatt Server - Register",
		ACTION_SUCCESS(gatt_server_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTS_REGISTER_SERVER, BT_STATUS_SUCCESS),
	),
	TEST_CASE_BREDRLE("Gatt Server - Unregister",
		ACTION_SUCCESS(gatt_server_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTS_REGISTER_SERVER, BT_STATUS_SUCCESS),
		ACTION_SUCCESS(gatt_server_unregister_action,
							INT_TO_PTR(APP1_ID)),
		ACTION_SUCCESS(gatt_server_register_action, &app1_uuid),
		CALLBACK_STATUS(CB_GATTS_REGISTER_SERVER, BT_STATUS_SUCCESS),
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
