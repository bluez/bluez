/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>

#include <glib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <libgen.h>
#include <sys/signalfd.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/tester.h"
#include "src/shared/hciemu.h"
#include "src/shared/mgmt.h"
#include "src/shared/queue.h"

#include <hardware/hardware.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>
#include <hardware/bt_hh.h>
#include <hardware/bt_gatt.h>
#include <hardware/bt_gatt_client.h>
#include <hardware/bt_gatt_server.h>

#define TEST_CASE_BREDR(text, ...) { \
		HCIEMU_TYPE_BREDR, \
		text, \
		sizeof((struct step[]) {__VA_ARGS__}) / sizeof(struct step), \
		(struct step[]) {__VA_ARGS__}, \
	}

#define TEST_CASE_BREDRLE(text, ...) { \
		HCIEMU_TYPE_BREDRLE, \
		text, \
		sizeof((struct step[]) {__VA_ARGS__}) / sizeof(struct step), \
		(struct step[]) {__VA_ARGS__}, \
	}

#define ACTION_SUCCESS(act_fun, data_set) { \
		.action_status = BT_STATUS_SUCCESS, \
		.action = act_fun, \
		.set_data = data_set, \
	}

#define ACTION_FAIL(act_fun, data_set) { \
		.action_status = BT_STATUS_FAIL, \
		.action = act_fun, \
		.set_data = data_set, \
	}

#define ACTION(status, act_fun, data_set) { \
		.action_status = status, \
		.action = act_fun, \
		.set_data = data_set, \
	}

#define CALLBACK(cb) { \
		.callback = cb, \
	}

#define CALLBACK_STATE(cb, cb_res) { \
		.callback = cb, \
		.callback_result.state = cb_res, \
	}

#define CALLBACK_STATUS(cb, cb_res) { \
		.callback = cb, \
		.callback_result.status = cb_res, \
	}

#define CALLBACK_ADAPTER_PROPS(props, prop_cnt) { \
		.callback = CB_BT_ADAPTER_PROPERTIES, \
		.callback_result.properties = props, \
		.callback_result.num_properties = prop_cnt, \
	}

#define CALLBACK_PROPS(cb, props, prop_cnt) { \
		.callback = cb, \
		.callback_result.properties = props, \
		.callback_result.num_properties = prop_cnt, \
	}

#define CALLBACK_HH_MODE(cb, cb_res, cb_mode) { \
		.callback = cb, \
		.callback_result.status = cb_res, \
		.callback_result.mode = cb_mode, \
	}

#define CALLBACK_HHREPORT(cb, cb_res, cb_rep_size) { \
		.callback = cb, \
		.callback_result.status = cb_res, \
		.callback_result.report_size = cb_rep_size, \
	}

#define CALLBACK_DEVICE_PROPS(props, prop_cnt) \
	CALLBACK_PROPS(CB_BT_REMOTE_DEVICE_PROPERTIES, props, prop_cnt)

#define CALLBACK_DEVICE_FOUND(props, prop_cnt) \
	CALLBACK_PROPS(CB_BT_DEVICE_FOUND, props, prop_cnt)

#define CALLBACK_BOND_STATE(cb_res, props, prop_cnt) { \
		.callback = CB_BT_BOND_STATE_CHANGED, \
		.callback_result.state = cb_res, \
		.callback_result.properties = props, \
		.callback_result.num_properties = prop_cnt, \
	}

#define CALLBACK_BOND_STATE_FAILED(cb_res, props, prop_cnt, reason) { \
		.callback = CB_BT_BOND_STATE_CHANGED, \
		.callback_result.state = cb_res, \
		.callback_result.status = reason, \
		.callback_result.properties = props, \
		.callback_result.num_properties = prop_cnt, \
	}

#define CALLBACK_SSP_REQ(pair_var, props, prop_cnt) { \
		.callback = CB_BT_SSP_REQUEST, \
		.callback_result.pairing_variant = pair_var, \
		.callback_result.properties = props, \
		.callback_result.num_properties = prop_cnt, \
	}

/*
 * NOTICE:
 * Callback enum sections should be
 * updated while adding new HAL to tester.
 */
typedef enum {
	CB_BT_ADAPTER_STATE_CHANGED = 1,
	CB_BT_ADAPTER_PROPERTIES,
	CB_BT_REMOTE_DEVICE_PROPERTIES,
	CB_BT_DEVICE_FOUND,
	CB_BT_DISCOVERY_STATE_CHANGED,
	CB_BT_PIN_REQUEST,
	CB_BT_SSP_REQUEST,
	CB_BT_BOND_STATE_CHANGED,
	CB_BT_ACL_STATE_CHANGED,
	CB_BT_THREAD_EVT,
	CB_BT_DUT_MODE_RECV,
	CB_BT_LE_TEST_MODE,

	/* Hidhost cb */
	CB_HH_CONNECTION_STATE,
	CB_HH_HID_INFO,
	CB_HH_PROTOCOL_MODE,
	CB_HH_IDLE_TIME,
	CB_HH_GET_REPORT,
	CB_HH_VIRTUAL_UNPLUG,

	/* Gatt client */
	CB_GATTC_REGISTER_CLIENT,
	CB_GATTC_SCAN_RESULT,
	CB_GATTC_OPEN,
	CB_GATTC_CLOSE,
	CB_GATTC_SEARCH_COMPLETE,
	CB_GATTC_SEARCH_RESULT,
	CB_GATTC_GET_CHARACTERISTIC,
	CB_GATTC_GET_DESCRIPTOR,
	CB_GATTC_GET_INCLUDED_SERVICE,
	CB_GATTC_REGISTER_FOR_NOTIFICATION,
	CB_GATTC_NOTIFY,
	CB_GATTC_READ_CHARACTERISTIC,
	CB_GATTC_WRITE_CHARACTERISTIC,
	CB_GATTC_READ_DESCRIPTOR,
	CB_GATTC_WRITE_DESCRIPTOR,
	CB_GATTC_EXECUTE_WRITE,
	CB_GATTC_READ_REMOTE_RSSI,
	CB_GATTC_LISTEN,

	/* Gatt server */
	CB_GATTS_REGISTER_SERVER,
	CB_GATTS_CONNECTION,
	CB_GATTS_SERVICE_ADDED,
	CB_GATTS_INCLUDED_SERVICE_ADDED,
	CB_GATTS_CHARACTERISTIC_ADDED,
	CB_GATTS_DESCRIPTOR_ADDED,
	CB_GATTS_SERVICE_STARTED,
	CB_GATTS_SERVICE_STOPPED,
	CB_GATTS_SERVICE_DELETED,
	CB_GATTS_REQUEST_READ,
	CB_GATTS_REQUEST_WRITE,
	CB_GATTS_REQUEST_EXEC_WRITE,
	CB_GATTS_RESPONSE_CONFIRMATION,
} expected_bt_callback_t;

struct test_data {
	struct mgmt *mgmt;
	struct hw_device_t *device;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;

	const bt_interface_t *if_bluetooth;
	const btsock_interface_t *if_sock;
	const bthh_interface_t *if_hid;
	const btgatt_interface_t *if_gatt;

	const void *test_data;
	struct queue *steps;

	guint signalfd;
	uint16_t mgmt_index;
	pid_t bluetoothd_pid;
};

/*
 * Struct holding bluetooth HAL action parameters
 */
struct bt_action_data {
	bt_bdaddr_t *addr;

	/* Remote props action arguments */
	const int prop_type;
	const bt_property_t *prop;

	/* Bonding requests parameters */
	bt_pin_code_t *pin;
	const uint8_t pin_len;
	const uint8_t ssp_variant;
	const bool accept;

	/* Socket HAL specific params */
	const btsock_type_t sock_type;
	const int channel;
	const uint8_t *service_uuid;
	const char *service_name;
	const int flags;
	int *fd;

	/* HidHost params */
	const int report_size;
};

/* bthost's l2cap server setup parameters */
struct emu_set_l2cap_data {
	const uint16_t psm;
	const bthost_l2cap_connect_cb func;
	void *user_data;
};

/*
 * Callback data structure should be enhanced with data
 * returned by callbacks. It's used for test case step
 * matching with expected step data.
 */
struct bt_callback_data {
	bt_state_t state;
	bt_status_t status;
	int num_properties;
	bt_property_t *properties;

	bt_ssp_variant_t pairing_variant;

	bthh_protocol_mode_t mode;
	int report_size;
};

/*
 * Step structure contains expected step data and step
 * action, which should be performed before step check.
 */
struct step {
	void (*action)(void);
	int action_status;

	expected_bt_callback_t callback;
	struct bt_callback_data callback_result;

	void *set_data;
	int set_data_len;
};

struct test_case {
	const uint8_t emu_type;
	const char *title;
	const uint16_t step_num;
	const struct step const *step;
};

/* Get, remove test cases API */
struct queue *get_bluetooth_tests(void);
void remove_bluetooth_tests(void);
struct queue *get_socket_tests(void);
void remove_socket_tests(void);
struct queue *get_hidhost_tests(void);
void remove_hidhost_tests(void);
struct queue *get_gatt_tests(void);
void remove_gatt_tests(void);

/* Generic tester API */
void schedule_action_verification(struct step *step);

/* Emulator actions */
void emu_setup_powered_remote_action(void);
void emu_set_pin_code_action(void);
void emu_set_ssp_mode_action(void);
void emu_add_l2cap_server_action(void);
void emu_add_rfcomm_server_action(void);

/* Actions */
void dummy_action(void);
void bluetooth_enable_action(void);
void bluetooth_disable_action(void);
void bt_set_property_action(void);
void bt_get_property_action(void);
void bt_start_discovery_action(void);
void bt_cancel_discovery_action(void);
void bt_get_device_props_action(void);
void bt_get_device_prop_action(void);
void bt_set_device_prop_action(void);
void bt_create_bond_action(void);
void bt_pin_reply_accept_action(void);
void bt_ssp_reply_accept_action(void);
void bt_cancel_bond_action(void);
void bt_remove_bond_action(void);
