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

#define get_test_case_step_num(tc) (sizeof(tc) / sizeof(struct step))

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
} expected_bt_callback_t;

struct test_data {
	struct mgmt *mgmt;
	struct hw_device_t *device;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;

	const bt_interface_t *if_bluetooth;
	const btsock_interface_t *if_sock;
	const bthh_interface_t *if_hid;

	const void *test_data;
	struct queue *steps;

	guint signalfd;
	uint16_t mgmt_index;
	pid_t bluetoothd_pid;
};

struct test_case {
	struct step *step;
	char *title;
	uint16_t step_num;
};

/*
 * Struct of data to check within step action.
 */
struct bt_action_data {
	uint8_t status;
};

/*
 * Callback data structure should be enhanced with data
 * returned by callbacks. It's used for test case step
 * matching with expected step data.
 */
struct bt_callback_data {
	bt_state_t state;
};

/*
 * Step structure contains expected step data and step
 * action, which should be performed before step check.
 */
struct step {
	void (*action)(void);
	struct bt_action_data action_result;

	expected_bt_callback_t callback;
	struct bt_callback_data callback_result;
};

/* Get, remove test cases API */
struct queue *get_bluetooth_tests(void);
void remove_bluetooth_tests(void);
struct queue *get_socket_tests(void);
void remove_socket_tests(void);
struct queue *get_hidhost_tests(void);
void remove_hidhost_tests(void);

/* Actions */
void dummy_action(void);
void bluetooth_enable_action(void);
