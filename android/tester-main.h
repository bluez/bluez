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

#define get_test_case_step_num(tc) (sizeof(tc) / sizeof(struct step))

struct test_data {
	struct mgmt *mgmt;
	struct hw_device_t *device;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;

	const bt_interface_t *if_bluetooth;

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
 * Step structure contains expected step data and step
 * action, which should be performed before step check.
 */
struct step {
	void (*action)(void);
	struct bt_action_data action_result;
};

/* Get, remove test cases API */
struct queue *get_bluetooth_tests(void);
void remove_bluetooth_tests(void);
