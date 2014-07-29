/*
 * Copyright (C) 2013 Intel Corporation
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

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <libgen.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/util.h"
#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

#include "emulator/bthost.h"
#include "monitor/bt.h"

#include <hardware/hardware.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>
#include <hardware/bt_hh.h>

#include "utils.h"

struct priority_property {
	bt_property_t prop;
	int prio;
};

struct generic_data {
	int expected_adapter_status;
	uint32_t expect_settings_set;
	int expected_cb_count;
	bt_property_t set_property;
	bt_callbacks_t expected_hal_cb;
	struct priority_property *expected_properties;
	uint8_t expected_properties_num;
};

struct socket_data {
	btsock_type_t sock_type;
	const char *service_name;
	const uint8_t *service_uuid;
	const bt_bdaddr_t *bdaddr;
	int channel;
	int flags;
	bt_status_t expected_status;
	bool test_channel;
};

struct hidhost_generic_data {
	bthh_status_t expected_status;
	int expected_conn_state;
	int expected_cb_count;
	bthh_protocol_mode_t expected_protocol_mode;
	int expected_report;
	bthh_callbacks_t expected_hal_cb;
	int expected_report_size;
};

#define WAIT_FOR_SIGNAL_TIME 2 /* in seconds */
#define EMULATOR_SIGNAL "emulator_started"

#define BT_STATUS_NOT_EXPECTED	-1

struct test_data {
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	unsigned int mgmt_settings_id;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	const void *test_data;
	pid_t bluetoothd_pid;
	guint signalfd;

	struct hw_device_t *device;
	const bt_interface_t *if_bluetooth;
	const btsock_interface_t *if_sock;
	const bthh_interface_t *if_hid;

	int conditions_left;

	/* Set to true if test conditions should be verified */
	bool test_checks_valid;

	bool test_result_set;

	int cb_count;
	GSList *expected_properties_list;

	/* hidhost */
	uint16_t sdp_handle;
	uint16_t sdp_cid;
	uint16_t ctrl_handle;
	uint16_t ctrl_cid;
	uint16_t intr_handle;
	uint16_t intr_cid;
};

struct bt_cb_data {
	bt_state_t state;
	bt_status_t status;

	bt_bdaddr_t bdaddr;
	bt_bdname_t bdname;
	uint32_t cod;

	bt_ssp_variant_t ssp_variant;
	uint32_t passkey;

	int num;
	bt_property_t *props;
};

struct hh_cb_data {
	bt_bdaddr_t bdaddr;

	bthh_status_t status;
	bthh_hid_info_t hid_info;
	bthh_protocol_mode_t mode;
	bthh_connection_state_t state;

	uint8_t *report;
	int size;
};

static char exec_dir[PATH_MAX];

static gint scheduled_cbacks_num = 0;

static void test_update_state(void)
{
	struct test_data *data = tester_get_data();

	if (data->conditions_left == 0 && !data->test_result_set) {
		data->test_result_set = true;
		tester_test_passed();
	}
}

static void check_cb_count(void)
{
	struct test_data *data = tester_get_data();

	if (!data->test_checks_valid)
		return;

	if (data->cb_count == 0) {
		data->conditions_left--;
		test_update_state();
	}
}

static void check_expected_status(uint8_t status)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test_data = data->test_data;

	if (test_data->expected_adapter_status == status) {
		data->conditions_left--;
		test_update_state();
	} else
		tester_test_failed();
}

static int locate_property(gconstpointer expected_data,
						gconstpointer received_prop)
{
	bt_property_t rec_prop = *((bt_property_t *)received_prop);
	bt_property_t exp_prop =
			((struct priority_property *)expected_data)->prop;

	if (exp_prop.type && (exp_prop.type != rec_prop.type))
		return 1;
	if (exp_prop.len && (exp_prop.len != rec_prop.len))
		return 1;
	if (exp_prop.val && memcmp(exp_prop.val, rec_prop.val, exp_prop.len))
		return 1;

	return 0;
}

static int compare_priorities(gconstpointer prop_list, gconstpointer priority)
{
	int prio = GPOINTER_TO_INT(priority);
	int comp_prio = ((struct priority_property *)prop_list)->prio;

	if (prio > comp_prio)
		return 0;

	return 1;
}

static bool check_prop_priority(int rec_prop_prio)
{
	struct test_data *data = tester_get_data();
	GSList *l = data->expected_properties_list;

	if (!rec_prop_prio || !g_slist_length(l))
		return true;

	if (g_slist_find_custom(l, GINT_TO_POINTER(rec_prop_prio),
							&compare_priorities))
		return false;

	return true;
}

static void check_expected_property(bt_property_t received_prop)
{
	struct test_data *data = tester_get_data();
	int rec_prio;
	GSList *l = data->expected_properties_list;
	GSList *found_exp_prop;

	if (!g_slist_length(l))
		return;

	found_exp_prop = g_slist_find_custom(l, &received_prop,
							&locate_property);

	if (found_exp_prop) {
		rec_prio = ((struct priority_property *)
						(found_exp_prop->data))->prio;
		if (check_prop_priority(rec_prio))
			l = g_slist_remove(l, found_exp_prop->data);
	}

	data->expected_properties_list = l;

	if (g_slist_length(l))
		return;

	data->conditions_left--;
	test_update_state();
}

static bool check_test_property(bt_property_t received_prop,
						bt_property_t expected_prop)
{
	if (expected_prop.type && (expected_prop.type != received_prop.type))
		return false;
	if (expected_prop.len && (expected_prop.len != received_prop.len))
		return false;
	if (expected_prop.val && memcmp(expected_prop.val, received_prop.val,
							expected_prop.len))
		return false;

	return true;
}

static void emu_connectable_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	switch (opcode) {
	case BT_HCI_CMD_WRITE_SCAN_ENABLE:
	case BT_HCI_CMD_LE_SET_ADV_ENABLE:
		break;
	default:
		return;
	}

	tester_print("Emulated remote set connectable status 0x%02x", status);

	if (status)
		tester_setup_failed();
	else
		tester_setup_complete();
}

static void setup_powered_emulated_remote(void)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	tester_print("Controller powered on");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_cmd_complete_cb(bthost, emu_connectable_complete, data);

	if (data->hciemu_type == HCIEMU_TYPE_LE)
		bthost_set_adv_enable(bthost, 0x01, 0x00);
	else
		bthost_write_scan_enable(bthost, 0x03);
}

static gboolean adapter_state_changed(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bt_cb_data *cb_data = user_data;

	if (data->test_checks_valid &&
			test->expected_hal_cb.adapter_state_changed_cb) {
		test->expected_hal_cb.adapter_state_changed_cb(cb_data->state);
		goto cleanup;
	}

	if (!data->test_checks_valid && cb_data->state == BT_STATE_ON)
		setup_powered_emulated_remote();

cleanup:
	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void adapter_state_changed_cb(bt_state_t state)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->state = state;

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(adapter_state_changed, cb_data);
}

static void discovery_start_success_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_DISCOVERY_STARTED) {
		data->cb_count--;
		check_cb_count();
	}
}

static void discovery_start_done_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	status = data->if_bluetooth->start_discovery();
	data->cb_count--;

	check_cb_count();
	check_expected_status(status);
}

static void discovery_stop_success_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	if (state == BT_DISCOVERY_STARTED && data->cb_count == 2) {
		status = data->if_bluetooth->cancel_discovery();
		check_expected_status(status);
		data->cb_count--;
		return;
	}
	if (state == BT_DISCOVERY_STOPPED && data->cb_count == 1) {
		data->cb_count--;
		check_cb_count();
	}
}

static void discovery_device_found_state_changed_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_DISCOVERY_STARTED && data->cb_count == 3) {
		data->cb_count--;
		return;
	}
	if (state == BT_DISCOVERY_STOPPED && data->cb_count == 1) {
		data->cb_count--;
		check_cb_count();
	}
}

static void remote_discovery_state_changed_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_DISCOVERY_STARTED && data->cb_count == 3) {
		data->cb_count--;
		return;
	}
	if (state == BT_DISCOVERY_STOPPED && data->cb_count == 1) {
		data->cb_count--;
		check_cb_count();
	}
}

static void remote_setprop_disc_state_changed_cb(bt_discovery_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_DISCOVERY_STARTED && data->cb_count == 3) {
		data->cb_count--;
		return;
	}
	if (state == BT_DISCOVERY_STOPPED) {
		data->cb_count--;
		check_cb_count();
	}
}

static gboolean discovery_state_changed(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bt_cb_data *cb_data = user_data;

	if (test && test->expected_hal_cb.discovery_state_changed_cb)
		test->expected_hal_cb.discovery_state_changed_cb(
								cb_data->state);

	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void discovery_state_changed_cb(bt_discovery_state_t state)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->state = state;
	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(discovery_state_changed, cb_data);
}

static bt_property_t *copy_properties(int num_properties,
						bt_property_t *properties)
{
	int i;
	bt_property_t *props = g_new0(bt_property_t, num_properties);

	for (i = 0; i < num_properties; i++) {
		props[i].type = properties[i].type;
		props[i].len = properties[i].len;
		props[i].val = g_memdup(properties[i].val, properties[i].len);
	}

	return props;
}

static void free_properties(int num_properties, bt_property_t *properties)
{
	int i;

	for (i = 0; i < num_properties; i++)
		g_free(properties[i].val);

	g_free(properties);
}

static void discovery_device_found_cb(int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	uint8_t *remote_bdaddr =
			(uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	uint32_t emu_remote_type = BT_DEVICE_DEVTYPE_BREDR;
	int32_t emu_remote_rssi = -60;
	bt_bdaddr_t emu_remote_bdaddr;
	int i;
	bt_property_t expected_prop;
	bt_property_t received_prop;

	data->cb_count--;
	check_cb_count();

	if (num_properties < 1) {
		tester_test_failed();
		return;
	}

	bdaddr2android((const bdaddr_t *) remote_bdaddr, &emu_remote_bdaddr);

	for (i = 0; i < num_properties; i++) {
		received_prop = properties[i];

		switch (properties[i].type) {
		case BT_PROPERTY_BDADDR:
			expected_prop.type = BT_PROPERTY_BDADDR;
			expected_prop.len = sizeof(emu_remote_bdaddr);
			expected_prop.val = &emu_remote_bdaddr;
			break;

		case BT_PROPERTY_TYPE_OF_DEVICE:
			expected_prop.type = BT_PROPERTY_TYPE_OF_DEVICE;
			expected_prop.len = sizeof(emu_remote_type);
			expected_prop.val = &emu_remote_type;
			break;

		case BT_PROPERTY_REMOTE_RSSI:
			expected_prop.type = BT_PROPERTY_REMOTE_RSSI;
			expected_prop.len = sizeof(emu_remote_rssi);
			expected_prop.val = &emu_remote_rssi;
			break;

		default:
			expected_prop.type = 0;
			expected_prop.len = 0;
			expected_prop.val = NULL;
			break;
		}

		if (!check_test_property(received_prop, expected_prop)) {
			data->if_bluetooth->cancel_discovery();
			tester_test_failed();
			return;
		}
	}

	data->if_bluetooth->cancel_discovery();
}

static void remote_getprops_device_found_cb(int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	if (data->cb_count == 2)
		data->cb_count--;

	data->if_bluetooth->cancel_discovery();
	data->if_bluetooth->get_remote_device_properties(&remote_addr);
}

static void remote_get_property_device_found_cb(int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	bt_status_t status;
	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;

	const bt_property_t prop = test->expected_properties[0].prop;

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	if (data->cb_count == 2)
		data->cb_count--;

	data->if_bluetooth->cancel_discovery();
	status = data->if_bluetooth->get_remote_device_property(&remote_addr,
								prop.type);
	check_expected_status(status);
}

static void remote_setprop_device_found_cb(int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	bt_status_t status;
	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;

	const bt_property_t prop = test->expected_properties[0].prop;

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	if (data->cb_count == 2)
		data->cb_count--;

	data->if_bluetooth->cancel_discovery();
	status = data->if_bluetooth->set_remote_device_property(&remote_addr,
									&prop);
	check_expected_status(status);

	data->if_bluetooth->get_remote_device_property(&remote_addr, prop.type);
}

static void remote_setprop_fail_device_found_cb(int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	bt_status_t status;
	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;

	const bt_property_t prop = test->expected_properties[0].prop;

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	if (data->cb_count == 2)
		data->cb_count--;

	data->if_bluetooth->cancel_discovery();
	status = data->if_bluetooth->set_remote_device_property(&remote_addr,
									&prop);
	check_expected_status(status);
}

static void bond_device_found_cb(int num_properties, bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;
	bt_status_t status;

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	if (data->cb_count == 4) {
		data->cb_count--;
		status = data->if_bluetooth->create_bond(&remote_addr);
		check_expected_status(status);
	}
}

static void bond_nostatus_device_found_cb(int num_properties,
						bt_property_t *properties)
{
	struct test_data *data = tester_get_data();
	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	if (data->cb_count == 4) {
		data->cb_count--;
		data->if_bluetooth->create_bond(&remote_addr);
	}
}

static gboolean device_found(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bt_cb_data *cb_data = user_data;

	if (data->test_checks_valid && test->expected_hal_cb.device_found_cb)
		test->expected_hal_cb.device_found_cb(cb_data->num,
								cb_data->props);

	free_properties(cb_data->num, cb_data->props);
	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void device_found_cb(int num_properties, bt_property_t *properties)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->num = num_properties;
	cb_data->props = copy_properties(num_properties, properties);

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(device_found, cb_data);
}

static gboolean adapter_properties(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bt_cb_data *cb_data = user_data;

	if (data->test_checks_valid &&
				test->expected_hal_cb.adapter_properties_cb)
		test->expected_hal_cb.adapter_properties_cb(cb_data->status,
						cb_data->num, cb_data->props);

	free_properties(cb_data->num, cb_data->props);
	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void adapter_properties_cb(bt_status_t status, int num_properties,
						bt_property_t *properties)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->status = status;
	cb_data->num = num_properties;
	cb_data->props = copy_properties(num_properties, properties);

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(adapter_properties, cb_data);
}

static void remote_test_device_properties_cb(bt_status_t status,
				bt_bdaddr_t *bd_addr, int num_properties,
				bt_property_t *properties)
{
	int i;

	for (i = 0; i < num_properties; i++)
		check_expected_property(properties[i]);
}

static gboolean remote_device_properties(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bt_cb_data *cb_data = user_data;

	if (data->test_checks_valid &&
			test->expected_hal_cb.remote_device_properties_cb)
		test->expected_hal_cb.remote_device_properties_cb(
					cb_data->status, &cb_data->bdaddr,
					cb_data->num, cb_data->props);

	free_properties(cb_data->num, cb_data->props);
	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void remote_device_properties_cb(bt_status_t status,
				bt_bdaddr_t *bd_addr, int num_properties,
				bt_property_t *properties)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->status = status;
	cb_data->bdaddr = *bd_addr;
	cb_data->num = num_properties;
	cb_data->props = copy_properties(num_properties, properties);

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(remote_device_properties, cb_data);
}

static void bond_test_bonded_state_changed_cb(bt_status_t status,
			bt_bdaddr_t *remote_bd_addr, bt_bond_state_t state)
{
	struct test_data *data = tester_get_data();

	switch (state) {
	case BT_BOND_STATE_BONDING:
		data->cb_count--;
		break;
	case BT_BOND_STATE_BONDED:
		data->cb_count--;
		check_cb_count();
		break;
	default:
		tester_test_failed();
		break;
	}
}

static void bond_test_none_state_changed_cb(bt_status_t status,
			bt_bdaddr_t *remote_bd_addr, bt_bond_state_t state)
{
	struct test_data *data = tester_get_data();

	switch (state) {
	case BT_BOND_STATE_BONDING:
		data->cb_count--;
		break;
	case BT_BOND_STATE_NONE:
		data->cb_count--;
		check_cb_count();
		break;
	default:
		tester_test_failed();
		break;
	}
}

static void bond_remove_success_state_changed_cb(bt_status_t status,
			bt_bdaddr_t *remote_bd_addr, bt_bond_state_t state)
{
	struct test_data *data = tester_get_data();
	bt_status_t remove_status;
	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	if (state == BT_BOND_STATE_BONDED) {
		data->cb_count--;
		remove_status = data->if_bluetooth->remove_bond(&remote_addr);
		check_expected_status(remove_status);
		return;
	}

	if (state == BT_BOND_STATE_NONE) {
		data->cb_count--;
		check_cb_count();
	}
}

static gboolean bond_state_changed(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bt_cb_data *cb_data = user_data;

	if (data->test_checks_valid &&
				test->expected_hal_cb.bond_state_changed_cb)
		test->expected_hal_cb.bond_state_changed_cb(cb_data->status,
					&cb_data->bdaddr, cb_data->state);

	g_free(cb_data);
	return FALSE;
}

static void bond_state_changed_cb(bt_status_t status,
			bt_bdaddr_t *remote_bd_addr, bt_bond_state_t state)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->status = status;
	cb_data->bdaddr = *remote_bd_addr;
	cb_data->state = state;

	g_idle_add(bond_state_changed, cb_data);
}

static void bond_create_pin_success_request_cb(bt_bdaddr_t *remote_bd_addr,
					bt_bdname_t *bd_name, uint32_t cod)
{
	struct test_data *data = tester_get_data();
	const bt_bdaddr_t *bdaddr = remote_bd_addr;
	bt_pin_code_t pin_code = {
	.pin = { 0x30, 0x30, 0x30, 0x30 },
	};
	uint8_t pin_len = 4;

	data->cb_count--;

	data->if_bluetooth->pin_reply(bdaddr, TRUE, pin_len, &pin_code);
}

static void bond_create_pin_fail_request_cb(bt_bdaddr_t *remote_bd_addr,
					bt_bdname_t *bd_name, uint32_t cod)
{
	struct test_data *data = tester_get_data();
	const bt_bdaddr_t *bdaddr = remote_bd_addr;
	bt_pin_code_t pin_code = {
	.pin = { 0x31, 0x31, 0x31, 0x31 },
	};
	uint8_t pin_len = 4;

	data->cb_count--;

	data->if_bluetooth->pin_reply(bdaddr, TRUE, pin_len, &pin_code);
}

static gboolean pin_request(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bt_cb_data *cb_data = user_data;

	if (data->test_checks_valid && test->expected_hal_cb.pin_request_cb)
		test->expected_hal_cb.pin_request_cb(&cb_data->bdaddr,
						&cb_data->bdname, cb_data->cod);

	g_free(cb_data);
	return FALSE;
}

static void pin_request_cb(bt_bdaddr_t *remote_bd_addr,
					bt_bdname_t *bd_name, uint32_t cod)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->bdaddr = *remote_bd_addr;
	cb_data->bdname = *bd_name;
	cb_data->cod = cod;

	g_idle_add(pin_request, cb_data);
}

static void bond_create_ssp_request_cb(const bt_bdaddr_t *remote_bd_addr,
					bt_ssp_variant_t pairing_variant,
					bool accept, uint32_t pass_key)
{
	struct test_data *data = tester_get_data();

	data->if_bluetooth->ssp_reply(remote_bd_addr,
					BT_SSP_VARIANT_PASSKEY_CONFIRMATION,
					accept, pass_key);

	data->cb_count--;
}

static void bond_create_ssp_success_request_cb(bt_bdaddr_t *remote_bd_addr,
					bt_bdname_t *bd_name, uint32_t cod,
					bt_ssp_variant_t pairing_variant,
					uint32_t pass_key)
{
	bool accept = true;

	bond_create_ssp_request_cb(remote_bd_addr, pairing_variant, accept,
								pass_key);
}

static void bond_create_ssp_fail_request_cb(bt_bdaddr_t *remote_bd_addr,
					bt_bdname_t *bd_name, uint32_t cod,
					bt_ssp_variant_t pairing_variant,
					uint32_t pass_key)
{
	bool accept = false;

	bond_create_ssp_request_cb(remote_bd_addr, pairing_variant, accept,
								pass_key);
}

static void bond_cancel_success_ssp_request_cb(bt_bdaddr_t *remote_bd_addr,
					bt_bdname_t *bd_name, uint32_t cod,
					bt_ssp_variant_t pairing_variant,
					uint32_t pass_key)
{
	struct test_data *data = tester_get_data();
	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;
	bt_status_t status;

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	data->cb_count--;

	status = data->if_bluetooth->cancel_bond(&remote_addr);
	check_expected_status(status);
}

static gboolean ssp_request(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	struct bt_cb_data *cb_data = user_data;

	if (data->test_checks_valid && test->expected_hal_cb.ssp_request_cb)
		test->expected_hal_cb.ssp_request_cb(&cb_data->bdaddr,
					&cb_data->bdname, cb_data->cod,
					cb_data->ssp_variant, cb_data->passkey);

	g_free(cb_data);
	return FALSE;
}

static void ssp_request_cb(bt_bdaddr_t *remote_bd_addr, bt_bdname_t *bd_name,
				uint32_t cod, bt_ssp_variant_t pairing_variant,
				uint32_t pass_key)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->bdaddr = *remote_bd_addr;
	cb_data->bdname = *bd_name;
	cb_data->cod = cod;
	cb_data->ssp_variant = pairing_variant;
	cb_data->passkey = pass_key;

	g_idle_add(ssp_request, cb_data);
}

static const struct generic_data bluetooth_discovery_start_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
						discovery_start_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bluetooth_discovery_start_success2_test = {
	.expected_hal_cb.discovery_state_changed_cb = discovery_start_done_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bluetooth_discovery_stop_success2_test = {
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bluetooth_discovery_stop_success_test = {
	.expected_hal_cb.discovery_state_changed_cb = discovery_stop_success_cb,
	.expected_cb_count = 2,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bluetooth_discovery_device_found_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					discovery_device_found_state_changed_cb,
	.expected_hal_cb.device_found_cb = discovery_device_found_cb,
	.expected_cb_count = 3,
	.expected_adapter_status = BT_STATUS_NOT_EXPECTED,
};

static const char remote_get_properties_bdname_val[] = "00:AA:01:01:00:00";
static uint32_t remote_get_properties_cod_val = 0;
static bt_device_type_t remote_get_properties_tod_val = BT_DEVICE_DEVTYPE_BREDR;
static int32_t remote_get_properties_rssi_val = -60;

static struct priority_property remote_getprops_props[] = {
	{
	.prop.type = BT_PROPERTY_BDNAME,
	.prop.val = &remote_get_properties_bdname_val,
	.prop.len = sizeof(remote_get_properties_bdname_val) - 1,
	},
	{
	.prop.type = BT_PROPERTY_UUIDS,
	.prop.val = NULL,
	.prop.len = 0,
	},
	{
	.prop.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.prop.val = &remote_get_properties_cod_val,
	.prop.len = sizeof(remote_get_properties_cod_val),
	},
	{
	.prop.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.prop.val = &remote_get_properties_tod_val,
	.prop.len = sizeof(remote_get_properties_tod_val),
	},
	{
	.prop.type = BT_PROPERTY_REMOTE_RSSI,
	.prop.val = &remote_get_properties_rssi_val,
	.prop.len = sizeof(remote_get_properties_rssi_val),
	},
	{
	.prop.type = BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP,
	.prop.val = NULL,
	.prop.len = 4,
	},
};

static const struct generic_data bt_dev_getprops_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_getprops_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties_num = 6,
	.expected_properties = remote_getprops_props,
	.expected_adapter_status = BT_STATUS_NOT_EXPECTED,
};

static const char remote_getprop_bdname_val[] = "00:AA:01:01:00:00";

static struct priority_property remote_getprop_bdname_props[] = {
	{
	.prop.type = BT_PROPERTY_BDNAME,
	.prop.val = &remote_getprop_bdname_val,
	.prop.len = sizeof(remote_getprop_bdname_val) - 1,
	},
};

static const struct generic_data bt_dev_getprop_bdname_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties_num = 1,
	.expected_properties = remote_getprop_bdname_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static struct priority_property remote_getprop_uuids_props[] = {
	{
	.prop.type = BT_PROPERTY_UUIDS,
	.prop.val = NULL,
	.prop.len = 0,
	},
};

static const struct generic_data bt_dev_getprop_uuids_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties_num = 1,
	.expected_properties = remote_getprop_uuids_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static uint32_t remote_getprop_cod_val = 0;

static struct priority_property remote_getprop_cod_props[] = {
	{
	.prop.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.prop.val = &remote_getprop_cod_val,
	.prop.len = sizeof(remote_getprop_cod_val),
	},
};

static const struct generic_data bt_dev_getprop_cod_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties_num = 1,
	.expected_properties = remote_getprop_cod_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_device_type_t remote_getprop_tod_val = BT_DEVICE_DEVTYPE_BREDR;

static struct priority_property remote_getprop_tod_props[] = {
	{
	.prop.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.prop.val = &remote_getprop_tod_val,
	.prop.len = sizeof(remote_getprop_tod_val),
	},
};

static const struct generic_data bt_dev_getprop_tod_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties_num = 1,
	.expected_properties = remote_getprop_tod_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static int32_t remote_getprop_rssi_val = -60;

static struct priority_property remote_getprop_rssi_props[] = {
	{
	.prop.type = BT_PROPERTY_REMOTE_RSSI,
	.prop.val = &remote_getprop_rssi_val,
	.prop.len = sizeof(remote_getprop_rssi_val),
	},
};

static const struct generic_data bt_dev_getprop_rssi_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties_num = 1,
	.expected_properties = remote_getprop_rssi_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static struct priority_property remote_getprop_timestamp_props[] = {
	{
	.prop.type = BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP,
	.prop.val = NULL,
	.prop.len = 4,
	},
};

static const struct generic_data bt_dev_getprop_timpestamp_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties_num = 1,
	.expected_properties = remote_getprop_timestamp_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_bdaddr_t remote_getprop_bdaddr_val = {
	.address = { 0x00, 0xaa, 0x01, 0x00, 0x00, 0x00 }
};

static struct priority_property remote_getprop_bdaddr_props[] = {
	{
	.prop.type = BT_PROPERTY_BDADDR,
	.prop.val = &remote_getprop_bdaddr_val,
	.prop.len = sizeof(remote_getprop_bdaddr_val),
	},
};

static const struct generic_data bt_dev_getprop_bdaddr_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_getprop_bdaddr_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_service_record_t remote_getprop_servrec_val = {
	.uuid = { {0x00} },
	.channel = 12,
	.name = "bt_name",
};

static struct priority_property remote_getprop_servrec_props[] = {
	{
	.prop.type = BT_PROPERTY_SERVICE_RECORD,
	.prop.val = &remote_getprop_servrec_val,
	.prop.len = sizeof(remote_getprop_servrec_val),
	},
};

static const struct generic_data bt_dev_getprop_servrec_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_getprop_servrec_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_scan_mode_t remote_getprop_scanmode_val = BT_SCAN_MODE_CONNECTABLE;

static struct priority_property remote_getprop_scanmode_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.prop.val = &remote_getprop_scanmode_val,
	.prop.len = sizeof(remote_getprop_scanmode_val),
	},
};

static const struct generic_data bt_dev_getprop_scanmode_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_getprop_scanmode_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static struct priority_property remote_getprop_bondeddev_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.prop.val = NULL,
	.prop.len = 0,
	},
};

static const struct generic_data bt_dev_getprop_bondeddev_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_getprop_bondeddev_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static uint32_t remote_getprop_disctimeout_val = 120;

static struct priority_property remote_getprop_disctimeout_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.prop.val = &remote_getprop_disctimeout_val,
	.prop.len = sizeof(remote_getprop_disctimeout_val),
	},
};

static const struct generic_data bt_dev_getprop_disctimeout_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_getprop_disctimeout_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static struct priority_property remote_getprop_verinfo_props[] = {
	{
	.prop.type = BT_PROPERTY_REMOTE_VERSION_INFO,
	.prop.val = NULL,
	.prop.len = 0,
	},
};

static const struct generic_data bt_dev_getprop_verinfo_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_getprop_verinfo_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static struct priority_property remote_getprop_fname_props[] = {
	{
	.prop.type = BT_PROPERTY_REMOTE_VERSION_INFO,
	.prop.val = NULL,
	.prop.len = 0,
	},
};

static const struct generic_data bt_dev_getprop_fname_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_get_property_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_getprop_fname_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static const char remote_setprop_fname_val[] = "set_fname_test";

static struct priority_property remote_setprop_fname_props[] = {
	{
	.prop.type = BT_PROPERTY_REMOTE_FRIENDLY_NAME,
	.prop.val = &remote_setprop_fname_val,
	.prop.len = sizeof(remote_setprop_fname_val) - 1,
	},
};

static const struct generic_data bt_dev_setprop_fname_success_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_setprop_disc_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_device_found_cb,
	.expected_hal_cb.remote_device_properties_cb =
					remote_test_device_properties_cb,
	.expected_cb_count = 3,
	.expected_properties_num = 1,
	.expected_properties = remote_setprop_fname_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const char remote_setprop_bdname_val[] = "setprop_bdname_fail";

static struct priority_property remote_setprop_bdname_props[] = {
	{
	.prop.type = BT_PROPERTY_BDNAME,
	.prop.val = &remote_setprop_bdname_val,
	.prop.len = sizeof(remote_setprop_bdname_val) - 1,
	},
};

static const struct generic_data bt_dev_setprop_bdname_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_bdname_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static struct priority_property remote_setprop_uuids_props[] = {
	{
	.prop.type = BT_PROPERTY_UUIDS,
	.prop.val = NULL,
	.prop.len = 0,
	},
};

static const struct generic_data bt_dev_setprop_uuids_fail_test  = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_uuids_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static uint32_t remote_setprop_cod_val = 0;

static struct priority_property remote_setprop_cod_props[] = {
	{
	.prop.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.prop.val = &remote_setprop_cod_val,
	.prop.len = sizeof(remote_setprop_cod_val),
	},
};

static const struct generic_data bt_dev_setprop_cod_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_cod_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_device_type_t remote_setprop_tod_val = BT_DEVICE_DEVTYPE_BREDR;

static struct priority_property remote_setprop_tod_props[] = {
	{
	.prop.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.prop.val = &remote_setprop_tod_val,
	.prop.len = sizeof(remote_setprop_tod_val),
	},
};

static const struct generic_data bt_dev_setprop_tod_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_tod_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static int32_t remote_setprop_rssi_val = -60;

static struct priority_property remote_setprop_rssi_props[] = {
	{
	.prop.type = BT_PROPERTY_REMOTE_RSSI,
	.prop.val = &remote_setprop_rssi_val,
	.prop.len = sizeof(remote_setprop_rssi_val),
	},
};

static const struct generic_data bt_dev_setprop_rssi_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_rssi_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static int32_t remote_setprop_timestamp_val = 0xAB;

static struct priority_property remote_setprop_timestamp_props[] = {
	{
	.prop.type = BT_PROPERTY_REMOTE_DEVICE_TIMESTAMP,
	.prop.val = (&remote_setprop_timestamp_val),
	.prop.len = sizeof(remote_setprop_timestamp_val),
	},
};

static const struct generic_data bt_dev_setprop_timpestamp_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_timestamp_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_bdaddr_t remote_setprop_bdaddr_val = {
	.address = { 0x00, 0xaa, 0x01, 0x00, 0x00, 0x00 }
};

static struct priority_property remote_setprop_bdaddr_props[] = {
	{
	.prop.type = BT_PROPERTY_BDADDR,
	.prop.val = &remote_setprop_bdaddr_val,
	.prop.len = sizeof(remote_setprop_bdaddr_val),
	},
};

static const struct generic_data bt_dev_setprop_bdaddr_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_bdaddr_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_service_record_t remote_setprop_servrec_val = {
	.uuid = { {0x00} },
	.channel = 12,
	.name = "bt_name",
};

static struct priority_property remote_setprop_servrec_props[] = {
	{
	.prop.type = BT_PROPERTY_SERVICE_RECORD,
	.prop.val = &remote_setprop_servrec_val,
	.prop.len = sizeof(remote_setprop_servrec_val),
	},
};

static const struct generic_data bt_dev_setprop_servrec_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_servrec_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_scan_mode_t remote_setprop_scanmode_val = BT_SCAN_MODE_CONNECTABLE;

static struct priority_property remote_setprop_scanmode_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.prop.val = &remote_setprop_scanmode_val,
	.prop.len = sizeof(remote_setprop_scanmode_val),
	},
};

static const struct generic_data bt_dev_setprop_scanmode_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_scanmode_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_bdaddr_t remote_setprop_bondeddev_val = {
	.address = { 0x00, 0xaa, 0x01, 0x00, 0x00, 0x00 }
};

static struct priority_property remote_setprop_bondeddev_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.prop.val = &remote_setprop_bondeddev_val,
	.prop.len = sizeof(remote_setprop_bondeddev_val),
	},
};

static const struct generic_data bt_dev_setprop_bondeddev_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_bondeddev_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static uint32_t remote_setprop_disctimeout_val = 120;

static struct priority_property remote_setprop_disctimeout_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.prop.val = &remote_setprop_disctimeout_val,
	.prop.len = sizeof(remote_setprop_disctimeout_val),
	},
};

static const struct generic_data bt_dev_setprop_disctimeout_fail_test = {
	.expected_hal_cb.discovery_state_changed_cb =
					remote_discovery_state_changed_cb,
	.expected_hal_cb.device_found_cb = remote_setprop_fail_device_found_cb,
	.expected_cb_count = 3,
	.expected_properties = remote_setprop_disctimeout_props,
	.expected_adapter_status = BT_STATUS_FAIL,
};

static const struct generic_data bt_bond_create_pin_success_test = {
	.expected_hal_cb.device_found_cb = bond_device_found_cb,
	.expected_hal_cb.bond_state_changed_cb =
					bond_test_bonded_state_changed_cb,
	.expected_hal_cb.pin_request_cb = bond_create_pin_success_request_cb,
	.expected_cb_count = 4,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bt_bond_create_pin_fail_test = {
	.expected_hal_cb.device_found_cb = bond_nostatus_device_found_cb,
	.expected_hal_cb.bond_state_changed_cb =
						bond_test_none_state_changed_cb,
	.expected_hal_cb.pin_request_cb = bond_create_pin_fail_request_cb,
	.expected_cb_count = 4,
	.expected_adapter_status = MGMT_STATUS_AUTH_FAILED,
};

static const struct generic_data bt_bond_create_ssp_success_test = {
	.expected_hal_cb.device_found_cb = bond_device_found_cb,
	.expected_hal_cb.bond_state_changed_cb =
					bond_test_bonded_state_changed_cb,
	.expected_hal_cb.ssp_request_cb = bond_create_ssp_success_request_cb,
	.expected_cb_count = 4,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bt_bond_create_ssp_fail_test = {
	.expected_hal_cb.device_found_cb = bond_nostatus_device_found_cb,
	.expected_hal_cb.bond_state_changed_cb =
						bond_test_none_state_changed_cb,
	.expected_hal_cb.ssp_request_cb = bond_create_ssp_fail_request_cb,
	.expected_cb_count = 4,
	.expected_adapter_status = MGMT_STATUS_AUTH_FAILED,
};

static const struct generic_data bt_bond_create_no_disc_success_test = {
	.expected_hal_cb.bond_state_changed_cb =
					bond_test_bonded_state_changed_cb,
	.expected_hal_cb.ssp_request_cb = bond_create_ssp_success_request_cb,
	.expected_cb_count = 3,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bt_bond_create_bad_addr_success_test = {
	.expected_adapter_status = MGMT_STATUS_CONNECT_FAILED,
};

static const struct generic_data bt_bond_cancel_success_test = {
	.expected_hal_cb.device_found_cb = bond_nostatus_device_found_cb,
	.expected_hal_cb.bond_state_changed_cb =
						bond_test_none_state_changed_cb,
	.expected_hal_cb.ssp_request_cb = bond_cancel_success_ssp_request_cb,
	.expected_cb_count = 4,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bt_bond_remove_success_test = {
	.expected_hal_cb.device_found_cb = bond_nostatus_device_found_cb,
	.expected_hal_cb.bond_state_changed_cb =
					bond_remove_success_state_changed_cb,
	.expected_hal_cb.ssp_request_cb = bond_create_ssp_success_request_cb,
	.expected_cb_count = 4,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_callbacks_t bt_callbacks = {
	.size = sizeof(bt_callbacks),
	.adapter_state_changed_cb = adapter_state_changed_cb,
	.adapter_properties_cb = adapter_properties_cb,
	.remote_device_properties_cb = remote_device_properties_cb,
	.device_found_cb = device_found_cb,
	.discovery_state_changed_cb = discovery_state_changed_cb,
	.pin_request_cb = pin_request_cb,
	.ssp_request_cb = ssp_request_cb,
	.bond_state_changed_cb = bond_state_changed_cb,
	.acl_state_changed_cb = NULL,
	.thread_evt_cb = NULL,
	.dut_mode_recv_cb = NULL,
	.le_test_mode_cb = NULL
};

const bt_bdaddr_t bdaddr_dummy = {
	.address = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
};

static const struct socket_data btsock_inv_param_socktype = {
	.bdaddr = &bdaddr_dummy,
	.sock_type = 0,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_PARM_INVALID,
};

static const struct socket_data btsock_inv_param_socktype_l2cap = {
	.bdaddr = &bdaddr_dummy,
	.sock_type = BTSOCK_L2CAP,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_UNSUPPORTED,
};

/* Test invalid: channel & uuid are both zeroes */
static const struct socket_data btsock_inv_params_chan_uuid = {
	.bdaddr = &bdaddr_dummy,
	.sock_type = BTSOCK_RFCOMM,
	.channel = 0,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_PARM_INVALID,
};

static const struct socket_data btsock_success = {
	.bdaddr = &bdaddr_dummy,
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_SUCCESS,
	.test_channel = false
};

static const struct socket_data btsock_success_check_chan = {
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_SUCCESS,
	.test_channel = true,
};

static const struct socket_data btsock_inv_param_bdaddr = {
	.bdaddr = NULL,
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_PARM_INVALID,
};

static const struct socket_data btsock_inv_listen_listen = {
	.sock_type = BTSOCK_RFCOMM,
	.channel = 1,
	.service_uuid = NULL,
	.service_name = "Test service",
	.flags = 0,
	.expected_status = BT_STATUS_BUSY,
	.test_channel = true,
};

static gboolean hidhost_connection_state(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct hidhost_generic_data *test = data->test_data;
	struct hh_cb_data *cb_data = user_data;

	data->cb_count++;

	if (cb_data->state == BTHH_CONN_STATE_CONNECTED)
		tester_setup_complete();

	if (test && test->expected_hal_cb.connection_state_cb)
		test->expected_hal_cb.connection_state_cb(&cb_data->bdaddr,
								cb_data->state);

	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void hidhost_connection_state_cb(bt_bdaddr_t *bd_addr,
						bthh_connection_state_t state)
{
	struct hh_cb_data *cb_data = g_new0(struct hh_cb_data, 1);

	cb_data->state = state;
	cb_data->bdaddr = *bd_addr;

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(hidhost_connection_state, cb_data);
}

static gboolean hidhost_virual_unplug(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct hidhost_generic_data *test = data->test_data;
	struct hh_cb_data *cb_data = user_data;

	data->cb_count++;

	if (test && test->expected_hal_cb.virtual_unplug_cb)
		test->expected_hal_cb.virtual_unplug_cb(&cb_data->bdaddr,
							cb_data->status);

	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void hidhost_virual_unplug_cb(bt_bdaddr_t *bd_addr, bthh_status_t status)
{
	struct hh_cb_data *cb_data = g_new0(struct hh_cb_data, 1);

	cb_data->bdaddr = *bd_addr;
	cb_data->status = status;

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(hidhost_virual_unplug, cb_data);
}

static gboolean hidhost_hid_info(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct hidhost_generic_data *test = data->test_data;
	struct hh_cb_data *cb_data = user_data;

	data->cb_count++;

	if (test && test->expected_hal_cb.hid_info_cb)
		test->expected_hal_cb.hid_info_cb(&cb_data->bdaddr,
							cb_data->hid_info);

	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void hidhost_hid_info_cb(bt_bdaddr_t *bd_addr, bthh_hid_info_t hid)
{
	struct hh_cb_data *cb_data = g_new0(struct hh_cb_data, 1);

	cb_data->bdaddr = *bd_addr;
	cb_data->hid_info = hid;

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(hidhost_hid_info, cb_data);
}

static gboolean hidhost_protocol_mode(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct hidhost_generic_data *test = data->test_data;
	struct hh_cb_data *cb_data = user_data;

	data->cb_count++;

	if (test && test->expected_hal_cb.protocol_mode_cb)
		test->expected_hal_cb.protocol_mode_cb(&cb_data->bdaddr,
						cb_data->status, cb_data->mode);

	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void hidhost_protocol_mode_cb(bt_bdaddr_t *bd_addr,
						bthh_status_t status,
						bthh_protocol_mode_t mode)
{
	struct hh_cb_data *cb_data = g_new0(struct hh_cb_data, 1);

	cb_data->bdaddr = *bd_addr;
	cb_data->status = status;
	cb_data->mode = mode;

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(hidhost_protocol_mode, cb_data);
}

static gboolean hidhost_get_report(gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct hidhost_generic_data *test = data->test_data;
	struct hh_cb_data *cb_data = user_data;

	data->cb_count++;

	if (test && test->expected_hal_cb.get_report_cb)
		test->expected_hal_cb.get_report_cb(&cb_data->bdaddr,
			cb_data->status, cb_data->report, cb_data->size);

	g_free(cb_data->report);
	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void hidhost_get_report_cb(bt_bdaddr_t *bd_addr, bthh_status_t status,
						uint8_t *report, int size)
{
	struct hh_cb_data *cb_data = g_new0(struct hh_cb_data, 1);

	cb_data->bdaddr = *bd_addr;
	cb_data->status = status;
	cb_data->report = g_memdup(report, size);
	cb_data->size = size;

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(hidhost_get_report, cb_data);
}

static bthh_callbacks_t bthh_callbacks = {
	.size = sizeof(bthh_callbacks),
	.connection_state_cb = hidhost_connection_state_cb,
	.hid_info_cb = hidhost_hid_info_cb,
	.protocol_mode_cb = hidhost_protocol_mode_cb,
	.idle_time_cb = NULL,
	.get_report_cb = hidhost_get_report_cb,
	.virtual_unplug_cb = hidhost_virual_unplug_cb
};

#define test_bredr(name, data, test_setup, test, test_teardown) \
	do { \
		struct test_data *user; \
		user = g_malloc0(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDR; \
		user->test_data = data; \
		tester_add_full(name, data, test_pre_setup, test_setup, \
				test, test_teardown, test_post_teardown, \
							1, user, g_free); \
	} while (0)

#define test_bredrle(name, data, test_setup, test, test_teardown) \
	do { \
		struct test_data *user; \
		user = g_malloc0(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDRLE; \
		user->test_data = data; \
		tester_add_full(name, data, test_pre_setup, test_setup, \
				test, test_teardown, test_post_teardown, \
							3, user, g_free); \
	} while (0)

int main(int argc, char *argv[])
{
	snprintf(exec_dir, sizeof(exec_dir), "%s", dirname(argv[0]));

	tester_init(&argc, &argv);

	return tester_run();
}
