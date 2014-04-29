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

static char exec_dir[PATH_MAX + 1];

static gint scheduled_cbacks_num = 0;

static gboolean check_callbacks_called(gpointer user_data)
{
	/*
	 * Wait for all callbacks scheduled in current test context to execute
	 * in main loop. This will avoid late callback calls after test case has
	 * already failed or timed out.
	 */

	if (g_atomic_int_get(&scheduled_cbacks_num) == 0) {
		tester_teardown_complete();
		return FALSE;
	}

	return TRUE;
}
static void check_daemon_term(void)
{
	int status;
	pid_t pid;
	struct test_data *data = tester_get_data();

	if (!data)
		return;

	pid = waitpid(data->bluetoothd_pid, &status, WNOHANG);
	if (pid != data->bluetoothd_pid)
		return;

	data->bluetoothd_pid = 0;

	if (WIFEXITED(status) && (WEXITSTATUS(status) == EXIT_SUCCESS)) {
		g_idle_add(check_callbacks_called, NULL);
		return;
	}

	tester_warn("Unexpected Daemon shutdown with status %d", status);
}

static gboolean signal_handler(GIOChannel *channel, GIOCondition cond,
							gpointer user_data)
{
	struct signalfd_siginfo si;
	ssize_t result;
	int fd;

	if (cond & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		return FALSE;

	fd = g_io_channel_unix_get_fd(channel);

	result = read(fd, &si, sizeof(si));
	if (result != sizeof(si))
		return FALSE;

	switch (si.ssi_signo) {
	case SIGCHLD:
		check_daemon_term();
		break;
	}

	return TRUE;
}

static guint setup_signalfd(void)
{
	GIOChannel *channel;
	guint source;
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
		return 0;

	fd = signalfd(-1, &mask, 0);
	if (fd < 0)
		return 0;

	channel = g_io_channel_unix_new(fd);

	g_io_channel_set_close_on_unref(channel, TRUE);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	source = g_io_add_watch(channel,
				G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				signal_handler, NULL);

	g_io_channel_unref(channel);

	return source;
}

static void mgmt_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
}

static void test_update_state(void)
{
	struct test_data *data = tester_get_data();

	if (data->conditions_left == 0 && !data->test_result_set) {
		data->test_result_set = true;
		tester_test_passed();
	}
}

static void test_mgmt_settings_set(struct test_data *data)
{
	data->conditions_left--;

	test_update_state();
}

static void command_generic_new_settings(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test_data = data->test_data;
	uint32_t settings;

	if (length != 4) {
		tester_warn("Invalid parameter size for new settings event");
		tester_test_failed();
		return;
	}

	settings = get_le32(param);

	if ((settings & test_data->expect_settings_set) !=
					test_data->expect_settings_set)
		return;

	test_mgmt_settings_set(data);
	mgmt_unregister(data->mgmt, data->mgmt_settings_id);
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

static void expected_cb_count_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;

	data->cb_count = test_data->expected_cb_count;

	check_cb_count();
}

static void mgmt_cb_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;

	if (!test_data->expect_settings_set)
		test_mgmt_settings_set(data);
	else
		data->mgmt_settings_id = mgmt_register(data->mgmt,
				MGMT_EV_NEW_SETTINGS, data->mgmt_index,
				command_generic_new_settings, NULL, NULL);
}

static void expected_status_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;

	if (test_data->expected_adapter_status == BT_STATUS_NOT_EXPECTED)
		data->conditions_left--;
}

static void test_property_init(struct test_data *data)
{
	const struct generic_data *test_data = data->test_data;
	GSList *l = data->expected_properties_list;
	int i;

	if (!test_data->expected_properties_num) {
		data->conditions_left--;
		return;
	}

	for (i = 0; i < test_data->expected_properties_num; i++)
		l = g_slist_prepend(l, &(test_data->expected_properties[i]));

	data->expected_properties_list = l;
}

static void init_test_conditions(struct test_data *data)
{
	data->test_checks_valid = true;

	data->conditions_left = 4;

	expected_cb_count_init(data);
	mgmt_cb_init(data);
	expected_status_init(data);
	test_property_init(data);
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

static void read_info_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct mgmt_rp_read_info *rp = param;
	char addr[18];
	uint16_t manufacturer;
	uint32_t supported_settings, current_settings;

	tester_print("Read Info callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	ba2str(&rp->bdaddr, addr);
	manufacturer = btohs(rp->manufacturer);
	supported_settings = btohl(rp->supported_settings);
	current_settings = btohl(rp->current_settings);

	tester_print("  Address: %s", addr);
	tester_print("  Version: 0x%02x", rp->version);
	tester_print("  Manufacturer: 0x%04x", manufacturer);
	tester_print("  Supported settings: 0x%08x", supported_settings);
	tester_print("  Current settings: 0x%08x", current_settings);
	tester_print("  Class: 0x%02x%02x%02x",
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	tester_print("  Name: %s", rp->name);
	tester_print("  Short name: %s", rp->short_name);

	if (strcmp(hciemu_get_address(data->hciemu), addr)) {
		tester_pre_setup_failed();
		return;
	}

	tester_pre_setup_complete();
}

static void index_added_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Added callback");
	tester_print("  Index: 0x%04x", index);

	data->mgmt_index = index;

	mgmt_send(data->mgmt, MGMT_OP_READ_INFO, data->mgmt_index, 0, NULL,
					read_info_callback, NULL, NULL);
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Removed callback");
	tester_print("  Index: 0x%04x", index);

	if (index != data->mgmt_index)
		return;

	mgmt_unregister_index(data->mgmt, data->mgmt_index);

	mgmt_unref(data->mgmt);
	data->mgmt = NULL;

	tester_post_teardown_complete();
}

static void read_index_list_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Read Index List callback");
	tester_print("  Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new(data->hciemu_type);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
		return;
	}

	tester_print("New hciemu instance created");
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->signalfd = setup_signalfd();
	if (!data->signalfd) {
		tester_warn("Failed to setup signalfd");
		tester_pre_setup_failed();
		return;
	}

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	if (!tester_use_debug())
		fclose(stderr);
	else
		mgmt_set_debug(data->mgmt, mgmt_debug, "mgmt: ", NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0,
				NULL, read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;

	g_source_remove(data->signalfd);
	data->signalfd = 0;
}

static void bluetoothd_start(int hci_index)
{
	char prg_name[PATH_MAX + 1];
	char index[8];
	char *prg_argv[5];

	snprintf(prg_name, sizeof(prg_name), "%s/%s", exec_dir, "bluetoothd");
	snprintf(index, sizeof(index), "%d", hci_index);

	prg_argv[0] = prg_name;
	prg_argv[1] = "-i";
	prg_argv[2] = index;
	prg_argv[3] = "-d";
	prg_argv[4] = NULL;

	if (!tester_use_debug())
		fclose(stderr);

	execve(prg_argv[0], prg_argv, NULL);
}

static void emulator(int pipe, int hci_index)
{
	static const char SYSTEM_SOCKET_PATH[] = "\0android_system";
	char buf[1024];
	struct sockaddr_un addr;
	struct timeval tv;
	int fd;
	ssize_t len;

	fd = socket(PF_LOCAL, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		goto failed;

	tv.tv_sec = WAIT_FOR_SIGNAL_TIME;
	tv.tv_usec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(addr.sun_path, SYSTEM_SOCKET_PATH, sizeof(SYSTEM_SOCKET_PATH));

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Failed to bind system socket");
		goto failed;
	}

	len = write(pipe, EMULATOR_SIGNAL, sizeof(EMULATOR_SIGNAL));
	if (len != sizeof(EMULATOR_SIGNAL))
		goto failed;

	memset(buf, 0, sizeof(buf));

	len = read(fd, buf, sizeof(buf));
	if (len <= 0 || strcmp(buf, "bluetooth.start=daemon"))
		goto failed;

	close(pipe);
	close(fd);
	return bluetoothd_start(hci_index);

failed:
	close(pipe);

	if (fd >= 0)
		close(fd);
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
		bthost_set_adv_enable(bthost, 0x01);
	else
		bthost_write_scan_enable(bthost, 0x03);
}

static void enable_success_cb(bt_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_STATE_ON) {
		setup_powered_emulated_remote();
		data->cb_count--;
		check_cb_count();
	}
}

static void disable_success_cb(bt_state_t state)
{
	struct test_data *data = tester_get_data();

	if (state == BT_STATE_OFF) {
		data->cb_count--;
		check_cb_count();
	}
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

	status = data->if_bluetooth->get_remote_device_property(&remote_addr, prop.type);
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

static void check_count_properties_cb(bt_status_t status, int num_properties,
						bt_property_t *properties)
{
	int i;

	for (i = 0; i < num_properties; i++)
		check_expected_property(properties[i]);
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

static bt_bdaddr_t enable_done_bdaddr_val = { {0x00} };
static const char enable_done_bdname_val[] = "BlueZ for Android";
static bt_uuid_t enable_done_uuids_val = {
	.uu = { 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
					0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb},
};
static bt_device_type_t enable_done_tod_val = BT_DEVICE_DEVTYPE_DUAL;
static bt_scan_mode_t enable_done_scanmode_val = BT_SCAN_MODE_NONE;
static uint32_t enable_done_disctimeout_val = 120;

static struct priority_property enable_done_props[] = {
	{
	.prop.type = BT_PROPERTY_BDADDR,
	.prop.len = sizeof(enable_done_bdaddr_val),
	.prop.val = &enable_done_bdaddr_val,
	.prio = 1,
	},
	{
	.prop.type = BT_PROPERTY_BDNAME,
	.prop.len = sizeof(enable_done_bdname_val) - 1,
	.prop.val = &enable_done_bdname_val,
	.prio = 2,
	},
	{
	.prop.type = BT_PROPERTY_UUIDS,
	.prop.len = sizeof(enable_done_uuids_val),
	.prop.val = &enable_done_uuids_val,
	.prio = 2,
	},
	{
	.prop.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.prop.len = sizeof(uint32_t),
	.prop.val = NULL,
	.prio = 2,
	},
	{
	.prop.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.prop.len = sizeof(enable_done_tod_val),
	.prop.val = &enable_done_tod_val,
	.prio = 2,
	},
	{
	.prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.prop.len = sizeof(enable_done_scanmode_val),
	.prop.val = &enable_done_scanmode_val,
	.prio = 2,
	},
	{
	.prop.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.prop.len = 0,
	.prop.val = NULL,
	.prio = 2,
	},
	{
	.prop.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.prop.len = sizeof(enable_done_disctimeout_val),
	.prop.val = &enable_done_disctimeout_val,
	.prio = 2,
	},
};

static const struct generic_data bluetooth_enable_success_test = {
	.expected_hal_cb.adapter_state_changed_cb = enable_success_cb,
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_cb_count = 1,
	.expected_properties_num = 8,
	.expected_properties = enable_done_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const struct generic_data bluetooth_enable_success2_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_adapter_status = BT_STATUS_SUCCESS,
	.expected_properties_num = 8,
	.expected_properties = enable_done_props,
};

static const struct generic_data bluetooth_disable_success_test = {
	.expected_hal_cb.adapter_state_changed_cb = disable_success_cb,
	.expected_cb_count = 1,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static char test_set_bdname[] = "test_bdname_set";

static struct priority_property setprop_bdname_props[] = {
	{
	.prop.type = BT_PROPERTY_BDNAME,
	.prop.val = test_set_bdname,
	.prop.len = sizeof(test_set_bdname) - 1,
	.prio = 0,
	},
};

static const struct generic_data bluetooth_setprop_bdname_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = setprop_bdname_props,
};

static bt_scan_mode_t test_setprop_scanmode_val =
					BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;

static struct priority_property setprop_scanmode_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.prop.val = &test_setprop_scanmode_val,
	.prop.len = sizeof(bt_scan_mode_t),
	},
};

static const struct generic_data bluetooth_setprop_scanmode_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = setprop_scanmode_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static uint32_t test_setprop_disctimeout_val = 120;

static struct priority_property setprop_disctimeout_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.prop.val = &test_setprop_disctimeout_val,
	.prop.len = sizeof(test_setprop_disctimeout_val),
	},
};

static const struct generic_data bluetooth_setprop_disctimeout_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = setprop_disctimeout_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_bdaddr_t test_getprop_bdaddr_val = { {0x00} };

static struct priority_property getprop_bdaddr_props[] = {
	{
	.prop.type = BT_PROPERTY_BDADDR,
	.prop.val = &test_getprop_bdaddr_val,
	.prop.len = sizeof(test_getprop_bdaddr_val),
	},
};

static const struct generic_data bluetooth_getprop_bdaddr_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = getprop_bdaddr_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static const char test_bdname[] = "test_bdname_setget";

static struct priority_property getprop_bdname_props[] = {
	{
	.prop.type = BT_PROPERTY_BDNAME,
	.prop.val = &test_bdname,
	.prop.len = sizeof(test_bdname) - 1,
	},
};

static const struct generic_data bluetooth_getprop_bdname_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = getprop_bdname_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static unsigned char setprop_uuids[] = { 0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00,
			0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00 };

static struct priority_property setprop_uuid_prop[] = {
	{
	.prop.type = BT_PROPERTY_UUIDS,
	.prop.val = &setprop_uuids,
	.prop.len = sizeof(setprop_uuids),
	},
};

static const struct generic_data bluetooth_setprop_uuid_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
};

static uint32_t setprop_class_of_device = 0;

static struct priority_property setprop_cod_props[] = {
	{
	.prop.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.prop.val = &setprop_class_of_device,
	.prop.len = sizeof(setprop_class_of_device),
	},
};

static const struct generic_data bluetooth_setprop_cod_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_device_type_t setprop_type_of_device = BT_DEVICE_DEVTYPE_DUAL;

static struct priority_property setprop_tod_props[] = {
	{
	.prop.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.prop.val = &setprop_type_of_device,
	.prop.len = sizeof(setprop_type_of_device),
	},
};

static const struct generic_data bluetooth_setprop_tod_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
};

static int32_t setprop_remote_rssi = 0;

static struct priority_property setprop_remote_rssi_props[] = {
	{
	.prop.type = BT_PROPERTY_REMOTE_RSSI,
	.prop.val = &setprop_remote_rssi,
	.prop.len = sizeof(setprop_remote_rssi),
	},
};

static const struct generic_data bluetooth_setprop_remote_rssi_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_service_record_t setprop_remote_service = {
	.uuid = { {0x00} },
	.channel = 12,
	.name = "bt_name",
};

static struct priority_property setprop_service_record_props[] = {
	{
	.prop.type = BT_PROPERTY_SERVICE_RECORD,
	.prop.val = &setprop_remote_service,
	.prop.len = sizeof(setprop_remote_service),
	},
};

static const struct generic_data
			bluetooth_setprop_service_record_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_bdaddr_t setprop_bdaddr = {
	.address = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
};

static struct priority_property setprop_bdaddr_props[] = {
	{
	.prop.type = BT_PROPERTY_BDADDR,
	.prop.val = &setprop_bdaddr,
	.prop.len = sizeof(setprop_bdaddr),
	},
};

static const struct generic_data bluetooth_setprop_bdaddr_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
};

static bt_scan_mode_t setprop_scanmode_connectable = BT_SCAN_MODE_CONNECTABLE;

static struct priority_property setprop_scanmode_connectable_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.prop.val = &setprop_scanmode_connectable,
	.prop.len = sizeof(setprop_scanmode_connectable),
	},
};

static const struct generic_data
			bluetooth_setprop_scanmode_connectable_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = setprop_scanmode_connectable_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_bdaddr_t setprop_bonded_devices = {
	.address = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 },
};

static struct priority_property setprop_bonded_devices_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.prop.val = &setprop_bonded_devices,
	.prop.len = sizeof(setprop_bonded_devices),
	},
};

static const struct generic_data
			bluetooth_setprop_bonded_devices_invalid_test = {
	.expected_adapter_status = BT_STATUS_FAIL,
};

static uint32_t getprop_cod = 0x00020c;

static struct priority_property getprop_cod_props[] = {
	{
	.prop.type = BT_PROPERTY_CLASS_OF_DEVICE,
	.prop.val = &getprop_cod,
	.prop.len = sizeof(getprop_cod),
	},
};

static const struct generic_data bluetooth_getprop_cod_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = getprop_cod_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_device_type_t getprop_tod = BT_DEVICE_DEVTYPE_DUAL;

static struct priority_property getprop_tod_props[] = {
	{
	.prop.type = BT_PROPERTY_TYPE_OF_DEVICE,
	.prop.val = &getprop_tod,
	.prop.len = sizeof(getprop_tod),
	},
};

static const struct generic_data bluetooth_getprop_tod_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = getprop_tod_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_scan_mode_t getprop_scanmode = BT_SCAN_MODE_NONE;

static struct priority_property getprop_scanmode_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.prop.val = &getprop_scanmode,
	.prop.len = sizeof(getprop_scanmode),
	},
};

static const struct generic_data bluetooth_getprop_scanmode_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = getprop_scanmode_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static uint32_t getprop_disctimeout_val = 120;

static struct priority_property getprop_disctimeout_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_DISCOVERY_TIMEOUT,
	.prop.val = &getprop_disctimeout_val,
	.prop.len = sizeof(getprop_disctimeout_val),
	},
};

static const struct generic_data bluetooth_getprop_disctimeout_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = getprop_disctimeout_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_uuid_t getprop_uuids = {
	.uu = { 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00,
					0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB },
};

static struct priority_property getprop_uuids_props[] = {
	{
	.prop.type = BT_PROPERTY_UUIDS,
	.prop.val = &getprop_uuids,
	.prop.len = sizeof(getprop_uuids),
	},
};

static const struct generic_data bluetooth_getprop_uuids_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = getprop_uuids_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static struct priority_property getprop_bondeddev_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_BONDED_DEVICES,
	.prop.val = NULL,
	.prop.len = 0,
	},
};

static const struct generic_data bluetooth_getprop_bondeddev_success_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = getprop_bondeddev_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

static bt_scan_mode_t setprop_scanmode_none = BT_SCAN_MODE_NONE;

static struct priority_property setprop_scanmode_none_props[] = {
	{
	.prop.type = BT_PROPERTY_ADAPTER_SCAN_MODE,
	.prop.val = &setprop_scanmode_none,
	.prop.len = sizeof(setprop_scanmode_none),
	},
};

static const struct generic_data
			bluetooth_setprop_scanmode_none_success2_test = {
	.expected_hal_cb.adapter_properties_cb = check_count_properties_cb,
	.expected_properties_num = 1,
	.expected_properties = setprop_scanmode_none_props,
	.expected_adapter_status = BT_STATUS_SUCCESS,
};

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

static bool setup(struct test_data *data)
{
	const hw_module_t *module;
	hw_device_t *device;
	int signal_fd[2];
	char buf[1024];
	pid_t pid;
	int len;
	int err;

	if (pipe(signal_fd))
		return false;

	pid = fork();

	if (pid < 0) {
		close(signal_fd[0]);
		close(signal_fd[1]);
		return false;
	}

	if (pid == 0) {
		if (!tester_use_debug())
			fclose(stderr);

		close(signal_fd[0]);
		emulator(signal_fd[1], data->mgmt_index);
		exit(0);
	}

	close(signal_fd[1]);
	data->bluetoothd_pid = pid;

	len = read(signal_fd[0], buf, sizeof(buf));
	if (len <= 0 || strcmp(buf, EMULATOR_SIGNAL)) {
		close(signal_fd[0]);
		return false;
	}

	close(signal_fd[0]);

	err = hw_get_module(BT_HARDWARE_MODULE_ID, &module);
	if (err)
		return false;

	err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
	if (err)
		return false;

	data->device = device;

	data->if_bluetooth = ((bluetooth_device_t *)
					device)->get_bluetooth_interface();
	if (!data->if_bluetooth)
		return false;

	return true;
}

static void setup_base(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	if (!setup(data)) {
		tester_setup_failed();
		return;
	}

	status = data->if_bluetooth->init(&bt_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
		return;
	}

	tester_setup_complete();
}

static void setup_enabled_adapter(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	if (!setup(data)) {
		tester_setup_failed();
		return;
	}

	status = data->if_bluetooth->init(&bt_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
		return;
	}

	status = data->if_bluetooth->enable();
	if (status != BT_STATUS_SUCCESS)
		tester_setup_failed();
}

static void teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (data->if_hid) {
		data->if_hid->cleanup();
		data->if_hid = NULL;
	}

	if (data->if_bluetooth) {
		data->if_bluetooth->cleanup();
		data->if_bluetooth = NULL;
	}

	/* Test result already known, no need to check further */
	data->test_checks_valid = false;

	if (data->expected_properties_list)
		g_slist_free(data->expected_properties_list);

	data->device->close(data->device);

	if (!data->bluetoothd_pid)
		tester_teardown_complete();
}

static void test_dummy(const void *test_data)
{
	tester_test_passed();
}

static void test_enable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t adapter_status;

	uint8_t *bdaddr = (uint8_t *)hciemu_get_master_bdaddr(data->hciemu);

	init_test_conditions(data);

	bdaddr2android((const bdaddr_t *)bdaddr,
					&enable_done_bdaddr_val.address);

	adapter_status = data->if_bluetooth->enable();
	check_expected_status(adapter_status);
}

static void test_enable_done(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t adapter_status;

	uint8_t *bdaddr = (uint8_t *)hciemu_get_master_bdaddr(data->hciemu);

	init_test_conditions(data);

	bdaddr2android((const bdaddr_t *)bdaddr,
					&enable_done_bdaddr_val.address);

	adapter_status = data->if_bluetooth->enable();
	check_expected_status(adapter_status);
}

static void test_disable(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->disable();
	check_expected_status(adapter_status);
}

static void test_setprop_bdname_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_bdname_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_scanmode_succes(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_scanmode_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_disctimeout_succes(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_disctimeout_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_getprop_bdaddr_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t prop = setprop_bdaddr_props[0].prop;
	bt_status_t adapter_status;
	uint8_t *bdaddr = (uint8_t *)hciemu_get_master_bdaddr(data->hciemu);

	init_test_conditions(data);

	bdaddr2android((const bdaddr_t *)bdaddr,
					&test_getprop_bdaddr_val.address);

	adapter_status = data->if_bluetooth->get_adapter_property(prop.type);
	check_expected_status(adapter_status);
}

static void test_getprop_bdname_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(getprop_bdname_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	if (adapter_status != BT_STATUS_SUCCESS) {
		tester_test_failed();
		return;
	}

	adapter_status = data->if_bluetooth->get_adapter_property((*prop).type);
	check_expected_status(adapter_status);
}
static void test_setprop_uuid_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_uuid_prop[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_cod_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_cod_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_tod_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct generic_data *test = data->test_data;
	const bt_property_t *prop = &test->set_property;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_rssi_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_remote_rssi_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_service_record_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_service_record_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_bdaddr_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_bdaddr_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_scanmode_connectable_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop =
				&(setprop_scanmode_connectable_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_setprop_bonded_devices_invalid(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_bonded_devices_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_getprop_cod_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t prop = setprop_cod_props[0].prop;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->get_adapter_property(prop.type);
	check_expected_status(adapter_status);
}

static void test_getprop_tod_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t prop = setprop_tod_props[0].prop;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->get_adapter_property(prop.type);
	check_expected_status(adapter_status);
}

static void test_getprop_scanmode_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t prop = setprop_scanmode_props[0].prop;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->get_adapter_property(prop.type);
	check_expected_status(adapter_status);
}

static void test_getprop_disctimeout_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t prop = setprop_disctimeout_props[0].prop;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->get_adapter_property(prop.type);
	check_expected_status(adapter_status);
}

static void test_getprop_uuids_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t prop = getprop_uuids_props[0].prop;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->get_adapter_property(prop.type);
	check_expected_status(adapter_status);
}

static void test_getprop_bondeddev_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t prop = getprop_bondeddev_props[0].prop;
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->get_adapter_property(prop.type);
	check_expected_status(adapter_status);
}

static void test_setprop_scanmode_none_done(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const bt_property_t *prop = &(setprop_scanmode_none_props[0].prop);
	bt_status_t adapter_status;

	init_test_conditions(data);

	adapter_status = data->if_bluetooth->set_adapter_property(prop);
	check_expected_status(adapter_status);
}

static void test_discovery_start_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	init_test_conditions(data);

	status = data->if_bluetooth->start_discovery();
	check_expected_status(status);
}

static void test_discovery_stop_done(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;

	init_test_conditions(data);

	status = data->if_bluetooth->cancel_discovery();
	check_expected_status(status);
}

static void test_discovery_stop_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_discovery_start_done(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_discovery_device_found(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprops_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_bdname_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_uuids_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_cod_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_tod_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_rssi_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_timestamp_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_bdaddr_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_servrec_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_scanmode_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_bondeddev_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_disctimeout_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_verinfo_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_getprop_fname_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_fname_success(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_bdname_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_uuids_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_cod_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_tod_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_rssi_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_timestamp_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_bdaddr_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_servrec_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_scanmode_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_bondeddev_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void test_dev_setprop_disctimeout_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();

	init_test_conditions(data);

	data->if_bluetooth->start_discovery();
}

static void bond_device_auth_fail_callback(uint16_t index, uint16_t length,
							const void *param,
							void *user_data)
{
	const struct mgmt_ev_auth_failed *ev = param;

	check_expected_status(ev->status);
}

static void test_bond_create_pin_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	static uint8_t pair_device_pin[] = { 0x30, 0x30, 0x30, 0x30 };
	const void *pin = pair_device_pin;
	uint8_t pin_len = 4;

	init_test_conditions(data);

	bthost_set_pin_code(bthost, pin, pin_len);

	data->if_bluetooth->start_discovery();
}

static void test_bond_create_pin_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	static uint8_t pair_device_pin[] = { 0x30, 0x30, 0x30, 0x30 };
	const void *pin = pair_device_pin;
	uint8_t pin_len = 4;

	init_test_conditions(data);

	mgmt_register(data->mgmt, MGMT_EV_AUTH_FAILED, data->mgmt_index,
					bond_device_auth_fail_callback, data,
					NULL);

	bthost_set_pin_code(bthost, pin, pin_len);

	data->if_bluetooth->start_discovery();
}

static void test_bond_create_ssp_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	init_test_conditions(data);

	bthost_write_ssp_mode(bthost, 0x01);

	data->if_bluetooth->start_discovery();
}

static void test_bond_create_ssp_fail(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	init_test_conditions(data);

	mgmt_register(data->mgmt, MGMT_EV_AUTH_FAILED, data->mgmt_index,
					bond_device_auth_fail_callback, data,
					NULL);

	bthost_write_ssp_mode(bthost, 0x01);

	data->if_bluetooth->start_discovery();
}

static void test_bond_create_no_disc_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	uint8_t *bdaddr = (uint8_t *)hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t remote_addr;
	bt_status_t status;

	init_test_conditions(data);

	bdaddr2android((const bdaddr_t *)bdaddr, &remote_addr.address);

	bthost_write_ssp_mode(bthost, 0x01);

	status = data->if_bluetooth->create_bond(&remote_addr);
	check_expected_status(status);
}

static void test_bond_create_bad_addr_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_bdaddr_t bad_addr = {
		.address = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12 }
	};

	init_test_conditions(data);

	mgmt_register(data->mgmt, MGMT_EV_CONNECT_FAILED, data->mgmt_index,
					bond_device_auth_fail_callback, data,
					NULL);

	data->if_bluetooth->create_bond(&bad_addr);
}

static void test_bond_cancel_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	init_test_conditions(data);

	bthost_write_ssp_mode(bthost, 0x01);

	data->if_bluetooth->start_discovery();
}

static void test_bond_remove_success(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	init_test_conditions(data);

	bthost_write_ssp_mode(bthost, 0x01);

	data->if_bluetooth->start_discovery();
}

/* Test Socket HAL */

static gboolean adapter_socket_state_changed(gpointer user_data)
{
	struct bt_cb_data *cb_data = user_data;

	switch (cb_data->state) {
	case BT_STATE_ON:
		setup_powered_emulated_remote();
		break;
	case BT_STATE_OFF:
		tester_setup_failed();
		break;
	default:
		break;
	}

	g_free(cb_data);

	g_atomic_int_dec_and_test(&scheduled_cbacks_num);
	return FALSE;
}

static void adapter_socket_state_changed_cb(bt_state_t state)
{
	struct bt_cb_data *cb_data = g_new0(struct bt_cb_data, 1);

	cb_data->state = state;

	g_atomic_int_inc(&scheduled_cbacks_num);
	g_idle_add(adapter_socket_state_changed, cb_data);
}

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

static bt_callbacks_t bt_socket_callbacks = {
	.size = sizeof(bt_callbacks),
	.adapter_state_changed_cb = adapter_socket_state_changed_cb,
	.adapter_properties_cb = NULL,
	.remote_device_properties_cb = NULL,
	.device_found_cb = NULL,
	.discovery_state_changed_cb = NULL,
	.pin_request_cb = NULL,
	.ssp_request_cb = NULL,
	.bond_state_changed_cb = NULL,
	.acl_state_changed_cb = NULL,
	.thread_evt_cb = NULL,
	.dut_mode_recv_cb = NULL,
	.le_test_mode_cb = NULL
};

static void setup_socket_interface(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;
	const void *sock;

	if (!setup(data)) {
		tester_setup_failed();
		return;
	}

	status = data->if_bluetooth->init(&bt_socket_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
		return;
	}

	sock = data->if_bluetooth->get_profile_interface(BT_PROFILE_SOCKETS_ID);
	if (!sock) {
		tester_setup_failed();
		return;
	}

	data->if_sock = sock;

	tester_setup_complete();
}

static void setup_socket_interface_enabled(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;
	const void *sock;

	if (!setup(data)) {
		tester_setup_failed();
		return;
	}

	status = data->if_bluetooth->init(&bt_socket_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		tester_setup_failed();
		return;
	}

	sock = data->if_bluetooth->get_profile_interface(BT_PROFILE_SOCKETS_ID);
	if (!sock) {
		tester_setup_failed();
		return;
	}

	data->if_sock = sock;

	status = data->if_bluetooth->enable();
	if (status != BT_STATUS_SUCCESS)
		tester_setup_failed();
}

static void test_generic_listen(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	bt_status_t status;
	int sock_fd = -1;

	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_test_failed();
		return;
	}

	if (status == BT_STATUS_SUCCESS && test->test_channel) {
		int channel, len;

		len = read(sock_fd, &channel, sizeof(channel));
		if (len != sizeof(channel) || channel != test->channel) {
			tester_test_failed();
			goto clean;
		}

		tester_print("read correct channel: %d", channel);
	}

	tester_test_passed();

clean:
	if (sock_fd >= 0)
		close(sock_fd);
}

static void test_listen_close(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	bt_status_t status;
	int sock_fd = -1;

	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_warn("sock->listen() failed");
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_warn("sock_fd %d is not valid", sock_fd);
		tester_test_failed();
		return;
	}

	tester_print("Got valid sock_fd: %d", sock_fd);

	/* Now close sock_fd */
	close(sock_fd);
	sock_fd = -1;

	/* Try to listen again */
	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_warn("sock->listen() failed");
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_warn("sock_fd %d is not valid", sock_fd);
		tester_test_failed();
		return;
	}

	tester_print("Got valid sock_fd: %d", sock_fd);

	tester_test_passed();

clean:
	if (sock_fd >= 0)
		close(sock_fd);
}

static void test_listen_listen(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	bt_status_t status;
	int sock_fd1 = -1, sock_fd2 = -1;

	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd1, test->flags);
	if (status != BT_STATUS_SUCCESS) {
		tester_warn("sock->listen() failed");
		tester_test_failed();
		goto clean;
	}

	status = data->if_sock->listen(test->sock_type,
					test->service_name, test->service_uuid,
					test->channel, &sock_fd2, test->flags);
	if (status != test->expected_status) {
		tester_warn("sock->listen() failed, status %d", status);
		tester_test_failed();
		goto clean;
	}

	tester_print("status after second listen(): %d", status);

	tester_test_passed();

clean:
	if (sock_fd1 >= 0)
		close(sock_fd1);

	if (sock_fd2 >= 0)
		close(sock_fd2);
}

static void test_generic_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	bt_status_t status;
	int sock_fd = -1;

	status = data->if_sock->connect(test->bdaddr, test->sock_type,
					test->service_uuid, test->channel,
					&sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_test_failed();
		return;
	}

	tester_test_passed();

clean:
	if (sock_fd >= 0)
		close(sock_fd);
}

static gboolean socket_chan_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	int sock_fd = g_io_channel_unix_get_fd(io);
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	int channel, len;

	tester_print("%s", __func__);

	if (cond & G_IO_HUP) {
		tester_warn("Socket %d hang up", sock_fd);
		goto failed;
	}

	if (cond & (G_IO_ERR | G_IO_NVAL)) {
		tester_warn("Socket error: sock %d cond %d", sock_fd, cond);
		goto failed;
	}

	if (test->test_channel) {
		len = read(sock_fd, &channel, sizeof(channel));
		if (len != sizeof(channel) || channel != test->channel)
			goto failed;

		tester_print("read correct channel: %d", channel);
		tester_test_passed();
		return FALSE;
	}

failed:
	tester_test_failed();
	return FALSE;
}

static void test_socket_real_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct socket_data *test = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	const uint8_t *client_bdaddr;
	bt_bdaddr_t emu_bdaddr;
	bt_status_t status;
	int sock_fd = -1;

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (!client_bdaddr) {
		tester_warn("No client bdaddr");
		tester_test_failed();
		return;
	}

	bdaddr2android((bdaddr_t *) client_bdaddr, &emu_bdaddr);

	bthost_add_l2cap_server(bthost, 0x0003, NULL, NULL);

	status = data->if_sock->connect(&emu_bdaddr, test->sock_type,
					test->service_uuid, test->channel,
					&sock_fd, test->flags);
	if (status != test->expected_status) {
		tester_test_failed();
		goto clean;
	}

	/* Check that file descriptor is valid */
	if (status == BT_STATUS_SUCCESS && fcntl(sock_fd, F_GETFD) < 0) {
		tester_test_failed();
		return;
	}

	tester_print("status %d sock_fd %d", status, sock_fd);

	if (status == BT_STATUS_SUCCESS) {
		GIOChannel *io;

		io = g_io_channel_unix_new(sock_fd);
		g_io_channel_set_close_on_unref(io, TRUE);

		g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				socket_chan_cb, NULL);

		g_io_channel_unref(io);
	}

	return;

clean:
	if (sock_fd >= 0)
		close(sock_fd);
}

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

static bool setup_hidhost(const void *test_data)
{
	struct test_data *data = tester_get_data();
	bt_status_t status;
	const void *hid;

	if (!setup(data))
		return false;

	status = data->if_bluetooth->init(&bt_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_bluetooth = NULL;
		return false;
	}

	hid = data->if_bluetooth->get_profile_interface(BT_PROFILE_HIDHOST_ID);
	if (!hid)
		return false;

	data->if_hid = hid;

	status = data->if_hid->init(&bthh_callbacks);
	if (status != BT_STATUS_SUCCESS) {
		data->if_hid = NULL;
		return false;
	}

	return true;
}

static void setup_hidhost_interface(const void *test_data)
{
	if (setup_hidhost(test_data))
		tester_setup_complete();
	else
		tester_setup_failed();
}

#define HID_GET_REPORT_PROTOCOL		0x60
#define HID_GET_BOOT_PROTOCOL		0x61
#define HID_SET_REPORT_PROTOCOL		0x70
#define HID_SET_BOOT_PROTOCOL		0x71

#define HID_SET_INPUT_REPORT		0x51
#define HID_SET_OUTPUT_REPORT		0x52
#define HID_SET_FEATURE_REPORT		0x53

#define HID_SEND_DATA			0xa2

#define HID_GET_INPUT_REPORT		0x49
#define HID_GET_OUTPUT_REPORT		0x4a
#define HID_GET_FEATURE_REPORT		0x4b

static void hid_prepare_reply_protocol_mode(const void *data, uint16_t len)
{
	struct test_data *t_data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(t_data->hciemu);
	uint8_t pdu[2] = { 0, 0 };
	uint16_t pdu_len = 0;

	pdu_len = 2;
	pdu[0] = 0xa0;
	pdu[1] = 0x00;

	bthost_send_cid(bthost, t_data->ctrl_handle, t_data->ctrl_cid,
						(void *)pdu, pdu_len);
}

static void hid_prepare_reply_report(const void *data, uint16_t len)
{
	struct test_data *t_data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(t_data->hciemu);
	uint8_t pdu[3] = { 0, 0, 0 };
	uint16_t pdu_len = 0;

	pdu_len = 3;
	pdu[0] = 0xa2;
	pdu[1] = 0x01;
	pdu[2] = 0x00;

	bthost_send_cid(bthost, t_data->ctrl_handle, t_data->ctrl_cid,
						(void *)pdu, pdu_len);
}

static void hid_intr_cid_hook_cb(const void *data, uint16_t len,
							void *user_data)
{
	uint8_t header = ((uint8_t *) data)[0];

	switch (header) {
	case HID_SEND_DATA:
		tester_test_passed();
		break;
	}
}

static void hid_intr_connect_cb(uint16_t handle, uint16_t cid, void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	data->intr_handle = handle;
	data->intr_cid = cid;

	bthost_add_cid_hook(bthost, handle, cid, hid_intr_cid_hook_cb, NULL);
}

static void hid_ctrl_cid_hook_cb(const void *data, uint16_t len,
							void *user_data)
{
	uint8_t header = ((uint8_t *) data)[0];

	switch (header) {
	case HID_GET_REPORT_PROTOCOL:
	case HID_GET_BOOT_PROTOCOL:
	case HID_SET_REPORT_PROTOCOL:
	case HID_SET_BOOT_PROTOCOL:
		hid_prepare_reply_protocol_mode(data, len);
		break;
	case HID_GET_INPUT_REPORT:
	case HID_GET_OUTPUT_REPORT:
	case HID_GET_FEATURE_REPORT:
		hid_prepare_reply_report(data, len);
		break;
	/*
	 * HID device doesnot reply for this commads, so reaching pdu's
	 * to hid device means assuming test passed
	 */
	case HID_SET_INPUT_REPORT:
	case HID_SET_OUTPUT_REPORT:
	case HID_SET_FEATURE_REPORT:
	case HID_SEND_DATA:
		tester_test_passed();
		break;
	}
}

static void hid_ctrl_connect_cb(uint16_t handle, uint16_t cid, void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	data->ctrl_handle = handle;
	data->ctrl_cid = cid;

	bthost_add_cid_hook(bthost, handle, cid, hid_ctrl_cid_hook_cb, NULL);
}

static const uint8_t did_req_pdu[] = { 0x06, /* PDU id */
			0x00, 0x00, /* Transaction id */
			0x00, 0x0f, /* Req length */
			0x35, 0x03, /* Attributes length */
			0x19, 0x12, 0x00, 0xff, 0xff, 0x35, 0x05, 0x0a, 0x00,
			0x00, 0xff, 0xff, 0x00 }; /* no continuation */

static const uint8_t did_rsp_pdu[] = { 0x07, /* PDU id */
			0x00, 0x00, /* Transaction id */
			0x00, 0x4f, /* Response length */
			0x00, 0x4c, /* Attributes length */
			0x35, 0x4a, 0x35, 0x48, 0x09, 0x00, 0x00, 0x0a, 0x00,
			0x01, 0x00, 0x00, 0x09, 0x00, 0x01, 0x35, 0x03, 0x19,
			0x12, 0x00, 0x09, 0x00, 0x05, 0x35, 0x03, 0x19, 0x10,
			0x02, 0x09, 0x00, 0x09, 0x35, 0x08, 0x35, 0x06, 0x19,
			0x12, 0x00, 0x09, 0x01, 0x03, 0x09, 0x02, 0x00, 0x09,
			0x01, 0x03, 0x09, 0x02, 0x01, 0x09, 0x1d, 0x6b, 0x09,
			0x02, 0x02, 0x09, 0x02, 0x46, 0x09, 0x02, 0x03, 0x09,
			0x05, 0x0e, 0x09, 0x02, 0x04, 0x28, 0x01, 0x09, 0x02,
			0x05, 0x09, 0x00, 0x02,
			0x00 }; /* no continuation */

static const uint8_t hid_rsp_pdu[] = { 0x07, /* PDU id */
			0x00, 0x01, /* Transaction id */
			0x01, 0x71, /* Response length */
			0x01, 0x6E, /* Attributes length */
			0x36, 0x01, 0x6b, 0x36, 0x01, 0x68, 0x09, 0x00, 0x00,
			0x0a, 0x00, 0x01, 0x00, 0x00, 0x09, 0x00, 0x01, 0x35,
			0x03, 0x19, 0x11, 0x24, 0x09, 0x00, 0x04, 0x35, 0x0d,
			0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x11, 0x35,
			0x03, 0x19, 0x00, 0x11, 0x09, 0x00, 0x05, 0x35, 0x03,
			0x19, 0x10, 0x02, 0x09, 0x00, 0x06, 0x35, 0x09, 0x09,
			0x65, 0x6e, 0x09, 0x00, 0x6a, 0x09, 0x01, 0x00, 0x09,
			0x00, 0x09, 0x35, 0x08, 0x35, 0x06, 0x19, 0x11, 0x24,
			0x09, 0x01, 0x00, 0x09, 0x00, 0x0d, 0x35, 0x0f, 0x35,
			0x0d, 0x35, 0x06, 0x19, 0x01, 0x00, 0x09, 0x00, 0x13,
			0x35, 0x03, 0x19, 0x00, 0x11, 0x09, 0x01, 0x00, 0x25,
			0x1e, 0x4c, 0x6f, 0x67, 0x69, 0x74, 0x65, 0x63, 0x68,
			0x20, 0x42, 0x6c, 0x75, 0x65, 0x74, 0x6f, 0x6f, 0x74,
			0x68, 0x20, 0x4d, 0x6f, 0x75, 0x73, 0x65, 0x20, 0x4d,
			0x35, 0x35, 0x35, 0x62, 0x09, 0x01, 0x01, 0x25, 0x0f,
			0x42, 0x6c, 0x75, 0x65, 0x74, 0x6f, 0x6f, 0x74, 0x68,
			0x20, 0x4d, 0x6f, 0x75, 0x73, 0x65, 0x09, 0x01, 0x02,
			0x25, 0x08, 0x4c, 0x6f, 0x67, 0x69, 0x74, 0x65, 0x63,
			0x68, 0x09, 0x02, 0x00, 0x09, 0x01, 0x00, 0x09, 0x02,
			0x01, 0x09, 0x01, 0x11, 0x09, 0x02, 0x02, 0x08, 0x80,
			0x09, 0x02, 0x03, 0x08, 0x21, 0x09, 0x02, 0x04, 0x28,
			0x01, 0x09, 0x02, 0x05, 0x28, 0x01, 0x09, 0x02, 0x06,
			0x35, 0x74, 0x35, 0x72, 0x08, 0x22, 0x25, 0x6e, 0x05,
			0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x02, 0x09, 0x01,
			0xa1, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x08, 0x15,
			0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02,
			0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x16, 0x01, 0xf8,
			0x26, 0xff, 0x07, 0x75, 0x0c, 0x95, 0x02, 0x81, 0x06,
			0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08, 0x95,
			0x01, 0x81, 0x06, 0x05, 0x0c, 0x0a, 0x38, 0x02, 0x81,
			0x06, 0x05, 0x09, 0x19, 0x09, 0x29, 0x10, 0x15, 0x00,
			0x25, 0x01, 0x95, 0x08, 0x75, 0x01, 0x81, 0x02, 0xc0,
			0xc0, 0x06, 0x00, 0xff, 0x09, 0x01, 0xa1, 0x01, 0x85,
			0x10, 0x75, 0x08, 0x95, 0x06, 0x15, 0x00, 0x26, 0xff,
			0x00, 0x09, 0x01, 0x81, 0x00, 0x09, 0x01, 0x91, 0x00,
			0xc0, 0x09, 0x02, 0x07, 0x35, 0x08, 0x35, 0x06, 0x09,
			0x04, 0x09, 0x09, 0x01, 0x00, 0x09, 0x02, 0x08, 0x28,
			0x00, 0x09, 0x02, 0x09, 0x28, 0x01, 0x09, 0x02, 0x0a,
			0x28, 0x01, 0x09, 0x02, 0x0b, 0x09, 0x01, 0x00, 0x09,
			0x02, 0x0c, 0x09, 0x0c, 0x80, 0x09, 0x02, 0x0d, 0x28,
			0x00, 0x09, 0x02, 0x0e, 0x28, 0x01,
			0x00 }; /* no continuation */

static void hid_sdp_cid_hook_cb(const void *data, uint16_t len, void *user_data)
{
	struct test_data *t_data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(t_data->hciemu);

	if (!memcmp(did_req_pdu, data, len)) {
		bthost_send_cid(bthost, t_data->sdp_handle, t_data->sdp_cid,
					did_rsp_pdu, sizeof(did_rsp_pdu));
		return;
	}

	bthost_send_cid(bthost, t_data->sdp_handle, t_data->sdp_cid,
					hid_rsp_pdu, sizeof(hid_rsp_pdu));
}

static void hid_sdp_search_cb(uint16_t handle, uint16_t cid, void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	data->sdp_handle = handle;
	data->sdp_cid = cid;

	bthost_add_cid_hook(bthost, handle, cid, hid_sdp_cid_hook_cb, NULL);
}

static void emu_powered_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *hid_addr = hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t bdaddr;
	bt_status_t bt_status;

	switch (opcode) {
	case BT_HCI_CMD_WRITE_SCAN_ENABLE:
	case BT_HCI_CMD_LE_SET_ADV_ENABLE:
		break;
	default:
		return;
	}

	if (status) {
		tester_setup_failed();
		return;
	}

	data->cb_count = 0;
	bdaddr2android((const bdaddr_t *) hid_addr, &bdaddr);
	bt_status = data->if_hid->connect(&bdaddr);
	if (bt_status != BT_STATUS_SUCCESS)
		tester_setup_failed();
}

static void setup_hidhost_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	if (!setup_hidhost(test_data)) {
		tester_setup_failed();
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);

	/* Emulate SDP (PSM = 1) */
	bthost_add_l2cap_server(bthost, 1, hid_sdp_search_cb, NULL);
	/* Emulate Control Channel (PSM = 17) */
	bthost_add_l2cap_server(bthost, 17, hid_ctrl_connect_cb, NULL);
	/* Emulate Interrupt Channel (PSM = 19) */
	bthost_add_l2cap_server(bthost, 19, hid_intr_connect_cb, NULL);

	bthost_set_cmd_complete_cb(bthost, emu_powered_complete, data);
	bthost_write_scan_enable(bthost, 0x03);
}

static void hid_discon_cb(bt_bdaddr_t *bd_addr, bthh_connection_state_t state)
{
	if (state == BTHH_CONN_STATE_DISCONNECTED)
		tester_test_passed();
}

static const struct hidhost_generic_data hidhost_test_disconnect = {
	.expected_hal_cb.connection_state_cb = hid_discon_cb,
};

static void test_hidhost_disconnect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *hid_addr = hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t bdaddr;
	bt_status_t bt_status;

	data->cb_count = 0;
	bdaddr2android((const bdaddr_t *) hid_addr, &bdaddr);
	bt_status = data->if_hid->disconnect(&bdaddr);
	if (bt_status != BT_STATUS_SUCCESS)
		tester_test_failed();
}

static void test_hidhost_virtual_unplug(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *hid_addr = hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t bdaddr;
	bt_status_t bt_status;

	data->cb_count = 0;
	bdaddr2android((const bdaddr_t *) hid_addr, &bdaddr);
	bt_status = data->if_hid->virtual_unplug(&bdaddr);
	if (bt_status != BT_STATUS_SUCCESS)
		tester_test_failed();
}

static void hid_protocol_mode_cb(bt_bdaddr_t *bd_addr, bthh_status_t status,
						bthh_protocol_mode_t mode)
{
	struct test_data *data = tester_get_data();
	const struct hidhost_generic_data *test = data->test_data;

	if (data->cb_count == test->expected_cb_count &&
					status == test->expected_status &&
					mode == test->expected_protocol_mode)
		tester_test_passed();
	else
		tester_test_failed();
}

static const struct hidhost_generic_data hidhost_test_get_protocol = {
	.expected_hal_cb.protocol_mode_cb = hid_protocol_mode_cb,
	.expected_cb_count = 1,
	.expected_protocol_mode = BTHH_BOOT_MODE,
	.expected_status = BTHH_OK,
};

static void test_hidhost_get_protocol(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *hid_addr = hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t bdaddr;
	bt_status_t bt_status;

	data->cb_count = 0;
	bdaddr2android((const bdaddr_t *) hid_addr, &bdaddr);
	bt_status = data->if_hid->get_protocol(&bdaddr, BTHH_REPORT_MODE);
	if (bt_status != BT_STATUS_SUCCESS)
		tester_test_failed();
}

static void test_hidhost_set_protocol(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *hid_addr = hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t bdaddr;
	bt_status_t bt_status;

	data->cb_count = 0;
	bdaddr2android((const bdaddr_t *) hid_addr, &bdaddr);
	bt_status = data->if_hid->set_protocol(&bdaddr, BTHH_REPORT_MODE);
	if (bt_status != BT_STATUS_SUCCESS)
		tester_test_failed();
}

static void test_hidhost_set_report(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *hid_addr = hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t bdaddr;
	bt_status_t bt_status;
	char *buf = "010101";

	data->cb_count = 0;
	bdaddr2android((const bdaddr_t *) hid_addr, &bdaddr);
	bt_status = data->if_hid->set_report(&bdaddr, BTHH_INPUT_REPORT, buf);
	if (bt_status != BT_STATUS_SUCCESS)
		tester_test_failed();
}

static void test_hidhost_send_data(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *hid_addr = hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t bdaddr;
	bt_status_t bt_status;
	char *buf = "fe0201";

	data->cb_count = 0;
	bdaddr2android((const bdaddr_t *) hid_addr, &bdaddr);
	bt_status = data->if_hid->send_data(&bdaddr, buf);
	if (bt_status != BT_STATUS_SUCCESS)
		tester_test_failed();
}

static void hid_get_report_cb(bt_bdaddr_t *bd_addr, bthh_status_t status,
						uint8_t *report, int size)
{
	struct test_data *data = tester_get_data();
	const struct hidhost_generic_data *test = data->test_data;

	if (data->cb_count == test->expected_cb_count &&
					status == test->expected_status &&
					size == test->expected_report_size)
		tester_test_passed();
	else
		tester_test_failed();
}

static const struct hidhost_generic_data hidhost_test_get_report = {
	.expected_hal_cb.get_report_cb = hid_get_report_cb,
	.expected_cb_count = 1,
	.expected_status = BTHH_OK,
	.expected_report_size = 2,
};

static void test_hidhost_get_report(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *hid_addr = hciemu_get_client_bdaddr(data->hciemu);
	bt_bdaddr_t bdaddr;
	bt_status_t bt_status;

	data->cb_count = 0;
	bdaddr2android((const bdaddr_t *) hid_addr, &bdaddr);
	bt_status = data->if_hid->get_report(&bdaddr, BTHH_INPUT_REPORT, 1, 20);
	if (bt_status != BT_STATUS_SUCCESS)
		tester_test_failed();
}

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

	test_bredrle("Bluetooth Init", NULL, setup_base, test_dummy, teardown);

	test_bredrle("Bluetooth Enable - Success",
						&bluetooth_enable_success_test,
						setup_base, test_enable,
						teardown);

	test_bredrle("Bluetooth Enable - Success 2",
						&bluetooth_enable_success2_test,
						setup_enabled_adapter,
						test_enable_done, teardown);

	test_bredrle("Bluetooth Disable - Success",
						&bluetooth_disable_success_test,
						setup_enabled_adapter,
						test_disable, teardown);

	test_bredrle("Bluetooth Set BDNAME - Success",
					&bluetooth_setprop_bdname_success_test,
					setup_enabled_adapter,
					test_setprop_bdname_success, teardown);

	test_bredrle("Bluetooth Set SCAN_MODE - Success",
				&bluetooth_setprop_scanmode_success_test,
				setup_enabled_adapter,
				test_setprop_scanmode_succes, teardown);

	test_bredrle("Bluetooth Set DISCOVERY_TIMEOUT - Success",
				&bluetooth_setprop_disctimeout_success_test,
				setup_enabled_adapter,
				test_setprop_disctimeout_succes, teardown);

	test_bredrle("Bluetooth Get BDADDR - Success",
					&bluetooth_getprop_bdaddr_success_test,
					setup_enabled_adapter,
					test_getprop_bdaddr_success, teardown);

	test_bredrle("Bluetooth Get BDNAME - Success",
					&bluetooth_getprop_bdname_success_test,
					setup_enabled_adapter,
					test_getprop_bdname_success, teardown);

	test_bredrle("Bluetooth Set UUID - Invalid",
					&bluetooth_setprop_uuid_invalid_test,
					setup_enabled_adapter,
					test_setprop_uuid_invalid, teardown);

	test_bredrle("Bluetooth Set CLASS_OF_DEVICE - Invalid",
					&bluetooth_setprop_cod_invalid_test,
					setup_enabled_adapter,
					test_setprop_cod_invalid, teardown);

	test_bredrle("Bluetooth Set TYPE_OF_DEVICE - Invalid",
					&bluetooth_setprop_tod_invalid_test,
					setup_enabled_adapter,
					test_setprop_tod_invalid, teardown);

	test_bredrle("Bluetooth Set REMOTE_RSSI - Invalid",
				&bluetooth_setprop_remote_rssi_invalid_test,
				setup_enabled_adapter,
				test_setprop_rssi_invalid, teardown);

	test_bredrle("Bluetooth Set SERVICE_RECORD - Invalid",
				&bluetooth_setprop_service_record_invalid_test,
				setup_enabled_adapter,
				test_setprop_service_record_invalid, teardown);

	test_bredrle("Bluetooth Set BDADDR - Invalid",
					&bluetooth_setprop_bdaddr_invalid_test,
					setup_enabled_adapter,
					test_setprop_bdaddr_invalid, teardown);

	test_bredrle("Bluetooth Set SCAN_MODE CONNECTABLE - Success",
			&bluetooth_setprop_scanmode_connectable_success_test,
			setup_enabled_adapter,
			test_setprop_scanmode_connectable_success, teardown);

	test_bredrle("Bluetooth Set BONDED_DEVICES - Invalid",
				&bluetooth_setprop_bonded_devices_invalid_test,
				setup_enabled_adapter,
				test_setprop_bonded_devices_invalid, teardown);

	test_bredrle("Bluetooth Get CLASS_OF_DEVICE - Success",
					&bluetooth_getprop_cod_success_test,
					setup_enabled_adapter,
					test_getprop_cod_success, teardown);

	test_bredrle("Bluetooth Get TYPE_OF_DEVICE - Success",
					&bluetooth_getprop_tod_success_test,
					setup_enabled_adapter,
					test_getprop_tod_success, teardown);

	test_bredrle("Bluetooth Get SCAN_MODE - Success",
				&bluetooth_getprop_scanmode_success_test,
				setup_enabled_adapter,
				test_getprop_scanmode_success, teardown);

	test_bredrle("Bluetooth Get DISCOVERY_TIMEOUT - Success",
				&bluetooth_getprop_disctimeout_success_test,
				setup_enabled_adapter,
				test_getprop_disctimeout_success, teardown);

	test_bredrle("Bluetooth Get UUIDS - Success",
					&bluetooth_getprop_uuids_success_test,
					setup_enabled_adapter,
					test_getprop_uuids_success, teardown);

	test_bredrle("Bluetooth Get BONDED_DEVICES - Success",
				&bluetooth_getprop_bondeddev_success_test,
				setup_enabled_adapter,
				test_getprop_bondeddev_success, teardown);

	test_bredrle("Bluetooth Set SCAN_MODE NONE - Success 2",
				&bluetooth_setprop_scanmode_none_success2_test,
				setup_enabled_adapter,
				test_setprop_scanmode_none_done, teardown);

	test_bredrle("Bluetooth BR/EDR Discovery Start - Success",
				&bluetooth_discovery_start_success_test,
				setup_enabled_adapter,
				test_discovery_start_success, teardown);

	test_bredrle("Bluetooth BR/EDR Discovery Start - Success 2",
				&bluetooth_discovery_start_success2_test,
				setup_enabled_adapter,
				test_discovery_start_done, teardown);

	test_bredrle("Bluetooth BR/EDR Discovery Stop - Success",
				&bluetooth_discovery_stop_success_test,
				setup_enabled_adapter,
				test_discovery_stop_success, teardown);

	test_bredrle("Bluetooth BR/EDR Discovery Stop - Success 2",
				&bluetooth_discovery_stop_success2_test,
				setup_enabled_adapter,
				test_discovery_stop_done, teardown);

	test_bredr("Bluetooth BR/EDR Discovery Device Found",
				&bluetooth_discovery_device_found_test,
				setup_enabled_adapter,
				test_discovery_device_found, teardown);

	test_bredr("Bluetooth Device Get Props - Success",
					&bt_dev_getprops_success_test,
					setup_enabled_adapter,
					test_dev_getprops_success, teardown);

	test_bredr("Bluetooth Device Get BDNAME - Success",
				&bt_dev_getprop_bdname_success_test,
				setup_enabled_adapter,
				test_dev_getprop_bdname_success, teardown);

	test_bredr("Bluetooth Device Get UUIDS - Success",
				&bt_dev_getprop_uuids_success_test,
				setup_enabled_adapter,
				test_dev_getprop_uuids_success, teardown);

	test_bredr("Bluetooth Device Get COD - Success",
					&bt_dev_getprop_cod_success_test,
					setup_enabled_adapter,
					test_dev_getprop_cod_success, teardown);

	test_bredr("Bluetooth Device Get TOD - Success",
					&bt_dev_getprop_tod_success_test,
					setup_enabled_adapter,
					test_dev_getprop_tod_success, teardown);

	test_bredr("Bluetooth Device Get RSSI - Success",
				&bt_dev_getprop_rssi_success_test,
				setup_enabled_adapter,
				test_dev_getprop_rssi_success, teardown);

	test_bredr("Bluetooth Device Get TIMESTAMP - Success",
				&bt_dev_getprop_timpestamp_success_test,
				setup_enabled_adapter,
				test_dev_getprop_timestamp_success, teardown);

	test_bredr("Bluetooth Device Get BDADDR - Fail",
				&bt_dev_getprop_bdaddr_fail_test,
				setup_enabled_adapter,
				test_dev_getprop_bdaddr_fail, teardown);

	test_bredr("Bluetooth Device Get SERVICE_RECORD - Fail",
				&bt_dev_getprop_servrec_fail_test,
				setup_enabled_adapter,
				test_dev_getprop_servrec_fail, teardown);

	test_bredr("Bluetooth Device Get SCAN_MODE - Fail",
				&bt_dev_getprop_scanmode_fail_test,
				setup_enabled_adapter,
				test_dev_getprop_scanmode_fail, teardown);

	test_bredr("Bluetooth Device Get BONDED_DEVICES - Fail",
				&bt_dev_getprop_bondeddev_fail_test,
				setup_enabled_adapter,
				test_dev_getprop_bondeddev_fail, teardown);

	test_bredr("Bluetooth Device Get DISCOVERY_TIMEOUT - Fail",
				&bt_dev_getprop_disctimeout_fail_test,
				setup_enabled_adapter,
				test_dev_getprop_disctimeout_fail, teardown);

	test_bredr("Bluetooth Device Get VERSION_INFO - Fail",
				&bt_dev_getprop_verinfo_fail_test,
				setup_enabled_adapter,
				test_dev_getprop_verinfo_fail, teardown);

	test_bredr("Bluetooth Device Get FRIENDLY_NAME - Fail",
					&bt_dev_getprop_fname_fail_test,
					setup_enabled_adapter,
					test_dev_getprop_fname_fail, teardown);

	test_bredr("Bluetooth Device Set FRIENDLY_NAME - Success",
				&bt_dev_setprop_fname_success_test,
				setup_enabled_adapter,
				test_dev_setprop_fname_success, teardown);

	test_bredr("Bluetooth Device Set BDNAME - Fail",
					&bt_dev_setprop_bdname_fail_test,
					setup_enabled_adapter,
					test_dev_setprop_bdname_fail, teardown);

	test_bredr("Bluetooth Device Set UUIDS - Fail",
					&bt_dev_setprop_uuids_fail_test,
					setup_enabled_adapter,
					test_dev_setprop_uuids_fail, teardown);

	test_bredr("Bluetooth Device Set COD - Fail",
					&bt_dev_setprop_cod_fail_test,
					setup_enabled_adapter,
					test_dev_setprop_cod_fail, teardown);

	test_bredr("Bluetooth Device Set TOD - Fail",
					&bt_dev_setprop_tod_fail_test,
					setup_enabled_adapter,
					test_dev_setprop_tod_fail, teardown);

	test_bredr("Bluetooth Device Set RSSI - Fail",
				&bt_dev_setprop_rssi_fail_test,
				setup_enabled_adapter,
				test_dev_setprop_rssi_fail, teardown);

	test_bredr("Bluetooth Device Set TIMESTAMP - Fail",
				&bt_dev_setprop_timpestamp_fail_test,
				setup_enabled_adapter,
				test_dev_setprop_timestamp_fail, teardown);

	test_bredr("Bluetooth Device Set BDADDR - Fail",
				&bt_dev_setprop_bdaddr_fail_test,
				setup_enabled_adapter,
				test_dev_setprop_bdaddr_fail, teardown);

	test_bredr("Bluetooth Device Set SERVICE_RECORD - Fail",
				&bt_dev_setprop_servrec_fail_test,
				setup_enabled_adapter,
				test_dev_setprop_servrec_fail, teardown);

	test_bredr("Bluetooth Device Set SCAN_MODE - Fail",
				&bt_dev_setprop_scanmode_fail_test,
				setup_enabled_adapter,
				test_dev_setprop_scanmode_fail, teardown);

	test_bredr("Bluetooth Device Set BONDED_DEVICES - Fail",
				&bt_dev_setprop_bondeddev_fail_test,
				setup_enabled_adapter,
				test_dev_setprop_bondeddev_fail, teardown);

	test_bredr("Bluetooth Device Set DISCOVERY_TIMEOUT - Fail",
				&bt_dev_setprop_disctimeout_fail_test,
				setup_enabled_adapter,
				test_dev_setprop_disctimeout_fail, teardown);

	test_bredr("Bluetooth Create Bond PIN - Success",
					&bt_bond_create_pin_success_test,
					setup_enabled_adapter,
					test_bond_create_pin_success, teardown);

	test_bredr("Bluetooth Create Bond PIN - Bad PIN",
					&bt_bond_create_pin_fail_test,
					setup_enabled_adapter,
					test_bond_create_pin_fail, teardown);

	test_bredr("Bluetooth Create Bond SSP - Success",
					&bt_bond_create_ssp_success_test,
					setup_enabled_adapter,
					test_bond_create_ssp_success, teardown);

	test_bredr("Bluetooth Create Bond SSP - Negative reply",
					&bt_bond_create_ssp_fail_test,
					setup_enabled_adapter,
					test_bond_create_ssp_fail, teardown);

	test_bredrle("Bluetooth Create Bond - No Discovery",
				&bt_bond_create_no_disc_success_test,
				setup_enabled_adapter,
				test_bond_create_no_disc_success, teardown);

	test_bredrle("Bluetooth Create Bond - Bad Address",
				&bt_bond_create_bad_addr_success_test,
				setup_enabled_adapter,
				test_bond_create_bad_addr_success, teardown);

	test_bredr("Bluetooth Cancel Bonding - Success",
					&bt_bond_cancel_success_test,
					setup_enabled_adapter,
					test_bond_cancel_success, teardown);

	test_bredr("Bluetooth Remove Bond - Success",
					&bt_bond_remove_success_test,
					setup_enabled_adapter,
					test_bond_remove_success, teardown);

	test_bredrle("Socket Init", NULL, setup_socket_interface,
						test_dummy, teardown);

	test_bredrle("Socket Listen - Invalid: sock_type 0",
			&btsock_inv_param_socktype, setup_socket_interface,
			test_generic_listen, teardown);

	test_bredrle("Socket Listen - Invalid: sock_type L2CAP",
			&btsock_inv_param_socktype_l2cap,
			setup_socket_interface, test_generic_listen, teardown);

	test_bredrle("Socket Listen - Invalid: chan, uuid",
			&btsock_inv_params_chan_uuid,
			setup_socket_interface, test_generic_listen, teardown);

	test_bredrle("Socket Listen - Check returned fd valid",
			&btsock_success,
			setup_socket_interface, test_generic_listen, teardown);

	test_bredrle("Socket Listen - Check returned channel",
			&btsock_success_check_chan,
			setup_socket_interface, test_generic_listen, teardown);

	test_bredrle("Socket Listen - Close and Listen again",
			&btsock_success_check_chan,
			setup_socket_interface, test_listen_close, teardown);

	test_bredrle("Socket Listen - Invalid: double Listen",
			&btsock_inv_listen_listen,
			setup_socket_interface, test_listen_listen, teardown);

	test_bredrle("Socket Connect - Check returned fd valid",
			&btsock_success, setup_socket_interface,
			test_generic_connect, teardown);

	test_bredrle("Socket Connect - Invalid: sock_type 0",
			&btsock_inv_param_socktype, setup_socket_interface,
			test_generic_connect, teardown);

	test_bredrle("Socket Connect - Invalid: sock_type L2CAP",
			&btsock_inv_param_socktype_l2cap,
			setup_socket_interface, test_generic_connect, teardown);

	test_bredrle("Socket Connect - Invalid: chan, uuid",
			&btsock_inv_params_chan_uuid,
			setup_socket_interface, test_generic_connect, teardown);

	test_bredrle("Socket Connect - Invalid: bdaddr",
			&btsock_inv_param_bdaddr,
			setup_socket_interface, test_generic_connect, teardown);

	test_bredrle("Socket Connect - Check returned chan",
			&btsock_success_check_chan,
			setup_socket_interface_enabled,
			test_socket_real_connect, teardown);

	test_bredrle("HIDHost Init", NULL, setup_hidhost_interface,
						test_dummy, teardown);

	test_bredrle("HIDHost Connect Success",
				NULL, setup_hidhost_connect,
				test_dummy, teardown);

	test_bredrle("HIDHost Disconnect Success",
				&hidhost_test_disconnect, setup_hidhost_connect,
				test_hidhost_disconnect, teardown);

	test_bredrle("HIDHost VirtualUnplug Success",
				&hidhost_test_disconnect, setup_hidhost_connect,
				test_hidhost_virtual_unplug, teardown);

	test_bredrle("HIDHost GetProtocol Success",
			&hidhost_test_get_protocol, setup_hidhost_connect,
				test_hidhost_get_protocol, teardown);

	test_bredrle("HIDHost SetProtocol Success",
			&hidhost_test_get_protocol, setup_hidhost_connect,
				test_hidhost_set_protocol, teardown);

	test_bredrle("HIDHost GetReport Success",
			&hidhost_test_get_report, setup_hidhost_connect,
				test_hidhost_get_report, teardown);

	test_bredrle("HIDHost SetReport Success",
				NULL, setup_hidhost_connect,
				test_hidhost_set_report, teardown);

	test_bredrle("HIDHost SendData Success",
				NULL, setup_hidhost_connect,
				test_hidhost_send_data, teardown);
	return tester_run();
}
