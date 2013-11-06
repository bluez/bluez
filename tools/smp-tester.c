/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"
#include "emulator/bthost.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

#define SMP_CID 0x0006

struct test_data {
	const void *test_data;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	unsigned int io_id;
	uint16_t handle;
};

struct smp_server_data {
	const void *send_req;
	uint16_t send_req_len;
	const void *expect_rsp;
	uint16_t expect_rsp_len;
};

struct smp_client_data {
	const void *expect_req;
	uint16_t expect_req_len;
	const void *send_rsp;
	uint16_t send_rsp_len;
};

static void mgmt_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	tester_print("%s%s", prefix, str);
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
	}

	tester_print("New hciemu instance created");
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->mgmt = mgmt_new_default();
	if (!data->mgmt) {
		tester_warn("Failed to setup management interface");
		tester_pre_setup_failed();
		return;
	}

	if (tester_use_debug())
		mgmt_set_debug(data->mgmt, mgmt_debug, "mgmt: ", NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	if (data->io_id > 0) {
		g_source_remove(data->io_id);
		data->io_id = 0;
	}

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void test_data_free(void *test_data)
{
	struct test_data *data = test_data;

	free(data);
}

#define test_smp(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_LE; \
		user->io_id = 0; \
		user->test_data = data; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, test_data_free); \
	} while (0)

static const uint8_t smp_nval_req_1[] = { 0x0b, 0x00 };
static const uint8_t smp_nval_req_1_rsp[] = { 0x05, 0x07 };

static const struct smp_server_data smp_server_nval_req_1_test = {
	.send_req = smp_nval_req_1,
	.send_req_len = sizeof(smp_nval_req_1),
	.expect_rsp = smp_nval_req_1_rsp,
	.expect_rsp_len = sizeof(smp_nval_req_1_rsp),
};

static const uint8_t smp_nval_req_2[7] = { 0x01 };
static const uint8_t smp_nval_req_2_rsp[] = { 0x05, 0x06 };

static const struct smp_server_data smp_server_nval_req_2_test = {
	.send_req = smp_nval_req_2,
	.send_req_len = sizeof(smp_nval_req_2),
	.expect_rsp = smp_nval_req_2_rsp,
	.expect_rsp_len = sizeof(smp_nval_req_2_rsp),
};

static const uint8_t smp_basic_req_1[] = {	0x01,	/* Pairing Request */
						0x03,	/* NoInputNoOutput */
						0x00,	/* OOB Flag */
						0x01,	/* Bonding - no MITM */
						0x10,	/* Max key size */
						0x00,	/* Init. key dist. */
						0x01,	/* Rsp. key dist. */

};
static const uint8_t smp_basic_req_1_rsp[] = {	0x02,	/* Pairing Response */
						0x03,	/* NoInputNoOutput */
						0x00,	/* OOB Flag */
						0x00,	/* SMP auth none */
						0x10,	/* Max key size */
						0x00,	/* Init. key dist. */
						0x00,	/* Rsp. key dist. */

};

static const struct smp_server_data smp_server_basic_req_1_test = {
	.send_req = smp_basic_req_1,
	.send_req_len = sizeof(smp_basic_req_1),
	.expect_rsp = smp_basic_req_1_rsp,
	.expect_rsp_len = sizeof(smp_basic_req_1_rsp),
};

static const struct smp_client_data smp_client_basic_req_1_test = {
	.expect_req = smp_basic_req_1,
	.expect_req_len = sizeof(smp_basic_req_1),
};

static void client_connectable_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	if (opcode != BT_HCI_CMD_LE_SET_ADV_ENABLE)
		return;

	tester_print("Client set connectable status 0x%02x", status);

	if (status)
		tester_setup_failed();
	else
		tester_setup_complete();
}

static void setup_powered_client_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_cmd_complete_cb(bthost, client_connectable_complete, data);
	bthost_set_adv_enable(bthost, 0x01);
}

static void setup_powered_client(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_SET_PAIRABLE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, setup_powered_client_callback,
			NULL, NULL);
}

static void pair_device_complete(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Pairing failed: %s", mgmt_errstr(status));
		tester_test_failed();
		return;
	}

	tester_print("Pairing succeedded");
	tester_test_passed();
}

static void smp_server(const void *data, uint16_t len, void *user_data)
{
	struct test_data *test_data = tester_get_data();
	const struct smp_client_data *cli = test_data->test_data;

	tester_print("Received SMP request");

	if (!cli->expect_req) {
		tester_test_passed();
		return;
	}

	if (cli->expect_req_len != len) {
		tester_warn("Unexpected SMP request length (%u != %u)",
						len, cli->expect_req_len);
		goto failed;
	}

	if (memcmp(cli->expect_req, data, len) != 0) {
		tester_warn("Unexpected SMP request");
		goto failed;
	}

	if (cli->send_rsp) {
		struct bthost *bthost;

		bthost = hciemu_client_get_host(test_data->hciemu);
		bthost_send_cid(bthost, test_data->handle, SMP_CID,
					cli->send_rsp, cli->send_rsp_len);
		return;
	}

	tester_test_passed();
	return;

failed:
	tester_test_failed();
}

static void smp_server_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	tester_print("New server connection with handle 0x%04x", handle);

	data->handle = handle;

	bthost_add_cid_hook(bthost, handle, SMP_CID, smp_server, NULL);
}

static void test_client(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *client_bdaddr;
	struct mgmt_cp_pair_device cp;
	struct bthost *bthost;

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (!client_bdaddr) {
		tester_warn("No client bdaddr");
		tester_test_failed();
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_connect_cb(bthost, smp_server_new_conn, data);

	memcpy(&cp.addr.bdaddr, client_bdaddr, sizeof(bdaddr_t));
	cp.addr.type = BDADDR_LE_PUBLIC;
	cp.io_cap = 0x03; /* NoInputNoOutput */

	mgmt_send(data->mgmt, MGMT_OP_PAIR_DEVICE, data->mgmt_index,
			sizeof(cp), &cp, pair_device_complete, NULL, NULL);

	tester_print("Pairing in progress");
}

static void setup_powered_server_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	tester_setup_complete();
}

static void setup_powered_server(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_SET_ADVERTISING, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, setup_powered_server_callback,
			NULL, NULL);
}

static void smp_client(const void *data, uint16_t len, void *user_data)
{
	struct test_data *test_data = user_data;
	const struct smp_server_data *srv = test_data->test_data;

	tester_print("SMP client received response");

	if (!srv->expect_rsp) {
		tester_test_passed();
		return;
	}

	if (srv->expect_rsp_len != len) {
		tester_warn("Unexpected SMP response length (%u != %u)",
						len, srv->expect_rsp_len);
		goto failed;
	}

	if (memcmp(srv->expect_rsp, data, len) != 0) {
		tester_warn("Unexpected SMP response");
		goto failed;
	}

	tester_test_passed();
	return;

failed:
	tester_test_failed();
}

static void smp_client_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;
	const struct smp_server_data *srv = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);

	tester_print("New SMP client connection with handle 0x%04x", handle);

	bthost_add_cid_hook(bthost, handle, SMP_CID, smp_client, data);

	if (!srv->send_req)
		return;

	tester_print("Sending SMP Request from client");

	bthost_send_cid(bthost, handle, SMP_CID, srv->send_req,
							srv->send_req_len);
}

static void test_server(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const uint8_t *master_bdaddr;
	struct bthost *bthost;

	master_bdaddr = hciemu_get_master_bdaddr(data->hciemu);
	if (!master_bdaddr) {
		tester_warn("No master bdaddr");
		tester_test_failed();
		return;
	}

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_connect_cb(bthost, smp_client_new_conn, data);

	bthost_hci_connect(bthost, master_bdaddr, BDADDR_LE_PUBLIC);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_smp("SMP Server - Basic Request 1",
					&smp_server_basic_req_1_test,
					setup_powered_server, test_server);
	test_smp("SMP Server - Invalid Request 1",
					&smp_server_nval_req_1_test,
					setup_powered_server, test_server);
	test_smp("SMP Server - Invalid Request 2",
					&smp_server_nval_req_2_test,
					setup_powered_server, test_server);

	test_smp("SMP Client - Basic Request 1",
					&smp_client_basic_req_1_test,
					setup_powered_client, test_client);

	return tester_run();
}
