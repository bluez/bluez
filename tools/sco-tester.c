// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sco.h"
#include "bluetooth/mgmt.h"

#include "monitor/bt.h"
#include "emulator/bthost.h"
#include "emulator/hciemu.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/util.h"

#include "tester.h"

struct test_data {
	const void *test_data;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	unsigned int io_id;
	unsigned int err_io_id;
	int sk;
	bool disable_esco;
	bool enable_codecs;
	bool disable_sco_flowctl;
	int step;
	uint16_t acl_handle;
	uint16_t handle;
	struct tx_tstamp_data tx_ts;
};

struct sco_client_data {
	int expect_err;
	const uint8_t *recv_data;
	const uint8_t *send_data;
	uint16_t data_len;

	/* Connect timeout */
	unsigned int connect_timeout_us;

	/* Shutdown socket after connect */
	bool shutdown;

	/* Close socket after connect */
	bool close_after_connect;

	/* Enable SO_TIMESTAMPING with these flags */
	uint32_t so_timestamping;

	/* Number of additional packets to send. */
	unsigned int repeat_send;

	/* Listen on SCO socket */
	bool server;

	/* Defer setup when accepting SCO connections */
	bool defer;
};

static void print_debug(const char *str, void *user_data)
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

static void enable_codec_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	if (status != MGMT_STATUS_SUCCESS) {
		tester_warn("Failed to enable codecs");
		tester_setup_failed();
		return;
	}

	tester_print("Enabled codecs");
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

	data->hciemu = hciemu_new(HCIEMU_TYPE_BREDRLE);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
		return;
	}

	if (tester_use_debug())
		hciemu_set_debug(data->hciemu, print_debug, "hciemu: ", NULL);

	tester_print("New hciemu instance created");

	if (data->disable_esco) {
		uint8_t *features;

		tester_print("Disabling eSCO packet type support");

		features = hciemu_get_features(data->hciemu);
		if (features)
			features[3] &= ~0x80;
	}

	if (data->disable_sco_flowctl) {
		uint8_t *commands;

		tester_print("Disabling SCO flow control");

		commands = hciemu_get_commands(data->hciemu);
		if (commands)
			commands[10] &= ~(BIT(3) | BIT(4));
	}
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
		mgmt_set_debug(data->mgmt, print_debug, "mgmt: ", NULL);

	mgmt_send(data->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
					read_index_list_callback, NULL, NULL);
}

static void test_post_teardown(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void test_data_free(void *test_data)
{
	struct test_data *data = test_data;

	if (data->io_id > 0)
		g_source_remove(data->io_id);

	free(data);
}

#define test_sco_full(name, data, setup, func, _disable_esco, _enable_codecs, \
					_disable_sco_flowctl, _timeout) \
	do { \
		struct test_data *user; \
		user = malloc(sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_BREDRLE; \
		user->io_id = 0; \
		user->err_io_id = 0; \
		user->sk = -1; \
		user->test_data = data; \
		user->step = 0; \
		user->disable_esco = _disable_esco; \
		user->enable_codecs = _enable_codecs; \
		user->disable_sco_flowctl = _disable_sco_flowctl; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, _timeout, user, \
				test_data_free); \
	} while (0)

#define test_sco(name, data, setup, func) \
	test_sco_full(name, data, setup, func, false, false, false, 2)

#define test_sco_no_flowctl(name, data, setup, func) \
	test_sco_full(name, data, setup, func, false, false, true, 2)

#define test_sco_11(name, data, setup, func) \
	test_sco_full(name, data, setup, func, true, false, false, 2)

#define test_sco_11_no_flowctl(name, data, setup, func) \
	test_sco_full(name, data, setup, func, true, false, true, 2)

#define test_offload_sco(name, data, setup, func) \
	test_sco_full(name, data, setup, func, false, true, false, 2)

static const struct sco_client_data connect_success = {
	.expect_err = 0
};

static const struct sco_client_data connect_timeout = {
	.expect_err = ETIMEDOUT,
	.connect_timeout_us = 1,
};

/* Check timeout handling if closed before connect finishes */
static const struct sco_client_data connect_close = {
	.close_after_connect = true,
};

static const struct sco_client_data disconnect_success = {
	.expect_err = 0,
	.shutdown = true,
};

static const struct sco_client_data connect_failure = {
	.expect_err = EOPNOTSUPP
};

static const struct sco_client_data connect_failure_reset = {
	.expect_err = ECONNRESET
};

const uint8_t data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8};

static const struct sco_client_data connect_recv_success = {
	.expect_err = 0,
	.data_len = sizeof(data),
	.recv_data = data,
};

static const struct sco_client_data connect_recv_rx_ts_success = {
	.expect_err = 0,
	.data_len = sizeof(data),
	.recv_data = data,
	.so_timestamping = (SOF_TIMESTAMPING_SOFTWARE |
					SOF_TIMESTAMPING_RX_SOFTWARE),
};

static const struct sco_client_data connect_send_success = {
	.expect_err = 0,
	.data_len = sizeof(data),
	.send_data = data,
	.repeat_send = 3
};

static const struct sco_client_data connect_send_tx_timestamping = {
	.expect_err = 0,
	.data_len = sizeof(data),
	.send_data = data,
	.so_timestamping = (SOF_TIMESTAMPING_SOFTWARE |
					SOF_TIMESTAMPING_OPT_ID |
					SOF_TIMESTAMPING_TX_SOFTWARE |
					SOF_TIMESTAMPING_TX_COMPLETION),
	.repeat_send = 2,
};

static const struct sco_client_data connect_send_no_flowctl_tx_timestamping = {
	.expect_err = 0,
	.data_len = sizeof(data),
	.send_data = data,
	.so_timestamping = (SOF_TIMESTAMPING_SOFTWARE |
					SOF_TIMESTAMPING_OPT_ID |
					SOF_TIMESTAMPING_TX_SOFTWARE),
	.repeat_send = 2,
};

static const struct sco_client_data listen_success = {
	.server = true,
	.expect_err = 0,
};

static const struct sco_client_data listen_defer_success = {
	.server = true,
	.defer = true,
	.expect_err = 0,
};

static const struct sco_client_data listen_recv_success = {
	.server = true,
	.expect_err = 0,
	.data_len = sizeof(data),
	.recv_data = data,
};

static const struct sco_client_data listen_send_success = {
	.server = true,
	.expect_err = 0,
	.data_len = sizeof(data),
	.send_data = data,
};

static void client_connectable_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	struct test_data *data = user_data;

	if (opcode != BT_HCI_CMD_WRITE_SCAN_ENABLE)
		return;

	tester_print("Client set connectable status 0x%02x", status);

	if (--data->step)
		return;

	if (status)
		tester_setup_failed();
	else
		tester_setup_complete();
}

static void bthost_recv_data(const void *buf, uint16_t len, uint8_t status,
								void *user_data)
{
	struct test_data *data = user_data;
	const struct sco_client_data *scodata = data->test_data;

	--data->step;

	tester_print("Client received %u bytes of data", len);

	if (scodata->send_data && (scodata->data_len != len ||
			memcmp(scodata->send_data, buf, len)))
		tester_test_failed();
	else if (!data->step)
		tester_test_passed();
}

static void bthost_sco_disconnected(void *user_data)
{
	struct test_data *data = user_data;

	tester_print("SCO handle 0x%04x disconnected", data->handle);

	data->handle = 0x0000;
}

static void acl_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;

	tester_print("New ACL connection with handle 0x%04x", handle);

	data->acl_handle = handle;

	if (--data->step)
		return;

	tester_setup_complete();
}

static void sco_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;
	const struct sco_client_data *scodata = data->test_data;
	struct bthost *host;
	struct iovec iov = { (void *)scodata->recv_data, scodata->data_len };

	tester_print("New client connection with handle 0x%04x", handle);

	data->handle = handle;

	host = hciemu_client_get_host(data->hciemu);
	bthost_add_sco_hook(host, data->handle, bthost_recv_data, data,
				bthost_sco_disconnected);

	if (scodata->recv_data)
		bthost_send_sco(host, data->handle, 0x00, &iov, 1);
}

static void setup_powered_callback(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct sco_client_data *scodata = data->test_data;
	struct bthost *bthost;
	const uint8_t *bdaddr;

	if (status != MGMT_STATUS_SUCCESS) {
		tester_setup_failed();
		return;
	}

	tester_print("Controller powered on");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_cmd_complete_cb(bthost, client_connectable_complete, data);
	bthost_write_scan_enable(bthost, 0x03);
	data->step++;

	if (!scodata)
		return;

	if (scodata->send_data || scodata->recv_data || scodata->server)
		bthost_set_sco_cb(bthost, sco_new_conn, data);

	if (scodata->server) {
		bdaddr = hciemu_get_central_bdaddr(data->hciemu);
		bthost_set_connect_cb(bthost, acl_new_conn, data);
		bthost_hci_connect(bthost, bdaddr, BDADDR_BREDR);
		data->step++;
	}
}

static void setup_powered(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller");

	mgmt_send(data->mgmt, MGMT_OP_SET_CONNECTABLE, data->mgmt_index,
					sizeof(param), param,
					NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_SSP, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	if (data->enable_codecs) {
		/* a6695ace-ee7f-4fb9-881a-5fac66c629af */
		static const uint8_t uuid[16] = {
				0xaf, 0x29, 0xc6, 0x66, 0xac, 0x5f, 0x1a, 0x88,
				0xb9, 0x4f, 0x7f, 0xee, 0xce, 0x5a, 0x69, 0xa6,
		};

		struct mgmt_cp_set_exp_feature cp;

		memset(&cp, 0, sizeof(cp));
		memcpy(cp.uuid, uuid, 16);
		cp.action = 1;

		tester_print("Enabling codecs");

		mgmt_send(data->mgmt, MGMT_OP_SET_EXP_FEATURE, data->mgmt_index,
			  sizeof(cp), &cp, enable_codec_callback, NULL, NULL);
	}

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
					sizeof(param), param,
					setup_powered_callback, NULL, NULL);
}

static void test_framework(const void *test_data)
{
	tester_test_passed();
}

static void test_socket(const void *test_data)
{
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_failed();
		return;
	}

	close(sk);

	tester_test_passed();
}

static void test_codecs_getsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	char buffer[255];

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_failed();
		return;
	}

	len = sizeof(buffer);
	memset(buffer, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_CODEC, buffer, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
			    strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	tester_test_passed();

end:
	close(sk);
}

static void test_codecs_setsockopt(const void *test_data)
{
	int sk, err;
	char buffer[255];
	struct bt_codecs *codecs;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_failed();
		return;
	}

	memset(buffer, 0, sizeof(buffer));

	codecs = (void *)buffer;

	codecs->codecs[0].id = 0x05;
	codecs->num_codecs = 1;
	codecs->codecs[0].data_path_id = 1;
	codecs->codecs[0].num_caps = 0x00;

	err = setsockopt(sk, SOL_BLUETOOTH, BT_CODEC, codecs, sizeof(buffer));
	if (err < 0) {
		tester_warn("Can't set socket option : %s (%d)",
			    strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	tester_test_passed();

end:
	close(sk);
}

static void test_getsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	struct bt_voice voice;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_failed();
		return;
	}

	len = sizeof(voice);
	memset(&voice, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	if (voice.setting != BT_VOICE_CVSD_16BIT) {
		tester_warn("Invalid voice setting");
		tester_test_failed();
		goto end;
	}

	tester_test_passed();

end:
	close(sk);
}

static void test_setsockopt(const void *test_data)
{
	int sk, err;
	socklen_t len;
	struct bt_voice voice;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
	if (sk < 0) {
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		tester_test_failed();
		goto end;
	}


	len = sizeof(voice);
	memset(&voice, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	if (voice.setting != BT_VOICE_CVSD_16BIT) {
		tester_warn("Invalid voice setting");
		tester_test_failed();
		goto end;
	}

	memset(&voice, 0, sizeof(voice));
	voice.setting = BT_VOICE_TRANSPARENT_16BIT;

	err = setsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, sizeof(voice));
	if (err < 0) {
		tester_warn("Can't set socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	len = sizeof(voice);
	memset(&voice, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	if (voice.setting != BT_VOICE_TRANSPARENT_16BIT) {
		tester_warn("Invalid voice setting");
		tester_test_failed();
		goto end;
	}

	memset(&voice, 0, sizeof(voice));
	voice.setting = BT_VOICE_TRANSPARENT;

	err = setsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, sizeof(voice));
	if (err < 0) {
		tester_warn("Can't set socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	len = sizeof(voice);
	memset(&voice, 0, len);

	err = getsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, &len);
	if (err < 0) {
		tester_warn("Can't get socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	if (voice.setting != BT_VOICE_TRANSPARENT) {
		tester_warn("Invalid voice setting");
		tester_test_failed();
		goto end;
	}

	tester_test_passed();

end:
	close(sk);
}

static int create_sco_sock(struct test_data *data)
{
	const struct sco_client_data *scodata = data->test_data;
	const uint8_t *central_bdaddr;
	struct sockaddr_sco addr;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK,
								BTPROTO_SCO);
	if (sk < 0) {
		err = -errno;
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	if (scodata->connect_timeout_us) {
		struct timeval timeout = {
			.tv_sec = scodata->connect_timeout_us / 1000000,
			.tv_usec = scodata->connect_timeout_us % 1000000
		};

		if (setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO,
					(void *)&timeout, sizeof(timeout))) {
			tester_warn("failed to set timeout: %m");
			return -EINVAL;
		}
	}

	central_bdaddr = hciemu_get_central_bdaddr(data->hciemu);
	if (!central_bdaddr) {
		tester_warn("No central bdaddr");
		return -ENODEV;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, (void *) central_bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		err = -errno;
		tester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		close(sk);
		return err;
	}

	return sk;
}

static int connect_sco_sock(struct test_data *data, int sk)
{
	const uint8_t *client_bdaddr;
	struct sockaddr_sco addr;
	int err;

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (!client_bdaddr) {
		tester_warn("No client bdaddr");
		return -ENODEV;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, (void *) client_bdaddr);

	err = connect(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0 && !(errno == EAGAIN || errno == EINPROGRESS)) {
		err = -errno;
		tester_warn("Can't connect socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	return 0;
}

static gboolean recv_errqueue(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = user_data;
	const struct sco_client_data *scodata = data->test_data;
	int sk = g_io_channel_unix_get_fd(io);
	int err;

	data->step--;

	err = tx_tstamp_recv(&data->tx_ts, sk, scodata->data_len);
	if (err > 0)
		return TRUE;
	else if (err)
		tester_test_failed();
	else if (!data->step)
		tester_test_passed();

	data->err_io_id = 0;
	return FALSE;
}

static void sco_tx_timestamping(struct test_data *data, GIOChannel *io)
{
	const struct sco_client_data *scodata = data->test_data;
	int so = scodata->so_timestamping;
	int sk;
	int err;
	unsigned int count;

	if (!(scodata->so_timestamping & TS_TX_RECORD_MASK))
		return;

	sk = g_io_channel_unix_get_fd(io);

	tester_print("Enabling TX timestamping");

	tx_tstamp_init(&data->tx_ts, scodata->so_timestamping, false);

	for (count = 0; count < scodata->repeat_send + 1; ++count)
		data->step += tx_tstamp_expect(&data->tx_ts, 0);

	err = setsockopt(sk, SOL_SOCKET, SO_TIMESTAMPING, &so, sizeof(so));
	if (err < 0) {
		tester_warn("setsockopt SO_TIMESTAMPING: %s (%d)",
						strerror(errno), errno);
		tester_test_failed();
		return;
	}

	data->err_io_id = g_io_add_watch(io, G_IO_ERR, recv_errqueue, data);
}

static gboolean sock_received_data(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct sco_client_data *scodata = data->test_data;
	bool tstamp = scodata->so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE;
	char buf[1024];
	int sk;
	ssize_t len;

	sk = g_io_channel_unix_get_fd(io);

	len = recv_tstamp(sk, buf, sizeof(buf), tstamp);
	if (len < 0) {
		tester_warn("Unable to read: %s (%d)", strerror(errno), errno);
		tester_test_failed();
		return FALSE;
	}

	tester_debug("read: %d", (int)len);

	if (len != scodata->data_len) {
		tester_test_failed();
		return FALSE;
	}

	--data->step;

	if (len != scodata->data_len ||
			memcmp(buf, scodata->recv_data, scodata->data_len))
		tester_test_failed();
	else if (!data->step)
		tester_test_passed();
	else
		return TRUE;

	return FALSE;
}

static void sco_recv_data(struct test_data *data, GIOChannel *io)
{
	const struct sco_client_data *scodata = data->test_data;

	data->step = 0;

	if (rx_timestamping_init(g_io_channel_unix_get_fd(io),
						scodata->so_timestamping))
		return;

	g_io_add_watch(io, G_IO_IN, sock_received_data, NULL);

	++data->step;
}

static gboolean sco_connect(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct sco_client_data *scodata = data->test_data;
	int err, sk_err, sk;
	socklen_t len = sizeof(sk_err);

	sk = g_io_channel_unix_get_fd(io);

	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &sk_err, &len) < 0)
		err = -errno;
	else
		err = -sk_err;

	if (err < 0)
		tester_warn("Connect failed: %s (%d)", strerror(-err), -err);
	else
		tester_print("Successfully connected");

	if (scodata->recv_data)
		sco_recv_data(data, io);

	if (scodata->send_data) {
		ssize_t ret = 0;
		unsigned int count;

		sco_tx_timestamping(data, io);

		tester_print("Writing %u*%u bytes of data",
				scodata->repeat_send + 1, scodata->data_len);

		for (count = 0; count < scodata->repeat_send + 1; ++count) {
			ret = write(sk, scodata->send_data, scodata->data_len);
			if (scodata->data_len != ret)
				break;
			data->step++;
		}
		if (scodata->data_len != ret) {
			tester_warn("Failed to write %u bytes: %zu %s (%d)",
					scodata->data_len, ret, strerror(errno),
					errno);
			err = -errno;
		}

		/* Don't close the socket until all data is sent */
		g_io_channel_set_close_on_unref(io, FALSE);
	}

	if (scodata->shutdown) {
		tester_print("Disconnecting...");
		shutdown(sk, SHUT_RDWR);
	}

	if (-err != scodata->expect_err)
		tester_test_failed();
	else if (!data->step)
		tester_test_passed();

	return FALSE;
}

static gboolean sco_connect_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();

	data->io_id = 0;
	sco_connect(io, cond, user_data);
	return FALSE;
}

static void test_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct sco_client_data *scodata = data->test_data;
	GIOChannel *io;
	int sk;

	sk = create_sco_sock(data);
	if (sk < 0) {
		tester_test_failed();
		return;
	}

	if (connect_sco_sock(data, sk) < 0) {
		close(sk);
		tester_test_failed();
		return;
	}

	if (scodata->close_after_connect) {
		close(sk);
		tester_test_passed();
		return;
	}

	data->sk = sk;

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	data->io_id = g_io_add_watch(io, G_IO_OUT, sco_connect_cb, NULL);

	g_io_channel_unref(io);

	tester_print("Connect in progress");
}

static void test_connect_transp(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct sco_client_data *scodata = data->test_data;
	int sk, err;
	struct bt_voice voice;

	sk = create_sco_sock(data);
	if (sk < 0) {
		tester_test_failed();
		return;
	}

	memset(&voice, 0, sizeof(voice));
	voice.setting = BT_VOICE_TRANSPARENT;

	err = setsockopt(sk, SOL_BLUETOOTH, BT_VOICE, &voice, sizeof(voice));
	if (err < 0) {
		tester_warn("Can't set socket option : %s (%d)",
							strerror(errno), errno);
		tester_test_failed();
		goto end;
	}

	err = connect_sco_sock(data, sk);

	tester_warn("Connect returned %s (%d), expected %s (%d)",
			strerror(-err), -err,
			strerror(scodata->expect_err), scodata->expect_err);

	if (-err != scodata->expect_err)
		tester_test_failed();
	else
		tester_test_passed();

end:
	close(sk);
}

static void test_connect_offload_msbc(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct sco_client_data *scodata = data->test_data;
	int sk, err;
	int len;
	char buffer[255];
	struct bt_codecs *codecs;

	sk = create_sco_sock(data);
	if (sk < 0) {
		tester_test_failed();
		return;
	}

	len = sizeof(buffer);
	memset(buffer, 0, len);

	codecs = (void *)buffer;

	codecs->codecs[0].id = 0x05;
	codecs->num_codecs = 1;
	codecs->codecs[0].data_path_id = 1;
	codecs->codecs[0].num_caps = 0x00;

	err = setsockopt(sk, SOL_BLUETOOTH, BT_CODEC, codecs, sizeof(buffer));
	if (err < 0) {
		tester_warn("Can't set socket option : %s (%d)",
			    strerror(errno), errno);
		tester_test_failed();
		goto end;
	}
	err = connect_sco_sock(data, sk);

	tester_warn("Connect returned %s (%d), expected %s (%d)",
			strerror(-err), -err,
			strerror(scodata->expect_err), scodata->expect_err);

	if (-err != scodata->expect_err)
		tester_test_failed();
	else
		tester_test_passed();

end:
	close(sk);
}

static bool hook_delay_evt(const void *msg, uint16_t len, void *user_data)
{
	tester_print("Delaying emulator response...");
	g_usleep(500000);
	tester_print("Delaying emulator response... Done.");
	return true;
}

static void test_connect_delayed(const void *test_data)
{
	struct test_data *data = tester_get_data();

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_POST_EVT,
					BT_HCI_EVT_SYNC_CONN_COMPLETE,
					hook_delay_evt, NULL);

	test_connect(test_data);
}

static bool hook_setup_sync_evt(const void *buf, uint16_t len, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct bt_hci_evt_sync_conn_complete *evt = buf;

	if (len < sizeof(*evt)) {
		tester_warn("Bad event size");
		tester_test_failed();
		return true;
	}

	data->handle = le16_to_cpu(evt->handle);
	tester_print("SCO Handle %u", data->handle);
	return true;
}

static bool hook_disconnect_evt(const void *buf, uint16_t len, void *user_data)
{
	struct test_data *data = tester_get_data();
	const struct bt_hci_evt_disconnect_complete *evt = buf;
	uint16_t handle;

	if (len < sizeof(*evt)) {
		tester_warn("Bad event size");
		tester_test_failed();
		return true;
	}

	handle = le16_to_cpu(evt->handle);
	tester_print("Disconnected Handle %u", handle);

	if (handle != data->handle)
		return true;

	if (evt->status) {
		tester_test_failed();
		return true;
	}

	data->step--;
	if (!data->step)
		tester_test_passed();

	return true;
}

static void test_disconnect(const void *test_data)
{
	struct test_data *data = tester_get_data();

	data->step++;

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_POST_EVT,
					BT_HCI_EVT_SYNC_CONN_COMPLETE,
					hook_setup_sync_evt, NULL);

	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_POST_EVT,
					BT_HCI_EVT_DISCONNECT_COMPLETE,
					hook_disconnect_evt, NULL);

	test_connect(test_data);
}

static bool hook_simult_disc(const void *msg, uint16_t len, void *user_data)
{
	const struct bt_hci_evt_sync_conn_complete *ev = msg;
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	tester_print("Simultaneous disconnect");

	if (len != sizeof(struct bt_hci_evt_sync_conn_complete)) {
		tester_test_failed();
		return true;
	}

	/* Disconnect from local and remote sides at the same time */
	bthost = hciemu_client_get_host(data->hciemu);
	bthost_hci_disconnect(bthost, le16_to_cpu(ev->handle), 0x13);

	shutdown(data->sk, SHUT_RDWR);

	return true;
}

static bool hook_delay_cmd(const void *data, uint16_t len, void *user_data)
{
	tester_print("Delaying emulator response...");
	g_usleep(250000);
	tester_print("Delaying emulator response... Done.");
	return true;
}

static void test_connect_simult_disc(const void *test_data)
{
	struct test_data *data = tester_get_data();

	/* Kernel shall not crash, but <= 6.5-rc1 crash */
	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_POST_EVT,
					BT_HCI_EVT_SYNC_CONN_COMPLETE,
					hook_simult_disc, NULL);
	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_PRE_CMD,
					BT_HCI_CMD_CREATE_CONN_CANCEL,
					hook_delay_cmd, NULL);

	test_connect(test_data);
}

static bool hook_acl_disc(const void *msg, uint16_t len, void *user_data)
{
	const struct bt_hci_evt_conn_complete *ev = msg;
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	tester_print("Disconnect ACL");

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_hci_disconnect(bthost, le16_to_cpu(ev->handle), 0x13);

	hciemu_flush_client_events(data->hciemu);

	return true;
}

static void test_connect_acl_disc(const void *test_data)
{
	struct test_data *data = tester_get_data();

	/* ACL disconnected before SCO is established seen.
	 * Kernel shall not crash, but <= 6.5-rc5 crash.
	 */
	hciemu_add_hook(data->hciemu, HCIEMU_HOOK_POST_EVT,
					BT_HCI_EVT_CONN_COMPLETE,
					hook_acl_disc, NULL);

	test_connect(test_data);
}

static void test_sco_ethtool_get_ts_info(const void *test_data)
{
	struct test_data *data = tester_get_data();

	test_ethtool_get_ts_info(data->mgmt_index, BTPROTO_SCO,
				!data->disable_sco_flowctl);
}

static int listen_sco_sock(struct test_data *data)
{
	const struct sco_client_data *scodata = data->test_data;
	struct sockaddr_sco addr;
	const uint8_t *src;
	int sk, err;

	sk = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_NONBLOCK, BTPROTO_SCO);
	if (sk < 0) {
		err = -errno;
		tester_warn("Can't create socket: %s (%d)", strerror(errno),
									errno);
		return err;
	}

	src = hciemu_get_central_bdaddr(data->hciemu);
	if (!src) {
		tester_warn("No source bdaddr");
		err = -ENODEV;
		goto fail;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.sco_family = AF_BLUETOOTH;
	bacpy(&addr.sco_bdaddr, (void *) src);

	err = bind(sk, (struct sockaddr *) &addr, sizeof(addr));
	if (err < 0) {
		err = -errno;
		tester_warn("Can't bind socket: %s (%d)", strerror(errno),
									errno);
		goto fail;
	}

	if (scodata->defer) {
		int opt = 1;

		if (setsockopt(sk, SOL_BLUETOOTH, BT_DEFER_SETUP, &opt,
							sizeof(opt)) < 0) {
			tester_print("Can't enable deferred setup: %s (%d)",
						strerror(errno), errno);
			goto fail;
		}
	}

	if (listen(sk, 10)) {
		err = -errno;
		tester_warn("Can't listen socket: %s (%d)", strerror(errno),
									errno);
		goto fail;
	}

	return sk;

fail:
	close(sk);
	return err;
}

static bool sco_defer_accept(struct test_data *data, GIOChannel *io)
{
	int sk;
	char c;
	struct pollfd pfd;

	sk = g_io_channel_unix_get_fd(io);

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = sk;
	pfd.events = POLLOUT;

	if (poll(&pfd, 1, 0) < 0) {
		tester_warn("poll: %s (%d)", strerror(errno), errno);
		return false;
	}

	if (!(pfd.revents & POLLOUT)) {
		if (read(sk, &c, 1) < 0) {
			tester_warn("read: %s (%d)", strerror(errno), errno);
			return false;
		}
	}

	tester_print("Accept deferred setup");

	return true;
}

static gboolean sco_accept_cb(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = tester_get_data();
	const struct sco_client_data *scodata = data->test_data;
	int sk, new_sk;
	gboolean ret;
	GIOChannel *new_io;

	tester_debug("New connection");

	sk = g_io_channel_unix_get_fd(io);

	new_sk = accept(sk, NULL, NULL);
	if (new_sk < 0) {
		tester_test_failed();
		return false;
	}

	new_io = g_io_channel_unix_new(new_sk);
	g_io_channel_set_close_on_unref(new_io, TRUE);

	if (scodata->defer) {
		if (scodata->expect_err < 0) {
			g_io_channel_unref(new_io);
			tester_test_passed();
			return false;
		}

		if (!sco_defer_accept(data, new_io)) {
			tester_warn("Unable to accept deferred setup");
			tester_test_failed();
			return false;
		}
	}

	ret = sco_connect(new_io, cond, user_data);

	g_io_channel_unref(new_io);
	return ret;
}

static void setup_listen(struct test_data *data, GIOFunc func)
{
	struct hciemu_client *client;
	struct bthost *host;
	int sk;
	GIOChannel *io;

	sk = listen_sco_sock(data);
	if (sk < 0) {
		if (sk == -EPROTONOSUPPORT)
			tester_test_abort();
		else
			tester_test_failed();
		return;
	}

	io = g_io_channel_unix_new(sk);
	g_io_channel_set_close_on_unref(io, TRUE);

	data->io_id = g_io_add_watch(io, G_IO_IN, func, NULL);
	g_io_channel_unref(io);

	tester_print("Listen in progress");

	client = hciemu_get_client(data->hciemu, 0);
	host = hciemu_client_host(client);

	bthost_setup_sco(host, data->acl_handle, BT_VOICE_CVSD_16BIT);
}

static void test_listen(const void *test_data)
{
	struct test_data *data = tester_get_data();

	setup_listen(data, sco_accept_cb);
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_sco("Basic Framework - Success", NULL, setup_powered,
							test_framework);

	test_sco("Basic SCO Socket - Success", NULL, setup_powered,
							test_socket);

	test_sco("Basic SCO Get Socket Option - Success", NULL, setup_powered,
							test_getsockopt);

	test_sco("Basic SCO Set Socket Option - Success", NULL, setup_powered,
							test_setsockopt);

	test_sco("eSCO CVSD - Success", &connect_success, setup_powered,
							test_connect);

	test_sco_full("eSCO CVSD - Timeout", &connect_timeout, setup_powered,
				test_connect_delayed, false, false, false, 8);

	test_sco("eSCO CVSD - Close", &connect_close, setup_powered,
						test_connect_delayed);

	test_sco("eSCO mSBC - Success", &connect_success, setup_powered,
							test_connect_transp);

	test_sco("SCO Disconnect - Success", &disconnect_success, setup_powered,
							test_disconnect);

	test_sco("eSCO Simultaneous Disconnect - Failure",
					&connect_failure_reset, setup_powered,
					test_connect_simult_disc);

	test_sco("eSCO ACL Disconnect - Failure",
					&connect_failure_reset, setup_powered,
					test_connect_acl_disc);

	test_sco_11("SCO CVSD 1.1 - Success", &connect_success, setup_powered,
							test_connect);

	test_sco_11("SCO mSBC 1.1 - Failure", &connect_failure, setup_powered,
							test_connect_transp);

	test_sco("SCO CVSD Recv - Success", &connect_recv_success,
					setup_powered, test_connect);

	test_sco("SCO CVSD Recv - RX Timestamping", &connect_recv_rx_ts_success,
					setup_powered, test_connect);

	test_sco("SCO CVSD Send - Success", &connect_send_success,
					setup_powered, test_connect);

	test_sco_no_flowctl("SCO CVSD Send No Flowctl - Success",
			&connect_send_success, setup_powered, test_connect);

	test_sco("SCO CVSD Send - TX Timestamping",
					&connect_send_tx_timestamping,
					setup_powered, test_connect);

	test_sco_no_flowctl("SCO CVSD Send No Flowctl - TX Timestamping",
				&connect_send_no_flowctl_tx_timestamping,
				setup_powered, test_connect);

	test_sco_11("SCO CVSD 1.1 Send - Success", &connect_send_success,
					setup_powered, test_connect);

	test_sco_11_no_flowctl("SCO CVSD 1.1 Send No Flowctl - Success",
			&connect_send_success, setup_powered, test_connect);

	test_offload_sco("Basic SCO Get Socket Option - Offload - Success",
				NULL, setup_powered, test_codecs_getsockopt);

	test_offload_sco("Basic SCO Set Socket Option - Offload - Success",
				NULL, setup_powered, test_codecs_setsockopt);

	test_offload_sco("eSCO mSBC - Offload - Success",
		&connect_success, setup_powered, test_connect_offload_msbc);

	test_sco("SCO Ethtool Get Ts Info - Success",
			NULL, setup_powered, test_sco_ethtool_get_ts_info);

	test_sco_no_flowctl("SCO Ethtool Get Ts Info No Flowctl - Success",
			NULL, setup_powered, test_sco_ethtool_get_ts_info);

	test_sco("SCO CVSD Listen - Success", &listen_success,
					setup_powered, test_listen);

	test_sco("SCO CVSD Listen Defer - Success", &listen_defer_success,
					setup_powered, test_listen);

	test_sco("SCO CVSD Listen Recv - Success", &listen_recv_success,
					setup_powered, test_listen);

	test_sco("SCO CVSD Listen Send - Success", &listen_send_success,
					setup_powered, test_listen);

	return tester_run();
}
