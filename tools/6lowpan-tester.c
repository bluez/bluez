// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013	Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>

#include <net/if.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/mgmt.h"

#include "monitor/bt.h"
#include "emulator/bthost.h"
#include "emulator/hciemu.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/util.h"

#include "tester.h"


#define L2CAP_PSM_IPSP		0x0023 /* 6LoWPAN */

struct test_data {
	const void *test_data;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	uint16_t handle;
	uint16_t dcid;
	unsigned int io_id;
	int packet_fd;
	int step;
};

struct client_data {
	/* Skip test by default if set */
	const char *skip_by_default_reason;

	/* Send disconnect command after L2CAP connection */
	bool disconnect;

	/* Terminate L2CAP connection immediately */
	bool terminate_l2cap;

	/* Disable 6lowpan immediately on L2CAP connection */
	bool disable_on_connect;

	/* Data to send to kernel client after L2CAP connect */
	const void *send_data;
	uint16_t send_data_len;

	/* Interface listener socket type, SOCK_RAW / DGRAM */
	int sk_type;
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
	tester_print("	Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	ba2str(&rp->bdaddr, addr);
	manufacturer = btohs(rp->manufacturer);
	supported_settings = btohl(rp->supported_settings);
	current_settings = btohl(rp->current_settings);

	tester_print("	Address: %s", addr);
	tester_print("	Version: 0x%02x", rp->version);
	tester_print("	Manufacturer: 0x%04x", manufacturer);
	tester_print("	Supported settings: 0x%08x", supported_settings);
	tester_print("	Current settings: 0x%08x", current_settings);
	tester_print("	Class: 0x%02x%02x%02x",
			rp->dev_class[2], rp->dev_class[1], rp->dev_class[0]);
	tester_print("	Name: %s", rp->name);
	tester_print("	Short name: %s", rp->short_name);

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
	tester_print("	Index: 0x%04x", index);

	data->mgmt_index = index;

	mgmt_send(data->mgmt, MGMT_OP_READ_INFO, data->mgmt_index, 0, NULL,
					read_info_callback, NULL, NULL);
}

static void index_removed_callback(uint16_t index, uint16_t length,
					const void *param, void *user_data)
{
	struct test_data *data = tester_get_data();

	tester_print("Index Removed callback");
	tester_print("	Index: 0x%04x", index);

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
	tester_print("	Status: 0x%02x", status);

	if (status || !param) {
		tester_pre_setup_failed();
		return;
	}

	mgmt_register(data->mgmt, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
					index_added_callback, NULL, NULL);

	mgmt_register(data->mgmt, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
					index_removed_callback, NULL, NULL);

	data->hciemu = hciemu_new(HCIEMU_TYPE_LE);
	if (!data->hciemu) {
		tester_warn("Failed to setup HCI emulation");
		tester_pre_setup_failed();
		return;
	}

	if (tester_use_debug())
		hciemu_set_debug(data->hciemu, print_debug, "hciemu: ", NULL);

	tester_print("New hciemu instance created");
}

static int write_6lowpan(const char *filename, const char *fmt, ...)
{
	va_list ap;
	char path[PATH_MAX];
	char cmd[512];
	int fd, ret, len;

	va_start(ap, fmt);
	len = vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);

	if (len < 0 || (size_t)len >= sizeof(cmd))
		return -ENOSPC;

	tester_debug("%s < %s", filename, cmd);

	snprintf(path, sizeof(path), "/sys/kernel/debug/bluetooth/%s",
								filename);

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -EIO;

	ret = write(fd, cmd, len);
	if (ret == len)
		tester_print("%s: OK", filename);
	else
		tester_warn("%s: %m", filename);

	close(fd);
	return ret == len ? 0 : -EIO;
}

static void test_pre_setup(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct client_data *cdata = data->test_data;
	int ret;

	if (cdata && cdata->skip_by_default_reason) {
		tester_warn("Skip test: %s", cdata->skip_by_default_reason);
		if (tester_pre_setup_skip_by_default())
			return;
	}

	ret = write_6lowpan("6lowpan_enable", "1");
	if (ret < 0) {
		tester_warn("Failed to enable 6lowpan");
		tester_pre_setup_failed();
		return;
	}

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
	int ret;

	if (data->io_id > 0) {
		g_source_remove(data->io_id);
		data->io_id = 0;
	}

	if (data->packet_fd > 0) {
		close(data->packet_fd);
		data->packet_fd = -1;
	}

	ret = write_6lowpan("6lowpan_enable", "0");
	if (ret < 0) {
		tester_warn("Failed to disable 6lowpan");
		tester_post_teardown_failed();
		return;
	}

	hciemu_unref(data->hciemu);
	data->hciemu = NULL;
}

static void test_data_free(void *test_data)
{
	struct test_data *data = test_data;

	free(data);
}

#define test_6lowpan_full(name, data, setup, func) \
	do { \
		struct test_data *user; \
		user = calloc(1, sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->test_data = data; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 5, user, test_data_free); \
	} while (0)

#define test_6lowpan(name, data, setup, func) \
	test_6lowpan_full(name, data, setup, func)

static const struct client_data client_connect_terminate = {
	.terminate_l2cap = true,
};

static const struct client_data client_connect_disable = {
	.disable_on_connect = true,
};

static const struct client_data client_connect_disconnect = {
	.disconnect = true,
};

static const uint8_t dgram_data[64+1] = {
	0x41, /* LOWPAN_DISPATCH_IPV6 */
	0xde, 0xad, 0xbe, 0xef /* some payload, not actually ipv6 */
};

static const struct client_data client_recv_dgram = {
	.send_data = dgram_data,
	.send_data_len = sizeof(dgram_data),
	.sk_type = SOCK_DGRAM,
	.disconnect = true,
};

static const struct client_data client_recv_raw = {
	.send_data = dgram_data,
	.send_data_len = sizeof(dgram_data),
	.sk_type = SOCK_RAW,
	.disconnect = true,
	.skip_by_default_reason = "kernel BUG at net/core/skbuff.c:212"
};

static void client_cmd_complete(uint16_t opcode, uint8_t status,
					const void *param, uint8_t len,
					void *user_data)
{
	switch (opcode) {
	case BT_HCI_CMD_LE_SET_ADV_ENABLE:
		tester_print("Client set adv enable status 0x%02x", status);
		break;
	default:
		return;
	}

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
	bthost_set_cmd_complete_cb(bthost, client_cmd_complete, user_data);
	bthost_set_adv_enable(bthost, 0x01);
}

static void setup_powered_common(void)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	mgmt_send(data->mgmt, MGMT_OP_SET_LE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);

	mgmt_send(data->mgmt, MGMT_OP_SET_BONDABLE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);
}

static void setup_powered_client(const void *test_data)
{
	struct test_data *data = tester_get_data();
	unsigned char param[] = { 0x01 };

	tester_print("Powering on controller");

	setup_powered_common();

	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
				sizeof(param), param,
				setup_powered_client_callback, NULL, NULL);

	tester_print("OK");
}

static void finish_step(struct test_data *data)
{
	if (!data->step)
		tester_test_failed();
	else if (--data->step == 0)
		tester_test_passed();
}

static void test_framework(const void *test_data)
{
	tester_test_passed();
}

static int open_iface(const char *ifname, int sk_type)
{
	int sk = -1;
	struct sockaddr_ll sa;
	struct ifreq ifr;
	struct packet_mreq mr;
	int err;
	socklen_t len;

	/* Open socket that receives all rx/tx on interface */

	if (!sk_type)
		sk_type = SOCK_RAW;

	sk = socket(PF_PACKET, sk_type, htons(ETH_P_ALL));
	if (sk < 0) {
		tester_print("socket: %m");
		goto error;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (ioctl(sk, SIOCGIFINDEX, &ifr) == -1) {
		tester_print("SIOCGIFINDEX: %s: %m", ifname);
		goto error;
	}

	sa.sll_family = AF_PACKET;
	sa.sll_ifindex = ifr.ifr_ifindex;
	sa.sll_protocol = 0;
	if (bind(sk, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		tester_print("bind: %m");
		goto error;
	}

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ifr.ifr_ifindex;
	mr.mr_type = PACKET_MR_PROMISC;
	if (setsockopt(sk, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
						&mr, sizeof(mr)) < 0) {
		tester_print("PACKET_ADD_MEMBERSHIP: %m");
		goto error;
	}

	len = sizeof(err);
	if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
		tester_print("getsockopt: %m");
		goto error;
	}

	if (err) {
		tester_print("SO_ERROR: %d", err);
		goto error;
	}

	return sk;

error:
	if (sk >= 0)
		close(sk);
	return -EIO;
}

static gboolean client_do_disconnect(gpointer user_data)
{
	struct test_data *data = user_data;
	const uint8_t *client_bdaddr;
	char addr[18];

	data->io_id = 0;

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	ba2str((void *) client_bdaddr, addr);

	/* XXX: sic - 6lowpan connect takes BDADDR_LE_* but disconnect takes
	 * XXX: ADDR_LE_DEV_* address type value.
	 * XXX: This is probably a bug in 6lowpan.c
	 */
	if (write_6lowpan("6lowpan_control", "disconnect %s 0", addr))
		tester_test_failed();

	return FALSE;
}

static gboolean recv_iface_packet(GIOChannel *io, GIOCondition cond,
							gpointer user_data)
{
	struct test_data *data = user_data;
	const struct client_data *cdata = data->test_data;
	uint8_t buf[256];
	int fd;
	ssize_t ret;
	int phy_hdr_size = (cdata->sk_type == SOCK_DGRAM) ? 1 : 0;

	if (cond & (G_IO_ERR | G_IO_HUP | G_IO_NVAL))
		goto done;

	fd = g_io_channel_unix_get_fd(io);
	ret = recv(fd, buf, sizeof(buf), 0);
	if (ret < 0) {
		tester_print("recv failed");
		tester_test_failed();
		goto done;
	}

	tester_print("Recv %d bytes", (int)ret);

	if (ret != cdata->send_data_len - phy_hdr_size)
		return TRUE;
	if (memcmp(buf, cdata->send_data + phy_hdr_size, ret))
		return TRUE;

	tester_print("Received sent packet");

	if (cdata->disconnect)
		client_do_disconnect(user_data);

	finish_step(data);

done:
	data->io_id = 0;
	return FALSE;
}

static gboolean client_open_iface(gpointer user_data)
{
	struct test_data *data = user_data;
	const struct client_data *cdata = data->test_data;

	data->io_id = 0;

	data->packet_fd = open_iface("bt0", cdata->sk_type);
	if (data->packet_fd < 0) {
		tester_print("Wait for interface...");
		data->io_id = g_timeout_add(500, client_open_iface, data);
		return FALSE;
	}

	if (cdata->send_data) {
		struct bthost *bthost;
		GIOChannel *io;

		bthost = hciemu_client_get_host(data->hciemu);

		io = g_io_channel_unix_new(data->packet_fd);
		data->io_id = g_io_add_watch(io,
				G_IO_IN | G_IO_ERR | G_IO_HUP | G_IO_NVAL,
				recv_iface_packet, data);
		g_io_channel_unref(io);

		tester_debug("Send %u+1 bytes", cdata->send_data_len - 1);
		bthost_send_cid(bthost, data->handle, data->dcid,
				cdata->send_data, cdata->send_data_len);
	} else if (cdata->disconnect) {
		data->io_id = g_idle_add(client_do_disconnect, data);
	}

	return FALSE;
}

static void client_l2cap_connect_cb(uint16_t handle, uint16_t cid,
							void *user_data)
{
	struct test_data *data = user_data;
	const struct client_data *cdata = data->test_data;

	tester_debug("Client connect CID 0x%04x handle 0x%04x", cid, handle);

	data->handle = handle;
	data->dcid = cid;

	if (cdata->terminate_l2cap) {
		struct bthost *bthost;
		struct bt_l2cap_pdu_disconn_req req;

		bthost = hciemu_client_get_host(data->hciemu);

		memset(&req, 0, sizeof(req));
		req.scid = cpu_to_le16(cid);
		req.dcid = cpu_to_le16(cid);

		bthost_l2cap_req(bthost, handle, BT_L2CAP_PDU_DISCONN_REQ,
				&req, sizeof(req), NULL, NULL);
	}

	/* Wait until kernel handles L2CAP connect RSP */
	if (cdata->send_data || cdata->disconnect)
		data->io_id = g_idle_add(client_open_iface, data);

	if (cdata->disable_on_connect) {
		if (write_6lowpan("6lowpan_enable", "0"))
			tester_test_failed();
		else
			tester_test_passed();
	}
}

static void client_l2cap_disconnect_cb(uint16_t handle, uint16_t cid,
							void *user_data)
{
	struct test_data *data = user_data;

	tester_debug("Client disconnect CID 0x%04x handle 0x%04x", cid, handle);

	if (handle == data->handle && cid == data->dcid)
		finish_step(data);
}

static void test_connect(const void *test_data)
{
	struct test_data *data = tester_get_data();
	const struct client_data *cdata = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	const uint8_t *client_bdaddr;
	char addr[18];

	if (cdata->terminate_l2cap || cdata->disconnect)
		data->step++;
	if (cdata->send_data)
		data->step++;

	bthost_add_l2cap_server_custom(bthost, L2CAP_PSM_IPSP,
				1280, 1280, 1,
				client_l2cap_connect_cb,
				client_l2cap_disconnect_cb,
				data);

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	ba2str((void *) client_bdaddr, addr);

	if (write_6lowpan("6lowpan_control", "connect %s 1", addr))
		tester_test_failed();
}

int main(int argc, char *argv[])
{
	tester_init(&argc, &argv);

	test_6lowpan("Basic Framework - Success", NULL, setup_powered_client,
							test_framework);

	test_6lowpan("Client Connect - Terminate", &client_connect_terminate,
							setup_powered_client,
							test_connect);

	test_6lowpan("Client Connect - Disable", &client_connect_disable,
							setup_powered_client,
							test_connect);

	test_6lowpan("Client Connect - Disconnect", &client_connect_disconnect,
							setup_powered_client,
							test_connect);

	test_6lowpan("Client Recv Dgram - Success", &client_recv_dgram,
							setup_powered_client,
							test_connect);

	test_6lowpan("Client Recv Raw - Success", &client_recv_raw,
							setup_powered_client,
							test_connect);

	return tester_run();
}
