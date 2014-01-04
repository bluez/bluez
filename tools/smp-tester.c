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
#include <sys/socket.h>

#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/mgmt.h"

#include "monitor/bt.h"
#include "emulator/bthost.h"

#include "src/shared/tester.h"
#include "src/shared/mgmt.h"
#include "src/shared/hciemu.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef AF_ALG
#define AF_ALG  38
#define PF_ALG  AF_ALG

#include <linux/types.h>

struct sockaddr_alg {
	__u16   salg_family;
	__u8    salg_type[14];
	__u32   salg_feat;
	__u32   salg_mask;
	__u8    salg_name[64];
};

struct af_alg_iv {
	__u32   ivlen;
	__u8    iv[0];
};

#define ALG_SET_KEY                     1
#define ALG_SET_IV                      2
#define ALG_SET_OP                      3

#define ALG_OP_DECRYPT                  0
#define ALG_OP_ENCRYPT                  1

#else
#include <linux/if_alg.h>
#endif

#define SMP_CID 0x0006

struct test_data {
	const void *test_data;
	struct mgmt *mgmt;
	uint16_t mgmt_index;
	struct hciemu *hciemu;
	enum hciemu_type hciemu_type;
	unsigned int io_id;
	uint8_t ia[6];
	uint8_t ia_type;
	uint8_t ra[6];
	uint8_t ra_type;
	bool out;
	uint16_t handle;
	size_t counter;
	int alg_sk;
	uint8_t smp_tk[16];
	uint8_t smp_prnd[16];
	uint8_t smp_rrnd[16];
	uint8_t smp_pcnf[16];
	uint8_t smp_preq[7];
	uint8_t smp_prsp[7];
	uint8_t smp_ltk[16];
};

struct smp_req_rsp {
	const void *send;
	uint16_t send_len;
	const void *expect;
	uint16_t expect_len;
};

struct smp_data {
	const struct smp_req_rsp *req;
	size_t req_count;
};

static int alg_setup(void)
{
	struct sockaddr_alg salg;
	int sk;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		tester_warn("socket(AF_ALG): %s", strerror(errno));
		return -1;
	}

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "skcipher");
	strcpy((char *) salg.salg_name, "ecb(aes)");

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		tester_warn("bind(AF_ALG): %s", strerror(errno));
		close(sk);
		return -1;
	}

	return sk;
}

static int alg_new(int alg_sk, const uint8_t *key)
{
	int sk;

	if (setsockopt(alg_sk, SOL_ALG, ALG_SET_KEY, key, 16) < 0) {
		tester_warn("setsockopt(ALG_SET_KEY): %s", strerror(errno));
		return -1;
	}

	sk = accept4(alg_sk, NULL, 0, SOCK_CLOEXEC);
	if (sk < 0) {
		tester_warn("accept4(AF_ALG): %s", strerror(errno));
		return -1;
	}

	return sk;
}

static int alg_encrypt(int sk, uint8_t in[16], uint8_t out[16])
{
	__u32 alg_op = ALG_OP_ENCRYPT;
	char cbuf[CMSG_SPACE(sizeof(alg_op))];
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	int ret;

	memset(cbuf, 0, sizeof(cbuf));
	memset(&msg, 0, sizeof(msg));

	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof(cbuf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(alg_op));
	memcpy(CMSG_DATA(cmsg), &alg_op, sizeof(alg_op));

	iov.iov_base = in;
	iov.iov_len = 16;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ret = sendmsg(sk, &msg, 0);
	if (ret < 0) {
		tester_warn("sendmsg(AF_ALG): %s", strerror(errno));
		return ret;
	}

	ret = read(sk, out, 16);
	if (ret < 0)
		tester_warn("read(AF_ALG): %s", strerror(errno));

	return 0;
}

static int smp_e(uint8_t key[16], uint8_t in[16], uint8_t out[16])
{
	struct test_data *data = tester_get_data();
	int sk, err;

	sk = alg_new(data->alg_sk, key);
	if (sk < 0)
		return sk;

	err = alg_encrypt(sk, in, out);

	close(sk);

	return err;
}

static inline void swap128(const uint8_t src[16], uint8_t dst[16])
{
	int i;
	for (i = 0; i < 16; i++)
		dst[15 - i] = src[i];
}

static inline void swap56(const uint8_t src[7], uint8_t dst[7])
{
	int i;
	for (i = 0; i < 7; i++)
		dst[6 - i] = src[i];
}

typedef struct {
	uint64_t a, b;
} u128;

static inline void u128_xor(void *r, const void *p, const void *q)
{
	const u128 pp = bt_get_unaligned((const u128 *) p);
	const u128 qq = bt_get_unaligned((const u128 *) q);
	u128 rr;

	rr.a = pp.a ^ qq.a;
	rr.b = pp.b ^ qq.b;

	bt_put_unaligned(rr, (u128 *) r);
}

static int smp_c1(uint8_t r[16], uint8_t res[16])
{
	struct test_data *data = tester_get_data();
	uint8_t p1[16], p2[16];
	int err;

	memset(p1, 0, 16);

	/* p1 = pres || preq || _rat || _iat */
	swap56(data->smp_prsp, p1);
	swap56(data->smp_preq, p1 + 7);
	p1[14] = data->ra_type;
	p1[15] = data->ia_type;

	memset(p2, 0, 16);

	/* p2 = padding || ia || ra */
	baswap((bdaddr_t *) (p2 + 4), (bdaddr_t *) data->ia);
	baswap((bdaddr_t *) (p2 + 10), (bdaddr_t *) data->ra);

	/* res = r XOR p1 */
	u128_xor(res, r, p1);

	/* res = e(k, res) */
	err = smp_e(data->smp_tk, res, res);
	if (err)
		return err;

	/* res = res XOR p2 */
	u128_xor(res, res, p2);

	/* res = e(k, res) */
	return smp_e(data->smp_tk, res, res);
}

static int smp_s1(uint8_t r1[16], uint8_t r2[16], uint8_t res[16])
{
	struct test_data *data = tester_get_data();

	memcpy(res, r1 + 8, 8);
	memcpy(res + 8, r2 + 8, 8);

	return smp_e(data->smp_tk, res, res);
}

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

	data->alg_sk = alg_setup();
	if (data->alg_sk < 0) {
		tester_warn("Failed to setup AF_ALG socket");
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

	if (data->alg_sk >= 0) {
		close(data->alg_sk);
		data->alg_sk = -1;
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
		user = calloc(1, sizeof(struct test_data)); \
		if (!user) \
			break; \
		user->hciemu_type = HCIEMU_TYPE_LE; \
		user->alg_sk = -1; \
		user->test_data = data; \
		tester_add_full(name, data, \
				test_pre_setup, setup, func, NULL, \
				test_post_teardown, 2, user, test_data_free); \
	} while (0)

static const uint8_t smp_nval_req_1[] = { 0x0b, 0x00 };
static const uint8_t smp_nval_req_1_rsp[] = { 0x05, 0x07 };

static const struct smp_req_rsp nval_req_1[] = {
	{ smp_nval_req_1, sizeof(smp_nval_req_1),
			smp_nval_req_1_rsp, sizeof(smp_nval_req_1_rsp) },
};

static const struct smp_data smp_server_nval_req_1_test = {
	.req = nval_req_1,
	.req_count = G_N_ELEMENTS(nval_req_1),
};

static const uint8_t smp_nval_req_2[7] = { 0x01 };
static const uint8_t smp_nval_req_2_rsp[] = { 0x05, 0x06 };

static const struct smp_req_rsp srv_nval_req_1[] = {
	{ smp_nval_req_2, sizeof(smp_nval_req_2),
			smp_nval_req_2_rsp, sizeof(smp_nval_req_2_rsp) },
};

static const struct smp_data smp_server_nval_req_2_test = {
	.req = srv_nval_req_1,
	.req_count = G_N_ELEMENTS(srv_nval_req_1),
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
						0x01,	/* Bonding - no MITM */
						0x10,	/* Max key size */
						0x00,	/* Init. key dist. */
						0x01,	/* Rsp. key dist. */
};

static const uint8_t smp_confirm_req_1[17] = { 0x03 };
static const uint8_t smp_random_req_1[17] = { 0x04 };

static const struct smp_req_rsp srv_basic_req_1[] = {
	{ smp_basic_req_1, sizeof(smp_basic_req_1),
			smp_basic_req_1_rsp, sizeof(smp_basic_req_1_rsp) },
	{ smp_confirm_req_1, sizeof(smp_confirm_req_1),
			smp_confirm_req_1, sizeof(smp_confirm_req_1) },
	{ smp_random_req_1, sizeof(smp_random_req_1),
			smp_random_req_1, sizeof(smp_random_req_1) },
};

static const struct smp_data smp_server_basic_req_1_test = {
	.req = srv_basic_req_1,
	.req_count = G_N_ELEMENTS(srv_basic_req_1),
};

static const struct smp_req_rsp cli_basic_req_1[] = {
	{ NULL, 0, smp_basic_req_1, sizeof(smp_basic_req_1) },
	{ smp_basic_req_1_rsp, sizeof(smp_basic_req_1_rsp),
			smp_confirm_req_1, sizeof(smp_confirm_req_1) },
	{ smp_confirm_req_1, sizeof(smp_confirm_req_1),
			smp_random_req_1, sizeof(smp_random_req_1) },
	{ smp_random_req_1, sizeof(smp_random_req_1), NULL, 0 },
};

static const struct smp_data smp_client_basic_req_1_test = {
	.req = cli_basic_req_1,
	.req_count = G_N_ELEMENTS(cli_basic_req_1),
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

static const void *get_pdu(const uint8_t *data)
{
	struct test_data *test_data = tester_get_data();
	uint8_t opcode = data[0];
	static uint8_t buf[17];
	uint8_t res[16];

	switch (opcode) {
	case 0x01: /* Pairing Request */
		memcpy(test_data->smp_preq, data, sizeof(test_data->smp_preq));
		break;
	case 0x02: /* Pairing Response */
		memcpy(test_data->smp_prsp, data, sizeof(test_data->smp_prsp));
		break;
	case 0x03: /* Pairing Confirm */
		buf[0] = data[0];
		smp_c1(test_data->smp_prnd, res);
		swap128(res, &buf[1]);
		return buf;
	case 0x04: /* Pairing Random */
		buf[0] = data[0];
		swap128(test_data->smp_prnd, &buf[1]);
		return buf;
	default:
		break;
	}

	return data;
}

static bool verify_random(const uint8_t rnd[16])
{
	struct test_data *data = tester_get_data();
	uint8_t confirm[16], res[16], key[16];
	int err;

	err = smp_c1(data->smp_rrnd, res);
	if (err < 0)
		return false;

	swap128(res, confirm);

	if (memcmp(data->smp_pcnf, confirm, sizeof(data->smp_pcnf) != 0)) {
		tester_warn("Confirmation values don't match");
		return false;
	}

	if (data->out) {
		struct bthost *bthost = hciemu_client_get_host(data->hciemu);
		smp_s1(data->smp_rrnd, data->smp_prnd, key);
		swap128(key, data->smp_ltk);
		bthost_le_start_encrypt(bthost, data->handle, data->smp_ltk);
	} else {
		smp_s1(data->smp_prnd, data->smp_rrnd, key);
		swap128(key, data->smp_ltk);
	}

	return true;
}

static void smp_server(const void *data, uint16_t len, void *user_data)
{
	struct test_data *test_data = user_data;
	struct bthost *bthost = hciemu_client_get_host(test_data->hciemu);
	const struct smp_data *smp = test_data->test_data;
	const struct smp_req_rsp *req;
	const void *pdu;
	uint8_t opcode;

	if (len < 1) {
		tester_warn("Received too small SMP PDU");
		goto failed;
	}

	opcode = *((const uint8_t *) data);

	tester_print("Received SMP opcode 0x%02x", opcode);

	if (test_data->counter >= smp->req_count) {
		tester_test_passed();
		return;
	}

	req = &smp->req[test_data->counter++];
	if (!req->expect)
		goto next;

	if (req->expect_len != len) {
		tester_warn("Unexpected SMP PDU length (%u != %u)",
							len, req->expect_len);
		goto failed;
	}

	switch (opcode) {
	case 0x01: /* Pairing Request */
		memcpy(test_data->smp_preq, data, sizeof(test_data->smp_preq));
		break;
	case 0x02: /* Pairing Response */
		memcpy(test_data->smp_prsp, data, sizeof(test_data->smp_prsp));
		break;
	case 0x03: /* Pairing Confirm */
		memcpy(test_data->smp_pcnf, data + 1, 16);
		goto next;
	case 0x04: /* Pairing Random */
		swap128(data + 1, test_data->smp_rrnd);
		if (!verify_random(data + 1))
			goto failed;
		goto next;
	default:
		break;
	}

	if (memcmp(req->expect, data, len) != 0) {
		tester_warn("Unexpected SMP PDU");
		goto failed;
	}

next:
	if (smp->req_count == test_data->counter) {
		tester_test_passed();
		return;
	}

	req = &smp->req[test_data->counter];

	pdu = get_pdu(req->send);
	bthost_send_cid(bthost, test_data->handle, SMP_CID, pdu,
							req->send_len);

	if (!req->expect)
		tester_test_passed();

	return;

failed:
	tester_test_failed();
}

static void smp_new_conn(uint16_t handle, void *user_data)
{
	struct test_data *data = user_data;
	const struct smp_data *smp = data->test_data;
	struct bthost *bthost = hciemu_client_get_host(data->hciemu);
	const struct smp_req_rsp *req;
	const void *pdu;

	tester_print("New SMP client connection with handle 0x%04x", handle);

	data->handle = handle;

	bthost_add_cid_hook(bthost, handle, SMP_CID, smp_server, data);

	if (smp->req_count == data->counter)
		return;

	req = &smp->req[data->counter];

	if (!req->send)
		return;

	tester_print("Sending SMP PDU");

	pdu = get_pdu(req->send);
	bthost_send_cid(bthost, handle, SMP_CID, pdu, req->send_len);
}

static void init_bdaddr(struct test_data *data)
{
	const uint8_t *master_bdaddr, *client_bdaddr;

	master_bdaddr = hciemu_get_master_bdaddr(data->hciemu);
	if (!master_bdaddr) {
		tester_warn("No master bdaddr");
		tester_test_failed();
		return;
	}

	client_bdaddr = hciemu_get_client_bdaddr(data->hciemu);
	if (!client_bdaddr) {
		tester_warn("No client bdaddr");
		tester_test_failed();
		return;
	}

	data->ia_type = LE_PUBLIC_ADDRESS;
	data->ra_type = LE_PUBLIC_ADDRESS;

	if (data->out) {
		memcpy(data->ia, client_bdaddr, sizeof(data->ia));
		memcpy(data->ra, master_bdaddr, sizeof(data->ra));
	} else {
		memcpy(data->ia, master_bdaddr, sizeof(data->ia));
		memcpy(data->ra, client_bdaddr, sizeof(data->ra));
	}
}

static void test_client(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct mgmt_cp_pair_device cp;
	struct bthost *bthost;

	init_bdaddr(data);

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_connect_cb(bthost, smp_new_conn, data);

	memcpy(&cp.addr.bdaddr, data->ra, sizeof(data->ra));
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
	mgmt_send(data->mgmt, MGMT_OP_SET_PAIRABLE, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_SET_ADVERTISING, data->mgmt_index,
				sizeof(param), param, NULL, NULL, NULL);
	mgmt_send(data->mgmt, MGMT_OP_SET_POWERED, data->mgmt_index,
			sizeof(param), param, setup_powered_server_callback,
			NULL, NULL);
}

static void test_server(const void *test_data)
{
	struct test_data *data = tester_get_data();
	struct bthost *bthost;

	data->out = true;

	init_bdaddr(data);

	bthost = hciemu_client_get_host(data->hciemu);
	bthost_set_connect_cb(bthost, smp_new_conn, data);

	bthost_hci_connect(bthost, data->ra, BDADDR_LE_PUBLIC);
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
