/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2013-2014  Intel Corporation
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/hci.h"

#include "src/shared/crypto.h"
#include "monitor/bt.h"
#include "bthost.h"

#define SMP_CID 0x0006

#define DIST_ENC_KEY	0x01
#define DIST_ID_KEY	0x02
#define DIST_SIGN	0x04

#define KEY_DIST (DIST_ENC_KEY | DIST_ID_KEY | DIST_SIGN)

struct smp {
	struct bthost *bthost;
	struct smp_conn *conn;
	struct bt_crypto *crypto;
};

struct smp_conn {
	struct smp *smp;
	uint16_t handle;
	bool out;
	uint8_t local_key_dist;
	uint8_t remote_key_dist;
	uint8_t ia[6];
	uint8_t ia_type;
	uint8_t ra[6];
	uint8_t ra_type;
	uint8_t tk[16];
	uint8_t prnd[16];
	uint8_t rrnd[16];
	uint8_t pcnf[16];
	uint8_t preq[7];
	uint8_t prsp[7];
	uint8_t ltk[16];
};

static void smp_send(struct smp_conn *conn, uint8_t smp_cmd, const void *data,
								uint8_t len)
{
	struct iovec iov[2];

	iov[0].iov_base = &smp_cmd;
	iov[0].iov_len = 1;

	iov[1].iov_base = (void *) data;
	iov[1].iov_len = len;

	bthost_send_cid_v(conn->smp->bthost, conn->handle, SMP_CID, iov, 2);
}

static bool verify_random(struct smp_conn *conn, const uint8_t rnd[16])
{
	uint8_t confirm[16];

	if (!bt_crypto_c1(conn->smp->crypto, conn->tk, conn->rrnd, conn->prsp,
				conn->preq, conn->ia_type, conn->ia,
				conn->ra_type, conn->ra, confirm))
		return false;

	if (memcmp(conn->pcnf, confirm, sizeof(conn->pcnf) != 0)) {
		printf("Confirmation values don't match\n");
		return false;
	}

	if (conn->out) {
		bt_crypto_s1(conn->smp->crypto, conn->tk, conn->rrnd,
							conn->prnd, conn->ltk);
		bthost_le_start_encrypt(conn->smp->bthost, conn->handle,
								conn->ltk);
	} else {
		bt_crypto_s1(conn->smp->crypto, conn->tk, conn->prnd,
							conn->rrnd, conn->ltk);
	}

	return true;
}

static void pairing_req(struct smp_conn *conn, const void *data, uint16_t len)
{
	struct bthost *bthost = conn->smp->bthost;
	struct bt_l2cap_smp_pairing_response rsp;

	memcpy(conn->preq, data, sizeof(conn->preq));

	rsp.io_capa		= bthost_get_io_capability(bthost);
	rsp.oob_data		= 0x00;
	rsp.auth_req		= bthost_get_auth_req(bthost);
	rsp.max_key_size	= 0x10;
	rsp.init_key_dist	= conn->preq[5] & KEY_DIST;
	rsp.resp_key_dist	= conn->preq[6] & KEY_DIST;

	conn->prsp[0] = BT_L2CAP_SMP_PAIRING_RESPONSE;
	memcpy(&conn->prsp[1], &rsp, sizeof(rsp));

	conn->local_key_dist	= rsp.resp_key_dist;
	conn->remote_key_dist	= rsp.init_key_dist;

	smp_send(conn, BT_L2CAP_SMP_PAIRING_RESPONSE, &rsp, sizeof(rsp));
}

static void pairing_rsp(struct smp_conn *conn, const void *data, uint16_t len)
{
	struct smp *smp = conn->smp;
	uint8_t cfm[16];

	memcpy(conn->prsp, data, sizeof(conn->prsp));

	conn->local_key_dist = conn->prsp[5];
	conn->remote_key_dist = conn->prsp[6];

	bt_crypto_c1(smp->crypto, conn->tk, conn->prnd, conn->prsp,
			conn->preq, conn->ia_type, conn->ia,
			conn->ra_type, conn->ra, cfm);

	smp_send(conn, BT_L2CAP_SMP_PAIRING_CONFIRM, cfm, sizeof(cfm));
}

static void pairing_cfm(struct smp_conn *conn, const void *data, uint16_t len)
{
	uint8_t rsp[16];

	memcpy(conn->pcnf, data + 1, 16);

	if (conn->out) {
		memset(rsp, 0, sizeof(rsp));
		smp_send(conn, BT_L2CAP_SMP_PAIRING_RANDOM, rsp, sizeof(rsp));
	} else {
		bt_crypto_c1(conn->smp->crypto, conn->tk, conn->prnd,
				conn->prsp, conn->preq, conn->ia_type,
				conn->ia, conn->ra_type, conn->ra, rsp);
		smp_send(conn, BT_L2CAP_SMP_PAIRING_CONFIRM, rsp, sizeof(rsp));
	}
}

static void pairing_rnd(struct smp_conn *conn, const void *data, uint16_t len)
{
	uint8_t rsp[16];

	memcpy(conn->rrnd, data + 1, 16);

	if (!verify_random(conn, data + 1))
		return;

	if (conn->out)
		return;

	memset(rsp, 0, sizeof(rsp));
	smp_send(conn, BT_L2CAP_SMP_PAIRING_RANDOM, rsp, sizeof(rsp));
}

static void distribute_keys(struct smp_conn *conn)
{
	uint8_t buf[16];

	if (conn->local_key_dist & DIST_ENC_KEY) {
		memset(buf, 0, sizeof(buf));
		smp_send(conn, BT_L2CAP_SMP_ENCRYPT_INFO, buf, sizeof(buf));
		smp_send(conn, BT_L2CAP_SMP_MASTER_IDENT, buf, 10);
	}

	if (conn->local_key_dist & DIST_ID_KEY) {
		memset(buf, 0, sizeof(buf));

		if (conn->out) {
			buf[0] = conn->ia_type;
			memcpy(&buf[1], conn->ia, 6);
		} else {
			buf[0] = conn->ra_type;
			memcpy(&buf[1], conn->ra, 6);
		}
		smp_send(conn, BT_L2CAP_SMP_IDENT_ADDR_INFO, buf, 7);

		memset(buf, 0, sizeof(buf));
		smp_send(conn, BT_L2CAP_SMP_IDENT_INFO, buf, sizeof(buf));
	}

	if (conn->local_key_dist & DIST_SIGN) {
		memset(buf, 0, sizeof(buf));
		smp_send(conn, BT_L2CAP_SMP_SIGNING_INFO, buf, sizeof(buf));
	}
}

static void encrypt_info(struct smp_conn *conn, const void *data, uint16_t len)
{
}

static void master_ident(struct smp_conn *conn, const void *data, uint16_t len)
{
	conn->remote_key_dist &= ~DIST_ENC_KEY;

	if (conn->out && !conn->remote_key_dist)
		distribute_keys(conn);
}

static void ident_addr_info(struct smp_conn *conn, const void *data,
								uint16_t len)
{
}

static void ident_info(struct smp_conn *conn, const void *data, uint16_t len)
{
	conn->remote_key_dist &= ~DIST_ID_KEY;

	if (conn->out && !conn->remote_key_dist)
		distribute_keys(conn);
}

static void signing_info(struct smp_conn *conn, const void *data, uint16_t len)
{
	conn->remote_key_dist &= ~DIST_SIGN;

	if (conn->out && !conn->remote_key_dist)
		distribute_keys(conn);
}

void smp_pair(void *conn_data, uint8_t io_cap, uint8_t auth_req)
{
	struct smp_conn *conn = conn_data;
	struct bt_l2cap_smp_pairing_request req;

	req.io_capa		= io_cap;
	req.oob_data		= 0x00;
	req.auth_req		= auth_req;
	req.max_key_size	= 0x10;
	req.init_key_dist	= KEY_DIST;
	req.resp_key_dist	= KEY_DIST;

	conn->preq[0] = BT_L2CAP_SMP_PAIRING_REQUEST;
	memcpy(&conn->preq[1], &req, sizeof(req));

	smp_send(conn, BT_L2CAP_SMP_PAIRING_REQUEST, &req, sizeof(req));
}

void smp_data(void *conn_data, const void *data, uint16_t len)
{
	struct smp_conn *conn = conn_data;
	uint8_t opcode;

	if (len < 1) {
		printf("Received too small SMP PDU\n");
		return;
	}

	opcode = *((const uint8_t *) data);

	switch (opcode) {
	case BT_L2CAP_SMP_PAIRING_REQUEST:
		pairing_req(conn, data, len);
		break;
	case BT_L2CAP_SMP_PAIRING_RESPONSE:
		pairing_rsp(conn, data, len);
		break;
	case BT_L2CAP_SMP_PAIRING_CONFIRM:
		pairing_cfm(conn, data, len);
		break;
	case BT_L2CAP_SMP_PAIRING_RANDOM:
		pairing_rnd(conn, data, len);
		break;
	case BT_L2CAP_SMP_ENCRYPT_INFO:
		encrypt_info(conn, data, len);
		break;
	case BT_L2CAP_SMP_MASTER_IDENT:
		master_ident(conn, data, len);
		break;
	case BT_L2CAP_SMP_IDENT_ADDR_INFO:
		ident_addr_info(conn, data, len);
		break;
	case BT_L2CAP_SMP_IDENT_INFO:
		ident_info(conn, data, len);
		break;
	case BT_L2CAP_SMP_SIGNING_INFO:
		signing_info(conn, data, len);
		break;
	default:
		break;
	}
}

int smp_get_ltk(void *smp_data, uint64_t rand, uint16_t ediv, uint8_t *ltk)
{
	struct smp_conn *conn = smp_data;
	static const uint8_t no_ltk[16] = { 0 };

	if (!memcmp(conn->ltk, no_ltk, 16))
		return -ENOENT;

	memcpy(ltk, conn->ltk, 16);

	return 0;
}

void smp_conn_encrypted(void *conn_data, uint8_t encrypt)
{
	struct smp_conn *conn = conn_data;

	if (!encrypt)
		return;

	if (conn->out && conn->remote_key_dist)
		return;

	distribute_keys(conn);
}

void *smp_conn_add(void *smp_data, uint16_t handle, const uint8_t *ia,
					const uint8_t *ra, bool conn_init)
{
	struct smp *smp = smp_data;
	struct smp_conn *conn;

	conn = malloc(sizeof(struct smp_conn));
	if (!conn)
		return NULL;

	memset(conn, 0, sizeof(*conn));

	conn->smp = smp;
	conn->handle = handle;
	conn->out = conn_init;

	conn->ia_type = LE_PUBLIC_ADDRESS;
	conn->ra_type = LE_PUBLIC_ADDRESS;
	memcpy(conn->ia, ia, 6);
	memcpy(conn->ra, ra, 6);

	return conn;
}

void smp_conn_del(void *conn_data)
{
	struct smp_conn *conn = conn_data;

	free(conn);
}

void *smp_start(struct bthost *bthost)
{
	struct smp *smp;

	smp = malloc(sizeof(struct smp));
	if (!smp)
		return NULL;

	memset(smp, 0, sizeof(*smp));

	smp->crypto = bt_crypto_new();
	if (!smp->crypto) {
		free(smp);
		return NULL;
	}

	smp->bthost = bthost;

	return smp;
}

void smp_stop(void *smp_data)
{
	struct smp *smp = smp_data;

	bt_crypto_unref(smp->crypto);

	free(smp);
}
