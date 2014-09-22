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
	uint8_t rsp[7];

	memcpy(conn->preq, data, sizeof(conn->preq));

	rsp[0] = BT_L2CAP_SMP_PAIRING_RESPONSE;
	rsp[1] = bthost_get_io_capability(bthost);
	rsp[2] = 0x00;				/* OOB Flag */
	rsp[3] = bthost_get_auth_req(bthost);
	rsp[4] = 0x10;				/* Max key size */
	rsp[5] = conn->preq[5] & KEY_DIST;	/* Init. key dist. */
	rsp[6] = conn->preq[6] & KEY_DIST;	/* Rsp. key dist. */

	memcpy(conn->prsp, rsp, sizeof(rsp));

	conn->local_key_dist = rsp[6];
	conn->remote_key_dist = rsp[5];

	bthost_send_cid(bthost, conn->handle, SMP_CID, rsp, sizeof(rsp));
}

static void pairing_rsp(struct smp_conn *conn, const void *data, uint16_t len)
{
	struct smp *smp = conn->smp;
	uint8_t cfm[17];

	memcpy(conn->prsp, data, sizeof(conn->prsp));

	conn->local_key_dist = conn->prsp[5];
	conn->remote_key_dist = conn->prsp[6];

	cfm[0] = BT_L2CAP_SMP_PAIRING_CONFIRM;
	bt_crypto_c1(smp->crypto, conn->tk, conn->prnd, conn->prsp,
			conn->preq, conn->ia_type, conn->ia,
			conn->ra_type, conn->ra, &cfm[1]);

	bthost_send_cid(smp->bthost, conn->handle, SMP_CID, cfm, sizeof(cfm));
}

static void pairing_cfm(struct smp_conn *conn, const void *data, uint16_t len)
{
	struct bthost *bthost = conn->smp->bthost;
	uint8_t rsp[17];

	memcpy(conn->pcnf, data + 1, 16);

	if (conn->out) {
		rsp[0] = BT_L2CAP_SMP_PAIRING_RANDOM;
		memset(&rsp[1], 0, 16);
	} else {
		rsp[0] = BT_L2CAP_SMP_PAIRING_CONFIRM;
		bt_crypto_c1(conn->smp->crypto, conn->tk, conn->prnd,
				conn->prsp, conn->preq, conn->ia_type,
				conn->ia, conn->ra_type, conn->ra, &rsp[1]);
	}

	bthost_send_cid(bthost, conn->handle, SMP_CID, rsp, sizeof(rsp));
}

static void pairing_rnd(struct smp_conn *conn, const void *data, uint16_t len)
{
	struct bthost *bthost = conn->smp->bthost;
	uint8_t rsp[17];

	memcpy(conn->rrnd, data + 1, 16);

	if (!verify_random(conn, data + 1))
		return;

	if (conn->out)
		return;

	rsp[0] = BT_L2CAP_SMP_PAIRING_RANDOM;
	memset(&rsp[1], 0, 16);

	bthost_send_cid(bthost, conn->handle, SMP_CID, rsp, sizeof(rsp));
}

static void distribute_keys(struct smp_conn *conn)
{
	uint8_t buf[17];
	struct bthost *bthost = conn->smp->bthost;

	if (conn->local_key_dist & DIST_ENC_KEY) {
		memset(buf, 0, sizeof(buf));

		buf[0] = BT_L2CAP_SMP_ENCRYPT_INFO;
		bthost_send_cid(bthost, conn->handle, SMP_CID, buf, 17);

		buf[0] = BT_L2CAP_SMP_MASTER_IDENT;
		bthost_send_cid(bthost, conn->handle, SMP_CID, buf, 11);
	}

	if (conn->local_key_dist & DIST_ID_KEY) {
		memset(buf, 0, sizeof(buf));

		buf[0] = BT_L2CAP_SMP_IDENT_ADDR_INFO;
		if (conn->out) {
			buf[1] = conn->ia_type;
			memcpy(&buf[2], conn->ia, 6);
		} else {
			buf[1] = conn->ra_type;
			memcpy(&buf[2], conn->ra, 6);
		}
		bthost_send_cid(bthost, conn->handle, SMP_CID, buf, 8);

		buf[0] = BT_L2CAP_SMP_IDENT_INFO;
		memset(&buf[1], 0, 16);
		bthost_send_cid(bthost, conn->handle, SMP_CID, buf, 17);
	}

	if (conn->local_key_dist & DIST_SIGN) {
		memset(buf, 0, sizeof(buf));
		buf[0] = BT_L2CAP_SMP_SIGNING_INFO;
		bthost_send_cid(bthost, conn->handle, SMP_CID, buf, 17);
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
	struct bthost *bthost = conn->smp->bthost;
	const uint8_t req[] = {	BT_L2CAP_SMP_PAIRING_REQUEST,
				io_cap,		/* IO Capability */
				0x00,		/* OOB Flag */
				auth_req,	/* Auth requirement */
				0x10,		/* Max key size */
				KEY_DIST,	/* Init. key dist. */
				KEY_DIST,	/* Rsp. key dist. */
			};

	memcpy(conn->preq, req, sizeof(req));

	bthost_send_cid(bthost, conn->handle, SMP_CID, req, sizeof(req));
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
