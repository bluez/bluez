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

#include "monitor/bt.h"
#include "bthost.h"

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

struct smp {
	struct bthost *bthost;
	struct smp_conn *conn;
	int alg_sk;
};

struct smp_conn {
	struct smp *smp;
	uint16_t handle;
	bool out;
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

static int alg_setup(void)
{
	struct sockaddr_alg salg;
	int sk;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0) {
		printf("socket(AF_ALG): %s\n", strerror(errno));
		return -1;
	}

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "skcipher");
	strcpy((char *) salg.salg_name, "ecb(aes)");

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		printf("bind(AF_ALG): %s\n", strerror(errno));
		close(sk);
		return -1;
	}

	return sk;
}

static int alg_new(int alg_sk, const uint8_t *key)
{
	int sk;

	if (setsockopt(alg_sk, SOL_ALG, ALG_SET_KEY, key, 16) < 0) {
		printf("setsockopt(ALG_SET_KEY): %s\n", strerror(errno));
		return -1;
	}

	sk = accept4(alg_sk, NULL, 0, SOCK_CLOEXEC);
	if (sk < 0) {
		printf("accept4(AF_ALG): %s\n", strerror(errno));
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
		printf("sendmsg(AF_ALG): %s\n", strerror(errno));
		return ret;
	}

	ret = read(sk, out, 16);
	if (ret < 0)
		printf("read(AF_ALG): %s\n", strerror(errno));

	return 0;
}

static int smp_e(int alg_sk, uint8_t key[16], uint8_t in[16], uint8_t out[16])
{
	int sk, err;

	sk = alg_new(alg_sk, key);
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

static int smp_c1(struct smp_conn *conn, uint8_t rnd[16], uint8_t res[16])
{
	uint8_t p1[16], p2[16];
	int err;

	memset(p1, 0, 16);

	/* p1 = pres || preq || _rat || _iat */
	swap56(conn->prsp, p1);
	swap56(conn->preq, p1 + 7);
	p1[14] = conn->ra_type;
	p1[15] = conn->ia_type;

	memset(p2, 0, 16);

	/* p2 = padding || ia || ra */
	baswap((bdaddr_t *) (p2 + 4), (bdaddr_t *) conn->ia);
	baswap((bdaddr_t *) (p2 + 10), (bdaddr_t *) conn->ra);

	/* res = r XOR p1 */
	u128_xor((u128 *) res, (u128 *) rnd, (u128 *) p1);

	/* res = e(k, res) */
	err = smp_e(conn->smp->alg_sk, conn->tk, res, res);
	if (err)
		return err;

	/* res = res XOR p2 */
	u128_xor((u128 *) res, (u128 *) res, (u128 *) p2);

	/* res = e(k, res) */
	return smp_e(conn->smp->alg_sk, conn->tk, res, res);
}

static int smp_s1(struct smp_conn *conn, uint8_t r1[16], uint8_t r2[16],
							uint8_t res[16])
{
	memcpy(res, r1 + 8, 8);
	memcpy(res + 8, r2 + 8, 8);

	return smp_e(conn->smp->alg_sk, conn->tk, res, res);
}

static bool verify_random(struct smp_conn *conn, const uint8_t rnd[16])
{
	uint8_t confirm[16], res[16], key[16];
	int err;

	err = smp_c1(conn, conn->rrnd, res);
	if (err < 0)
		return false;

	swap128(res, confirm);

	if (memcmp(conn->pcnf, confirm, sizeof(conn->pcnf) != 0)) {
		printf("Confirmation values don't match\n");
		return false;
	}

	if (conn->out) {
		smp_s1(conn, conn->rrnd, conn->prnd, key);
		swap128(key, conn->ltk);
		bthost_le_start_encrypt(conn->smp->bthost, conn->handle,
								conn->ltk);
	} else {
		smp_s1(conn, conn->prnd, conn->rrnd, key);
		swap128(key, conn->ltk);
	}

	return true;
}

static void pairing_req(struct smp_conn *conn, const void *data, uint16_t len)
{
	struct bthost *bthost = conn->smp->bthost;
	static const uint8_t rsp[] = {	0x02,	/* Pairing Response */
					0x03,	/* NoInputNoOutput */
					0x00,	/* OOB Flag */
					0x01,	/* Bonding - no MITM */
					0x10,	/* Max key size */
					0x00,	/* Init. key dist. */
					0x01,	/* Rsp. key dist. */
				};

	memcpy(conn->preq, data, sizeof(conn->preq));
	memcpy(conn->prsp, rsp, sizeof(rsp));

	bthost_send_cid(bthost, conn->handle, SMP_CID, rsp, sizeof(rsp));
}

static void pairing_rsp(struct smp_conn *conn, const void *data, uint16_t len)
{
	memcpy(conn->prsp, data, sizeof(conn->prsp));

	/*bthost_send_cid(bthost, handle, SMP_CID, pdu, req->send_len);*/
}

static void pairing_cfm(struct smp_conn *conn, const void *data, uint16_t len)
{
	struct bthost *bthost = conn->smp->bthost;
	const uint8_t *cfm = data;
	uint8_t rsp[17];
	uint8_t res[16];

	memcpy(conn->pcnf, data + 1, 16);

	rsp[0] = cfm[0];
	smp_c1(conn, conn->prnd, res);
	swap128(res, &rsp[1]);

	bthost_send_cid(bthost, conn->handle, SMP_CID, rsp, sizeof(rsp));
}

static void pairing_rnd(struct smp_conn *conn, const void *data, uint16_t len)
{
	struct bthost *bthost = conn->smp->bthost;
	const uint8_t *rnd = data;
	uint8_t rsp[17];

	swap128(data + 1, conn->rrnd);

	if (!verify_random(conn, data + 1))
		return;

	rsp[0] = rnd[0];
	swap128(conn->prnd, &rsp[1]);

	bthost_send_cid(bthost, conn->handle, SMP_CID, rsp, sizeof(rsp));
}

void smp_pair(void *conn_data)
{
	struct smp_conn *conn = conn_data;
	struct bthost *bthost = conn->smp->bthost;
	const uint8_t smp_pair_req[] = {	0x01,	/* Pairing Request */
						0x03,	/* NoInputNoOutput */
						0x00,	/* OOB Flag */
						0x01,	/* Bonding - no MITM */
						0x10,	/* Max key size */
						0x00,	/* Init. key dist. */
						0x01,	/* Rsp. key dist. */
					};

	memcpy(conn->preq, smp_pair_req, sizeof(smp_pair_req));

	bthost_send_cid(bthost, conn->handle, SMP_CID, smp_pair_req,
							sizeof(smp_pair_req));
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
	case 0x01: /* Pairing Request */
		pairing_req(conn, data, len);
		break;
	case 0x02: /* Pairing Response */
		pairing_rsp(conn, data, len);
		break;
	case 0x03: /* Pairing Confirm */
		pairing_cfm(conn, data, len);
		break;
	case 0x04: /* Pairing Random */
		pairing_rnd(conn, data, len);
		break;
	default:
		break;
	}
}

int smp_get_ltk(void *smp_data, const uint8_t *rand, uint16_t div,
								uint8_t *ltk)
{
	struct smp_conn *conn = smp_data;
	static const uint8_t no_ltk[16] = { 0 };

	if (!memcmp(conn->ltk, no_ltk, 16))
		return -ENOENT;

	memcpy(ltk, conn->ltk, 16);

	return 0;
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

	smp->alg_sk = alg_setup();
	if (smp->alg_sk < 0) {
		free(smp);
		return NULL;
	}

	smp->bthost = bthost;

	return smp;
}

void smp_stop(void *smp_data)
{
	struct smp *smp = smp_data;

	close(smp->alg_sk);

	free(smp);
}
