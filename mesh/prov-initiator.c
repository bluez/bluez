/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "src/shared/ecc.h"

#include "mesh/util.h"
#include "mesh/net_keys.h"
#include "mesh/crypto.h"
#include "mesh/net.h"
#include "mesh/error.h"
#include "mesh/prov.h"
#include "mesh/provision.h"
#include "mesh/pb-adv.h"
#include "mesh/mesh.h"
#include "mesh/agent.h"

/* Quick size sanity check */
static const uint16_t expected_pdu_size[] = {
	2,	/* PROV_INVITE */
	12,	/* PROV_CAPS */
	6,	/* PROV_START */
	65,	/* PROV_PUB_KEY */
	1,	/* PROV_INP_CMPLT */
	17,	/* PROV_CONFIRM */
	17,	/* PROV_RANDOM */
	34,	/* PROV_DATA */
	1,	/* PROV_COMPLETE */
	2,	/* PROV_FAILED */
};

#define BEACON_TYPE_UNPROVISIONED		0x00

static const uint8_t pkt_filter = MESH_AD_TYPE_PROVISION;

enum int_state {
	INT_PROV_IDLE = 0,
	INT_PROV_INVITE_SENT,
	INT_PROV_INVITE_ACKED,
	INT_PROV_START_SENT,
	INT_PROV_START_ACKED,
	INT_PROV_KEY_SENT,
	INT_PROV_KEY_ACKED,
	INT_PROV_CONF_SENT,
	INT_PROV_CONF_ACKED,
	INT_PROV_RAND_SENT,
	INT_PROV_RAND_ACKED,
	INT_PROV_DATA_SENT,
	INT_PROV_DATA_ACKED,
};

#define MAT_REMOTE_PUBLIC	0x01
#define MAT_LOCAL_PRIVATE	0x02
#define MAT_RAND_AUTH		0x04
#define MAT_SECRET	(MAT_REMOTE_PUBLIC | MAT_LOCAL_PRIVATE)

struct mesh_prov_initiator {
	mesh_prov_initiator_complete_func_t cmplt;
	prov_trans_tx_t trans_tx;
	void *agent;
	void *caller_data;
	void *trans_data;
	struct l_timeout *timeout;
	uint32_t to_secs;
	enum int_state	state;
	enum trans_type transport;
	uint8_t material;
	uint8_t expected;
	int8_t previous;
	struct conf_input conf_inputs;
	uint8_t calc_key[16];
	uint8_t salt[16];
	uint8_t confirm[16];
	uint8_t s_key[16];
	uint8_t s_nonce[13];
	uint8_t private_key[32];
	uint8_t secret[32];
	uint8_t rand_auth_workspace[48];
};

static struct mesh_prov_initiator *prov = NULL;

static void initiator_free(void)
{

	if (prov)
		l_timeout_remove(prov->timeout);

	mesh_send_cancel(&pkt_filter, sizeof(pkt_filter));

	l_free(prov);
	prov = NULL;
}

static void int_prov_close(void *user_data, uint8_t reason)
{
	/* TODO: Handle Close */
}

static void int_prov_open(void *user_data, prov_trans_tx_t trans_tx,
				void *trans_data, uint8_t transport)
{
	struct mesh_prov_initiator *rx_prov = user_data;
	uint8_t invite[] = { PROV_INVITE, 30 };

	/* Only one provisioning session may be open at a time */
	if (rx_prov != prov)
		return;

	/* Only one provisioning session may be open at a time */
	if (prov->trans_tx && prov->trans_tx != trans_tx &&
					prov->transport != transport)
		return;

	/* We only care here if transport does *not* match */
	if (transport != prov->transport)
		return;

	/* Always use an ephemeral key when Initiator */
	ecc_make_key(prov->conf_inputs.prv_pub_key, prov->private_key);
	prov->material |= MAT_LOCAL_PRIVATE;

	prov->trans_tx = trans_tx;
	prov->trans_data = trans_data;
	prov->state = INT_PROV_INVITE_SENT;
	prov->expected = PROV_CAPS;

	prov->conf_inputs.invite.attention = invite[1];
	prov->trans_tx(prov->trans_data, invite, sizeof(invite));
	return;
}

static void swap_u256_bytes(uint8_t *u256)
{
	int i;

	/* End-to-End byte reflection of 32 octet buffer */
	for (i = 0; i < 16; i++) {
		u256[i] ^= u256[31 - i];
		u256[31 - i] ^= u256[i];
		u256[i] ^= u256[31 - i];
	}
}

static void prov_calc_secret(const uint8_t *pub, const uint8_t *priv,
							uint8_t *secret)
{
	uint8_t tmp[64];

	/* Convert to ECC byte order */
	memcpy(tmp, pub, 64);
	swap_u256_bytes(tmp);
	swap_u256_bytes(tmp + 32);

	ecdh_shared_secret(tmp, priv, secret);

	/* Convert to Mesh byte order */
	swap_u256_bytes(secret);
}

static void int_credentials(struct mesh_prov_initiator *prov)
{
	prov_calc_secret(prov->conf_inputs.dev_pub_key,
			prov->private_key, prov->secret);

	mesh_crypto_s1(&prov->conf_inputs,
			sizeof(prov->conf_inputs), prov->salt);

	mesh_crypto_prov_conf_key(prov->secret, prov->salt,
			prov->calc_key);

	l_getrandom(prov->rand_auth_workspace, 16);

	print_packet("PublicKeyProv", prov->conf_inputs.prv_pub_key, 64);
	print_packet("PublicKeyDev", prov->conf_inputs.dev_pub_key, 64);
	print_packet("PrivateKeyLocal", prov->private_key, 32);
	print_packet("ConfirmationInputs", &prov->conf_inputs,
						sizeof(prov->conf_inputs));
	print_packet("ECDHSecret", prov->secret, 32);
	print_packet("LocalRandom", prov->rand_auth_workspace, 16);
	print_packet("ConfirmationSalt", prov->salt, 16);
	print_packet("ConfirmationKey", prov->calc_key, 16);
}

static uint8_t u16_high_bit(uint16_t mask)
{
	uint8_t cnt = 0;

	if (!mask)
		return 0xff;

	while (mask & 0xfffe) {
		cnt++;
		mask >>= 1;
	}

	return cnt;
}

static uint32_t digit_mod(uint8_t power)
{
	uint32_t ret = 1;

	while (power--)
		ret *= 10;

	return ret;
}

static void calc_local_material(const uint8_t *random)
{
	/* Calculate SessionKey while the data is fresh */
	mesh_crypto_prov_prov_salt(prov->salt,
			prov->rand_auth_workspace, random,
			prov->salt);
	mesh_crypto_session_key(prov->secret, prov->salt,
			prov->s_key);
	mesh_crypto_nonce(prov->secret, prov->salt, prov->s_nonce);

	print_packet("SessionKey", prov->s_key, sizeof(prov->s_key));
	print_packet("Nonce", prov->s_nonce, sizeof(prov->s_nonce));
	print_packet("RandomDevice", prov->rand_auth_workspace, 16);
}

static void number_cb(void *user_data, int err, uint32_t number)
{
	struct mesh_prov_initiator *rx_prov = user_data;
	uint8_t out[2];

	if (prov != rx_prov)
		return;

	if (err) {
		out[0] = PROV_FAILED;
		out[1] = PROV_ERR_UNEXPECTED_ERR;
		prov->trans_tx(prov->trans_data, out, 2);
		return;
	}

	/* Save two copies, to generate two confirmation values */
	l_put_be32(number, prov->rand_auth_workspace + 28);
	l_put_be32(number, prov->rand_auth_workspace + 44);
	prov->material |= MAT_RAND_AUTH;
}

static void static_cb(void *user_data, int err, uint8_t *key, uint32_t len)
{
	struct mesh_prov_initiator *rx_prov = user_data;
	uint8_t out[2];

	if (prov != rx_prov)
		return;

	if (err || !key || len != 16) {
		out[0] = PROV_FAILED;
		out[1] = PROV_ERR_UNEXPECTED_ERR;
		prov->trans_tx(prov->trans_data, out, 2);
		return;
	}

	memcpy(prov->rand_auth_workspace + 16, key, 16);
	memcpy(prov->rand_auth_workspace + 32, key, 16);
	prov->material |= MAT_RAND_AUTH;
}

static void pub_key_cb(void *user_data, int err, uint8_t *key, uint32_t len)
{
	struct mesh_prov_initiator *rx_prov = user_data;
	uint8_t out[2];

	if (prov != rx_prov)
		return;

	if (err || !key || len != 64) {
		out[0] = PROV_FAILED;
		out[1] = PROV_ERR_UNEXPECTED_ERR;
		prov->trans_tx(prov->trans_data, out, 2);
		return;
	}

		memcpy(prov->conf_inputs.dev_pub_key, key, 64);
		prov->material |= MAT_REMOTE_PUBLIC;

		if ((prov->material & MAT_SECRET) == MAT_SECRET)
			int_credentials(prov);
}

static void int_prov_rx(void *user_data, const uint8_t *data, uint16_t len)
{
	struct mesh_prov_initiator *rx_prov = user_data;
	uint8_t *out;
	uint8_t type = *data++;
	uint8_t fail_code[2];
	uint32_t oob_key;
	uint64_t mic;

	if (rx_prov != prov || !prov->trans_tx)
		return;

	l_debug("Provisioning packet received type: %2.2x (%u octets)",
								type, len);

	if (type == prov->previous) {
		l_error("Ignore repeated %2.2x packet", type);
		return;
	} else if (type > prov->expected || type < prov->previous) {
		l_error("Expected %2.2x, Got:%2.2x", prov->expected, type);
		fail_code[1] = PROV_ERR_UNEXPECTED_PDU;
		goto failure;
	}

	if (type >= L_ARRAY_SIZE(expected_pdu_size) ||
					len != expected_pdu_size[type]) {
		l_error("Expected PDU size %d, Got %d (type: %2.2x)",
			len, expected_pdu_size[type], type);
		fail_code[1] = PROV_ERR_INVALID_FORMAT;
		goto failure;
	}

	switch (type) {
	case PROV_CAPS: /* Capabilities */
		prov->state = INT_PROV_INVITE_ACKED;
		memcpy(&prov->conf_inputs.caps, data,
					sizeof(prov->conf_inputs.caps));

		l_debug("Got Num Ele %d", data[0]);
		l_debug("Got alg %4.4x", l_get_be16(data + 1));
		l_debug("Got pub_type %d", data[3]);
		l_debug("Got static_type %d", data[4]);
		l_debug("Got output_size %d", data[5]);
		l_debug("Got output_action %d", l_get_be16(data + 6));
		l_debug("Got input_size %d", data[8]);
		l_debug("Got input_action %d", l_get_be16(data + 9));

		if (!(l_get_be16(data + 1) & 0x0001)) {
			l_error("Unsupported Algorithm");
			fail_code[1] = PROV_ERR_INVALID_FORMAT;
			goto failure;
		}

		/* If Public Key available Out of Band, use it */
		if (prov->conf_inputs.caps.pub_type) {
			prov->conf_inputs.start.pub_key = 0x01;
			prov->expected = PROV_CONFIRM;
			/* Prompt Agent for remote Public Key */
			mesh_agent_request_public_key(prov->agent,
							pub_key_cb, prov);

			/* Nothing else for us to do now */
		} else
			prov->expected = PROV_PUB_KEY;

		/* Parse OOB Options, prefer static, then out, then in */
		if (prov->conf_inputs.caps.static_type) {

			prov->conf_inputs.start.auth_method = 0x01;

		} else if (prov->conf_inputs.caps.output_size &&
				prov->conf_inputs.caps.output_action) {

			prov->conf_inputs.start.auth_method = 0x02;
			prov->conf_inputs.start.auth_action =
					u16_high_bit(l_get_be16(data + 6));
			prov->conf_inputs.start.auth_size =
						(data[5] > 8 ? 8 : data[5]);

		} else if (prov->conf_inputs.caps.input_size &&
				prov->conf_inputs.caps.input_action) {

			prov->conf_inputs.start.auth_method = 0x03;
			prov->conf_inputs.start.auth_action =
					u16_high_bit(l_get_be16(data + 9));
			prov->conf_inputs.start.auth_size =
						(data[8] > 8 ? 8 : data[8]);

		}

		out = l_malloc(1 + sizeof(prov->conf_inputs.start));
		out[0] = PROV_START;
		memcpy(out + 1, &prov->conf_inputs.start,
					sizeof(prov->conf_inputs.start));

		prov->state = INT_PROV_START_SENT;
		prov->trans_tx(prov->trans_data, out,
					sizeof(prov->conf_inputs.start) + 1);
		l_free(out);
		break;

	case PROV_PUB_KEY: /* Public Key */
		/* If we expected Pub Key Out-Of-Band, then fail */
		if (prov->conf_inputs.start.pub_key) {
			fail_code[1] = PROV_ERR_INVALID_PDU;
			goto failure;
		}

		memcpy(prov->conf_inputs.dev_pub_key, data, 64);
		prov->material |= MAT_REMOTE_PUBLIC;
		prov->expected = PROV_CONFIRM;

		if ((prov->material & MAT_SECRET) != MAT_SECRET)
			return;

		int_credentials(prov);
		prov->state = INT_PROV_KEY_ACKED;

		prov->expected = PROV_CONFIRM;

		memset(prov->rand_auth_workspace + 16, 0, 32);
		switch (prov->conf_inputs.start.auth_method) {
		default:
		case 0:
			/* Auth Type 3c - No OOB */
			prov->material |= MAT_RAND_AUTH;
			break;
		case 1:
			/* Auth Type 3c - Static OOB */
			/* Prompt Agent for Static OOB */
			fail_code[1] = mesh_agent_request_static(prov->agent,
					static_cb, prov);

			if (fail_code[1])
				goto failure;

			break;
		case 2:
			/* Auth Type 3a - Output OOB */
			/* Prompt Agent for Output OOB */
			if (prov->conf_inputs.start.auth_action ==
							PROV_ACTION_OUT_ALPHA) {
				fail_code[1] = mesh_agent_prompt_alpha(
					prov->agent,
					static_cb, prov);
			} else {
				fail_code[1] = mesh_agent_prompt_number(
					prov->agent, true,
					prov->conf_inputs.start.auth_action,
					number_cb, prov);
			}

			if (fail_code[1])
				goto failure;

			break;


		case 3:
			/* Auth Type 3b - input OOB */
			l_getrandom(&oob_key, sizeof(oob_key));
			oob_key %= digit_mod(prov->conf_inputs.start.auth_size);

			/* Save two copies, for two confirmation values */
			l_put_be32(oob_key, prov->rand_auth_workspace + 28);
			l_put_be32(oob_key, prov->rand_auth_workspace + 44);
			prov->material |= MAT_RAND_AUTH;
			/* Ask Agent to Display U32 */
			if (prov->conf_inputs.start.auth_action ==
							PROV_ACTION_IN_ALPHA) {
				/* TODO: Construst NUL-term string to pass */
				fail_code[1] = mesh_agent_display_string(
					prov->agent, NULL, NULL, prov);
			} else {
				fail_code[1] = mesh_agent_display_number(
					prov->agent, false,
					prov->conf_inputs.start.auth_action,
					oob_key, NULL, prov);
			}

			if (fail_code[1])
				goto failure;

			break;


		}
		break;

	case PROV_INP_CMPLT: /* Provisioning Input Complete */
		/* TODO: Cancel Agent prompt */
		prov->expected = PROV_CONFIRM;
		out = l_malloc(17);
		out[0] = PROV_CONFIRM;
		mesh_crypto_aes_cmac(prov->calc_key, prov->rand_auth_workspace,
								32, out + 1);
		prov->trans_tx(prov->trans_data, out, 17);
		l_free(out);
		break;

	case PROV_CONFIRM: /* Confirmation */
		prov->state = INT_PROV_CONF_ACKED;
		/* RXed Device Confirmation */
		memcpy(prov->confirm, data, 16);
		print_packet("ConfirmationDevice", prov->confirm, 16);
		prov->expected = PROV_RANDOM;
		out = l_malloc(17);
		out[0] = PROV_RANDOM;
		memcpy(out + 1, prov->rand_auth_workspace, 16);
		prov->trans_tx(prov->trans_data, out, 17);
		l_free(out);
		break;

	case PROV_RANDOM: /* Random */
		prov->state = INT_PROV_RAND_ACKED;

		/* RXed Device Confirmation */
		memcpy(prov->rand_auth_workspace + 16, data, 16);
		print_packet("RandomDevice", data, 16);
		calc_local_material(data);

		mesh_crypto_aes_cmac(prov->calc_key,
						prov->rand_auth_workspace + 16,
						32, prov->rand_auth_workspace);

		if (memcmp(prov->rand_auth_workspace, prov->confirm, 16)) {
			l_error("Provisioning Failed-Confirm compare)");
			fail_code[1] = PROV_ERR_CONFIRM_FAILED;
			goto failure;
		}

		if (prov->state == INT_PROV_RAND_ACKED) {
			prov->expected = PROV_COMPLETE;
			out = l_malloc(34);
			out[0] = PROV_DATA;
			/* TODO: Fill Prov Data Structure */
			/* Encrypt Prov Data */
			mesh_crypto_aes_ccm_encrypt(prov->s_nonce, prov->s_key,
					NULL, 0,
					out + 1,
					25,
					out + 1,
					&mic, sizeof(mic));
			prov->trans_tx(prov->trans_data, out, 34);
			l_free(out);
		}
		break;

	case PROV_COMPLETE: /* Complete */
		l_info("Provisioning Complete");
		prov->state = INT_PROV_IDLE;
		//mesh_prov_close(prov, 0);
		break;

	case PROV_FAILED: /* Failed */
		l_error("Provisioning Failed (reason: %d)", data[0]);
		//mesh_prov_close(prov, data[0]);
		break;

	default:
		l_error("Unknown Pkt %2.2x", type);
		fail_code[1] = PROV_ERR_UNEXPECTED_PDU;
		goto failure;
	}

	prov->previous = type;
	return;

failure:
	fail_code[0] = PROV_FAILED;
	prov->trans_tx(prov->trans_data, fail_code, 2);
	/* TODO: Call Complete Callback (Fail)*/
}

static void int_prov_ack(void *user_data, uint8_t msg_num)
{
	/* TODO: Handle PB-ADV Ack */
}


bool initiator_start(enum trans_type transport,
		uint8_t uuid[16],
		uint16_t max_ele,
		uint16_t server, /* Only valid for PB-Remote */
		uint32_t timeout, /* in seconds from mesh.conf */
		struct mesh_agent *agent,
		mesh_prov_initiator_complete_func_t complete_cb,
		void *caller_data)
{
	bool result;

	/* Invoked from Add() method in mesh-api.txt, to add a
	 * remote unprovisioned device network.
	 */

	if (prov)
		return false;

	prov = l_new(struct mesh_prov_initiator, 1);
	prov->to_secs = timeout;
	prov->agent = agent;
	prov->cmplt = complete_cb;
	prov->caller_data = caller_data;
	prov->previous = -1;

	/* Always register for PB-ADV */
	result = pb_adv_reg(int_prov_open, int_prov_close, int_prov_rx,
						int_prov_ack, uuid, prov);

	if (result)
		return true;

	initiator_free();
	return false;
}

void initiator_cancel(void *user_data)
{
	initiator_free();
}
