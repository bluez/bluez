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

#include "mesh/display.h"
#include "mesh/crypto.h"
#include "mesh/net.h"
#include "mesh/prov.h"
#include "mesh/provision.h"
#include "mesh/node.h"

#define PROV_INVITE	0x00
#define PROV_CAPS	0x01
#define PROV_START	0x02
#define PROV_PUB_KEY	0x03
#define PROV_INP_CMPLT	0x04
#define PROV_CONFIRM	0x05
#define PROV_RANDOM	0x06
#define PROV_DATA	0x07
#define PROV_COMPLETE	0x08
#define PROV_FAILED	0x09

#define PROV_ERR_INVALID_PDU		0x01
#define PROV_ERR_INVALID_FORMAT		0x02
#define PROV_ERR_UNEXPECTED_PDU		0x03
#define PROV_ERR_CONFIRM_FAILED		0x04
#define PROV_ERR_INSUF_RESOURCE		0x05
#define PROV_ERR_DECRYPT_FAILED		0x06
#define PROV_ERR_UNEXPECTED_ERR		0x07
#define PROV_ERR_CANT_ASSIGN_ADDR	0x08

/* Expected Provisioning PDU sizes */
static const uint16_t expected_pdu_size[] = {
	1 + 1,					/* PROV_INVITE */
	1 + 1 + 2 + 1 + 1 + 1 + 2 + 1 + 2,	/* PROV_CAPS */
	1 + 1 + 1 + 1 + 1 + 1,			/* PROV_START */
	1 + 64,					/* PROV_PUB_KEY */
	1,					/* PROV_INP_CMPLT */
	1 + 16,					/* PROV_CONFIRM */
	1 + 16,					/* PROV_RANDOM */
	1 + 16 + 2 + 1 + 4 + 2 + 8,		/* PROV_DATA */
	1,					/* PROV_COMPLETE */
	1 + 1,					/* PROV_FAILED */
};

static enum {
	PUB_KEY_TYPE_ephemeral,
	PUB_KEY_TYPE_available,
} pub_key_type = PUB_KEY_TYPE_ephemeral;

static enum {
	AUTH_TYPE_3a,
	AUTH_TYPE_3b,
	AUTH_TYPE_3c,
} prov_auth_type = AUTH_TYPE_3c;

enum {
	INT_PROV_IDLE,
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
} int_prov_state = INT_PROV_IDLE;

enum {
	ACP_PROV_IDLE,
	ACP_PROV_CAPS_SENT,
	ACP_PROV_CAPS_ACKED,
	ACP_PROV_KEY_SENT,
	ACP_PROV_KEY_ACKED,
	ACP_PROV_INP_CMPLT_SENT,
	ACP_PROV_INP_CMPLT_ACKED,
	ACP_PROV_CONF_SENT,
	ACP_PROV_CONF_ACKED,
	ACP_PROV_RAND_SENT,
	ACP_PROV_RAND_ACKED,
	ACP_PROV_CMPLT_SENT,
	ACP_PROV_FAIL_SENT,
} acp_prov_state = ACP_PROV_IDLE;

static uint8_t prov_expected;
static int8_t prov_last = -1;

static void int_prov_send_cmplt(bool success, struct mesh_prov *prov);
static void acp_prov_send_cmplt(bool success, struct mesh_prov *prov);

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

static uint8_t u16_highest_bit(uint16_t mask)
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

static void send_prov_start(struct mesh_prov *prov)
{
	struct mesh_net *net = prov->net;
	struct mesh_net_prov_caps *caps = mesh_net_prov_caps_get(net);
	uint8_t prov_start[6] = { PROV_START };

	memset(prov_start + 1, 0, 1 + 1 + 1 + 1 + 1);
	if (!(caps->algorithms & 0x0001)) {
		/* We only support FIPS P-256 Elliptic Curve */
		l_error("Unrecognized Algorithm %4.4x", caps->algorithms);
		return;
	}

	if (caps->pub_type) {
		/* Prov Step 2b: New device exposed PublicKey OOB */
		prov_start[2] = 0x01;
		pub_key_type = PUB_KEY_TYPE_available;
	} else {
		pub_key_type = PUB_KEY_TYPE_ephemeral;
	}

	if (caps->output_size &&
			caps->output_action) {
		/* Prov Step 3a: Output OOB used */
		prov_start[3] = 0x02;
		prov_start[4] = u16_highest_bit(caps->output_action);
		prov_start[5] = caps->output_size > 8 ?
			8 : caps->output_size;

		prov_auth_type = AUTH_TYPE_3a;

	} else if (caps->input_size &&
			caps->input_action) {
		/* Prov Step 3b: Input OOB used */
		prov_start[3] = 0x03;
		prov_start[4] = u16_highest_bit(caps->input_action);
		prov_start[5] = caps->input_size > 8 ?
			8 : caps->input_size;

		prov_auth_type = AUTH_TYPE_3b;

	} else  {
		if (caps->static_type)
			prov_start[3] = 0x01;

		/* Prov Step 3c: Static OOB used (or no OOB available) */
		prov_auth_type = AUTH_TYPE_3c;
	}

	memcpy(&prov->conf_inputs.start, prov_start + 1,
					sizeof(prov->conf_inputs.start));

	int_prov_state = INT_PROV_START_SENT;
	if (pub_key_type == PUB_KEY_TYPE_ephemeral)
		prov_expected = PROV_PUB_KEY;
	else if (prov_auth_type == AUTH_TYPE_3b)
		prov_expected = PROV_INP_CMPLT;
	else
		prov_expected = PROV_CONFIRM;

	mesh_prov_send(prov, prov_start, 6,
			int_prov_send_cmplt, prov);

}

static void calculate_secrets(struct mesh_prov *prov, bool initiator)
{
	struct mesh_net *net = prov->net;
	uint8_t *priv_key = mesh_net_priv_key_get(net);
	bool test_mode = mesh_net_test_mode(net);
	uint8_t tmp[64];

	if (initiator) {
		memcpy(prov->conf_inputs.prv_pub_key,
					prov->l_public, sizeof(prov->l_public));
		memcpy(prov->conf_inputs.dev_pub_key,
					prov->r_public, sizeof(prov->r_public));
	} else {
		memcpy(prov->conf_inputs.prv_pub_key,
					prov->r_public, sizeof(prov->r_public));
		memcpy(prov->conf_inputs.dev_pub_key,
					prov->l_public, sizeof(prov->l_public));
	}

	/* Convert to Mesh byte order */
	memcpy(tmp, prov->r_public, 64);
	swap_u256_bytes(tmp);
	swap_u256_bytes(tmp + 32);

	ecdh_shared_secret(tmp, priv_key, prov->secret);

	/* Convert to Mesh byte order */
	swap_u256_bytes(prov->secret);

	mesh_crypto_s1(&prov->conf_inputs,
			sizeof(prov->conf_inputs), prov->conf_salt);


	mesh_crypto_prov_conf_key(prov->secret, prov->conf_salt,
							prov->conf_key);

	if (test_mode) {
		print_packet("PublicKeyRemote", prov->r_public, 64);
		print_packet("PublicKeyLocal", prov->l_public, 64);
		print_packet("PrivateKeyLocal", priv_key, 32);
		print_packet("ConfirmationInputs", &prov->conf_inputs,
						sizeof(prov->conf_inputs));
		print_packet("ECDHSecret", prov->secret,
						sizeof(prov->secret));
		print_packet("ConfirmationSalt", prov->conf_salt, 16);
		print_packet("ConfirmationKey", prov->conf_key,
						sizeof(prov->conf_key));
	}
}

static void send_prov_key(struct mesh_prov *prov,
					mesh_prov_send_func_t send_callback)
{
	uint8_t send_pub_key[65] = { PROV_PUB_KEY };

	memcpy(send_pub_key + 1, prov->l_public, 64);
	mesh_prov_send(prov, send_pub_key, 65,
			send_callback, prov);
}

static void send_prov_data(struct mesh_prov *prov)
{
	struct mesh_net *net = prov->net;
	struct mesh_net_prov_caps *caps = mesh_net_prov_caps_get(net);
	uint64_t mic;
	uint32_t iv_index;
	uint8_t snb_flags;
	uint16_t net_idx = mesh_prov_get_idx(prov);
	uint8_t prov_data[1 + 16 + 2 + 1 + 4 + 2 + sizeof(mic)] = { PROV_DATA };
	uint16_t uni_addr = mesh_net_prov_uni(net, caps->num_ele);
	bool test_mode = mesh_net_test_mode(net);

	/* Calculate Provisioning Data */
	prov_expected = PROV_COMPLETE;
	mesh_net_get_snb_state(net, &snb_flags, &iv_index);

	mesh_net_get_key(net, !!(snb_flags & 0x01), net_idx, prov_data + 1);
	l_put_be16(net_idx, prov_data + 1 + 16);
	l_put_u8(snb_flags, prov_data + 1 + 16 + 2);
	l_put_be32(iv_index, prov_data + 1 + 16 + 2 + 1);
	l_put_be16(uni_addr, prov_data + 1 + 16 + 2 + 1 + 4);

	if (test_mode)
		print_packet("Data", prov_data + 1, 16 + 2 + 1 + 4 + 2);

	mesh_crypto_device_key(prov->secret, prov->prov_salt, prov->dev_key);
	if (test_mode) {
		print_packet("DevKey", prov->dev_key, 16);
		print_packet("NetworkKey", prov_data + 1, 16);
		print_packet("NetworkKey Index", prov_data + 1 + 16, 2);
		print_packet("SNB Flags", prov_data + 1 + 16 + 2, 1);
		print_packet("IVindex", prov_data + 1 + 16 + 2 + 1, 4);
		print_packet("Unicast Addr", prov_data + 1 + 16 + 2 + 1 + 4, 2);
	}

	mesh_crypto_aes_ccm_encrypt(prov->s_nonce, prov->s_key,
					NULL, 0,
					&prov_data[1],
					sizeof(prov_data) - 1 - sizeof(mic),
					&prov_data[1],
					&mic, sizeof(mic));
	if (test_mode)
		print_packet("DataEncrypted + mic", prov_data + 1,
						sizeof(prov_data) - 1);

	int_prov_state = INT_PROV_DATA_SENT;
	mesh_prov_send(prov, prov_data, sizeof(prov_data),
			int_prov_send_cmplt, prov);
	mesh_prov_set_addr(prov, uni_addr);
}

static void send_prov_conf(struct mesh_prov *prov,
			mesh_prov_send_func_t send_callback)
{
	struct mesh_net *net = prov->net;
	uint8_t *test_rand = mesh_net_prov_rand(net);
	uint8_t prov_conf[1 + sizeof(prov->conf)] = { PROV_CONFIRM };
	bool test_mode = mesh_net_test_mode(net);

	if (test_mode && test_rand[0])
		memcpy(prov->rand_auth, test_rand, 16);
	else
		l_getrandom(prov->rand_auth, 16);

	/* Calculate Confirmation */
	mesh_crypto_aes_cmac(prov->conf_key, prov->rand_auth,
				sizeof(prov->rand_auth), prov->conf);

	/* Marshal Confirmation */
	memcpy(prov_conf + 1, prov->conf, sizeof(prov->conf));

	if (test_mode) {
		print_packet("ConfirmationKey", prov->conf_key,
						sizeof(prov->conf_key));
		print_packet("RandomAuthValue", prov->rand_auth,
						sizeof(prov->rand_auth));
		print_packet("Sending Confirmation", prov->conf,
						sizeof(prov->conf));
	}

	mesh_prov_send(prov, prov_conf, sizeof(prov_conf),
					send_callback, prov);
}

static void send_prov_rand(struct mesh_prov *prov,
			mesh_prov_send_func_t send_callback)
{
	struct mesh_net *net = prov->net;
	uint8_t prov_rand[17] = { PROV_RANDOM };
	bool test_mode = mesh_net_test_mode(net);

	/* Marshal Random */
	memcpy(prov_rand + 1, prov->rand_auth, 16);

	if (test_mode)
		print_packet("Sending Random", prov->rand_auth, 16);

	mesh_prov_send(prov, prov_rand, sizeof(prov_rand),
					send_callback, prov);
}

enum inputType {
	INP_key,
	INP_dec,
	INP_text,
};

struct input_data {
	struct mesh_prov *prov;
	enum inputType type;
	bool initiator;
	void *dest;
	void *user_data;
	union {
		struct {
			uint8_t idx;
			char data[129];
		} key;
		struct {
			uint64_t value;
		} dec;
		struct {
			uint8_t idx;
			char str[16];
		} text;
	} u;
};

static void collectInput(struct mesh_prov *prov, char *prompt,
					enum inputType type, bool initiator,
					void *dest, void *user_data)
{
	struct input_data *inp = l_new(struct input_data, 1);

	inp->prov = prov;
	inp->type = type;
	inp->dest = dest;
	inp->initiator = initiator;
	inp->user_data = user_data;

	if (prompt)
		l_info("%s", prompt);

	/* TODO: Request agent get OOB data */
}

static uint32_t digit_mod(uint8_t power)
{
	uint32_t ret = 1;

	while (power--)
		ret *= 10;

	return ret;
}

static char *key_type(uint8_t type)
{
	switch (type) {
	case 0x01:
		return "QR-Code";
	case 0x02:
		return "Barcode";
	case 0x03:
		return "NFC Tag";
	case 0x04:
		return "Printed Number";
	default:
		return "unknown Source";
	}
}

static void int_prov_send_cmplt(bool success, struct mesh_prov *prov)
{
	struct mesh_net *net = prov->net;
	struct mesh_net_prov_caps *caps = mesh_net_prov_caps_get(net);

	l_debug("Provision sending complete");

	switch (int_prov_state) {
	case INT_PROV_INVITE_SENT:
		int_prov_state = INT_PROV_INVITE_ACKED;
		if (acp_prov_state == ACP_PROV_CAPS_SENT)
			send_prov_start(prov);
		break;
	case INT_PROV_START_SENT:
		int_prov_state = INT_PROV_START_ACKED;
		if (pub_key_type == PUB_KEY_TYPE_ephemeral) {
			int_prov_state = INT_PROV_KEY_SENT;
			send_prov_key(prov, int_prov_send_cmplt);
		} else {
			collectInput(prov, NULL, INP_key, true,
						prov->r_public, prov);
			l_info("\n\nEnter key from %s:\n",
				key_type(caps->pub_type));
		}
		break;
	case INT_PROV_KEY_SENT:
		int_prov_state = INT_PROV_KEY_ACKED;
		if (pub_key_type == PUB_KEY_TYPE_ephemeral) {
			prov_expected = PROV_PUB_KEY;
			break;
		}

		/* Start Step 3 */
		memset(prov->rand_auth + 16, 0, 16);
		if (prov_auth_type == AUTH_TYPE_3a)
			collectInput(prov,
				"\n\nEnter prompted number from device:",
				INP_dec, true,
				prov->rand_auth + 32 - sizeof(uint32_t),
				prov);

		else if (prov_auth_type == AUTH_TYPE_3b) {
			uint32_t oob_key;

			l_getrandom(&oob_key, sizeof(uint32_t));
			oob_key %= digit_mod(caps->input_size);
			l_put_be32(oob_key,
					prov->rand_auth + 32 -
					sizeof(uint32_t));
			l_info("\n\nEnter %d on Device\n", oob_key);
			prov_expected = PROV_INP_CMPLT;

		} else if (caps->static_type) {
			collectInput(prov, NULL, INP_text, true,
					prov->rand_auth + 16, prov);
			l_info("\n\nstatic OOB str from %s:\n",
				key_type(caps->static_type));

		} else {
			int_prov_state = INT_PROV_CONF_SENT;
			send_prov_conf(prov, int_prov_send_cmplt);
		}

		break;
	case INT_PROV_CONF_SENT:
		int_prov_state = INT_PROV_CONF_ACKED;
		if (acp_prov_state == ACP_PROV_CONF_SENT) {
			int_prov_state = INT_PROV_RAND_SENT;
			prov_expected = PROV_RANDOM;
			send_prov_rand(prov, int_prov_send_cmplt);
		}
		break;
	case INT_PROV_RAND_SENT:
		int_prov_state = INT_PROV_RAND_ACKED;
		if (acp_prov_state == ACP_PROV_RAND_SENT)
			send_prov_data(prov);
		break;
	case INT_PROV_DATA_SENT:
		int_prov_state = INT_PROV_DATA_ACKED;
		break;
	default:
	case INT_PROV_INVITE_ACKED:
	case INT_PROV_START_ACKED:
	case INT_PROV_KEY_ACKED:
	case INT_PROV_CONF_ACKED:
	case INT_PROV_RAND_ACKED:
	case INT_PROV_DATA_ACKED:
	case INT_PROV_IDLE:
		break;
	}
}

void initiator_prov_open(struct mesh_prov *prov)
{
	uint8_t invite[] = { PROV_INVITE, 30 };
	uint8_t *priv_key;

	l_info("Provisioning link opened");

	priv_key = mesh_net_priv_key_get(prov->net);
	ecc_make_key(prov->l_public, priv_key);

	int_prov_state = INT_PROV_INVITE_SENT;
	prov_expected = PROV_CAPS;
	prov_last = -1;
	prov->conf_inputs.invite.attention = invite[1];
	mesh_prov_send(prov, invite, sizeof(invite),
					int_prov_send_cmplt, prov);
}

void initiator_prov_close(struct mesh_prov *prov, uint8_t reason)
{
	struct mesh_net *net = prov->net;
	uint32_t iv_index;
	uint8_t snb_flags;

	l_info("Provisioning link closed");

	/* Get the provisioned node's composition data*/
	if (reason == 0) {
		mesh_net_get_snb_state(net, &snb_flags, &iv_index);

		l_info("Save provisioner's DB");
	}
}

void initiator_prov_receive(const void *pkt, uint16_t size,
							struct mesh_prov *prov)
{
	struct mesh_net *net = prov->net;
	struct mesh_net_prov_caps *caps = mesh_net_prov_caps_get(net);
	bool test_mode = mesh_net_test_mode(net);
	const uint8_t *data = pkt;
	uint8_t tmp[16];
	uint8_t type = *data++;
	uint8_t err = 0;


	l_debug("Provisioning packet received type: %2.2x (%u octets)",
								type, size);

	if (type == prov_last) {
		l_error("Ignore repeated %2.2x packet", type);
		return;
	} else if ((type > prov_expected || type < prov_last) &&
						type != PROV_FAILED) {
		l_error("Expected %2.2x, Got:%2.2x", prov_expected, type);
		err = PROV_ERR_UNEXPECTED_PDU;
		goto failure;
	}

	if (type >= L_ARRAY_SIZE(expected_pdu_size) ||
					size != expected_pdu_size[type]) {
		l_error("Expected PDU size %d, Got %d (type: %2.2x)",
					expected_pdu_size[type], size, type);
		err = PROV_ERR_INVALID_FORMAT;
		goto failure;
	}

	prov_last = type;

	switch (type) {
	case PROV_CAPS: /* Capabilities */
		int_prov_state = INT_PROV_INVITE_ACKED;
		acp_prov_state = ACP_PROV_CAPS_SENT;
		caps->num_ele = data[0];
		if (test_mode)
			l_info("Got Num Ele %d", data[0]);

		caps->algorithms = l_get_be16(data + 1);
		if (test_mode)
			l_info("Got alg %d", caps->algorithms);

		caps->pub_type = data[3];
		if (test_mode)
			l_info("Got pub_type %d", data[3]);

		caps->static_type = data[4];
		if (test_mode)
			l_info("Got static_type %d", data[4]);

		caps->output_size = data[5];
		if (test_mode)
			l_info("Got output_size %d", data[5]);

		caps->output_action = l_get_be16(data + 6);
		if (test_mode)
			l_info("Got output_action %d", l_get_be16(data + 6));

		caps->input_size = data[8];
		if (test_mode)
			l_info("Got input_size %d", data[8]);

		caps->input_action = l_get_be16(data + 9);
		if (test_mode)
			l_info("Got input_action %d", l_get_be16(data + 9));

		if (caps->algorithms != 0x0001) {
			l_error("Unsupported Algorithm");
			err = PROV_ERR_INVALID_FORMAT;
			goto failure;
		}

		memcpy(&prov->conf_inputs.caps, data, 11);

		if (int_prov_state == INT_PROV_INVITE_ACKED)
			send_prov_start(prov);
		break;

	case PROV_PUB_KEY: /* Public Key */
		int_prov_state = INT_PROV_KEY_ACKED;
		acp_prov_state = ACP_PROV_KEY_SENT;
		memcpy(prov->r_public, data, 64);
		calculate_secrets(prov, true);
		prov_expected = PROV_CONFIRM;

		memset(prov->rand_auth + 16, 0, 16);
		if (prov_auth_type == AUTH_TYPE_3a) {
			collectInput(prov,
				"\n\nEnter number from device:",
				INP_dec, true,
				prov->rand_auth + 32 - sizeof(uint32_t),
				prov);

		} else if (prov_auth_type == AUTH_TYPE_3b) {

			uint32_t oob_key;

			l_getrandom(&oob_key, sizeof(uint32_t));
			oob_key %= digit_mod(caps->input_size);
			l_put_be32(oob_key,
					prov->rand_auth + 32 -
					sizeof(uint32_t));
			l_info("\n\nEnter %d on Device\n", oob_key);
			prov_expected = PROV_INP_CMPLT;

		} else if (caps->static_type) {
			collectInput(prov, NULL, INP_dec, true,
					prov->rand_auth + 16, prov);
			l_info("\n\nstatic OOB str from %s:\n",
				key_type(caps->static_type));

		} else
			send_prov_conf(prov, int_prov_send_cmplt);
		break;

	case PROV_INP_CMPLT: /* Provisioning Input Complete */
		acp_prov_state = ACP_PROV_INP_CMPLT_SENT;
		prov_expected = PROV_CONFIRM;
		send_prov_conf(prov, int_prov_send_cmplt);
		break;

	case PROV_CONFIRM: /* Confirmation */
		int_prov_state = INT_PROV_CONF_ACKED;
		acp_prov_state = ACP_PROV_CONF_SENT;
		/* RXed Device Confirmation */
		memcpy(prov->conf, data, sizeof(prov->conf));
		if (test_mode)
			print_packet("ConfirmationDevice", prov->conf,
							sizeof(prov->conf));

		if (int_prov_state == INT_PROV_CONF_ACKED) {
			prov_expected = PROV_RANDOM;
			send_prov_rand(prov, int_prov_send_cmplt);
		}
		break;

	case PROV_RANDOM: /* Random */
		int_prov_state = INT_PROV_RAND_ACKED;
		acp_prov_state = ACP_PROV_RAND_SENT;

		/* Calculate SessionKey while the data is fresh */
		mesh_crypto_prov_prov_salt(prov->conf_salt,
						prov->rand_auth, data,
						prov->prov_salt);
		mesh_crypto_session_key(prov->secret, prov->prov_salt,
							prov->s_key);
		mesh_crypto_nonce(prov->secret, prov->prov_salt, prov->s_nonce);
		if (test_mode) {
			print_packet("SessionKey", prov->s_key,
					sizeof(prov->s_key));
			print_packet("Nonce", prov->s_nonce,
					sizeof(prov->s_nonce));
		}

		/* RXed Device Confirmation */
		memcpy(prov->rand_auth, data, sizeof(prov->conf));
		if (test_mode)
			print_packet("RandomDevice", prov->rand_auth, 16);

		mesh_crypto_aes_cmac(prov->conf_key, prov->rand_auth,
					sizeof(prov->rand_auth), tmp);

		if (memcmp(tmp, prov->conf, sizeof(prov->conf))) {
			l_error("Provisioning Failed-Confirm compare)");
			err = PROV_ERR_CONFIRM_FAILED;
			goto failure;
		}

		if (int_prov_state == INT_PROV_RAND_ACKED) {
			prov_expected = PROV_COMPLETE;
			send_prov_data(prov);
		}
		break;

	case PROV_COMPLETE: /* Complete */
		l_info("Provisioning Complete");
		int_prov_state = INT_PROV_IDLE;
		mesh_prov_close(prov, 0);
		break;

	case PROV_FAILED: /* Failed */
		l_error("Provisioning Failed (reason: %d)", data[0]);
		err = data[0];
		goto failure;

	default:
		l_error("Unknown Pkt %2.2x", type);
		err = PROV_ERR_UNEXPECTED_PDU;
		goto failure;
	}

	return;

failure:
	int_prov_state = INT_PROV_IDLE;
	mesh_prov_close(prov, err);
}

static void acp_prov_send_cmplt(bool success, struct mesh_prov *prov)
{
	l_debug("Provision sending complete");

	switch (acp_prov_state) {
	case ACP_PROV_CAPS_SENT:
		acp_prov_state = ACP_PROV_CAPS_ACKED;
		if (int_prov_state == INT_PROV_KEY_SENT) {
			acp_prov_state = ACP_PROV_KEY_SENT;
			prov_expected = PROV_CONFIRM;
			send_prov_key(prov, acp_prov_send_cmplt);
		}
		break;
	case ACP_PROV_KEY_SENT:
		acp_prov_state = ACP_PROV_KEY_ACKED;
		if (int_prov_state == INT_PROV_CONF_SENT) {
			acp_prov_state = ACP_PROV_CONF_SENT;
			prov_expected = PROV_RANDOM;
			send_prov_conf(prov, acp_prov_send_cmplt);
		}
		break;
	case ACP_PROV_INP_CMPLT_SENT:
		acp_prov_state = ACP_PROV_INP_CMPLT_ACKED;
		break;
	case ACP_PROV_CONF_SENT:
		acp_prov_state = ACP_PROV_CONF_ACKED;
		if (int_prov_state == INT_PROV_RAND_SENT) {
			acp_prov_state = ACP_PROV_RAND_SENT;
			prov_expected = PROV_DATA;
			send_prov_rand(prov, acp_prov_send_cmplt);
		}
		break;
	case ACP_PROV_RAND_SENT:
		acp_prov_state = ACP_PROV_RAND_ACKED;
		break;
	case ACP_PROV_CMPLT_SENT:
		acp_prov_state = ACP_PROV_IDLE;
		mesh_net_provisioned_set(prov->net, true);
	default:
	case ACP_PROV_IDLE:
	case ACP_PROV_CAPS_ACKED:
	case ACP_PROV_KEY_ACKED:
	case ACP_PROV_INP_CMPLT_ACKED:
	case ACP_PROV_CONF_ACKED:
	case ACP_PROV_RAND_ACKED:
	case ACP_PROV_FAIL_SENT:
		break;
	}
}

void acceptor_prov_open(struct mesh_prov *prov)
{
	uint8_t *priv_key;

	l_info("Provisioning link opened");

	priv_key = mesh_net_priv_key_get(prov->net);
	ecc_make_key(prov->l_public, priv_key);

	prov_expected = PROV_INVITE;
	prov_last = -1;
}

void acceptor_prov_close(struct mesh_prov *prov, uint8_t reason)
{
	l_info("Provisioning link closed");
	mesh_prov_unref(prov);
}

static void prov_store_cfm(void *user_data, bool result)
{
	struct mesh_prov *prov = user_data;
	uint8_t out[2];

	if (result) {
		acp_prov_state = ACP_PROV_CMPLT_SENT;
		out[0] = PROV_COMPLETE;
		mesh_prov_send(prov, out, 1,
				acp_prov_send_cmplt,
				prov);
	} else {
		acp_prov_state = ACP_PROV_FAIL_SENT;
		out[0] = PROV_FAILED;
		out[1] = PROV_ERR_INSUF_RESOURCE;
		mesh_prov_send(prov, out, 2, NULL, NULL);
	}
}

void acceptor_prov_receive(const void *pkt, uint16_t size,
							struct mesh_prov *prov)
{
	struct mesh_net *net = prov->net;
	struct mesh_net_prov_caps *caps = mesh_net_prov_caps_get(net);
	uint8_t *priv_key = mesh_net_priv_key_get(net);
	bool test_mode = mesh_net_test_mode(net);
	bool ret;
	const uint8_t *data = pkt;
	uint8_t type = *data++;
	uint8_t out[129];
	uint8_t tmp[16];
	uint8_t rand_dev[16];
	uint64_t rx_mic, decode_mic;

	l_debug("Provisioning packet received type: %2.2x (%u octets)",
								type, size);

	if (type == prov_last) {
		l_error("Ignore repeated %2.2x packet", type);
		return;
	} else if (type > prov_expected || type < prov_last) {
		l_error("Expected %2.2x, Got:%2.2x", prov_expected, type);
		out[1] = PROV_ERR_UNEXPECTED_PDU;
		goto failure;
	}

	if (type >= L_ARRAY_SIZE(expected_pdu_size) ||
					size != expected_pdu_size[type]) {
		l_error("Expected PDU size %d, Got %d (type: %2.2x)",
			size, expected_pdu_size[type], type);
		out[1] = PROV_ERR_INVALID_FORMAT;
		goto failure;
	}

	prov_last = type;

	switch (type) {
	case PROV_INVITE: /* Prov Invite */
		int_prov_state = INT_PROV_INVITE_SENT;
		/* Prov Capabilities */
		out[0] = PROV_CAPS;
		out[1] = caps->num_ele;
		l_put_be16(caps->algorithms, out + 2);
		out[4] = caps->pub_type;
		out[5] = caps->static_type;
		out[6] = caps->output_size;
		l_put_be16(caps->output_action, out + 7);
		out[9] = caps->input_size;
		l_put_be16(caps->input_action, out + 10);

		prov->conf_inputs.invite.attention = data[0];
		memcpy(&prov->conf_inputs.caps, out + 1,
				sizeof(prov->conf_inputs.caps));

		acp_prov_state = ACP_PROV_CAPS_SENT;
		prov_expected = PROV_START;
		mesh_prov_send(prov, out, sizeof(*caps) + 1,
				acp_prov_send_cmplt, prov);
		break;

	case PROV_START: /* Prov Start */
		if (data[0]) {
			/* Only Algorithm 0x00 supported */
			l_error("Invalid Algorithm: %2.2x", data[0]);
			out[1] = PROV_ERR_INVALID_FORMAT;
			goto failure;
		}

		acp_prov_state = ACP_PROV_CAPS_ACKED;
		int_prov_state = INT_PROV_START_SENT;
		prov_expected = PROV_PUB_KEY;
		memcpy(&prov->conf_inputs.start, data,
				sizeof(prov->conf_inputs.start));
		if (data[1] == 1 && caps->pub_type) {
			pub_key_type = PUB_KEY_TYPE_available;
			ecc_make_key(prov->l_public, priv_key);
		} else if (data[1] == 0) {
			pub_key_type = PUB_KEY_TYPE_ephemeral;
			/* Use Ephemeral Key */
			l_getrandom(priv_key, 32);
			ecc_make_key(prov->l_public, priv_key);
		} else {
			out[1] = PROV_ERR_INVALID_FORMAT;
			goto failure;
		}

		swap_u256_bytes(prov->l_public);
		swap_u256_bytes(prov->l_public + 32);

		switch (data[2]) {
		default:
			out[1] = PROV_ERR_INVALID_FORMAT;
			goto failure;

		case 0x00:
		case 0x01:
			prov_auth_type = AUTH_TYPE_3c;
			break;

		case 0x02:
			prov_auth_type = AUTH_TYPE_3a;
			caps->output_action = 1 << data[3];
			caps->output_size = data[4];
			break;

		case 0x03:
			prov_auth_type = AUTH_TYPE_3b;
			caps->input_action = 1 << data[3];
			caps->input_size = data[4];
			break;
		}
		break;

	case PROV_PUB_KEY: /* Public Key */
		int_prov_state = INT_PROV_KEY_SENT;
		prov_expected = PROV_CONFIRM;
		/* Save Key */
		memcpy(prov->r_public, data, 64);
		calculate_secrets(prov, false);

		if (pub_key_type == PUB_KEY_TYPE_ephemeral) {
			acp_prov_state = ACP_PROV_KEY_SENT;
			send_prov_key(prov, acp_prov_send_cmplt);
		}

		/* Start Step 3 */
		memset(prov->rand_auth + 16, 0, 16);
		if (prov_auth_type == AUTH_TYPE_3a) {
			uint32_t oob_key;

			l_getrandom(&oob_key, sizeof(uint32_t));
			oob_key %= digit_mod(caps->output_size);
			l_put_be32(oob_key,
				prov->rand_auth + 32 - sizeof(uint32_t));
			l_info("\n\nEnter %d on Provisioner\n",
							oob_key);

		} else if (prov_auth_type == AUTH_TYPE_3b) {
			if (caps->input_action == (1 << 3)) {
				/* TODO: Collect Text Input data */
				;
			} else {
				/* TODO: Collect Decimal Input data */
				;
			}

		} else {
			if (caps->static_type) {
				/* TODO: Collect Static Input data */
				/* (If needed) */
				;
			}
		}

		break;

	case PROV_CONFIRM: /* Confirmation */
		int_prov_state = INT_PROV_CONF_SENT;
		acp_prov_state = ACP_PROV_KEY_ACKED;
		/* RXed Provision Confirmation */
		memcpy(prov->r_conf, data, sizeof(prov->r_conf));
		if (test_mode)
			print_packet("ConfirmationProvisioner",
					prov->r_conf,
					sizeof(prov->r_conf));

		if (acp_prov_state == ACP_PROV_KEY_ACKED) {
			prov_expected = PROV_RANDOM;
			send_prov_conf(prov, acp_prov_send_cmplt);
		}
		break;

	case PROV_RANDOM: /* Random */
		int_prov_state = INT_PROV_RAND_SENT;
		acp_prov_state = ACP_PROV_CONF_ACKED;

		/* Calculate Session key while the data is fresh */
		mesh_crypto_prov_prov_salt(prov->conf_salt, data,
						prov->rand_auth,
						prov->prov_salt);
		mesh_crypto_session_key(prov->secret, prov->prov_salt,
							prov->s_key);
		mesh_crypto_nonce(prov->secret, prov->prov_salt, prov->s_nonce);

		if (test_mode) {
			print_packet("SessionKey", prov->s_key,
					sizeof(prov->s_key));
			print_packet("Nonce", prov->s_nonce,
					sizeof(prov->s_nonce));
		}


		/* Save Local Random data to send after verification */
		memcpy(rand_dev, prov->rand_auth, 16);
		/* RXed Provisioner Confirmation */
		memcpy(prov->rand_auth, data, 16);
		if (test_mode)
			print_packet("RandomProvisioner", prov->rand_auth, 16);

		mesh_crypto_aes_cmac(prov->conf_key, prov->rand_auth,
					sizeof(prov->rand_auth), tmp);

		if (memcmp(tmp, prov->r_conf,
					sizeof(prov->r_conf))) {
			l_error("Provisioning Failed-Confirm compare");
			out[1] = PROV_ERR_CONFIRM_FAILED;
			goto failure;
		}


		memcpy(prov->rand_auth, rand_dev, 16);
		if (acp_prov_state == ACP_PROV_CONF_ACKED) {
			prov_expected = PROV_DATA;
			send_prov_rand(prov, acp_prov_send_cmplt);
		}
		break;

	case PROV_DATA: /* Provisioning Data */
		int_prov_state = INT_PROV_DATA_SENT;
		acp_prov_state = ACP_PROV_RAND_ACKED;
		if (test_mode) {
			print_packet("DataEncrypted + mic", data, size - 1);
			print_packet("Rxed-mic", data + 16 + 2 + 1 + 4 + 2, 8);
		}

		rx_mic = l_get_be64(data + 16 + 2 + 1 + 4 + 2);
		mesh_crypto_aes_ccm_decrypt(prov->s_nonce, prov->s_key,
				NULL, 0,
				data, size - 1, out + 1,
				&decode_mic, sizeof(decode_mic));

		if (test_mode) {
			print_packet("Data", out + 1, 16 + 2 + 1 + 4 + 2);
			l_info("Calc-mic: %16.16lx", decode_mic);
		}

		if (rx_mic == decode_mic) {
			mesh_crypto_device_key(prov->secret,
						prov->prov_salt,
						prov->dev_key);
			if (test_mode) {
				print_packet("DevKey", prov->dev_key, 16);
				print_packet("NetworkKey", out + 1, 16);
				print_packet("NetworkKey Index",
					out + 1 + 16, 2);
				print_packet("SNB Flags",
					out + 1 + 16 + 2, 1);
				print_packet("IVindex",
					out + 1 + 16 + 2 + 1, 4);
				print_packet("Unicast Addr",
					out + 1 + 16 + 2 + 1 + 4, 2);
			}

			/* Set Provisioned Data */
			ret = mesh_net_provisioned_new(prov->net,
					prov->dev_key,
					l_get_be16(out + 17),
					out + 1,
					l_get_be16(out + 24),
					out[19],
					l_get_be32(out + 20),
					prov_store_cfm, prov);

			if (!ret) {
				out[1] = PROV_ERR_INSUF_RESOURCE;
				goto failure;
			}
		} else {
			l_error("Provisioning Failed-MIC compare");
			out[1] = PROV_ERR_DECRYPT_FAILED;
			goto failure;
		}
		break;

	default:
		l_error("Unknown Pkt %2.2x", type);
		out[1] = PROV_ERR_UNEXPECTED_PDU;
		goto failure;
	}

	return;

failure:
	acp_prov_state = ACP_PROV_FAIL_SENT;
	out[0] = PROV_FAILED;
	mesh_prov_send(prov, out, 2, acp_prov_send_cmplt, prov);
}
