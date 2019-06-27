/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "mesh/crypto.h"
#include "mesh/net-keys.h"

#define BEACON_TYPE_SNB		0x01
#define KEY_REFRESH		0x01
#define IV_INDEX_UPDATE		0x02

struct net_key {
	uint32_t id;
	uint16_t ref_cnt;
	uint8_t friend_key;
	uint8_t nid;
	uint8_t master[16];
	uint8_t encrypt[16];
	uint8_t privacy[16];
	uint8_t beacon[16];
	uint8_t network[8];
};

static struct l_queue *keys = NULL;
static uint32_t last_master_id = 0;

/* To avoid re-decrypting same packet for multiple nodes, cache and check */
static uint8_t cache_pkt[29];
static uint8_t cache_plain[29];
static size_t cache_len;
static size_t cache_plainlen;
static uint32_t cache_id;
static uint32_t cache_iv_index;

static bool match_master(const void *a, const void *b)
{
	const struct net_key *key = a;

	return (memcmp(key->master, b, sizeof(key->master)) == 0);
}

static bool match_id(const void *a, const void *b)
{
	const struct net_key *key = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return id == key->id;
}

static bool match_network(const void *a, const void *b)
{
	const struct net_key *key = a;
	const uint8_t *network = b;

	return memcmp(key->network, network, sizeof(key->network)) == 0;
}

/* Key added from Provisioning, NetKey Add or NetKey update */
uint32_t net_key_add(const uint8_t master[16])
{
	struct net_key *key = l_queue_find(keys, match_master, master);
	uint8_t p[] = {0};
	bool result;

	if (key) {
		key->ref_cnt++;
		return key->id;
	}

	if (!keys)
		keys = l_queue_new();

	key = l_new(struct net_key, 1);
	memcpy(key->master, master, 16);
	key->ref_cnt++;
	result = mesh_crypto_k2(master, p, sizeof(p), &key->nid, key->encrypt,
								key->privacy);
	if (!result)
		goto fail;

	result = mesh_crypto_k3(master, key->network);
	if (!result)
		goto fail;

	result = mesh_crypto_nkbk(master, key->beacon);
	if (!result)
		goto fail;

	key->id = ++last_master_id;
	l_queue_push_tail(keys, key);
	return key->id;

fail:
	l_free(key);
	return 0;
}

uint32_t net_key_frnd_add(uint32_t master_id, uint16_t lpn, uint16_t frnd,
					uint16_t lp_cnt, uint16_t fn_cnt)
{
	const struct net_key *key = l_queue_find(keys, match_id,
						L_UINT_TO_PTR(master_id));
	struct net_key *frnd_key;
	uint8_t p[9] = {0x01};
	bool result;

	if (!key || key->friend_key)
		return 0;

	frnd_key = l_new(struct net_key, 1);

	l_put_be16(lpn, p + 1);
	l_put_be16(frnd, p + 3);
	l_put_be16(lp_cnt, p + 5);
	l_put_be16(fn_cnt, p + 7);

	result = mesh_crypto_k2(key->master, p, sizeof(p), &frnd_key->nid,
				frnd_key->encrypt, frnd_key->privacy);

	if (!result) {
		l_free(frnd_key);
		return 0;
	}

	frnd_key->friend_key = true;
	frnd_key->ref_cnt++;
	frnd_key->id = ++last_master_id;
	l_queue_push_head(keys, frnd_key);

	return frnd_key->id;
}

void net_key_unref(uint32_t id)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (key && key->ref_cnt) {
		if (--key->ref_cnt == 0) {
			l_queue_remove(keys, key);
			l_free(key);
		}
	}
}

bool net_key_confirm(uint32_t id, const uint8_t *master)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (key)
		return memcmp(key->master, master, sizeof(key->master)) == 0;

	return false;
}

bool net_key_retrieve(uint32_t id, uint8_t *master)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (key) {
		memcpy(master, key->master, sizeof(key->master));
		return true;
	}

	return false;
}

static void decrypt_net_pkt(void *a, void *b)
{
	const struct net_key *key = a;
	bool result;

	if (cache_id || !key->ref_cnt || (cache_pkt[0] & 0x7f) != key->nid)
		return;

	result = mesh_crypto_packet_decode(cache_pkt, cache_len, false,
						cache_plain, cache_iv_index,
						key->encrypt, key->privacy);

	if (result) {
		cache_id = key->id;
		if (cache_plain[1] & 0x80)
			cache_plainlen = cache_len - 8;
		else
			cache_plainlen = cache_len - 4;
	}
}

uint32_t net_key_decrypt(uint32_t iv_index, const uint8_t *pkt, size_t len,
					uint8_t **plain, size_t *plain_len)
{
	/* If we already successfully decrypted this packet, use cached data */
	if (cache_id && cache_len == len && !memcmp(pkt, cache_pkt, len)) {
		/* IV Index must match what was used to decrypt */
		if (cache_iv_index != iv_index)
			return 0;

		goto done;
	}

	cache_id = 0;
	memcpy(cache_pkt, pkt, len);
	cache_len = len;
	cache_iv_index = iv_index;

	/* Try all network keys known to us */
	l_queue_foreach(keys, decrypt_net_pkt, NULL);

done:
	if (cache_id) {
		*plain = cache_plain;
		*plain_len = cache_plainlen;
	}

	return cache_id;
}

bool net_key_encrypt(uint32_t id, uint32_t iv_index, uint8_t *pkt, size_t len)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));
	bool result;

	if (!key)
		return false;

	result = mesh_crypto_packet_encode(pkt, len, key->encrypt, iv_index,
							key->privacy);

	if (!result)
		return false;

	result = mesh_crypto_packet_label(pkt, len, iv_index, key->nid);

	return result;
}

uint32_t net_key_network_id(const uint8_t network[8])
{
	struct net_key *key = l_queue_find(keys, match_network, network);

	if (!key)
		return 0;

	return key->id;
}

bool net_key_snb_check(uint32_t id, uint32_t iv_index, bool kr, bool ivu,
								uint64_t cmac)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));
	uint64_t cmac_check;

	if (!key)
		return false;

	/* Any behavioral changes must pass CMAC test */
	if (!mesh_crypto_beacon_cmac(key->beacon, key->network, iv_index, kr,
							ivu, &cmac_check)) {
		l_error("mesh_crypto_beacon_cmac failed");
		return false;
	}

	if (cmac != cmac_check) {
		l_error("cmac compare failed 0x%16" PRIx64 " != 0x%16" PRIx64,
						cmac, cmac_check);
		return false;
	}

	return true;
}

bool net_key_snb_compose(uint32_t id, uint32_t iv_index, bool kr, bool ivu,
								uint8_t *snb)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));
	uint64_t cmac;

	if (!key)
		return false;

	/* Any behavioral changes must pass CMAC test */
	if (!mesh_crypto_beacon_cmac(key->beacon, key->network, iv_index, kr,
								ivu, &cmac)) {
		l_error("mesh_crypto_beacon_cmac failed");
		return false;
	}

	snb[0] = BEACON_TYPE_SNB;
	snb[1] = 0;

	if (kr)
		snb[1] |= KEY_REFRESH;

	if (ivu)
		snb[1] |= IV_INDEX_UPDATE;

	memcpy(snb + 2, key->network, 8);
	l_put_be32(iv_index, snb + 10);
	l_put_be64(cmac, snb + 14);

	return true;
}
