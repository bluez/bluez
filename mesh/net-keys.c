// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <time.h>

#include <ell/ell.h>

#include "src/shared/ad.h"

#include "mesh/mesh-defs.h"
#include "mesh/util.h"
#include "mesh/crypto.h"
#include "mesh/mesh-io.h"
#include "mesh/net.h"
#include "mesh/net-keys.h"

#define BEACON_INTERVAL_MIN	10
#define BEACON_INTERVAL_MAX	600

/* This allows daemon to skip decryption on recently seen beacons */
#define BEACON_CACHE_MAX	10

struct beacon_rx {
	uint8_t data[BEACON_LEN_MAX];
	uint32_t id;
	uint32_t ivi;
	bool kr;
	bool ivu;
};

struct beacon_observe {
	struct l_timeout *timeout;
	uint32_t ts;
	uint16_t period;
	uint16_t seen;
	uint16_t expected;
	bool half_period;
};

struct net_key {
	uint32_t id;
	struct l_timeout *mpb_to;
	uint8_t *mpb;
	uint8_t *snb;
	struct beacon_observe observe;
	uint32_t ivi;
	uint16_t ref_cnt;
	uint16_t mpb_enables;
	uint16_t snb_enables;
	uint8_t mpb_refresh;
	uint8_t friend_key;
	uint8_t nid;
	uint8_t flooding[16];
	uint8_t enc_key[16];
	uint8_t prv_key[16];
	uint8_t snb_key[16];
	uint8_t pvt_key[16];
	uint8_t net_id[8];
	bool kr;
	bool ivu;
};

static struct l_queue *beacons;
static struct l_queue *keys;
static uint32_t last_flooding_id;

/* To avoid re-decrypting same packet for multiple nodes, cache and check */
static uint8_t cache_pkt[MESH_NET_MAX_PDU_LEN];
static uint8_t cache_plain[MESH_NET_MAX_PDU_LEN];
static size_t cache_len;
static size_t cache_plainlen;
static uint32_t cache_id;
static uint32_t cache_iv_index;

static bool match_flooding(const void *a, const void *b)
{
	const struct net_key *key = a;

	return (memcmp(key->flooding, b, sizeof(key->flooding)) == 0);
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
	const uint8_t *net_id = b;

	return memcmp(key->net_id, net_id, sizeof(key->net_id)) == 0;
}

/* Key added from Provisioning, NetKey Add or NetKey update */
uint32_t net_key_add(const uint8_t flooding[16])
{
	struct net_key *key = l_queue_find(keys, match_flooding, flooding);
	uint8_t p[] = {0};
	bool result;

	if (key) {
		key->ref_cnt++;
		return key->id;
	}

	if (!keys)
		keys = l_queue_new();

	if (!beacons)
		beacons = l_queue_new();

	key = l_new(struct net_key, 1);
	memcpy(key->flooding, flooding, 16);
	key->ref_cnt++;
	key->mpb_refresh = NET_MPB_REFRESH_DEFAULT;
	result = mesh_crypto_k2(flooding, p, sizeof(p), &key->nid, key->enc_key,
								key->prv_key);
	if (!result)
		goto fail;

	result = mesh_crypto_k3(flooding, key->net_id);
	if (!result)
		goto fail;

	result = mesh_crypto_nkbk(flooding, key->snb_key);
	if (!result)
		goto fail;

	result = mesh_crypto_nkpk(flooding, key->pvt_key);
	if (!result)
		goto fail;

	key->id = ++last_flooding_id;
	l_queue_push_tail(keys, key);
	return key->id;

fail:
	l_free(key);
	return 0;
}

uint32_t net_key_frnd_add(uint32_t flooding_id, uint16_t lpn, uint16_t frnd,
					uint16_t lp_cnt, uint16_t fn_cnt)
{
	const struct net_key *key = l_queue_find(keys, match_id,
						L_UINT_TO_PTR(flooding_id));
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

	result = mesh_crypto_k2(key->flooding, p, sizeof(p), &frnd_key->nid,
				frnd_key->enc_key, frnd_key->prv_key);

	if (!result) {
		l_free(frnd_key);
		return 0;
	}

	frnd_key->friend_key = true;
	frnd_key->ref_cnt++;
	frnd_key->id = ++last_flooding_id;
	l_queue_push_head(keys, frnd_key);

	return frnd_key->id;
}

void net_key_unref(uint32_t id)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (key && key->ref_cnt) {
		if (--key->ref_cnt == 0) {
			l_timeout_remove(key->observe.timeout);
			l_queue_remove(keys, key);
			l_free(key);
		}
	}
}

bool net_key_confirm(uint32_t id, const uint8_t flooding[16])
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (key)
		return !memcmp(key->flooding, flooding, sizeof(key->flooding));

	return false;
}

bool net_key_retrieve(uint32_t id, uint8_t *flooding)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (key) {
		memcpy(flooding, key->flooding, sizeof(key->flooding));
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
						key->enc_key, key->prv_key);

	if (result) {
		cache_id = key->id;
		cache_plainlen = cache_len;
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

	result = mesh_crypto_packet_encode(pkt, len, iv_index, key->enc_key,
							key->prv_key);

	if (!result)
		return false;

	result = mesh_crypto_packet_label(pkt, len, iv_index, key->nid);

	return result;
}

uint32_t net_key_network_id(const uint8_t net_id[8])
{
	struct net_key *key = l_queue_find(keys, match_network, net_id);

	if (!key)
		return 0;

	return key->id;
}

struct auth_check {
	const uint8_t *data;
	uint32_t id;
	uint32_t ivi;
	bool ivu;
	bool kr;
};

static void check_auth(void *a, void *b)
{
	struct net_key *key = a;
	struct auth_check *auth = b;
	uint8_t out[5];


	/* Stop checking if already found */
	if (auth->id)
		return;

	if (mesh_crypto_aes_ccm_decrypt(auth->data + 1, key->pvt_key, NULL, 0,
							auth->data + 14, 13,
							out, NULL, 8)) {
		auth->id = key->id;
		auth->ivi = l_get_be32(out + 1);
		auth->ivu = !!(out[0] & 0x02);
		auth->kr = !!(out[0] & 0x01);
	}
}

static uint32_t private_beacon_check(const void *beacon, uint32_t *ivi,
							bool *ivu, bool *kr)
{
	struct auth_check auth = {
		.data = beacon,
		.id = 0,
	};

	auth.id = 0;
	l_queue_foreach(keys, check_auth, &auth);

	if (auth.id) {
		*ivi = auth.ivi;
		*ivu = auth.ivu;
		*kr = auth.kr;
	}

	return auth.id;
}

bool net_key_snb_check(uint32_t id, uint32_t iv_index, bool kr, bool ivu,
								uint64_t cmac)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));
	uint64_t cmac_check;

	if (!key)
		return false;

	/* Any behavioral changes must pass CMAC test */
	if (!mesh_crypto_beacon_cmac(key->snb_key, key->net_id, iv_index, kr,
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

static bool mpb_compose(struct net_key *key, uint32_t ivi, bool kr, bool ivu)
{
	uint8_t b_data[5 + 8];
	uint8_t random[13];

	if (!key)
		return false;

	b_data[0] = 0;
	l_put_be32(ivi, b_data + 1);

	if (kr)
		b_data[0] |= KEY_REFRESH;

	if (ivu)
		b_data[0] |= IV_INDEX_UPDATE;

	l_getrandom(random, sizeof(random));
	if (!mesh_crypto_aes_ccm_encrypt(random, key->pvt_key, NULL, 0,
						b_data, 5, b_data, 8))
		return false;

	key->mpb[0] = BT_AD_MESH_BEACON;
	key->mpb[1] = BEACON_TYPE_MPB;
	memcpy(key->mpb + 2, random, 13);
	memcpy(key->mpb + 15, b_data, 13);

	return true;
}

static bool snb_compose(struct net_key *key, uint32_t ivi, bool kr, bool ivu)
{
	uint64_t cmac;

	if (!key)
		return false;

	/* Any behavioral changes must pass CMAC test */
	if (!mesh_crypto_beacon_cmac(key->snb_key, key->net_id, ivi, kr,
								ivu, &cmac)) {
		l_error("mesh_crypto_beacon_cmac failed");
		return false;
	}

	key->snb[0] = BT_AD_MESH_BEACON;
	key->snb[1] = BEACON_TYPE_SNB;
	key->snb[2] = 0;

	if (kr)
		key->snb[2] |= KEY_REFRESH;

	if (ivu)
		key->snb[2] |= IV_INDEX_UPDATE;

	memcpy(key->snb + 3, key->net_id, 8);
	l_put_be32(ivi, key->snb + 11);
	l_put_be64(cmac, key->snb + 15);

	return true;
}

static bool match_beacon(const void *a, const void *b)
{
	const struct beacon_rx *cached = a;
	const uint8_t *incoming = b;

	if (incoming[0] == BEACON_TYPE_MPB)
		return !memcmp(cached->data, incoming, BEACON_LEN_MPB - 1);

	if (incoming[0] == BEACON_TYPE_SNB)
		return !memcmp(cached->data, incoming, BEACON_LEN_SNB - 1);

	return false;
}

uint32_t net_key_beacon(const uint8_t *data, uint16_t len, uint32_t *ivi,
							bool *ivu, bool *kr)
{
	struct net_key *key;
	struct beacon_rx *beacon;
	uint32_t b_id, b_ivi;
	bool b_ivu, b_kr;

	if (data[1] == BEACON_TYPE_SNB && len != BEACON_LEN_SNB)
		return 0;

	if (data[1] == BEACON_TYPE_MPB && len != BEACON_LEN_MPB)
		return 0;

	beacon = l_queue_remove_if(beacons, match_beacon, data + 1);

	if (beacon)
		goto accept;

	/* Validate beacon data */
	if (data[1] == BEACON_TYPE_SNB) {
		key = l_queue_find(keys, match_network, data + 3);

		if (!key)
			return 0;

		b_id = key->id;
		b_ivu = !!(data[2] & 0x02);
		b_kr = !!(data[2] & 0x01);
		b_ivi = l_get_be32(data + 11);

		if (!net_key_snb_check(b_id, b_ivi, b_kr, b_ivu,
							l_get_be64(data + 15)))
			return 0;

	} else if (data[1] == BEACON_TYPE_MPB) {
		b_id = private_beacon_check(data + 1, &b_ivi, &b_ivu, &b_kr);

		if (!b_id)
			return 0;

	} else
		return 0;

	beacon = l_new(struct beacon_rx, 1);
	memcpy(beacon->data, data + 1, len - 1);
	beacon->id = b_id;
	beacon->ivi = b_ivi;
	beacon->ivu = b_ivu;
	beacon->kr = b_kr;

accept:
	*ivi = beacon->ivi;
	*ivu = beacon->ivu;
	*kr = beacon->kr;

	l_queue_push_head(beacons, beacon);

	return beacon->id;
}

static void send_network_beacon(struct net_key *key)
{
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = 100,
		.u.gen.cnt = 1,
		.u.gen.min_delay = DEFAULT_MIN_DELAY,
		.u.gen.max_delay = DEFAULT_MAX_DELAY
	};

	if (key->mpb_enables) {
		/* If Interval steps == 0, refresh key every time */
		if (!key->mpb_refresh || !key->mpb || !key->mpb[0])
			net_key_beacon_refresh(key->id, key->ivi, key->kr,
								key->ivu, true);

		mesh_io_send(NULL, &info, key->mpb, BEACON_LEN_MPB);
	}

	if (key->snb_enables) {
		if (!key->snb || !key->snb[0]) {
			net_key_beacon_refresh(key->id, key->ivi, key->kr,
								key->ivu, true);
		}

		mesh_io_send(NULL, &info, key->snb, BEACON_LEN_SNB);
	}
}

static void beacon_timeout(struct l_timeout *timeout, void *user_data)
{
	struct net_key *key = user_data;
	uint32_t interval, scale_factor;

	/* Always send at least one beacon */
	send_network_beacon(key);

	/* Count our own beacons towards the vicinity total */
	key->observe.seen++;

	if (!key->observe.half_period) {

		l_debug("beacon %d for %d nodes, period %d, obs %d, exp %d",
					key->id,
					key->snb_enables + key->mpb_enables,
					key->observe.period,
					key->observe.seen,
					key->observe.expected);


		interval = (key->observe.period * key->observe.seen)
							/ key->observe.expected;

		/* Limit Increases and Decreases by 10 seconds Up and
		 * 20 seconds down each step, to avoid going nearly silent
		 * in highly populated environments.
		 */
		if (interval - 10 > key->observe.period)
			interval = key->observe.period + 10;
		else if (interval + 20 < key->observe.period)
			interval = key->observe.period - 20;

		/* Beaconing must be no *slower* than once every 10 minutes,
		 * and no *faster* than once every 10 seconds, per spec.
		 * Observation period is twice beaconing period.
		 */
		if (interval < BEACON_INTERVAL_MIN * 2)
			interval = BEACON_INTERVAL_MIN * 2;
		else if (interval > BEACON_INTERVAL_MAX * 2)
			interval = BEACON_INTERVAL_MAX * 2;

		key->observe.period = interval;
		key->observe.seen = 0;

		/* To prevent "over slowing" of the beaconing frequency,
		 * require more significant "over observing" the slower
		 * our own beaconing frequency.
		 */
		key->observe.expected = interval / 10;
		scale_factor = interval / 60;
		key->observe.expected += scale_factor * 3;
	}

	interval = key->observe.period / 2;
	key->observe.half_period = !key->observe.half_period;

	if (key->mpb_enables || key->snb_enables)
		l_timeout_modify(timeout, interval);
	else {
		l_timeout_remove(timeout);
		key->observe.timeout = NULL;
	}
}

void net_key_beacon_seen(uint32_t id)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (key) {
		key->observe.seen++;
		key->observe.ts = get_timestamp_secs();
	}
}

uint32_t net_key_beacon_last_seen(uint32_t id)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (key)
		return key->observe.ts;

	return 0;
}

bool net_key_beacon_refresh(uint32_t id, uint32_t ivi, bool kr, bool ivu,
								bool force)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));
	bool refresh = force;
	uint32_t rand_ms;

	if (!key)
		return false;

	if (key->snb_enables && !key->snb) {
		key->snb = l_new(uint8_t, BEACON_LEN_SNB);
		refresh = true;
	}

	if (key->mpb_enables && !key->mpb) {
		key->mpb = l_new(uint8_t, BEACON_LEN_MPB);
		refresh = true;
	}

	if (key->ivi != ivi || key->ivu != ivu || key->kr != kr)
		refresh = true;

	if (!refresh)
		return true;

	if (key->mpb) {
		if (!mpb_compose(key, ivi, kr, ivu))
			return false;

		print_packet("Set MPB to", key->mpb, BEACON_LEN_MPB);
	}

	if (key->snb) {
		if (!snb_compose(key, ivi, kr, ivu))
			return false;

		print_packet("Set SNB to", key->snb, BEACON_LEN_SNB);
	}

	l_debug("Set Beacon: IVI: %8.8x, IVU: %d, KR: %d", ivi, ivu, kr);

	key->ivi = ivi;
	key->ivu = ivu;
	key->kr = kr;

	/* Propagate changes to all local nodes */
	net_local_beacon(id, ivi, ivu, kr);

	/* Send one new SNB soon, after all nodes have seen it */
	l_getrandom(&rand_ms, sizeof(rand_ms));
	rand_ms %= 1000;
	key->observe.expected++;

	if (key->observe.timeout)
		l_timeout_modify_ms(key->observe.timeout, 500 + rand_ms);
	else
		key->observe.timeout = l_timeout_create_ms(500 + rand_ms,
						beacon_timeout, key, NULL);

	return true;
}

static void mpb_timeout(struct l_timeout *timeout, void *user_data)
{
	struct net_key *key = user_data;

	if (key->mpb_refresh) {
		l_debug("Refresh in %d seconds", key->mpb_refresh * 10);
		l_timeout_modify(timeout, key->mpb_refresh * 10);
	}

	net_key_beacon_refresh(key->id, key->ivi, key->kr, key->ivu, true);
}

void net_key_beacon_enable(uint32_t id, bool mpb, uint8_t refresh_count)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));
	bool enabled;
	uint32_t rand_ms;

	if (!key)
		return;

	enabled = !!key->snb_enables || !!key->mpb_enables;

	if (mpb) {
		key->mpb_enables++;
		key->mpb_refresh = refresh_count;
		l_timeout_remove(key->mpb_to);
		if (refresh_count)
			key->mpb_to = l_timeout_create(refresh_count * 10,
						mpb_timeout, key, NULL);
		else
			key->mpb_to = NULL;
	} else
		key->snb_enables++;

	/* If already Enabled, do nothing */
	if (enabled)
		return;

	/* Randomize first timeout to avoid bursts of beacons */
	l_getrandom(&rand_ms, sizeof(rand_ms));
	rand_ms %= (BEACON_INTERVAL_MIN * 1000);
	rand_ms++;

	/* Enable Periodic Beaconing on this key */
	key->observe.period = BEACON_INTERVAL_MIN * 2;
	key->observe.expected = 2;
	key->observe.seen = 0;
	key->observe.half_period = true;
	l_timeout_remove(key->observe.timeout);
	key->observe.timeout = l_timeout_create_ms(rand_ms, beacon_timeout,
								key, NULL);
}

void net_key_beacon_disable(uint32_t id, bool mpb)
{
	struct net_key *key = l_queue_find(keys, match_id, L_UINT_TO_PTR(id));

	if (!key)
		return;

	if (mpb) {
		if (!key->mpb_enables)
			return;

		key->mpb_enables--;

		if (!key->mpb_enables) {
			l_free(key->mpb);
			key->mpb = NULL;
			l_timeout_remove(key->mpb_to);
			key->mpb_to = NULL;
		}
	} else {
		if (!key->snb_enables)
			return;

		key->snb_enables--;

		if (!key->snb_enables) {
			l_free(key->snb);
			key->snb = NULL;
		}
	}

	if (key->snb_enables || key->mpb_enables)
		return;

	/* Disable periodic Beaconing on this key */
	l_timeout_remove(key->observe.timeout);
	key->observe.timeout = NULL;
}

static void free_key(void *data)
{
	struct net_key *key = data;

	l_timeout_remove(key->mpb_to);
	l_free(key->snb);
	l_free(key->mpb);
	l_free(key);
}

void net_key_cleanup(void)
{
	l_queue_destroy(keys, free_key);
	keys = NULL;
	l_queue_destroy(beacons, l_free);
	beacons = NULL;
}
