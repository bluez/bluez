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

#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/net_keys.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/crypto.h"
#include "mesh/model.h"
#include "mesh/util.h"

#include "mesh/friend.h"

#define MAX_FRND_GROUPS		20
#define FRND_RELAY_WINDOW	250		/* 250 ms */
#define FRND_CACHE_SIZE		16
#define FRND_SUB_LIST_SIZE	8

#define RESPONSE_DELAY		(100 - 12)	/*  100  ms - 12ms hw delay */
#define MIN_RESP_DELAY		10		/*   10  ms */
#define MAX_RESP_DELAY		255		/*  255  ms */

/* Absolute maximum time to wait for LPN to choose us. */
#define RESPONSE_POLL_DELAY	1300		/* 1.300  s */

static uint8_t frnd_relay_window = FRND_RELAY_WINDOW;
static uint8_t frnd_cache_size = FRND_CACHE_SIZE;
static uint8_t frnd_sublist_size = FRND_SUB_LIST_SIZE;

struct frnd_negotiation {
	struct l_timeout	*timeout;
	struct mesh_net		*net;
	uint32_t		key_id;
	uint32_t		poll_timeout;
	uint16_t		low_power_node;
	uint16_t		old_relay;
	uint8_t			num_ele;
	uint8_t			lp_cnt;
	uint8_t			fn_cnt;
	uint8_t			wrfrw;
	uint8_t			receive_delay;
	int8_t			rssi;
	bool			clearing;
};

static struct l_queue *frnd_negotiations;
static uint16_t counter;

static void response_timeout(struct l_timeout *timeout, void *user_data)
{
	struct frnd_negotiation *neg = user_data;

	/* LPN did not choose us */
	l_debug("Did not win negotiation for %4.4x", neg->low_power_node);

	net_key_unref(neg->key_id);
	l_queue_remove(frnd_negotiations, neg);
	l_timeout_remove(timeout);
	l_free(neg);
}

static void response_delay(struct l_timeout *timeout, void *user_data)
{
	struct frnd_negotiation *neg = user_data;
	uint16_t net_idx = mesh_net_get_primary_idx(neg->net);
	uint32_t key_id;
	uint8_t msg[8];
	uint16_t n = 0;
	bool res;

	l_timeout_remove(timeout);

	/* Create key Set for this offer */
	res = mesh_net_get_key(neg->net, false, net_idx, &key_id);
	if (!res)
		goto cleanup;

	neg->key_id = net_key_frnd_add(key_id, neg->low_power_node,
						mesh_net_get_address(neg->net),
						neg->lp_cnt, counter);
	if (!neg->key_id)
		goto cleanup;

	neg->fn_cnt = counter++;

	msg[n++] = NET_OP_FRND_OFFER;
	msg[n++] = frnd_relay_window;
	msg[n++] = frnd_cache_size;
	msg[n++] = frnd_sublist_size;
	msg[n++] = neg->rssi;
	l_put_be16(neg->fn_cnt, msg + n);
	n += 2;
	print_packet("Tx-NET_OP_FRND_OFFER", msg, n);
	mesh_net_transport_send(neg->net, 0, true,
			mesh_net_get_iv_index(neg->net), 0,
			0, 0, neg->low_power_node,
			msg, n);

	/* Offer expires in 1.3 seconds, which is the max time for LPN to
	 * receive all offers, 1 second to make decision, and a little extra
	 */
	neg->timeout = l_timeout_create_ms(1000 + MAX_RESP_DELAY,
						response_timeout, neg, NULL);

	return;

cleanup:
	net_key_unref(neg->key_id);
	l_queue_remove(frnd_negotiations, neg);
	l_free(neg);
}

static uint8_t cache_size(uint8_t power)
{
	return 1 << power;
}

static bool match_by_lpn(const void *a, const void *b)
{
	const struct frnd_negotiation *neg = a;
	uint16_t lpn = L_PTR_TO_UINT(b);

	return neg->low_power_node == lpn;
}

static bool match_by_dst(const void *a, const void *b)
{
	const struct mesh_friend *frnd = a;
	uint16_t dst = L_PTR_TO_UINT(b);

	return frnd->dst == dst;
}

/* Scaling factors in 1/10 ms */
static const int32_t scaling[] = {
	10,
	15,
	20,
	15,
};

void friend_request(struct mesh_net *net, uint16_t src,
		uint8_t minReq, uint8_t delay, uint32_t timeout,
		uint16_t prev, uint8_t num_ele, uint16_t cntr,
		int8_t rssi)
{
	struct frnd_negotiation *neg;
	uint8_t rssiScale = (minReq >> 5) & 3;
	uint8_t winScale = (minReq >> 3) & 3;
	uint8_t minCache = (minReq >> 0) & 7;
	int32_t rsp_delay;

	l_debug("RSSI of Request: %d dbm", rssi);
	l_debug("Delay: %d ms", delay);
	l_debug("Poll Timeout of Request: %d ms", timeout * 100);
	l_debug("Previous Friend: %4.4x", prev);
	l_debug("Num Elem: %2.2x", num_ele);
	l_debug("Cache Requested: %d", cache_size(minCache));
	l_debug("Cache to offer: %d", frnd_cache_size);

	/* Determine our own suitability before
	 * deciding to participate in negotiation
	 */
	if (minCache == 0 || num_ele == 0)
		return;

	if (delay < 0x0A)
		return;

	if (timeout < 0x00000A || timeout > 0x34BBFF)
		return;

	if (cache_size(minCache) > frnd_cache_size)
		return;

	if (frnd_negotiations == NULL)
		frnd_negotiations = l_queue_new();

	/* TODO: Check RSSI, and then start Negotiation if appropriate */

	/* We are participating in this Negotiation */
	neg = l_new(struct frnd_negotiation, 1);
	l_queue_push_head(frnd_negotiations, neg);

	neg->net = net;
	neg->low_power_node = src;
	neg->lp_cnt = cntr;
	neg->rssi = rssi;
	neg->receive_delay = delay;
	neg->poll_timeout = timeout;
	neg->old_relay = prev;
	neg->num_ele = num_ele;

	/* RSSI (Negative Factor, larger values == less time)
	 * Scaling factor 0-3 == multiplier of 1.0 - 2.5
	 * Minimum factor of 1. Bit 1 adds additional factor
	 * of 1, bit zero and additional 0.5
	 */
	rsp_delay = -(rssi * scaling[rssiScale]);
	l_debug("RSSI Factor: %d ms", rsp_delay / 10);

	/* Relay Window (Positive Factor, larger values == more time)
	 * Scaling factor 0-3 == multiplier of 1.0 - 2.5
	 * Minimum factor of 1. Bit 1 adds additional factor
	 * of 1, bit zero and additional 0.5
	 */
	rsp_delay += frnd_relay_window * scaling[winScale];
	l_debug("Win Size Factor: %d ms",
			(frnd_relay_window * scaling[winScale]) / 10);

	/* Normalize to ms */
	rsp_delay /= 10;

	/* Range limits are 10-255 ms */
	if (rsp_delay < MIN_RESP_DELAY)
		rsp_delay = MIN_RESP_DELAY;
	else if (rsp_delay > MAX_RESP_DELAY)
		rsp_delay = MAX_RESP_DELAY;

	l_debug("Total Response Delay: %d ms", rsp_delay);

	/* Add in 100ms delay before start of "Offer Period" */
	rsp_delay += RESPONSE_DELAY;

	neg->timeout = l_timeout_create_ms(rsp_delay,
						response_delay, neg, NULL);
}

static struct l_queue *retired_lpns;

void friend_clear_confirm(struct mesh_net *net, uint16_t src,
					uint16_t lpn, uint16_t lpnCounter)
{
	struct frnd_negotiation *neg = l_queue_remove_if(frnd_negotiations,
					match_by_lpn, L_UINT_TO_PTR(lpn));

	l_debug("Friend Clear confirmed %4.4x (cnt %4.4x)", lpn, lpnCounter);

	if (!neg)
		return;

	l_timeout_remove(neg->timeout);
	l_queue_remove(frnd_negotiations, neg);
	l_free(neg);
}

static void friend_poll_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mesh_friend *frnd = user_data;

	if (mesh_friend_clear(frnd->net, frnd))
		l_debug("Friend Poll Timeout %4.4x", frnd->dst);

	l_timeout_remove(frnd->timeout);
	frnd->timeout = NULL;

	/* Friend may be in either Network or Retired list, so try both */
	l_queue_remove(retired_lpns, frnd);
	mesh_friend_free(frnd);
}

void friend_clear(struct mesh_net *net, uint16_t src, uint16_t lpn,
				uint16_t lpnCounter, struct mesh_friend *frnd)
{
	uint8_t msg[5] = { NET_OP_FRND_CLEAR_CONFIRM };
	bool removed = false;
	uint16_t lpnDelta;

	if (frnd) {
		lpnDelta = lpnCounter - frnd->lp_cnt;

		/* Ignore old Friend Clear commands */
		if (lpnDelta > 0x100)
			return;

		/* Move friend from Network list to Retired list */
		removed = mesh_friend_clear(net, frnd);
		if (removed) {
			struct mesh_friend *old;
			struct frnd_negotiation *neg = l_queue_remove_if(
						frnd_negotiations,
						match_by_lpn,
						L_UINT_TO_PTR(frnd->dst));

			/* Cancel any negotiations or clears */
			if (neg) {
				l_timeout_remove(neg->timeout);
				l_free(neg);
			}

			/* Create Retired LPN list if needed */
			if (retired_lpns == NULL)
				retired_lpns = l_queue_new();

			/* Find any duplicates */
			old = l_queue_find(retired_lpns, match_by_dst,
						L_UINT_TO_PTR(lpn));

			/* Force time-out of old friendship */
			if (old)
				friend_poll_timeout(old->timeout, old);

			/* Retire this LPN (keeps timeout running) */
			l_queue_push_tail(retired_lpns, frnd);
		}
	} else {
		frnd = l_queue_find(retired_lpns, match_by_dst,
						L_UINT_TO_PTR(lpn));
		if (!frnd)
			return;

		lpnDelta = lpnCounter - frnd->lp_cnt;

		/* Ignore old Friend Clear commands */
		if (!lpnDelta || (lpnDelta > 0x100))
			return;
	}

	l_debug("Friend Cleared %4.4x (%4.4x)", lpn, lpnCounter);

	l_put_be16(lpn, msg + 1);
	l_put_be16(lpnCounter, msg + 3);
	mesh_net_transport_send(net, 0, false,
			mesh_net_get_iv_index(net), DEFAULT_TTL,
			0, 0, src,
			msg, sizeof(msg));
}

static void clear_retry(struct l_timeout *timeout, void *user_data)
{
	struct frnd_negotiation *neg = user_data;
	uint8_t msg[5] = { NET_OP_FRND_CLEAR };
	uint32_t secs = 1 << neg->receive_delay;


	l_put_be16(neg->low_power_node, msg + 1);
	l_put_be16(neg->lp_cnt, msg + 3);
	mesh_net_transport_send(neg->net, 0, false,
			mesh_net_get_iv_index(neg->net), DEFAULT_TTL,
			0, 0, neg->old_relay,
			msg, sizeof(msg));

	if (secs && ((secs << 1) < neg->poll_timeout/10)) {
		neg->receive_delay++;
		l_debug("Try FRND_CLR again in %d seconds (total timeout %d)",
						secs, neg->poll_timeout/10);
		l_timeout_modify(neg->timeout, secs);
	} else {
		l_debug("FRND_CLR timed out %d", secs);
		l_timeout_remove(timeout);
		l_queue_remove(frnd_negotiations, neg);
		l_free(neg);
	}
}

static void friend_delay_rsp(struct l_timeout *timeout, void *user_data)
{
	struct mesh_friend *frnd = user_data;
	struct mesh_friend_msg *pkt = frnd->pkt;
	struct mesh_net *net = frnd->net;
	uint32_t net_seq, iv_index;
	uint8_t upd[7] = { NET_OP_FRND_UPDATE };

	l_timeout_remove(timeout);

	if (pkt == NULL)
		goto update;

	if (pkt->ctl) {
		/* Make sure we don't change the bit-sense of MD,
		 * once it has been set because that would cause
		 * a "Dirty Nonce" security violation
		 */
		if (((pkt->u.one[0].hdr >> OPCODE_HDR_SHIFT) & OPCODE_MASK) ==
						NET_OP_SEG_ACKNOWLEDGE) {
			bool rly = !!((pkt->u.one[0].hdr >> RELAY_HDR_SHIFT) &
									true);
			uint16_t seqZero = pkt->u.one[0].hdr >>
							SEQ_ZERO_HDR_SHIFT;

			seqZero &= SEQ_ZERO_MASK;

			l_debug("Fwd ACK pkt %6.6x-%8.8x",
					pkt->u.one[0].seq,
					pkt->iv_index);

			pkt->u.one[0].sent = true;
			mesh_net_ack_send(net, frnd->net_key_cur,
					pkt->iv_index, pkt->ttl,
					pkt->u.one[0].seq, pkt->src, pkt->dst,
					rly, seqZero,
					l_get_be32(pkt->u.one[0].data));


		} else {
			l_debug("Fwd CTL pkt %6.6x-%8.8x",
					pkt->u.one[0].seq,
					pkt->iv_index);

			print_packet("Frnd-CTL",
					pkt->u.one[0].data, pkt->last_len);

			pkt->u.one[0].sent = true;
			mesh_net_transport_send(net, frnd->net_key_cur, false,
					pkt->iv_index, pkt->ttl,
					pkt->u.one[0].seq, pkt->src, pkt->dst,
					pkt->u.one[0].data, pkt->last_len);
		}
	} else {
		/* If segments after this one, then More Data must be TRUE */
		uint8_t len;

		if (pkt->cnt_out < pkt->cnt_in)
			len = sizeof(pkt->u.s12[0].data);
		else
			len = pkt->last_len;

		l_debug("Fwd FRND pkt %6.6x",
				pkt->u.s12[pkt->cnt_out].seq);

		print_packet("Frnd-Msg", pkt->u.s12[pkt->cnt_out].data, len);

		pkt->u.s12[pkt->cnt_out].sent = true;
		mesh_net_send_seg(net, frnd->net_key_cur,
				pkt->iv_index,
				pkt->ttl,
				pkt->u.s12[pkt->cnt_out].seq,
				pkt->src, pkt->dst,
				pkt->u.s12[pkt->cnt_out].hdr,
				pkt->u.s12[pkt->cnt_out].data, len);
	}

	return;

update:
	/* No More Data -- send Update message with md = false */
	net_seq = mesh_net_get_seq_num(net);
	l_debug("Fwd FRND UPDATE %6.6x with MD == 0", net_seq);

	frnd->last = frnd->seq;
	mesh_net_get_snb_state(net, upd + 1, &iv_index);
	l_put_be32(iv_index, upd + 2);
	upd[6] = false; /* Queue is Empty */
	print_packet("Update", upd, sizeof(upd));
	mesh_net_transport_send(net, frnd->net_key_cur, false,
			mesh_net_get_iv_index(net), 0,
			net_seq, 0, frnd->dst,
			upd, sizeof(upd));
	mesh_net_next_seq_num(net);
}


void friend_poll(struct mesh_net *net, uint16_t src, bool seq,
					struct mesh_friend *frnd)
{
	struct frnd_negotiation *neg;
	struct mesh_friend_msg *pkt;
	bool md;

	neg = l_queue_find(frnd_negotiations, match_by_lpn, L_UINT_TO_PTR(src));
	if (neg && !neg->clearing) {
		uint8_t msg[5] = { NET_OP_FRND_CLEAR };

		l_debug("Won negotiation for %4.4x", neg->low_power_node);

		/* This call will clean-up and replace if already friends */
		frnd = mesh_friend_new(net, src, neg->num_ele,
						neg->receive_delay,
						neg->wrfrw,
						neg->poll_timeout,
						neg->fn_cnt, neg->lp_cnt);

		frnd->timeout = l_timeout_create_ms(
					frnd->poll_timeout * 100,
					friend_poll_timeout, frnd, NULL);

		l_timeout_remove(neg->timeout);
		net_key_unref(neg->key_id);
		neg->key_id = 0;

		if (neg->old_relay == 0 ||
				neg->old_relay == mesh_net_get_address(net)) {
			l_queue_remove(frnd_negotiations, neg);
			l_free(neg);
		} else {
			neg->clearing = true;
			l_put_be16(neg->low_power_node, msg + 1);
			l_put_be16(neg->lp_cnt, msg + 3);
			mesh_net_transport_send(net, 0, false,
					mesh_net_get_iv_index(net), DEFAULT_TTL,
					0, 0, neg->old_relay,
					msg, sizeof(msg));

			/* Reuse receive_delay as a shift counter to
			 * time-out FRIEND_CLEAR
			 */
			neg->receive_delay = 1;
			neg->timeout = l_timeout_create(1, clear_retry,
								neg, NULL);
		}
	}

	if (!frnd)
		return;

	/* Reset Poll Timeout */
	l_timeout_modify_ms(frnd->timeout, frnd->poll_timeout * 100);

	if (!l_queue_length(frnd->pkt_cache))
		goto update;

	if (frnd->seq != frnd->last && frnd->seq != seq) {
		pkt = l_queue_peek_head(frnd->pkt_cache);
		if (pkt->cnt_out < pkt->cnt_in) {
			pkt->cnt_out++;
		} else {
			pkt = l_queue_pop_head(frnd->pkt_cache);
			l_free(pkt);
		}
	}

	pkt = l_queue_peek_head(frnd->pkt_cache);

	if (!pkt)
		goto update;

	frnd->seq = seq;
	frnd->last = !seq;
	md = !!(l_queue_length(frnd->pkt_cache) > 1);

	if (pkt->ctl) {
		/* Make sure we don't change the bit-sense of MD,
		 * once it has been set because that would cause
		 * a "Dirty Nonce" security violation
		 */
		if (!(pkt->u.one[0].sent))
			pkt->u.one[0].md = md;
	} else {
		/* If segments after this one, then More Data must be TRUE */
		if (pkt->cnt_out < pkt->cnt_in)
			md = true;

		/* Make sure we don't change the bit-sense of MD, once
		 * it has been set because that would cause a
		 * "Dirty Nonce" security violation
		 */
		if (!(pkt->u.s12[pkt->cnt_out].sent))
			pkt->u.s12[pkt->cnt_out].md = md;
	}
	frnd->pkt = pkt;
	l_timeout_create_ms(frnd->frd, friend_delay_rsp, frnd, NULL);

	return;

update:
	frnd->pkt = NULL;
	l_timeout_create_ms(frnd->frd, friend_delay_rsp, frnd, NULL);
}

void friend_sub_add(struct mesh_net *net, struct mesh_friend *frnd,
					const uint8_t *pkt, uint8_t len)
{
	uint16_t *new_list;
	uint32_t net_seq;
	uint8_t plen = len;
	uint8_t msg[] = { NET_OP_PROXY_SUB_CONFIRM, 0 };

	if (!frnd || MAX_FRND_GROUPS < frnd->grp_cnt + (len/2))
		return;

	msg[1] = *pkt++;
	plen--;

	/* Sanity Check Values, abort if any illegal */
	while (plen >= 2) {
		plen -= 2;
		if (l_get_be16(pkt + plen) < 0x8000)
			return;
	}

	new_list = l_malloc(frnd->grp_cnt * sizeof(uint16_t) + len);
	if (frnd->grp_list)
		memcpy(new_list, frnd->grp_list,
				frnd->grp_cnt * sizeof(uint16_t));

	while (len >= 2) {
		new_list[frnd->grp_cnt++] = l_get_be16(pkt);
		pkt += 2;
		len -= 2;
	}

	l_free(frnd->grp_list);
	frnd->grp_list = new_list;

	print_packet("Tx-NET_OP_PROXY_SUB_CONFIRM", msg, sizeof(msg));
	net_seq = mesh_net_get_seq_num(net);
	mesh_net_transport_send(net, frnd->net_key_cur, false,
			mesh_net_get_iv_index(net), 0,
			net_seq, 0, frnd->dst,
			msg, sizeof(msg));
	mesh_net_next_seq_num(net);
}

void friend_sub_del(struct mesh_net *net, struct mesh_friend *frnd,
					const uint8_t *pkt, uint8_t len)
{
	uint32_t net_seq;
	uint8_t msg[] = { NET_OP_PROXY_SUB_CONFIRM, 0 };
	int i;

	if (!frnd)
		return;

	msg[1] = *pkt++;
	len--;

	while (len >= 2) {
		uint16_t grp = l_get_be16(pkt);

		for (i = frnd->grp_cnt - 1; i >= 0; i--) {
			if (frnd->grp_list[i] == grp) {
				frnd->grp_cnt--;
				memcpy(&frnd->grp_list[i],
						&frnd->grp_list[i + 1],
						(frnd->grp_cnt - i) * 2);
				break;
			}
		}
		len -= 2;
		pkt += 2;
	}

	print_packet("Tx-NET_OP_PROXY_SUB_CONFIRM", msg, sizeof(msg));
	net_seq = mesh_net_get_seq_num(net);
	mesh_net_transport_send(net, frnd->net_key_cur, false,
			mesh_net_get_iv_index(net), 0,
			net_seq, 0, frnd->dst,
			msg, sizeof(msg));
	mesh_net_next_seq_num(net);
}

/* Low-Power-Node role */
struct frnd_offers {
	uint16_t fn_cnt;
	uint16_t src;
	uint8_t window;
	uint8_t cache;
	uint8_t sub_list_size;
	int8_t local_rssi;
	int8_t remote_rssi;
};

#define MAX_POLL_RETRIES	5
static bool quick_pick;
static uint8_t poll_cnt;
static struct l_queue *offers;
static uint16_t old_friend;
static uint16_t fn_cnt, cnt = 0xffff;
static uint32_t poll_period_ms;
static struct l_timeout *poll_retry_to;
static struct l_timeout *poll_period_to;
static uint32_t lpn_key_id;
static uint32_t new_lpn_id;

void frnd_offer(struct mesh_net *net, uint16_t src, uint8_t window,
			uint8_t cache, uint8_t sub_list_size,
			int8_t r_rssi, int8_t l_rssi, uint16_t fn_cnt)
{
	struct frnd_offers *offer;

	l_debug("RSSI of Offer: %d dbm", l_rssi);

	/* Ignore RFU window value 0 */
	if (window == 0)
		return;

	if (mesh_net_get_friend(net))
		return;

	if (quick_pick) {
		if (mesh_net_set_friend(net, src)) {
			old_friend = src;
			frnd_poll(net, false);
		}
		return;
	}

	offer = l_new(struct frnd_offers, 1);
	offer->src = src;
	offer->window = window;
	offer->cache = cache;
	offer->sub_list_size = sub_list_size;
	offer->local_rssi = l_rssi;
	offer->remote_rssi = r_rssi;
	offer->fn_cnt = fn_cnt;

	l_queue_push_tail(offers, offer);
}

static void frnd_poll_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mesh_net *net = user_data;

	frnd_poll(net, true);
}

static void frnd_negotiated_to(struct l_timeout *timeout, void *user_data)
{
	struct mesh_net *net = user_data;

	l_debug("frnd_negotiated_to");
	if (!mesh_net_get_friend(net)) {
		l_timeout_remove(poll_period_to);
		poll_period_to = NULL;
		return;
	}

	if (!poll_retry_to)
		frnd_poll(net, false);
}

void frnd_poll_cancel(struct mesh_net *net)
{
	l_timeout_remove(poll_retry_to);
	poll_retry_to = NULL;
}

void frnd_poll(struct mesh_net *net, bool retry)
{
	uint32_t key_id = lpn_key_id;
	uint32_t net_seq;
	uint8_t msg[2] = { NET_OP_FRND_POLL };
	bool seq = mesh_net_get_frnd_seq(net);

	/* Check if we are in Phase 2 of Key Refresh */
	if (new_lpn_id) {
		uint8_t phase;
		uint16_t net_idx = mesh_net_get_primary_idx(net);
		uint8_t status =
			mesh_net_key_refresh_phase_get(net, net_idx, &phase);

		if (status == MESH_STATUS_SUCCESS &&
				phase == KEY_REFRESH_PHASE_TWO)
			key_id = new_lpn_id;
	}

	if (!retry) {
		poll_cnt = MAX_POLL_RETRIES;
		seq = !seq;
		mesh_net_set_frnd_seq(net, seq);
	} else if (!(poll_cnt--)) {
		l_debug("Lost Friendship with %4.4x", old_friend);
		l_timeout_remove(poll_period_to);
		poll_period_to = NULL;
		frnd_poll_cancel(net);
		net_key_unref(lpn_key_id);
		net_key_unref(new_lpn_id);
		new_lpn_id = lpn_key_id = 0;
		mesh_net_set_friend(net, 0);
		return;
	}

	if (poll_retry_to)
		l_timeout_remove(poll_retry_to);

	l_debug("TX-FRIEND POLL %d", seq);
	msg[1] = seq;
	net_seq = mesh_net_get_seq_num(net);
	mesh_net_transport_send(net, key_id, true,
			mesh_net_get_iv_index(net), 0,
			net_seq, 0, mesh_net_get_friend(net),
			msg, sizeof(msg));
	mesh_net_next_seq_num(net);
	poll_retry_to = l_timeout_create_ms(1000, frnd_poll_timeout, net, NULL);

	/* Reset Poll Period for next "Wake Up" */
	if (poll_period_to)
		l_timeout_modify_ms(poll_period_to, poll_period_ms);
	else
		poll_period_to = l_timeout_create_ms(poll_period_ms,
						frnd_negotiated_to, net, NULL);
}

void frnd_ack_poll(struct mesh_net *net)
{
	/* Start new POLL, but only if not already Polling */
	if (poll_retry_to == NULL)
		frnd_poll(net, false);
}

static void req_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mesh_net *net = user_data;
	struct frnd_offers *best;
	struct frnd_offers *offer = l_queue_pop_head(offers);
	uint32_t key_id = 0;
	bool res;

	l_timeout_remove(timeout);

	best = offer;
	while (offer) {
		/* Screen out clearly inferior RSSI friends first */
		if (offer->local_rssi < -40 && offer->remote_rssi < -40) {
			if (best->local_rssi + 20 < offer->local_rssi ||
				best->remote_rssi + 20 < offer->remote_rssi) {

				l_free(best);
				best = offer;
				offer = l_queue_pop_head(offers);
				continue;
			}
		}

		/* Otherwise use best Windows, with Cache size as tie breaker */
		if (best->window > offer->window ||
				(best->window == offer->window &&
				 best->cache < offer->cache)) {
			l_free(best);
			best = offer;
		} else if (best != offer)
			l_free(offer);

		offer = l_queue_pop_head(offers);
	}

	net_key_unref(lpn_key_id);
	net_key_unref(new_lpn_id);
	new_lpn_id = lpn_key_id = 0;
	if (mesh_net_get_friend(net)) {
		l_free(best);
		return;
	} else if (!best) {
		l_debug("No Offers Received");
		return;
	}

	fn_cnt = best->fn_cnt;
	res = mesh_net_get_key(net, false, mesh_net_get_primary_idx(net),
								&key_id);
	if (!res)
		return;

	lpn_key_id = net_key_frnd_add(key_id, mesh_net_get_address(net),
						best->src, cnt, best->fn_cnt);
	if (!lpn_key_id)
		return;

	res = mesh_net_get_key(net, true, mesh_net_get_primary_idx(net),
								&key_id);

	if (!res)
		goto old_keys_only;

	new_lpn_id = net_key_frnd_add(key_id, mesh_net_get_address(net),
						best->src, cnt, best->fn_cnt);

old_keys_only:

	l_debug("Winning offer %4.4x RSSI: %ddb Window: %dms Cache sz: %d",
			best->src, best->local_rssi,
			best->window, best->cache);

	if (mesh_net_set_friend(net, best->src)) {
		old_friend = best->src;
		mesh_net_set_frnd_seq(net, true);
		frnd_poll(net, false);
	}

	l_free(best);
}

void frnd_clear(struct mesh_net *net)
{
	uint8_t msg[12];
	uint8_t n = 0;
	uint16_t frnd_addr = mesh_net_get_friend(net);
	uint16_t my_addr = mesh_net_get_address(net);

	msg[n++] = NET_OP_FRND_CLEAR;
	l_put_be16(my_addr, msg + n);
	n += 2;
	l_put_be16(cnt, msg + n);
	n += 2;

	net_key_unref(lpn_key_id);
	net_key_unref(new_lpn_id);
	mesh_net_set_friend(net, 0);

	mesh_net_transport_send(net, 0, false,
			mesh_net_get_iv_index(net), 0,
			0, 0, frnd_addr,
			msg, n);
}

void frnd_request_friend(struct mesh_net *net, uint8_t cache,
			uint8_t offer_delay, uint8_t delay, uint32_t timeout)
{
	uint8_t msg[12];
	uint8_t n = 0;

	if (offers == NULL)
		offers = l_queue_new();

	msg[n++] = NET_OP_FRND_REQUEST;
	msg[n] = cache & 0x07;		/* MinRequirements - Cache */
	msg[n++] |= (offer_delay & 0x0f) << 3;	/* Offer Delay */
	poll_period_ms = (timeout * 300) / 4; /* 3/4 of the time in ms */
	l_put_be32(timeout, msg + n);	/* PollTimeout */
	msg[n++] = delay;		/* ReceiveDelay */
	n += 3;
	l_put_be16(old_friend, msg + n);	/* PreviousAddress */
	n += 2;
	msg[n++] = mesh_net_get_num_ele(net);	/* NumElements */
	l_put_be16(cnt + 1, msg + n);	/* Next counter */
	n += 2;
	print_packet("Tx-NET_OP_FRND_REQUEST", msg, n);
	mesh_net_transport_send(net, 0, false,
			mesh_net_get_iv_index(net), 0,
			0, 0, FRIENDS_ADDRESS,
			msg, n);
	l_timeout_create_ms(1000, req_timeout, net, NULL); /* 1000 ms */
	mesh_net_set_friend(net, 0);
	cnt++;
}

static uint8_t trans_id;
void frnd_sub_add(struct mesh_net *net, uint32_t parms[7])
{
	uint32_t key_id = lpn_key_id;
	uint32_t net_seq;
	uint8_t msg[15] = { NET_OP_PROXY_SUB_ADD };
	uint8_t i, n = 1;

	/* Check if we are in Phase 2 of Key Refresh */
	if (new_lpn_id) {
		uint8_t phase;
		uint16_t net_idx = mesh_net_get_primary_idx(net);
		uint8_t status = mesh_net_key_refresh_phase_get(net,
							net_idx, &phase);

		if (status == MESH_STATUS_SUCCESS &&
				phase == KEY_REFRESH_PHASE_TWO)
			key_id = new_lpn_id;
	}

	msg[n++] = ++trans_id;
	for (i = 0; i < 7; i++) {
		if (parms[i] < 0x8000 || parms[i] > 0xffff)
			break;

		l_put_be16(parms[i], msg + n);
		n += 2;
	}

	net_seq = mesh_net_get_seq_num(net);
	print_packet("Friend Sub Add", msg, n);
	mesh_net_transport_send(net, key_id, false,
			mesh_net_get_iv_index(net), 0,
			net_seq, 0, mesh_net_get_friend(net),
			msg, n);
	mesh_net_next_seq_num(net);
}

void frnd_sub_del(struct mesh_net *net, uint32_t parms[7])
{
	uint32_t key_id = lpn_key_id;
	uint32_t net_seq;
	uint8_t msg[15] = { NET_OP_PROXY_SUB_REMOVE };
	uint8_t i, n = 1;

	/* Check if we are in Phase 2 of Key Refresh */
	if (new_lpn_id) {
		uint8_t phase;
		uint16_t net_idx = mesh_net_get_primary_idx(net);
		uint8_t status = mesh_net_key_refresh_phase_get(net,
							net_idx, &phase);

		if (status == MESH_STATUS_SUCCESS &&
				phase == KEY_REFRESH_PHASE_TWO)
			key_id = new_lpn_id;
	}

	msg[n++] = ++trans_id;
	for (i = 0; i < 7; i++) {
		if (parms[i] < 0x8000 || parms[i] > 0xffff)
			break;

		l_put_be16(parms[i], msg + n);
		n += 2;
	}

	net_seq = mesh_net_get_seq_num(net);
	print_packet("Friend Sub Del", msg, n);
	mesh_net_transport_send(net, key_id, false,
			mesh_net_get_iv_index(net), 0,
			net_seq, 0, mesh_net_get_friend(net),
			msg, n);
	mesh_net_next_seq_num(net);
}

void frnd_key_refresh(struct mesh_net *net, uint8_t phase)
{
	uint16_t net_idx = mesh_net_get_primary_idx(net);
	uint32_t key_id;

	switch (phase) {
	default:
	case 0:
	case 3:
		if (new_lpn_id) {
			l_debug("LPN Retiring KeySet %d", lpn_key_id);
			net_key_unref(lpn_key_id);
			lpn_key_id = new_lpn_id;
		}
		return;

	case 1:
		net_key_unref(new_lpn_id);
		if (!mesh_net_get_key(net, true, net_idx, &key_id)) {
			new_lpn_id = 0;
			return;
		}

		new_lpn_id = net_key_frnd_add(key_id, mesh_net_get_address(net),
						mesh_net_get_friend(net),
						cnt, fn_cnt);
		return;

	case 2:
		/* Should we do anything here?  Maybe not */
		return;
	}
}

uint32_t frnd_get_key(struct mesh_net *net)
{
	uint8_t idx = mesh_net_get_primary_idx(net);
	uint8_t phase = 0;

	mesh_net_key_refresh_phase_get(net, idx, &phase);

	if (phase == 2)
		return new_lpn_id;
	else
		return lpn_key_id;
}
