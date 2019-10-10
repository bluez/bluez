/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE

#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/util.h"
#include "mesh/crypto.h"
#include "mesh/net-keys.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/mesh-io.h"
#include "mesh/friend.h"
#include "mesh/mesh-config.h"
#include "mesh/model.h"
#include "mesh/appkey.h"

#define abs_diff(a, b) ((a) > (b) ? (a) - (b) : (b) - (a))

#define IV_IDX_DIFF_RANGE	42

/*#define IV_IDX_UPD_MIN	(5 * 60)	* 5 minute for Testing */
#define IV_IDX_UPD_MIN	(60 * 60 * 96)	/* 96 Hours - per Spec */
#define IV_IDX_UPD_HOLD	(IV_IDX_UPD_MIN/2)
#define IV_IDX_UPD_MAX	(IV_IDX_UPD_MIN + IV_IDX_UPD_HOLD)

#define iv_is_updating(net) ((net)->iv_upd_state == IV_UPD_UPDATING)

#define IV_UPDATE_SEQ_TRIGGER 0x800000  /* Half of Seq-Nums expended */

#define SEG_TO	2
#define MSG_TO	60

#define DEFAULT_MIN_DELAY		0
#define DEFAULT_MAX_DELAY		25

#define DEFAULT_TRANSMIT_COUNT		1
#define DEFAULT_TRANSMIT_INTERVAL	100

#define BEACON_INTERVAL_MIN	10
#define BEACON_INTERVAL_MAX	600

#define SAR_KEY(src, seq0)	((((uint32_t)(seq0)) << 16) | (src))

enum _relay_advice {
	RELAY_NONE,		/* Relay not enabled in node */
	RELAY_ALLOWED,		/* Relay enabled, msg not to node's unicast */
	RELAY_DISALLOWED,	/* Msg was unicast handled by this node */
	RELAY_ALWAYS		/* Relay enabled, msg to a group */
};

enum _iv_upd_state {
	/* Allows acceptance of any iv_index secure net beacon */
	IV_UPD_INIT,
	/* Normal, can transition, accept current or old */
	IV_UPD_NORMAL,
	/* Updating proc running, we use old, accept old or new */
	IV_UPD_UPDATING,
	/* Normal, can *not* transition, accept current or old iv_index */
	IV_UPD_NORMAL_HOLD,
};

struct net_key {
	struct mesh_key_set key_set;
	unsigned int beacon_id;
	uint8_t key[16];
	uint8_t beacon_key[16];
	uint8_t network_id[8];
};

struct mesh_beacon {
	struct l_timeout *timeout;
	uint32_t ts;
	uint16_t observe_period;
	uint16_t observed;
	uint16_t expected;
	uint8_t half_period;
	uint8_t beacon[23];
};

struct mesh_subnet {
	struct mesh_net *net;
	uint16_t idx;
	uint32_t net_key_tx;
	uint32_t net_key_cur;
	uint32_t net_key_upd;
	struct mesh_beacon snb;
	uint8_t key_refresh;
	uint8_t kr_phase;
};

struct mesh_net {
	struct mesh_io *io;
	struct mesh_node *node;
	struct mesh_prov *prov;
	struct l_queue *app_keys;
	unsigned int pkt_id;
	unsigned int bea_id;
	unsigned int beacon_id;
	unsigned int sar_id_next;

	bool friend_enable;
	bool beacon_enable;
	bool proxy_enable;
	bool provisioner;
	bool friend_seq;
	struct l_timeout *iv_update_timeout;
	enum _iv_upd_state iv_upd_state;

	bool iv_update;
	uint32_t instant; /* Controller Instant of recent Rx */
	uint32_t iv_index;
	uint32_t seq_num;
	uint16_t src_addr;
	uint16_t last_addr;
	uint16_t friend_addr;
	uint16_t tx_interval;
	uint16_t tx_cnt;
	uint8_t chan; /* Channel of recent Rx */
	uint8_t default_ttl;
	uint8_t tid;
	uint8_t window_accuracy;

	struct {
		bool enable;
		uint16_t interval;
		uint8_t count;
	} relay;

	struct mesh_net_heartbeat heartbeat;

	struct l_queue *subnets;
	struct l_queue *msg_cache;
	struct l_queue *sar_in;
	struct l_queue *sar_out;
	struct l_queue *frnd_msgs;
	struct l_queue *friends;
	struct l_queue *destinations;

	uint8_t prov_priv_key[32];

	/* Unprovisioned Identity */
	char id_name[20];
	uint8_t id_uuid[16];

	/* Provisioner: unicast address range */
	struct mesh_net_addr_range prov_uni_addr;

	/* Test Data */
	uint8_t prov_rand[16];
	uint8_t test_bd_addr[6];
	struct mesh_net_prov_caps prov_caps;
	bool test_mode;
};

struct mesh_msg {
	uint16_t src;
	uint32_t seq;
	uint32_t mic;
};

struct mesh_sar {
	unsigned int id;
	struct l_timeout *seg_timeout;
	struct l_timeout *msg_timeout;
	mesh_net_status_func_t status_func;
	void *user_data;
	uint32_t flags;
	uint32_t last_nak;
	uint32_t iv_index;
	uint32_t seqAuth;
	uint16_t seqZero;
	uint16_t app_idx;
	uint16_t src;
	uint16_t remote;
	uint16_t len;
	bool szmic;
	bool frnd;
	bool frnd_cred;
	uint8_t ttl;
	uint8_t last_seg;
	uint8_t key_aid;
	uint8_t buf[4]; /* Large enough for ACK-Flags and MIC */
};

struct mesh_destination {
	uint16_t dst;
	uint16_t ref_cnt;
};

struct msg_rx {
	const uint8_t *data;
	uint32_t iv_index;
	uint32_t seq;
	uint16_t src;
	uint16_t dst;
	uint16_t size;
	uint8_t tc;
	bool done;
	bool szmic;
	union {
		struct {
			uint16_t app_idx;
			uint8_t key_aid;
		} m;
		struct {
			uint16_t seq0;
		} a;
		struct {
			uint8_t opcode;
		} c;
	} u;
};

struct net_decode {
	struct mesh_net *net;
	struct mesh_friend *frnd;
	struct mesh_key_set *key_set;
	uint8_t *packet;
	uint32_t iv_index;
	uint8_t size;
	uint8_t nid;
	bool proxy;
};

struct net_queue_data {
	struct mesh_io_recv_info *info;
	struct mesh_net *net;
	const uint8_t *data;
	uint8_t *out;
	size_t out_size;
	enum _relay_advice relay_advice;
	uint32_t key_id;
	uint32_t iv_index;
	uint16_t len;
};

struct net_beacon_data {
	const uint8_t *data;
	uint16_t len;
};

#define FAST_CACHE_SIZE 8
static struct l_queue *fast_cache;
static struct l_queue *nets;

static void net_rx(void *net_ptr, void *user_data);

static inline struct mesh_subnet *get_primary_subnet(struct mesh_net *net)
{
	return l_queue_peek_head(net->subnets);
}

static bool match_key_index(const void *a, const void *b)
{
	const struct mesh_subnet *subnet = a;
	uint16_t idx = L_PTR_TO_UINT(b);

	return subnet->idx == idx;
}

static bool match_key_id(const void *a, const void *b)
{
	const struct mesh_subnet *subnet = a;
	uint32_t key_id = L_PTR_TO_UINT(b);

	return (key_id == subnet->net_key_cur) ||
					(key_id == subnet->net_key_upd);
}

static void idle_mesh_heartbeat_send(void *net)
{
	mesh_net_heartbeat_send(net);
}

static void trigger_heartbeat(struct mesh_net *net, uint16_t feature,
								bool in_use)
{
	struct mesh_net_heartbeat *hb = &net->heartbeat;

	l_info("%s: %4.4x --> %d", __func__, feature, in_use);
	if (in_use) {
		if (net->heartbeat.features & feature)
			return; /* no change */

		hb->features |= feature;
	} else {
		if (!(hb->features & feature))
			return; /* no change */

		hb->features &= ~feature;
	}

	if (!(hb->pub_features & feature))
		return; /* not interested in this feature */

	l_idle_oneshot(idle_mesh_heartbeat_send, net, NULL);

}

static bool match_by_friend(const void *a, const void *b)
{
	const struct mesh_friend *frnd = a;
	uint16_t dst = L_PTR_TO_UINT(b);

	return frnd->dst == dst;
}

static void free_friend_internals(struct mesh_friend *frnd)
{
	if (frnd->pkt_cache)
		l_queue_destroy(frnd->pkt_cache, l_free);

	if (frnd->grp_list)
		l_free(frnd->grp_list);

	frnd->pkt_cache = NULL;
	frnd->grp_list = NULL;
	net_key_unref(frnd->net_key_cur);
	net_key_unref(frnd->net_key_upd);
}

static void frnd_kr_phase1(void *a, void *b)
{
	struct mesh_friend *frnd = a;
	uint32_t key_id = L_PTR_TO_UINT(b);

	frnd->net_key_upd = net_key_frnd_add(key_id, frnd->dst,
			frnd->net->src_addr, frnd->lp_cnt, frnd->fn_cnt);
}

static void frnd_kr_phase2(void *a, void *b)
{
	struct mesh_friend *frnd = a;

	/*
	 * I think that a Friend should use Old Key as long as possible
	 * Because a Friend Node will enter Phase 3 before it's LPN.
	 * Alternatively, the FN could keep the Old Friend Keys until it
	 * receives it's first Poll using the new keys (?)
	 */

	l_info("Use Both KeySet %d && %d for %4.4x",
			frnd->net_key_cur, frnd->net_key_upd, frnd->dst);
}

static void frnd_kr_phase3(void *a, void *b)
{
	struct mesh_friend *frnd = a;

	l_info("Replace KeySet %d with %d for %4.4x",
			frnd->net_key_cur, frnd->net_key_upd, frnd->dst);
	net_key_unref(frnd->net_key_cur);
	frnd->net_key_cur = frnd->net_key_upd;
	frnd->net_key_upd = 0;
}

/* TODO: add net key idx? For now, use primary net key */
struct mesh_friend *mesh_friend_new(struct mesh_net *net, uint16_t dst,
					uint8_t ele_cnt, uint8_t frd,
					uint8_t frw, uint32_t fpt,
					uint16_t fn_cnt, uint16_t lp_cnt)
{
	struct mesh_subnet *subnet;
	struct mesh_friend *frnd = l_queue_find(net->friends,
					match_by_friend, L_UINT_TO_PTR(dst));

	if (frnd) {
		/* Kill all timers and empty cache for this friend */
		free_friend_internals(frnd);
		l_timeout_remove(frnd->timeout);
		frnd->timeout = NULL;
	} else {
		frnd = l_new(struct mesh_friend, 1);
		l_queue_push_head(net->friends, frnd);
	}

	/* add _k2 */
	frnd->net = net;
	frnd->dst = dst;
	frnd->frd = frd;
	frnd->frw = frw;
	frnd->fn_cnt = fn_cnt;
	frnd->lp_cnt = lp_cnt;
	frnd->poll_timeout = fpt;
	frnd->ele_cnt = ele_cnt;
	frnd->pkt_cache = l_queue_new();
	frnd->net_key_upd = 0;

	subnet = get_primary_subnet(net);
	/* TODO: the primary key must be present, do we need to add check?. */

	frnd->net_key_cur = net_key_frnd_add(subnet->net_key_cur,
							dst, net->src_addr,
							lp_cnt, fn_cnt);

	if (!subnet->net_key_upd)
		return frnd;

	frnd->net_key_upd = net_key_frnd_add(subnet->net_key_upd,
							dst, net->src_addr,
							lp_cnt, fn_cnt);

	return frnd;
}

void mesh_friend_free(void *data)
{
	struct mesh_friend *frnd = data;

	free_friend_internals(frnd);
	l_timeout_remove(frnd->timeout);
	l_free(frnd);
}

bool mesh_friend_clear(struct mesh_net *net, struct mesh_friend *frnd)
{
	bool removed = l_queue_remove(net->friends, frnd);

	free_friend_internals(frnd);

	return removed;
}

void mesh_friend_sub_add(struct mesh_net *net, uint16_t lpn, uint8_t ele_cnt,
							uint8_t grp_cnt,
							const uint8_t *list)
{
	uint16_t *new_list;
	uint16_t *grp_list;
	struct mesh_friend *frnd = l_queue_find(net->friends,
							match_by_friend,
							L_UINT_TO_PTR(lpn));
	if (!frnd)
		return;

	new_list = l_malloc((grp_cnt + frnd->grp_cnt) * sizeof(uint16_t));
	grp_list = frnd->grp_list;

	if (grp_list && frnd->grp_cnt)
		memcpy(new_list, grp_list, frnd->grp_cnt * sizeof(uint16_t));

	memcpy(&new_list[frnd->grp_cnt], list, grp_cnt * sizeof(uint16_t));
	l_free(grp_list);
	frnd->ele_cnt = ele_cnt;
	frnd->grp_list = new_list;
	frnd->grp_cnt += grp_cnt;
}

void mesh_friend_sub_del(struct mesh_net *net, uint16_t lpn,
						uint8_t cnt,
						const uint8_t *del_list)
{
	uint16_t *grp_list;
	int16_t i, grp_cnt;
	size_t cnt16 = cnt * sizeof(uint16_t);
	struct mesh_friend *frnd = l_queue_find(net->friends,
							match_by_friend,
							L_UINT_TO_PTR(lpn));
	if (!frnd)
		return;

	grp_cnt = frnd->grp_cnt;
	grp_list = frnd->grp_list;

	while (cnt-- && grp_cnt) {
		cnt16 -= sizeof(uint16_t);
		for (i = grp_cnt - 1; i >= 0; i--) {
			if (l_get_le16(del_list + cnt16) == grp_list[i]) {
				grp_cnt--;
				memcpy(&grp_list[i], &grp_list[i + 1],
					(grp_cnt - i) * sizeof(uint16_t));
				break;
			}
		}
	}

	frnd->grp_cnt = grp_cnt;

	if (!grp_cnt) {
		l_free(frnd->grp_list);
		frnd->grp_list = NULL;
	}
}

uint32_t mesh_net_next_seq_num(struct mesh_net *net)
{
	uint32_t seq = net->seq_num++;

	node_set_sequence_number(net->node, net->seq_num);
	return seq;
}

static struct mesh_sar *mesh_sar_new(size_t len)
{
	size_t size = sizeof(struct mesh_sar) + len;
	struct mesh_sar *sar;

	sar = l_malloc(size);

	memset(sar, 0, size);

	return sar;
}

static void mesh_sar_free(void *data)
{
	struct mesh_sar *sar = data;

	if (!sar)
		return;

	l_timeout_remove(sar->seg_timeout);
	l_timeout_remove(sar->msg_timeout);
	l_free(sar);
}

static void mesh_msg_free(void *data)
{
	struct mesh_msg *msg = data;

	l_free(msg);
}

static void subnet_free(void *data)
{
	struct mesh_subnet *subnet = data;

	net_key_unref(subnet->net_key_cur);
	net_key_unref(subnet->net_key_upd);
	l_free(subnet);
}

static void lpn_process_beacon(void *user_data, const void *data, uint8_t size,
								int8_t rssi);

static struct mesh_subnet *subnet_new(struct mesh_net *net, uint16_t idx)
{
	struct mesh_subnet *subnet;

	subnet = l_new(struct mesh_subnet, 1);
	if (!subnet)
		return NULL;

	subnet->net = net;
	subnet->idx = idx;
	subnet->snb.beacon[0] = MESH_AD_TYPE_BEACON;
	return subnet;
}

static bool create_secure_beacon(struct mesh_net *net,
					struct mesh_subnet *subnet,
					uint8_t *beacon_data)
{
	bool kr = (subnet->kr_phase == KEY_REFRESH_PHASE_TWO);

	return net_key_snb_compose(subnet->net_key_tx, net->iv_index,
					kr, net->iv_update, beacon_data);
}

static void send_network_beacon(struct mesh_subnet *subnet,
							struct mesh_net *net)
{
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = net->tx_interval,
		.u.gen.cnt = 1,
		.u.gen.min_delay = DEFAULT_MIN_DELAY,
		.u.gen.max_delay = DEFAULT_MAX_DELAY
	};

	l_info("Send SNB on network %3.3x", subnet->idx);
	mesh_io_send(net->io, &info, subnet->snb.beacon,
						sizeof(subnet->snb.beacon));
}

static void network_beacon_timeout(struct l_timeout *timeout, void *user_data)
{
	struct mesh_subnet *subnet = user_data;
	uint32_t interval;

	send_network_beacon(subnet, subnet->net);

	if (!subnet->snb.half_period) {
		l_debug("beacon TO period %d, observed %d, expected %d",
						subnet->snb.observe_period,
						subnet->snb.observed,
						subnet->snb.expected);
		interval = subnet->snb.observe_period *
			(subnet->snb.observed + 1) / subnet->snb.expected;
		subnet->snb.observe_period = interval * 2;
		subnet->snb.expected = subnet->snb.observe_period / 10;
		subnet->snb.observed = 0;
	} else
		interval = subnet->snb.observe_period / 2;

	if (interval < BEACON_INTERVAL_MIN)
		interval = BEACON_INTERVAL_MIN;

	if (interval > BEACON_INTERVAL_MAX)
		interval = BEACON_INTERVAL_MAX;

	subnet->snb.ts = get_timestamp_secs();
	subnet->snb.half_period ^= 1;
	l_timeout_modify(timeout, interval);
}

static void start_network_beacon(void *a, void *b)
{
	struct mesh_subnet *subnet = a;
	struct mesh_net *net = b;

	if (!net->beacon_enable) {
		if (subnet->snb.timeout)
			l_timeout_remove(subnet->snb.timeout);
		subnet->snb.timeout = NULL;
		return;
	}

	/* If timeout is active, let it run it's course */
	if (subnet->snb.timeout)
		return;

	send_network_beacon(subnet, subnet->net);

	subnet->snb.ts = get_timestamp_secs();
	subnet->snb.expected = 2;
	subnet->snb.observed = 0;
	subnet->snb.half_period = 1;
	subnet->snb.observe_period = BEACON_INTERVAL_MIN * 2;

	subnet->snb.timeout = l_timeout_create(BEACON_INTERVAL_MIN,
				network_beacon_timeout, subnet, NULL);
}

struct mesh_net *mesh_net_new(struct mesh_node *node)
{
	struct mesh_net *net;

	net = l_new(struct mesh_net, 1);

	net->node = node;
	net->pkt_id = 0;
	net->bea_id = 0;

	net->beacon_enable = true;
	net->proxy_enable = false;
	net->relay.enable = false;

	net->seq_num = 0x000000;
	net->src_addr = 0x0000;
	net->default_ttl = 0x7f;

	net->provisioner = false;

	net->test_mode = false;
	memset(&net->prov_caps, 0, sizeof(net->prov_caps));
	net->prov_caps.algorithms = 1;

	net->tx_cnt = DEFAULT_TRANSMIT_COUNT;
	net->tx_interval = DEFAULT_TRANSMIT_INTERVAL;

	net->subnets = l_queue_new();
	net->msg_cache = l_queue_new();
	net->sar_in = l_queue_new();
	net->sar_out = l_queue_new();
	net->frnd_msgs = l_queue_new();
	net->friends = l_queue_new();
	net->destinations = l_queue_new();
	net->app_keys = l_queue_new();

	memset(&net->heartbeat, 0, sizeof(net->heartbeat));

	if (!nets)
		nets = l_queue_new();

	if (!fast_cache)
		fast_cache = l_queue_new();

	return net;
}

void mesh_net_free(struct mesh_net *net)
{
	if (!net)
		return;

	l_queue_destroy(net->subnets, subnet_free);
	l_queue_destroy(net->msg_cache, mesh_msg_free);
	l_queue_destroy(net->sar_in, mesh_sar_free);
	l_queue_destroy(net->sar_out, mesh_sar_free);
	l_queue_destroy(net->frnd_msgs, l_free);
	l_queue_destroy(net->friends, mesh_friend_free);
	l_queue_destroy(net->destinations, l_free);
	l_queue_destroy(net->app_keys, appkey_key_free);

	l_free(net);
}

bool mesh_net_set_seq_num(struct mesh_net *net, uint32_t seq)
{
	if (!net)
		return false;

	net->seq_num = seq;
	node_set_sequence_number(net->node, net->seq_num);

	return true;
}

bool mesh_net_set_default_ttl(struct mesh_net *net, uint8_t ttl)
{
	if (!net)
		return false;

	net->default_ttl = ttl;

	return true;
}

uint32_t mesh_net_get_seq_num(struct mesh_net *net)
{
	if (!net)
		return 0;

	return net->seq_num;
}

uint8_t mesh_net_get_default_ttl(struct mesh_net *net)
{
	if (!net)
		return 0;

	return net->default_ttl;
}

uint16_t mesh_net_get_address(struct mesh_net *net)
{
	if (!net)
		return 0;

	return net->src_addr;
}

bool mesh_net_register_unicast(struct mesh_net *net,
					uint16_t address, uint8_t num_ele)
{
	if (!net || !IS_UNICAST(address) || !num_ele)
		return false;

	net->src_addr = address;
	net->last_addr = address + num_ele - 1;
	if (net->last_addr < net->src_addr)
		return false;

	do {
		mesh_net_dst_reg(net, address);
		address++;
		num_ele--;
	} while (num_ele > 0);

	return true;
}

uint8_t mesh_net_get_num_ele(struct mesh_net *net)
{
	if (!net)
		return 0;

	return net->last_addr - net->src_addr + 1;
}

bool mesh_net_set_proxy_mode(struct mesh_net *net, bool enable)
{
	if (!net)
		return false;

	/* No support for proxy yet */
	if (enable) {
		l_error("Proxy not supported!");
		return false;
	}

	trigger_heartbeat(net, FEATURE_PROXY, enable);
	return true;
}

bool mesh_net_set_friend_mode(struct mesh_net *net, bool enable)
{
	if (!net)
		return false;

	if (net->friend_enable && !enable)
		l_queue_clear(net->friends, mesh_friend_free);

	net->friend_enable = enable;
	trigger_heartbeat(net, FEATURE_FRIEND, enable);
	return true;
}

bool mesh_net_set_relay_mode(struct mesh_net *net, bool enable,
				uint8_t cnt, uint8_t interval)
{
	if (!net)
		return false;

	net->relay.enable = enable;
	net->relay.count = cnt;
	net->relay.interval = interval;
	trigger_heartbeat(net, FEATURE_RELAY, enable);
	return true;
}

struct mesh_net_prov_caps *mesh_net_prov_caps_get(struct mesh_net *net)
{
	if (net)
		return &net->prov_caps;

	return NULL;
}

char *mesh_net_id_name(struct mesh_net *net)
{
	if (net && net->id_name[0])
		return net->id_name;

	return NULL;
}

bool mesh_net_id_uuid_set(struct mesh_net *net, uint8_t uuid[16])
{
	if (!net)
		return false;

	memcpy(net->id_uuid, uuid, 16);

	return true;
}

uint8_t *mesh_net_priv_key_get(struct mesh_net *net)
{
	if (net)
		return net->prov_priv_key;

	return NULL;
}

bool mesh_net_priv_key_set(struct mesh_net *net, uint8_t key[32])
{
	if (!net)
		return false;

	memcpy(net->prov_priv_key, key, 32);
	return true;
}

uint8_t *mesh_net_test_addr(struct mesh_net *net)
{
	const uint8_t zero_addr[] = {0, 0, 0, 0, 0, 0};

	if (net && memcmp(net->test_bd_addr, zero_addr, 6))
		return net->test_bd_addr;

	return NULL;
}

uint8_t *mesh_net_prov_rand(struct mesh_net *net)
{
	if (net)
		return net->prov_rand;

	return NULL;
}

uint16_t mesh_net_prov_uni(struct mesh_net *net, uint8_t ele_cnt)
{
	uint16_t uni;
	uint16_t next;

	if (!net)
		return 0;

	next = net->prov_uni_addr.next + ele_cnt;
	if (next > 0x8000 || next > net->prov_uni_addr.high)
		return UNASSIGNED_ADDRESS;

	uni = net->prov_uni_addr.next;
	net->prov_uni_addr.next = next;

	return uni;
}

bool mesh_net_test_mode(struct mesh_net *net)
{
	if (net)
		return net->test_mode;

	return false;
}

int mesh_net_get_identity_mode(struct mesh_net *net, uint16_t idx,
								uint8_t *mode)
{
	struct mesh_subnet *subnet;

	if (!net)
		return MESH_STATUS_UNSPECIFIED_ERROR;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));
	if (!subnet)
		return MESH_STATUS_INVALID_NETKEY;

	/* Currently, proxy mode is not supported */
	*mode = MESH_MODE_UNSUPPORTED;

	return MESH_STATUS_SUCCESS;
}

int mesh_net_del_key(struct mesh_net *net, uint16_t idx)
{
	struct mesh_subnet *subnet;

	if (!net)
		return MESH_STATUS_UNSPECIFIED_ERROR;

	/* Cannot remove primary key */
	if (l_queue_length(net->subnets) <= 1)
		return MESH_STATUS_CANNOT_REMOVE;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));
	if (!subnet)
		return MESH_STATUS_CANNOT_REMOVE;

	/* Delete associated app keys */
	appkey_delete_bound_keys(net, idx);

	/* Disable hearbeat publication on this subnet */
	if (idx == net->heartbeat.pub_net_idx)
		net->heartbeat.pub_dst = UNASSIGNED_ADDRESS;

	/* TODO: cancel beacon_enable on this subnet */

	l_queue_remove(net->subnets, subnet);
	subnet_free(subnet);

	if (!mesh_config_net_key_del(node_config_get(net->node), idx))
		return MESH_STATUS_STORAGE_FAIL;

	return MESH_STATUS_SUCCESS;
}

static struct mesh_subnet *add_key(struct mesh_net *net, uint16_t idx,
							const uint8_t *value)
{
	struct mesh_subnet *subnet;

	subnet = subnet_new(net, idx);
	if (!subnet)
		return NULL;

	subnet->net_key_tx = subnet->net_key_cur = net_key_add(value);
	if (!subnet->net_key_cur) {
		l_free(subnet);
		return NULL;
	}

	if (!create_secure_beacon(net, subnet, subnet->snb.beacon + 1)) {
		subnet_free(subnet);
		return NULL;
	}

	l_queue_push_tail(net->subnets, subnet);

	return subnet;
}

/*
 * This function is called when Configuration Server Model receives
 * a NETKEY_ADD command
 */
int mesh_net_add_key(struct mesh_net *net, uint16_t idx, const uint8_t *value)
{
	struct mesh_subnet *subnet;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));

	if (subnet) {
		if (net_key_confirm(subnet->net_key_cur, value))
			return MESH_STATUS_SUCCESS;
		else
			return MESH_STATUS_IDX_ALREADY_STORED;
	}

	subnet = add_key(net, idx, value);
	if (!subnet)
		return MESH_STATUS_INSUFF_RESOURCES;

	if (!mesh_config_net_key_add(node_config_get(net->node), idx, value)) {
		l_queue_remove(net->subnets, subnet);
		subnet_free(subnet);
		return MESH_STATUS_STORAGE_FAIL;
	}

	if (net->io)
		start_network_beacon(subnet, net);

	return MESH_STATUS_SUCCESS;
}

void mesh_net_flush_msg_queues(struct mesh_net *net)
{
	l_queue_clear(net->msg_cache, mesh_msg_free);
}

uint32_t mesh_net_get_iv_index(struct mesh_net *net)
{
	if (!net)
		return 0xffffffff;

	return net->iv_index - net->iv_update;
}

/* TODO: net key index? */
void mesh_net_get_snb_state(struct mesh_net *net, uint8_t *flags,
							uint32_t *iv_index)
{
	struct mesh_subnet *subnet;

	if (!net || !flags || !iv_index)
		return;

	*iv_index = net->iv_index;
	*flags = (net->iv_upd_state == IV_UPD_UPDATING) ? 0x02 : 0x00;

	subnet = get_primary_subnet(net);
	if (subnet)
		*flags |= subnet->key_refresh ? 0x01 : 0x00;
}

bool mesh_net_get_key(struct mesh_net *net, bool new_key, uint16_t idx,
							uint32_t *key_id)
{
	struct mesh_subnet *subnet;

	if (!net)
		return false;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));
	if (!subnet)
		return false;

	if (!new_key) {
		*key_id = subnet->net_key_cur;
		return true;
	}

	if (!subnet->net_key_upd)
		return false;

	*key_id = subnet->net_key_upd;
	return true;
}

bool mesh_net_key_list_get(struct mesh_net *net, uint8_t *buf, uint16_t *size)
{
	const struct l_queue_entry *entry;
	uint16_t n, buf_size;

	if (!net || !buf || !size)
		return false;

	buf_size = *size;
	if (buf_size < l_queue_length(net->subnets) * 2)
		return false;

	n = 0;
	entry = l_queue_get_entries(net->subnets);

	for (; entry; entry = entry->next) {
		struct mesh_subnet *subnet = entry->data;

		l_put_le16(subnet->idx, buf);
		n += 2;
	}

	*size = n;
	return true;
}

bool mesh_net_get_frnd_seq(struct mesh_net *net)
{
	if (!net)
		return false;

	return net->friend_seq;
}

void mesh_net_set_frnd_seq(struct mesh_net *net, bool seq)
{
	if (!net)
		return;

	net->friend_seq = seq;
}

static bool match_cache(const void *a, const void *b)
{
	const struct mesh_msg *msg = a;
	const struct mesh_msg *tst = b;

	if (msg->seq != tst->seq || msg->mic != tst->mic ||
					msg->src != tst->src)
		return false;

	return true;
}

static bool msg_in_cache(struct mesh_net *net, uint16_t src, uint32_t seq,
								uint32_t mic)
{
	struct mesh_msg *msg;
	struct mesh_msg tst = {
		.src = src,
		.seq = seq,
		.mic = mic,
	};

	msg = l_queue_remove_if(net->msg_cache, match_cache, &tst);

	if (msg) {
		l_debug("Supressing duplicate %4.4x + %6.6x + %8.8x",
							src, seq, mic);
		l_queue_push_head(net->msg_cache, msg);
		return true;
	}

	msg = l_new(struct mesh_msg, 1);
	*msg = tst;
	l_queue_push_head(net->msg_cache, msg);
	l_debug("Add %4.4x + %6.6x + %8.8x", src, seq, mic);

	if (l_queue_length(net->msg_cache) > MSG_CACHE_SIZE) {
		msg = l_queue_peek_tail(net->msg_cache);
		/* Remove Tail (oldest msg in cache) */
		l_debug("Remove %4.4x + %6.6x + %8.8x",
						msg->src, msg->seq, msg->mic);
		if (l_queue_remove(net->msg_cache, msg))
			l_free(msg);
	}

	return false;
}

static bool match_sar_seq0(const void *a, const void *b)
{
	const struct mesh_sar *sar = a;
	uint16_t seqZero = L_PTR_TO_UINT(b);

	return sar->seqZero == seqZero;
}

static bool match_sar_remote(const void *a, const void *b)
{
	const struct mesh_sar *sar = a;
	uint16_t remote = L_PTR_TO_UINT(b);

	return sar->remote == remote;
}

static bool match_msg_timeout(const void *a, const void *b)
{
	const struct mesh_sar *sar = a;
	const struct l_timeout *msg_timeout = b;

	return sar->msg_timeout == msg_timeout;
}

static bool match_seg_timeout(const void *a, const void *b)
{
	const struct mesh_sar *sar = a;
	const struct l_timeout *seg_timeout = b;

	return sar->seg_timeout == seg_timeout;
}

static bool match_dest_dst(const void *a, const void *b)
{
	const struct mesh_destination *dest = a;
	uint16_t dst = L_PTR_TO_UINT(b);

	return dst == dest->dst;
}

static bool match_frnd_dst(const void *a, const void *b)
{
	const struct mesh_friend *frnd = a;
	uint16_t dst = L_PTR_TO_UINT(b);
	int16_t i, grp_cnt = frnd->grp_cnt;
	uint16_t *grp_list = frnd->grp_list;

	/*
	 * Determine if this message is for this friends unicast
	 * address, and/or one of it's group/virtual addresses
	 */
	if (dst >= frnd->dst && dst < (frnd->dst + frnd->ele_cnt))
		return true;

	if (!(dst & 0x8000))
		return false;

	for (i = 0; i < grp_cnt; i++) {
		if (dst == grp_list[i])
			return true;
	}

	return false;
}

static bool is_lpn_friend(struct mesh_net *net, uint16_t addr, bool frnd)
{
	void *tst;

	if (!frnd)
		return false;

	tst = l_queue_find(net->friends, match_frnd_dst, L_UINT_TO_PTR(addr));

	return tst != NULL;
}

static bool is_us(struct mesh_net *net, uint16_t addr, bool src)
{
	void *tst;

	if (IS_ALL_NODES(addr))
		return true;

	if (addr == FRIENDS_ADDRESS)
		return net->friend_enable;

	if (addr == RELAYS_ADDRESS)
		return net->relay.enable;

	if (addr == PROXIES_ADDRESS)
		return net->proxy_enable;

	if (addr >= net->src_addr && addr <= net->last_addr)
		return true;

	tst = l_queue_find(net->destinations, match_dest_dst,
							L_UINT_TO_PTR(addr));

	if (tst == NULL && !src)
		tst = l_queue_find(net->friends, match_frnd_dst,
							L_UINT_TO_PTR(addr));

	return tst != NULL;
}

static struct mesh_friend_msg *mesh_friend_msg_new(uint8_t seg_max)
{
	struct mesh_friend_msg *frnd_msg;

	if (seg_max) {
		size_t size = sizeof(struct mesh_friend_msg) -
					sizeof(struct mesh_friend_seg_one);

		size += (seg_max + 1) * sizeof(struct mesh_friend_seg_12);
		frnd_msg = l_malloc(size);
	} else
		frnd_msg = l_new(struct mesh_friend_msg, 1);


	return frnd_msg;
}


static bool match_ack(const void *a, const void *b)
{
	const struct mesh_friend_msg *old = a;
	const struct mesh_friend_msg *rx = b;
	uint32_t old_hdr;
	uint32_t new_hdr;

	/* Determine if old pkt is ACK to same SAR message that new ACK is */
	if (!old->ctl || old->src != rx->src)
		return false;

	/* Check the quickest items first before digging deeper */
	old_hdr = old->u.one[0].hdr & HDR_ACK_MASK;
	new_hdr = rx->u.one[0].hdr & HDR_ACK_MASK;

	return old_hdr == new_hdr;
}

static void enqueue_friend_pkt(void *a, void *b)
{
	struct mesh_friend *frnd = a;
	struct mesh_friend_msg *pkt, *rx = b;
	size_t size;
	int16_t i;

	if (rx->done)
		return;

	/*
	 * Determine if this message is for this friends unicast
	 * address, and/or one of it's group/virtual addresses
	 */
	if (rx->dst >= frnd->dst && (rx->dst - frnd->dst) < frnd->ele_cnt) {
		rx->done = true;
		goto enqueue;
	}

	if (!(rx->dst & 0x8000))
		return;

	if (!IS_ALL_NODES(rx->dst)) {
		for (i = 0; i < frnd->grp_cnt; i++) {
			if (rx->dst == frnd->grp_list[i])
				goto enqueue;
		}
		return;
	}

enqueue:
	/* Special handling for Seg Ack -- Only one per message queue */
	if (((rx->u.one[0].hdr >> OPCODE_HDR_SHIFT) & OPCODE_MASK) ==
						NET_OP_SEG_ACKNOWLEDGE) {
		void *old_head = l_queue_peek_head(frnd->pkt_cache);
		/* Suppress duplicate ACKs */
		do {
			void *old = l_queue_remove_if(frnd->pkt_cache,
							match_ack, rx);

			if (old) {
				if (old_head == old) {
					/*
					 * If we are discarding head for any
					 * reason, reset FRND SEQ
					 */
					frnd->last = frnd->seq;
				}

				l_free(old);
			} else
				break;

		} while (true);
	}

	l_debug("%s for %4.4x from %4.4x ttl: %2.2x (seq: %6.6x) (ctl: %d)",
			__func__, frnd->dst, rx->src, rx->ttl,
			rx->u.one[0].seq, rx->ctl);

	if (rx->cnt_in) {
		size = sizeof(struct mesh_friend_msg) -
				sizeof(struct mesh_friend_seg_one);
		size += (rx->cnt_in + 1) * sizeof(struct mesh_friend_seg_12);
	} else
		size = sizeof(struct mesh_friend_msg);

	pkt = l_malloc(size);
	memcpy(pkt, rx, size);

	l_queue_push_tail(frnd->pkt_cache, pkt);

	if (l_queue_length(frnd->pkt_cache) > FRND_CACHE_MAX) {
		/*
		 * TODO: Guard against popping UPDATE packets
		 * (disallowed per spec)
		 */
		pkt = l_queue_pop_head(frnd->pkt_cache);
		l_free(pkt);
		frnd->last = frnd->seq;
	}
}

static void enqueue_update(void *a, void *b)
{
	struct mesh_friend *frnd = a;
	struct mesh_friend_msg *pkt = b;

	pkt->dst = frnd->dst;
	pkt->done = false;
	enqueue_friend_pkt(frnd, pkt);
}

static uint32_t seq_auth(uint32_t seq, uint16_t seqZero)
{
	uint32_t seqAuth = seqZero & SEQ_ZERO_MASK;

	seqAuth |= seq & (~SEQ_ZERO_MASK);
	if (seqAuth > seq)
		seqAuth -= (SEQ_ZERO_MASK + 1);

	return seqAuth;
}

static bool friend_packet_queue(struct mesh_net *net,
					uint32_t iv_index,
					bool ctl, uint8_t ttl,
					uint32_t seq,
					uint16_t src, uint16_t dst,
					uint32_t hdr,
					const uint8_t *data, uint16_t size)
{
	struct mesh_friend_msg *frnd_msg;
	uint8_t seg_max = SEG_TOTAL(hdr);
	bool ret;

	if (seg_max && !IS_SEGMENTED(hdr))
		return false;

	frnd_msg = mesh_friend_msg_new(seg_max);

	if (IS_SEGMENTED(hdr)) {
		uint32_t seqAuth = seq_auth(seq, hdr >> SEQ_ZERO_HDR_SHIFT);
		uint8_t i;

		for (i = 0; i <= seg_max; i++) {
			memcpy(frnd_msg->u.s12[i].data, data, 12);
			frnd_msg->u.s12[i].hdr = hdr;
			frnd_msg->u.s12[i].seq = seqAuth + i;
			data += 12;
			hdr += (1 << SEGO_HDR_SHIFT);
		}
		frnd_msg->u.s12[seg_max].seq = seq;
		frnd_msg->cnt_in = seg_max;
		frnd_msg->last_len = size % 12;
		if (!frnd_msg->last_len)
			frnd_msg->last_len = 12;
	} else {
		uint8_t opcode = hdr >> OPCODE_HDR_SHIFT;

		if (ctl && opcode != NET_OP_SEG_ACKNOWLEDGE) {

			/* Don't cache Friend Ctl opcodes */
			if (FRND_OPCODE(opcode)) {
				l_free(frnd_msg);
				return false;
			}

			memcpy(frnd_msg->u.one[0].data + 1, data, size);
			frnd_msg->last_len = size + 1;
			frnd_msg->u.one[0].data[0] = opcode;
		} else {
			memcpy(frnd_msg->u.one[0].data, data, size);
			frnd_msg->last_len = size;
		}
		frnd_msg->u.one[0].hdr = hdr;
		frnd_msg->u.one[0].seq = seq;
	}

	frnd_msg->iv_index = iv_index;
	frnd_msg->src = src;
	frnd_msg->dst = dst;
	frnd_msg->ctl = ctl;
	frnd_msg->ttl = ttl;

	/* Re-Package into Friend Delivery payload */
	l_queue_foreach(net->friends, enqueue_friend_pkt, frnd_msg);
	ret = frnd_msg->done;

	/* TODO Optimization(?): Unicast messages keep this buffer */
	l_free(frnd_msg);

	return ret;
}

static void friend_ack_rxed(struct mesh_net *net, uint32_t iv_index,
					uint32_t seq,
					uint16_t src, uint16_t dst,
					const uint8_t *pkt)
{
	uint32_t hdr = l_get_be32(pkt) &
		((SEQ_ZERO_MASK << SEQ_ZERO_HDR_SHIFT) | /* Preserve SeqZero */
		 (true << RELAY_HDR_SHIFT));		/* Preserve Relay bit */
	uint32_t flags = l_get_be32(pkt + 3);
	struct mesh_friend_msg frnd_ack = {
		.ctl = true,
		.iv_index = iv_index,
		.src = src,
		.dst = dst,
		.last_len = sizeof(flags),
		.u.one[0].seq = seq,
		.done = false,
	};

	hdr |= NET_OP_SEG_ACKNOWLEDGE << OPCODE_HDR_SHIFT;
	frnd_ack.u.one[0].hdr = hdr;
	l_put_be32(flags, frnd_ack.u.one[0].data);
	l_queue_foreach(net->friends, enqueue_friend_pkt, &frnd_ack);
}

static bool send_seg(struct mesh_net *net, struct mesh_sar *msg, uint8_t seg);

static void send_frnd_ack(struct mesh_net *net, uint16_t src, uint16_t dst,
						uint32_t hdr, uint32_t flags)
{
	uint32_t expected;
	uint8_t msg[7];

	/* We don't ACK from multicast destinations */
	if (src & 0x8000)
		return;

	/* Calculate the "Full ACK" mask */
	expected = 0xffffffff >> (31 - SEG_TOTAL(hdr));

	/* Clear Hdr bits that don't apply to Seg ACK */
	hdr &= ~((true << SEG_HDR_SHIFT) |
			(OPCODE_MASK << OPCODE_HDR_SHIFT) |
			(true << SZMIC_HDR_SHIFT) |
			(SEG_MASK << SEGO_HDR_SHIFT) |
			(SEG_MASK << SEGN_HDR_SHIFT));

	hdr |= NET_OP_SEG_ACKNOWLEDGE << OPCODE_HDR_SHIFT;
	hdr |= true << RELAY_HDR_SHIFT;

	/* Clear all unexpected bits */
	flags &= expected;

	l_put_be32(hdr, msg);
	l_put_be32(flags, msg + 3);

	l_info("Send Friend ACK to Segs: %8.8x", flags);

	if (is_lpn_friend(net, dst, true)) {
		/* If we are acking our LPN Friend, queue, don't send */
		friend_ack_rxed(net, mesh_net_get_iv_index(net),
				mesh_net_next_seq_num(net), 0, dst, msg);
	} else {
		mesh_net_transport_send(net, 0, false,
				mesh_net_get_iv_index(net), DEFAULT_TTL,
				0, 0, dst, msg, sizeof(msg));
	}
}

static void send_net_ack(struct mesh_net *net, struct mesh_sar *sar,
								uint32_t flags)
{
	uint8_t msg[7];
	uint32_t hdr;
	uint16_t src = sar->src;
	uint16_t dst = sar->remote;

	/* We don't ACK from multicast destinations */
	if (src & 0x8000)
		return;

	/* We don't ACK segments as a Low Power Node */
	if (net->friend_addr)
		return;

	hdr = NET_OP_SEG_ACKNOWLEDGE << OPCODE_HDR_SHIFT;
	hdr |= sar->seqZero << SEQ_ZERO_HDR_SHIFT;

	if (is_lpn_friend(net, src, true))
		hdr |= true << RELAY_HDR_SHIFT;

	l_put_be32(hdr, msg);
	l_put_be32(flags, msg + 3);
	l_info("Send%s ACK to Segs: %8.8x", sar->frnd ? " Friend" : "", flags);

	if (is_lpn_friend(net, dst, true)) {
		/* If we are acking our LPN Friend, queue, don't send */
		friend_ack_rxed(net, mesh_net_get_iv_index(net),
				mesh_net_next_seq_num(net), src, dst, msg);
		return;
	}

	mesh_net_transport_send(net, 0, false,
				mesh_net_get_iv_index(net), DEFAULT_TTL,
				0, src, dst, msg, sizeof(msg));
}

static void inseg_to(struct l_timeout *seg_timeout, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_sar *sar = l_queue_find(net->sar_in,
					match_seg_timeout, seg_timeout);

	l_timeout_remove(seg_timeout);
	if (!sar)
		return;

	/* Send NAK */
	l_info("Timeout %p %3.3x", sar, sar->app_idx);
	send_net_ack(net, sar, sar->flags);

	sar->seg_timeout = l_timeout_create(SEG_TO, inseg_to, net, NULL);
}

static void inmsg_to(struct l_timeout *msg_timeout, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_sar *sar = l_queue_remove_if(net->sar_in,
			match_msg_timeout, msg_timeout);

	l_timeout_remove(msg_timeout);
	if (!sar)
		return;

	sar->msg_timeout = NULL;

	/* print_packet("Incoming SAR Timeout", sar->buf, sar->len); */
	mesh_sar_free(sar);
}

static void outmsg_to(struct l_timeout *msg_timeout, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_sar *sar = l_queue_remove_if(net->sar_out,
			match_msg_timeout, msg_timeout);

	l_timeout_remove(msg_timeout);
	if (!sar)
		return;

	sar->msg_timeout = NULL;

	if (sar->status_func)
		sar->status_func(sar->remote, 1,
				sar->buf, sar->len - 4,
				sar->user_data);

	/* print_packet("Outgoing SAR Timeout", sar->buf, sar->len); */
	mesh_sar_free(sar);
}

static void outseg_to(struct l_timeout *seg_timeout, void *user_data);
static void ack_received(struct mesh_net *net, bool timeout,
				uint16_t src, uint16_t dst,
				uint16_t seq0, uint32_t ack_flag)
{
	struct mesh_sar *outgoing;
	uint32_t seg_flag = 0x00000001;
	uint32_t ack_copy = ack_flag;
	uint16_t i;

	l_info("ACK Rxed (%x) (to:%d): %8.8x", seq0, timeout, ack_flag);

	outgoing = l_queue_find(net->sar_out, match_sar_seq0,
							L_UINT_TO_PTR(seq0));

	if (!outgoing) {
		l_info("Not Found: %4.4x", seq0);
		return;
	}

	/*
	 * TODO -- If we receive from different
	 * SRC than we are sending to, make sure the OBO flag is set
	 */

	if ((!timeout && !ack_flag) ||
			(outgoing->flags & ack_flag) == outgoing->flags) {
		l_debug("ob_sar_removal (%x)", outgoing->flags);

		/* Note: ack_flags == 0x00000000 is a remote Cancel request */
		if (outgoing->status_func)
			outgoing->status_func(src, ack_flag ? 0 : 1,
					outgoing->buf,
					outgoing->len - 4, outgoing->user_data);

		l_queue_remove(net->sar_out, outgoing);
		mesh_sar_free(outgoing);

		return;
	}

	outgoing->last_nak |= ack_flag;

	ack_copy &= outgoing->flags;

	for (i = 0; i <= SEG_MAX(outgoing->len); i++, seg_flag <<= 1) {
		if (seg_flag & ack_flag) {
			l_debug("Skipping Seg %d of %d",
					i, SEG_MAX(outgoing->len));
			continue;
		}

		ack_copy |= seg_flag;

		l_info("Resend Seg %d net:%p dst:%x app_idx:%3.3x",
				i, net, outgoing->remote, outgoing->app_idx);

		send_seg(net, outgoing, i);
	}

	l_timeout_remove(outgoing->seg_timeout);
	outgoing->seg_timeout = l_timeout_create(SEG_TO, outseg_to, net, NULL);
}

static void outack_to(struct l_timeout *seg_timeout, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_sar *sar = l_queue_find(net->sar_out,
					match_seg_timeout, seg_timeout);

	l_timeout_remove(seg_timeout);
	if (!sar)
		return;

	sar->seg_timeout = NULL;

	/* Re-Send missing segments by faking NAK */
	ack_received(net, true, sar->remote, sar->src,
				sar->seqZero, sar->last_nak);
}

static void outseg_to(struct l_timeout *seg_timeout, void *user_data)
{
	struct mesh_net *net = user_data;
	struct mesh_sar *sar = l_queue_find(net->sar_out,
					match_seg_timeout, seg_timeout);

	l_timeout_remove(seg_timeout);
	if (!sar)
		return;

	sar->seg_timeout = NULL;

	if (net->friend_addr) {
		/* We are LPN -- Poll for ACK */
		frnd_ack_poll(net);
		sar->seg_timeout = l_timeout_create(SEG_TO,
				outack_to, net, NULL);
	} else {
		/* Re-Send missing segments by faking NACK */
		ack_received(net, true, sar->remote, sar->src,
					sar->seqZero, sar->last_nak);
	}
}

static bool msg_rxed(struct mesh_net *net, bool frnd, uint32_t iv_index,
					uint8_t ttl, uint32_t seq,
					uint16_t net_idx,
					uint16_t src, uint16_t dst,
					uint8_t key_aid,
					bool szmic, uint16_t seqZero,
					const uint8_t *data, uint16_t size)
{
	uint32_t seqAuth = seq_auth(seq, seqZero);

	/* Sanity check seqAuth */
	if (seqAuth > seq)
		return false;

	/* Save un-decrypted messages for our friends */
	if (!frnd && l_queue_length(net->friends)) {
		uint32_t hdr = key_aid << KEY_HDR_SHIFT;
		uint8_t frnd_ttl = ttl;

		/* If not from us, decrement for our hop */
		if (src < net->src_addr || src > net->last_addr) {
			if (frnd_ttl > 1)
				frnd_ttl--;
			else
				goto not_for_friend;
		}

		if (szmic || size > 15) {
			hdr |= true << SEG_HDR_SHIFT;
			hdr |= szmic << SZMIC_HDR_SHIFT;
			hdr |= (seqZero & SEQ_ZERO_MASK) << SEQ_ZERO_HDR_SHIFT;
			hdr |= SEG_MAX(size) << SEGN_HDR_SHIFT;
		}

		if (friend_packet_queue(net, iv_index, false, frnd_ttl,
					seq, src, dst,
					hdr, data, size))
			return true;
	}

not_for_friend:
	return mesh_model_rx(net->node, szmic, seqAuth, seq, iv_index, ttl,
					net_idx, src, dst, key_aid, data, size);
}

static bool match_frnd_sar_dst(const void *a, const void *b)
{
	const struct mesh_friend_msg *frnd_msg = a;
	uint16_t dst = L_PTR_TO_UINT(b);

	return frnd_msg->dst == dst;
}

static void friend_seg_rxed(struct mesh_net *net,
				uint32_t iv_index,
				uint8_t ttl, uint32_t seq,
				uint16_t src, uint16_t dst, uint32_t hdr,
				const uint8_t *data, uint8_t size)
{
	struct mesh_friend *frnd = NULL;
	struct mesh_friend_msg *frnd_msg = NULL;
	uint8_t cnt;
	uint8_t segN = hdr & 0x1f;
	uint8_t segO = ((hdr >> 5) & 0x1f);
	uint32_t expected = 0xffffffff >> (31 - segN);
	uint32_t this_seg_flag = 0x00000001 << segO;
	uint32_t largest = (0xffffffff << segO) & expected;
	uint32_t hdr_key =  hdr & HDR_KEY_MASK;

	frnd = l_queue_find(net->friends, match_frnd_dst,
			L_UINT_TO_PTR(dst));
	if (!frnd)
		return;

	if (frnd->last_hdr == hdr_key) {
		/* We are no longer receiving this msg. Resend final ACK */
		send_frnd_ack(net, dst, src, frnd->last_hdr, 0xffffffff);
		return;
	}

	/* Check if we have a SAR-in-progress that matches incoming segment */
	frnd_msg = l_queue_find(net->frnd_msgs, match_frnd_sar_dst,
			L_UINT_TO_PTR(dst));

	if (frnd_msg) {
		/* Flush if SZMICN or IV Index has changed */
		if (frnd_msg->iv_index != iv_index)
			frnd_msg->u.s12[0].hdr = 0;

		/* Flush incomplete old SAR message if it doesn't match */
		if ((frnd_msg->u.s12[0].hdr & HDR_KEY_MASK) != hdr_key) {
			l_queue_remove(net->frnd_msgs, frnd_msg);
			l_free(frnd_msg);
			frnd_msg = NULL;
		}
	}

	if (!frnd_msg) {
		frnd_msg = mesh_friend_msg_new(segN);
		frnd_msg->iv_index = iv_index;
		frnd_msg->src = src;
		frnd_msg->dst = dst;
		frnd_msg->ttl = ttl;
		l_queue_push_tail(net->frnd_msgs, frnd_msg);
	} else if (frnd_msg->flags & this_seg_flag) /* Ignore dup segs */
		return;

	cnt = frnd_msg->cnt_in;
	frnd_msg->flags |= this_seg_flag;

	frnd_msg->u.s12[cnt].hdr = hdr;
	frnd_msg->u.s12[cnt].seq = seq;
	memcpy(frnd_msg->u.s12[cnt].data, data, size);

	/* Last segment could be short */
	if (segN == segO)
		frnd_msg->last_len = size;

	l_info("RXed Seg %d, Flags %8.8x (cnt: %d)",
						segO, frnd_msg->flags, cnt);

	/* In reality, if one of these is true, then *both* must be true */
	if ((cnt == segN) || (frnd_msg->flags == expected)) {
		l_info("Full ACK");
		send_frnd_ack(net, dst, src, hdr, frnd_msg->flags);

		if (frnd_msg->ttl > 1) {
			frnd_msg->ttl--;
			/* Add to friends cache  */
			l_queue_foreach(net->friends,
					enqueue_friend_pkt, frnd_msg);
		}

		/* Remove from "in progress" queue */
		l_queue_remove(net->frnd_msgs, frnd_msg);

		/* TODO Optimization(?): Unicast messages keep this buffer */
		l_free(frnd_msg);
		return;
	}

	/* Always ACK if this is the largest outstanding segment */
	if ((largest & frnd_msg->flags) == largest) {
		l_info("Partial ACK");
		send_frnd_ack(net, dst, src, hdr, frnd_msg->flags);
	}

	frnd_msg->cnt_in++;
}

static bool seg_rxed(struct mesh_net *net, bool frnd, uint32_t iv_index,
					uint8_t ttl, uint32_t seq,
					uint16_t net_idx,
					uint16_t src, uint16_t dst,
					uint8_t key_aid,
					bool szmic, uint16_t seqZero,
					uint8_t segO, uint8_t segN,
					const uint8_t *data, uint8_t size)
{
	struct mesh_sar *sar_in = NULL;
	uint16_t seg_off = 0;
	uint32_t expected, this_seg_flag, largest, seqAuth;
	bool reset_seg_to = true;

	/*
	 * DST could receive additional Segments after
	 * completing due to a lost ACK, so re-ACK and discard
	 */
	sar_in = l_queue_find(net->sar_in, match_sar_remote,
						L_UINT_TO_PTR(src));

	/* Discard *old* incoming-SAR-in-progress if this segment newer */
	seqAuth = seq_auth(seq, seqZero);
	if (sar_in && (sar_in->seqAuth != seqAuth ||
				sar_in->iv_index != iv_index)) {
		bool newer;

		if (iv_index > sar_in->iv_index)
			newer = true;
		else if (iv_index == sar_in->iv_index)
			newer = seqAuth > sar_in->seqAuth;
		else
			newer = false;

		if (newer) {
			/* Cancel Old, start New */
			l_queue_remove(net->sar_in, sar_in);
			mesh_sar_free(sar_in);
			sar_in = NULL;
		} else
			/* Ignore Old */
			return false;
	}

	expected = 0xffffffff >> (31 - segN);

	if (sar_in) {
		l_info("RXed (old: %04x %06x size:%d) %d of %d",
					seqZero, seq, size, segO, segN);
		/* Sanity Check--> certain things must match */
		if (SEG_MAX(sar_in->len) != segN ||
				sar_in->key_aid != key_aid)
			return false;

		if (sar_in->flags == expected) {
			/* Re-Send ACK for full msg */
			if (!net->friend_addr)
				send_net_ack(net, sar_in, expected);
			return true;
		}
	} else {
		uint16_t len = MAX_SEG_TO_LEN(segN);

		l_info("RXed (new: %04x %06x size: %d len: %d) %d of %d",
				seqZero, seq, size, len, segO, segN);
		l_debug("Queue Size: %d", l_queue_length(net->sar_in));
		sar_in = mesh_sar_new(len);
		sar_in->seqAuth = seqAuth;
		sar_in->iv_index = iv_index;
		sar_in->src = dst;
		sar_in->remote = src;
		sar_in->seqZero = seqZero;
		sar_in->key_aid = key_aid;
		sar_in->len = len;
		sar_in->last_seg = 0xff;
		if (!net->friend_addr)
			sar_in->msg_timeout = l_timeout_create(MSG_TO,
					inmsg_to, net, NULL);

		l_debug("First Seg %4.4x", sar_in->flags);
		l_queue_push_head(net->sar_in, sar_in);
	}
	/* print_packet("Seg", data, size); */

	seg_off = segO * MAX_SEG_LEN;
	memcpy(sar_in->buf + seg_off, data, size);
	this_seg_flag = 0x00000001 << segO;

	/* Don't reset Seg TO or NAK if we already have this seg */
	if (this_seg_flag & sar_in->flags)
		reset_seg_to = false;

	sar_in->flags |= this_seg_flag;
	sar_in->ttl = ttl;

	l_debug("Have Frags %4.4x", sar_in->flags);

	/* Msg length only definitive on last segment */
	if (segO == segN)
		sar_in->len = segN * MAX_SEG_LEN + size;

	if (sar_in->flags == expected) {
		/* Got it all */
		if (!net->friend_addr)
			send_net_ack(net, sar_in, expected);

		msg_rxed(net, frnd, iv_index, ttl, seq, net_idx,
				sar_in->remote, dst,
				key_aid,
				szmic, sar_in->seqZero,
				sar_in->buf, sar_in->len);

		/* Kill Inter-Seg timeout */
		l_timeout_remove(sar_in->seg_timeout);
		sar_in->seg_timeout = NULL;
		return true;
	}

	if (reset_seg_to) {
		/* Restart Inter-Seg Timeout */
		l_timeout_remove(sar_in->seg_timeout);

		/* if this is the largest outstanding segment, send NAK now */
		if (!net->friend_addr) {
			largest = (0xffffffff << segO) & expected;
			if ((largest & sar_in->flags) == largest)
				send_net_ack(net, sar_in, sar_in->flags);

			sar_in->seg_timeout = l_timeout_create(SEG_TO,
				inseg_to, net, NULL);
		} else
			largest = 0;
	} else
		largest = 0;

	l_debug("NAK: %d expected:%08x largest:%08x flags:%08x",
			reset_seg_to, expected, largest, sar_in->flags);
	return false;
}

static bool ctl_received(struct mesh_net *net, bool frnd, uint32_t iv_index,
						uint8_t ttl,
						uint32_t seq,
						uint16_t src, uint16_t dst,
						uint8_t opcode, int8_t rssi,
						const uint8_t *pkt, uint8_t len)
{
	uint8_t msg[12];
	uint8_t rsp_ttl = DEFAULT_TTL;
	uint8_t n = 0;

	if (!frnd && ttl > 1) {
		uint32_t hdr = opcode << OPCODE_HDR_SHIFT;
		uint8_t frnd_ttl = ttl - 1;

		if (friend_packet_queue(net, iv_index,
					true, frnd_ttl,
					seq,
					src, dst,
					hdr,
					pkt, len))
			return true;
	}

	/* Don't process other peoples Unicast destinations */
	if (dst < 0x8000 && (dst < net->src_addr || dst > net->last_addr))
		return false;

	switch (opcode) {
	default:
		l_error("Unsupported Ctl Opcode: %2.2x", opcode);
		break;

	case NET_OP_FRND_POLL:
		if (len != 1 || ttl)
			return false;

		print_packet("Rx-NET_OP_FRND_POLL", pkt, len);
		friend_poll(net, src, !!(pkt[0]),
				l_queue_find(net->friends,
						match_by_friend,
						L_UINT_TO_PTR(src)));
		break;

	case NET_OP_FRND_UPDATE:
		if (ttl)
			return false;

		print_packet("Rx-NET_OP_FRND_UPDATE", pkt, len);
		lpn_process_beacon(net, pkt, len, 0);
		break;

	case NET_OP_FRND_REQUEST:
		if (!net->friend_enable)
			return false;

		if (!IS_ALL_NODES(dst) && dst != FRIENDS_ADDRESS)
			return false;

		if (len != 10 || ttl)
			return false;

		print_packet("Rx-NET_OP_FRND_REQUEST", pkt, len);
		friend_request(net, src, pkt[0], pkt[1],
				l_get_be32(pkt + 1) & 0xffffff,
				l_get_be16(pkt + 5), pkt[7],
				l_get_be16(pkt + 8), rssi);
		break;

	case NET_OP_FRND_OFFER:
		if (len != 6 || ttl)
			return false;

		print_packet("Rx-NET_OP_FRND_OFFER", pkt, len);
		frnd_offer(net, src, pkt[0], pkt[1], pkt[2],
				(int8_t) pkt[3], rssi, l_get_be16(pkt + 4));
		break;

	case NET_OP_FRND_CLEAR_CONFIRM:
		if (len != 4)
			return false;

		print_packet("Rx-NET_OP_FRND_CLEAR_CONFIRM", pkt, len);
		friend_clear_confirm(net, src, l_get_be16(pkt),
						l_get_be16(pkt + 2));
		break;

	case NET_OP_FRND_CLEAR:
		if (len != 4 || dst != net->src_addr)
			return false;

		print_packet("Rx-NET_OP_FRND_CLEAR", pkt, len);
		friend_clear(net, src, l_get_be16(pkt), l_get_be16(pkt + 2),
				l_queue_find(net->friends,
					match_by_friend,
					L_UINT_TO_PTR(l_get_be16(pkt))));
		l_info("Remaining Friends: %d", l_queue_length(net->friends));
		break;

	case NET_OP_PROXY_SUB_ADD:
		if (ttl)
			return false;

		print_packet("Rx-NET_OP_PROXY_SUB_ADD", pkt, len);
		friend_sub_add(net, l_queue_find(net->friends,
					match_by_friend, L_UINT_TO_PTR(src)),
				pkt, len);
		break;

	case NET_OP_PROXY_SUB_REMOVE:
		if (ttl)
			return false;

		print_packet("Rx-NET_OP_PROXY_SUB_REMOVE", pkt, len);
		friend_sub_del(net, l_queue_find(net->friends,
					match_by_friend, L_UINT_TO_PTR(src)),
				pkt, len);
		break;

	case NET_OP_PROXY_SUB_CONFIRM:
		if (ttl)
			return false;

		print_packet("Rx-NET_OP_PROXY_SUB_CONFIRM", pkt, len);
		break;

	case NET_OP_HEARTBEAT:
		if (net->heartbeat.sub_enabled &&
				src == net->heartbeat.sub_src) {
			uint8_t hops = pkt[0] - ttl + 1;

			print_packet("Rx-NET_OP_HEARTBEAT", pkt, len);

			if (net->heartbeat.sub_count != 0xffff)
				net->heartbeat.sub_count++;

			if (net->heartbeat.sub_min_hops > hops)
				net->heartbeat.sub_min_hops = hops;

			if (net->heartbeat.sub_max_hops < hops)
				net->heartbeat.sub_max_hops = hops;

			l_info("HB: cnt:%4.4x min:%2.2x max:%2.2x",
					net->heartbeat.sub_count,
					net->heartbeat.sub_min_hops,
					net->heartbeat.sub_max_hops);
		}
		break;
	}

	if (n) {
		mesh_net_transport_send(net, 0, false,
				mesh_net_get_iv_index(net), rsp_ttl,
				0, dst & 0x8000 ? 0 : dst, src,
				msg, n);
	}

	return true;
}

static bool find_fast_hash(const void *a, const void *b)
{
	const uint64_t *entry = a;
	const uint64_t *test = b;

	return *entry == *test;
}

static bool check_fast_cache(uint64_t hash)
{
	void *found = l_queue_find(fast_cache, find_fast_hash, &hash);
	uint64_t *new_hash;

	if (found)
		return false;

	if (l_queue_length(fast_cache) >= FAST_CACHE_SIZE)
		new_hash = l_queue_pop_head(fast_cache);
	else
		new_hash = l_malloc(sizeof(hash));

	*new_hash = hash;
	l_queue_push_tail(fast_cache, new_hash);

	return true;
}

static bool match_by_dst(const void *a, const void *b)
{
	const struct mesh_destination *dest = a;
	uint16_t dst = L_PTR_TO_UINT(b);

	return dest->dst == dst;
}

static void send_relay_pkt(struct mesh_net *net, uint8_t *data, uint8_t size)
{
	uint8_t packet[30];
	struct mesh_io *io = net->io;
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.interval = net->relay.interval,
		.u.gen.cnt = net->relay.count,
		.u.gen.min_delay = DEFAULT_MIN_DELAY,
		.u.gen.max_delay = DEFAULT_MAX_DELAY
	};

	packet[0] = MESH_AD_TYPE_NETWORK;
	memcpy(packet + 1, data, size);

	mesh_io_send(io, &info, packet, size + 1);
}

static void send_msg_pkt(struct mesh_net *net, uint8_t *packet, uint8_t size)
{
	struct mesh_io *io = net->io;
	struct mesh_io_send_info info;
	struct net_queue_data net_data = {
		.info = NULL,
		.data = packet + 1,
		.len = size - 1,
		.relay_advice = RELAY_NONE,
	};

	/* Send to local nodes first */
	l_queue_foreach(nets, net_rx, &net_data);

	if (net_data.relay_advice == RELAY_DISALLOWED)
		return;

	packet[0] = MESH_AD_TYPE_NETWORK;
	info.type = MESH_IO_TIMING_TYPE_GENERAL;
	info.u.gen.interval = net->tx_interval;
	info.u.gen.cnt = net->tx_cnt;
	info.u.gen.min_delay = DEFAULT_MIN_DELAY;
	/* No extra randomization when sending regular mesh messages */
	info.u.gen.max_delay = DEFAULT_MIN_DELAY;

	mesh_io_send(io, &info, packet, size);
}

static uint16_t key_id_to_net_idx(struct mesh_net *net, uint32_t key_id)
{
	struct mesh_subnet *subnet;

	if (!net)
		return NET_IDX_INVALID;

	subnet = l_queue_find(net->subnets, match_key_id,
						L_UINT_TO_PTR(key_id));

	if (subnet)
		return subnet->idx;
	else
		return NET_IDX_INVALID;
}

static enum _relay_advice packet_received(void *user_data,
				uint32_t key_id, uint32_t iv_index,
				const void *data, uint8_t size, int8_t rssi)
{
	struct mesh_net *net = user_data;
	const uint8_t *msg = data;
	uint8_t app_msg_len;
	uint8_t net_ttl, net_key_id, net_segO, net_segN, net_opcode;
	uint32_t net_seq, cache_cookie;
	uint16_t net_src, net_dst, net_seqZero;
	uint16_t net_idx;
	uint8_t packet[31];
	bool net_ctl, net_segmented, net_szmic, net_relay;
	struct mesh_friend *net_frnd = NULL;
	bool drop = false;

	/* Tester--Drop 90% of packets */
	/* l_getrandom(&iv_flag, 1); */
	/* if (iv_flag%10<9) drop = true; */


	memcpy(packet + 2, data, size);

	if (!drop)
		print_packet("RX: Network [clr] :", packet + 2, size);

	net_idx = key_id_to_net_idx(net, key_id);
	if (net_idx == NET_IDX_INVALID)
		return RELAY_NONE;

	if (!mesh_crypto_packet_parse(packet + 2, size,
					&net_ctl, &net_ttl,
					&net_seq,
					&net_src, &net_dst,
					&cache_cookie,
					&net_opcode,
					&net_segmented,
					&net_key_id,
					&net_szmic, &net_relay, &net_seqZero,
					&net_segO, &net_segN,
					&msg, &app_msg_len)) {
		l_error("Failed to parse packet content");
		return RELAY_NONE;
	}

	/* Ignore incoming packets if we are LPN and frnd bit not set */
	if (net->friend_addr) {
		struct mesh_subnet *subnet;

		subnet = l_queue_find(net->subnets, match_key_id,
							L_UINT_TO_PTR(key_id));
		if (subnet)
			return RELAY_NONE;

		/* If the queue is empty, stop polling */
		if (net_ctl && net_opcode == NET_OP_FRND_UPDATE && !msg[5])
			frnd_poll_cancel(net);
		else
			frnd_poll(net, false);

	} else if (net_dst == 0) {
		l_error("illegal parms: DST: %4.4x Ctl: %d TTL: %2.2x",
						net_dst, net_ctl, net_ttl);
		return RELAY_NONE;
	}

	/* Ignore if we originally sent this */
	if (is_us(net, net_src, true))
		return RELAY_NONE;

	if (drop) {
		l_info("Dropping SEQ 0x%06x", net_seq);
		return RELAY_NONE;
	}

	l_debug("check %08x", cache_cookie);

	/* As a Relay, suppress repeats of last N packets that pass through */
	/* The "cache_cookie" should be unique part of App message */
	if (msg_in_cache(net, net_src, net_seq, cache_cookie))
		return RELAY_NONE;

	l_debug("RX: Network %04x -> %04x : TTL 0x%02x : IV : %8.8x SEQ 0x%06x",
			net_src, net_dst, net_ttl, iv_index, net_seq);

	if (is_us(net, net_dst, false) ||
			is_lpn_friend(net, net_src, !!(net_frnd)) ||
			(net_ctl && net_opcode == NET_OP_HEARTBEAT)) {

		l_info("RX: App 0x%04x -> 0x%04x : TTL 0x%02x : SEQ 0x%06x",
					net_src, net_dst, net_ttl, net_seq);

		l_debug("seq:%x seq0:%x", net_seq, net_seqZero);
		if (net_ctl) {
			l_debug("CTL - %4.4x RX", net_seqZero);
			if (net_opcode == NET_OP_SEG_ACKNOWLEDGE) {
				/* Illegal to send ACK to non-Unicast Addr */
				if (net_dst & 0x8000)
					return RELAY_NONE;

				/* print_packet("Got ACK", msg, app_msg_len); */
				/* Pedantic check for correct size */
				if (app_msg_len != 7)
					return RELAY_NONE;

				/* If this is an ACK to our friend queue-only */
				if (is_lpn_friend(net, net_dst, true))
					friend_ack_rxed(net, iv_index, net_seq,
							net_src, net_dst,
							msg);
				else
					ack_received(net, false,
							net_src, net_dst,
							net_seqZero,
							l_get_be32(msg + 3));
			} else {
				ctl_received(net, !!(net_frnd), iv_index,
						net_ttl, net_seq, net_src,
						net_dst, net_opcode, rssi,
						msg, app_msg_len);
			}
		} else if (net_segmented) {
			/* If we accept SAR packets to non-Unicast, then
			 * Friend Sar at least needs to be Unicast Only
			 */
			if (is_lpn_friend(net, net_dst, true) &&
							!(net_dst & 0x8000)) {
				/* Check TTL >= 2 before accepting segments
				 * for Friends
				 */
				if (net_ttl >= 2) {
					friend_seg_rxed(net, iv_index,
						net_ttl, net_seq,
						net_src, net_dst,
						l_get_be32(packet + 2 + 9),
						msg, app_msg_len);
				}
			} else {
				seg_rxed(net, net_frnd, iv_index, net_ttl,
						net_seq, net_idx,
						net_src, net_dst,
						net_key_id,
						net_szmic, net_seqZero,
						net_segO, net_segN,
						msg, app_msg_len);
			}

		} else {
			msg_rxed(net, net_frnd,
						iv_index,
						net_ttl,
						net_seq,
						net_idx,
						net_src, net_dst,
						net_key_id,
						false, net_seq & SEQ_ZERO_MASK,
						msg, app_msg_len);
		}

		if (!!(net_frnd))
			l_info("Ask for more data!");

		/* If this is one of our Unicast addresses, disallow relay */
		if (IS_UNICAST(net_dst))
			return RELAY_DISALLOWED;
	}

	/* If relay not enable, or no more hops allowed */
	if (!net->relay.enable || net_ttl < 0x02 || net_frnd)
		return RELAY_NONE;

	/* Group or Virtual destinations should *always* be relayed */
	if (IS_GROUP(net_dst) || IS_VIRTUAL(net_dst))
		return RELAY_ALWAYS;

	/* Unicast destinations for other nodes *may* be relayed */
	else if (IS_UNICAST(net_dst))
		return RELAY_ALLOWED;

	/* Otherwise, do not make a relay decision */
	else
		return RELAY_NONE;
}

static void net_rx(void *net_ptr, void *user_data)
{
	struct net_queue_data *data = user_data;
	struct mesh_net *net = net_ptr;
	enum _relay_advice relay_advice;
	uint8_t *out;
	size_t out_size;
	uint32_t key_id;
	int8_t rssi = 0;
	bool ivi_net = !!(net->iv_index & 1);
	bool ivi_pkt = !!(data->data[0] & 0x80);

	/* if IVI flag differs, use previous IV Index */
	uint32_t iv_index = net->iv_index - (ivi_pkt ^ ivi_net);

	key_id = net_key_decrypt(iv_index, data->data, data->len,
							&out, &out_size);

	if (!key_id)
		return;

	print_packet("RX: Network [enc] :", data->data, data->len);

	if (data->info) {
		net->instant = data->info->instant;
		net->chan = data->info->chan;
		rssi = data->info->rssi;
	}

	relay_advice = packet_received(net, key_id, iv_index,
							out, out_size, rssi);
	if (relay_advice > data->relay_advice) {
		data->iv_index = iv_index;
		data->relay_advice = relay_advice;
		data->key_id = key_id;
		data->net = net;
		data->out = out;
		data->out_size = out_size;
	}
}

static void net_msg_recv(void *user_data, struct mesh_io_recv_info *info,
					const uint8_t *data, uint16_t len)
{
	uint64_t hash;
	bool isNew;
	struct net_queue_data net_data = {
		.info = info,
		.data = data + 1,
		.len = len - 1,
		.relay_advice = RELAY_NONE,
	};

	if (len < 9)
		return;

	hash = l_get_le64(data + 1);

	/* Only process packet once per reception */
	isNew = check_fast_cache(hash);
	if (!isNew)
		return;

	l_queue_foreach(nets, net_rx, &net_data);

	if (net_data.relay_advice == RELAY_ALWAYS ||
			net_data.relay_advice == RELAY_ALLOWED) {
		uint8_t ttl = net_data.out[1] & TTL_MASK;

		net_data.out[1] &=  ~TTL_MASK;
		net_data.out[1] |= ttl - 1;
		net_key_encrypt(net_data.key_id, net_data.iv_index,
					net_data.out, net_data.out_size);
		send_relay_pkt(net_data.net, net_data.out, net_data.out_size);
	}
}

static void set_network_beacon(void *a, void *b)
{
	struct mesh_subnet *subnet = a;
	struct mesh_net *net = b;
	uint8_t beacon_data[22];

	if (!create_secure_beacon(net, subnet, beacon_data))
		return;

	if (memcmp(&subnet->snb.beacon[1], beacon_data,
						sizeof(beacon_data)) == 0)
		return;

	memcpy(&subnet->snb.beacon[1], beacon_data, sizeof(beacon_data));

	if (net->beacon_enable && !net->friend_addr) {
		print_packet("Set My Beacon to",
			beacon_data, sizeof(beacon_data));
		start_network_beacon(subnet, net);
	}

	if (l_queue_length(net->friends)) {
		struct mesh_friend_msg update = {
			.src = net->src_addr,
			.iv_index = mesh_net_get_iv_index(net),
			.last_len = 7,
			.ctl = true,
		};

		update.u.one[0].hdr = NET_OP_FRND_UPDATE << OPCODE_HDR_SHIFT;
		update.u.one[0].seq = mesh_net_next_seq_num(net);
		update.u.one[0].data[0] = NET_OP_FRND_UPDATE;
		update.u.one[0].data[1] = beacon_data[3];
		l_put_be32(net->iv_index, update.u.one[0].data + 2);
		update.u.one[0].data[6] = 0x01; /* More Data */
		/* print_packet("Frnd-Beacon-SRC",
		 *			beacon_data, sizeof(beacon_data));
		 */
		/* print_packet("Frnd-Update", update.u.one[0].data, 6); */

		l_queue_foreach(net->friends, enqueue_update, &update);
	}
}

static void iv_upd_to(struct l_timeout *upd_timeout, void *user_data)
{
	struct mesh_net *net = user_data;

	switch (net->iv_upd_state) {
	case IV_UPD_UPDATING:
		if (l_queue_length(net->sar_out)) {
			l_info("don't leave IV Update until sar_out empty");
			l_timeout_modify(net->iv_update_timeout, 10);
			break;
		}

		l_debug("iv_upd_state = IV_UPD_NORMAL_HOLD");
		net->iv_upd_state = IV_UPD_NORMAL_HOLD;
		l_timeout_modify(net->iv_update_timeout, IV_IDX_UPD_MIN);
		if (net->iv_update)
			mesh_net_set_seq_num(net, 0);

		net->iv_update = false;
		mesh_config_write_iv_index(node_config_get(net->node),
							net->iv_index, false);
		l_queue_foreach(net->subnets, set_network_beacon, net);
		mesh_net_flush_msg_queues(net);
		break;

	case IV_UPD_INIT:
	case IV_UPD_NORMAL_HOLD:
	case IV_UPD_NORMAL:
		l_timeout_remove(upd_timeout);
		net->iv_update_timeout = NULL;
		l_debug("iv_upd_state = IV_UPD_NORMAL");
		net->iv_upd_state = IV_UPD_NORMAL;
		if (net->iv_update)
			mesh_net_set_seq_num(net, 0);

		net->iv_update = false;
		if (net->seq_num > IV_UPDATE_SEQ_TRIGGER)
			mesh_net_iv_index_update(net);
		break;
	}
}


static int key_refresh_phase_two(struct mesh_net *net, uint16_t idx)
{
	struct mesh_subnet *subnet;

	if (!net)
		return MESH_STATUS_UNSPECIFIED_ERROR;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));

	if (!subnet || !subnet->net_key_upd)
		return MESH_STATUS_INVALID_NETKEY;

	l_info("Key refresh procedure phase 2: start using new net TX keys");
	subnet->key_refresh = 1;
	subnet->net_key_tx = subnet->net_key_upd;
	/* TODO: Provisioner may need to stay in phase three until
	 * it hears beacons from all the nodes
	 */
	subnet->kr_phase = KEY_REFRESH_PHASE_TWO;
	set_network_beacon(subnet, net);

	if (net->friend_addr)
		frnd_key_refresh(net, 2);
	else
		l_queue_foreach(net->friends, frnd_kr_phase2, net);

	mesh_config_net_key_set_phase(node_config_get(net->node), idx,
						KEY_REFRESH_PHASE_TWO);

	return MESH_STATUS_SUCCESS;
}

static int key_refresh_finish(struct mesh_net *net, uint16_t idx)
{
	struct mesh_subnet *subnet;

	if (!net)
		return MESH_STATUS_UNSPECIFIED_ERROR;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));
	if (!subnet || !subnet->net_key_upd)
		return MESH_STATUS_INVALID_NETKEY;

	if (subnet->kr_phase == KEY_REFRESH_PHASE_NONE)
		return MESH_STATUS_SUCCESS;

	l_info("Key refresh phase 3: use new keys only, discard old ones");

	/* Switch to using new keys, discard old ones */
	net_key_unref(subnet->net_key_cur);
	subnet->net_key_tx = subnet->net_key_cur = subnet->net_key_upd;
	subnet->net_key_upd = 0;
	subnet->key_refresh = 0;
	subnet->kr_phase = KEY_REFRESH_PHASE_NONE;
	set_network_beacon(subnet, net);

	if (net->friend_addr)
		frnd_key_refresh(net, 3);
	else
		l_queue_foreach(net->friends, frnd_kr_phase3, net);

	mesh_config_net_key_set_phase(node_config_get(net->node), idx,
							KEY_REFRESH_PHASE_NONE);

	return MESH_STATUS_SUCCESS;
}

static void update_kr_state(struct mesh_subnet *subnet, bool kr, uint32_t id)
{
	/* Figure out the key refresh phase */
	if (kr) {
		if (id == subnet->net_key_upd) {
			l_debug("Beacon based KR phase 2 change");
			key_refresh_phase_two(subnet->net, subnet->idx);
		}
	} else {
		if (id == subnet->net_key_upd) {
			l_debug("Beacon based KR phase 3 change");
			key_refresh_finish(subnet->net, subnet->idx);
		}
	}
}

static void update_iv_ivu_state(struct mesh_net *net, uint32_t iv_index,
								bool ivu)
{
	uint32_t local_iv_index;
	bool local_ivu;

	/* Save original settings to differentiate what has changed */
	local_iv_index = net->iv_index;
	local_ivu = net->iv_update;

	if ((iv_index - ivu) > (local_iv_index - local_ivu)) {
		/* Don't accept IV_Index changes when performing SAR Out */
		if (l_queue_length(net->sar_out))
			return;
	}

	/* If first beacon seen, accept without judgement */
	if (net->iv_upd_state == IV_UPD_INIT) {
		if (ivu) {
			/* Other devices will be accepting old or new iv_index,
			 * but we don't know how far through update they are.
			 * Starting permissive state will allow us maximum
			 * (96 hours) to resync
			 */
			l_info("iv_upd_state = IV_UPD_UPDATING");
			net->iv_upd_state = IV_UPD_UPDATING;
			net->iv_update_timeout = l_timeout_create(
				IV_IDX_UPD_MIN, iv_upd_to, net, NULL);
		} else {
			l_info("iv_upd_state = IV_UPD_NORMAL");
			net->iv_upd_state = IV_UPD_NORMAL;
		}
	} else if (ivu) {
		/* Ignore beacons with IVU if they come too soon */
		if (!local_ivu && net->iv_upd_state == IV_UPD_NORMAL_HOLD) {
			l_error("Update attempted too soon");
			return;
		}

		if (!local_ivu) {
			l_info("iv_upd_state = IV_UPD_UPDATING");
			net->iv_upd_state = IV_UPD_UPDATING;
			net->iv_update_timeout = l_timeout_create(
					IV_IDX_UPD_MIN, iv_upd_to, net, NULL);
		}
	} else if (local_ivu) {
		l_error("IVU clear attempted too soon");
		return;
	}

	if ((iv_index - ivu) > (local_iv_index - local_ivu))
		mesh_net_set_seq_num(net, 0);

	if (ivu != net->iv_update || local_iv_index != net->iv_index) {
		struct mesh_config *cfg = node_config_get(net->node);

		mesh_config_write_iv_index(cfg, iv_index, ivu);
	}

	net->iv_index = iv_index;
	net->iv_update = ivu;
}

static void process_beacon(void *net_ptr, void *user_data)
{
	struct mesh_net *net = net_ptr;
	const uint8_t *buf = *(uint8_t **)user_data;
	uint32_t ivi;
	bool ivu, kr, local_kr;
	struct mesh_subnet *subnet;
	uint32_t key_id;

	ivi = l_get_be32(buf + 10);

	/* Ignore out-of-range IV_Index for this network */
	if ((net->iv_index + IV_IDX_DIFF_RANGE < ivi) || (ivi < net->iv_index))
		return;

	/* Ignore Network IDs unknown to this mesh universe */
	key_id = net_key_network_id(buf + 2);
	if (!key_id)
		return;

	subnet = l_queue_find(net->subnets, match_key_id,
							L_UINT_TO_PTR(key_id));
	if (!subnet)
		return;

	/* Get IVU and KR boolean bits from beacon */
	ivu = !!(buf[1] & 0x02);
	kr = !!(buf[1] & 0x01);
	local_kr = !!(subnet->kr_phase != KEY_REFRESH_PHASE_TWO);

	if (net->iv_upd_state != IV_UPD_INIT) {
		/* Ignore beacons that indicate *no change* */
		if (!memcmp(&subnet->snb.beacon[1], buf, 22)) {
			subnet->snb.observed++;
			return;
		}
	}

	/* Validate beacon before accepting */
	if (!net_key_snb_check(key_id, ivi, kr, ivu, l_get_be64(buf + 14))) {
		l_error("mesh_crypto_beacon verify failed");
		return;
	}

	/* We have officially *seen* this beacon now */
	subnet->snb.observed++;

	update_iv_ivu_state(net, ivi, ivu);
	update_kr_state(subnet, kr, key_id);

	if (ivi != net->iv_index || ivu != net->iv_update || kr != local_kr)
		set_network_beacon(subnet, net);
}

static void lpn_process_beacon(void *user_data, const void *data,
						uint8_t size, int8_t rssi)
{
	struct mesh_net *net = user_data;
	const uint8_t *buf = data;
	uint32_t ivi;
	bool ivu, kr, local_kr;
	struct mesh_subnet *subnet;
	bool kr_transition = false;

	/* print_packet("lpn: Secure Net Beacon RXed", data, size); */
	kr = !!(buf[0] & 0x01);
	ivu = !!(buf[0] & 0x02);
	ivi = l_get_be32(buf + 1);

	l_debug("KR: %d -- IVU: %d -- IVI: %8.8x", kr, ivu, ivi);

	/* TODO: figure out actual network index (i.e., friendship subnet) */
	subnet = get_primary_subnet(net);
	if (!subnet)
		return;

	local_kr = (subnet->kr_phase == KEY_REFRESH_PHASE_TWO);

	/* Don't bother going further if nothing has changed */
	if (local_kr == kr && ivi == net->iv_index && ivu == net->iv_update &&
					net->iv_upd_state != IV_UPD_INIT)
		return;

	update_iv_ivu_state(net, ivi, ivu);

	if (kr)
		update_kr_state(subnet, kr_transition, subnet->net_key_upd);
	else
		update_kr_state(subnet, kr_transition, subnet->net_key_cur);
}

static void beacon_recv(void *user_data, struct mesh_io_recv_info *info,
					const uint8_t *data, uint16_t len)
{
	const uint8_t *ptr = data + 1;

	if (len != 23 || data[1] != 0x01)
		return;

	l_debug("KR: %d -- IVU: %d -- IV: %8.8x",
			data[2] & 1, !!(data[2] & 2), l_get_be32(data + 11));

	l_queue_foreach(nets, process_beacon, &ptr);
}

bool mesh_net_set_beacon_mode(struct mesh_net *net, bool enable)
{
	if (!net || !IS_UNASSIGNED(net->friend_addr))
		return false;

	if (net->beacon_enable != enable) {
		uint8_t type = MESH_AD_TYPE_BEACON;

		net->beacon_enable = enable;

		if (!enable)
			mesh_io_send_cancel(net->io, &type, 1);

		l_queue_foreach(net->subnets, start_network_beacon, net);
	}

	return true;
}

/* This function is called when network keys are restored from storage. */
bool mesh_net_set_key(struct mesh_net *net, uint16_t idx, const uint8_t *key,
					const uint8_t *new_key, uint8_t phase)
{
	struct mesh_subnet *subnet;

	/* Current key must be always present */
	if (!key)
		return false;

	/* If key refresh is in progress, a new key must be present */
	if (phase != KEY_REFRESH_PHASE_NONE && !new_key)
		return false;

	/* Check if the subnet with the specified index already exists */
	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));
	if (subnet)
		return false;

	subnet = add_key(net, idx, key);
	if (!subnet)
		return false;

	if (new_key && phase)
		subnet->net_key_upd = net_key_add(new_key);

	/* Preserve key refresh state to generate secure beacon flags*/
	if (phase == KEY_REFRESH_PHASE_TWO) {
		subnet->key_refresh = 1;
		subnet->net_key_tx = subnet->net_key_upd;
	}

	subnet->kr_phase = phase;

	set_network_beacon(subnet, net);

	if (net->io)
		start_network_beacon(subnet, net);

	return true;
}

static bool is_this_net(const void *a, const void *b)
{
	return a == b;
}

bool mesh_net_attach(struct mesh_net *net, struct mesh_io *io)
{
	bool first;

	if (!net)
		return false;

	first = l_queue_isempty(nets);
	if (first) {
		if (!nets)
			nets = l_queue_new();

		if (!fast_cache)
			fast_cache = l_queue_new();

		l_info("Register io cb");
		mesh_io_register_recv_cb(io, MESH_IO_FILTER_BEACON,
							beacon_recv, NULL);
		mesh_io_register_recv_cb(io, MESH_IO_FILTER_NET,
							net_msg_recv, NULL);
		l_queue_foreach(net->subnets, start_network_beacon, net);
	}

	if (l_queue_find(nets, is_this_net, net))
		return false;

	l_queue_push_head(nets, net);

	net->io = io;

	return true;
}

struct mesh_io *mesh_net_detach(struct mesh_net *net)
{
	struct mesh_io *io;
	uint8_t type = 0;

	if (!net || !net->io)
		return NULL;

	io = net->io;

	mesh_io_send_cancel(net->io, &type, 1);
	mesh_io_deregister_recv_cb(io, MESH_IO_FILTER_BEACON);
	mesh_io_deregister_recv_cb(io, MESH_IO_FILTER_NET);

	net->io = NULL;
	l_queue_remove(nets, net);

	return io;
}

bool mesh_net_iv_index_update(struct mesh_net *net)
{
	if (net->iv_upd_state != IV_UPD_NORMAL)
		return false;

	l_info("iv_upd_state = IV_UPD_UPDATING");
	mesh_net_flush_msg_queues(net);
	if (!mesh_config_write_iv_index(node_config_get(net->node),
						net->iv_index + 1, true))
		return false;

	net->iv_upd_state = IV_UPD_UPDATING;
	net->iv_index++;
	net->iv_update = true;
	l_queue_foreach(net->subnets, set_network_beacon, net);
	net->iv_update_timeout = l_timeout_create(
			IV_IDX_UPD_MIN,
			iv_upd_to, net, NULL);

	return true;
}



void mesh_net_sub_list_add(struct mesh_net *net, uint16_t addr)
{
	uint8_t msg[11] = { PROXY_OP_FILTER_ADD };
	uint8_t n = 1;

	l_put_be16(addr, msg + n);
	n += 2;

	mesh_net_transport_send(net, 0, false,
			mesh_net_get_iv_index(net), 0,
			0, 0, 0, msg, n);
}

void mesh_net_sub_list_del(struct mesh_net *net, uint16_t addr)
{
	uint8_t msg[11] = { PROXY_OP_FILTER_DEL };
	uint8_t n = 1;

	l_put_be16(addr, msg + n);
	n += 2;

	mesh_net_transport_send(net, 0, false,
			mesh_net_get_iv_index(net), 0,
			0, 0, 0, msg, n);
}

/* TODO: change to use net index */
bool mesh_net_set_friend(struct mesh_net *net, uint16_t friend_addr)
{
	if (!net)
		return false;

	net->bea_id = 0;

	l_info("Set Frnd addr: %4.4x", friend_addr);
	if (!friend_addr)
		trigger_heartbeat(net, FEATURE_LPN, false);
	else
		trigger_heartbeat(net, FEATURE_LPN, true);

	net->friend_addr = friend_addr;

	set_network_beacon(get_primary_subnet(net), net);
	return true;
}

uint16_t mesh_net_get_friend(struct mesh_net *net)
{
	if (!net)
		return 0;

	return net->friend_addr;
}

bool mesh_net_dst_reg(struct mesh_net *net, uint16_t dst)
{
	struct mesh_destination *dest = l_queue_find(net->destinations,
					match_by_dst, L_UINT_TO_PTR(dst));

	if (IS_UNASSIGNED(dst) || IS_ALL_NODES(dst))
		return false;

	if (!dest) {
		dest = l_new(struct mesh_destination, 1);

		if (dst < 0x8000)
			l_queue_push_head(net->destinations, dest);
		else
			l_queue_push_tail(net->destinations, dest);

		/* If LPN, and Group/Virtual, add to Subscription List */
		if (net->friend_addr) {
			/* TODO: Fix this garbage */
			uint32_t u32_dst[7] = {dst, 0xffffffff};

			frnd_sub_add(net, u32_dst);
		}
	}

	dest->dst = dst;
	dest->ref_cnt++;

	return true;
}

bool mesh_net_dst_unreg(struct mesh_net *net, uint16_t dst)
{
	struct mesh_destination *dest = l_queue_find(net->destinations,
					match_by_dst, L_UINT_TO_PTR(dst));

	if (!dest)
		return false;

	if (dest->ref_cnt)
		dest->ref_cnt--;

	if (dest->ref_cnt)
		return true;

	/* TODO: If LPN, and Group/Virtual, remove from Subscription List */
	if (net->friend_addr) {
		/* TODO: Fix this garbage */
		uint32_t u32_dst[7] = {dst, 0xffffffff};

		frnd_sub_del(net, u32_dst);
	}

	l_queue_remove(net->destinations, dest);

	l_free(dest);
	return true;
}

bool mesh_net_flush(struct mesh_net *net)
{
	if (!net)
		return false;

	/* TODO mesh-io Flush */
	return true;
}

/* TODO: add net key index */
static bool send_seg(struct mesh_net *net, struct mesh_sar *msg, uint8_t segO)
{
	uint8_t seg_len;
	uint8_t gatt_data[30];
	uint8_t *packet = gatt_data;
	uint8_t packet_len;
	uint8_t segN = SEG_MAX(msg->len);
	uint16_t seg_off = SEG_OFF(segO);
	uint32_t key_id = 0;
	uint32_t seq_num = mesh_net_next_seq_num(net);

	if (segN) {
		if (msg->len - seg_off > SEG_OFF(1))
			seg_len = SEG_OFF(1);
		else
			seg_len = msg->len - seg_off;
	} else {
		seg_len = msg->len;
	}

	/* Start IV Update procedure when we hit our trigger point */
	if (!msg->frnd && net->seq_num > IV_UPDATE_SEQ_TRIGGER)
		mesh_net_iv_index_update(net);

	l_debug("segN %d segment %d seg_off %d", segN, segO, seg_off);
	/* print_packet("Sending", msg->buf + seg_off, seg_len); */
	{
		/* TODO: Are we RXing on an LPN's behalf? Then set RLY bit */

		if (!mesh_crypto_packet_build(false, msg->ttl,
					seq_num,
					msg->src, msg->remote,
					0,
					segN ? true : false, msg->key_aid,
					msg->szmic, false, msg->seqZero,
					segO, segN,
					msg->buf + seg_off, seg_len,
					packet + 1, &packet_len)) {
			l_error("Failed to build packet");
			return false;
		}
	}
	print_packet("Clr-Net Tx", packet + 1, packet_len);

	if (msg->frnd_cred && net->friend_addr)
		key_id = frnd_get_key(net);

	if (!key_id) {
		struct mesh_subnet *subnet = get_primary_subnet(net);

		key_id = subnet->net_key_tx;
	}

	if (!net_key_encrypt(key_id, msg->iv_index, packet + 1, packet_len)) {
		l_error("Failed to encode packet");
		return false;
	}

	/* print_packet("Step 4", packet + 1, packet_len); */

	{
		char *str;

		send_msg_pkt(net, packet, packet_len + 1);

		str = l_util_hexstring(packet + 1, packet_len);
		l_info("TX: Network %04x -> %04x : %s (%u) : TTL %d : SEQ %06x",
				msg->src, msg->remote, str,
				packet_len, msg->ttl,
				msg->frnd ? msg->seqAuth + segO : seq_num);
		l_free(str);
	}

	msg->last_seg = segO;

	return true;
}

void mesh_net_send_seg(struct mesh_net *net, uint32_t net_key_id,
				uint32_t iv_index,
				uint8_t ttl,
				uint32_t seq,
				uint16_t src, uint16_t dst,
				uint32_t hdr,
				const void *seg, uint16_t seg_len)
{
	char *str;
	uint8_t packet[30];
	uint8_t packet_len;
	bool segmented = !!((hdr >> SEG_HDR_SHIFT) & true);
	uint8_t app_key_id = (hdr >> KEY_HDR_SHIFT) & KEY_ID_MASK;
	bool szmic = !!((hdr >> SZMIC_HDR_SHIFT) & true);
	uint16_t seqZero = (hdr >> SEQ_ZERO_HDR_SHIFT) & SEQ_ZERO_MASK;
	uint8_t segO = (hdr >> SEGO_HDR_SHIFT) & SEG_MASK;
	uint8_t segN = (hdr >> SEGN_HDR_SHIFT) & SEG_MASK;

	/* TODO: Only used for current POLLed segments to LPNs */

	l_debug("SEQ: %6.6x", seq + segO);
	l_debug("SEQ0: %6.6x", seq);
	l_debug("segO: %d", segO);

	if (!mesh_crypto_packet_build(false, ttl,
				seq,
				src, dst,
				0,
				segmented, app_key_id,
				szmic, false, seqZero,
				segO, segN,
				seg, seg_len,
				packet + 1, &packet_len)) {
		l_error("Failed to build packet");
		return;
	}

	if (!net_key_encrypt(net_key_id, iv_index, packet + 1, packet_len)) {
		l_error("Failed to encode packet");
		return;
	}

	/* print_packet("Step 4", packet + 1, packet_len); */

	send_msg_pkt(net, packet, packet_len + 1);

	str = l_util_hexstring(packet + 1, packet_len);
	l_info("TX: Friend Seg-%d %04x -> %04x : %s (%u) : TTL %d : SEQ %06x",
			segO, src, dst, str, packet_len, ttl, seq);
	l_free(str);
}

bool mesh_net_app_send(struct mesh_net *net, bool frnd_cred, uint16_t src,
				uint16_t dst, uint8_t key_aid, uint16_t net_idx,
				uint8_t ttl, uint32_t seq, uint32_t iv_index,
				bool szmic, const void *msg, uint16_t msg_len,
				mesh_net_status_func_t status_func,
				void *user_data)
{
	struct mesh_sar *payload = NULL;
	uint8_t seg, seg_max;
	bool result;

	if (!net || msg_len > 384)
		return false;

	if (!src)
		src = net->src_addr;

	if (!src || !dst)
		return false;

	if (ttl == DEFAULT_TTL)
		ttl = net->default_ttl;

	seg_max = SEG_MAX(msg_len);

	/* First enqueue to any Friends and internal models */
	result = msg_rxed(net, false, iv_index, ttl,
				seq + seg_max,
				net_idx,
				src, dst,
				key_aid,
				szmic, seq & SEQ_ZERO_MASK,
				msg, msg_len);

	/* If successfully enqued or delivered
	 * to Unicast address, we are done
	 */
	if (result || src == dst ||
			(dst >= net->src_addr && dst <= net->last_addr)) {
		/* Adjust our seq_num for "virtual" delivery */
		net->seq_num += seg_max;
		mesh_net_next_seq_num(net);
		return true;
	}

	/* If Segmented, Cancel any OB segmented message to same DST */
	if (seg_max) {
		payload = l_queue_remove_if(net->sar_out, match_sar_remote,
							L_UINT_TO_PTR(dst));
		mesh_sar_free(payload);
	}

	/* Setup OTA Network send */
	payload = mesh_sar_new(msg_len);
	memcpy(payload->buf, msg, msg_len);
	payload->len = msg_len;
	payload->src = src;
	payload->remote = dst;
	payload->ttl = ttl;
	payload->szmic = szmic;
	payload->frnd_cred = frnd_cred;
	payload->key_aid = key_aid;
	if (seg_max) {
		payload->flags = 0xffffffff >> (31 - seg_max);
		payload->seqZero = seq & SEQ_ZERO_MASK;
	}

	payload->iv_index = mesh_net_get_iv_index(net);
	payload->seqAuth = net->seq_num;

	result = true;
	if (!IS_UNICAST(dst) && seg_max) {
		int i;

		for (i = 0; i < 4; i++) {
			for (seg = 0; seg <= seg_max && result; seg++)
				result = send_seg(net, payload, seg);
		}
	} else {
		for (seg = 0; seg <= seg_max && result; seg++)
			result = send_seg(net, payload, seg);
	}

	/* Reliable: Cache; Unreliable: Flush*/
	if (result && seg_max && IS_UNICAST(dst)) {
		l_queue_push_head(net->sar_out, payload);
		payload->seg_timeout =
			l_timeout_create(SEG_TO, outseg_to, net, NULL);
		payload->msg_timeout =
			l_timeout_create(MSG_TO, outmsg_to, net, NULL);
		payload->status_func = status_func;
		payload->user_data = user_data;
		payload->id = ++net->sar_id_next;
	} else
		mesh_sar_free(payload);

	return result;
}

void mesh_net_ack_send(struct mesh_net *net, uint32_t key_id,
				uint32_t iv_index,
				uint8_t ttl,
				uint32_t seq,
				uint16_t src, uint16_t dst,
				bool rly, uint16_t seqZero,
				uint32_t ack_flags)
{
	uint32_t hdr;
	uint8_t data[7];
	uint8_t pkt_len;
	uint8_t pkt[30];
	char *str;

	hdr = NET_OP_SEG_ACKNOWLEDGE << OPCODE_HDR_SHIFT;
	hdr |= rly << RELAY_HDR_SHIFT;
	hdr |= (seqZero & SEQ_ZERO_MASK) << SEQ_ZERO_HDR_SHIFT;
	l_put_be32(hdr, data);
	l_put_be32(ack_flags, data + 3);
	if (!mesh_crypto_packet_build(true, ttl,
					seq,
					src, dst,
					NET_OP_SEG_ACKNOWLEDGE,
					false, /* Not Segmented */
					0,	/* No Key ID associated */
					false, rly, seqZero,
					0, 0,	/* no segO or segN */
					data + 1, 6,
					pkt + 1, &pkt_len)) {
		return;
	}

	if (!key_id) {
		struct mesh_subnet *subnet = get_primary_subnet(net);

		key_id = subnet->net_key_tx;
	}

	if (!net_key_encrypt(key_id, iv_index, pkt + 1, pkt_len)) {
		l_error("Failed to encode packet");
		return;
	}

	/* print_packet("Step 4", pkt, pkt_len); */
	send_msg_pkt(net, pkt, pkt_len + 1);

	str = l_util_hexstring(pkt + 1, pkt_len);
	l_info("TX: Friend ACK %04x -> %04x : %s (%u) : TTL %d : SEQ %06x",
			src, dst, str, pkt_len,
			ttl, seq);
	l_free(str);
}

/* TODO: add net key index */
void mesh_net_transport_send(struct mesh_net *net, uint32_t key_id,
				bool fast, uint32_t iv_index, uint8_t ttl,
				uint32_t seq, uint16_t src, uint16_t dst,
				const uint8_t *msg, uint16_t msg_len)
{
	uint32_t use_seq = seq;
	uint8_t pkt_len;
	uint8_t pkt[30];
	bool result = false;

	if (!net->src_addr)
		return;

	if (!src)
		src = net->src_addr;

	if (src == dst)
		return;

	if (ttl == DEFAULT_TTL)
		ttl = net->default_ttl;

	/* Range check the Opcode and msg length*/
	if (*msg & 0xc0 || (9 + msg_len + 8 > 29))
		return;

	/* Enqueue for Friend if forwardable and from us */
	if (!key_id && src >= net->src_addr && src <= net->last_addr) {
		uint32_t hdr = msg[0] << OPCODE_HDR_SHIFT;
		uint8_t frnd_ttl = ttl;

		if (friend_packet_queue(net, iv_index,
					true, frnd_ttl,
					mesh_net_next_seq_num(net),
					src, dst,
					hdr,
					msg + 1, msg_len - 1)) {
			return;
		}
	}

	/* Deliver to Local entities if applicable */
	if (!(dst & 0x8000) && src >= net->src_addr && src <= net->last_addr) {
		result = ctl_received(net, !!(key_id),
					iv_index, ttl,
					mesh_net_next_seq_num(net),
					src, dst,
					msg[0], 0, msg + 1, msg_len - 1);
	}

	if (!key_id) {
		struct mesh_subnet *subnet = get_primary_subnet(net);

		key_id = subnet->net_key_tx;
		use_seq = mesh_net_next_seq_num(net);

		if (result || (dst >= net->src_addr && dst <= net->last_addr))
			return;
	}

	if (!mesh_crypto_packet_build(true, ttl,
				use_seq,
				src, dst,
				msg[0],
				false, 0,
				false, false, 0,
				0, 0,
				msg + 1, msg_len - 1,
				pkt + 1, &pkt_len))
		return;

	/* print_packet("Step 2", pkt + 1, pkt_len); */

	if (!net_key_encrypt(key_id, iv_index, pkt + 1, pkt_len)) {
		l_error("Failed to encode packet");
		return;
	}

	/* print_packet("Step 4", pkt + 1, pkt_len); */

	if (dst != 0) {
		char *str;

		send_msg_pkt(net, pkt, pkt_len + 1);

		str = l_util_hexstring(pkt + 1, pkt_len);
		l_info("TX: Network %04x -> %04x : %s (%u) : TTL %d : SEQ %06x",
				src, dst, str, pkt_len,
				ttl, use_seq);
		l_free(str);
	}
}

uint8_t mesh_net_key_refresh_phase_set(struct mesh_net *net, uint16_t idx,
							uint8_t transition)
{
	struct mesh_subnet *subnet;

	if (!net)
		return MESH_STATUS_UNSPECIFIED_ERROR;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));
	if (!subnet)
		return MESH_STATUS_INVALID_NETKEY;

	if (transition == subnet->kr_phase)
		return MESH_STATUS_SUCCESS;

	if ((transition != 2 && transition != 3) ||
						transition < subnet->kr_phase)
		return MESH_STATUS_CANNOT_SET;

	switch (transition) {
	case 2:
		if (key_refresh_phase_two(net, idx)
							!= MESH_STATUS_SUCCESS)
			return MESH_STATUS_CANNOT_SET;
		break;
	case 3:
		if (key_refresh_finish(net, idx)
							!= MESH_STATUS_SUCCESS)
			return MESH_STATUS_CANNOT_SET;
		break;
	default:
		return MESH_STATUS_CANNOT_SET;
	}

	return MESH_STATUS_SUCCESS;
}

uint8_t mesh_net_key_refresh_phase_get(struct mesh_net *net, uint16_t idx,
								uint8_t *phase)
{
	struct mesh_subnet *subnet;

	if (!net)
		return MESH_STATUS_UNSPECIFIED_ERROR;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));
	if (!subnet)
		return MESH_STATUS_INVALID_NETKEY;

	*phase = subnet->kr_phase;
	return MESH_STATUS_SUCCESS;
}

/*
 * This function is called when Configuration Server Model receives
 * a NETKEY_UPDATE command
 */
int mesh_net_update_key(struct mesh_net *net, uint16_t idx,
							const uint8_t *value)
{
	struct mesh_subnet *subnet;

	if (!net)
		return MESH_STATUS_UNSPECIFIED_ERROR;

	subnet = l_queue_find(net->subnets, match_key_index,
							L_UINT_TO_PTR(idx));

	if (!subnet)
		return MESH_STATUS_INVALID_NETKEY;

	/* Check if the key has been already successfully updated */
	if (subnet->kr_phase == KEY_REFRESH_PHASE_ONE &&
				net_key_confirm(subnet->net_key_upd, value))
		return MESH_STATUS_SUCCESS;

	if (subnet->kr_phase != KEY_REFRESH_PHASE_NONE)
		return MESH_STATUS_CANNOT_UPDATE;

	if (subnet->net_key_upd) {
		net_key_unref(subnet->net_key_upd);
		l_info("Warning: overwriting new keys");
	}

	/* Preserve starting data */
	subnet->net_key_upd = net_key_add(value);

	if (!subnet->net_key_upd) {
		l_error("Failed to start key refresh phase one");
		return MESH_STATUS_CANNOT_UPDATE;
	}

	/* If we are an LPN, generate our keys here */
	if (net->friend_addr)
		frnd_key_refresh(net, 1);
	else
		/* If we are a Friend-Node, generate all our new keys */
		l_queue_foreach(net->friends, frnd_kr_phase1,
					L_UINT_TO_PTR(subnet->net_key_upd));

	l_info("key refresh phase 1: Key ID %d", subnet->net_key_upd);

	if (!mesh_config_net_key_update(node_config_get(net->node), idx, value))
		return MESH_STATUS_STORAGE_FAIL;

	subnet->kr_phase = KEY_REFRESH_PHASE_ONE;

	return MESH_STATUS_SUCCESS;
}

uint16_t mesh_net_get_features(struct mesh_net *net)
{
	uint16_t features = 0;

	if (net->relay.enable)
		features |= FEATURE_RELAY;
	if (net->proxy_enable)
		features |= FEATURE_PROXY;
	if (!l_queue_isempty(net->friends))
		features |= FEATURE_FRIEND;
	if (net->friend_addr != UNASSIGNED_ADDRESS)
		features |= FEATURE_LPN;

	return features;
}

struct mesh_net_heartbeat *mesh_net_heartbeat_get(struct mesh_net *net)
{
	return &net->heartbeat;
}

void mesh_net_heartbeat_send(struct mesh_net *net)
{
	struct mesh_net_heartbeat *hb = &net->heartbeat;
	uint8_t msg[4];
	int n = 0;

	if (hb->pub_dst == UNASSIGNED_ADDRESS)
		return;

	msg[n++] = NET_OP_HEARTBEAT;
	msg[n++] = hb->pub_ttl;
	l_put_be16(hb->features, msg + n);
	n += 2;

	mesh_net_transport_send(net, 0, false, mesh_net_get_iv_index(net),
				hb->pub_ttl, 0, 0, hb->pub_dst, msg, n);
}

void mesh_net_heartbeat_init(struct mesh_net *net)
{
	struct mesh_net_heartbeat *hb = &net->heartbeat;

	memset(hb, 0, sizeof(struct mesh_net_heartbeat));
	hb->sub_min_hops = 0xff;
	hb->features = mesh_net_get_features(net);
}

void mesh_net_uni_range_set(struct mesh_net *net,
				struct mesh_net_addr_range *range)
{
	net->prov_uni_addr.low = range->low;
	net->prov_uni_addr.high = range->high;
	net->prov_uni_addr.next = range->next;
}

struct mesh_net_addr_range mesh_net_uni_range_get(struct mesh_net *net)
{
	return net->prov_uni_addr;
}

void mesh_net_set_iv_index(struct mesh_net *net, uint32_t index, bool update)
{
	net->iv_index = index;
	net->iv_update = update;
}

void mesh_net_provisioner_mode_set(struct mesh_net *net, bool mode)
{
	net->provisioner = mode;
}

bool mesh_net_provisioner_mode_get(struct mesh_net *net)
{
	return net->provisioner;
}

uint16_t mesh_net_get_primary_idx(struct mesh_net *net)
{
	struct mesh_subnet *subnet;

	if (!net)
		return NET_IDX_INVALID;

	subnet = get_primary_subnet(net);
	if (!subnet)
		return NET_IDX_INVALID;

	return subnet->idx;
}

uint32_t mesh_net_friend_timeout(struct mesh_net *net, uint16_t addr)
{
	struct mesh_friend *frnd = l_queue_find(net->friends, match_by_friend,
						L_UINT_TO_PTR(addr));

	if (!frnd)
		return 0;
	else
		return frnd->poll_timeout;
}

struct mesh_node *mesh_net_node_get(struct mesh_net *net)
{
	return  net->node;
}

struct l_queue *mesh_net_get_app_keys(struct mesh_net *net)
{
	if (!net)
		return NULL;

	if (!net->app_keys)
		net->app_keys = l_queue_new();

	return net->app_keys;
}

bool mesh_net_have_key(struct mesh_net *net, uint16_t idx)
{
	if (!net)
		return false;

	return (l_queue_find(net->subnets, match_key_index,
						L_UINT_TO_PTR(idx)) != NULL);
}

bool mesh_net_is_local_address(struct mesh_net *net, uint16_t src,
								uint16_t count)
{
	const uint16_t last = src + count - 1;
	if (!net)
		return false;

	return (src >= net->src_addr && src <= net->last_addr) &&
			(last >= net->src_addr && last <= net->last_addr);
}

void mesh_net_set_window_accuracy(struct mesh_net *net, uint8_t accuracy)
{
	if (!net)
		return;

	net->window_accuracy = accuracy;
}

void mesh_net_transmit_params_set(struct mesh_net *net, uint8_t count,
							uint16_t interval)
{
	if (!net)
		return;

	net->tx_interval = interval;
	net->tx_cnt = count;
}

void mesh_net_transmit_params_get(struct mesh_net *net, uint8_t *count,
							uint16_t *interval)
{
	if (!net)
		return;

	*interval = net->tx_interval;
	*count = net->tx_cnt;
}

struct mesh_io *mesh_net_get_io(struct mesh_net *net)
{
	if (!net)
		return NULL;

	return net->io;
}

struct mesh_prov *mesh_net_get_prov(struct mesh_net *net)
{
	if (!net)
		return NULL;

	return net->prov;
}

void mesh_net_set_prov(struct mesh_net *net, struct mesh_prov *prov)
{
	if (!net)
		return;

	net->prov = prov;
}

uint32_t mesh_net_get_instant(struct mesh_net *net)
{
	return net->instant;
}
