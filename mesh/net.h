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

#ifndef __packed
#define __packed __attribute__((packed))
#endif

struct mesh_io;
struct mesh_node;

#define DEV_ID	0

#define UNUSED_KEY_IDX	0xffff

#define APP_AID_DEV	0x00

#define CTL		0x80
#define SEQ_MASK	0xffffff

#define CREDFLAG_MASK	0x1000

#define KEY_CACHE_SIZE	64
#define FRND_CACHE_MAX	32

#define MAX_UNSEG_LEN	15 /* msg_len == 11 + sizeof(MIC) */
#define MAX_SEG_LEN	12 /* UnSeg length - 3 octets overhead */
#define SEG_MAX(len)	(((len) <= MAX_UNSEG_LEN) ? 0 : \
						(((len) - 1) / MAX_SEG_LEN))
#define SEG_OFF(seg)	((seg) * MAX_SEG_LEN)
#define MAX_SEG_TO_LEN(seg)	((seg) ? SEG_OFF((seg) + 1) : MAX_UNSEG_LEN)

#define SEGMENTED	0x80
#define UNSEGMENTED	0x00
#define SEG_HDR_SHIFT	31
#define IS_SEGMENTED(hdr)	(!!((hdr) & (true << SEG_HDR_SHIFT)))

#define KEY_ID_MASK	0x7f
#define KEY_AID_MASK	0x3f
#define KEY_ID_AKF	0x40
#define KEY_AID_SHIFT	0
#define AKF_HDR_SHIFT	30
#define KEY_HDR_SHIFT	24
#define HAS_APP_KEY(hdr)	(!!((hdr) & (true << AKF_HDR_SHIFT)))

#define OPCODE_MASK	0x7f
#define OPCODE_HDR_SHIFT	24
#define RELAY		0x80
#define RELAY_HDR_SHIFT	23
#define SZMIC		0x80
#define SZMIC_HDR_SHIFT	23
#define SEQ_ZERO_MASK	0x1fff
#define SEQ_ZERO_HDR_SHIFT	10
#define IS_RELAYED(hdr)	(!!((hdr) & (true << RELAY_HDR_SHIFT)))
#define HAS_MIC64(hdr)	(!!((hdr) & (true << SZMIC_HDR_SHIFT)))

#define SEG_MASK	0x1f
#define SEGO_HDR_SHIFT	5
#define SEGN_HDR_SHIFT	0
#define SEG_TOTAL(hdr)	(((hdr) >> SEGN_HDR_SHIFT) & SEG_MASK)

/* Mask of Hdr bits which must be constant over entire incoming SAR message */
/* (SEG || AKF || AID || SZMIC || SeqZero || SegN) */
#define HDR_KEY_MASK		((true << SEG_HDR_SHIFT) |		\
				(KEY_ID_MASK << KEY_HDR_SHIFT) |	\
				(true << SZMIC_HDR_SHIFT) |		\
				(SEQ_ZERO_MASK << SEQ_ZERO_HDR_SHIFT) |	\
				(SEG_MASK << SEGN_HDR_SHIFT))

#define HDR_ACK_MASK		((OPCODE_MASK << OPCODE_HDR_SHIFT) |	\
				(SEQ_ZERO_MASK << SEQ_ZERO_HDR_SHIFT))



#define MSG_CACHE_SIZE		70
#define REPLAY_CACHE_SIZE	10

/* Proxy Configuration Opcodes */
#define PROXY_OP_SET_FILTER_TYPE	0x00
#define PROXY_OP_FILTER_ADD		0x01
#define PROXY_OP_FILTER_DEL		0x02
#define PROXY_OP_FILTER_STATUS		0x03

/* Proxy Filter Defines */
#define PROXY_FILTER_WHITELIST		0x00
#define PROXY_FILTER_BLACKLIST		0x01

/* Network Tranport Opcodes */
#define NET_OP_SEG_ACKNOWLEDGE		0x00
#define NET_OP_FRND_POLL		0x01
#define NET_OP_FRND_UPDATE		0x02
#define NET_OP_FRND_REQUEST		0x03
#define NET_OP_FRND_OFFER		0x04
#define NET_OP_FRND_CLEAR		0x05
#define NET_OP_FRND_CLEAR_CONFIRM	0x06

#define NET_OP_PROXY_SUB_ADD		0x07
#define NET_OP_PROXY_SUB_REMOVE		0x08
#define NET_OP_PROXY_SUB_CONFIRM	0x09
#define NET_OP_HEARTBEAT		0x0a

#define FRND_OPCODE(x) \
		((x) >= NET_OP_FRND_POLL && (x) <= NET_OP_FRND_CLEAR_CONFIRM)

#define DEFAULT_MIN_DELAY		0
#define DEFAULT_MAX_DELAY		25

struct mesh_net_addr_range {
	uint16_t low;
	uint16_t high;
	uint16_t next;
};

struct mesh_net_prov_caps {
	uint8_t num_ele;
	uint16_t algorithms;
	uint8_t pub_type;
	uint8_t static_type;
	uint8_t output_size;
	uint16_t output_action;
	uint8_t input_size;
	uint16_t input_action;
} __packed;

struct mesh_net_heartbeat {
	struct l_timeout *pub_timer;
	struct l_timeout *sub_timer;
	struct timeval sub_time;
	bool sub_enabled;
	uint32_t pub_period;
	uint32_t sub_period;
	uint32_t sub_start;
	uint16_t pub_dst;
	uint16_t pub_count;
	uint16_t pub_features;
	uint16_t features;
	uint16_t pub_net_idx;
	uint16_t sub_src;
	uint16_t sub_dst;
	uint16_t sub_count;
	uint8_t pub_ttl;
	uint8_t sub_min_hops;
	uint8_t sub_max_hops;
};

struct mesh_key_set {
	bool frnd;
	uint8_t nid;
	uint8_t enc_key[16];
	uint8_t privacy_key[16];
};

struct friend_neg {
	int8_t rssi;
	bool clearing;
};

struct friend_act {
	uint16_t *grp_list;
	uint32_t last_hdr;
	int16_t grp_cnt;
	bool seq;
	bool last;
};

struct mesh_friend {
	struct mesh_net *net;
	struct l_timeout *timeout;
	struct l_queue *pkt_cache;
	void *pkt;
	uint32_t poll_timeout;
	uint32_t net_key_cur;
	uint32_t net_key_upd;
	uint16_t old_friend;
	uint16_t net_idx;
	uint16_t lp_addr;/* dst; * Primary Element unicast addr */
	uint16_t fn_cnt;
	uint16_t lp_cnt;
	uint8_t	receive_delay;
	uint8_t ele_cnt;
	uint8_t frd;
	uint8_t frw;
	union {
		struct friend_neg negotiate;
		struct friend_act active;
	} u;
};

struct mesh_frnd_pkt {
	uint32_t iv_index;
	uint32_t seq;
	uint16_t src;
	uint16_t dst;
	uint16_t size;
	uint8_t segN;
	uint8_t segO;
	uint8_t ttl;
	uint8_t tc;
	bool szmict;
	union {
		struct {
			uint8_t key_id;
		} m;
		struct {
			uint16_t seq0;
		} a;
		struct {
			uint8_t opcode;
		} c;
	} u;
	uint8_t data[];
};

struct mesh_friend_seg_one {
	uint32_t hdr;
	uint32_t seq;
	bool sent;
	bool md;
	uint8_t data[15];
};

struct mesh_friend_seg_12 {
	uint32_t hdr;
	uint32_t seq;
	bool sent;
	bool md;
	uint8_t data[12];
};

struct mesh_friend_msg {
	uint32_t iv_index;
	uint32_t flags;
	uint16_t src;
	uint16_t dst;
	uint8_t ttl;
	uint8_t cnt_in;
	uint8_t cnt_out;
	uint8_t last_len;
	bool done;
	bool ctl;
	union {
		struct mesh_friend_seg_one one[1]; /* Single segment */
		struct mesh_friend_seg_12 s12[0]; /* Array of segments */
	} u;
};

typedef void (*mesh_status_func_t)(void *user_data, bool result);
typedef void (*mesh_net_status_func_t)(uint16_t remote, uint8_t status,
					void *data, uint16_t size,
					void *user_data);

struct mesh_net *mesh_net_new(struct mesh_node *node);
void mesh_net_free(struct mesh_net *net);
void mesh_net_flush_msg_queues(struct mesh_net *net);
void mesh_net_set_iv_index(struct mesh_net *net, uint32_t index, bool update);
bool mesh_net_iv_index_update(struct mesh_net *net);
bool mesh_net_set_seq_num(struct mesh_net *net, uint32_t number);
uint32_t mesh_net_get_seq_num(struct mesh_net *net);
uint32_t mesh_net_next_seq_num(struct mesh_net *net);
bool mesh_net_set_default_ttl(struct mesh_net *net, uint8_t ttl);
uint8_t mesh_net_get_default_ttl(struct mesh_net *net);
bool mesh_net_get_frnd_seq(struct mesh_net *net);
void mesh_net_set_frnd_seq(struct mesh_net *net, bool seq);
uint16_t mesh_net_get_address(struct mesh_net *net);
bool mesh_net_register_unicast(struct mesh_net *net,
					uint16_t unicast, uint8_t num_ele);
uint8_t mesh_net_get_num_ele(struct mesh_net *net);
void net_local_beacon(uint32_t key_id, uint8_t *beacon);
bool mesh_net_set_beacon_mode(struct mesh_net *net, bool enable);
bool mesh_net_set_proxy_mode(struct mesh_net *net, bool enable);
bool mesh_net_set_relay_mode(struct mesh_net *net, bool enable, uint8_t cnt,
							uint8_t interval);
bool mesh_net_set_friend_mode(struct mesh_net *net, bool enable);
int mesh_net_del_key(struct mesh_net *net, uint16_t net_idx);
int mesh_net_add_key(struct mesh_net *net, uint16_t net_idx,
							const uint8_t *key);
int mesh_net_update_key(struct mesh_net *net, uint16_t net_idx,
							const uint8_t *key);
bool mesh_net_set_key(struct mesh_net *net, uint16_t idx, const uint8_t *key,
					const uint8_t *new_key, uint8_t phase);
uint32_t mesh_net_get_iv_index(struct mesh_net *net);
void mesh_net_get_snb_state(struct mesh_net *net,
					uint8_t *flags, uint32_t *iv_index);
bool mesh_net_get_key(struct mesh_net *net, bool new_key, uint16_t idx,
							uint32_t *key_id);
bool mesh_net_attach(struct mesh_net *net, struct mesh_io *io);
struct mesh_io *mesh_net_detach(struct mesh_net *net);
struct l_queue *mesh_net_get_app_keys(struct mesh_net *net);

bool mesh_net_flush(struct mesh_net *net);
void mesh_net_transport_send(struct mesh_net *net, uint32_t key_id,
				bool fast, uint32_t iv_index, uint8_t ttl,
				uint32_t seq, uint16_t src, uint16_t dst,
				const uint8_t *msg, uint16_t msg_len);

bool mesh_net_app_send(struct mesh_net *net, bool frnd_cred, uint16_t src,
				uint16_t dst, uint8_t key_id, uint16_t net_idx,
				uint8_t ttl, uint32_t seq, uint32_t iv_index,
				bool szmic, const void *msg, uint16_t msg_len,
				mesh_net_status_func_t status_func,
				void *user_data);
void mesh_net_ack_send(struct mesh_net *net, uint32_t key_id,
				uint32_t iv_index, uint8_t ttl, uint32_t seq,
				uint16_t src, uint16_t dst, bool rly,
				uint16_t seqZero, uint32_t ack_flags);
struct mesh_net_prov_caps *mesh_net_prov_caps_get(struct mesh_net *net);
uint8_t *mesh_net_priv_key_get(struct mesh_net *net);
bool mesh_net_priv_key_set(struct mesh_net *net, uint8_t key[32]);
uint8_t *mesh_net_prov_rand(struct mesh_net *net);
uint16_t mesh_net_prov_uni(struct mesh_net *net, uint8_t ele_cnt);
bool mesh_net_id_uuid_set(struct mesh_net *net, uint8_t uuid[16]);
uint8_t *mesh_net_test_addr(struct mesh_net *net);
int mesh_net_get_identity_mode(struct mesh_net *net, uint16_t idx,
								uint8_t *mode);
char *mesh_net_id_name(struct mesh_net *net);
bool mesh_net_test_mode(struct mesh_net *net);
bool mesh_net_dst_reg(struct mesh_net *net, uint16_t dst);
bool mesh_net_dst_unreg(struct mesh_net *net, uint16_t dst);
struct mesh_friend *mesh_friend_new(struct mesh_net *net, uint16_t dst,
					uint8_t ele_cnt, uint8_t frd,
					uint8_t frw, uint32_t fpt,
					uint16_t fn_cnt, uint16_t lp_cnt);
void mesh_friend_free(void *frnd);
bool mesh_friend_clear(struct mesh_net *net, struct mesh_friend *frnd);
void mesh_friend_sub_add(struct mesh_net *net, uint16_t lpn, uint8_t ele_cnt,
							uint8_t grp_cnt,
							const uint8_t *list);
void mesh_friend_sub_del(struct mesh_net *net, uint16_t lpn, uint8_t cnt,
						const uint8_t *del_list);
uint8_t mesh_net_key_refresh_phase_set(struct mesh_net *net, uint16_t net_idx,
							uint8_t transition);
uint8_t mesh_net_key_refresh_phase_get(struct mesh_net *net, uint16_t net_idx,
							uint8_t *phase);
void mesh_net_send_seg(struct mesh_net *net, uint32_t key_id,
				uint32_t iv_index, uint8_t ttl, uint32_t seq,
				uint16_t src, uint16_t dst, uint32_t hdr,
				const void *seg, uint16_t seg_len);
uint16_t mesh_net_get_features(struct mesh_net *net);
struct mesh_net_heartbeat *mesh_net_heartbeat_get(struct mesh_net *net);
void mesh_net_heartbeat_init(struct mesh_net *net);
void mesh_net_heartbeat_send(struct mesh_net *net);
void mesh_net_uni_range_set(struct mesh_net *net,
				struct mesh_net_addr_range *range);
struct mesh_net_addr_range mesh_net_uni_range_get(struct mesh_net *net);
void mesh_net_provisioner_mode_set(struct mesh_net *net, bool mode);
bool mesh_net_provisioner_mode_get(struct mesh_net *net);
bool mesh_net_key_list_get(struct mesh_net *net, uint8_t *buf, uint16_t *count);
uint16_t mesh_net_get_primary_idx(struct mesh_net *net);
void mesh_net_sub_list_add(struct mesh_net *net, uint16_t addr);
void mesh_net_sub_list_del(struct mesh_net *net, uint16_t addr);
uint32_t mesh_net_friend_timeout(struct mesh_net *net, uint16_t addr);
struct mesh_io *mesh_net_get_io(struct mesh_net *net);
struct mesh_node *mesh_net_node_get(struct mesh_net *net);
bool mesh_net_have_key(struct mesh_net *net, uint16_t net_idx);
bool mesh_net_is_local_address(struct mesh_net *net, uint16_t src,
							uint16_t count);
void mesh_net_set_window_accuracy(struct mesh_net *net, uint8_t accuracy);
void mesh_net_transmit_params_set(struct mesh_net *net, uint8_t count,
							uint16_t interval);
void mesh_net_transmit_params_get(struct mesh_net *net, uint8_t *count,
							uint16_t *interval);
struct mesh_prov *mesh_net_get_prov(struct mesh_net *net);
void mesh_net_set_prov(struct mesh_net *net, struct mesh_prov *prov);
uint32_t mesh_net_get_instant(struct mesh_net *net);
struct l_queue *mesh_net_get_friends(struct mesh_net *net);
struct l_queue *mesh_net_get_negotiations(struct mesh_net *net);
bool net_msg_check_replay_cache(struct mesh_net *net, uint16_t src,
				uint16_t crpl, uint32_t seq, uint32_t iv_index);
void net_msg_add_replay_cache(struct mesh_net *net, uint16_t src, uint32_t seq,
							uint32_t iv_index);
