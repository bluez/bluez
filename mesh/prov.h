/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
 *
 *
 */

#ifndef __packed
#define __packed __attribute__((packed))
#endif

typedef void (*prov_trans_tx_t)(void *tx_data, const void *data, uint16_t len);
typedef void (*mesh_prov_open_func_t)(void *user_data, prov_trans_tx_t trans_tx,
					void *trans_data, uint8_t trans_type);

typedef void (*mesh_prov_close_func_t)(void *user_data, uint8_t reason);
typedef void (*mesh_prov_ack_func_t)(void *user_data, uint8_t msg_num);
typedef void (*mesh_prov_receive_func_t)(void *user_data, const void *data,
								uint16_t size);


struct prov_invite {
	uint8_t attention;
} __packed;

struct prov_invite_msg {
	uint8_t opcode;
	struct prov_invite invite;
} __packed;

struct prov_start {
	uint8_t algorithm;
	uint8_t pub_key;
	uint8_t auth_method;
	uint8_t auth_action;
	uint8_t auth_size;
} __packed;

struct prov_caps_msg {
	uint8_t opcode;
	struct mesh_net_prov_caps caps;
} __packed;

struct prov_start_msg {
	uint8_t opcode;
	struct prov_start start;
} __packed;

struct prov_pub_key_msg {
	uint8_t opcode;
	uint8_t pub_key[64];
} __packed;

struct prov_conf_msg {
	uint8_t opcode;
	uint8_t conf[16];
} __packed;

struct prov_rand_msg {
	uint8_t opcode;
	uint8_t rand[16];
} __packed;

struct prov_data {
	uint8_t net_key[16];
	uint16_t net_idx;
	uint8_t flags;
	uint32_t iv_index;
	uint16_t primary;
} __packed;

struct prov_data_msg {
	uint8_t opcode;
	struct prov_data data;
	uint64_t mic;
} __packed;

struct prov_fail_msg {
	uint8_t opcode;
	uint8_t reason;
} __packed;

struct conf_input {
	struct prov_invite		invite;
	struct mesh_net_prov_caps	caps;
	struct prov_start		start;
	uint8_t				prv_pub_key[64];
	uint8_t				dev_pub_key[64];
} __packed;
