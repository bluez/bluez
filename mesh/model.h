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

struct mesh_model;

#define OP_UNRELIABLE			0x0100

#define MAX_BINDINGS	10
#define MAX_GRP_PER_MOD	10

#define OP_MODEL_TEST			0x8000fffe
#define OP_MODEL_INVALID		0x8000ffff

#define USE_PUB_VALUE			0x00

#define ACTION_ADD		1
#define ACTION_UPDATE		2
#define ACTION_DELETE		3

struct mesh_virtual;

struct mesh_model_pub {
	struct mesh_virtual *virt;
	uint16_t addr;
	uint16_t idx;
	uint8_t ttl;
	uint8_t credential;
	uint8_t period;
	uint8_t retransmit;
};

typedef void (*mesh_model_unregister)(void *user_data);
typedef bool (*mesh_model_recv_cb)(uint16_t src, uint16_t unicast,
					uint16_t app_idx, uint16_t net_idx,
					const uint8_t *data, uint16_t len,
					const void *user_data);
typedef int (*mesh_model_bind_cb)(uint16_t app_idx, int action);
typedef int (*mesh_model_pub_cb)(struct mesh_model_pub *pub);
typedef int (*mesh_model_sub_cb)(uint16_t sub_addr, int action);

struct mesh_model_ops {
	mesh_model_unregister unregister;
	mesh_model_recv_cb recv;
	mesh_model_bind_cb bind;
	mesh_model_pub_cb pub;
	mesh_model_sub_cb sub;
};

struct mesh_model *mesh_model_new(uint8_t ele_idx, uint32_t mod_id);
void mesh_model_free(void *data);
uint32_t mesh_model_get_model_id(const struct mesh_model *model);
bool mesh_model_register(struct mesh_node *node, uint8_t ele_idx,
			uint32_t mod_id, const struct mesh_model_ops *cbs,
							void *user_data);
struct mesh_model *mesh_model_setup(struct mesh_node *node, uint8_t ele_idx,
								void *data);
struct mesh_model_pub *mesh_model_pub_get(struct mesh_node *node,
				uint16_t addr, uint32_t mod_id, int *status);
int mesh_model_pub_set(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *pub_addr, uint16_t idx, bool cred_flag,
			uint8_t ttl, uint8_t period, uint8_t retransmit,
			bool is_virt, uint16_t *dst);

int mesh_model_binding_add(struct mesh_node *node, uint16_t addr, uint32_t id,
								uint16_t idx);
int mesh_model_binding_del(struct mesh_node *node, uint16_t addr, uint32_t id,
								uint16_t idx);
int mesh_model_get_bindings(struct mesh_node *node, uint16_t addr, uint32_t id,
				uint8_t *buf, uint16_t buf_len, uint16_t *size);
int mesh_model_sub_add(struct mesh_node *node, uint16_t addr, uint32_t id,
				const uint8_t *grp, bool b_virt, uint16_t *dst);
int mesh_model_sub_del(struct mesh_node *node, uint16_t addr, uint32_t id,
				const uint8_t *grp, bool b_virt, uint16_t *dst);
int mesh_model_sub_del_all(struct mesh_node *node, uint16_t addr, uint32_t id);
int mesh_model_sub_ovr(struct mesh_node *node, uint16_t addr, uint32_t id,
				const uint8_t *grp, bool b_virt, uint16_t *dst);
int mesh_model_sub_get(struct mesh_node *node, uint16_t addr, uint32_t id,
			uint8_t *buf, uint16_t buf_size, uint16_t *size);
uint16_t mesh_model_cfg_blk(uint8_t *pkt);
bool mesh_model_send(struct mesh_node *node, uint16_t src, uint16_t dst,
					uint16_t app_idx, uint16_t net_idx,
					uint8_t ttl,
					const void *msg, uint16_t msg_len);
int mesh_model_publish(struct mesh_node *node, uint32_t mod_id, uint16_t src,
				uint8_t ttl, const void *msg, uint16_t msg_len);
bool mesh_model_rx(struct mesh_node *node, bool szmict, uint32_t seq0,
			uint32_t seq, uint32_t iv_index, uint16_t net_idx,
			uint16_t src, uint16_t dst, uint8_t key_aid,
			const uint8_t *data, uint16_t size);
void mesh_model_app_key_generate_new(struct mesh_node *node, uint16_t net_idx);
void mesh_model_app_key_delete(struct mesh_node *node, struct l_queue *models,
								uint16_t idx);
struct l_queue *mesh_model_get_appkeys(struct mesh_node *node);
uint16_t mesh_model_opcode_set(uint32_t opcode, uint8_t *buf);
bool mesh_model_opcode_get(const uint8_t *buf, uint16_t size, uint32_t *opcode,
								uint16_t *n);
void model_build_config(void *model, void *msg_builder);

void mesh_model_init(void);
void mesh_model_cleanup(void);
