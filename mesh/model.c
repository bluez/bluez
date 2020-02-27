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

#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/crypto.h"
#include "mesh/node.h"
#include "mesh/mesh-config.h"
#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/cfgmod.h"
#include "mesh/error.h"
#include "mesh/dbus.h"
#include "mesh/util.h"
#include "mesh/model.h"
#include "mesh/keyring.h"

/* Divide and round to ceiling (up) to calculate segment count */
#define CEILDIV(val, div) (((val) + (div) - 1) / (div))

#define VIRTUAL_BASE			0x10000

struct mesh_model {
	const struct mesh_model_ops *cbs;
	void *user_data;
	struct l_queue *bindings;
	struct l_queue *subs;
	struct l_queue *virtuals;
	struct mesh_model_pub *pub;
	uint32_t id;
	uint8_t ele_idx;
};

struct mesh_virtual {
	uint16_t ref_cnt;
	uint16_t addr; /* 16-bit virtual address, used in messages */
	uint8_t label[16]; /* 128 bit label UUID */
};

/* These struct is used to pass lots of params to l_queue_foreach */
struct mod_forward {
	struct mesh_virtual *virt;
	const uint8_t *data;
	uint16_t src;
	uint16_t dst;
	uint16_t unicast;
	uint16_t app_idx;
	uint16_t net_idx;
	uint16_t size;
	int8_t rssi;
	bool szmict;
	bool has_dst;
	bool done;
};

static struct l_queue *mesh_virtuals;

static struct timeval tx_start;

static bool is_internal(uint32_t id)
{
	if (id == CONFIG_SRV_MODEL || id == CONFIG_CLI_MODEL)
		return true;

	return false;
}

static void unref_virt(void *data)
{
	struct mesh_virtual *virt = data;

	if (virt->ref_cnt > 0)
		virt->ref_cnt--;

	if (virt->ref_cnt)
		return;

	l_queue_remove(mesh_virtuals, virt);
	l_free(virt);
}

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

static bool has_binding(struct l_queue *bindings, uint16_t idx)
{
	const struct l_queue_entry *l;

	for (l = l_queue_get_entries(bindings); l; l = l->next) {
		if (L_PTR_TO_UINT(l->data) == idx)
			return true;
	}
	return false;
}

static bool find_virt_by_label(const void *a, const void *b)
{
	const struct mesh_virtual *virt = a;
	const uint8_t *label = b;

	return memcmp(virt->label, label, 16) == 0;
}

static bool match_model_id(const void *a, const void *b)
{
	const struct mesh_model *model = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return (mesh_model_get_model_id(model) == id);
}

static struct mesh_model *get_model(struct mesh_node *node, uint8_t ele_idx,
						uint32_t id, int *status)
{
	struct l_queue *models;
	struct mesh_model *model;

	models = node_get_element_models(node, ele_idx, status);
	if (!models) {
		*status = MESH_STATUS_INVALID_MODEL;
		return NULL;
	}

	model = l_queue_find(models, match_model_id, L_UINT_TO_PTR(id));

	*status = (model) ? MESH_STATUS_SUCCESS : MESH_STATUS_INVALID_MODEL;

	return model;
}

static struct mesh_model *find_model(struct mesh_node *node, uint16_t addr,
						uint32_t mod_id, int *status)
{
	int ele_idx;

	ele_idx = node_get_element_idx(node, addr);

	if (ele_idx < 0) {
		*status = MESH_STATUS_INVALID_ADDRESS;
		return NULL;
	}

	return get_model(node, (uint8_t) ele_idx, mod_id, status);
}

static uint32_t pub_period_to_ms(uint8_t pub_period)
{
	int n;

	n = pub_period >> 2;

	switch (pub_period & 0x3) {
	default:
		return n * 100;
	case 2:
		n *= 10;
		/* Fall Through */
	case 1:
		return n * 1000;
	case 3:
		return n * 10 * 60 * 1000;
	}
}

static struct l_dbus_message *create_config_update_msg(struct mesh_node *node,
					uint8_t ele_idx, uint32_t id,
					struct l_dbus_message_builder **builder)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *msg;
	const char *owner;
	const char *path;
	uint16_t model_id;

	owner = node_get_owner(node);
	path = node_get_element_path(node, ele_idx);
	if (!path || !owner)
		return NULL;

	l_debug("Send \"UpdateModelConfiguration\"");
	msg = l_dbus_message_new_method_call(dbus, owner, path,
						MESH_ELEMENT_INTERFACE,
						"UpdateModelConfiguration");

	*builder = l_dbus_message_builder_new(msg);

	model_id = (uint16_t) id;

	l_dbus_message_builder_append_basic(*builder, 'q', &model_id);

	l_dbus_message_builder_enter_array(*builder, "{sv}");

	if ((id & VENDOR_ID_MASK) != VENDOR_ID_MASK) {
		uint16_t vendor = id >> 16;
		dbus_append_dict_entry_basic(*builder, "Vendor", "q", &vendor);
	}

	return msg;
}

static void config_update_model_pub_period(struct mesh_node *node,
					uint8_t ele_idx, uint32_t model_id,
					uint32_t period)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *msg;
	struct l_dbus_message_builder *builder;

	msg = create_config_update_msg(node, ele_idx, model_id, &builder);
	if (!msg)
		return;

	dbus_append_dict_entry_basic(builder, "PublicationPeriod", "u",
								&period);

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
	l_dbus_send(dbus, msg);
}

static void append_dict_uint16_array(struct l_dbus_message_builder *builder,
					struct l_queue *q, const char *key)
{
	const struct l_queue_entry *entry;

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', key);
	l_dbus_message_builder_enter_variant(builder, "aq");
	l_dbus_message_builder_enter_array(builder, "q");

	for (entry = l_queue_get_entries(q); entry; entry = entry->next) {
		uint16_t value = (uint16_t) L_PTR_TO_UINT(entry->data);

		l_dbus_message_builder_append_basic(builder,'q', &value);
	}

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);
}

static void config_update_model_bindings(struct mesh_node *node,
							struct mesh_model *mod)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *msg;
	struct l_dbus_message_builder *builder;

	msg = create_config_update_msg(node, mod->ele_idx, mod->id,
								&builder);
	if (!msg)
		return;

	append_dict_uint16_array(builder, mod->bindings, "Bindings");

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
	l_dbus_send(dbus, msg);
}

static void append_dict_subs_array(struct l_dbus_message_builder *builder,
						struct l_queue *subs,
						struct l_queue *virts,
						const char *key)
{
	const struct l_queue_entry *entry;

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', key);
	l_dbus_message_builder_enter_variant(builder, "av");
	l_dbus_message_builder_enter_array(builder, "v");

	if (l_queue_isempty(subs))
		goto virts;

	for (entry = l_queue_get_entries(subs); entry; entry = entry->next) {
		uint16_t grp = L_PTR_TO_UINT(entry->data);

		l_dbus_message_builder_enter_variant(builder, "q");
		l_dbus_message_builder_append_basic(builder, 'q', &grp);
		l_dbus_message_builder_leave_variant(builder);
	}

virts:
	if (l_queue_isempty(virts))
		goto done;

	for (entry = l_queue_get_entries(virts); entry; entry = entry->next) {
		const struct mesh_virtual *virt = entry->data;

		l_dbus_message_builder_enter_variant(builder, "ay");
		dbus_append_byte_array(builder, virt->label,
							sizeof(virt->label));
		l_dbus_message_builder_leave_variant(builder);

	}

done:
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);
}

static void config_update_model_subscriptions(struct mesh_node *node,
							struct mesh_model *mod)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *msg;
	struct l_dbus_message_builder *builder;

	msg = create_config_update_msg(node, mod->ele_idx, mod->id,
								&builder);
	if (!msg)
		return;

	append_dict_subs_array(builder, mod->subs, mod->virtuals,
							"Subscriptions");

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
	l_dbus_send(dbus, msg);
}

static void forward_model(void *a, void *b)
{
	struct mesh_model *mod = a;
	struct mod_forward *fwd = b;
	struct mesh_virtual *virt;
	uint16_t dst;
	bool result;

	if (fwd->app_idx != APP_IDX_DEV_LOCAL &&
				fwd->app_idx != APP_IDX_DEV_REMOTE &&
				!has_binding(mod->bindings, fwd->app_idx))
		return;

	dst = fwd->dst;

	if (dst == fwd->unicast || IS_FIXED_GROUP_ADDRESS(dst)) {
		fwd->has_dst = true;
	} else if (fwd->virt) {
		virt = l_queue_find(mod->virtuals, simple_match, fwd->virt);
		if (virt) {
			fwd->has_dst = true;
			dst = virt->addr;
		}
	} else {
		if (l_queue_find(mod->subs, simple_match, L_UINT_TO_PTR(dst)))
			fwd->has_dst = true;
	}

	if (!fwd->has_dst)
		return;

	/* Return, if this is not a internal model */
	if (!mod->cbs)
		return;

	result = false;

	if (mod->cbs->recv)
		result = mod->cbs->recv(fwd->src, dst, fwd->app_idx,
				fwd->net_idx,
				fwd->data, fwd->size, mod->user_data);

	if (dst == fwd->unicast && result)
		fwd->done = true;
}

static int app_packet_decrypt(struct mesh_net *net, const uint8_t *data,
				uint16_t size, bool szmict, uint16_t src,
				uint16_t dst, uint8_t *virt, uint16_t virt_size,
				uint8_t key_aid, uint32_t seq,
				uint32_t iv_idx, uint8_t *out)
{
	struct l_queue *app_keys = mesh_net_get_app_keys(net);
	const struct l_queue_entry *entry;

	if (!app_keys)
		return -1;

	for (entry = l_queue_get_entries(app_keys); entry;
							entry = entry->next) {
		const uint8_t *old_key = NULL, *new_key = NULL;
		uint8_t old_key_aid, new_key_aid;
		int app_idx;
		bool decrypted;

		app_idx = appkey_get_key_idx(entry->data,
							&old_key, &old_key_aid,
							&new_key, &new_key_aid);

		if (app_idx < 0)
			continue;

		if (old_key && old_key_aid == key_aid) {
			decrypted = mesh_crypto_payload_decrypt(virt, virt_size,
					data, size, szmict, src, dst, key_aid,
						seq, iv_idx, out, old_key);

			if (decrypted) {
				print_packet("Used App Key", old_key, 16);
				return app_idx;
			}

			print_packet("Failed App Key", old_key, 16);
		}

		if (new_key && new_key_aid == key_aid) {
			decrypted = mesh_crypto_payload_decrypt(virt, virt_size,
					data, size, szmict, src, dst, key_aid,
						seq, iv_idx, out, new_key);

			if (decrypted) {
				print_packet("Used App Key", new_key, 16);
				return app_idx;
			}

			print_packet("Failed App Key", new_key, 16);
		}
	}

	return -1;
}

static int dev_packet_decrypt(struct mesh_node *node, const uint8_t *data,
				uint16_t size, bool szmict, uint16_t src,
				uint16_t dst, uint8_t key_aid, uint32_t seq,
				uint32_t iv_idx, uint8_t *out)
{
	uint8_t dev_key[16];
	const uint8_t *key;

	key = node_get_device_key(node);
	if (!key)
		return -1;

	if (mesh_crypto_payload_decrypt(NULL, 0, data, size, szmict, src,
					dst, key_aid, seq, iv_idx, out, key))
		return APP_IDX_DEV_LOCAL;

	if (!keyring_get_remote_dev_key(node, src, dev_key))
		return -1;

	key = dev_key;
	if (mesh_crypto_payload_decrypt(NULL, 0, data, size, szmict, src,
					dst, key_aid, seq, iv_idx, out, key))
		return APP_IDX_DEV_REMOTE;

	return -1;
}

static int virt_packet_decrypt(struct mesh_net *net, const uint8_t *data,
				uint16_t size, bool szmict, uint16_t src,
				uint16_t dst, uint8_t key_aid, uint32_t seq,
				uint32_t iv_idx, uint8_t *out,
				struct mesh_virtual **decrypt_virt)
{
	const struct l_queue_entry *v;

	for (v = l_queue_get_entries(mesh_virtuals); v; v = v->next) {
		struct mesh_virtual *virt = v->data;
		int decrypt_idx;

		if (virt->addr != dst)
			continue;

		decrypt_idx = app_packet_decrypt(net, data, size, szmict, src,
							dst, virt->label, 16,
							key_aid, seq, iv_idx,
							out);

		if (decrypt_idx >= 0) {
			*decrypt_virt = virt;
			return decrypt_idx;
		}
	}

	return -1;
}

static void cmplt(uint16_t remote, uint8_t status,
					void *data, uint16_t size,
					void *user_data)
{
	struct timeval tx_end;

	if (status)
		l_debug("Tx-->%4.4x (%d octets) Failed (%d)",
				remote, size, status);
	else
		l_debug("Tx-->%4.4x (%d octets) Succeeded", remote, size);

	/* print_packet("Sent Data", data, size); */

	gettimeofday(&tx_end, NULL);
	if (tx_end.tv_sec == tx_start.tv_sec) {
		l_debug("Duration 0.%6.6lu seconds",
				tx_end.tv_usec - tx_start.tv_usec);
	} else {
		if (tx_start.tv_usec > tx_end.tv_usec)
			l_debug("Duration %lu.%6.6lu seconds",
				tx_end.tv_sec - tx_start.tv_sec - 1,
				tx_end.tv_usec + 1000000 - tx_start.tv_usec);
		else
			l_debug("Duration %lu.%6.6lu seconds",
					tx_end.tv_sec - tx_start.tv_sec,
					tx_end.tv_usec - tx_start.tv_usec);
	}
}

static bool msg_send(struct mesh_node *node, bool credential, uint16_t src,
		uint32_t dst, uint16_t app_idx, uint16_t net_idx,
		uint8_t *label, uint8_t ttl,
		const void *msg, uint16_t msg_len)
{
	uint8_t dev_key[16];
	uint32_t iv_index, seq_num;
	const uint8_t *key;
	uint8_t *out;
	uint8_t key_aid = APP_AID_DEV;
	bool szmic = false;
	bool ret = false;
	uint16_t out_len = msg_len + sizeof(uint32_t);
	struct mesh_net *net = node_get_net(node);

	/* Use large MIC if it doesn't affect segmentation */
	if (msg_len > 11 && msg_len <= 376) {
		if (CEILDIV(out_len, 12) == CEILDIV(out_len + 4, 12)) {
			szmic = true;
			out_len = msg_len + sizeof(uint64_t);
		}
	}

	if (app_idx == APP_IDX_DEV_LOCAL) {
		key = node_get_device_key(node);
		if (!key)
			return false;
	} else if (app_idx == APP_IDX_DEV_REMOTE) {
		if (!keyring_get_remote_dev_key(node, dst, dev_key))
			return false;

		key = dev_key;
	} else {
		key = appkey_get_key(node_get_net(node), app_idx, &key_aid);
		if (!key) {
			l_debug("no app key for (%x)", app_idx);
			return false;
		}

		net_idx = appkey_net_idx(node_get_net(node), app_idx);
	}

	l_debug("(%x) %p", app_idx, key);
	l_debug("net_idx %x", net_idx);

	out = l_malloc(out_len);

	iv_index = mesh_net_get_iv_index(net);

	seq_num = mesh_net_next_seq_num(net);
	if (!mesh_crypto_payload_encrypt(label, msg, out, msg_len, src, dst,
				key_aid, seq_num, iv_index, szmic, key)) {
		l_error("Failed to Encrypt Payload");
		goto done;
	}

	/* print_packet("Encrypted with", key, 16); */

	ret = mesh_net_app_send(net, credential, src, dst, key_aid, net_idx,
					ttl, seq_num, iv_index, szmic, out,
					out_len, cmplt, NULL);
done:
	l_free(out);
	return ret;
}

static void remove_pub(struct mesh_node *node, struct mesh_model *mod)
{
	if (mod->pub) {
		if (mod->pub->virt)
			unref_virt(mod->pub->virt);

		l_free(mod->pub);
		mod->pub = NULL;
	}

	if (!mod->cbs)
		/* External models */
		config_update_model_pub_period(node, mod->ele_idx, mod->id, 0);
	else if (mod->cbs && mod->cbs->pub)
		/* Internal models */
		mod->cbs->pub(NULL);
}

static void model_unbind_idx(struct mesh_node *node, struct mesh_model *mod,
								uint16_t idx)
{
	l_queue_remove(mod->bindings, L_UINT_TO_PTR(idx));

	if (!mod->cbs)
		/* External model */
		config_update_model_bindings(node, mod);
	else if (mod->cbs->bind)
		/* Internal model */
		mod->cbs->bind(idx, ACTION_DELETE);

	/* Remove model publication if the publication key is unbound */
	if (mod->pub && idx == mod->pub->idx)
		remove_pub(node, mod);
}

static void model_bind_idx(struct mesh_node *node, struct mesh_model *mod,
								uint16_t idx)
{
	if (!mod->bindings)
		mod->bindings = l_queue_new();

	l_queue_push_tail(mod->bindings, L_UINT_TO_PTR(idx));

	l_debug("Add %4.4x to model %8.8x", idx, mod->id);

	if (!mod->cbs)
		/* External model */
		config_update_model_bindings(node, mod);
	else if (mod->cbs->bind)
		/* Internal model */
		mod->cbs->bind(idx, ACTION_ADD);
}

static int update_binding(struct mesh_node *node, uint16_t addr, uint32_t id,
						uint16_t app_idx, bool unbind)
{
	int status;
	struct mesh_model *mod;
	bool is_present, is_vendor;

	mod = find_model(node, addr, id, &status);
	if (!mod) {
		l_debug("Model not found");
		return status;
	}

	is_vendor = id < VENDOR_ID_MASK && id > 0xffff;
	id = !is_vendor ? (id & 0xffff) : id;

	if (id == CONFIG_SRV_MODEL || id == CONFIG_CLI_MODEL)
		return MESH_STATUS_INVALID_MODEL;

	if (!appkey_have_key(node_get_net(node), app_idx))
		return MESH_STATUS_INVALID_APPKEY;

	is_present = has_binding(mod->bindings, app_idx);

	if (!is_present && unbind)
		return MESH_STATUS_SUCCESS;

	if (is_present && !unbind)
		return MESH_STATUS_SUCCESS;

	if (unbind) {
		model_unbind_idx(node, mod, app_idx);
		if (!mesh_config_model_binding_del(node_config_get(node),
					addr, is_vendor, id, app_idx))
			return MESH_STATUS_STORAGE_FAIL;

		return MESH_STATUS_SUCCESS;
	}

	if (l_queue_length(mod->bindings) >= MAX_BINDINGS)
		return MESH_STATUS_INSUFF_RESOURCES;

	if (!mesh_config_model_binding_add(node_config_get(node),
					addr, is_vendor, id, app_idx))
		return MESH_STATUS_STORAGE_FAIL;

	model_bind_idx(node, mod, app_idx);

	return MESH_STATUS_SUCCESS;

}

static struct mesh_virtual *add_virtual(const uint8_t *v)
{
	struct mesh_virtual *virt = l_queue_find(mesh_virtuals,
						find_virt_by_label, v);

	if (virt) {
		virt->ref_cnt++;
		return virt;
	}

	virt = l_new(struct mesh_virtual, 1);

	if (!mesh_crypto_virtual_addr(v, &virt->addr)) {
		l_free(virt);
		return NULL;
	}

	memcpy(virt->label, v, 16);
	virt->ref_cnt = 1;
	l_queue_push_head(mesh_virtuals, virt);

	return virt;
}

static int set_pub(struct mesh_model *mod, uint16_t pub_addr,
			uint16_t idx, bool cred_flag, uint8_t ttl,
			uint8_t period, uint8_t retransmit)
{
	if (!mod->pub)
		mod->pub = l_new(struct mesh_model_pub, 1);

	mod->pub->addr = pub_addr;
	mod->pub->credential = cred_flag;
	mod->pub->idx = idx;
	mod->pub->ttl = ttl;
	mod->pub->period = period;
	mod->pub->retransmit = retransmit;

	return MESH_STATUS_SUCCESS;
}

static int set_virt_pub(struct mesh_model *mod, const uint8_t *label,
			uint16_t idx, bool cred_flag, uint8_t ttl,
			uint8_t period, uint8_t retransmit)
{
	struct mesh_virtual *virt = NULL;

	virt = add_virtual(label);
	if (!virt)
		return MESH_STATUS_STORAGE_FAIL;

	if (!mod->pub)
		mod->pub = l_new(struct mesh_model_pub, 1);

	mod->pub->virt = virt;
	return set_pub(mod, virt->addr, idx, cred_flag, ttl, period,
								retransmit);
}

static int add_virt_sub(struct mesh_net *net, struct mesh_model *mod,
			     const uint8_t *label, uint16_t *dst)
{
	struct mesh_virtual *virt = l_queue_find(mod->virtuals,
						find_virt_by_label, label);

	if (!virt) {
		virt = add_virtual(label);
		if (!virt)
			return MESH_STATUS_STORAGE_FAIL;

		l_queue_push_head(mod->virtuals, virt);
		mesh_net_dst_reg(net, virt->addr);
		l_debug("Added virtual sub addr %4.4x", virt->addr);
	}

	if (dst)
		*dst = virt->addr;

	return MESH_STATUS_SUCCESS;
}

static int add_sub(struct mesh_net *net, struct mesh_model *mod,
			const uint8_t *group, bool b_virt, uint16_t *dst)
{
	uint16_t grp;

	if (b_virt)
		return add_virt_sub(net, mod, group, dst);

	grp = l_get_le16(group);
	if (dst)
		*dst = grp;

	if (!l_queue_find(mod->subs, simple_match, L_UINT_TO_PTR(grp))) {

		if (!mod->subs)
			mod->subs = l_queue_new();

		l_queue_push_tail(mod->subs, L_UINT_TO_PTR(grp));
		mesh_net_dst_reg(net, grp);
		l_debug("Added group subscription %4.4x", grp);
	}

	return MESH_STATUS_SUCCESS;
}

static void send_dev_key_msg_rcvd(struct mesh_node *node, uint8_t ele_idx,
					uint16_t src, uint16_t app_idx,
					uint16_t net_idx, uint16_t size,
					const uint8_t *data)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *msg;
	struct l_dbus_message_builder *builder;
	const char *owner;
	const char *path;
	bool remote = (app_idx != APP_IDX_DEV_LOCAL);

	owner = node_get_owner(node);
	path = node_get_element_path(node, ele_idx);
	if (!path || !owner)
		return;

	l_debug("Send \"DevKeyMessageReceived\"");

	msg = l_dbus_message_new_method_call(dbus, owner, path,
						MESH_ELEMENT_INTERFACE,
						"DevKeyMessageReceived");

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'q', &src);
	l_dbus_message_builder_append_basic(builder, 'b', &remote);
	l_dbus_message_builder_append_basic(builder, 'q', &net_idx);
	dbus_append_byte_array(builder, data, size);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	l_dbus_send(dbus, msg);
}

static void send_msg_rcvd(struct mesh_node *node, uint8_t ele_idx,
					uint16_t src, uint16_t dst,
					const struct mesh_virtual *virt,
					uint16_t app_idx,
					uint16_t size, const uint8_t *data)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *msg;
	struct l_dbus_message_builder *builder;
	const char *owner;
	const char *path;

	owner = node_get_owner(node);
	path = node_get_element_path(node, ele_idx);
	if (!path || !owner)
		return;

	l_debug("Send \"MessageReceived\"");

	msg = l_dbus_message_new_method_call(dbus, owner, path,
				MESH_ELEMENT_INTERFACE, "MessageReceived");

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'q', &src);
	l_dbus_message_builder_append_basic(builder, 'q', &app_idx);

	if (virt) {
		l_dbus_message_builder_enter_variant(builder, "ay");
		dbus_append_byte_array(builder, virt->label,
							sizeof(virt->label));
		l_dbus_message_builder_leave_variant(builder);
	} else {
		l_dbus_message_builder_enter_variant(builder, "q");
		l_dbus_message_builder_append_basic(builder, 'q', &dst);
		l_dbus_message_builder_leave_variant(builder);
	}

	dbus_append_byte_array(builder, data, size);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
	l_dbus_send(dbus, msg);
}

bool mesh_model_rx(struct mesh_node *node, bool szmict, uint32_t seq0,
			uint32_t seq, uint32_t iv_index,
			uint16_t net_idx, uint16_t src, uint16_t dst,
			uint8_t key_aid, const uint8_t *data, uint16_t size)
{
	uint8_t *clear_text;
	struct mod_forward forward = {
		.src = src,
		.dst = dst,
		.data = NULL,
		.size = size - (szmict ? 8 : 4),
		.virt = NULL,
	};
	struct mesh_net *net = node_get_net(node);
	uint8_t num_ele;
	int decrypt_idx, i, ele_idx;
	uint16_t addr, crpl;
	struct mesh_virtual *decrypt_virt = NULL;
	bool result = false;
	bool is_subscription;

	l_debug("iv_index %8.8x key_aid = %2.2x", iv_index, key_aid);
	if (!dst)
		return false;

	ele_idx = node_get_element_idx(node, dst);

	if (dst < 0x8000 && ele_idx < 0)
		/* Unicast and not addressed to us */
		return false;

	/* Don't process if already in RPL */
	crpl = node_get_crpl(node);
	if (net_msg_check_replay_cache(net, src, crpl, seq, iv_index))
		return false;

	clear_text = l_malloc(size);
	forward.data = clear_text;

	/*
	 * The packet needs to be decoded by the correct key which
	 * is hinted by key_aid, but is not necessarily definitive
	 */
	if (key_aid == APP_AID_DEV || mesh_net_provisioner_mode_get(net))
		decrypt_idx = dev_packet_decrypt(node, data, size, szmict, src,
						dst, key_aid, seq0, iv_index,
						clear_text);
	else if ((dst & 0xc000) == 0x8000)
		decrypt_idx = virt_packet_decrypt(net, data, size, szmict, src,
							dst, key_aid, seq0,
							iv_index, clear_text,
							&decrypt_virt);
	else
		decrypt_idx = app_packet_decrypt(net, data, size, szmict, src,
						dst, NULL, 0,
						key_aid, seq0, iv_index,
						clear_text);

	if (decrypt_idx < 0) {
		l_error("model.c - Failed to decrypt application payload");
		result = false;
		goto done;
	}

	print_packet("Clr Rx", clear_text, size - (szmict ? 8 : 4));

	forward.virt = decrypt_virt;
	forward.app_idx = decrypt_idx;
	forward.net_idx = net_idx;
	num_ele = node_get_num_elements(node);
	addr = node_get_primary(node);

	if (!num_ele || IS_UNASSIGNED(addr))
		goto done;

	/*
	 * In case of fixed group  addresses check if the
	 * corresponding mode is enabled.
	 */
	if (dst == PROXIES_ADDRESS &&
			(node_proxy_mode_get(node) != MESH_MODE_ENABLED))
		goto done;

	if (dst == FRIENDS_ADDRESS &&
			(node_friend_mode_get(node) != MESH_MODE_ENABLED))
		goto done;

	if (dst == RELAYS_ADDRESS) {
		uint8_t cnt;
		uint16_t interval;

		if (node_relay_mode_get(node, &cnt, &interval) !=
							MESH_MODE_ENABLED)
			goto done;
	}

	is_subscription = !(IS_UNICAST(dst));


	for (i = 0; i < num_ele; i++) {
		struct l_queue *models;

		if (!is_subscription && ele_idx != i)
			continue;

		forward.unicast = addr + i;
		forward.has_dst = false;

		models = node_get_element_models(node, i, NULL);

		/* Internal models */
		l_queue_foreach(models, forward_model, &forward);

		/*
		 * Cycle through external models if the message has not been
		 * handled by internal models
		 */
		if (forward.has_dst && !forward.done) {
			if ((decrypt_idx & APP_IDX_MASK) == decrypt_idx)
				send_msg_rcvd(node, i, src, dst, decrypt_virt,
						forward.app_idx, forward.size,
						forward.data);
			else if (decrypt_idx == APP_IDX_DEV_REMOTE ||
				 decrypt_idx == APP_IDX_DEV_LOCAL)
				send_dev_key_msg_rcvd(node, i, src, decrypt_idx,
						0, forward.size, forward.data);
		}

		/*
		 * Either the message has been processed internally or
		 * has been passed on to an external model.
		 */
		result |= forward.has_dst | forward.done;

		/* If the message was to unicast address, we are done */
		if (!is_subscription && ele_idx == i)
			break;

		/*
		 * For the fixed group addresses, i.e., all-proxies,
		 * all-friends, all-relays, all-nodes, the message is delivered
		 * to a primary element only.
		 */
		if (IS_FIXED_GROUP_ADDRESS(dst))
			break;
	}

	/* If message has been handled by us, add to RPL */
	if (result)
		net_msg_add_replay_cache(net, src, seq, iv_index);

done:
	l_free(clear_text);

	return result;
}

int mesh_model_publish(struct mesh_node *node, uint32_t mod_id,
				uint16_t src, uint8_t ttl,
				const void *msg, uint16_t msg_len)
{
	struct mesh_net *net = node_get_net(node);
	struct mesh_model *mod;
	uint8_t *label = NULL;
	uint16_t net_idx;
	bool result;
	int status;

	/* print_packet("Mod Tx", msg, msg_len); */

	if (!net || msg_len > 380)
		return MESH_ERROR_INVALID_ARGS;

	/* If SRC is 0, use the Primary Element */
	if (src == 0)
		src = mesh_net_get_address(net);

	mod = find_model(node, src, mod_id, &status);
	if (!mod) {
		l_debug("model %x not found", mod_id);
		return MESH_ERROR_NOT_FOUND;
	}

	if (!mod->pub) {
		l_debug("publication doesn't exist (model %x)", mod_id);
		return MESH_ERROR_DOES_NOT_EXIST;
	}

	gettimeofday(&tx_start, NULL);

	if (IS_UNASSIGNED(mod->pub->addr))
		return MESH_ERROR_DOES_NOT_EXIST;

	if (mod->pub->virt)
		label = mod->pub->virt->label;

	l_debug("publish dst=%x", mod->pub->addr);

	net_idx = appkey_net_idx(net, mod->pub->idx);

	result = msg_send(node, mod->pub->credential != 0, src,
				mod->pub->addr, mod->pub->idx, net_idx,
				label, ttl, msg, msg_len);

	return result ? MESH_ERROR_NONE : MESH_ERROR_FAILED;
}

bool mesh_model_send(struct mesh_node *node, uint16_t src, uint16_t dst,
					uint16_t app_idx, uint16_t net_idx,
					uint8_t ttl,
					const void *msg, uint16_t msg_len)
{
	/* print_packet("Mod Tx", msg, msg_len); */

	/* If SRC is 0, use the Primary Element */
	if (src == 0)
		src = node_get_primary(node);

	gettimeofday(&tx_start, NULL);

	if (IS_UNASSIGNED(dst))
		return false;

	return msg_send(node, false, src, dst, app_idx, net_idx,
						NULL, ttl, msg, msg_len);
}

int mesh_model_pub_set(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *pub_addr, uint16_t idx, bool cred_flag,
			uint8_t ttl, uint8_t period, uint8_t retransmit,
			bool is_virt, uint16_t *dst)
{
	struct mesh_model *mod;
	int status;

	mod = find_model(node, addr, id, &status);
	if (!mod)
		return status;

	if (id == CONFIG_SRV_MODEL || id == CONFIG_CLI_MODEL)
		return MESH_STATUS_INVALID_PUB_PARAM;

	if (!appkey_have_key(node_get_net(node), idx))
		return MESH_STATUS_INVALID_APPKEY;

	/*
	 * If the publication address is set to unassigned address value,
	 * remove the publication
	 */
	if (!is_virt && IS_UNASSIGNED(l_get_le16(pub_addr))) {
		remove_pub(node, mod);
		return MESH_STATUS_SUCCESS;
	}

	/* Check if the old publication destination is a virtual label */
	if (mod->pub && mod->pub->virt) {
		unref_virt(mod->pub->virt);
		mod->pub->virt = NULL;
	}

	if (!is_virt) {
		status = set_pub(mod, l_get_le16(pub_addr), idx, cred_flag,
						ttl, period, retransmit);
	} else
		status = set_virt_pub(mod, pub_addr, idx, cred_flag, ttl,
						period, retransmit);

	*dst = mod->pub->addr;

	if (status != MESH_STATUS_SUCCESS)
		return status;

	if (!mod->cbs)
		/* External model */
		config_update_model_pub_period(node, mod->ele_idx, id,
						pub_period_to_ms(period));
	else
		/* Internal model, call registered callbacks */
		mod->cbs->pub(mod->pub);

	return MESH_STATUS_SUCCESS;
}

struct mesh_model_pub *mesh_model_pub_get(struct mesh_node *node, uint16_t addr,
						uint32_t mod_id, int *status)
{
	struct mesh_model *mod;

	mod = find_model(node, addr, mod_id, status);
	if (!mod)
		return NULL;

	return mod->pub;
}

void mesh_model_free(void *data)
{
	struct mesh_model *mod = data;

	l_queue_destroy(mod->bindings, NULL);
	l_queue_destroy(mod->subs, NULL);
	l_queue_destroy(mod->virtuals, unref_virt);
	l_free(mod->pub);
	l_free(mod);
}

struct mesh_model *mesh_model_new(uint8_t ele_idx, uint32_t id)
{
	struct mesh_model *mod = l_new(struct mesh_model, 1);

	mod->id = id;
	mod->ele_idx = ele_idx;
	mod->virtuals = l_queue_new();
	return mod;
}

/* Internal models only */
static void restore_model_state(struct mesh_model *mod)
{
	const struct mesh_model_ops *cbs;
	const struct l_queue_entry *b;

	cbs = mod->cbs;
	if (!cbs)
		return;

	if (!l_queue_isempty(mod->bindings) && cbs->bind) {
		for (b = l_queue_get_entries(mod->bindings); b; b = b->next) {
			if (cbs->bind(L_PTR_TO_UINT(b->data), ACTION_ADD) !=
							MESH_STATUS_SUCCESS)
				break;
		}
	}

	if (mod->pub && cbs->pub)
		cbs->pub(mod->pub);

}

uint32_t mesh_model_get_model_id(const struct mesh_model *model)
{
	return model->id;
}

/* This registers an internal model, i.e. implemented within meshd */
bool mesh_model_register(struct mesh_node *node, uint8_t ele_idx,
					uint32_t mod_id,
					const struct mesh_model_ops *cbs,
					void *user_data)
{
	struct mesh_model *mod;
	int status;

	/* Internal models are always SIG models */
	mod_id = VENDOR_ID_MASK | mod_id;

	mod = get_model(node, ele_idx, mod_id, &status);
	if (!mod)
		return false;

	mod->cbs = cbs;
	mod->user_data = user_data;

	restore_model_state(mod);

	return true;
}

void mesh_model_app_key_delete(struct mesh_node *node, struct l_queue *models,
							uint16_t app_idx)
{
	const struct l_queue_entry *entry = l_queue_get_entries(models);

	for (; entry; entry = entry->next) {
		struct mesh_model *model = entry->data;

		model_unbind_idx(node, model, app_idx);
	}
}

int mesh_model_binding_del(struct mesh_node *node, uint16_t addr, uint32_t id,
						uint16_t app_idx)
{
	l_debug("0x%x, 0x%x, %d", addr, id, app_idx);
	return update_binding(node, addr, id, app_idx, true);
}

int mesh_model_binding_add(struct mesh_node *node, uint16_t addr, uint32_t id,
						uint16_t app_idx)
{
	l_debug("0x%x, 0x%x, %d", addr, id, app_idx);
	return update_binding(node, addr, id, app_idx, false);
}

int mesh_model_get_bindings(struct mesh_node *node, uint16_t addr, uint32_t id,
				uint8_t *buf, uint16_t buf_size, uint16_t *size)
{
	int status;
	struct mesh_model *mod;
	const struct l_queue_entry *entry;
	uint16_t n;
	uint32_t idx_pair;
	int i;

	mod = find_model(node, addr, id, &status);

	if (!mod) {
		*size = 0;
		return status;
	}

	entry = l_queue_get_entries(mod->bindings);
	n = 0;
	i = 0;
	idx_pair = 0;

	for (; entry; entry = entry->next) {
		uint16_t app_idx = (uint16_t) (L_PTR_TO_UINT(entry->data));

		if (!(i & 0x1)) {
			idx_pair = app_idx;
		} else {
			idx_pair <<= 12;
			idx_pair += app_idx;

			/* Unlikely, but check for overflow*/
			if ((n + 3) > buf_size) {
				l_warn("Binding list too large");
				goto done;
			}

			l_put_le32(idx_pair, buf);
			buf += 3;
			n += 3;
		}

		i++;
	}

	/* Process the last app key if present */
	if (i & 0x1 && ((n + 2) <= buf_size)) {
		l_put_le16(idx_pair, buf);
		n += 2;
	}

done:
	*size = n;
	return MESH_STATUS_SUCCESS;
}

int mesh_model_sub_get(struct mesh_node *node, uint16_t addr, uint32_t id,
			uint8_t *buf, uint16_t buf_size, uint16_t *size)
{
	int status;
	int16_t n;
	struct mesh_model *mod;
	const struct l_queue_entry *entry;

	mod = find_model(node, addr, id, &status);
	if (!mod)
		return status;

	entry = l_queue_get_entries(mod->subs);
	*size = 0;
	n = 0;

	for (; entry; entry = entry->next) {
		if ((n + 2) > buf_size)
			return MESH_STATUS_UNSPECIFIED_ERROR;

		l_put_le16((uint16_t) L_PTR_TO_UINT(entry->data), buf);
		buf += 2;
		n += 2;
	}

	entry = l_queue_get_entries(mod->virtuals);

	for (; entry; entry = entry->next) {
		struct mesh_virtual *virt = entry->data;

		if ((n + 2) > buf_size)
			return MESH_STATUS_UNSPECIFIED_ERROR;

		l_put_le16((uint16_t) L_PTR_TO_UINT(virt->addr), buf);
		buf += 2;
		n += 2;
	}

	*size = n;
	return MESH_STATUS_SUCCESS;
}

int mesh_model_sub_add(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *group, bool is_virt, uint16_t *dst)
{
	int status;
	struct mesh_model *mod;

	mod = find_model(node, addr, id, &status);
	if (!mod)
		return status;

	status = add_sub(node_get_net(node), mod, group, is_virt, dst);

	if (status != MESH_STATUS_SUCCESS)
		return status;

	if (!mod->cbs)
		/* External models */
		config_update_model_subscriptions(node, mod);

	return MESH_STATUS_SUCCESS;
}

int mesh_model_sub_ovr(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *group, bool is_virt, uint16_t *dst)
{
	int status;
	struct l_queue *virtuals, *subs;
	struct mesh_model *mod;

	mod = find_model(node, addr, id, &status);
	if (!mod)
		return status;

	subs = mod->subs;
	virtuals = mod->virtuals;
	mod->subs = l_queue_new();
	mod->virtuals = l_queue_new();

	if (!mod->subs || !mod->virtuals)
		return MESH_STATUS_INSUFF_RESOURCES;

	status = add_sub(node_get_net(node), mod, group, is_virt, dst);

	if (status != MESH_STATUS_SUCCESS) {
		/* Adding new group failed, so revert to old lists */
		l_queue_destroy(mod->subs, NULL);
		mod->subs = subs;
		l_queue_destroy(mod->virtuals, unref_virt);
		mod->virtuals = virtuals;
	} else {
		const struct l_queue_entry *entry;
		struct mesh_net *net = node_get_net(node);

		entry = l_queue_get_entries(subs);

		for (; entry; entry = entry->next)
			mesh_net_dst_unreg(net,
					(uint16_t) L_PTR_TO_UINT(entry->data));

		/* Destroy old lists */
		l_queue_destroy(subs, NULL);
		l_queue_destroy(virtuals, unref_virt);
	}

	if (!mod->cbs)
		/* External models */
		config_update_model_subscriptions(node, mod);

	return status;
}

int mesh_model_sub_del(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *group, bool is_virt, uint16_t *dst)
{
	int status;
	uint16_t grp;
	struct mesh_model *mod;

	mod = find_model(node, addr, id, &status);
	if (!mod)
		return status;

	if (is_virt) {
		struct mesh_virtual *virt;

		virt = l_queue_find(mod->virtuals, find_virt_by_label, group);
		if (virt) {
			l_queue_remove(mod->virtuals, virt);
			grp = virt->addr;
			unref_virt(virt);
		} else {
			if (!mesh_crypto_virtual_addr(group, &grp))
				return MESH_STATUS_STORAGE_FAIL;
		}
	} else {
		grp = l_get_le16(group);
	}

	*dst = grp;

	if (l_queue_remove(mod->subs, L_UINT_TO_PTR(grp)))
		mesh_net_dst_unreg(node_get_net(node), grp);

	if (!mod->cbs)
		/* External models */
		config_update_model_subscriptions(node, mod);

	return MESH_STATUS_SUCCESS;
}

int mesh_model_sub_del_all(struct mesh_node *node, uint16_t addr, uint32_t id)
{
	int status;
	struct mesh_model *mod;
	const struct l_queue_entry *entry;
	struct mesh_net *net = node_get_net(node);

	mod = find_model(node, addr, id, &status);
	if (!mod)
		return status;

	entry = l_queue_get_entries(mod->subs);

	for (; entry; entry = entry->next)
		mesh_net_dst_unreg(net, (uint16_t) L_PTR_TO_UINT(entry->data));

	l_queue_clear(mod->subs, NULL);
	l_queue_clear(mod->virtuals, unref_virt);

	if (!mod->cbs)
		/* External models */
		config_update_model_subscriptions(node, mod);

	return MESH_STATUS_SUCCESS;
}

struct mesh_model *mesh_model_setup(struct mesh_node *node, uint8_t ele_idx,
								void *data)
{
	struct mesh_config_model *db_mod = data;
	struct mesh_model *mod;
	struct mesh_net *net;
	struct mesh_config_pub *pub = db_mod->pub;
	uint32_t i;

	if (db_mod->num_bindings > MAX_BINDINGS) {
		l_warn("Binding list too long %u (max %u)",
					db_mod->num_bindings, MAX_BINDINGS);
		return NULL;
	}

	mod = mesh_model_new(ele_idx, db_mod->vendor ? db_mod->id :
						db_mod->id | VENDOR_ID_MASK);

	/* Implicitly bind config server model to device key */
	if (db_mod->id == CONFIG_SRV_MODEL) {

		if (ele_idx != PRIMARY_ELE_IDX)
			return NULL;

		l_queue_push_head(mod->bindings,
					L_UINT_TO_PTR(APP_IDX_DEV_LOCAL));
		return mod;
	}

	if (db_mod->id == CONFIG_CLI_MODEL) {
		l_queue_push_head(mod->bindings,
					L_UINT_TO_PTR(APP_IDX_DEV_LOCAL));
		return mod;
	}

	net = node_get_net(node);

	/* Add application key bindings if present */
	if (db_mod->bindings) {
		mod->bindings = l_queue_new();
		for (i = 0; i < db_mod->num_bindings; i++)
			model_bind_idx(node, mod, db_mod->bindings[i]);
	}

	/* Add publication if present */
	if (pub) {
		uint8_t retransmit = pub->count +
					((pub->interval / 50 - 1) << 3);
		if (pub->virt)
			set_virt_pub(mod, pub->virt_addr, pub->idx,
						pub->credential, pub->ttl,
						pub->period, retransmit);
		else if (!IS_UNASSIGNED(pub->addr))
			set_pub(mod, pub->addr, pub->idx, pub->credential,
				pub->ttl, pub->period, retransmit);
	}

	/* Add subscriptions if present */
	if (!db_mod->subs)
		return mod;

	for (i = 0; i < db_mod->num_subs; i++) {
		uint16_t group;
		uint8_t *src;

		/*
		 * To keep calculations for virtual label coherent,
		 * convert to little endian.
		 */
		l_put_le16(db_mod->subs[i].src.addr, &group);
		src = db_mod->subs[i].virt ? db_mod->subs[i].src.virt_addr :
			(uint8_t *) &group;

		if (add_sub(net, mod, src, db_mod->subs[i].virt, NULL) !=
							MESH_STATUS_SUCCESS) {
			mesh_model_free(mod);
			return NULL;
		}
	}

	return mod;
}

uint16_t mesh_model_opcode_set(uint32_t opcode, uint8_t *buf)
{
	if (opcode <= 0x7e) {
		buf[0] = opcode;
		return 1;
	}

	if (opcode >= 0x8000 && opcode <= 0xbfff) {
		l_put_be16(opcode, buf);
		return 2;
	}

	if (opcode >= 0xc00000 && opcode <= 0xffffff) {
		buf[0] = (opcode >> 16) & 0xff;
		l_put_be16(opcode, buf + 1);
		return 3;
	}

	l_debug("Illegal Opcode %x", opcode);
	return 0;
}

bool mesh_model_opcode_get(const uint8_t *buf, uint16_t size,
					uint32_t *opcode, uint16_t *n)
{
	if (!n || !opcode || size < 1)
		return false;

	switch (buf[0] & 0xc0) {
	case 0x00:
	case 0x40:
		/* RFU */
		if (buf[0] == 0x7f)
			return false;

		*n = 1;
		*opcode = buf[0];
		break;

	case 0x80:
		if (size < 2)
			return false;

		*n = 2;
		*opcode = l_get_be16(buf);
		break;

	case 0xc0:
		if (size < 3)
			return false;

		*n = 3;
		*opcode = l_get_be16(buf + 1);
		*opcode |= buf[0] << 16;
		break;

	default:
		print_packet("Bad", buf, size);
		return false;
	}

	return true;
}

void model_build_config(void *model, void *msg_builder)
{
	struct l_dbus_message_builder *builder = msg_builder;
	struct mesh_model *mod = model;
	uint16_t id;

	if (is_internal(mod->id))
		return;

	if (!l_queue_length(mod->subs) && !l_queue_length(mod->virtuals) &&
				!mod->pub && !l_queue_length(mod->bindings))
		return;

	l_dbus_message_builder_enter_struct(builder, "qa{sv}");

	/* Model id */
	id = mod->id & 0xffff;
	l_dbus_message_builder_append_basic(builder, 'q', &id);

	l_dbus_message_builder_enter_array(builder, "{sv}");

	/* For vendor models, add vendor id */
	if ((mod->id & VENDOR_ID_MASK) != VENDOR_ID_MASK) {
		uint16_t vendor = mod->id >> 16;
		dbus_append_dict_entry_basic(builder, "Vendor", "q", &vendor);
	}

	/* Model bindings, if present */
	if (l_queue_length(mod->bindings))
		append_dict_uint16_array(builder, mod->bindings, "Bindings");

	/* Model periodic publication interval, if present */
	if (mod->pub) {
		uint32_t period = pub_period_to_ms(mod->pub->period);
		dbus_append_dict_entry_basic(builder, "PublicationPeriod", "u",
								&period);
	}

	if (l_queue_length(mod->subs) || l_queue_length(mod->virtuals))
		append_dict_subs_array(builder, mod->subs, mod->virtuals,
							"Subscriptions");

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_struct(builder);
}

void mesh_model_init(void)
{
	mesh_virtuals = l_queue_new();
}

void mesh_model_cleanup(void)
{
	l_queue_destroy(mesh_virtuals, l_free);
	mesh_virtuals = NULL;
}
