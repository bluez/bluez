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

#include <sys/time.h>
#include <ell/ell.h>
#include <json-c/json.h>

#include "mesh/mesh-defs.h"

#include "mesh/mesh.h"
#include "mesh/crypto.h"
#include "mesh/node.h"
#include "mesh/mesh-db.h"
#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/cfgmod.h"
#include "mesh/storage.h"
#include "mesh/error.h"
#include "mesh/dbus.h"
#include "mesh/util.h"
#include "mesh/model.h"

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
	uint32_t id; /*Identifier of internally stored addr, min val 0x10000 */
	uint16_t ota;
	uint16_t ref_cnt;
	uint8_t addr[16];
};

/* These struct is used to pass lots of params to l_queue_foreach */
struct mod_forward {
	struct mesh_virtual *virt;
	const uint8_t *data;
	uint16_t src;
	uint16_t dst;
	uint16_t unicast;
	uint16_t idx;
	uint16_t size;
	uint8_t ttl;
	int8_t rssi;
	bool szmict;
	bool has_dst;
	bool done;
};

static struct l_queue *mesh_virtuals;

static uint32_t virt_id_next = VIRTUAL_BASE;
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

static bool find_virt_by_id(const void *a, const void *b)
{
	const struct mesh_virtual *virt = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return virt->id == id;
}

static bool find_virt_by_addr(const void *a, const void *b)
{
	const struct mesh_virtual *virt = a;
	const uint8_t *addr = b;

	return memcmp(virt->addr, addr, 16) == 0;
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
		*status = MESH_STATUS_INVALID_ADDRESS;
		return NULL;
	}

	model = l_queue_find(models, match_model_id, L_UINT_TO_PTR(id));

	if (status)
		*status = (model) ? MESH_STATUS_SUCCESS :
						MESH_STATUS_INVALID_MODEL;

	return model;
}

static struct mesh_model *find_model(struct mesh_node *node, uint16_t addr,
						uint32_t mod_id, int *fail)
{
	int ele_idx;

	ele_idx = node_get_element_idx(node, addr);

	if (ele_idx < 0) {
		if (fail)
			*fail = MESH_STATUS_INVALID_ADDRESS;
		return NULL;
	}

	return get_model(node, (uint8_t) ele_idx, mod_id, fail);
}

static uint32_t convert_pub_period_to_ms(uint8_t pub_period)
{
	int n;

	n = (pub_period & 0x3f);

	switch (pub_period >> 6) {
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
	if (l_dbus_message_builder_finalize(builder))
		l_dbus_send(dbus, msg);

	l_dbus_message_builder_destroy(builder);
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
	if (l_dbus_message_builder_finalize(builder))
		l_dbus_send(dbus, msg);

	l_dbus_message_builder_destroy(builder);
}

static void forward_model(void *a, void *b)
{
	struct mesh_model *mod = a;
	struct mod_forward *fwd = b;
	struct mesh_virtual *virt;
	uint32_t dst;
	bool result;

	l_debug("model %8.8x with idx %3.3x", mod->id, fwd->idx);
	if (fwd->idx != APP_IDX_DEV && !has_binding(mod->bindings, fwd->idx))
		return;

	dst = fwd->dst;
	if (dst == fwd->unicast || IS_ALL_NODES(dst))
		fwd->has_dst = true;
	else if (fwd->virt) {
		virt = l_queue_find(mod->virtuals, simple_match, fwd->virt);

		/* Check that this is not own publication */
		if (mod->pub && (virt && virt->id == mod->pub->addr))
			return;

		if (virt) {
			/*
			 * Map Virtual addresses to a usable namespace that
			 * prevents us for forwarding a false positive
			 * (multiple Virtual Addresses that map to the same
			 * u16 OTA addr)
			 */
			fwd->has_dst = true;
			dst = virt->id;
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
		result = mod->cbs->recv(fwd->src, dst, fwd->unicast, fwd->idx,
				fwd->data, fwd->size, fwd->ttl, mod->user_data);

	if (dst == fwd->unicast && result)
		fwd->done = true;
}

static int dev_packet_decrypt(struct mesh_node *node, const uint8_t *data,
				uint16_t size, bool szmict, uint16_t src,
				uint16_t dst, uint8_t key_id, uint32_t seq,
				uint32_t iv_idx, uint8_t *out)
{
	const uint8_t *dev_key;

	dev_key = node_get_device_key(node);
	if (!dev_key)
		return false;

	if (mesh_crypto_payload_decrypt(NULL, 0, data, size, szmict, src,
					dst, key_id, seq, iv_idx, out, dev_key))
		return APP_IDX_DEV;

	return -1;
}

static int virt_packet_decrypt(struct mesh_net *net, const uint8_t *data,
				uint16_t size, bool szmict, uint16_t src,
				uint16_t dst, uint8_t key_id, uint32_t seq,
				uint32_t iv_idx, uint8_t *out,
				struct mesh_virtual **decrypt_virt)
{
	const struct l_queue_entry *v;

	for (v = l_queue_get_entries(mesh_virtuals); v; v = v->next) {
		struct mesh_virtual *virt = v->data;
		int decrypt_idx;

		if (virt->ota != dst)
			continue;

		decrypt_idx = appkey_packet_decrypt(net, szmict, seq,
							iv_idx, src, dst,
							virt->addr, 16, key_id,
							data, size, out);

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
		l_debug("Duration 0.%zu seconds",
				tx_end.tv_usec - tx_start.tv_usec);
	} else {
		if (tx_start.tv_usec > tx_end.tv_usec)
			l_debug("Duration %zu.%zu seconds",
				tx_end.tv_sec - tx_start.tv_sec - 1,
				tx_end.tv_usec + 1000000 - tx_start.tv_usec);
		else
			l_debug("Duration %zu.%zu seconds",
					tx_end.tv_sec - tx_start.tv_sec,
					tx_end.tv_usec - tx_start.tv_usec);
	}
}

static bool pub_frnd_cred(struct mesh_node *node, uint16_t src, uint32_t mod_id)
{
	struct mesh_model *mod = find_model(node, src, mod_id, NULL);

	if (!mod || !mod->pub)
		return false;

	return (mod->pub->credential != 0);
}

static bool msg_send(struct mesh_node *node, bool credential, uint16_t src,
		uint32_t dst, uint8_t key_id, const uint8_t *key,
		uint8_t *aad, uint8_t ttl, const void *msg, uint16_t msg_len)
{
	bool ret = false;
	uint32_t iv_index, seq_num;
	uint8_t *out;
	bool szmic = false;
	uint16_t out_len = msg_len + sizeof(uint32_t);
	struct mesh_net *net = node_get_net(node);

	/* Use large MIC if it doesn't affect segmentation */
	if (msg_len > 11 && msg_len <= 376) {
		if ((out_len / 12) == ((out_len + 4) / 12)) {
			szmic = true;
			out_len = msg_len + sizeof(uint64_t);
		}
	}

	out = l_malloc(out_len);

	iv_index = mesh_net_get_iv_index(net);

	seq_num = mesh_net_get_seq_num(net);
	if (!mesh_crypto_payload_encrypt(aad, msg, out, msg_len,
				src, dst, key_id,
				seq_num, iv_index,
				szmic, key)) {
		l_error("Failed to Encrypt Payload");
		goto done;
	}

	/* print_packet("Encrypted with", key, 16); */

	ret = mesh_net_app_send(net, credential,
				src, dst, key_id, ttl,
				seq_num, iv_index,
				szmic,
				out, out_len,
				cmplt, NULL);
done:
	l_free(out);
	return ret;
}

static void remove_pub(struct mesh_node *node, struct mesh_model *mod)
{
	l_free(mod->pub);
	mod->pub = NULL;

	/* TODO: remove from storage */

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

	if (mod->pub && idx != mod->pub->idx)
		return;

	/* Remove model publication if the publication key is unbound */
	remove_pub(node, mod);
}

static void model_bind_idx(struct mesh_node *node, struct mesh_model *mod,
								uint16_t idx)
{
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
	int fail;
	struct mesh_model *mod;
	bool is_present;

	mod = find_model(node, addr, id, &fail);
	if (!mod) {
		l_debug("Model not found");
		return fail;
	}

	id = (id >= VENDOR_ID_MASK) ? (id & 0xffff) : id;

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

		if (!storage_model_bind(node, addr, id, app_idx, true))
			return MESH_STATUS_STORAGE_FAIL;

		return MESH_STATUS_SUCCESS;
	}

	if (l_queue_length(mod->bindings) >= MAX_BINDINGS)
		return MESH_STATUS_INSUFF_RESOURCES;

	if (!storage_model_bind(node, addr, id, app_idx, false))
		return MESH_STATUS_STORAGE_FAIL;

	model_bind_idx(node, mod, app_idx);

	return MESH_STATUS_SUCCESS;

}

static int set_pub(struct mesh_model *mod, const uint8_t *mod_addr,
			uint16_t idx, bool cred_flag, uint8_t ttl,
			uint8_t period, uint8_t retransmit, bool b_virt,
			uint16_t *dst)
{
	struct mesh_virtual *virt;
	uint16_t grp;

	if (dst) {
		if (b_virt)
			*dst = 0;
		else
			*dst = l_get_le16(mod_addr);
	}

	if (b_virt) {
		if (!mesh_crypto_virtual_addr(mod_addr, &grp))
			return MESH_STATUS_STORAGE_FAIL;
	}

	/* If old publication was Virtual, remove it */
	if (mod->pub && mod->pub->addr >= VIRTUAL_BASE) {
		virt = l_queue_find(mod->virtuals, find_virt_by_id,
						L_UINT_TO_PTR(mod->pub->addr));
		if (virt) {
			l_queue_remove(mod->virtuals, virt);
			unref_virt(virt);
		}
	}

	mod->pub = l_new(struct mesh_model_pub, 1);
	if (b_virt) {
		virt = l_queue_find(mesh_virtuals, find_virt_by_addr, mod_addr);
		if (!virt) {
			virt = l_new(struct mesh_virtual, 1);
			virt->id = virt_id_next++;
			virt->ota = grp;
			memcpy(virt->addr, mod_addr, sizeof(virt->addr));
			l_queue_push_head(mesh_virtuals, virt);
		} else {
			grp = virt->ota;
		}
		virt->ref_cnt++;
		l_queue_push_head(mod->virtuals, virt);
		mod->pub->addr = virt->id;
	} else {
		grp = l_get_le16(mod_addr);
		mod->pub->addr = grp;
	}

	if (dst)
		*dst = grp;

	if (IS_UNASSIGNED(grp) && mod->pub) {
		l_free(mod->pub);
		mod->pub = NULL;
		/* Remove publication if Pub Addr is 0x0000 */
	} else {
		if (!mod->pub)
			mod->pub = l_new(struct mesh_model_pub, 1);
		if (!mod->pub)
			return MESH_STATUS_STORAGE_FAIL;

		mod->pub->credential = cred_flag;
		mod->pub->idx = idx;
		mod->pub->ttl = ttl;
		mod->pub->period = period;
		mod->pub->retransmit = retransmit;
	}

	return MESH_STATUS_SUCCESS;
}

static int add_sub(struct mesh_net *net, struct mesh_model *mod,
			const uint8_t *group, bool b_virt, uint16_t *dst)
{
	struct mesh_virtual *virt;
	uint16_t grp;

	if (b_virt) {
		virt = l_queue_find(mesh_virtuals, find_virt_by_addr, group);
		if (!virt) {
			if (!mesh_crypto_virtual_addr(group, &grp))
				return MESH_STATUS_STORAGE_FAIL;

			virt = l_new(struct mesh_virtual, 1);
			virt->id = virt_id_next++;
			virt->ota = grp;
			memcpy(virt->addr, group, sizeof(virt->addr));
			if (!l_queue_push_head(mesh_virtuals, virt))
				return MESH_STATUS_STORAGE_FAIL;
		} else {
			grp = virt->ota;
		}
		virt->ref_cnt++;
		l_queue_push_head(mod->virtuals, virt);
	} else {
		grp = l_get_le16(group);
	}

	if (dst)
		*dst = grp;

	if (!mod->subs)
		mod->subs = l_queue_new();
	if (!mod->subs)
		return MESH_STATUS_STORAGE_FAIL;

	if (l_queue_find(mod->subs, simple_match, L_UINT_TO_PTR(grp)))
		/* Group already exists */
		return MESH_STATUS_SUCCESS;

	l_queue_push_tail(mod->subs, L_UINT_TO_PTR(grp));

	l_debug("Added %4.4x", grp);

	mesh_net_dst_reg(net, grp);

	return MESH_STATUS_SUCCESS;
}

static void send_msg_rcvd(struct mesh_node *node, uint8_t ele_idx, bool is_sub,
					uint16_t src, uint16_t key_idx,
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

	if (!l_dbus_message_builder_append_basic(builder, 'q', &src))
		goto error;

	if (!l_dbus_message_builder_append_basic(builder, 'q', &key_idx))
		goto error;

	if (!l_dbus_message_builder_append_basic(builder, 'b', &is_sub))
		goto error;

	if (!dbus_append_byte_array(builder, data, size))
		goto error;

	if (!l_dbus_message_builder_finalize(builder))
		goto error;

	l_dbus_send(dbus, msg);

error:
	l_dbus_message_builder_destroy(builder);
}

bool mesh_model_rx(struct mesh_node *node, bool szmict, uint32_t seq0,
			uint32_t seq, uint32_t iv_index, uint8_t ttl,
			uint16_t src, uint16_t dst, uint8_t key_id,
			const uint8_t *data, uint16_t size)
{
	uint8_t *clear_text;
	struct mod_forward forward = {
		.src = src,
		.dst = dst,
		.data = NULL,
		.size = size - (szmict ? 8 : 4),
		.ttl = ttl,
		.virt = NULL,
	};
	struct mesh_net *net = node_get_net(node);
	uint8_t num_ele;
	int decrypt_idx, i, ele_idx;
	uint16_t addr;
	struct mesh_virtual *decrypt_virt = NULL;
	bool result = false;
	bool is_subscription;

	l_debug("iv_index %8.8x key_id = %2.2x", iv_index, key_id);
	if (!dst)
		return false;

	ele_idx = node_get_element_idx(node, dst);

	if (dst < 0x8000 && ele_idx < 0)
		/* Unicast and not addressed to us */
		return false;

	clear_text = l_malloc(size);
	if (!clear_text)
		return false;

	forward.data = clear_text;

	/*
	 * The packet needs to be decoded by the correct key which
	 * is hinted by key_id, but is not necessarily definitive
	 */
	if (key_id == APP_ID_DEV || mesh_net_provisioner_mode_get(net))
		decrypt_idx = dev_packet_decrypt(node, data, size, szmict, src,
						dst, key_id, seq0, iv_index,
						clear_text);
	else if ((dst & 0xc000) == 0x8000)
		decrypt_idx = virt_packet_decrypt(net, data, size, szmict, src,
							dst, key_id, seq0,
							iv_index, clear_text,
							&decrypt_virt);
	else
		decrypt_idx = appkey_packet_decrypt(net, szmict, seq0,
							iv_index, src, dst,
							NULL, 0, key_id, data,
							size, clear_text);

	if (decrypt_idx < 0) {
		l_error("model.c - Failed to decrypt application payload");
		result = false;
		goto done;
	}

	/* print_packet("Clr Rx (pre-cache-check)", clear_text, size - 4); */

	if (key_id != APP_ID_DEV) {
		uint16_t crpl = node_get_crpl(node);

		if (appkey_msg_in_replay_cache(net, (uint16_t) decrypt_idx, src,
							crpl, seq, iv_index)) {
			result = true;
			goto done;
		}
	}

	print_packet("Clr Rx", clear_text, size - (szmict ? 8 : 4));

	forward.virt = decrypt_virt;
	forward.idx = decrypt_idx;
	num_ele = node_get_num_elements(node);
	addr = node_get_primary(node);

	if (!num_ele || IS_UNASSIGNED(addr))
		goto done;

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
		if (forward.has_dst && !forward.done)
			send_msg_rcvd(node, i, is_subscription, src,
					forward.idx, forward.size,
					forward.data);

		/*
		 * Either the message has been processed internally or
		 * has been passed on to an external model.
		 */
		result = forward.has_dst | forward.done;

		/* If the message was to unicast address, we are done */
		if (!is_subscription && ele_idx == i)
			break;
	}

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
	uint32_t target;
	uint8_t *aad = NULL;
	uint16_t dst;
	uint8_t key_id;
	const uint8_t *key;
	bool result;

	/* print_packet("Mod Tx", msg, msg_len); */

	if (!net || msg_len > 380)
		return MESH_ERROR_INVALID_ARGS;

	/* If SRC is 0, use the Primary Element */
	if (src == 0)
		src = mesh_net_get_address(net);

	mod = find_model(node, src, mod_id, NULL);
	if (!mod) {
		l_debug("model %x not found", mod_id);
		return MESH_ERROR_NOT_FOUND;
	}

	if (!mod->pub) {
		l_debug("publication doesn't exist (model %x)", mod_id);
		return MESH_ERROR_DOES_NOT_EXIST;
	}

	gettimeofday(&tx_start, NULL);

	target = mod->pub->addr;

	if (IS_UNASSIGNED(target))
		return false;

	if (target >= VIRTUAL_BASE) {
		struct mesh_virtual *virt = l_queue_find(mesh_virtuals,
				find_virt_by_id,
				L_UINT_TO_PTR(target));

		if (!virt)
			return false;

		aad = virt->addr;
		dst = virt->ota;
	} else {
		dst = target;
	}

	l_debug("publish dst=%x", dst);

	key = appkey_get_key(net, mod->pub->idx, &key_id);
	if (!key) {
		l_debug("no app key for (%x)", mod->pub->idx);
		return false;
	}

	l_debug("(%x) %p", mod->pub->idx, key);
	l_debug("key_id %x", key_id);

	result = msg_send(node, pub_frnd_cred(node, src, mod_id), src,
				dst, key_id, key, aad, ttl, msg, msg_len);

	return result ? MESH_ERROR_NONE : MESH_ERROR_FAILED;

}

bool mesh_model_send(struct mesh_node *node, uint16_t src, uint16_t target,
					uint16_t app_idx, uint8_t ttl,
					const void *msg, uint16_t msg_len)
{
	uint8_t key_id;
	const uint8_t *key;

	/* print_packet("Mod Tx", msg, msg_len); */

	/* If SRC is 0, use the Primary Element */
	if (src == 0)
		src = node_get_primary(node);

	gettimeofday(&tx_start, NULL);

	if (IS_UNASSIGNED(target))
		return false;

	if (app_idx == APP_IDX_DEV) {
		key = node_get_device_key(node);
		if (!key)
			return false;

		l_debug("(%x)", app_idx);
		key_id = APP_ID_DEV;
	} else {
		key = appkey_get_key(node_get_net(node), app_idx, &key_id);
		if (!key) {
			l_debug("no app key for (%x)", app_idx);
			return false;
		}

		l_debug("(%x) %p", app_idx, key);
		l_debug("key_id %x", key_id);
	}

	return msg_send(node, false, src, target, key_id, key, NULL, ttl,
			msg, msg_len);
}

int mesh_model_pub_set(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *mod_addr, uint16_t idx, bool cred_flag,
			uint8_t ttl, uint8_t period, uint8_t retransmit,
			bool b_virt, uint16_t *dst)
{
	int fail = MESH_STATUS_SUCCESS;
	int ele_idx;
	struct mesh_model *mod;
	int result;

	ele_idx = node_get_element_idx(node, addr);

	if (ele_idx < 0) {
		fail = MESH_STATUS_INVALID_ADDRESS;
		return false;
	}

	mod = get_model(node, (uint8_t) ele_idx, id, &fail);
	if (!mod)
		return fail;

	if (id == CONFIG_SRV_MODEL || id == CONFIG_CLI_MODEL)
		return MESH_STATUS_INVALID_PUB_PARAM;

	if (!appkey_have_key(node_get_net(node), idx))
		return MESH_STATUS_INVALID_APPKEY;

	result = set_pub(mod, mod_addr, idx, cred_flag, ttl, period, retransmit,
								b_virt, dst);

	if (result != MESH_STATUS_SUCCESS)
		return result;

	/* TODO: save to storage */

	/*
	 * If the publication address is set to unassigned address value,
	 * remove publication
	 */
	if (IS_UNASSIGNED(*dst))
		remove_pub(node, mod);

	/* Internal model, call registered callbacks */
	if (mod->cbs && mod->cbs->pub) {
		mod->cbs->pub(mod->pub);
		return MESH_STATUS_SUCCESS;
	}

	/* External model */
	config_update_model_pub_period(node, ele_idx, id,
					convert_pub_period_to_ms(period));

	return MESH_STATUS_SUCCESS;
}

struct mesh_model_pub *mesh_model_pub_get(struct mesh_node *node,
				 uint8_t ele_idx, uint32_t mod_id, int *status)
{
	struct mesh_model *mod;

	mod = get_model(node, ele_idx, mod_id, status);
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

static struct mesh_model *model_new(uint8_t ele_idx, uint32_t id)
{
	struct mesh_model *mod = l_new(struct mesh_model, 1);

	mod->id = id;
	mod->ele_idx = ele_idx;
	mod->virtuals = l_queue_new();
	return mod;
}

struct mesh_model *mesh_model_new(uint8_t ele_idx, uint16_t id)
{
	return model_new(ele_idx, id | VENDOR_ID_MASK);
}

struct mesh_model *mesh_model_vendor_new(uint8_t ele_idx, uint16_t vendor_id,
								uint16_t mod_id)
{
	uint32_t id = mod_id | (vendor_id << 16);

	return model_new(ele_idx, id);
}

/* Internal models only */
static void restore_model_state(struct mesh_model *mod)
{

	const struct mesh_model_ops *cbs;
	const struct l_queue_entry *b;

	cbs = mod->cbs;
	if (!cbs)
		return;

	if (l_queue_isempty(mod->bindings) || !mod->cbs->bind) {
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

	/* Internal models are always SIG models */
	mod_id = VENDOR_ID_MASK | mod_id;

	mod = get_model(node, ele_idx, mod_id, NULL);
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
	int fail;
	struct mesh_model *mod;
	const struct l_queue_entry *entry;
	uint16_t n;
	uint32_t idx_pair;
	int i;

	mod = find_model(node, addr, id, &fail);

	if (!mod) {
		*size = 0;
		return fail;
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
	int fail = MESH_STATUS_SUCCESS;
	int16_t n;
	struct mesh_model *mod;
	const struct l_queue_entry *entry;

	mod = find_model(node, addr, id, &fail);
	if (!mod)
		return fail;

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

	*size = n;
	return MESH_STATUS_SUCCESS;
}

int mesh_model_sub_add(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *group, bool b_virt, uint16_t *dst)
{
	int fail = MESH_STATUS_SUCCESS;
	int ele_idx = -1;
	struct mesh_model *mod;

	ele_idx = node_get_element_idx(node, addr);

	if (!node || ele_idx < 0) {
		fail = MESH_STATUS_INVALID_ADDRESS;
		return false;
	}

	mod = get_model(node, (uint8_t) ele_idx, id, &fail);
	if (!mod)
		return fail;

	return add_sub(node_get_net(node), mod, group, b_virt, dst);
	/* TODO: communicate to registered models that sub has changed */
}

int mesh_model_sub_ovr(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *group, bool b_virt, uint16_t *dst)
{
	int fail = MESH_STATUS_SUCCESS;
	struct l_queue *virtuals, *subs;
	struct mesh_virtual *virt;
	struct mesh_model *mod;

	mod = find_model(node, addr, id, &fail);
	if (!mod)
		return fail;

	subs = mod->subs;
	virtuals = mod->virtuals;
	mod->subs = l_queue_new();
	mod->virtuals = l_queue_new();

	if (!mod->subs || !mod->virtuals)
		return MESH_STATUS_INSUFF_RESOURCES;

	/*
	 * When overwriting the Subscription List,
	 * make sure any virtual Publication address is preserved
	 */
	if (mod->pub && mod->pub->addr >= VIRTUAL_BASE) {
		virt = l_queue_find(virtuals, find_virt_by_id,
				L_UINT_TO_PTR(mod->pub->addr));
		if (virt) {
			virt->ref_cnt++;
			l_queue_push_head(mod->virtuals, virt);
		}
	}

	fail = mesh_model_sub_add(node, addr, id, group, b_virt, dst);

	if (fail) {
		/* Adding new group failed, so revert to old list */
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

		l_queue_destroy(subs, NULL);
		l_queue_destroy(virtuals, unref_virt);
	}

	return fail;
}

int mesh_model_sub_del(struct mesh_node *node, uint16_t addr, uint32_t id,
			const uint8_t *group, bool b_virt, uint16_t *dst)
{
	int fail = MESH_STATUS_SUCCESS;
	uint16_t grp;
	struct mesh_model *mod;

	mod = find_model(node, addr, id, &fail);
	if (!mod)
		return fail;

	if (b_virt) {
		struct mesh_virtual *virt;

		virt = l_queue_find(mod->virtuals, find_virt_by_addr, group);
		if (virt) {
			l_queue_remove(mod->virtuals, virt);
			grp = virt->ota;
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

	return MESH_STATUS_SUCCESS;
}

int mesh_model_sub_del_all(struct mesh_node *node, uint16_t addr, uint32_t id)
{
	int fail = MESH_STATUS_SUCCESS;
	struct mesh_model *mod;
	const struct l_queue_entry *entry;
	struct mesh_net *net = node_get_net(node);

	mod = find_model(node, addr, id, &fail);
	if (!mod)
		return fail;

	entry = l_queue_get_entries(mod->subs);
	for (; entry; entry = entry->next)
		mesh_net_dst_unreg(net, (uint16_t) L_PTR_TO_UINT(entry->data));

	l_queue_destroy(mod->subs, NULL);
	l_queue_destroy(mod->virtuals, unref_virt);
	mod->virtuals = l_queue_new();

	return fail;
}

struct mesh_model *mesh_model_setup(struct mesh_node *node, uint8_t ele_idx,
								void *data)
{
	struct mesh_db_model *db_mod = data;
	struct mesh_model *mod;
	struct mesh_net *net;
	uint32_t i;

	if (db_mod->num_bindings > MAX_BINDINGS) {
		l_warn("Binding list too long %u (max %u)",
					db_mod->num_bindings, MAX_BINDINGS);
		return NULL;
	}

	mod = model_new(ele_idx, db_mod->vendor ? db_mod->id :
						db_mod->id | VENDOR_ID_MASK);

	/* Implicitly bind config server model to device key */
	if (db_mod->id == CONFIG_SRV_MODEL) {

		if (ele_idx != PRIMARY_ELE_IDX)
			return NULL;

		l_queue_push_head(mod->bindings, L_UINT_TO_PTR(APP_IDX_DEV));
		return mod;
	}

	if (db_mod->id == CONFIG_CLI_MODEL) {
		l_queue_push_head(mod->bindings, L_UINT_TO_PTR(APP_IDX_DEV));
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
	if (db_mod->pub) {
		struct mesh_db_pub *pub = db_mod->pub;
		uint8_t mod_addr[2];
		uint8_t *pub_addr;

		/* Add publication */
		l_put_le16(pub->addr, &mod_addr);
		pub_addr = pub->virt ? pub->virt_addr : (uint8_t *) &mod_addr;

		if (set_pub(mod, pub_addr, pub->idx, pub->credential, pub->ttl,
			pub->period, pub->retransmit, pub->virt, NULL) !=
							MESH_STATUS_SUCCESS) {
			mesh_model_free(mod);
			return NULL;
		}
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

void mesh_model_add_virtual(struct mesh_node *node, const uint8_t *v)
{
	struct mesh_virtual *virt = l_queue_find(mesh_virtuals,
						find_virt_by_addr, v);

	if (virt) {
		virt->ref_cnt++;
		return;
	}

	virt = l_new(struct mesh_virtual, 1);
	if (!virt)
		return;

	if (!mesh_crypto_virtual_addr(v, &virt->ota)) {
		l_free(virt);
		return; /* Storage Failure */
	}

	memcpy(virt->addr, v, 16);
	virt->ref_cnt++;
	virt->id = virt_id_next++;
	l_queue_push_head(mesh_virtuals, virt);
}

void mesh_model_del_virtual(struct mesh_node *node, uint32_t va24)
{
	struct mesh_virtual *virt = l_queue_remove_if(mesh_virtuals,
						find_virt_by_id,
						L_UINT_TO_PTR(va24));

	if (virt)
		unref_virt(virt);
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
		uint32_t period = convert_pub_period_to_ms(mod->pub->period);
		dbus_append_dict_entry_basic(builder, "PublicationPeriod", "u",
								&period);
	}

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
}
