// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2023-2024 NXP
 *
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include "lib/bluetooth.h"
#include "lib/uuid.h"

#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/shared/bass.h"

#define DBG(_bass, fmt, arg...) \
	bass_debug(_bass, "%s:%s() " fmt, __FILE__, __func__, ## arg)

struct bt_bass_db;

struct bt_bass_cb {
	unsigned int id;
	bt_bass_func_t attached;
	bt_bass_func_t detached;
	void *user_data;
};

struct bt_bcast_recv_state {
	struct bt_bass_db *bdb;
	struct gatt_db_attribute *attr;
	struct gatt_db_attribute *ccc;
};

struct bt_bass_db {
	struct gatt_db *db;
	bdaddr_t adapter_bdaddr;
	struct queue *bcast_srcs;
	struct gatt_db_attribute *service;
	struct gatt_db_attribute *bcast_audio_scan_cp;
	struct bt_bcast_recv_state *bcast_recv_states[NUM_BCAST_RECV_STATES];
};

struct bt_bass {
	int ref_count;
	struct bt_bass_db *ldb;
	struct bt_bass_db *rdb;
	struct bt_gatt_client *client;
	struct bt_att *att;

	struct queue *notify;

	bt_bass_debug_func_t debug_func;
	bt_bass_destroy_func_t debug_destroy;
	void *debug_data;

	struct queue *src_cbs;
	struct queue *cp_handlers;

	unsigned int disconn_id;

	void *user_data;
};

struct bt_bass_cp_handler {
	unsigned int id;
	bt_bass_cp_handler_func_t handler;
	bt_bass_destroy_func_t destroy;
	void *data;
};

/* BASS subgroup field of the Broadcast
 * Receive State characteristic
 */
struct bt_bass_subgroup_data {
	uint32_t bis_sync;
	uint32_t pending_bis_sync;
	uint8_t meta_len;
	uint8_t *meta;
};

/* BASS Broadcast Source structure */
struct bt_bcast_src {
	struct bt_bass *bass;
	struct gatt_db_attribute *attr;
	uint8_t id;
	uint8_t addr_type;
	bdaddr_t addr;
	uint8_t sid;
	uint32_t bid;
	uint8_t sync_state;
	uint8_t enc;
	uint8_t bad_code[BT_BASS_BCAST_CODE_SIZE];
	uint8_t num_subgroups;
	struct bt_bass_subgroup_data *subgroup_data;
};

typedef void (*bass_notify_t)(struct bt_bass *bass, uint16_t value_handle,
				const uint8_t *value, uint16_t length,
				void *user_data);

struct bt_bass_notify {
	unsigned int id;
	struct bt_bass *bass;
	bass_notify_t func;
	void *user_data;
};

static struct queue *bass_db;
static struct queue *bass_cbs;
static struct queue *sessions;

struct bt_bass_src_changed {
	unsigned int id;
	bt_bass_src_func_t cb;
	bt_bass_destroy_func_t destroy;
	void *data;
};

static void bass_bcast_src_free(void *data);

static void bass_debug(struct bt_bass *bass, const char *format, ...)
{
	va_list ap;

	if (!bass || !format || !bass->debug_func)
		return;

	va_start(ap, format);
	util_debug_va(bass->debug_func, bass->debug_data, format, ap);
	va_end(ap);
}

unsigned int bt_bass_cp_handler_register(struct bt_bass *bass,
				bt_bass_cp_handler_func_t handler,
				bt_bass_destroy_func_t destroy,
				void *user_data)
{
	struct bt_bass_cp_handler *cb;
	static unsigned int id;

	if (!bass)
		return 0;

	cb = new0(struct bt_bass_cp_handler, 1);
	cb->id = ++id ? id : ++id;
	cb->handler = handler;
	cb->destroy = destroy;
	cb->data = user_data;

	queue_push_tail(bass->cp_handlers, cb);

	return cb->id;
}

static void bass_cp_handler_free(void *data)
{
	struct bt_bass_cp_handler *cb = data;

	if (cb->destroy)
		cb->destroy(cb->data);

	free(cb);
}

static bool match_cb_id(const void *data, const void *match_data)
{
	const struct bt_bass_cp_handler *cb = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return (cb->id == id);
}

bool bt_bass_cp_handler_unregister(struct bt_bass *bass,
				unsigned int id)
{
	struct bt_bass_cp_handler *cb;

	if (!bass)
		return false;

	cb = queue_remove_if(bass->cp_handlers, match_cb_id,
						UINT_TO_PTR(id));
	if (!cb)
		return false;

	bass_cp_handler_free(cb);

	return true;
}

unsigned int bt_bass_src_register(struct bt_bass *bass, bt_bass_src_func_t cb,
				void *user_data, bt_bass_destroy_func_t destroy)
{
	struct bt_bass_src_changed *changed;
	static unsigned int id;

	if (!bass)
		return 0;

	changed = new0(struct bt_bass_src_changed, 1);
	if (!changed)
		return 0;

	changed->id = ++id ? id : ++id;
	changed->cb = cb;
	changed->destroy = destroy;
	changed->data = user_data;

	queue_push_tail(bass->src_cbs, changed);

	return changed->id;
}

static void bass_src_changed_free(void *data)
{
	struct bt_bass_src_changed *changed = data;

	if (changed->destroy)
		changed->destroy(changed->data);

	free(changed);
}

static bool match_src_changed_id(const void *data, const void *match_data)
{
	const struct bt_bass_src_changed *changed = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return (changed->id == id);
}

bool bt_bass_src_unregister(struct bt_bass *bass, unsigned int id)
{
	struct bt_bass_src_changed *changed;

	if (!bass)
		return false;

	changed = queue_remove_if(bass->src_cbs, match_src_changed_id,
						UINT_TO_PTR(id));
	if (!changed)
		return false;

	bass_src_changed_free(changed);

	return true;
}

static int bass_build_bcast_src(struct bt_bcast_src *bcast_src,
				const uint8_t *value, uint16_t length)
{
	struct bt_bass_subgroup_data *subgroup_data = NULL;
	uint8_t id;
	uint8_t addr_type;
	uint8_t *addr;
	uint8_t sid;
	uint32_t bid;
	uint8_t pa_sync_state;
	uint8_t enc;
	uint8_t *bad_code = NULL;
	uint8_t num_subgroups;
	uint32_t bis_sync_state;
	uint8_t meta_len;
	uint8_t *meta;

	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len = length,
	};

	/* Extract all fields from notification */
	if (!util_iov_pull_u8(&iov, &id)) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (!util_iov_pull_u8(&iov, &addr_type)) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	addr = util_iov_pull_mem(&iov, sizeof(bdaddr_t));
	if (!addr) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (!util_iov_pull_u8(&iov, &sid)) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (!util_iov_pull_le24(&iov, &bid)) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (!util_iov_pull_u8(&iov, &pa_sync_state)) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (!util_iov_pull_u8(&iov, &enc)) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (enc == BT_BASS_BIG_ENC_STATE_BAD_CODE) {
		bad_code = util_iov_pull_mem(&iov, BT_BASS_BCAST_CODE_SIZE);
		if (!bad_code) {
			DBG(bcast_src->bass, "Unable to parse "
				"Broadcast Receive State");
			return -1;
		}
	}

	if (!util_iov_pull_u8(&iov, &num_subgroups)) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (num_subgroups == 0)
		goto done;

	subgroup_data = new0(struct bt_bass_subgroup_data, 1);
	if (!subgroup_data) {
		DBG(bcast_src->bass, "Unable to allocate memory");
		return -1;
	}

	for (int i = 0; i < num_subgroups; i++) {
		if (!util_iov_pull_le32(&iov, &bis_sync_state)) {
			DBG(bcast_src->bass, "Unable to parse "
				"Broadcast Receive State");

			for (int j = 0; j < i; j++)
				free(subgroup_data[j].meta);

			free(subgroup_data);
			return -1;
		}

		subgroup_data[i].bis_sync = bis_sync_state;

		if (!util_iov_pull_u8(&iov, &meta_len)) {
			DBG(bcast_src->bass, "Unable to parse "
				"Broadcast Receive State");

			for (int j = 0; j < i; j++)
				free(subgroup_data[j].meta);

			free(subgroup_data);
			return -1;
		}

		subgroup_data[i].meta_len = meta_len;

		if (meta_len == 0)
			continue;

		subgroup_data[i].meta = malloc0(meta_len);
		if (!subgroup_data[i].meta) {
			DBG(bcast_src->bass, "Unable to allocate memory");

			for (int j = 0; j < i; j++)
				free(subgroup_data[j].meta);

			free(subgroup_data);
			return -1;
		}

		meta = util_iov_pull_mem(&iov, meta_len);
		if (!meta) {
			DBG(bcast_src->bass, "Unable to parse "
				"Broadcast Receive State");

			for (int j = 0; j < i; j++)
				free(subgroup_data[j].meta);

			free(subgroup_data);
			return -1;
		}

		memcpy(subgroup_data[i].meta, meta, meta_len);
	}

done:
	/*
	 * If no errors occurred, copy extracted fields into
	 * the broadcast source structure
	 */
	if (bcast_src->subgroup_data) {
		for (int i = 0; i < bcast_src->num_subgroups; i++)
			free(bcast_src->subgroup_data[i].meta);

		free(bcast_src->subgroup_data);
	}

	bcast_src->id = id;
	bcast_src->addr_type = addr_type;
	memcpy(&bcast_src->addr, addr, sizeof(bdaddr_t));
	bcast_src->sid = sid;
	bcast_src->bid = bid;
	bcast_src->sync_state = pa_sync_state;
	bcast_src->enc = enc;

	if (enc == BT_BASS_BIG_ENC_STATE_BAD_CODE)
		memcpy(bcast_src->bad_code, bad_code, BT_BASS_BCAST_CODE_SIZE);
	else
		memset(bcast_src->bad_code, 0, BT_BASS_BCAST_CODE_SIZE);

	bcast_src->num_subgroups = num_subgroups;

	bcast_src->subgroup_data = subgroup_data;

	return 0;
}

static struct iovec *bass_parse_bcast_src(struct bt_bcast_src *bcast_src)
{
	size_t len = 0;
	uint8_t *notif = NULL;
	struct iovec *iov;

	if (!bcast_src)
		return NULL;

	len = BT_BASS_BCAST_SRC_LEN + bcast_src->num_subgroups *
			BT_BASS_BCAST_SRC_SUBGROUP_LEN;

	if (bcast_src->enc == BT_BASS_BIG_ENC_STATE_BAD_CODE)
		len += BT_BASS_BCAST_CODE_SIZE;

	for (size_t i = 0; i < bcast_src->num_subgroups; i++) {
		/* Add length for subgroup metadata */
		len += bcast_src->subgroup_data[i].meta_len;
	}

	notif = malloc0(len);
	if (!notif)
		return NULL;

	iov = new0(struct iovec, 1);
	if (!iov) {
		free(notif);
		return NULL;
	}

	iov->iov_base = notif;
	iov->iov_len = 0;

	util_iov_push_u8(iov, bcast_src->id);
	util_iov_push_u8(iov, bcast_src->addr_type);
	util_iov_push_mem(iov, sizeof(bcast_src->addr),
			&bcast_src->addr);
	util_iov_push_u8(iov, bcast_src->sid);
	util_iov_push_le24(iov, bcast_src->bid);
	util_iov_push_u8(iov, bcast_src->sync_state);
	util_iov_push_u8(iov, bcast_src->enc);

	if (bcast_src->enc == BT_BASS_BIG_ENC_STATE_BAD_CODE)
		util_iov_push_mem(iov, sizeof(bcast_src->bad_code),
					bcast_src->bad_code);

	util_iov_push_u8(iov, bcast_src->num_subgroups);

	for (size_t i = 0; i < bcast_src->num_subgroups; i++) {
		/* Add subgroup bis_sync */
		util_iov_push_le32(iov, bcast_src->subgroup_data[i].bis_sync);

		/* Add subgroup meta_len */
		util_iov_push_u8(iov, bcast_src->subgroup_data[i].meta_len);

		/* Add subgroup metadata */
		if (bcast_src->subgroup_data[i].meta_len > 0)
			util_iov_push_mem(iov,
				bcast_src->subgroup_data[i].meta_len,
				bcast_src->subgroup_data[i].meta);
	}

	return iov;
}

static bool bass_check_cp_command_subgroup_data_len(uint8_t num_subgroups,
							struct iovec *iov)
{
	uint32_t bis_sync_state;
	uint8_t *meta_len;
	uint8_t *meta;

	for (int i = 0; i < num_subgroups; i++) {
		if (!util_iov_pull_le32(iov, &bis_sync_state))
			return false;

		meta_len = util_iov_pull_mem(iov,
					sizeof(*meta_len));
		if (!meta_len)
			return false;

		meta = util_iov_pull_mem(iov, *meta_len);
		if (!meta)
			return false;
	}

	return true;
}

static bool bass_check_cp_command_len(const uint8_t *value, size_t len)
{
	struct bt_bass_bcast_audio_scan_cp_hdr *hdr;
	union {
		struct bt_bass_add_src_params *add_src_params;
		struct bt_bass_mod_src_params *mod_src_params;
		struct bt_bass_set_bcast_code_params *set_bcast_code_params;
		struct bt_bass_remove_src_params *remove_src_params;
	} params;

	struct iovec iov = {
		.iov_base = (void *)value,
		.iov_len = len,
	};

	/* Get command header */
	hdr = util_iov_pull_mem(&iov, sizeof(*hdr));

	if (!hdr)
		return false;

	/* Check command parameters */
	switch (hdr->op) {
	case BT_BASS_ADD_SRC:
		params.add_src_params = util_iov_pull_mem(&iov,
						sizeof(*params.add_src_params));
		if (!params.add_src_params)
			return false;

		if (!bass_check_cp_command_subgroup_data_len(
					params.add_src_params->num_subgroups,
					&iov))
			return false;

		break;
	case BT_BASS_MOD_SRC:
		params.mod_src_params = util_iov_pull_mem(&iov,
						sizeof(*params.mod_src_params));
		if (!params.mod_src_params)
			return false;

		if (!bass_check_cp_command_subgroup_data_len(
					params.mod_src_params->num_subgroups,
					&iov))
			return false;

		break;
	case BT_BASS_SET_BCAST_CODE:
		params.set_bcast_code_params = util_iov_pull_mem(&iov,
					sizeof(*params.set_bcast_code_params));
		if (!params.set_bcast_code_params)
			return false;

		break;
	case BT_BASS_REMOVE_SRC:
		params.remove_src_params = util_iov_pull_mem(&iov,
					sizeof(*params.remove_src_params));
		if (!params.remove_src_params)
			return false;

		break;
	case BT_BASS_REMOTE_SCAN_STOPPED:
	case BT_BASS_REMOTE_SCAN_STARTED:
		break;
	default:
		return true;
	}

	if (iov.iov_len > 0)
		return false;

	return true;
}

static void bass_handle_remote_scan_stopped_op(struct bt_bass *bass,
					struct gatt_db_attribute *attrib,
					uint8_t opcode,
					unsigned int id,
					struct iovec *iov,
					struct bt_att *att)
{
	gatt_db_attribute_write_result(attrib, id, 0x00);
}

static void bass_handle_remote_scan_started_op(struct bt_bass *bass,
					struct gatt_db_attribute *attrib,
					uint8_t opcode,
					unsigned int id,
					struct iovec *iov,
					struct bt_att *att)
{
	gatt_db_attribute_write_result(attrib, id, 0x00);
}

static bool bass_src_id_match(const void *data, const void *match_data)
{
	const struct bt_bcast_src *bcast_src = data;
	const uint8_t *id = match_data;

	return (bcast_src->id == *id);
}

static void bass_handle_remove_src_op(struct bt_bass *bass,
					struct gatt_db_attribute *attrib,
					uint8_t opcode,
					unsigned int id,
					struct iovec *iov,
					struct bt_att *att)
{
	struct bt_bass_remove_src_params *params;
	struct bt_bcast_src *bcast_src;
	int att_err = 0;

	/* Get Remove Source command parameters */
	params = util_iov_pull_mem(iov, sizeof(*params));

	bcast_src = queue_find(bass->ldb->bcast_srcs,
						bass_src_id_match,
						&params->id);

	if (!bcast_src) {
		/* No source matches the written source id */
		att_err = BT_BASS_ERROR_INVALID_SOURCE_ID;
		goto done;
	}

	/* Ignore if server is synchronized to the PA
	 * of the source
	 */
	if (bcast_src->sync_state == BT_BASS_SYNCHRONIZED_TO_PA)
		goto done;

	/* Ignore if server is synchronized to any BIS
	 * of the source
	 */
	for (int i = 0; i < bcast_src->num_subgroups; i++)
		if (bcast_src->subgroup_data[i].bis_sync)
			goto done;

	/* Accept the operation and remove source */
	queue_remove(bass->ldb->bcast_srcs, bcast_src);
	gatt_db_attribute_notify(bcast_src->attr, NULL, 0, att);
	bass_bcast_src_free(bcast_src);

done:
	gatt_db_attribute_write_result(attrib, id,
			att_err);
}

static bool bass_src_attr_match(const void *data, const void *match_data)
{
	const struct bt_bcast_src *bcast_src = data;
	const struct gatt_db_attribute *attr = match_data;

	return (bcast_src->attr == attr);
}

static bool bass_trigger_big_sync(struct bt_bcast_src *bcast_src)
{
	for (int i = 0; i < bcast_src->num_subgroups; i++) {
		struct bt_bass_subgroup_data *data =
				&bcast_src->subgroup_data[i];

		if (data->pending_bis_sync &&
			data->pending_bis_sync != BIS_SYNC_NO_PREF)
			return true;
	}

	return false;
}

static struct bt_bass *bass_get_session(struct bt_att *att, struct gatt_db *db,
		const bdaddr_t *adapter_bdaddr)
{
	const struct queue_entry *entry;
	struct bt_bass *bass;

	for (entry = queue_get_entries(sessions); entry; entry = entry->next) {
		struct bt_bass *bass = entry->data;

		if (att == bt_bass_get_att(bass))
			return bass;
	}

	bass = bt_bass_new(db, NULL, adapter_bdaddr);
	bass->att = att;

	bt_bass_attach(bass, NULL);

	return bass;
}

static bool bass_validate_bis_sync(uint8_t num_subgroups,
				struct iovec *iov)
{
	uint32_t bis_sync_state;
	uint32_t bitmask = 0U;
	uint8_t *meta_len;

	for (int i = 0; i < num_subgroups; i++) {
		util_iov_pull_le32(iov, &bis_sync_state);

		if (bis_sync_state != BIS_SYNC_NO_PREF)
			for (int bis_idx = 0; bis_idx < 31; bis_idx++) {
				if (bis_sync_state & (1 << bis_idx)) {
					if (bitmask & (1 << bis_idx))
						return false;

					bitmask |= (1 << bis_idx);
				}
			}

		meta_len = util_iov_pull_mem(iov,
					sizeof(*meta_len));
		util_iov_pull_mem(iov, *meta_len);
	}

	return true;
}

static bool bass_validate_add_src_params(uint8_t *value, size_t len)
{
	struct bt_bass_add_src_params *params;
	struct iovec iov = {
		.iov_base = (void *)value,
		.iov_len = len,
	};

	params = util_iov_pull_mem(&iov, sizeof(*params));

	if (params->pa_sync > PA_SYNC_NO_PAST)
		return false;

	if (params->addr_type > 0x01)
		return false;

	if (params->sid > 0x0F)
		return false;

	if (!bass_validate_bis_sync(params->num_subgroups,
					&iov))
		return false;

	return true;
}

static void bass_handle_add_src_op(struct bt_bass *bass,
					struct gatt_db_attribute *attrib,
					uint8_t opcode,
					unsigned int id,
					struct iovec *iov,
					struct bt_att *att)
{
	struct bt_bcast_src *bcast_src, *src;
	uint8_t src_id = 0;
	struct gatt_db_attribute *attr;
	uint8_t pa_sync;
	struct iovec *notif;
	int ret;
	const struct queue_entry *entry;
	struct bt_bass_add_src_params *params;

	gatt_db_attribute_write_result(attrib, id, 0x00);

	/* Ignore operation if parameters are invalid */
	if (!bass_validate_add_src_params(iov->iov_base, iov->iov_len))
		return;

	/* Allocate a new broadcast source */
	bcast_src = new0(struct bt_bcast_src, 1);
	if (!bcast_src) {
		DBG(bass, "Unable to allocate broadcast source");
		return;
	}

	queue_push_tail(bass->ldb->bcast_srcs, bcast_src);

	bcast_src->bass = bass;

	/* Map the source to a Broadcast Receive State characteristic */
	for (int i = 0; i < NUM_BCAST_RECV_STATES; i++) {
		src = queue_find(bass->ldb->bcast_srcs,
				bass_src_attr_match,
				bass->ldb->bcast_recv_states[i]->attr);
		if (!src) {
			/* Found and empty characteristic */
			bcast_src->attr =
				bass->ldb->bcast_recv_states[i]->attr;
			break;
		}
	}

	if (!bcast_src->attr) {
		/* If no empty characteristic has been found,
		 * overwrite an existing one
		 */
		attr = bass->ldb->bcast_recv_states[0]->attr;

		src = queue_find(bass->ldb->bcast_srcs,
					bass_src_attr_match,
					attr);

		queue_remove(bass->ldb->bcast_srcs, src);
		bass_bcast_src_free(src);
		bcast_src->attr = attr;
	}

	/* Allocate source id */
	while (true) {
		src = queue_find(bass->ldb->bcast_srcs,
				bass_src_id_match,
				&src_id);
		if (!src)
			break;

		if (src_id == 0xFF) {
			DBG(bass, "Unable to allocate broadcast source id");
			return;
		}

		src_id++;
	}

	bcast_src->id = src_id;

	params = util_iov_pull_mem(iov, sizeof(*params));

	/* Populate broadcast source fields from command parameters */
	bcast_src->addr_type = params->addr_type;

	/* Convert to three-value type */
	if (bcast_src->addr_type)
		params->addr_type = BDADDR_LE_RANDOM;
	else
		params->addr_type = BDADDR_LE_PUBLIC;

	bacpy(&bcast_src->addr, &params->addr);
	bcast_src->sid = params->sid;
	memcpy(&bcast_src->bid, params->bid, sizeof(params->bid));

	pa_sync = params->pa_sync;
	bcast_src->sync_state = BT_BASS_NOT_SYNCHRONIZED_TO_PA;

	bcast_src->num_subgroups = params->num_subgroups;

	if (!bcast_src->num_subgroups)
		return;

	bcast_src->subgroup_data = new0(struct bt_bass_subgroup_data,
					bcast_src->num_subgroups);
	if (!bcast_src->subgroup_data) {
		DBG(bass, "Unable to allocate subgroup data");
		goto err;
	}

	for (int i = 0; i < bcast_src->num_subgroups; i++) {
		struct bt_bass_subgroup_data *data =
				&bcast_src->subgroup_data[i];

		util_iov_pull_le32(iov, &data->pending_bis_sync);

		data->meta_len = *(uint8_t *)util_iov_pull_mem(iov,
						sizeof(data->meta_len));
		if (!data->meta_len)
			continue;

		data->meta = malloc0(data->meta_len);
		if (!data->meta)
			goto err;

		memcpy(data->meta, (uint8_t *)util_iov_pull_mem(iov,
					data->meta_len), data->meta_len);
	}

	if (pa_sync != PA_SYNC_NO_SYNC) {
		for (entry = queue_get_entries(bass->cp_handlers); entry;
							entry = entry->next) {
			struct bt_bass_cp_handler *cb = entry->data;

			if (cb->handler) {
				ret = cb->handler(bcast_src,
						BT_BASS_ADD_SRC,
						params, cb->data);
				if (ret)
					goto err;
			}
		}
	} else {
		for (int i = 0; i < bcast_src->num_subgroups; i++)
			bcast_src->subgroup_data[i].bis_sync =
				bcast_src->subgroup_data[i].pending_bis_sync;

		notif = bass_parse_bcast_src(bcast_src);
		if (!notif)
			return;

		gatt_db_attribute_notify(bcast_src->attr,
				notif->iov_base, notif->iov_len,
				bt_bass_get_att(bcast_src->bass));

		free(notif->iov_base);
		free(notif);
	}

	return;

err:
	if (bcast_src->subgroup_data) {
		for (int i = 0; i < bcast_src->num_subgroups; i++)
			free(bcast_src->subgroup_data[i].meta);

		free(bcast_src->subgroup_data);
	}

	free(bcast_src);
}

static void bass_handle_set_bcast_code_op(struct bt_bass *bass,
					struct gatt_db_attribute *attrib,
					uint8_t opcode,
					unsigned int id,
					struct iovec *iov,
					struct bt_att *att)
{
	struct bt_bass_set_bcast_code_params *params;
	struct bt_bcast_src *bcast_src;
	struct iovec *notif;
	const struct queue_entry *entry;
	int ret;

	/* Get Set Broadcast Code command parameters */
	params = util_iov_pull_mem(iov, sizeof(*params));

	bcast_src = queue_find(bass->ldb->bcast_srcs,
						bass_src_id_match,
						&params->id);

	if (!bcast_src) {
		/* No source matches the written source id */
		gatt_db_attribute_write_result(attrib, id,
					BT_BASS_ERROR_INVALID_SOURCE_ID);

		return;
	}

	gatt_db_attribute_write_result(attrib, id, 0x00);

	for (entry = queue_get_entries(bass->cp_handlers); entry;
						entry = entry->next) {
		struct bt_bass_cp_handler *cb = entry->data;

		if (cb->handler) {
			ret = cb->handler(bcast_src,
					BT_BASS_SET_BCAST_CODE,
					params, cb->data);
			if (ret)
				DBG(bass, "Unable to handle Set "
						"Broadcast Code operation");
		}
	}

	if (!bass_trigger_big_sync(bcast_src)) {
		bcast_src->enc = BT_BASS_BIG_ENC_STATE_DEC;

		notif = bass_parse_bcast_src(bcast_src);
		if (!notif)
			return;

		gatt_db_attribute_notify(bcast_src->attr,
					notif->iov_base, notif->iov_len,
					bt_bass_get_att(bcast_src->bass));

		free(notif->iov_base);
		free(notif);
	}
}

static void bass_handle_mod_src_op(struct bt_bass *bass,
					struct gatt_db_attribute *attrib,
					uint8_t opcode,
					unsigned int id,
					struct iovec *iov,
					struct bt_att *att)
{
	struct bt_bcast_src *bcast_src;
	struct bt_bass_mod_src_params *params;
	const struct queue_entry *entry;
	struct iovec *notif;
	bool updated = false;
	int err = 0;

	/* Get Modify Source command parameters */
	params = util_iov_pull_mem(iov, sizeof(*params));

	bcast_src = queue_find(bass->ldb->bcast_srcs,
						bass_src_id_match,
						&params->id);

	if (!bcast_src) {
		/* No source matches the written source id */
		gatt_db_attribute_write_result(attrib, id,
					BT_BASS_ERROR_INVALID_SOURCE_ID);

		return;
	}

	gatt_db_attribute_write_result(attrib, id, 0x00);

	for (int i = 0; i < bcast_src->num_subgroups; i++) {
		struct bt_bass_subgroup_data *data =
				&bcast_src->subgroup_data[i];
		uint8_t meta_len;
		uint8_t *meta;

		if (!util_iov_pull_le32(iov, &data->pending_bis_sync))
			return;

		if (!util_iov_pull_u8(iov, &meta_len))
			return;

		/* Check for metadata updates and notify peers */
		if (meta_len != data->meta_len) {
			updated = true;
			data->meta_len = meta_len;

			free(data->meta);
			data->meta = malloc0(data->meta_len);
			if (!data->meta)
				return;
		}

		if (!data->meta_len)
			continue;

		meta = (uint8_t *)util_iov_pull_mem(iov, meta_len);
		if (!meta)
			return;

		if (memcmp(meta, data->meta, data->meta_len)) {
			updated = true;
			memcpy(data->meta, meta, data->meta_len);
		}
	}

	for (entry = queue_get_entries(bass->cp_handlers); entry;
						entry = entry->next) {
		struct bt_bass_cp_handler *cb = entry->data;

		if (cb->handler) {
			err = cb->handler(bcast_src,
					BT_BASS_MOD_SRC,
					params, cb->data);
			if (err)
				DBG(bass, "Unable to handle Modify Source "
						"operation");
		}
	}

	if (!updated)
		return;

	notif = bass_parse_bcast_src(bcast_src);
	if (!notif)
		return;

	gatt_db_attribute_notify(bcast_src->attr,
			notif->iov_base, notif->iov_len,
			bt_bass_get_att(bcast_src->bass));

	free(notif->iov_base);
	free(notif);
}

#define BASS_OP(_str, _op, _size, _func) \
	{ \
		.str = _str, \
		.op = _op, \
		.size = _size, \
		.func = _func, \
	}

struct bass_op_handler {
	const char	*str;
	uint8_t		op;
	size_t		size;
	void		(*func)(struct bt_bass *bass,
				struct gatt_db_attribute *attrib,
				uint8_t opcode,
				unsigned int id,
				struct iovec *iov,
				struct bt_att *att);
} bass_handlers[] = {
	BASS_OP("Remote Scan Stopped", BT_BASS_REMOTE_SCAN_STOPPED,
		0, bass_handle_remote_scan_stopped_op),
	BASS_OP("Remote Scan Started", BT_BASS_REMOTE_SCAN_STARTED,
		0, bass_handle_remote_scan_started_op),
	BASS_OP("Remove Source", BT_BASS_REMOVE_SRC,
		0, bass_handle_remove_src_op),
	BASS_OP("Add Source", BT_BASS_ADD_SRC,
		0, bass_handle_add_src_op),
	BASS_OP("Set Broadcast Code", BT_BASS_SET_BCAST_CODE,
		0, bass_handle_set_bcast_code_op),
	BASS_OP("Modify Source", BT_BASS_MOD_SRC,
		0, bass_handle_mod_src_op),
	{}
};

static void bass_bcast_audio_scan_cp_write(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				const uint8_t *value, size_t len,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_bass_db *bdb = user_data;
	struct bt_bass_bcast_audio_scan_cp_hdr *hdr;
	struct bass_op_handler *handler;
	struct bt_bass *bass = bass_get_session(att, bdb->db,
						&bdb->adapter_bdaddr);
	struct iovec iov = {
		.iov_base = (void *)value,
		.iov_len = len,
	};

	/* Validate written command length */
	if (!bass_check_cp_command_len(value, len)) {
		gatt_db_attribute_write_result(attrib, id,
				BT_ERROR_WRITE_REQUEST_REJECTED);
		return;
	}

	/* Get command header */
	hdr = util_iov_pull_mem(&iov, sizeof(*hdr));

	/* Call the appropriate opcode handler */
	for (handler = bass_handlers; handler && handler->str; handler++) {
		if (handler->op == hdr->op) {
			handler->func(bass, attrib, opcode, id, &iov, att);
			return;
		}
	}

	/* Send error response if unsupported opcode was written */
	gatt_db_attribute_write_result(attrib, id,
			BT_BASS_ERROR_OPCODE_NOT_SUPPORTED);
}

static bool bass_src_match_attrib(const void *data, const void *match_data)
{
	const struct bt_bcast_src *bcast_src = data;
	const struct gatt_db_attribute *attr = match_data;

	return (bcast_src->attr == attr);
}

static void bass_bcast_recv_state_read(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bt_bass_db *bdb = user_data;
	struct iovec *rsp;
	struct bt_bcast_src *bcast_src;
	struct bt_bass *bass = bass_get_session(att, bdb->db,
						&bdb->adapter_bdaddr);

	bcast_src = queue_find(bass->ldb->bcast_srcs,
					bass_src_match_attrib,
					attrib);

	if (!bcast_src) {
		gatt_db_attribute_read_result(attrib, id, 0, NULL,
							0);
		return;
	}

	/* Build read response */
	rsp = bass_parse_bcast_src(bcast_src);

	if (!rsp) {
		gatt_db_attribute_read_result(attrib, id,
					BT_ATT_ERROR_UNLIKELY,
					NULL, 0);
		return;
	}

	gatt_db_attribute_read_result(attrib, id, 0, rsp->iov_base,
						rsp->iov_len);

	free(rsp->iov_base);
	free(rsp);
}

static void bcast_recv_new(struct bt_bass_db *bdb, int i)
{
	struct bt_bcast_recv_state *bcast_recv_state;
	bt_uuid_t uuid;

	if (!bdb)
		return;

	bcast_recv_state = new0(struct bt_bcast_recv_state, 1);
	bcast_recv_state->bdb = bdb;

	bt_uuid16_create(&uuid, BCAST_RECV_STATE_UUID);
	bcast_recv_state->attr =
		gatt_db_service_add_characteristic(bdb->service, &uuid,
				BT_ATT_PERM_READ,
				BT_GATT_CHRC_PROP_READ |
				BT_GATT_CHRC_PROP_NOTIFY,
				bass_bcast_recv_state_read, NULL,
				bdb);

	bcast_recv_state->ccc = gatt_db_service_add_ccc(bdb->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bdb->bcast_recv_states[i] = bcast_recv_state;
}

static void bass_new(struct bt_bass_db *bdb)
{
	bt_uuid_t uuid;
	int i;

	/* Populate DB with BASS attributes */
	bt_uuid16_create(&uuid, BASS_UUID);
	bdb->service = gatt_db_add_service(bdb->db, &uuid, true,
					3 + (NUM_BCAST_RECV_STATES * 3));

	for (i = 0; i < NUM_BCAST_RECV_STATES; i++)
		bcast_recv_new(bdb, i);

	bt_uuid16_create(&uuid, BCAST_AUDIO_SCAN_CP_UUID);
	bdb->bcast_audio_scan_cp =
		gatt_db_service_add_characteristic(bdb->service,
				&uuid,
				BT_ATT_PERM_WRITE,
				BT_GATT_CHRC_PROP_WRITE |
				BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
				NULL, bass_bcast_audio_scan_cp_write,
				bdb);

	gatt_db_service_set_active(bdb->service, true);
}

static void bass_bcast_src_free(void *data)
{
	struct bt_bcast_src *bcast_src = data;

	if (!bcast_src)
		return;

	for (int i = 0; i < bcast_src->num_subgroups; i++)
		free(bcast_src->subgroup_data[i].meta);

	free(bcast_src->subgroup_data);

	free(bcast_src);
}

static void read_bcast_recv_state(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_bcast_src *bcast_src = user_data;

	if (!success) {
		DBG(bcast_src->bass, "Unable to read "
			"Broadcast Receive State: error 0x%02x",
			att_ecode);
		return;
	}

	if (length == 0) {
		queue_remove(bcast_src->bass->rdb->bcast_srcs, bcast_src);
		bass_bcast_src_free(bcast_src);
		return;
	}

	if (bass_build_bcast_src(bcast_src, value, length)) {
		queue_remove(bcast_src->bass->rdb->bcast_srcs, bcast_src);
		bass_bcast_src_free(bcast_src);
		return;
	}
}

static void notify_src_changed(void *data, void *user_data)
{
	struct bt_bass_src_changed *changed = data;
	struct bt_bcast_src *bcast_src = user_data;
	uint32_t bis_sync = 0;

	for (uint8_t i = 0; i < bcast_src->num_subgroups; i++) {
		struct bt_bass_subgroup_data *sgrp =
				&bcast_src->subgroup_data[i];

		/* Create a bitmask of all BIS indices that the peer has
		 * synchronized with.
		 */
		bis_sync |= sgrp->bis_sync;
	}

	if (changed->cb)
		changed->cb(bcast_src->id, bcast_src->bid, bcast_src->enc,
					bis_sync, changed->data);
}

static void bcast_recv_state_notify(struct bt_bass *bass, uint16_t value_handle,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct gatt_db_attribute *attr = user_data;
	struct bt_bcast_src *bcast_src;
	bool new_src = false;

	bcast_src = queue_find(bass->rdb->bcast_srcs,
					bass_src_match_attrib, attr);
	if (!bcast_src) {
		new_src = true;
		bcast_src = new0(struct bt_bcast_src, 1);

		if (!bcast_src) {
			DBG(bass, "Failed to allocate "
				"memory for broadcast source");
			return;
		}

		bcast_src->bass = bass;
		bcast_src->attr = attr;
	}

	if (bass_build_bcast_src(bcast_src, value, length)
							&& new_src) {
		bass_bcast_src_free(bcast_src);
		return;
	}

	if (new_src)
		queue_push_tail(bass->rdb->bcast_srcs, bcast_src);

	/* Notify the update in the Broadcast Receive State characteristic
	 * to all drivers that registered a callback.
	 */
	queue_foreach(bass->src_cbs, notify_src_changed, bcast_src);
}

static void bass_register(uint16_t att_ecode, void *user_data)
{
	struct bt_bass_notify *notify = user_data;

	if (att_ecode)
		DBG(notify->bass, "BASS register notify failed: 0x%04x",
					att_ecode);
}

static void bass_notify(uint16_t value_handle, const uint8_t *value,
				uint16_t length, void *user_data)
{
	struct bt_bass_notify *notify = user_data;

	if (notify->func)
		notify->func(notify->bass, value_handle, value, length,
						notify->user_data);
}

static void bass_notify_destroy(void *data)
{
	struct bt_bass_notify *notify = data;
	struct bt_bass *bass = notify->bass;

	if (queue_remove_if(bass->notify, NULL, notify))
		free(notify);
}

static unsigned int bass_register_notify(struct bt_bass *bass,
					uint16_t value_handle,
					bass_notify_t func,
					void *user_data)
{
	struct bt_bass_notify *notify;

	notify = new0(struct bt_bass_notify, 1);
	notify->bass = bass;
	notify->func = func;
	notify->user_data = user_data;

	notify->id = bt_gatt_client_register_notify(bass->client,
						value_handle, bass_register,
						bass_notify, notify,
						bass_notify_destroy);
	if (!notify->id) {
		DBG(bass, "Unable to register for notifications");
		free(notify);
		return 0;
	}

	queue_push_tail(bass->notify, notify);

	return notify->id;
}

static void foreach_bass_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_bass *bass = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid, uuid_bcast_audio_scan_cp, uuid_bcast_recv_state;

	/* Get attribute value handle and uuid */
	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
						NULL, NULL, &uuid))
		return;

	bt_uuid16_create(&uuid_bcast_audio_scan_cp, BCAST_AUDIO_SCAN_CP_UUID);
	bt_uuid16_create(&uuid_bcast_recv_state, BCAST_RECV_STATE_UUID);

	if (!bt_uuid_cmp(&uuid, &uuid_bcast_audio_scan_cp)) {
		/* Found Broadcast Audio Scan Control Point characteristic */
		bass->rdb->bcast_audio_scan_cp = attr;

		DBG(bass, "Broadcast Audio Scan Control Point "
			"found: handle 0x%04x", value_handle);
	}

	if (!bt_uuid_cmp(&uuid, &uuid_bcast_recv_state)) {
		/* Found Broadcast Receive State characteristic */
		struct bt_bcast_src *bcast_src =
				queue_find(bass->rdb->bcast_srcs,
						bass_src_match_attrib, attr);

		if (!bcast_src) {
			bcast_src = new0(struct bt_bcast_src, 1);

			if (bcast_src == NULL) {
				DBG(bass, "Failed to allocate "
					"memory for broadcast source");
				return;
			}

			bcast_src->bass = bass;
			bcast_src->attr = attr;

			queue_push_tail(bass->rdb->bcast_srcs, bcast_src);
		}

		bt_gatt_client_read_value(bass->client, value_handle,
						read_bcast_recv_state,
						bcast_src, NULL);

		(void)bass_register_notify(bass, value_handle,
						bcast_recv_state_notify,
						attr);

		DBG(bass, "Broadcast Receive State found: handle 0x%04x",
							value_handle);
	}
}

static void foreach_bass_service(struct gatt_db_attribute *attr,
						void *user_data)
{
	struct bt_bass *bass = user_data;

	/* Store BASS service reference */
	bass->rdb->service = attr;

	/* Handle BASS characteristics */
	gatt_db_service_foreach_char(attr, foreach_bass_char, bass);
}

static void bass_attached(void *data, void *user_data)
{
	struct bt_bass_cb *cb = data;
	struct bt_bass *bass = user_data;

	cb->attached(bass, cb->user_data);
}

static void bass_disconnected(int err, void *user_data)
{
	struct bt_bass *bass = user_data;

	bass->disconn_id = 0;

	DBG(bass, "bass %p disconnected err %d", bass, err);

	bt_bass_detach(bass);
}

static void bass_attach_att(struct bt_bass *bass, struct bt_att *att)
{
	if (bass->disconn_id) {
		if (att == bt_bass_get_att(bass))
			return;

		bt_att_unregister_disconnect(bt_bass_get_att(bass),
							bass->disconn_id);
	}

	bass->disconn_id = bt_att_register_disconnect(att,
							bass_disconnected,
							bass, NULL);
}

bool bt_bass_attach(struct bt_bass *bass, struct bt_gatt_client *client)
{
	bt_uuid_t uuid;

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, bass);

	queue_foreach(bass_cbs, bass_attached, bass);

	if (!client) {
		if (bass->att)
			bass_attach_att(bass, bass->att);
		return true;
	}

	if (bass->client)
		return false;

	bass->client = bt_gatt_client_clone(client);
	if (!bass->client)
		return false;

	bass_attach_att(bass, bt_gatt_client_get_att(client));

	bt_uuid16_create(&uuid, BASS_UUID);
	gatt_db_foreach_service(bass->rdb->db, &uuid, foreach_bass_service,
				bass);

	return true;
}

bool bt_bass_set_att(struct bt_bass *bass, struct bt_att *att)
{
	if (!bass)
		return false;

	bass->att = att;
	return true;
}

static void bass_detached(void *data, void *user_data)
{
	struct bt_bass_cb *cb = data;
	struct bt_bass *bass = user_data;

	cb->detached(bass, cb->user_data);
}

void bt_bass_detach(struct bt_bass *bass)
{
	struct  bt_att *att;

	if (!queue_remove(sessions, bass))
		return;

	if (bass->client)
		att = bt_gatt_client_get_att(bass->client);
	else
		att = bass->att;

	bt_att_unregister_disconnect(att, bass->disconn_id);

	bt_gatt_client_unref(bass->client);
	bass->client = NULL;

	bass->att = NULL;

	queue_foreach(bass_cbs, bass_detached, bass);
}

static void bass_db_free(void *data)
{
	struct bt_bass_db *bdb = data;

	if (!bdb)
		return;

	gatt_db_unref(bdb->db);
	queue_destroy(bdb->bcast_srcs, bass_bcast_src_free);

	free(bdb);
}

static void bass_free(void *data)
{
	struct bt_bass *bass = data;

	bt_bass_detach(bass);
	bass_db_free(bass->rdb);
	queue_destroy(bass->notify, NULL);
	queue_destroy(bass->src_cbs, bass_src_changed_free);
	queue_destroy(bass->cp_handlers, bass_cp_handler_free);

	free(bass);
}

void bt_bass_unref(struct bt_bass *bass)
{
	if (!bass)
		return;

	if (__sync_sub_and_fetch(&bass->ref_count, 1))
		return;

	bass_free(bass);
}

bool bt_bass_set_user_data(struct bt_bass *bass, void *user_data)
{
	if (!bass)
		return false;

	bass->user_data = user_data;

	return true;
}

static struct bt_bass_db *bass_db_new(struct gatt_db *db,
				const bdaddr_t *adapter_bdaddr)
{
	struct bt_bass_db *bdb;

	if (!db)
		return NULL;

	bdb = new0(struct bt_bass_db, 1);
	bdb->db = gatt_db_ref(db);
	bacpy(&bdb->adapter_bdaddr, adapter_bdaddr);
	bdb->bcast_srcs = queue_new();

	if (!bass_db)
		bass_db = queue_new();

	bass_new(bdb);

	queue_push_tail(bass_db, bdb);

	return bdb;
}

static bool bass_db_match(const void *data, const void *match_data)
{
	const struct bt_bass_db *bdb = data;
	const struct gatt_db *db = match_data;

	return (bdb->db == db);
}

static struct bt_bass_db *bass_get_db(struct gatt_db *db,
				const bdaddr_t *adapter_bdaddr)
{
	struct bt_bass_db *bdb;

	bdb = queue_find(bass_db, bass_db_match, db);
	if (bdb)
		return bdb;

	return bass_db_new(db, adapter_bdaddr);
}

static struct bt_bass *bt_bass_ref(struct bt_bass *bass)
{
	if (!bass)
		return NULL;

	__sync_fetch_and_add(&bass->ref_count, 1);

	return bass;
}

struct bt_bass *bt_bass_new(struct gatt_db *ldb, struct gatt_db *rdb,
				const bdaddr_t *adapter_bdaddr)
{
	struct bt_bass *bass;
	struct bt_bass_db *db;

	if (!ldb)
		return NULL;

	db = bass_get_db(ldb, adapter_bdaddr);
	if (!db)
		return NULL;

	bass = new0(struct bt_bass, 1);
	bass->ldb = db;
	bass->notify = queue_new();
	bass->src_cbs = queue_new();
	bass->cp_handlers = queue_new();

	if (!rdb)
		goto done;

	db = new0(struct bt_bass_db, 1);
	db->db = gatt_db_ref(rdb);
	db->bcast_srcs = queue_new();

	bass->rdb = db;

done:
	bt_bass_ref(bass);

	return bass;
}

struct bt_att *bt_bass_get_att(struct bt_bass *bass)
{
	if (!bass)
		return NULL;

	if (bass->att)
		return bass->att;

	return bt_gatt_client_get_att(bass->client);
}

struct bt_gatt_client *bt_bass_get_client(struct bt_bass *bass)
{
	if (!bass)
		return NULL;

	return bass->client;
}

bool bt_bass_set_debug(struct bt_bass *bass, bt_bass_debug_func_t func,
			void *user_data, bt_bass_destroy_func_t destroy)
{
	if (!bass)
		return false;

	if (bass->debug_destroy)
		bass->debug_destroy(bass->debug_data);

	bass->debug_func = func;
	bass->debug_destroy = destroy;
	bass->debug_data = user_data;

	return true;
}

unsigned int bt_bass_register(bt_bass_func_t attached, bt_bass_func_t detached,
							void *user_data)
{
	struct bt_bass_cb *cb;
	static unsigned int id;

	if (!attached && !detached)
		return 0;

	if (!bass_cbs)
		bass_cbs = queue_new();

	cb = new0(struct bt_bass_cb, 1);
	cb->id = ++id ? id : ++id;
	cb->attached = attached;
	cb->detached = detached;
	cb->user_data = user_data;

	queue_push_tail(bass_cbs, cb);

	return cb->id;
}
static bool match_id(const void *data, const void *match_data)
{
	const struct bt_bass_cb *cb = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return (cb->id == id);
}

bool bt_bass_unregister(unsigned int id)
{
	struct bt_bass_cb *cb;

	cb = queue_remove_if(bass_cbs, match_id, UINT_TO_PTR(id));
	if (!cb)
		return false;

	free(cb);

	return true;
}

void bt_bass_add_db(struct gatt_db *db, const bdaddr_t *adapter_bdaddr)
{
	bass_db_new(db, adapter_bdaddr);
}

int bt_bass_send(struct bt_bass *bass,
		struct bt_bass_bcast_audio_scan_cp_hdr *hdr,
		struct iovec *params)
{
	struct iovec req = {0};
	uint16_t handle;
	int err = 0;

	if (!bass || !bass->client || !bass->rdb)
		return -EINVAL;

	DBG(bass, "bass %p", bass);

	req.iov_base = malloc0(sizeof(*hdr) + params->iov_len);
	if (!req.iov_base)
		return -EINVAL;

	util_iov_push_mem(&req, sizeof(*hdr), hdr);
	util_iov_push_mem(&req, params->iov_len, params->iov_base);

	if (!gatt_db_attribute_get_char_data(bass->rdb->bcast_audio_scan_cp,
			NULL, &handle, NULL, NULL, NULL)) {
		err = -EINVAL;
		goto done;
	}

	if (!bt_gatt_client_write_without_response(bass->client, handle,
					false, req.iov_base, req.iov_len))
		err = -EINVAL;

done:
	free(req.iov_base);

	return err;
}

static void bt_bass_notify_all(struct gatt_db_attribute *attr,
						struct iovec *iov)
{
	const struct queue_entry *entry;

	for (entry = queue_get_entries(sessions); entry; entry = entry->next) {
		struct bt_bass *bass = entry->data;

		gatt_db_attribute_notify(attr, iov->iov_base,
			iov->iov_len, bt_bass_get_att(bass));
	}
}

int bt_bass_set_pa_sync(struct bt_bcast_src *bcast_src, uint8_t sync_state)
{
	struct iovec *iov;

	if (!bcast_src)
		return -EINVAL;

	bcast_src->sync_state = sync_state;

	iov = bass_parse_bcast_src(bcast_src);
	if (!iov)
		return -ENOMEM;

	bt_bass_notify_all(bcast_src->attr, iov);

	free(iov->iov_base);
	free(iov);

	return 0;
}

int bt_bass_get_pa_sync(struct bt_bcast_src *bcast_src, uint8_t *sync_state)
{
	if (!bcast_src)
		return -EINVAL;

	*sync_state = bcast_src->sync_state;

	return 0;
}

int bt_bass_set_bis_sync(struct bt_bcast_src *bcast_src, uint8_t bis)
{
	struct iovec *iov;

	for (uint8_t i = 0; i < bcast_src->num_subgroups; i++) {
		struct bt_bass_subgroup_data *sgrp =
				&bcast_src->subgroup_data[i];
		uint32_t bitmask = 1 << (bis - 1);

		if (sgrp->pending_bis_sync & bitmask) {
			sgrp->bis_sync |= bitmask;

			if (bcast_src->enc == BT_BASS_BIG_ENC_STATE_BCODE_REQ)
				bcast_src->enc = BT_BASS_BIG_ENC_STATE_DEC;

			iov = bass_parse_bcast_src(bcast_src);
			if (!iov)
				return -ENOMEM;

			bt_bass_notify_all(bcast_src->attr, iov);

			free(iov->iov_base);
			free(iov);
		}
	}

	return 0;
}

int bt_bass_clear_bis_sync(struct bt_bcast_src *bcast_src, uint8_t bis)
{
	struct iovec *iov;

	for (uint8_t i = 0; i < bcast_src->num_subgroups; i++) {
		struct bt_bass_subgroup_data *sgrp =
				&bcast_src->subgroup_data[i];
		uint32_t bitmask = 1 << (bis - 1);

		if (sgrp->bis_sync & bitmask) {
			sgrp->bis_sync &= ~bitmask;

			iov = bass_parse_bcast_src(bcast_src);
			if (!iov)
				return -ENOMEM;

			bt_bass_notify_all(bcast_src->attr, iov);

			free(iov->iov_base);
			free(iov);
		}
	}

	return 0;
}

bool bt_bass_check_bis(struct bt_bcast_src *bcast_src, uint8_t bis)
{
	for (uint8_t i = 0; i < bcast_src->num_subgroups; i++) {
		struct bt_bass_subgroup_data *sgrp =
				&bcast_src->subgroup_data[i];
		uint32_t bitmask = 1 << (bis - 1);

		if (sgrp->pending_bis_sync & bitmask)
			return true;
	}

	return false;
}

int bt_bass_set_enc(struct bt_bcast_src *bcast_src, uint8_t enc)
{
	struct iovec *iov;

	if (!bcast_src)
		return -EINVAL;

	if (bcast_src->enc == enc)
		return 0;

	bcast_src->enc = enc;

	iov = bass_parse_bcast_src(bcast_src);
	if (!iov)
		return -ENOMEM;

	bt_bass_notify_all(bcast_src->attr, iov);

	free(iov->iov_base);
	free(iov);

	return 0;
}
