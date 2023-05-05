// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2023 NXP
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

	void *user_data;
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

static void bass_debug(struct bt_bass *bass, const char *format, ...)
{
	va_list ap;

	if (!bass || !format || !bass->debug_func)
		return;

	va_start(ap, format);
	util_debug_va(bass->debug_func, bass->debug_data, format, ap);
	va_end(ap);
}

static int
bass_build_bcast_src_from_notif(struct bt_bcast_src *bcast_src,
				const uint8_t *value, uint16_t length)
{
	struct bt_bass_subgroup_data *subgroup_data = NULL;
	uint8_t *id;
	uint8_t *addr_type;
	uint8_t *addr;
	uint8_t *sid;
	uint32_t bid;
	uint8_t *pa_sync_state;
	uint8_t *enc;
	uint8_t *bad_code = NULL;
	uint8_t *num_subgroups;
	uint32_t bis_sync_state;
	uint8_t *meta_len;
	uint8_t *meta;

	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len = length,
	};

	/* Extract all fields from notification */
	id = util_iov_pull_mem(&iov, sizeof(*id));
	if (!id) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	addr_type = util_iov_pull_mem(&iov, sizeof(*addr_type));
	if (!addr_type) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	addr = util_iov_pull_mem(&iov, sizeof(bdaddr_t));
	if (!addr) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	sid = util_iov_pull_mem(&iov, sizeof(*sid));
	if (!sid) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (!util_iov_pull_le24(&iov, &bid)) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	pa_sync_state = util_iov_pull_mem(&iov, sizeof(*pa_sync_state));
	if (!pa_sync_state) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	enc = util_iov_pull_mem(&iov, sizeof(*enc));
	if (!enc) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (*enc == BT_BASS_BIG_ENC_STATE_BAD_CODE) {
		bad_code = util_iov_pull_mem(&iov, BT_BASS_BCAST_CODE_SIZE);
		if (!bad_code) {
			DBG(bcast_src->bass, "Unable to parse "
				"Broadcast Receive State");
			return -1;
		}
	}

	num_subgroups = util_iov_pull_mem(&iov, sizeof(*num_subgroups));
	if (!num_subgroups) {
		DBG(bcast_src->bass, "Unable to parse Broadcast Receive State");
		return -1;
	}

	if (*num_subgroups == 0)
		goto done;

	subgroup_data = malloc((*num_subgroups) * sizeof(*subgroup_data));
	if (!subgroup_data) {
		DBG(bcast_src->bass, "Unable to allocate memory");
		return -1;
	}

	memset(subgroup_data, 0, (*num_subgroups) * sizeof(*subgroup_data));

	for (int i = 0; i < *num_subgroups; i++) {
		if (!util_iov_pull_le32(&iov, &bis_sync_state)) {
			DBG(bcast_src->bass, "Unable to parse "
				"Broadcast Receive State");

			for (int j = 0; j < i; j++)
				free(subgroup_data[j].meta);

			free(subgroup_data);
			return -1;
		}

		subgroup_data[i].bis_sync = bis_sync_state;

		meta_len = util_iov_pull_mem(&iov, sizeof(*meta_len));
		if (!meta_len) {
			DBG(bcast_src->bass, "Unable to parse "
				"Broadcast Receive State");

			for (int j = 0; j < i; j++)
				free(subgroup_data[j].meta);

			free(subgroup_data);
			return -1;
		}

		subgroup_data[i].meta_len = *meta_len;

		if (*meta_len == 0)
			continue;

		subgroup_data[i].meta = malloc(*meta_len);
		if (!subgroup_data[i].meta) {
			DBG(bcast_src->bass, "Unable to allocate memory");

			for (int j = 0; j < i; j++)
				free(subgroup_data[j].meta);

			free(subgroup_data);
			return -1;
		}

		meta = util_iov_pull_mem(&iov, *meta_len);
		if (!meta) {
			DBG(bcast_src->bass, "Unable to parse "
				"Broadcast Receive State");

			for (int j = 0; j < i; j++)
				free(subgroup_data[j].meta);

			free(subgroup_data);
			return -1;
		}

		memcpy(subgroup_data[i].meta, meta, *meta_len);
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

	bcast_src->id = *id;
	bcast_src->addr_type = *addr_type;
	memcpy(&bcast_src->addr, addr, sizeof(bdaddr_t));
	bcast_src->sid = *sid;
	bcast_src->bid = bid;
	bcast_src->sync_state = *pa_sync_state;
	bcast_src->enc = *enc;

	if (*enc == BT_BASS_BIG_ENC_STATE_BAD_CODE)
		memcpy(bcast_src->bad_code, bad_code, BT_BASS_BCAST_CODE_SIZE);
	else
		memset(bcast_src->bad_code, 0, BT_BASS_BCAST_CODE_SIZE);

	bcast_src->num_subgroups = *num_subgroups;

	bcast_src->subgroup_data = subgroup_data;

	return 0;
}

static int
bass_build_bcast_src_from_read_rsp(struct bt_bcast_src *bcast_src,
				const uint8_t *value, uint16_t length)
{
	return bass_build_bcast_src_from_notif(bcast_src, value, length);
}

static uint8_t *bass_build_notif_from_bcast_src(struct bt_bcast_src *bcast_src,
							size_t *notif_len)
{
	size_t len = 0;
	uint8_t *notif = NULL;
	struct iovec iov;

	*notif_len = 0;

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

	notif = malloc(len);
	if (!notif)
		return NULL;

	memset(notif, 0, len);

	iov.iov_base = notif;
	iov.iov_len = 0;

	util_iov_push_mem(&iov, sizeof(bcast_src->id),
			&bcast_src->id);
	util_iov_push_mem(&iov, sizeof(bcast_src->addr_type),
			&bcast_src->addr_type);
	util_iov_push_mem(&iov, sizeof(bcast_src->addr),
			&bcast_src->addr);
	util_iov_push_mem(&iov, sizeof(bcast_src->sid),
			&bcast_src->sid);
	util_iov_push_le24(&iov, bcast_src->bid);
	util_iov_push_mem(&iov, sizeof(bcast_src->sync_state),
			&bcast_src->sync_state);
	util_iov_push_mem(&iov, sizeof(bcast_src->enc),
			&bcast_src->enc);

	if (bcast_src->enc == BT_BASS_BIG_ENC_STATE_BAD_CODE)
		util_iov_push_mem(&iov, sizeof(bcast_src->bad_code),
					bcast_src->bad_code);

	util_iov_push_mem(&iov, sizeof(bcast_src->num_subgroups),
				&bcast_src->num_subgroups);

	for (size_t i = 0; i < bcast_src->num_subgroups; i++) {
		/* Add subgroup bis_sync */
		util_iov_push_le32(&iov, bcast_src->subgroup_data[i].bis_sync);

		/* Add subgroup meta_len */
		util_iov_push_mem(&iov,
			sizeof(bcast_src->subgroup_data[i].meta_len),
			&bcast_src->subgroup_data[i].meta_len);

		/* Add subgroup metadata */
		if (bcast_src->subgroup_data[i].meta_len > 0)
			util_iov_push_mem(&iov,
				bcast_src->subgroup_data[i].meta_len,
				bcast_src->subgroup_data[i].meta);
	}

	*notif_len = len;
	return notif;
}

static uint8_t *
bass_build_read_rsp_from_bcast_src(struct bt_bcast_src *bcast_src,
					size_t *rsp_len)
{
	return bass_build_notif_from_bcast_src(bcast_src, rsp_len);
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

static bool bass_check_cp_command_len(struct iovec *iov)
{
	struct bt_bass_bcast_audio_scan_cp_hdr *hdr;
	union {
		struct bt_bass_add_src_params *add_src_params;
		struct bt_bass_mod_src_params *mod_src_params;
		struct bt_bass_set_bcast_code_params *set_bcast_code_params;
		struct bt_bass_remove_src_params *remove_src_params;
	} params;

	/* Get command header */
	hdr = util_iov_pull_mem(iov, sizeof(*hdr));

	if (!hdr)
		return false;

	/* Check command parameters */
	switch (hdr->op) {
	case BT_BASS_ADD_SRC:
		params.add_src_params = util_iov_pull_mem(iov,
						sizeof(*params.add_src_params));
		if (!params.add_src_params)
			return false;

		if (!bass_check_cp_command_subgroup_data_len(
					params.add_src_params->num_subgroups,
					iov))
			return false;

		break;
	case BT_BASS_MOD_SRC:
		params.mod_src_params = util_iov_pull_mem(iov,
						sizeof(*params.mod_src_params));
		if (!params.mod_src_params)
			return false;

		if (!bass_check_cp_command_subgroup_data_len(
					params.mod_src_params->num_subgroups,
					iov))
			return false;

		break;
	case BT_BASS_SET_BCAST_CODE:
		params.set_bcast_code_params = util_iov_pull_mem(iov,
					sizeof(*params.set_bcast_code_params));
		if (!params.set_bcast_code_params)
			return false;

		break;
	case BT_BASS_REMOVE_SRC:
		params.remove_src_params = util_iov_pull_mem(iov,
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

	if (iov->iov_len > 0)
		return false;

	return true;
}

static void bass_bcast_audio_scan_cp_write(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				const uint8_t *value, size_t len,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct iovec iov = {
		.iov_base = (void *)value,
		.iov_len = len,
	};

	/* Validate written command length */
	if (!bass_check_cp_command_len(&iov)) {
		if (opcode == BT_ATT_OP_WRITE_REQ) {
			gatt_db_attribute_write_result(attrib, id,
					BT_ERROR_WRITE_REQUEST_REJECTED);
		}
		return;
	}

	/* TODO: Implement handlers for the written opcodes */
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
	uint8_t *rsp;
	size_t rsp_len;
	struct bt_bcast_src *bcast_src;

	bcast_src = queue_find(bdb->bcast_srcs,
					bass_src_match_attrib,
					attrib);

	if (!bcast_src) {
		gatt_db_attribute_read_result(attrib, id, 0, NULL,
							0);
		return;
	}

	/* Build read response */
	rsp = bass_build_read_rsp_from_bcast_src(bcast_src, &rsp_len);

	if (!rsp) {
		gatt_db_attribute_read_result(attrib, id,
					BT_ATT_ERROR_UNLIKELY,
					NULL, 0);
		return;
	}

	gatt_db_attribute_read_result(attrib, id, 0, (void *)rsp,
						rsp_len);

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
				BT_GATT_CHRC_PROP_WRITE,
				NULL, bass_bcast_audio_scan_cp_write,
				bdb);

	gatt_db_service_set_active(bdb->service, true);
}

static void bass_bcast_src_free(void *data)
{
	struct bt_bcast_src *bcast_src = data;

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

	if (bass_build_bcast_src_from_read_rsp(bcast_src, value, length)) {
		queue_remove(bcast_src->bass->rdb->bcast_srcs, bcast_src);
		bass_bcast_src_free(bcast_src);
		return;
	}
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
		bcast_src = malloc(sizeof(*bcast_src));

		if (!bcast_src) {
			DBG(bass, "Failed to allocate "
				"memory for broadcast source");
			return;
		}

		memset(bcast_src, 0, sizeof(struct bt_bcast_src));
		bcast_src->bass = bass;
		bcast_src->attr = attr;
	}

	if (bass_build_bcast_src_from_notif(bcast_src, value, length)
							&& new_src) {
		bass_bcast_src_free(bcast_src);
		return;
	}

	if (new_src)
		queue_push_tail(bass->rdb->bcast_srcs, bcast_src);
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
			bcast_src = malloc(sizeof(struct bt_bcast_src));

			if (bcast_src == NULL) {
				DBG(bass, "Failed to allocate "
					"memory for broadcast source");
				return;
			}

			memset(bcast_src, 0, sizeof(struct bt_bcast_src));
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

bool bt_bass_attach(struct bt_bass *bass, struct bt_gatt_client *client)
{
	bt_uuid_t uuid;

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, bass);

	if (!client)
		return true;

	if (bass->client)
		return false;

	bass->client = bt_gatt_client_clone(client);
	if (!bass->client)
		return false;

	bt_uuid16_create(&uuid, BASS_UUID);
	gatt_db_foreach_service(bass->rdb->db, &uuid, foreach_bass_service,
				bass);

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
	if (!queue_remove(sessions, bass))
		return;

	bt_gatt_client_unref(bass->client);
	bass->client = NULL;

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

static struct bt_bass_db *bass_db_new(struct gatt_db *db)
{
	struct bt_bass_db *bdb;

	if (!db)
		return NULL;

	bdb = new0(struct bt_bass_db, 1);
	bdb->db = gatt_db_ref(db);
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

static struct bt_bass_db *bass_get_db(struct gatt_db *db)
{
	struct bt_bass_db *bdb;

	bdb = queue_find(bass_db, bass_db_match, db);
	if (bdb)
		return bdb;

	return bass_db_new(db);
}

static struct bt_bass *bt_bass_ref(struct bt_bass *bass)
{
	if (!bass)
		return NULL;

	__sync_fetch_and_add(&bass->ref_count, 1);

	return bass;
}

struct bt_bass *bt_bass_new(struct gatt_db *ldb, struct gatt_db *rdb)
{
	struct bt_bass *bass;
	struct bt_bass_db *db;

	if (!ldb)
		return NULL;

	db = bass_get_db(ldb);
	if (!db)
		return NULL;

	bass = new0(struct bt_bass, 1);
	bass->ldb = db;
	bass->notify = queue_new();

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
