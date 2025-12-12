// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022	Intel Corporation. All rights reserved.
 *  Copyright (C) 2025	Pauli Virtanen. All rights reserved.
 *
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"
#include "bluetooth/hci.h"

#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "src/shared/timeout.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"
#include "src/shared/mcp.h"
#include "src/shared/mcs.h"

#define DBG_MCP(mcp, fmt, ...) \
	mcp_debug(mcp, "%s:%s() mcp %p | " fmt, __FILE__, __func__, mcp, \
								##__VA_ARGS__)
#define DBG_SVC(service, fmt, ...) \
	mcp_debug(service->mcp, "%s:%s() svc %p | " fmt, __FILE__, __func__, \
							service, ##__VA_ARGS__)
#define DBG_MCS(mcs, fmt, ...) \
	mcs_debug(mcs, "%s:%s() mcs %p | " fmt, __FILE__, __func__, mcs, \
								##__VA_ARGS__)

#define MAX_ATTR	32
#define MAX_PENDING	256

struct bt_mcs_db {
	bool gmcs;
	int ccid_value;
	uint32_t media_cp_op_supported_value;
	uint16_t playing_order_supported_value;

	struct gatt_db_attribute *service;
	struct gatt_db_attribute *media_player_name;
	struct gatt_db_attribute *media_player_name_ccc;
	struct gatt_db_attribute *track_changed;
	struct gatt_db_attribute *track_changed_ccc;
	struct gatt_db_attribute *track_title;
	struct gatt_db_attribute *track_title_ccc;
	struct gatt_db_attribute *track_duration;
	struct gatt_db_attribute *track_duration_ccc;
	struct gatt_db_attribute *track_position;
	struct gatt_db_attribute *track_position_ccc;
	struct gatt_db_attribute *playback_speed;
	struct gatt_db_attribute *playback_speed_ccc;
	struct gatt_db_attribute *seeking_speed;
	struct gatt_db_attribute *seeking_speed_ccc;
	struct gatt_db_attribute *playing_order;
	struct gatt_db_attribute *playing_order_ccc;
	struct gatt_db_attribute *playing_order_supported;
	struct gatt_db_attribute *media_state;
	struct gatt_db_attribute *media_state_ccc;
	struct gatt_db_attribute *media_cp;
	struct gatt_db_attribute *media_cp_ccc;
	struct gatt_db_attribute *media_cp_op_supported;
	struct gatt_db_attribute *media_cp_op_supported_ccc;
	struct gatt_db_attribute *ccid;
};

struct bt_mcs_client {
	struct bt_att *att;

	/* Per-client state.
	 *
	 * Concurrency is not specified in MCS v1.0.1, everything currently
	 * implemented seems OK to be in global state.
	 *
	 * TODO: Search Results ID likely should go here
	 */
};

struct bt_mcs {
	struct gatt_db *db;
	struct bt_mcs_db ldb;
	struct queue *clients;

	uint8_t media_state;

	const struct bt_mcs_callback *cb;
	void *user_data;
};

struct bt_mcp_listener {
	const struct bt_mcp_listener_callback *cb;
	void *user_data;
};

struct bt_mcp_service {
	struct bt_mcp *mcp;
	struct bt_mcs_db rdb;

	bool ready;

	unsigned int notify_id[MAX_ATTR];
	unsigned int notify_id_count;

	unsigned int pending_id;

	struct queue *pending;
	struct queue *listeners;
};

struct bt_mcp_pending {
	struct bt_mcp_service *service;
	unsigned int id;
	uint8_t op;
	struct {
		unsigned int client_id;
		struct gatt_db_attribute *attrib;
		uint8_t result;
	} write;
};

struct bt_mcp {
	bool gmcs;
	struct bt_gatt_client *client;
	unsigned int idle_id;
	unsigned int db_id;
	bool ready;

	struct queue *services;

	const struct bt_mcp_callback *cb;
	void *user_data;
};

#define MCS_COMMAND(name_, op_, arg_, end_state_) \
	{ \
		.name = name_, \
		.op = BT_MCS_CMD_ ## op_, \
		.support = BT_MCS_CMD_ ## op_ ## _SUPPORTED, \
		.int32_arg = arg_, \
		.end_state = end_state_, \
	}

#define ANY_STATE	-1

static const struct mcs_command {
	const char *name;
	uint8_t op;
	uint32_t support;
	bool int32_arg;
	int end_state;
} mcs_command[] = {
	MCS_COMMAND("Play", PLAY, false, BT_MCS_STATE_PLAYING),
	MCS_COMMAND("Pause", PAUSE, false, BT_MCS_STATE_PAUSED),
	MCS_COMMAND("Fast Rewind", FAST_REWIND, false, BT_MCS_STATE_SEEKING),
	MCS_COMMAND("Fast Forward", FAST_FORWARD, false, BT_MCS_STATE_SEEKING),
	MCS_COMMAND("Stop", STOP, false, BT_MCS_STATE_PAUSED),
	MCS_COMMAND("Move Relative", MOVE_RELATIVE, true, ANY_STATE),
	MCS_COMMAND("Prev Segment", PREV_SEGMENT, false, ANY_STATE),
	MCS_COMMAND("Next Segment", NEXT_SEGMENT, false, ANY_STATE),
	MCS_COMMAND("First Segment", FIRST_SEGMENT, false, ANY_STATE),
	MCS_COMMAND("Last Segment", LAST_SEGMENT, false, ANY_STATE),
	MCS_COMMAND("Goto Segment", GOTO_SEGMENT, true, ANY_STATE),
	MCS_COMMAND("Prev Track", PREV_TRACK, false, ANY_STATE),
	MCS_COMMAND("Next Track", NEXT_TRACK, false, ANY_STATE),
	MCS_COMMAND("First Track", FIRST_TRACK, false, ANY_STATE),
	MCS_COMMAND("Last Track", LAST_TRACK, false, ANY_STATE),
	MCS_COMMAND("Goto Track", GOTO_TRACK, true, ANY_STATE),
	MCS_COMMAND("Prev Group", PREV_GROUP, false, ANY_STATE),
	MCS_COMMAND("Next Group", NEXT_GROUP, false, ANY_STATE),
	MCS_COMMAND("First Group", FIRST_GROUP, false, ANY_STATE),
	MCS_COMMAND("Last Group", LAST_GROUP, false, ANY_STATE),
	MCS_COMMAND("Goto Group", GOTO_GROUP, true, ANY_STATE),
};

#define MCS_PLAYING_ORDER(name) \
	{ BT_MCS_ORDER_ ## name, BT_MCS_ORDER_SUPPORTED_ ## name }

static const struct {
	uint8_t order;
	uint16_t support;
} mcs_playing_orders[] = {
	MCS_PLAYING_ORDER(SINGLE_ONCE),
	MCS_PLAYING_ORDER(SINGLE_REPEAT),
	MCS_PLAYING_ORDER(IN_ORDER_ONCE),
	MCS_PLAYING_ORDER(IN_ORDER_REPEAT),
	MCS_PLAYING_ORDER(OLDEST_ONCE),
	MCS_PLAYING_ORDER(OLDEST_REPEAT),
	MCS_PLAYING_ORDER(NEWEST_ONCE),
	MCS_PLAYING_ORDER(NEWEST_REPEAT),
	MCS_PLAYING_ORDER(SHUFFLE_ONCE),
	MCS_PLAYING_ORDER(SHUFFLE_REPEAT)
};

typedef bool (*mcs_command_func_t)(void *data);
typedef bool (*mcs_command_func_int32_t)(void *data, int32_t offset);
typedef void (*mcs_get_func_t)(struct bt_mcs *mcs, struct iovec *buf,
								size_t size);
typedef bool (*mcs_set_func_t)(struct bt_mcs *mcs, void *data);

static struct queue *servers;
static uint8_t servers_ccid;


/*
 * MCS Server
 */

static void mcs_debug_func(const char *str, void *user_data)
{
	struct bt_mcs *mcs = user_data;

	mcs->cb->debug(mcs->user_data, str);
}

static void mcs_debug(struct bt_mcs *mcs, const char *format, ...)
{
	va_list ap;

	if (!mcs || !format || !mcs->cb->debug)
		return;

	va_start(ap, format);
	util_debug_va(mcs_debug_func, mcs, format, ap);
	va_end(ap);
}

static const struct mcs_command *mcs_get_command(uint8_t op)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(mcs_command); ++i)
		if (mcs_command[i].op == op)
			return &mcs_command[i];

	return NULL;
}

static mcs_command_func_t mcs_get_handler(struct bt_mcs *mcs, uint8_t op)

{
	switch (op) {
	case BT_MCS_CMD_PLAY: return mcs->cb->play;
	case BT_MCS_CMD_PAUSE: return mcs->cb->pause;
	case BT_MCS_CMD_FAST_REWIND: return mcs->cb->fast_rewind;
	case BT_MCS_CMD_FAST_FORWARD: return mcs->cb->fast_forward;
	case BT_MCS_CMD_STOP: return mcs->cb->stop;
	case BT_MCS_CMD_PREV_SEGMENT: return mcs->cb->previous_segment;
	case BT_MCS_CMD_NEXT_SEGMENT: return mcs->cb->next_segment;
	case BT_MCS_CMD_FIRST_SEGMENT: return mcs->cb->first_segment;
	case BT_MCS_CMD_LAST_SEGMENT: return mcs->cb->last_segment;
	case BT_MCS_CMD_PREV_TRACK: return mcs->cb->previous_track;
	case BT_MCS_CMD_NEXT_TRACK: return mcs->cb->next_track;
	case BT_MCS_CMD_FIRST_TRACK: return mcs->cb->first_track;
	case BT_MCS_CMD_LAST_TRACK: return mcs->cb->last_track;
	case BT_MCS_CMD_PREV_GROUP: return mcs->cb->previous_group;
	case BT_MCS_CMD_NEXT_GROUP: return mcs->cb->next_group;
	case BT_MCS_CMD_FIRST_GROUP: return mcs->cb->first_group;
	case BT_MCS_CMD_LAST_GROUP: return mcs->cb->last_group;
	}
	return NULL;
}

static mcs_command_func_int32_t mcs_get_handler_int32(struct bt_mcs *mcs,
								uint8_t op)

{
	switch (op) {
	case BT_MCS_CMD_MOVE_RELATIVE: return mcs->cb->move_relative;
	case BT_MCS_CMD_GOTO_SEGMENT: return mcs->cb->goto_segment;
	case BT_MCS_CMD_GOTO_TRACK: return mcs->cb->goto_track;
	case BT_MCS_CMD_GOTO_GROUP: return mcs->cb->goto_group;
	}
	return NULL;
}

static uint32_t mcs_get_supported(struct bt_mcs *mcs)
{
	unsigned int i;
	uint32_t value = 0;

	for (i = 0; i < ARRAY_SIZE(mcs_command); ++i)
		value |= mcs_command[i].support;

	if (mcs->cb->media_cp_op_supported)
		value = mcs->cb->media_cp_op_supported(mcs->user_data);

	for (i = 0; i < ARRAY_SIZE(mcs_command); ++i) {
		void *handler = mcs_get_handler(mcs, mcs_command[i].op);

		if (!handler)
			handler = mcs_get_handler_int32(mcs, mcs_command[i].op);
		if (!handler)
			value &= ~mcs_command[i].support;
	}

	mcs->ldb.media_cp_op_supported_value = value;
	return value;
}

static void write_media_cp(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				const uint8_t *data, size_t len,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_mcs *mcs = user_data;
	struct iovec iov = { .iov_base = (void *)data, .iov_len = len };
	const struct mcs_command *cmd = NULL;
	struct bt_mcs_cp_rsp rsp = {
		.op = 0,
		.result = BT_MCS_RESULT_COMMAND_CANNOT_COMPLETE
	};
	int ret = 0;
	int32_t arg = 0;
	uint8_t op;
	bool ok = false;

	if (offset) {
		ret = BT_ATT_ERROR_INVALID_OFFSET;
		goto respond;
	}

	if (!util_iov_pull_u8(&iov, &op)) {
		ret = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto respond;
	}

	rsp.op = op;

	cmd = mcs_get_command(op);
	if (!cmd || !(cmd->support & mcs_get_supported(mcs))) {
		rsp.result = BT_MCS_RESULT_OP_NOT_SUPPORTED;
		goto respond;
	}

	DBG_MCS(mcs, "Command %s", cmd->name);

	/* We may attempt to perform the operation also if inactive (MCS v1.0.1
	 * p. 26), leave decision to upper layer.
	 */

	ok = cmd->int32_arg ?
		mcs_get_handler_int32(mcs, op)(mcs->user_data, arg) :
		mcs_get_handler(mcs, op)(mcs->user_data);
	if (ok)
		rsp.result = BT_MCS_RESULT_SUCCESS;
	else if (mcs->media_state == BT_MCS_STATE_INACTIVE)
		rsp.result = BT_MCS_RESULT_MEDIA_PLAYER_INACTIVE;
	else
		rsp.result = BT_MCS_RESULT_COMMAND_CANNOT_COMPLETE;

respond:
	DBG_MCS(mcs, "%s ret %u result %u", cmd ? cmd->name : "-",
							ret, rsp.result);

	gatt_db_attribute_write_result(attrib, id, ret);
	if (!rsp.op)
		return;

	/* Make state transition immediately if command was successful and has
	 * specified end state. Upper layer shall emit spontaneous transitions
	 * to correct as needed.
	 */
	if (ok) {
		bt_mcs_set_media_state(mcs, cmd->end_state);

		switch (op) {
		case BT_MCS_CMD_STOP:
		case BT_MCS_CMD_PREV_TRACK:
		case BT_MCS_CMD_NEXT_TRACK:
		case BT_MCS_CMD_FIRST_TRACK:
		case BT_MCS_CMD_LAST_TRACK:
		case BT_MCS_CMD_GOTO_TRACK:
		case BT_MCS_CMD_PREV_GROUP:
		case BT_MCS_CMD_NEXT_GROUP:
		case BT_MCS_CMD_FIRST_GROUP:
		case BT_MCS_CMD_LAST_GROUP:
		case BT_MCS_CMD_GOTO_GROUP:
			if (mcs->cb->set_track_position)
				mcs->cb->set_track_position(mcs->user_data, 0);
			bt_mcs_changed(mcs, MCS_TRACK_POSITION_CHRC_UUID);
			break;
		}
	}

	gatt_db_attribute_notify(attrib, (uint8_t *)&rsp, sizeof(rsp), att);
}

void bt_mcs_set_media_state(struct bt_mcs *mcs, uint8_t state)
{
	switch (state) {
	case BT_MCS_STATE_INACTIVE:
	case BT_MCS_STATE_PLAYING:
	case BT_MCS_STATE_PAUSED:
	case BT_MCS_STATE_SEEKING:
		break;
	default:
		return;
	}

	if (state == mcs->media_state)
		return;

	mcs->media_state = state;
	bt_mcs_changed(mcs, MCS_MEDIA_STATE_CHRC_UUID);
}

uint8_t bt_mcs_get_media_state(struct bt_mcs *mcs)
{
	return mcs->media_state;
}

static void get_media_player_name(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	if (mcs->cb->media_player_name)
		mcs->cb->media_player_name(mcs->user_data, buf, size);
}

static void get_track_changed(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
}

static void get_track_title(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	if (mcs->cb->track_title)
		mcs->cb->track_title(mcs->user_data, buf, size);
}

static void get_track_duration(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	int32_t value = BT_MCS_DURATION_UNAVAILABLE;

	if (mcs->cb->track_duration)
		value = mcs->cb->track_duration(mcs->user_data);

	util_iov_push_le32(buf, (uint32_t)value);
}

static void get_track_position(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	int32_t value = BT_MCS_POSITION_UNAVAILABLE;

	if (mcs->cb->track_position)
		value = mcs->cb->track_position(mcs->user_data);

	util_iov_push_le32(buf, (uint32_t)value);
}

static void get_playback_speed(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	int8_t value = 0x00;

	if (mcs->cb->playback_speed)
		value = mcs->cb->playback_speed(mcs->user_data);

	util_iov_push_u8(buf, (uint8_t)value);
}

static void get_seeking_speed(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	int8_t value = 0x00;

	if (mcs->cb->seeking_speed)
		value = mcs->cb->seeking_speed(mcs->user_data);

	util_iov_push_u8(buf, (uint8_t)value);
}

static void get_playing_order(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	uint8_t value = BT_MCS_ORDER_IN_ORDER_REPEAT;

	if (mcs->cb->playing_order)
		value = mcs->cb->playing_order(mcs->user_data);

	util_iov_push_u8(buf, value);
}

static void get_playing_order_supported(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	uint16_t value = BT_MCS_ORDER_SUPPORTED_IN_ORDER_REPEAT;

	if (mcs->cb->playing_order_supported)
		value = mcs->cb->playing_order_supported(mcs->user_data);

	util_iov_push_le16(buf, value);
}

static void get_media_state(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	util_iov_push_u8(buf, mcs->media_state);
}

static void get_media_cp_op_supported(struct bt_mcs *mcs, struct iovec *buf,
								size_t size)
{
	util_iov_push_le32(buf, mcs_get_supported(mcs));
}

static void get_ccid(struct bt_mcs *mcs, struct iovec *buf, size_t size)
{
	util_iov_push_u8(buf, mcs->ldb.ccid_value);
}

static bool set_track_position(struct bt_mcs *mcs, void *data)
{
	int32_t value = (int32_t)get_le32(data);

	DBG_MCS(mcs, "Set Track Position %d", value);

	if (mcs->cb->set_track_position)
		return mcs->cb->set_track_position(mcs->user_data, value);
	return false;
}

static bool set_playback_speed(struct bt_mcs *mcs, void *data)
{
	int8_t value = (int8_t)get_u8(data);

	DBG_MCS(mcs, "Set Playback Speed %d", value);

	if (mcs->cb->set_playback_speed)
		return mcs->cb->set_playback_speed(mcs->user_data, value);
	return false;
}

static bool set_playing_order(struct bt_mcs *mcs, void *data)
{
	uint8_t value = get_u8(data);

	DBG_MCS(mcs, "Set Playing Order %u", value);

	if (mcs->cb->set_playing_order)
		return mcs->cb->set_playing_order(mcs->user_data, value);
	return false;
}

static void read_result(struct bt_mcs *mcs, struct gatt_db_attribute *attrib,
			unsigned int id, uint16_t offset, mcs_get_func_t get)
{
	uint8_t buf[BT_ATT_MAX_VALUE_LEN];
	struct iovec iov = { .iov_base = buf, .iov_len = 0 };

	get(mcs, &iov, sizeof(buf));

	if (offset > iov.iov_len) {
		gatt_db_attribute_read_result(attrib, id,
					BT_ATT_ERROR_INVALID_OFFSET, NULL, 0);
		return;
	}

	gatt_db_attribute_read_result(attrib, id, 0, buf + offset,
							iov.iov_len - offset);
}

#define READ_FUNC(name) \
	static void read_ ## name(struct gatt_db_attribute *attrib, \
				unsigned int id, uint16_t offset, \
				uint8_t opcode, struct bt_att *att, \
				void *user_data) \
	{ \
		DBG_MCS(user_data, ""); \
		read_result(user_data, attrib, id, offset, get_ ##name); \
	}

READ_FUNC(media_player_name)
READ_FUNC(track_title)
READ_FUNC(track_duration)
READ_FUNC(track_position)
READ_FUNC(playback_speed)
READ_FUNC(seeking_speed)
READ_FUNC(playing_order)
READ_FUNC(playing_order_supported)
READ_FUNC(media_state)
READ_FUNC(media_cp_op_supported)
READ_FUNC(ccid)

static void write_result(struct bt_mcs *mcs,
				struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				const uint8_t *data, size_t len,
				mcs_get_func_t get, mcs_set_func_t set)
{
	uint8_t buf[4];
	struct iovec iov = { .iov_base = buf, .iov_len = 0 };
	bt_uuid_t uuid;
	uint8_t ret;

	get(mcs, &iov, sizeof(buf));

	if (len > iov.iov_len) {
		gatt_db_attribute_write_result(attrib, id,
				BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN);
		return;
	}

	if (offset + len > iov.iov_len) {
		gatt_db_attribute_write_result(attrib, id,
				BT_ATT_ERROR_INVALID_OFFSET);
		return;
	}

	memcpy(iov.iov_base + offset, data, len);

	if (set(mcs, iov.iov_base))
		ret = 0;
	else
		ret = BT_ATT_ERROR_VALUE_NOT_ALLOWED;

	gatt_db_attribute_write_result(attrib, id, ret);

	if (!gatt_db_attribute_get_char_data(attrib, NULL, NULL, NULL, NULL,
									&uuid))
		return;
	if (!ret)
		bt_mcs_changed(mcs, uuid.value.u16);
}

#define WRITE_FUNC(name) \
	static void write_ ## name(struct gatt_db_attribute *attrib, \
				unsigned int id, uint16_t offset, \
				const uint8_t *data, size_t len, \
				uint8_t opcode, struct bt_att *att, \
				void *user_data) \
	{ write_result(user_data, attrib, id, offset, data, len, \
						get_ ## name, set_ ## name); }

WRITE_FUNC(track_position)
WRITE_FUNC(playback_speed)
WRITE_FUNC(playing_order)

void bt_mcs_changed(struct bt_mcs *mcs, uint16_t chrc_uuid)
{
	struct {
		struct gatt_db_attribute *attr;
		mcs_get_func_t get;
	} attrs[] = {
		{ mcs->ldb.media_player_name, get_media_player_name },
		{ mcs->ldb.track_changed, get_track_changed },
		{ mcs->ldb.track_title, get_track_title },
		{ mcs->ldb.track_duration, get_track_duration },
		{ mcs->ldb.track_position, get_track_position },
		{ mcs->ldb.playback_speed, get_playback_speed },
		{ mcs->ldb.seeking_speed, get_seeking_speed },
		{ mcs->ldb.playing_order, get_playing_order },
		{ mcs->ldb.media_state, get_media_state },
		{ mcs->ldb.media_cp_op_supported, get_media_cp_op_supported },
	};
	uint8_t buf[BT_ATT_MAX_VALUE_LEN];
	struct iovec iov = { .iov_base = buf, .iov_len = 0 };
	unsigned int i;
	bt_uuid_t uuid, uuid_attr;
	uint8_t props;

	bt_uuid16_create(&uuid, chrc_uuid);

	for (i = 0; i < ARRAY_SIZE(attrs); ++i) {
		if (!gatt_db_attribute_get_char_data(attrs[i].attr, NULL,
						NULL, &props, NULL, &uuid_attr))
			continue;
		if (bt_uuid_cmp(&uuid_attr, &uuid))
			continue;

		DBG_MCS(mcs, "Notify %u", chrc_uuid);

		attrs[i].get(mcs, &iov, sizeof(buf));

		/* No client-specific state: notify everyone */
		gatt_db_attribute_notify(attrs[i].attr, iov.iov_base,
							iov.iov_len, NULL);
		break;
	}
}

static bool mcs_init_db(struct bt_mcs *mcs, bool is_gmcs)
{
	struct gatt_db *db = mcs->db;
	struct bt_mcs_db *ldb = &mcs->ldb;
	bt_uuid_t uuid;

	bt_uuid16_create(&uuid, is_gmcs ? GMCS_UUID : MCS_UUID);
	ldb->service = gatt_db_add_service(db, &uuid, true, 38);

	/* Add also optional CCC */

	bt_uuid16_create(&uuid, MCS_MEDIA_PLAYER_NAME_CHRC_UUID);
	ldb->media_player_name = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
		read_media_player_name, NULL, mcs);

	ldb->media_player_name_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_TRACK_CHANGED_CHRC_UUID);
	ldb->track_changed = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_NONE, BT_GATT_CHRC_PROP_NOTIFY,
		NULL, NULL, mcs);
	gatt_db_attribute_set_fixed_length(ldb->track_changed, 0);

	ldb->track_changed_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_TRACK_TITLE_CHRC_UUID);
	ldb->track_title = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
		read_track_title, NULL, mcs);

	ldb->track_title_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_TRACK_DURATION_CHRC_UUID);
	ldb->track_duration = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
		read_track_duration, NULL, mcs);
	gatt_db_attribute_set_fixed_length(ldb->track_duration,
							sizeof(int32_t));

	ldb->track_duration_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_TRACK_POSITION_CHRC_UUID);
	ldb->track_position = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY |
		BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
		read_track_position, write_track_position, mcs);
	gatt_db_attribute_set_fixed_length(ldb->track_position,
							sizeof(int32_t));

	ldb->track_position_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_PLAYBACK_SPEED_CHRC_UUID);
	ldb->playback_speed = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY |
		BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
		read_playback_speed, write_playback_speed, mcs);
	gatt_db_attribute_set_fixed_length(ldb->playback_speed, sizeof(int8_t));

	ldb->playback_speed_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_SEEKING_SPEED_CHRC_UUID);
	ldb->seeking_speed = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
		read_seeking_speed, NULL, mcs);
	gatt_db_attribute_set_fixed_length(ldb->seeking_speed, sizeof(int8_t));

	ldb->seeking_speed_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_PLAYING_ORDER_CHRC_UUID);
	ldb->playing_order = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY |
		BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
		read_playing_order, write_playing_order, mcs);
	gatt_db_attribute_set_fixed_length(ldb->playing_order, sizeof(uint8_t));

	ldb->playing_order_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID);
	ldb->playing_order_supported = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ, BT_GATT_CHRC_PROP_READ,
		read_playing_order_supported, NULL, mcs);
	gatt_db_attribute_set_fixed_length(ldb->playing_order_supported,
							sizeof(uint16_t));

	bt_uuid16_create(&uuid, MCS_MEDIA_STATE_CHRC_UUID);
	ldb->media_state = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
		read_media_state, NULL, mcs);
	gatt_db_attribute_set_fixed_length(ldb->media_state, sizeof(uint8_t));

	ldb->media_state_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_MEDIA_CP_CHRC_UUID);
	ldb->media_cp = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_WRITE,
		BT_GATT_CHRC_PROP_WRITE | BT_GATT_CHRC_PROP_NOTIFY |
					BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP,
		NULL, write_media_cp, mcs);

	ldb->media_cp_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID);
	ldb->media_cp_op_supported = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ,
		BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
		read_media_cp_op_supported, NULL, mcs);
	gatt_db_attribute_set_fixed_length(ldb->media_cp_op_supported,
							sizeof(uint32_t));

	ldb->media_cp_op_supported_ccc = gatt_db_service_add_ccc(
		ldb->service, BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, MCS_CCID_CHRC_UUID);
	ldb->ccid = gatt_db_service_add_characteristic(
		ldb->service, &uuid,
		BT_ATT_PERM_READ, BT_GATT_CHRC_PROP_READ,
		read_ccid, NULL, mcs);
	gatt_db_attribute_set_fixed_length(ldb->ccid, sizeof(uint8_t));

	return true;
}

uint8_t bt_mcs_get_ccid(struct bt_mcs *mcs)
{
	return mcs->ldb.ccid_value;
}

struct match_mcs_data {
	struct gatt_db *db;
	bool gmcs;
	bool any;
	int ccid;
};

static bool match_mcs(const void *data, const void *user_data)
{
	const struct bt_mcs *mcs = data;
	const struct match_mcs_data *match = user_data;

	if (match->db != mcs->db)
		return false;
	if (match->gmcs)
		return mcs->ldb.gmcs;
	if (match->any)
		return true;
	return match->ccid == mcs->ldb.ccid_value;
}

static int mcs_alloc_ccid(struct gatt_db *db)
{
	unsigned int ccid;

	if (!db)
		return 0;

	for (ccid = servers_ccid; ccid < servers_ccid + 0x100u; ccid++) {
		struct match_mcs_data match = { .db = db, .ccid = ccid & 0xff };

		if (!queue_find(servers, match_mcs, &match)) {
			servers_ccid = ccid + 1;
			return match.ccid;
		}
	}

	return -ENOENT;
}

void bt_mcs_test_util_reset_ccid(void)
{
	servers_ccid = 0;
}

struct bt_mcs *bt_mcs_register(struct gatt_db *db, bool is_gmcs,
			const struct bt_mcs_callback *cb, void *user_data)
{
	struct bt_mcs *mcs;
	int ccid;

	if (!db || !cb)
		return NULL;

	if (is_gmcs) {
		struct match_mcs_data match = { .db = db, .gmcs = true };

		/* Only one GMCS possible */
		if (queue_find(servers, match_mcs, &match))
			return NULL;
	}

	ccid = mcs_alloc_ccid(db);
	if (ccid < 0)
		return NULL;

	mcs = new0(struct bt_mcs, 1);
	mcs->db = db;
	mcs->ldb.ccid_value = ccid;
	mcs->cb = cb;
	mcs->user_data = user_data;

	mcs->media_state = BT_MCS_STATE_INACTIVE;

	if (!mcs_init_db(mcs, is_gmcs)) {
		free(mcs);
		return NULL;
	}

	gatt_db_ref(mcs->db);

	if (!servers)
		servers = queue_new();
	queue_push_tail(servers, mcs);

	gatt_db_service_set_active(mcs->ldb.service, true);
	return mcs;
}

void bt_mcs_unregister(struct bt_mcs *mcs)
{
	if (!mcs)
		return;

	if (mcs->cb->destroy)
		mcs->cb->destroy(mcs->user_data);

	queue_remove(servers, mcs);

	gatt_db_remove_service(mcs->db, mcs->ldb.service);
	gatt_db_unref(mcs->db);

	if (queue_isempty(servers)) {
		queue_destroy(servers, NULL);
		servers = NULL;
	}

	free(mcs);
}

void bt_mcs_unregister_all(struct gatt_db *db)
{
	struct bt_mcs *mcs;

	do {
		struct match_mcs_data match = { .db = db, .any = true };

		mcs = queue_find(servers, match_mcs, &match);
		bt_mcs_unregister(mcs);
	} while (mcs);
}

/*
 * MCP Client
 */

static void mcp_service_reread(struct bt_mcp_service *service,
					struct gatt_db_attribute *attrib,
					bool skip_notify);
static void foreach_mcs_char(struct gatt_db_attribute *attr, void *user_data);

static void mcp_debug_func(const char *str, void *user_data)
{
	struct bt_mcp *mcp = user_data;

	mcp->cb->debug(mcp->user_data, str);
}

static void mcp_debug(struct bt_mcp *mcp, const char *format, ...)
{
	va_list ap;

	if (!mcp || !format || !mcp->cb->debug)
		return;

	va_start(ap, format);
	util_debug_va(mcp_debug_func, mcp, format, ap);
	va_end(ap);
}

static bool match_ccid(const void *data, const void *user_data)
{
	const struct bt_mcp_service *service = data;

	return service->rdb.ccid_value == (int)PTR_TO_UINT(user_data);
}

static struct bt_mcp_service *mcp_service(struct bt_mcp *mcp, uint8_t ccid)
{
	if (!mcp)
		return NULL;

	return queue_find(mcp->services, match_ccid, UINT_TO_PTR(ccid));
}

static bool match_pending(const void *data, const void *user_data)
{
	const struct bt_mcp_pending *pending = data;

	return pending->id == PTR_TO_UINT(user_data);
}

static struct bt_mcp_pending *mcp_pending_new(struct bt_mcp_service *service)
{
	struct bt_mcp_pending *pending;

	if (queue_length(service->pending) > MAX_PENDING)
		return NULL;

	while (!service->pending_id || queue_find(service->pending,
			match_pending, UINT_TO_PTR(service->pending_id)))
		service->pending_id++;

	pending = new0(struct bt_mcp_pending, 1);
	pending->service = service;
	pending->id = service->pending_id++;
	return pending;
}

static unsigned int mcp_send(struct bt_mcp_service *service, uint8_t *buf,
								uint16_t length)
{
	struct bt_mcp *mcp = service->mcp;
	uint16_t handle;
	struct bt_mcp_pending *pending;
	int ret;
	uint8_t op = buf[0];

	if (!gatt_db_attribute_get_char_data(service->rdb.media_cp, NULL,
						&handle, NULL, NULL, NULL))
		return 0;

	pending = mcp_pending_new(service);
	if (!pending)
		return 0;

	ret = bt_gatt_client_write_without_response(mcp->client,
						handle, false, buf, length);
	if (!ret) {
		free(pending);
		return 0;
	}

	pending->op = op;
	queue_push_tail(service->pending, pending);

	DBG_SVC(service, "%u", pending->id);
	return pending->id;
}

static void mcp_pending_write_cb(bool success, uint8_t att_ecode,
								void *user_data)
{
	struct bt_mcp_pending *pending = user_data;

	if (!success) {
		pending->write.result = BT_MCS_RESULT_COMMAND_CANNOT_COMPLETE;
		return;
	}

	pending->write.result = BT_MCS_RESULT_SUCCESS;

	/* If the attribute doesn't have notify, reread to get the new value */
	mcp_service_reread(pending->service, pending->write.attrib, true);
}

static void mcp_pending_write_done(void *user_data)
{
	struct bt_mcp_pending *pending = user_data;
	struct bt_mcp_service *service = pending->service;
	struct bt_mcp *mcp = service->mcp;

	DBG_SVC(service, "write %u", pending->id);

	queue_remove(service->pending, pending);

	if (mcp->cb->complete)
		mcp->cb->complete(mcp->user_data, pending->id,
							pending->write.result);
	free(pending);
}

static unsigned int mcp_write_chrc(struct bt_mcp_service *service,
		struct gatt_db_attribute *attrib, void *data, uint16_t length)
{
	struct bt_mcp *mcp;
	struct bt_mcp_pending *pending;
	uint16_t handle;

	if (!service)
		return 0;

	mcp = service->mcp;

	if (!gatt_db_attribute_get_char_data(attrib, NULL, &handle, NULL, NULL,
									NULL))
		return 0;

	pending = mcp_pending_new(service);
	if (!pending)
		return 0;

	pending->write.attrib = attrib;
	pending->write.client_id = bt_gatt_client_write_value(mcp->client,
				handle, data, length, mcp_pending_write_cb,
				pending, mcp_pending_write_done);
	if (!pending->write.client_id) {
		free(pending);
		return 0;
	}

	queue_push_tail(service->pending, pending);
	return pending->id;
}

static bool match_pending_write(const void *data, const void *user_data)
{
	const struct bt_mcp_pending *pending = data;

	return !pending->op;
}

static void mcp_cancel_pending_writes(struct bt_mcp_service *service)
{
	struct bt_mcp_pending *pending;
	struct bt_gatt_client *client = service->mcp->client;

	do {
		pending = queue_remove_if(service->pending, match_pending_write,
									NULL);
		if (pending) {
			if (!bt_gatt_client_cancel(client,
						pending->write.client_id))
				free(pending);
		}
	} while (pending);
}

static unsigned int mcp_command(struct bt_mcp *mcp, uint8_t ccid, uint8_t op,
								int32_t arg)
{
	const struct mcs_command *cmd = mcs_get_command(op);
	struct bt_mcp_service *service = mcp_service(mcp, ccid);
	uint8_t buf[5];
	struct iovec iov = { .iov_base = buf, .iov_len = 0 };

	if (!service || !cmd)
		return 0;

	if (!(service->rdb.media_cp_op_supported_value & cmd->support))
		return 0;

	DBG_SVC(service, "%s %d", cmd->name, arg);

	util_iov_push_u8(&iov, op);
	if (cmd->int32_arg)
		util_iov_push_le32(&iov, arg);

	return mcp_send(service, iov.iov_base, iov.iov_len);
}

unsigned int bt_mcp_play(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_PLAY, 0);
}

unsigned int bt_mcp_pause(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_PAUSE, 0);
}

unsigned int bt_mcp_fast_rewind(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_FAST_REWIND, 0);
}

unsigned int bt_mcp_fast_forward(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_FAST_FORWARD, 0);
}

unsigned int bt_mcp_stop(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_STOP, 0);
}

unsigned int bt_mcp_move_relative(struct bt_mcp *mcp, uint8_t ccid,
								int32_t offset)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_MOVE_RELATIVE, offset);
}

unsigned int bt_mcp_previous_segment(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_PREV_SEGMENT, 0);
}

unsigned int bt_mcp_next_segment(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_NEXT_SEGMENT, 0);
}

unsigned int bt_mcp_first_segment(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_FIRST_SEGMENT, 0);
}

unsigned int bt_mcp_last_segment(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_LAST_SEGMENT, 0);
}

unsigned int bt_mcp_goto_segment(struct bt_mcp *mcp, uint8_t ccid, int32_t n)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_GOTO_SEGMENT, n);
}

unsigned int bt_mcp_previous_track(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_PREV_TRACK, 0);
}

unsigned int bt_mcp_next_track(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_NEXT_TRACK, 0);
}

unsigned int bt_mcp_first_track(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_FIRST_TRACK, 0);
}

unsigned int bt_mcp_last_track(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_LAST_TRACK, 0);
}

unsigned int bt_mcp_goto_track(struct bt_mcp *mcp, uint8_t ccid, int32_t n)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_GOTO_TRACK, n);
}

unsigned int bt_mcp_previous_group(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_PREV_GROUP, 0);
}

unsigned int bt_mcp_next_group(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_NEXT_GROUP, 0);
}

unsigned int bt_mcp_first_group(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_FIRST_GROUP, 0);
}

unsigned int bt_mcp_last_group(struct bt_mcp *mcp, uint8_t ccid)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_LAST_GROUP, 0);
}

unsigned int bt_mcp_goto_group(struct bt_mcp *mcp, uint8_t ccid, int32_t n)
{
	return mcp_command(mcp, ccid, BT_MCS_CMD_GOTO_GROUP, n);
}

unsigned int bt_mcp_set_track_position(struct bt_mcp *mcp, uint8_t ccid,
							int32_t position)
{
	struct bt_mcp_service *service = mcp_service(mcp, ccid);

	position = cpu_to_le32(position);
	return mcp_write_chrc(service, service->rdb.track_position,
						&position, sizeof(position));
}

unsigned int bt_mcp_set_playback_speed(struct bt_mcp *mcp, uint8_t ccid,
								int8_t value)
{
	struct bt_mcp_service *service = mcp_service(mcp, ccid);

	return mcp_write_chrc(service, service->rdb.playback_speed,
							&value, sizeof(value));
}

unsigned int bt_mcp_set_playing_order(struct bt_mcp *mcp, uint8_t ccid,
								uint8_t value)
{
	struct bt_mcp_service *service = mcp_service(mcp, ccid);
	uint16_t support = 0;
	unsigned int i;

	if (!service)
		return 0;

	for (i = 0; i < ARRAY_SIZE(mcs_playing_orders); ++i) {
		if (mcs_playing_orders[i].order == value) {
			support = mcs_playing_orders[i].support;
			break;
		}
	}
	if (!(service->rdb.playing_order_supported_value & support))
		return 0;

	return mcp_write_chrc(service, service->rdb.playing_order,
							&value, sizeof(value));
}

uint16_t bt_mcp_get_supported_playing_order(struct bt_mcp *mcp, uint8_t ccid)
{
	struct bt_mcp_service *service = mcp_service(mcp, ccid);

	if (!service)
		return 0;
	return service->rdb.playing_order_supported_value;
}

uint32_t bt_mcp_get_supported_commands(struct bt_mcp *mcp, uint8_t ccid)
{
	struct bt_mcp_service *service = mcp_service(mcp, ccid);

	if (!service)
		return 0;
	return service->rdb.media_cp_op_supported_value;
}

#define LISTENER_CB(service, method, ...) \
	do { \
		const struct queue_entry *entry = \
				queue_get_entries((service)->listeners); \
		for (; entry; entry = entry->next) { \
			struct bt_mcp_listener *listener = entry->data; \
			if (listener->cb->method) \
				listener->cb->method(listener->user_data, \
							## __VA_ARGS__); \
		} \
	} while (0)

static void update_media_player_name(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;

	DBG_SVC(service, "Media Player Name");

	LISTENER_CB(service, media_player_name, value, length);
}

static void update_track_changed(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;

	if (!success) {
		DBG_SVC(service, "Unable to read Track Changed: "
						"error 0x%02x", att_ecode);
		return;
	}

	mcp_service_reread(service, NULL, true);

	DBG_SVC(service, "Track Changed");

	LISTENER_CB(service, track_changed);
}

static void update_track_title(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;

	if (!success) {
		DBG_SVC(service, "Unable to read Track Title: error 0x%02x",
								att_ecode);
		return;
	}

	DBG_SVC(service, "Track Title");

	LISTENER_CB(service, track_title, value, length);
}

static void update_track_duration(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint32_t v;

	if (!success || !util_iov_pull_le32(&iov, &v)) {
		DBG_SVC(service, "Unable to read Track Duration: "
						"error 0x%02x", att_ecode);
		return;
	}

	DBG_SVC(service, "Track Duration: %d", (int32_t)v);

	LISTENER_CB(service, track_duration, (int32_t)v);
}

static void update_track_position(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint32_t v;

	if (!success || !util_iov_pull_le32(&iov, &v)) {
		DBG_SVC(service, "Unable to read Track Position: "
						"error 0x%02x", att_ecode);
		return;
	}

	DBG_SVC(service, "Track Position: %d", (int32_t)v);

	LISTENER_CB(service, track_position, (int32_t)v);
}

static void update_playback_speed(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint8_t v;

	if (!success || !util_iov_pull_u8(&iov, &v)) {
		DBG_SVC(service, "Unable to read Playback Speed: "
						"error 0x%02x", att_ecode);
		return;
	}

	DBG_SVC(service, "Playback Speed: %d", (int8_t)v);

	LISTENER_CB(service, playback_speed, (int8_t)v);
}

static void update_seeking_speed(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint8_t v;

	if (!success || !util_iov_pull_u8(&iov, &v)) {
		DBG_SVC(service, "Unable to read Seeking Speed: "
						"error 0x%02x", att_ecode);
		return;
	}

	DBG_SVC(service, "Seeking Speed: %d", (int8_t)v);

	LISTENER_CB(service, seeking_speed, (int8_t)v);
}

static void update_playing_order(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint8_t v;

	if (!success || !util_iov_pull_u8(&iov, &v)) {
		DBG_SVC(service, "Unable to read Playing Order: "
						"error 0x%02x", att_ecode);
		return;
	}

	DBG_SVC(service, "Playing Order: %u", v);

	LISTENER_CB(service, playing_order, v);
}

static void update_playing_order_supported(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint16_t v;

	if (!success || !util_iov_pull_le16(&iov, &v)) {
		DBG_SVC(service, "Unable to read "
			"Playing Order Supported: error 0x%02x", att_ecode);
		return;
	}

	DBG_SVC(service, "Playing Order Supported: %u", v);

	service->rdb.playing_order_supported_value = v;
}

static void update_media_state(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint8_t v;

	if (!success || !util_iov_pull_u8(&iov, &v)) {
		DBG_SVC(service, "Unable to read Media State: error 0x%02x",
								att_ecode);
		return;
	}

	DBG_SVC(service, "Media State: %u", v);

	LISTENER_CB(service, media_state, v);
}

static bool match_pending_op(const void *data, const void *user_data)
{
	const struct bt_mcp_pending *pending = data;

	return pending->op && pending->op == PTR_TO_UINT(user_data);
}

static void update_media_cp(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct bt_mcp *mcp = service->mcp;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	struct bt_mcp_pending *pending;
	uint8_t op, result;

	if (!success || !util_iov_pull_u8(&iov, &op) ||
					!util_iov_pull_u8(&iov, &result)) {
		DBG_SVC(service, "Unable to read Media CP: error 0x%02x",
								att_ecode);
		return;
	}

	DBG_SVC(service, "Media CP %u result %u", op, result);

	pending = queue_remove_if(service->pending, match_pending_op,
							UINT_TO_PTR(op));
	if (!pending)
		return;

	if (mcp->cb->complete)
		mcp->cb->complete(mcp->user_data, pending->id, result);

	free(pending);
}

static void update_media_cp_op_supported(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint32_t v;

	if (!success || !util_iov_pull_le32(&iov, &v)) {
		DBG_SVC(service, "Unable to read "
			"Media CP Op Supported: error 0x%02x", att_ecode);
		return;
	}

	DBG_SVC(service, "Media CP Op Supported: %d", v);

	service->rdb.media_cp_op_supported_value = v;
}

static void update_add_service(void *data, void *user_data)
{
	struct bt_mcp_service *service = data;
	struct bt_mcp *mcp = user_data;

	if (service->rdb.ccid_value < 0)
		return;

	if (service->ready)
		return;

	service->ready = true;
	if (mcp->cb->ccid)
		mcp->cb->ccid(mcp->user_data, service->rdb.ccid_value,
							service->rdb.gmcs);
}

static void update_ccid(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint8_t v;

	if (!success || !util_iov_pull_u8(&iov, &v)) {
		DBG_SVC(service, "Unable to read CCID: error 0x%02x",
								att_ecode);
		return;
	}

	DBG_SVC(service, "CCID: %u", v);

	service->rdb.ccid_value = v;

	gatt_db_service_foreach_char(service->rdb.service, foreach_mcs_char,
								service);

	update_add_service(service, service->mcp);
}

static void mcp_service_reread(struct bt_mcp_service *service,
					struct gatt_db_attribute *attrib,
					bool skip_notify)
{
	const struct {
		struct gatt_db_attribute *attr;
		bt_gatt_client_read_callback_t cb;
	} attrs[] = {
		{ service->rdb.track_title, update_track_title },
		{ service->rdb.track_duration, update_track_duration },
		{ service->rdb.track_position, update_track_position },
		{ service->rdb.playback_speed, update_playback_speed },
		{ service->rdb.seeking_speed, update_seeking_speed },
		{ service->rdb.playing_order, update_playing_order },
		{ service->rdb.playing_order_supported,
		  update_playing_order_supported },
		{ service->rdb.media_state, update_media_state },
		{ service->rdb.media_cp_op_supported,
		  update_media_cp_op_supported },
	};
	struct bt_gatt_client *client = service->mcp->client;
	uint16_t value_handle;
	uint8_t props;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(attrs); ++i) {
		if (!attrs[i].attr)
			continue;
		if (attrib && attrs[i].attr != attrib)
			continue;

		if (!gatt_db_attribute_get_char_data(attrs[i].attr, NULL,
					&value_handle, &props, NULL, NULL))
			continue;
		if (skip_notify && (props & BT_GATT_CHRC_PROP_NOTIFY))
			continue;

		DBG_SVC(service, "re-read handle 0x%04x", value_handle);

		bt_gatt_client_read_value(client, value_handle,
						attrs[i].cb, service, NULL);
	}
}

static void notify_media_player_name(struct bt_mcp_service *service)
{
	/* On player name change, re-read all attributes */
	mcp_service_reread(service, NULL, false);
}

static void mcp_idle(void *data)
{
	struct bt_mcp *mcp = data;

	DBG_MCP(mcp, "");

	mcp->idle_id = 0;

	if (!mcp->ready) {
		mcp->ready = true;
		if (mcp->cb->ready)
			mcp->cb->ready(mcp->user_data);
	}
}

struct chrc_notify_data {
	const char *name;
	struct bt_mcp_service *service;
	bt_gatt_client_read_callback_t cb;
	void (*notify_cb)(struct bt_mcp_service *service);
};

static void chrc_register(uint16_t att_ecode, void *user_data)
{
	struct chrc_notify_data *data = user_data;

	if (att_ecode)
		DBG_SVC(data->service, "%s notification failed: 0x%04x",
							data->name, att_ecode);
}

static void chrc_notify(uint16_t value_handle, const uint8_t *value,
					uint16_t length, void *user_data)
{
	struct chrc_notify_data *data = user_data;
	struct bt_mcp_service *service = data->service;
	struct bt_gatt_client *client = service->mcp->client;
	uint16_t mtu = bt_gatt_client_get_mtu(client);

	DBG_SVC(service, "Notify %s", data->name);

	if (length == mtu - 3) {
		/* Probably truncated value */
		DBG_SVC(service, "Read %s", data->name);

		bt_gatt_client_read_value(client, value_handle,
						data->cb, service, NULL);
		return;
	}

	data->cb(true, 0xff, value, length, data->service);

	if (data->notify_cb)
		data->notify_cb(service);
}

static void foreach_mcs_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_mcp_service *service = user_data;
	struct bt_mcp *mcp = service->mcp;
	const struct {
		uint16_t uuid;
		const char *name;
		struct gatt_db_attribute **dst;
		bt_gatt_client_read_callback_t cb;
		void (*notify_cb)(struct bt_mcp_service *service);
		bool no_read;
		bool no_notify;
	} attrs[] = {
		{ MCS_CCID_CHRC_UUID, "CCID", &service->rdb.ccid,
		  update_ccid, .no_notify = true },
		{ MCS_MEDIA_PLAYER_NAME_CHRC_UUID, "Media Player Name",
		  &service->rdb.media_player_name, update_media_player_name,
		  .notify_cb = notify_media_player_name },
		{ MCS_TRACK_CHANGED_CHRC_UUID, "Track Changed",
		  &service->rdb.track_changed, update_track_changed,
		  .no_read = true },
		{ MCS_TRACK_TITLE_CHRC_UUID, "Track Title",
		  &service->rdb.track_title, update_track_title },
		{ MCS_TRACK_DURATION_CHRC_UUID, "Track Duration",
		  &service->rdb.track_duration, update_track_duration },
		{ MCS_TRACK_POSITION_CHRC_UUID, "Track Position",
		  &service->rdb.track_position, update_track_position },
		{ MCS_PLAYBACK_SPEED_CHRC_UUID, "Playback Speed",
		  &service->rdb.playback_speed, update_playback_speed },
		{ MCS_SEEKING_SPEED_CHRC_UUID, "Seeking Speed",
		  &service->rdb.seeking_speed, update_seeking_speed },
		{ MCS_PLAYING_ORDER_CHRC_UUID, "Playing Order",
		  &service->rdb.playing_order, update_playing_order },
		{ MCS_PLAYING_ORDER_SUPPORTED_CHRC_UUID,
		  "Playing Order Supported",
		  &service->rdb.playing_order_supported,
		  update_playing_order_supported, .no_notify = true },
		{ MCS_MEDIA_STATE_CHRC_UUID, "Media State",
		  &service->rdb.media_state, update_media_state },
		{ MCS_MEDIA_CP_CHRC_UUID, "Media Control Point",
		  &service->rdb.media_cp, update_media_cp },
		{ MCS_MEDIA_CP_OP_SUPPORTED_CHRC_UUID, "Media CP Op Supported",
		  &service->rdb.media_cp_op_supported,
		  update_media_cp_op_supported },
	};
	struct bt_gatt_client *client = service->mcp->client;
	bt_uuid_t uuid, uuid_attr;
	uint16_t value_handle;
	uint8_t props;
	unsigned int i;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
						&props, NULL, &uuid_attr))
		return;

	for (i = 0; i < ARRAY_SIZE(attrs); ++i) {
		unsigned int id;
		struct chrc_notify_data *data;

		if (*attrs[i].dst)
			continue;

		bt_uuid16_create(&uuid, attrs[i].uuid);
		if (bt_uuid_cmp(&uuid_attr, &uuid))
			continue;

		DBG_SVC(service, "%s found: handle 0x%04x",
						attrs[i].name, value_handle);
		*attrs[i].dst = attr;

		if ((props & BT_GATT_CHRC_PROP_READ) && !attrs[i].no_read)
			bt_gatt_client_read_value(client, value_handle,
						attrs[i].cb, service, NULL);

		if (!(props & BT_GATT_CHRC_PROP_NOTIFY) || attrs[i].no_notify)
			break;
		if (service->notify_id_count >= ARRAY_SIZE(service->notify_id))
			break;

		data = new0(struct chrc_notify_data, 1);
		data->name = attrs[i].name;
		data->service = service;
		data->cb = attrs[i].cb;

		id = bt_gatt_client_register_notify(client, value_handle,
						chrc_register, chrc_notify,
						data, free);
		if (id)
			service->notify_id[service->notify_id_count++] = id;
		else
			free(data);

		break;
	}

	if (!mcp->idle_id && i < ARRAY_SIZE(attrs))
		mcp->idle_id = bt_gatt_client_idle_register(mcp->client,
							mcp_idle, mcp, NULL);
}

static void foreach_mcs_ccid(struct gatt_db_attribute *attr, void *user_data)
{
	bt_uuid_t uuid, uuid_attr;

	if (!gatt_db_attribute_get_char_data(attr, NULL, NULL, NULL, NULL,
								&uuid_attr))
		return;

	bt_uuid16_create(&uuid, MCS_CCID_CHRC_UUID);
	if (bt_uuid_cmp(&uuid_attr, &uuid))
		return;

	foreach_mcs_char(attr, user_data);
}

static void listener_destroy(void *data)
{
	struct bt_mcp_listener *listener = data;

	if (listener->cb->destroy)
		listener->cb->destroy(listener->user_data);

	free(listener);
}

static void mcp_service_destroy(void *data)
{
	struct bt_mcp_service *service = data;
	struct bt_gatt_client *client = service->mcp->client;
	unsigned int i;

	mcp_cancel_pending_writes(service);

	queue_destroy(service->listeners, listener_destroy);

	for (i = 0; i < service->notify_id_count; ++i)
		bt_gatt_client_unregister_notify(client, service->notify_id[i]);

	queue_destroy(service->pending, free);
	free(service);
}

static void foreach_mcs_service(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_mcp *mcp = user_data;
	struct bt_mcp_service *service;
	bt_uuid_t uuid, uuid_attr;
	bool gmcs, mcs;

	DBG_MCP(mcp, "");

	if (!gatt_db_attribute_get_service_uuid(attr, &uuid_attr))
		return;

	bt_uuid16_create(&uuid, GMCS_UUID);
	gmcs = !bt_uuid_cmp(&uuid_attr, &uuid);

	if (gmcs != mcp->gmcs)
		return;

	bt_uuid16_create(&uuid, MCS_UUID);
	mcs = !bt_uuid_cmp(&uuid_attr, &uuid);

	if (!gmcs && !mcs)
		return;

	service = new0(struct bt_mcp_service, 1);
	service->mcp = mcp;
	service->rdb.gmcs = gmcs;
	service->rdb.service = attr;
	service->rdb.ccid_value = -1;
	service->pending = queue_new();
	service->listeners = queue_new();

	/* Find CCID first */
	gatt_db_service_foreach_char(attr, foreach_mcs_ccid, service);

	queue_push_tail(mcp->services, service);
}

static bool match_service_attr(const void *data, const void *user_data)
{
	const struct bt_mcp_service *service = data;

	return service->rdb.service == user_data;
}

static void mcp_service_added(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_mcp *mcp = user_data;

	foreach_mcs_service(attr, mcp);
}

static void mcp_service_removed(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_mcp *mcp = user_data;

	queue_remove_all(mcp->services, match_service_attr, attr,
							mcp_service_destroy);
}

struct bt_mcp *bt_mcp_attach(struct bt_gatt_client *client, bool gmcs,
			const struct bt_mcp_callback *cb, void *user_data)
{
	struct bt_mcp *mcp;
	struct gatt_db *db;
	bt_uuid_t uuid;

	if (!cb)
		return NULL;

	client = bt_gatt_client_clone(client);
	if (!client)
		return NULL;

	mcp = new0(struct bt_mcp, 1);
	mcp->gmcs = gmcs;
	mcp->client = client;
	mcp->services = queue_new();
	mcp->cb = cb;
	mcp->user_data = user_data;

	DBG_MCP(mcp, "");

	db = bt_gatt_client_get_db(client);

	bt_uuid16_create(&uuid, GMCS_UUID);
	gatt_db_foreach_service(db, &uuid, foreach_mcs_service, mcp);

	bt_uuid16_create(&uuid, MCS_UUID);
	gatt_db_foreach_service(db, &uuid, foreach_mcs_service, mcp);

	mcp->db_id = gatt_db_register(db, mcp_service_added,
						mcp_service_removed, mcp, NULL);

	if (!mcp->idle_id)
		mcp_idle(mcp);

	return mcp;
}

void bt_mcp_detach(struct bt_mcp *mcp)
{
	struct gatt_db *db;

	if (!mcp)
		return;

	DBG_MCP(mcp, "");

	queue_destroy(mcp->services, mcp_service_destroy);

	if (mcp->cb->destroy)
		mcp->cb->destroy(mcp->user_data);

	if (mcp->idle_id)
		bt_gatt_client_idle_unregister(mcp->client, mcp->idle_id);

	db = bt_gatt_client_get_db(mcp->client);
	if (mcp->db_id)
		gatt_db_unregister(db, mcp->db_id);

	bt_gatt_client_unref(mcp->client);

	free(mcp);
}

bool bt_mcp_add_listener(struct bt_mcp *mcp, uint8_t ccid,
				const struct bt_mcp_listener_callback *cb,
				void *user_data)
{
	struct bt_mcp_listener *listener;
	struct bt_mcp_service *service;

	if (!cb)
		return false;

	service = queue_find(mcp->services, match_ccid, UINT_TO_PTR(ccid));
	if (!service)
		return false;

	listener = new0(struct bt_mcp_listener, 1);
	listener->cb = cb;
	listener->user_data = user_data;

	queue_push_tail(service->listeners, listener);
	return true;
}
