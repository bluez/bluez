// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
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
#include "src/shared/timeout.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"
#include "src/shared/vcp.h"

#define DBG(_vcp, fmt, arg...) \
	vcp_debug(_vcp, "%s:%s() " fmt, __FILE__, __func__, ## arg)

#define VCP_STEP_SIZE 1

/* Apllication Error Code */
#define BT_ATT_ERROR_INVALID_CHANGE_COUNTER	0x80
#define BT_ATT_ERROR_OPCODE_NOT_SUPPORTED	0x81

struct bt_vcp_db {
	struct gatt_db *db;
	struct bt_vcs *vcs;
};

typedef void (*vcp_func_t)(struct bt_vcp *vcp, bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data);

struct bt_vcp_pending {
	unsigned int id;
	struct bt_vcp *vcp;
	vcp_func_t func;
	void *user_data;
};

struct bt_vcs_param {
	uint8_t	op;
	uint8_t	change_counter;
} __packed;

struct bt_vcs_ab_vol {
	uint8_t	change_counter;
	uint8_t	vol_set;
} __packed;

struct bt_vcp_cb {
	unsigned int id;
	bt_vcp_func_t attached;
	bt_vcp_func_t detached;
	void *user_data;
};

typedef void (*vcp_notify_t)(struct bt_vcp *vcp, uint16_t value_handle,
				const uint8_t *value, uint16_t length,
				void *user_data);

struct bt_vcp_notify {
	unsigned int id;
	struct bt_vcp *vcp;
	vcp_notify_t func;
	void *user_data;
};

struct bt_vcp {
	int ref_count;
	struct bt_vcp_db *ldb;
	struct bt_vcp_db *rdb;
	struct bt_gatt_client *client;
	struct bt_att *att;
	unsigned int vstate_id;
	unsigned int vflag_id;

	struct queue *notify;
	struct queue *pending;

	bt_vcp_debug_func_t debug_func;
	bt_vcp_destroy_func_t debug_destroy;
	void *debug_data;
	void *user_data;
};

#define RESET_VOLUME_SETTING 0x00
#define USERSET_VOLUME_SETTING 0x01

/* Contains local bt_vcp_db */
struct vol_state {
	uint8_t	vol_set;
	uint8_t	mute;
	uint8_t counter;
} __packed;

struct bt_vcs {
	struct bt_vcp_db *vdb;
	struct vol_state *vstate;
	uint8_t vol_flag;
	struct gatt_db_attribute *service;
	struct gatt_db_attribute *vs;
	struct gatt_db_attribute *vs_ccc;
	struct gatt_db_attribute *vol_cp;
	struct gatt_db_attribute *vf;
	struct gatt_db_attribute *vf_ccc;
};

static struct queue *vcp_db;
static struct queue *vcp_cbs;
static struct queue *sessions;

static void *iov_pull_mem(struct iovec *iov, size_t len)
{
	void *data = iov->iov_base;

	if (iov->iov_len < len)
		return NULL;

	iov->iov_base += len;
	iov->iov_len -= len;

	return data;
}

static struct bt_vcp_db *vcp_get_vdb(struct bt_vcp *vcp)
{
	if (!vcp)
		return NULL;

	if (vcp->ldb)
		return vcp->ldb;

	return NULL;
}

static struct vol_state *vdb_get_vstate(struct bt_vcp_db *vdb)
{
	if (!vdb->vcs)
		return NULL;

	if (vdb->vcs->vstate)
		return vdb->vcs->vstate;

	return NULL;
}

static struct bt_vcs *vcp_get_vcs(struct bt_vcp *vcp)
{
	if (!vcp)
		return NULL;

	if (vcp->rdb->vcs)
		return vcp->rdb->vcs;

	vcp->rdb->vcs = new0(struct bt_vcs, 1);
	vcp->rdb->vcs->vdb = vcp->rdb;

	return vcp->rdb->vcs;
}

static void vcp_detached(void *data, void *user_data)
{
	struct bt_vcp_cb *cb = data;
	struct bt_vcp *vcp = user_data;

	cb->detached(vcp, cb->user_data);
}

void bt_vcp_detach(struct bt_vcp *vcp)
{
	if (!queue_remove(sessions, vcp))
		return;

	bt_gatt_client_unref(vcp->client);
	vcp->client = NULL;

	queue_foreach(vcp_cbs, vcp_detached, vcp);
}

static void vcp_db_free(void *data)
{
	struct bt_vcp_db *vdb = data;

	if (!vdb)
		return;

	gatt_db_unref(vdb->db);

	free(vdb->vcs);
	free(vdb);
}

static void vcp_free(void *data)
{
	struct bt_vcp *vcp = data;

	bt_vcp_detach(vcp);

	vcp_db_free(vcp->rdb);

	queue_destroy(vcp->pending, NULL);

	free(vcp);
}
bool bt_vcp_set_user_data(struct bt_vcp *vcp, void *user_data)
{
	if (!vcp)
		return false;

	vcp->user_data = user_data;

	return true;
}

static bool vcp_db_match(const void *data, const void *match_data)
{
	const struct bt_vcp_db *vdb = data;
	const struct gatt_db *db = match_data;

	return (vdb->db == db);
}

struct bt_att *bt_vcp_get_att(struct bt_vcp *vcp)
{
	if (!vcp)
		return NULL;

	if (vcp->att)
		return vcp->att;

	return bt_gatt_client_get_att(vcp->client);
}

struct bt_vcp *bt_vcp_ref(struct bt_vcp *vcp)
{
	if (!vcp)
		return NULL;

	__sync_fetch_and_add(&vcp->ref_count, 1);

	return vcp;
}

void bt_vcp_unref(struct bt_vcp *vcp)
{
	if (!vcp)
		return;

	if (__sync_sub_and_fetch(&vcp->ref_count, 1))
		return;

	vcp_free(vcp);
}

static void vcp_debug(struct bt_vcp *vcp, const char *format, ...)
{
	va_list ap;

	if (!vcp || !format || !vcp->debug_func)
		return;

	va_start(ap, format);
	util_debug_va(vcp->debug_func, vcp->debug_data, format, ap);
	va_end(ap);
}

static void vcp_disconnected(int err, void *user_data)
{
	struct bt_vcp *vcp = user_data;

	DBG(vcp, "vcp %p disconnected err %d", vcp, err);

	bt_vcp_detach(vcp);
}

static struct bt_vcp *vcp_get_session(struct bt_att *att, struct gatt_db *db)
{
	const struct queue_entry *entry;
	struct bt_vcp *vcp;

	for (entry = queue_get_entries(sessions); entry; entry = entry->next) {
		struct bt_vcp *vcp = entry->data;

		if (att == bt_vcp_get_att(vcp))
			return vcp;
	}

	vcp = bt_vcp_new(db, NULL);
	vcp->att = att;

	bt_att_register_disconnect(att, vcp_disconnected, vcp, NULL);

	bt_vcp_attach(vcp, NULL);

	return vcp;

}

static uint8_t vcs_rel_vol_down(struct bt_vcs *vcs, struct bt_vcp *vcp,
				struct iovec *iov)
{
	struct bt_vcp_db *vdb;
	struct vol_state *vstate;
	uint8_t	*change_counter;

	DBG(vcp, "Volume Down");

	vdb = vcp_get_vdb(vcp);
	if (!vdb) {
		DBG(vcp, "error: VDB not available");
		return 0;
	}

	vstate = vdb_get_vstate(vdb);
	if (!vstate) {
		DBG(vcp, "error: VSTATE not available");
		return 0;
	}

	change_counter = iov_pull_mem(iov, sizeof(*change_counter));
	if (!change_counter)
		return 0;

	if (*change_counter != vstate->counter) {
		DBG(vcp, "Change Counter Mismatch Volume not decremented!");
		return BT_ATT_ERROR_INVALID_CHANGE_COUNTER;
	}

	vstate->vol_set = MAX((vstate->vol_set - VCP_STEP_SIZE), 0);
	vstate->counter = -~vstate->counter; /*Increment Change Counter*/

	gatt_db_attribute_notify(vdb->vcs->vs, (void *)vstate,
				 sizeof(struct vol_state),
				 bt_vcp_get_att(vcp));
	return 0;
}

static uint8_t vcs_rel_vol_up(struct bt_vcs *vcs, struct bt_vcp *vcp,
				struct iovec *iov)
{
	struct bt_vcp_db *vdb;
	struct vol_state *vstate;
	uint8_t	*change_counter;

	DBG(vcp, "Volume Up");

	vdb = vcp_get_vdb(vcp);
	if (!vdb) {
		DBG(vcp, "error: VDB not available");
		return 0;
	}

	vstate = vdb_get_vstate(vdb);
	if (!vstate) {
		DBG(vcp, "error: VCP database not available");
		return 0;
	}

	change_counter = iov_pull_mem(iov, sizeof(*change_counter));
	if (!change_counter)
		return 0;

	if (*change_counter != vstate->counter) {
		DBG(vcp, "Change Counter Mismatch Volume not decremented!");
		return BT_ATT_ERROR_INVALID_CHANGE_COUNTER;
	}

	vstate->vol_set = MIN((vstate->vol_set + VCP_STEP_SIZE), 255);
	vstate->counter = -~vstate->counter; /*Increment Change Counter*/

	gatt_db_attribute_notify(vdb->vcs->vs, (void *)vstate,
				 sizeof(struct vol_state),
				 bt_vcp_get_att(vcp));
	return 0;
}

static uint8_t vcs_unmute_rel_vol_down(struct bt_vcs *vcs, struct bt_vcp *vcp,
				struct iovec *iov)
{
	struct bt_vcp_db *vdb;
	struct vol_state *vstate;
	uint8_t	*change_counter;

	DBG(vcp, "Un Mute and Volume Down");

	vdb = vcp_get_vdb(vcp);
	if (!vdb) {
		DBG(vcp, "error: VDB not available");
		return 0;
	}

	vstate = vdb_get_vstate(vdb);
	if (!vstate) {
		DBG(vcp, "error: VCP database not available");
		return 0;
	}

	change_counter = iov_pull_mem(iov, sizeof(*change_counter));
	if (!change_counter)
		return 0;

	if (*change_counter != vstate->counter) {
		DBG(vcp, "Change Counter Mismatch Volume not decremented!");
		return BT_ATT_ERROR_INVALID_CHANGE_COUNTER;
	}

	vstate->mute = 0x00;
	vstate->vol_set = MAX((vstate->vol_set - VCP_STEP_SIZE), 0);
	vstate->counter = -~vstate->counter; /*Increment Change Counter*/

	gatt_db_attribute_notify(vdb->vcs->vs, (void *)vstate,
				 sizeof(struct vol_state),
				 bt_vcp_get_att(vcp));
	return 0;
}

static uint8_t vcs_unmute_rel_vol_up(struct bt_vcs *vcs, struct bt_vcp *vcp,
				struct iovec *iov)
{
	struct bt_vcp_db *vdb;
	struct vol_state *vstate;
	uint8_t	*change_counter;

	DBG(vcp, "UN Mute and Volume Up");

	vdb = vcp_get_vdb(vcp);
	if (!vdb) {
		DBG(vcp, "error: VDB not available");
		return 0;
	}

	vstate = vdb_get_vstate(vdb);
	if (!vstate) {
		DBG(vcp, "error: VSTATE not available");
		return 0;
	}

	change_counter = iov_pull_mem(iov, sizeof(*change_counter));
	if (!change_counter)
		return 0;

	if (*change_counter != vstate->counter) {
		DBG(vcp, "Change Counter Mismatch Volume not decremented!");
		return BT_ATT_ERROR_INVALID_CHANGE_COUNTER;
	}

	vstate->mute = 0x00;
	vstate->vol_set = MIN((vstate->vol_set + VCP_STEP_SIZE), 255);
	vstate->counter = -~vstate->counter; /*Increment Change Counter*/

	gatt_db_attribute_notify(vdb->vcs->vs, (void *)vstate,
				 sizeof(struct vol_state),
				 bt_vcp_get_att(vcp));
	return 0;
}

static uint8_t vcs_set_absolute_vol(struct bt_vcs *vcs, struct bt_vcp *vcp,
				struct iovec *iov)
{
	struct bt_vcp_db *vdb;
	struct vol_state *vstate;
	struct bt_vcs_ab_vol *req;

	DBG(vcp, "Set Absolute Volume");

	vdb = vcp_get_vdb(vcp);
	if (!vdb) {
		DBG(vcp, "error: VDB not available");
		return 0;
	}

	vstate = vdb_get_vstate(vdb);
	if (!vstate) {
		DBG(vcp, "error: VSTATE not available");
		return 0;
	}

	req = iov_pull_mem(iov, sizeof(*req));
	if (!req)
		return 0;

	if (req->change_counter != vstate->counter) {
		DBG(vcp, "Change Counter Mismatch Volume not decremented!");
		return BT_ATT_ERROR_INVALID_CHANGE_COUNTER;
	}

	vstate->vol_set = req->vol_set;
	vstate->counter = -~vstate->counter; /*Increment Change Counter*/

	gatt_db_attribute_notify(vdb->vcs->vs, (void *)vstate,
				 sizeof(struct vol_state),
				 bt_vcp_get_att(vcp));
	return 0;
}

static uint8_t vcs_unmute(struct bt_vcs *vcs, struct bt_vcp *vcp,
				struct iovec *iov)
{
	struct bt_vcp_db *vdb;
	struct vol_state *vstate;
	uint8_t	*change_counter;

	DBG(vcp, "Un Mute");

	vdb = vcp_get_vdb(vcp);
	if (!vdb) {
		DBG(vcp, "error: VDB not available");
		return 0;
	}

	vstate = vdb_get_vstate(vdb);
	if (!vstate) {
		DBG(vcp, "error: VSTATE not available");
		return 0;
	}

	change_counter = iov_pull_mem(iov, sizeof(*change_counter));
	if (!change_counter)
		return 0;

	if (*change_counter != vstate->counter) {
		DBG(vcp, "Change Counter Mismatch Volume not decremented!");
		return BT_ATT_ERROR_INVALID_CHANGE_COUNTER;
	}

	vstate->mute = 0x00;
	vstate->counter = -~vstate->counter; /*Increment Change Counter*/

	gatt_db_attribute_notify(vdb->vcs->vs, (void *)vstate,
				 sizeof(struct vol_state),
				 bt_vcp_get_att(vcp));
	return 0;
}

static uint8_t vcs_mute(struct bt_vcs *vcs, struct bt_vcp *vcp,
				struct iovec *iov)
{
	struct bt_vcp_db *vdb;
	struct vol_state *vstate;
	uint8_t	*change_counter;

	DBG(vcp, "MUTE");

	vdb = vcp_get_vdb(vcp);
	if (!vdb) {
		DBG(vcp, "error: VDB not available");
		return 0;
	}

	vstate = vdb_get_vstate(vdb);
	if (!vstate) {
		DBG(vcp, "error: VSTATE not available");
		return 0;
	}

	change_counter = iov_pull_mem(iov, sizeof(*change_counter));
	if (!change_counter)
		return 0;

	if (*change_counter != vstate->counter) {
		DBG(vcp, "Change Counter Mismatch Volume not decremented!");
		return BT_ATT_ERROR_INVALID_CHANGE_COUNTER;
	}

	vstate->mute = 0x01;
	vstate->counter = -~vstate->counter; /*Increment Change Counter*/

	return 0;
}

#define	BT_VCS_REL_VOL_DOWN		0x00
#define	BT_VCS_REL_VOL_UP		0x01
#define	BT_VCS_UNMUTE_REL_VOL_DOWN	0x02
#define	BT_VCS_UNMUTE_REL_VOL_UP	0x03
#define	BT_VCS_SET_ABSOLUTE_VOL		0x04
#define	BT_VCS_UNMUTE			0x05
#define	BT_VCS_MUTE			0x06

#define VCS_OP(_str, _op, _size, _func) \
	{ \
		.str = _str, \
		.op = _op, \
		.size = _size, \
		.func = _func, \
	}

struct vcs_op_handler {
	const char *str;
	uint8_t	op;
	size_t	size;
	uint8_t	(*func)(struct bt_vcs *vcs, struct bt_vcp *vcp,
			struct iovec *iov);
} vcp_handlers[] = {
	VCS_OP("Relative Volume Down", BT_VCS_REL_VOL_DOWN,
		sizeof(uint8_t), vcs_rel_vol_down),
	VCS_OP("Relative Volume Up", BT_VCS_REL_VOL_UP,
		sizeof(uint8_t), vcs_rel_vol_up),
	VCS_OP("Unmute - Relative Volume Down", BT_VCS_UNMUTE_REL_VOL_DOWN,
		sizeof(uint8_t), vcs_unmute_rel_vol_down),
	VCS_OP("Unmute - Relative Volume Up", BT_VCS_UNMUTE_REL_VOL_UP,
		sizeof(uint8_t), vcs_unmute_rel_vol_up),
	VCS_OP("Set Absolute Volume", BT_VCS_SET_ABSOLUTE_VOL,
		sizeof(struct bt_vcs_ab_vol), vcs_set_absolute_vol),
	VCS_OP("UnMute", BT_VCS_UNMUTE,
		sizeof(uint8_t), vcs_unmute),
	VCS_OP("Mute", BT_VCS_MUTE,
		sizeof(uint8_t), vcs_mute),
	{}
};

static void vcs_cp_write(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				const uint8_t *value, size_t len,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_vcs *vcs = user_data;
	struct bt_vcp *vcp = vcp_get_session(att, vcs->vdb->db);
	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len = len,
	};
	uint8_t	*vcp_op;
	struct vcs_op_handler *handler;
	uint8_t ret = BT_ATT_ERROR_REQUEST_NOT_SUPPORTED;

	DBG(vcp, "VCP Control Point Write");

	if (offset) {
		DBG(vcp, "invalid offset %d", offset);
		ret = BT_ATT_ERROR_INVALID_OFFSET;
		goto respond;
	}

	if (len < sizeof(*vcp_op)) {
		DBG(vcp, "invalid len %ld < %ld sizeof(*param)", len,
							sizeof(*vcp_op));
		ret = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto respond;
	}

	vcp_op = iov_pull_mem(&iov, sizeof(*vcp_op));

	for (handler = vcp_handlers; handler && handler->str; handler++) {
		if (handler->op != *vcp_op)
			continue;

		if (iov.iov_len < handler->size) {
			DBG(vcp, "invalid len %ld < %ld handler->size", len,
			    handler->size);
			ret = BT_ATT_ERROR_OPCODE_NOT_SUPPORTED;
			goto respond;
		}

		break;
	}

	if (handler && handler->str) {
		DBG(vcp, "%s", handler->str);

		ret = handler->func(vcs, vcp, &iov);
	} else {
		DBG(vcp, "Unknown opcode 0x%02x", *vcp_op);
		ret = BT_ATT_ERROR_OPCODE_NOT_SUPPORTED;
	}

respond:
	gatt_db_attribute_write_result(attrib, id, ret);
}

static void vcs_state_read(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_vcs *vcs = user_data;
	struct iovec iov;

	iov.iov_base = vcs->vstate;
	iov.iov_len = sizeof(*vcs->vstate);

	gatt_db_attribute_read_result(attrib, id, 0, iov.iov_base,
							iov.iov_len);
}

static void vcs_flag_read(struct gatt_db_attribute *attrib,
				unsigned int id, uint16_t offset,
				uint8_t opcode, struct bt_att *att,
				void *user_data)
{
	struct bt_vcs *vcs = user_data;
	struct iovec iov;

	iov.iov_base = &vcs->vol_flag;
	iov.iov_len = sizeof(vcs->vol_flag);

	gatt_db_attribute_read_result(attrib, id, 0, iov.iov_base,
							iov.iov_len);
}

static struct bt_vcs *vcs_new(struct gatt_db *db)
{
	struct bt_vcs *vcs;
	struct vol_state *vstate;
	bt_uuid_t uuid;

	if (!db)
		return NULL;

	vcs = new0(struct bt_vcs, 1);

	vstate = new0(struct vol_state, 1);

	vcs->vstate = vstate;
	vcs->vol_flag = USERSET_VOLUME_SETTING;

	/* Populate DB with VCS attributes */
	bt_uuid16_create(&uuid, VCS_UUID);
	vcs->service = gatt_db_add_service(db, &uuid, true, 9);

	bt_uuid16_create(&uuid, VOL_STATE_CHRC_UUID);
	vcs->vs = gatt_db_service_add_characteristic(vcs->service,
					&uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					vcs_state_read, NULL,
					vcs);

	vcs->vs_ccc = gatt_db_service_add_ccc(vcs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	bt_uuid16_create(&uuid, VOL_CP_CHRC_UUID);
	vcs->vol_cp = gatt_db_service_add_characteristic(vcs->service,
					&uuid,
					BT_ATT_PERM_WRITE,
					BT_GATT_CHRC_PROP_WRITE,
					NULL, vcs_cp_write,
					vcs);

	bt_uuid16_create(&uuid, VOL_FLAG_CHRC_UUID);
	vcs->vf = gatt_db_service_add_characteristic(vcs->service,
					&uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_NOTIFY,
					vcs_flag_read, NULL,
					vcs);

	vcs->vf_ccc = gatt_db_service_add_ccc(vcs->service,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);


	gatt_db_service_set_active(vcs->service, true);

	return vcs;
}

static struct bt_vcp_db *vcp_db_new(struct gatt_db *db)
{
	struct bt_vcp_db *vdb;

	if (!db)
		return NULL;

	vdb = new0(struct bt_vcp_db, 1);
	vdb->db = gatt_db_ref(db);

	if (!vcp_db)
		vcp_db = queue_new();

	vdb->vcs = vcs_new(db);
	vdb->vcs->vdb = vdb;

	queue_push_tail(vcp_db, vdb);

	return vdb;
}

static struct bt_vcp_db *vcp_get_db(struct gatt_db *db)
{
	struct bt_vcp_db *vdb;

	vdb = queue_find(vcp_db, vcp_db_match, db);
	if (vdb)
		return vdb;

	return vcp_db_new(db);
}

void bt_vcp_add_db(struct gatt_db *db)
{
	vcp_db_new(db);
}

bool bt_vcp_set_debug(struct bt_vcp *vcp, bt_vcp_debug_func_t func,
			void *user_data, bt_vcp_destroy_func_t destroy)
{
	if (!vcp)
		return false;

	if (vcp->debug_destroy)
		vcp->debug_destroy(vcp->debug_data);

	vcp->debug_func = func;
	vcp->debug_destroy = destroy;
	vcp->debug_data = user_data;

	return true;
}

unsigned int bt_vcp_register(bt_vcp_func_t attached, bt_vcp_func_t detached,
							void *user_data)
{
	struct bt_vcp_cb *cb;
	static unsigned int id;

	if (!attached && !detached)
		return 0;

	if (!vcp_cbs)
		vcp_cbs = queue_new();

	cb = new0(struct bt_vcp_cb, 1);
	cb->id = ++id ? id : ++id;
	cb->attached = attached;
	cb->detached = detached;
	cb->user_data = user_data;

	queue_push_tail(vcp_cbs, cb);

	return cb->id;
}

static bool match_id(const void *data, const void *match_data)
{
	const struct bt_vcp_cb *cb = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return (cb->id == id);
}

bool bt_vcp_unregister(unsigned int id)
{
	struct bt_vcp_cb *cb;

	cb = queue_remove_if(vcp_cbs, match_id, UINT_TO_PTR(id));
	if (!cb)
		return false;

	free(cb);

	return true;
}

struct bt_vcp *bt_vcp_new(struct gatt_db *ldb, struct gatt_db *rdb)
{
	struct bt_vcp *vcp;
	struct bt_vcp_db *vdb;

	if (!ldb)
		return NULL;

	vdb = vcp_get_db(ldb);
	if (!vdb)
		return NULL;

	vcp = new0(struct bt_vcp, 1);
	vcp->ldb = vdb;
	vcp->pending = queue_new();

	if (!rdb)
		goto done;

	vdb = new0(struct bt_vcp_db, 1);
	vdb->db = gatt_db_ref(rdb);

	vcp->rdb = vdb;

done:
	bt_vcp_ref(vcp);

	return vcp;
}

static void vcp_vstate_notify(struct bt_vcp *vcp, uint16_t value_handle,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct vol_state vstate;

	memcpy(&vstate, value, sizeof(struct vol_state));

	DBG(vcp, "Vol Settings 0x%x", vstate.vol_set);
	DBG(vcp, "Mute Status 0x%x", vstate.mute);
	DBG(vcp, "Vol Counter 0x%x", vstate.counter);
}

static void vcp_vflag_notify(struct bt_vcp *vcp, uint16_t value_handle,
			     const uint8_t *value, uint16_t length,
			     void *user_data)
{
	uint8_t vflag;

	memcpy(&vflag, value, sizeof(vflag));

	DBG(vcp, "Vol Flag 0x%x", vflag);
}

static void read_vol_flag(struct bt_vcp *vcp, bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	uint8_t *vol_flag;
	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len = length,
	};

	if (!success) {
		DBG(vcp, "Unable to read Vol Flag: error 0x%02x", att_ecode);
		return;
	}

	vol_flag = iov_pull_mem(&iov, sizeof(*vol_flag));
	if (!vol_flag) {
		DBG(vcp, "Unable to get Vol Flag");
		return;
	}

	DBG(vcp, "Vol Flag:%x", *vol_flag);
}

static void read_vol_state(struct bt_vcp *vcp, bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct vol_state *vs;
	struct iovec iov = {
		.iov_base = (void *) value,
		.iov_len = length,
	};

	if (!success) {
		DBG(vcp, "Unable to read Vol State: error 0x%02x", att_ecode);
		return;
	}

	vs = iov_pull_mem(&iov, sizeof(*vs));
	if (!vs) {
		DBG(vcp, "Unable to get Vol State");
		return;
	}

	DBG(vcp, "Vol Set:%x", vs->vol_set);
	DBG(vcp, "Vol Mute:%x", vs->mute);
	DBG(vcp, "Vol Counter:%x", vs->counter);
}

static void vcp_pending_destroy(void *data)
{
	struct bt_vcp_pending *pending = data;
	struct bt_vcp *vcp = pending->vcp;

	if (queue_remove_if(vcp->pending, NULL, pending))
		free(pending);
}

static void vcp_pending_complete(bool success, uint8_t att_ecode,
				const uint8_t *value, uint16_t length,
				void *user_data)
{
	struct bt_vcp_pending *pending = user_data;

	if (pending->func)
		pending->func(pending->vcp, success, att_ecode, value, length,
						pending->user_data);
}

static void vcp_read_value(struct bt_vcp *vcp, uint16_t value_handle,
				vcp_func_t func, void *user_data)
{
	struct bt_vcp_pending *pending;

	pending = new0(struct bt_vcp_pending, 1);
	pending->vcp = vcp;
	pending->func = func;
	pending->user_data = user_data;

	pending->id = bt_gatt_client_read_value(vcp->client, value_handle,
						vcp_pending_complete, pending,
						vcp_pending_destroy);
	if (!pending->id) {
		DBG(vcp, "Unable to send Read request");
		free(pending);
		return;
	}

	queue_push_tail(vcp->pending, pending);
}

static void vcp_register(uint16_t att_ecode, void *user_data)
{
	struct bt_vcp_notify *notify = user_data;

	if (att_ecode)
		DBG(notify->vcp, "VCP register failed: 0x%04x", att_ecode);
}

static void vcp_notify(uint16_t value_handle, const uint8_t *value,
				uint16_t length, void *user_data)
{
	struct bt_vcp_notify *notify = user_data;

	if (notify->func)
		notify->func(notify->vcp, value_handle, value, length,
						notify->user_data);
}

static void vcp_notify_destroy(void *data)
{
	struct bt_vcp_notify *notify = data;
	struct bt_vcp *vcp = notify->vcp;

	if (queue_remove_if(vcp->notify, NULL, notify))
		free(notify);
}

static unsigned int vcp_register_notify(struct bt_vcp *vcp,
					uint16_t value_handle,
					vcp_notify_t func,
					void *user_data)
{
	struct bt_vcp_notify *notify;

	notify = new0(struct bt_vcp_notify, 1);
	notify->vcp = vcp;
	notify->func = func;
	notify->user_data = user_data;

	notify->id = bt_gatt_client_register_notify(vcp->client,
						value_handle, vcp_register,
						vcp_notify, notify,
						vcp_notify_destroy);
	if (!notify->id) {
		DBG(vcp, "Unable to register for notifications");
		free(notify);
		return 0;
	}

	queue_push_tail(vcp->notify, notify);

	return notify->id;
}

static void foreach_vcs_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_vcp *vcp = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid, uuid_vstate, uuid_cp, uuid_vflag;
	struct bt_vcs *vcs;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
						NULL, NULL, &uuid))
		return;

	bt_uuid16_create(&uuid_vstate, VOL_STATE_CHRC_UUID);
	bt_uuid16_create(&uuid_cp, VOL_CP_CHRC_UUID);
	bt_uuid16_create(&uuid_vflag, VOL_FLAG_CHRC_UUID);

	if (!bt_uuid_cmp(&uuid, &uuid_vstate)) {
		DBG(vcp, "VCS Vol state found: handle 0x%04x", value_handle);

		vcs = vcp_get_vcs(vcp);
		if (!vcs || vcs->vs)
			return;

		vcs->vs = attr;

		vcp_read_value(vcp, value_handle, read_vol_state, vcp);

		vcp->vstate_id = vcp_register_notify(vcp, value_handle,
						     vcp_vstate_notify, NULL);

		return;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_cp)) {
		DBG(vcp, "VCS Volume CP found: handle 0x%04x", value_handle);

		vcs = vcp_get_vcs(vcp);
		if (!vcs || vcs->vol_cp)
			return;

		vcs->vol_cp = attr;

		return;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_vflag)) {
		DBG(vcp, "VCS Vol Flag found: handle 0x%04x", value_handle);

		vcs = vcp_get_vcs(vcp);
		if (!vcs || vcs->vf)
			return;

		vcs->vf = attr;

		vcp_read_value(vcp, value_handle, read_vol_flag, vcp);
		vcp->vflag_id = vcp_register_notify(vcp, value_handle,
						    vcp_vflag_notify, NULL);

	}
}

static void foreach_vcs_service(struct gatt_db_attribute *attr,
						void *user_data)
{
	struct bt_vcp *vcp = user_data;
	struct bt_vcs *vcs = vcp_get_vcs(vcp);

	vcs->service = attr;

	gatt_db_service_set_claimed(attr, true);

	gatt_db_service_foreach_char(attr, foreach_vcs_char, vcp);
}

bool bt_vcp_attach(struct bt_vcp *vcp, struct bt_gatt_client *client)
{
	bt_uuid_t uuid;

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, vcp);

	if (!client)
		return true;

	if (vcp->client)
		return false;

	vcp->client = bt_gatt_client_clone(client);
	if (!vcp->client)
		return false;

	bt_uuid16_create(&uuid, VCS_UUID);
	gatt_db_foreach_service(vcp->ldb->db, &uuid, foreach_vcs_service, vcp);

	return true;
}

