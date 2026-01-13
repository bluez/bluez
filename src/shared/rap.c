/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define _GNU_SOURCE
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/uuid.h"

#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "src/shared/timeout.h"
#include "src/log.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"
#include "src/shared/rap.h"

#define RAS_UUID16			        0x185B
#define RAS_FEATURES_UUID		    0x2C14
#define RAS_REALTIME_DATA_UUID	    0x2C15
#define RAS_ONDEMAND_DATA_UUID	    0x2C16
#define RAS_CONTROL_POINT_UUID	    0x2C17
#define RAS_DATA_READY_UUID		    0x2C18
#define RAS_DATA_OVERWRITTEN_UUID	0x2C19

/* Total number of attribute handles reserved for the RAS service */
#define RAS_TOTAL_NUM_HANDLES		18

/* Ranging Service context */
struct ras {
	struct bt_rap_db *rapdb;

	/* Service and characteristic attributes */
	struct gatt_db_attribute *svc;
	struct gatt_db_attribute *feat_chrc;
	struct gatt_db_attribute *realtime_chrc;
	struct gatt_db_attribute *realtime_chrc_ccc;
	struct gatt_db_attribute *ondemand_chrc;
	struct gatt_db_attribute *cp_chrc;
	struct gatt_db_attribute *ready_chrc;
	struct gatt_db_attribute *overwritten_chrc;
};

struct bt_rap_db {
	struct gatt_db *db;
	struct ras *ras;
};

struct bt_rap {
	int ref_count;
	struct bt_rap_db *lrapdb;
	struct bt_rap_db *rrapdb;
	struct bt_gatt_client *client;
	struct bt_att *att;

	unsigned int idle_id;

	struct queue *notify;
	struct queue *pending;
	struct queue *ready_cbs;

	void *user_data;
};

static struct queue *rap_db;
static struct queue *bt_rap_cbs;
static struct queue *sessions;

struct bt_rap_cb {
	unsigned int id;
	bt_rap_func_t attached;
	bt_rap_func_t detached;
	void *user_data;
};

typedef void (*rap_func_t)(struct bt_rap *rap, bool success,
			   uint8_t att_ecode, const uint8_t *value,
			   uint16_t length, void *user_data);

struct bt_rap_pending {
	unsigned int id;
	struct bt_rap *rap;
	rap_func_t func;
	void *userdata;
};

struct bt_rap_ready {
	unsigned int id;
	bt_rap_ready_func_t func;
	bt_rap_destroy_func_t destroy;
	void *data;
};

typedef void (*rap_notify_t)(struct bt_rap *rap, uint16_t value_handle,
			     const uint8_t *value, uint16_t length,
			     void *user_data);

struct bt_rap_notify {
	unsigned int id;
	struct bt_rap *rap;
	rap_notify_t func;
	void *user_data;
};

static bool real_time_enabled;
static bool on_demand_enabled;
struct gatt_db_attribute *global_real_time_char;
struct gatt_db_attribute *global_on_demand_char;
struct gatt_db_attribute *global_data_ready_char;
struct gatt_db_attribute *global_data_overwritten_char;
struct gatt_db_attribute *global_control_point_char;

static struct bt_rap_db *rap_get_rapdb(struct bt_rap *rap)
{
	if (!rap)
		return NULL;

	if (rap->lrapdb)
		return rap->lrapdb;

	return NULL;
}

struct ras *rap_get_ras(struct bt_rap *rap)
{
	if (!rap)
		return NULL;

	if (rap->rrapdb->ras)
		return rap->rrapdb->ras;

	rap->rrapdb->ras = new0(struct ras, 1);
	rap->rrapdb->ras->rapdb = rap->rrapdb;

	return rap->rrapdb->ras;
}

static void rap_detached(void *data, void *user_data)
{
	struct bt_rap_cb *cb = data;
	struct bt_rap *rap = user_data;

	cb->detached(rap, cb->user_data);
}

void bt_rap_detach(struct bt_rap *rap)
{
	if (!queue_remove(sessions, rap))
		return;

	bt_gatt_client_idle_unregister(rap->client, rap->idle_id);
	bt_gatt_client_unref(rap->client);
	rap->client = NULL;

	queue_foreach(bt_rap_cbs, rap_detached, rap);
}

static void rap_db_free(void *data)
{
	struct bt_rap_db *rapdb = data;

	if (!rapdb)
		return;

	gatt_db_unref(rapdb->db);

	free(rapdb->ras);
	free(rapdb);
}

static void rap_ready_free(void *data)
{
	struct bt_rap_ready *ready = data;

	if (ready->destroy)
		ready->destroy(ready->data);

	free(ready);
}

static void rap_free(void *data)
{
	struct bt_rap *rap = data;

	bt_rap_detach(rap);

	rap_db_free(rap->rrapdb);

	queue_destroy(rap->notify, free);
	queue_destroy(rap->pending, NULL);
	queue_destroy(rap->ready_cbs, rap_ready_free);

	free(rap);
}

bool bt_rap_set_user_data(struct bt_rap *rap, void *user_data)
{
	if (!rap)
		return false;

	rap->user_data = user_data;

	return true;
}

static bool rap_db_match(const void *data, const void *match_data)
{
	const struct bt_rap_db *rapdb = data;
	const struct gatt_db *db = match_data;

	return rapdb->db == db;
}

struct bt_att *bt_rap_get_att(struct bt_rap *rap)
{
	if (!rap)
		return NULL;

	if (rap->att)
		return rap->att;

	return bt_gatt_client_get_att(rap->client);
}

struct bt_rap *bt_rap_ref(struct bt_rap *rap)
{
	if (!rap)
		return NULL;

	__sync_fetch_and_add(&rap->ref_count, 1);

	return rap;
}

void bt_rap_unref(struct bt_rap *rap)
{
	if (!rap)
		return;

	if (__sync_sub_and_fetch(&rap->ref_count, 1))
		return;

	rap_free(rap);
}

static void ras_features_read_cb(struct gatt_db_attribute *attrib,
				 unsigned int id, uint16_t offset,
				 uint8_t opcode, struct bt_att *att,
				 void *user_data)
{
	DBG(" ");
	/*
	 * Feature mask: bits 0-2 set:
	 *  - Real-time ranging
	 *  - Retrieve stored results
	 *  - Abort operation
	 */
	uint8_t value[4] = { 0x01, 0x00, 0x00, 0x00 };

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

static void ras_realtime_read_cb(struct gatt_db_attribute *attrib,
				 unsigned int id, uint16_t offset,
				 uint8_t opcode, struct bt_att *att,
				 void *user_data)
{
	/* No static read data; real-time data is provided via notifications. */
	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}

static void ras_ondemand_read_cb(struct gatt_db_attribute *attrib,
				 unsigned int id, uint16_t offset,
				 uint8_t opcode, struct bt_att *att,
				 void *user_data)
{
	DBG(" ");
	/* No static read data – on‑demand data is pushed via notifications */
	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}

/*
 * Control point handler.
 * Parses the opcode and acts on queued data (implementation TBD).
 */
static void ras_control_point_write_cb(struct gatt_db_attribute *attrib,
				       unsigned int id, uint16_t offset,
				       const uint8_t *value, size_t len,
				       uint8_t opcode, struct bt_att *att,
				       void *user_data)
{
	DBG(" ");
}

/* Data Ready – returns the latest ranging counter. */
static void ras_data_ready_read_cb(struct gatt_db_attribute *attrib,
				   unsigned int id, uint16_t offset,
				   uint8_t opcode, struct bt_att *att,
				   void *user_data)
{
	uint16_t counter = 0;
	uint8_t value[2];

	DBG("RAS data ready read");

	put_le16(counter, value);
	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

/* Data Overwritten – indicates how many results were overwritten. */
static void ras_data_overwritten_read_cb(struct gatt_db_attribute *attrib,
					 unsigned int id, uint16_t offset,
					 uint8_t opcode, struct bt_att *att,
					 void *user_data)
{
	uint8_t value[2] = { 0x00, 0x00 };

	DBG("RAS data overwritten read");

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}

/* Service registration – store attribute pointers */
static struct ras *register_ras_service(struct gatt_db *db)
{
	struct ras *ras;
	struct gatt_db_attribute *service;
	bt_uuid_t uuid;

	if (!db)
		return NULL;

	ras = new0(struct ras, 1);
	if (!ras)
		return NULL;

	/* Primary RAS service */
	bt_uuid16_create(&uuid, RAS_UUID16);
	service = gatt_db_add_service(db, &uuid, true, RAS_TOTAL_NUM_HANDLES);
	if (!service) {
		DBG("RAS service UUID could not be added");
		free(ras);
		return NULL;
	}

	ras->svc = service;

	/* RAS Features */
	bt_uuid16_create(&uuid, RAS_FEATURES_UUID);
		ras->feat_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_READ,
						  ras_features_read_cb, NULL, ras);

	/* Real-time Ranging Data */
	bt_uuid16_create(&uuid, RAS_REALTIME_DATA_UUID);
	ras->realtime_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_NOTIFY |
						  BT_GATT_CHRC_PROP_INDICATE,
						  NULL, NULL, ras);

	ras->realtime_chrc_ccc =
		gatt_db_service_add_ccc(ras->svc,
					BT_ATT_PERM_READ |
					BT_ATT_PERM_WRITE);

	/* On-demand Ranging Data */
	bt_uuid16_create(&uuid, RAS_ONDEMAND_DATA_UUID);
	ras->ondemand_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_NOTIFY |
						  BT_GATT_CHRC_PROP_INDICATE,
						  ras_ondemand_read_cb, NULL,
						  ras);

	gatt_db_service_add_ccc(ras->svc,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	/* RAS Control Point */
	bt_uuid16_create(&uuid, RAS_CONTROL_POINT_UUID);
	ras->cp_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_WRITE |
						  BT_ATT_PERM_WRITE_ENCRYPT,
						  BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP |
						  BT_GATT_CHRC_PROP_INDICATE,
						  NULL,
						  ras_control_point_write_cb,
						  ras);

	gatt_db_service_add_ccc(ras->svc,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	/* RAS Data Ready */
	bt_uuid16_create(&uuid, RAS_DATA_READY_UUID);
	ras->ready_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_READ |
						  BT_GATT_CHRC_PROP_NOTIFY |
						  BT_GATT_CHRC_PROP_INDICATE,
						  ras_data_ready_read_cb, NULL,
						  ras);

	gatt_db_service_add_ccc(ras->svc,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	/* RAS Data Overwritten */
	bt_uuid16_create(&uuid, RAS_DATA_OVERWRITTEN_UUID);
	ras->overwritten_chrc =
		gatt_db_service_add_characteristic(ras->svc, &uuid,
						  BT_ATT_PERM_READ |
						  BT_ATT_PERM_READ_ENCRYPT,
						  BT_GATT_CHRC_PROP_READ |
						  BT_GATT_CHRC_PROP_NOTIFY |
						  BT_GATT_CHRC_PROP_INDICATE,
						  ras_data_overwritten_read_cb,
						  NULL, ras);

	gatt_db_service_add_ccc(ras->svc,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE);

	/* Activate the service */
	gatt_db_service_set_active(ras->svc, true);

	return ras;
}

static struct bt_rap_db *rap_db_new(struct gatt_db *db)
{
	struct bt_rap_db *rapdb;

	if (!db)
		return NULL;

	rapdb = new0(struct bt_rap_db, 1);
	if (!rapdb) {
		DBG("RAP DB probe failed: memory allocation failed");
		return NULL;
	}

	rapdb->db = gatt_db_ref(db);

	if (!rap_db)
		rap_db = queue_new();

	rapdb->ras = register_ras_service(db);
	if (rapdb->ras)
		rapdb->ras->rapdb = rapdb;

	queue_push_tail(rap_db, rapdb);

	return rapdb;
}

static struct bt_rap_db *rap_get_db(struct gatt_db *db)
{
	struct bt_rap_db *rapdb;

	rapdb = queue_find(rap_db, rap_db_match, db);
	if (rapdb)
		return rapdb;

	return rap_db_new(db);
}

void bt_rap_add_db(struct gatt_db *db)
{
	rap_db_new(db);
}

unsigned int bt_rap_register(bt_rap_func_t attached, bt_rap_func_t detached,
			     void *user_data)
{
	struct bt_rap_cb *cb;
	static unsigned int id;

	if (!attached && !detached)
		return 0;

	if (!bt_rap_cbs)
		bt_rap_cbs = queue_new();

	cb = new0(struct bt_rap_cb, 1);
	cb->id = ++id ? id : ++id;
	cb->attached = attached;
	cb->detached = detached;
	cb->user_data = user_data;

	queue_push_tail(bt_rap_cbs, cb);

	return cb->id;
}

static bool match_id(const void *data, const void *match_data)
{
	const struct bt_rap_cb *cb = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return cb->id == id;
}

bool bt_rap_unregister(unsigned int id)
{
	struct bt_rap_cb *cb;

	cb = queue_remove_if(bt_rap_cbs, match_id, UINT_TO_PTR(id));
	if (!cb)
		return false;

	free(cb);

	return true;
}

struct bt_rap *bt_rap_new(struct gatt_db *ldb, struct gatt_db *rdb)
{
	struct bt_rap *rap;
	struct bt_rap_db *rapdb;

	if (!ldb)
		return NULL;

	rapdb = rap_get_db(ldb);
	if (!rapdb)
		return NULL;

	rap = new0(struct bt_rap, 1);
	rap->lrapdb = rapdb;
	rap->pending = queue_new();
	rap->ready_cbs = queue_new();
	rap->notify = queue_new();

	if (!rdb)
		goto done;

	rapdb = new0(struct bt_rap_db, 1);
	rapdb->db = gatt_db_ref(rdb);

	rap->rrapdb = rapdb;

done:
	bt_rap_ref(rap);

	return rap;
}

static void rap_pending_destroy(void *data)
{
	struct bt_rap_pending *pending = data;
	struct bt_rap *rap = pending->rap;

	if (queue_remove_if(rap->pending, NULL, pending))
		free(pending);
}

static void rap_pending_complete(bool success, uint8_t att_ecode,
				 const uint8_t *value, uint16_t length,
				 void *user_data)
{
	struct bt_rap_pending *pending = user_data;

	if (pending->func)
		pending->func(pending->rap, success, att_ecode, value,
			      length, pending->userdata);
}

static void rap_register(uint16_t att_ecode, void *user_data)
{
	struct bt_rap_notify *notify = user_data;

	if (att_ecode)
		DBG("RAS register failed 0x%04x", att_ecode);
}

static void rap_notify(uint16_t value_handle, const uint8_t *value,
		       uint16_t length, void *user_data)
{
	struct bt_rap_notify *notify = user_data;

	if (notify->func)
		notify->func(notify->rap, value_handle, value, length,
			     notify->user_data);
}

static void rap_notify_destroy(void *data)
{
	struct bt_rap_notify *notify = data;
	struct bt_rap *rap = notify->rap;

	if (queue_remove_if(rap->notify, NULL, notify))
		free(notify);
}

static unsigned int bt_rap_register_notify(struct bt_rap *rap,
					   uint16_t value_handle,
					   rap_notify_t func,
					   void *user_data)
{
	struct bt_rap_notify *notify;

	notify = new0(struct bt_rap_notify, 1);
	notify->rap = rap;
	notify->func = func;
	notify->user_data = user_data;

	notify->id = bt_gatt_client_register_notify(rap->client,
						    value_handle,
						    rap_register,
						    rap_notify,
						    notify,
						    rap_notify_destroy);
	if (!notify->id) {
		DBG("Unable to register for notifications");
		free(notify);
		return 0;
	}

	queue_push_tail(rap->notify, notify);

	return notify->id;
}

static void foreach_rap_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_rap *rap = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid;
	bt_uuid_t uuid_features;
	bt_uuid_t uuid_realtime;
	bt_uuid_t uuid_ondemand;
	bt_uuid_t uuid_cp;
	bt_uuid_t uuid_dataready;
	bt_uuid_t uuid_overwritten;
	struct ras *ras;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
					     NULL, NULL, &uuid))
		return;

	bt_uuid16_create(&uuid_features, RAS_FEATURES_UUID);
	bt_uuid16_create(&uuid_realtime, RAS_REALTIME_DATA_UUID);
	bt_uuid16_create(&uuid_ondemand, RAS_ONDEMAND_DATA_UUID);
	bt_uuid16_create(&uuid_cp, RAS_CONTROL_POINT_UUID);
	bt_uuid16_create(&uuid_dataready, RAS_DATA_READY_UUID);
	bt_uuid16_create(&uuid_overwritten, RAS_DATA_OVERWRITTEN_UUID);

	if (!bt_uuid_cmp(&uuid, &uuid_features)) {
		DBG("Features characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->feat_chrc)
			return;

		ras->feat_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_realtime)) {
		DBG("Real Time Data characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->realtime_chrc)
			return;

		ras->realtime_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_ondemand)) {
		DBG("On-demand Data characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->ondemand_chrc)
			return;

		ras->ondemand_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_cp)) {
		DBG("Control Point characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->cp_chrc)
			return;

		ras->cp_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_dataready)) {
		DBG("Data Ready characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->ready_chrc)
			return;

		ras->ready_chrc = attr;
	}

	if (!bt_uuid_cmp(&uuid, &uuid_overwritten)) {
		DBG("Overwritten characteristic found: handle 0x%04x",
		    value_handle);

		ras = rap_get_ras(rap);
		if (!ras || ras->overwritten_chrc)
			return;

		ras->overwritten_chrc = attr;
	}
}

static void foreach_rap_service(struct gatt_db_attribute *attr,
				void *user_data)
{
	struct bt_rap *rap = user_data;
	struct ras *ras = rap_get_ras(rap);

	ras->svc = attr;

	gatt_db_service_set_claimed(attr, true);

	gatt_db_service_foreach_char(attr, foreach_rap_char, rap);
}

unsigned int bt_rap_ready_register(struct bt_rap *rap,
				   bt_rap_ready_func_t func, void *user_data,
				   bt_rap_destroy_func_t destroy)
{
	struct bt_rap_ready *ready;
	static unsigned int id;

	DBG("bt_rap_ready_register");

	if (!rap)
		return 0;

	ready = new0(struct bt_rap_ready, 1);
	ready->id = ++id ? id : ++id;
	ready->func = func;
	ready->destroy = destroy;
	ready->data = user_data;

	queue_push_tail(rap->ready_cbs, ready);

	return ready->id;
}

static bool match_ready_id(const void *data, const void *match_data)
{
	const struct bt_rap_ready *ready = data;
	unsigned int id = PTR_TO_UINT(match_data);

	return ready->id == id;
}

bool bt_rap_ready_unregister(struct bt_rap *rap, unsigned int id)
{
	struct bt_rap_ready *ready;

	ready = queue_remove_if(rap->ready_cbs, match_ready_id,
				UINT_TO_PTR(id));
	if (!ready)
		return false;

	rap_ready_free(ready);

	return true;
}

static struct bt_rap *bt_rap_ref_safe(struct bt_rap *rap)
{
	if (!rap || !rap->ref_count)
		return NULL;

	return bt_rap_ref(rap);
}

static void rap_notify_ready(struct bt_rap *rap)
{
	const struct queue_entry *entry;

	if (!bt_rap_ref_safe(rap))
		return;

	for (entry = queue_get_entries(rap->ready_cbs); entry;
	     entry = entry->next) {
		struct bt_rap_ready *ready = entry->data;

		ready->func(rap, ready->data);
	}

	bt_rap_unref(rap);
}

static void rap_idle(void *data)
{
	struct bt_rap *rap = data;

	rap->idle_id = 0;
	rap_notify_ready(rap);
}

bool bt_rap_attach(struct bt_rap *rap, struct bt_gatt_client *client)
{
	bt_uuid_t uuid;

	if (!sessions)
		sessions = queue_new();

	queue_push_tail(sessions, rap);

	if (!client)
		return true;

	if (rap->client)
		return false;

	rap->client = bt_gatt_client_clone(client);
	if (!rap->client)
		return false;

	bt_gatt_client_idle_register(rap->client, rap_idle, rap, NULL);

	bt_uuid16_create(&uuid, RAS_UUID16);

	gatt_db_foreach_service(rap->lrapdb->db, &uuid,
				foreach_rap_service, rap);

	return true;
}
