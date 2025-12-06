// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "src/shared/timeout.h"
#include "src/shared/att.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gmap.h"

#define DBG(_gmap, fmt, arg...) \
	gmap_debug(_gmap, "%s:%s() " fmt, __FILE__, __func__, ## arg)

struct bt_gmas_attr {
	struct bt_gmap *gmap;
	const char *name;
	struct gatt_db_attribute *attr;
	uint8_t value;
};

struct bt_gmas_db {
	struct gatt_db *db;
	struct gatt_db_attribute *service;
	struct bt_gmas_attr role;
	struct bt_gmas_attr ugg;
	struct bt_gmas_attr ugt;
	struct bt_gmas_attr bgs;
	struct bt_gmas_attr bgr;
};

struct bt_gmap {
	int ref_count;
	struct bt_gatt_client *client;
	struct bt_gmas_db db;

	int idle_id;
	bt_gmap_ready_func_t ready_func;
	void *ready_data;

	bt_gmap_debug_func_t debug_func;
	bt_gmap_destroy_func_t debug_destroy;
	void *debug_data;
};

static struct queue *instances;

static void gmap_free(void *data)
{
	struct bt_gmap *gmap = data;

	if (gmap->client) {
		bt_gatt_client_idle_unregister(gmap->client, gmap->idle_id);
		bt_gatt_client_unref(gmap->client);
	} else {
		gatt_db_remove_service(gmap->db.db, gmap->db.service);
		gatt_db_unref(gmap->db.db);
	}

	queue_remove(instances, gmap);
	if (queue_isempty(instances)) {
		queue_destroy(instances, NULL);
		instances = NULL;
	}

	free(gmap);
}

struct bt_gmap *bt_gmap_ref(struct bt_gmap *gmap)
{
	if (!gmap)
		return NULL;

	__sync_fetch_and_add(&gmap->ref_count, 1);

	return gmap;
}

void bt_gmap_unref(struct bt_gmap *gmap)
{
	if (!gmap)
		return;

	if (__sync_sub_and_fetch(&gmap->ref_count, 1))
		return;

	gmap_free(gmap);
}

static void gmap_debug(struct bt_gmap *gmap, const char *format, ...)
{
	va_list ap;

	if (!gmap || !format || !gmap->debug_func)
		return;

	va_start(ap, format);
	util_debug_va(gmap->debug_func, gmap->debug_data, format, ap);
	va_end(ap);
}

bool bt_gmap_set_debug(struct bt_gmap *gmap, bt_gmap_debug_func_t cb,
		void *user_data, bt_gmap_destroy_func_t destroy)
{
	if (!gmap)
		return false;

	if (gmap->debug_destroy)
		gmap->debug_destroy(gmap->debug_data);

	gmap->debug_func = cb;
	gmap->debug_destroy = destroy;
	gmap->debug_data = user_data;

	return true;
}

uint8_t bt_gmap_get_role(struct bt_gmap *gmap)
{
	if (!gmap)
		return 0;

	return gmap->db.role.value & BT_GMAP_ROLE_MASK;
}

uint32_t bt_gmap_get_features(struct bt_gmap *gmap)
{
	if (!gmap)
		return 0;

	return (((uint32_t)gmap->db.ugg.value << BT_GMAP_UGG_FEATURE_SHIFT) |
		((uint32_t)gmap->db.ugt.value << BT_GMAP_UGT_FEATURE_SHIFT) |
		((uint32_t)gmap->db.bgs.value << BT_GMAP_BGS_FEATURE_SHIFT) |
		((uint32_t)gmap->db.bgr.value << BT_GMAP_BGR_FEATURE_SHIFT)) &
		BT_GMAP_FEATURE_MASK;
}

/*
 * GMA Client
 */

static void gmap_attr_read(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct bt_gmas_attr *attr = user_data;
	struct bt_gmap *gmap = attr->gmap;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint8_t v;

	if (!success) {
		DBG(gmap, "Unable to read %s: error 0x%02x",
							attr->name, att_ecode);
		return;
	}

	if (!util_iov_pull_u8(&iov, &v)) {
		DBG(gmap, "Invalid %s", attr->name);
		return;
	}

	DBG(gmap, "%s Value 0x%x", attr->name, v);
	attr->value = v;
}

static void foreach_gmap_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_gmap *gmap = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid, uuid_attr;
	struct {
		const uint32_t uuid;
		struct bt_gmas_attr *attr;
		const char *name;
	} attrs[] = {
		{ GMAP_ROLE_CHRC_UUID, &gmap->db.role, "Role" },
		{ GMAP_UGG_CHRC_UUID, &gmap->db.ugg, "UGG Features" },
		{ GMAP_UGT_CHRC_UUID, &gmap->db.ugt, "UGT Features" },
		{ GMAP_BGS_CHRC_UUID, &gmap->db.bgs, "BGS Features" },
		{ GMAP_BGR_CHRC_UUID, &gmap->db.bgr, "BGR Features" },
	};
	unsigned int i;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
						NULL, NULL, &uuid))
		return;

	for (i = 0; i < ARRAY_SIZE(attrs); ++i) {
		bt_uuid16_create(&uuid_attr, attrs[i].uuid);
		if (bt_uuid_cmp(&uuid, &uuid_attr))
			continue;

		attrs[i].attr->gmap = gmap;
		attrs[i].attr->name = attrs[i].name;

		DBG(gmap, "GMAS %s Char found: handle 0x%04x",
			attrs[i].name, value_handle);
		bt_gatt_client_read_value(gmap->client, value_handle,
					gmap_attr_read, attrs[i].attr,
					NULL);
		return;
	}
}

static void foreach_gmap_service(struct gatt_db_attribute *attr,
						void *user_data)
{
	struct bt_gmap *gmap = user_data;

	gatt_db_service_set_claimed(attr, true);
	gatt_db_service_foreach_char(attr, foreach_gmap_char, gmap);
}

static void gmap_idle(void *data)
{
	struct bt_gmap *gmap = data;

	gmap->idle_id = 0;

	if (!instances)
		instances = queue_new();
	queue_push_tail(instances, gmap);

	if (gmap->ready_func)
		gmap->ready_func(gmap, gmap->ready_data);
}

struct bt_gmap *bt_gmap_attach(struct bt_gatt_client *client,
				bt_gmap_ready_func_t ready, void *user_data)
{
	struct bt_gmap *gmap;
	bt_uuid_t uuid;

	if (!client)
		return NULL;

	client = bt_gatt_client_clone(client);
	if (!client)
		return NULL;

	gmap = new0(struct bt_gmap, 1);
	gmap->client = client;
	gmap->ready_func = ready;
	gmap->ready_data = user_data;
	gmap->db.db = bt_gatt_client_get_db(gmap->client);

	bt_uuid16_create(&uuid, GMAS_UUID);
	gatt_db_foreach_service(gmap->db.db, &uuid, foreach_gmap_service, gmap);

	gmap->idle_id = bt_gatt_client_idle_register(gmap->client, gmap_idle,
								gmap, NULL);

	return bt_gmap_ref(gmap);
}

/*
 * GMAS Service
 */

static void gmas_attr_read(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bt_gmas_attr *attr = user_data;
	struct iovec iov = {
		.iov_base = &attr->value,
		.iov_len = sizeof(attr->value)
	};

	gatt_db_attribute_read_result(attrib, id, 0, iov.iov_base,
							iov.iov_len);
}

static bool match_db(const void *data, const void *match_data)
{
	const struct bt_gmap *gmap = data;

	return gmap->db.db == match_data;
}

struct bt_gmap *bt_gmap_find(struct gatt_db *db)
{
	return db ? queue_find(instances, match_db, db) : NULL;
}

static void gmap_update_chrc(struct bt_gmap *gmap)
{
	struct {
		const uint32_t uuid;
		uint8_t role;
		struct bt_gmas_attr *attr;
		const char *name;
	} attrs[] = {
		{ GMAP_ROLE_CHRC_UUID, 0, &gmap->db.role, "Role" },
		{ GMAP_UGG_CHRC_UUID, BT_GMAP_ROLE_UGG, &gmap->db.ugg,
							"UGG Features" },
		{ GMAP_UGT_CHRC_UUID, BT_GMAP_ROLE_UGT, &gmap->db.ugt,
							"UGT Features" },
		{ GMAP_BGS_CHRC_UUID, BT_GMAP_ROLE_BGS, &gmap->db.bgs,
							"BGS Features" },
		{ GMAP_BGR_CHRC_UUID, BT_GMAP_ROLE_BGR, &gmap->db.bgr,
							"BGR Features" },
	};
	unsigned int i;
	bt_uuid_t uuid;

	for (i = 0; i < ARRAY_SIZE(attrs); ++i) {
		if (attrs[i].attr->attr)
			continue;

		attrs[i].attr->gmap = gmap;
		attrs[i].attr->name = attrs[i].name;

		if (attrs[i].role && !(gmap->db.role.value & attrs[i].role))
			continue;

		bt_uuid16_create(&uuid, attrs[i].uuid);
		attrs[i].attr->attr = gatt_db_service_add_characteristic(
					gmap->db.service,
					&uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ,
					gmas_attr_read, NULL,
					attrs[i].attr);
		gatt_db_attribute_set_fixed_length(attrs[i].attr->attr, 1);
	}
}

static void gmap_init_service(struct bt_gmas_db *db)
{
	bt_uuid_t uuid;

	if (db->service) {
		gatt_db_remove_service(db->db, db->service);
		db->service = NULL;
		db->role.attr = NULL;
		db->ugg.attr = NULL;
		db->ugt.attr = NULL;
		db->bgs.attr = NULL;
		db->bgr.attr = NULL;
	}

	bt_uuid16_create(&uuid, GMAS_UUID);
	db->service = gatt_db_add_service(db->db, &uuid, true, 5*2 + 1);
}

struct bt_gmap *bt_gmap_add_db(struct gatt_db *db)
{
	struct bt_gmap *gmap;

	if (!db || queue_find(instances, match_db, db))
		return NULL;

	gmap = new0(struct bt_gmap, 1);
	gmap->db.db = gatt_db_ref(db);

	gmap_init_service(&gmap->db);

	if (!instances)
		instances = queue_new();
	queue_push_tail(instances, gmap);

	return bt_gmap_ref(gmap);
}

void bt_gmap_set_role(struct bt_gmap *gmap, uint8_t role)
{
	if (!gmap || gmap->client)
		return;

	role &= BT_GMAP_ROLE_MASK;
	if (role == gmap->db.role.value)
		return;

	DBG(gmap, "set role 0x%02x", role);

	gmap->db.role.value = role;

	/* Removing role must remove feature chrc too; reset svc if needed */
	if (role && ((!(role & BT_GMAP_ROLE_UGG) && gmap->db.ugg.attr) ||
			(!(role & BT_GMAP_ROLE_UGT) && gmap->db.ugt.attr) ||
			(!(role & BT_GMAP_ROLE_BGS) && gmap->db.bgs.attr) ||
			(!(role & BT_GMAP_ROLE_BGR) && gmap->db.bgr.attr)))
		gmap_init_service(&gmap->db);

	gmap_update_chrc(gmap);

	/* Expose values only when first set and active */
	gatt_db_service_set_active(gmap->db.service, role != 0);
}

void bt_gmap_set_features(struct bt_gmap *gmap, uint32_t features)
{
	if (!gmap || gmap->client)
		return;

	features &= BT_GMAP_FEATURE_MASK;
	if (features == bt_gmap_get_features(gmap))
		return;

	DBG(gmap, "set features 0x%08x", features);

	gmap->db.ugg.value = (features & BT_GMAP_UGG_FEATURE_MASK)
						>> BT_GMAP_UGG_FEATURE_SHIFT;
	gmap->db.ugt.value = (features & BT_GMAP_UGT_FEATURE_MASK)
						>> BT_GMAP_UGT_FEATURE_SHIFT;
	gmap->db.bgs.value = (features & BT_GMAP_BGS_FEATURE_MASK)
						>> BT_GMAP_BGS_FEATURE_SHIFT;
	gmap->db.bgr.value = (features & BT_GMAP_BGR_FEATURE_MASK)
						>> BT_GMAP_BGR_FEATURE_SHIFT;
}
