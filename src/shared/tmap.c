// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Pauli Virtanen. All rights reserved.
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
#include "src/shared/tmap.h"
#include "src/shared/bap.h"

#define DBG(_tmap, fmt, arg...) \
	tmap_debug(_tmap, "%s:%s() " fmt, __FILE__, __func__, ## arg)

struct bt_tmas_db {
	struct gatt_db *db;
	struct gatt_db_attribute *service;
	struct gatt_db_attribute *role;
	uint16_t role_value;
};

struct bt_tmap {
	int ref_count;
	struct bt_gatt_client *client;
	struct bt_tmas_db db;

	int idle_id;
	bt_tmap_ready_func_t ready_func;
	void *ready_data;

	bt_tmap_debug_func_t debug_func;
	bt_tmap_destroy_func_t debug_destroy;
	void *debug_data;
};

static struct queue *instances;

static void tmap_free(void *data)
{
	struct bt_tmap *tmap = data;

	if (tmap->client) {
		bt_gatt_client_idle_unregister(tmap->client, tmap->idle_id);
		bt_gatt_client_unref(tmap->client);
	} else {
		gatt_db_remove_service(tmap->db.db, tmap->db.service);
		gatt_db_unref(tmap->db.db);
	}

	queue_remove(instances, tmap);
	if (queue_isempty(instances)) {
		queue_destroy(instances, NULL);
		instances = NULL;
	}

	free(tmap);
}

struct bt_tmap *bt_tmap_ref(struct bt_tmap *tmap)
{
	if (!tmap)
		return NULL;

	__sync_fetch_and_add(&tmap->ref_count, 1);

	return tmap;
}

void bt_tmap_unref(struct bt_tmap *tmap)
{
	if (!tmap)
		return;

	if (__sync_sub_and_fetch(&tmap->ref_count, 1))
		return;

	tmap_free(tmap);
}

static void tmap_debug(struct bt_tmap *tmap, const char *format, ...)
{
	va_list ap;

	if (!tmap || !format || !tmap->debug_func)
		return;

	va_start(ap, format);
	util_debug_va(tmap->debug_func, tmap->debug_data, format, ap);
	va_end(ap);
}

bool bt_tmap_set_debug(struct bt_tmap *tmap, bt_tmap_debug_func_t cb,
		void *user_data, bt_tmap_destroy_func_t destroy)
{
	if (!tmap)
		return false;

	if (tmap->debug_destroy)
		tmap->debug_destroy(tmap->debug_data);

	tmap->debug_func = cb;
	tmap->debug_destroy = destroy;
	tmap->debug_data = user_data;

	return true;
}

uint16_t bt_tmap_get_role(struct bt_tmap *tmap)
{
	if (!tmap)
		return 0;

	return tmap->db.role_value;
}

/*
 * TMA Client
 */

static void tmap_role_read(bool success, uint8_t att_ecode,
					const uint8_t *value, uint16_t length,
					void *user_data)
{
	struct bt_tmap *tmap = user_data;
	struct iovec iov = { .iov_base = (void *)value, .iov_len = length };
	uint16_t role;

	if (!success) {
		DBG(tmap, "Unable to read Role: error 0x%02x", att_ecode);
		return;
	}

	if (!util_iov_pull_le16(&iov, &role)) {
		DBG(tmap, "Invalid Role");
		return;
	}

	DBG(tmap, "Role 0x%x", role);
	tmap->db.role_value = role & BT_TMAP_ROLE_MASK;
}

static void foreach_tmap_char(struct gatt_db_attribute *attr, void *user_data)
{
	struct bt_tmap *tmap = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid, uuid_role;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle,
						NULL, NULL, &uuid))
		return;

	bt_uuid16_create(&uuid_role, TMAP_ROLE_CHRC_UUID);

	if (!bt_uuid_cmp(&uuid, &uuid_role)) {
		DBG(tmap, "TMAS Role Char found: handle 0x%04x", value_handle);
		bt_gatt_client_read_value(tmap->client, value_handle,
					tmap_role_read, tmap, NULL);
		return;
	}
}

static void foreach_tmap_service(struct gatt_db_attribute *attr,
						void *user_data)
{
	struct bt_tmap *tmap = user_data;

	gatt_db_service_set_claimed(attr, true);
	gatt_db_service_foreach_char(attr, foreach_tmap_char, tmap);
}

static void tmap_idle(void *data)
{
	struct bt_tmap *tmap = data;

	tmap->idle_id = 0;

	if (!instances)
		instances = queue_new();
	queue_push_tail(instances, tmap);

	if (tmap->ready_func)
		tmap->ready_func(tmap, tmap->ready_data);
}

struct bt_tmap *bt_tmap_attach(struct bt_gatt_client *client,
				bt_tmap_ready_func_t ready, void *user_data)
{
	struct bt_tmap *tmap;
	bt_uuid_t uuid;

	if (!client)
		return NULL;

	client = bt_gatt_client_clone(client);
	if (!client)
		return NULL;

	tmap = new0(struct bt_tmap, 1);
	tmap->client = client;
	tmap->ready_func = ready;
	tmap->ready_data = user_data;
	tmap->db.db = bt_gatt_client_get_db(tmap->client);

	bt_uuid16_create(&uuid, TMAS_UUID);
	gatt_db_foreach_service(tmap->db.db, &uuid, foreach_tmap_service, tmap);

	tmap->idle_id = bt_gatt_client_idle_register(tmap->client, tmap_idle,
								tmap, NULL);

	return bt_tmap_ref(tmap);
}

/*
 * TMAS Service
 */

static void tmas_role_read(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bt_tmas_db *db = user_data;
	struct iovec iov = {
		.iov_base = &db->role_value,
		.iov_len = sizeof(db->role_value)
	};

	gatt_db_attribute_read_result(attrib, id, 0, iov.iov_base,
							iov.iov_len);
}

static bool match_db(const void *data, const void *match_data)
{
	const struct bt_tmap *tmap = data;

	return tmap->db.db == match_data;
}

struct bt_tmap *bt_tmap_find(struct gatt_db *db)
{
	return db ? queue_find(instances, match_db, db) : NULL;
}

struct bt_tmap *bt_tmap_add_db(struct gatt_db *db)
{
	struct bt_tmap *tmap;
	bt_uuid_t uuid;

	if (!db || queue_find(instances, match_db, db))
		return NULL;

	tmap = new0(struct bt_tmap, 1);
	tmap->db.db = gatt_db_ref(db);

	bt_uuid16_create(&uuid, TMAS_UUID);
	tmap->db.service = gatt_db_add_service(db, &uuid, true, 3);

	bt_uuid16_create(&uuid, TMAP_ROLE_CHRC_UUID);
	tmap->db.role = gatt_db_service_add_characteristic(
					tmap->db.service,
					&uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ,
					tmas_role_read, NULL,
					&tmap->db);

	if (!instances)
		instances = queue_new();
	queue_push_tail(instances, tmap);

	return bt_tmap_ref(tmap);
}

void bt_tmap_set_role(struct bt_tmap *tmap, uint16_t role)
{
	if (!tmap || tmap->client)
		return;

	role &= BT_TMAP_ROLE_MASK;
	if (role == tmap->db.role_value)
		return;

	DBG(tmap, "set role 0x%02x", role);

	tmap->db.role_value = role;

	/* Expose when first set and present. Role does not have Notify. */
	gatt_db_service_set_active(tmap->db.service, role != 0);
}
