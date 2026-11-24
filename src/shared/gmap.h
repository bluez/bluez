/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Pauli Virtanen. All rights reserved.
 *
 */

#include <stdbool.h>
#include <inttypes.h>

#define BT_GMAP_ROLE_UGG		BIT(0)
#define BT_GMAP_ROLE_UGT		BIT(1)
#define BT_GMAP_ROLE_BGS		BIT(2)
#define BT_GMAP_ROLE_BGR		BIT(3)
#define BT_GMAP_ROLE_MASK		(BIT(4) - 1)

#define BT_GMAP_UGG_MULTIPLEX		(BIT(0) << 0)
#define BT_GMAP_UGG_96KBPS_SOURCE	(BIT(1) << 0)
#define BT_GMAP_UGG_MULTISINK		(BIT(2) << 0)
#define BT_GMAP_UGG_FEATURE_MASK	((BIT(3) - 1) << 0)
#define BT_GMAP_UGG_FEATURE_SHIFT	0

#define BT_GMAP_UGT_SOURCE		(BIT(0) << 8)
#define BT_GMAP_UGT_80KBPS_SOURCE	(BIT(1) << 8)
#define BT_GMAP_UGT_SINK		(BIT(2) << 8)
#define BT_GMAP_UGT_64KBPS_SINK		(BIT(3) << 8)
#define BT_GMAP_UGT_MULTIPLEX		(BIT(4) << 8)
#define BT_GMAP_UGT_MULTISINK		(BIT(5) << 8)
#define BT_GMAP_UGT_MULTISOURCE		(BIT(6) << 8)
#define BT_GMAP_UGT_FEATURE_MASK	((BIT(7) - 1) << 8)
#define BT_GMAP_UGT_FEATURE_SHIFT	8

#define BT_GMAP_BGS_96KBPS		(BIT(0) << 16)
#define BT_GMAP_BGS_FEATURE_MASK	((BIT(1) - 1) << 16)
#define BT_GMAP_BGS_FEATURE_SHIFT	16

#define BT_GMAP_BGR_MULTISINK		(BIT(0) << 24)
#define BT_GMAP_BGR_MULTIPLEX		(BIT(1) << 24)
#define BT_GMAP_BGR_FEATURE_MASK	((BIT(2) - 1) << 24)
#define BT_GMAP_BGR_FEATURE_SHIFT	24

#define BT_GMAP_FEATURE_MASK		(BT_GMAP_UGG_FEATURE_MASK | \
					BT_GMAP_UGT_FEATURE_MASK | \
					BT_GMAP_BGS_FEATURE_MASK | \
					BT_GMAP_BGR_FEATURE_MASK)

#define BT_GMAP_ROLE_UGG_STR		"ugg"
#define BT_GMAP_ROLE_UGT_STR		"ugt"
#define BT_GMAP_ROLE_BGS_STR		"bgs"
#define BT_GMAP_ROLE_BGR_STR		"bgr"

#define BT_GMAP_UGG_MULTIPLEX_STR	"ugg-multiplex"
#define BT_GMAP_UGG_96KBPS_SOURCE_STR	"ugg-96kbps-source"
#define BT_GMAP_UGG_MULTISINK_STR	"ugg-multisink"

#define BT_GMAP_UGT_SOURCE_STR		"ugt-source"
#define BT_GMAP_UGT_80KBPS_SOURCE_STR	"ugt-80kbps-source"
#define BT_GMAP_UGT_SINK_STR		"ugt-sink"
#define BT_GMAP_UGT_64KBPS_SINK_STR	"ugt-64kbps-sink"
#define BT_GMAP_UGT_MULTIPLEX_STR	"ugt-multiplex"
#define BT_GMAP_UGT_MULTISINK_STR	"ugt-multisink"
#define BT_GMAP_UGT_MULTISOURCE_STR	"ugt-multisource"

#define BT_GMAP_BGS_96KBPS_STR		"bgs-96kbps"

#define BT_GMAP_BGR_MULTISINK_STR	"bgr-multisink"
#define BT_GMAP_BGR_MULTIPLEX_STR	"bgr-multiplex"

#define BT_GMAP_ROLE_LIST(role) \
	role(BT_GMAP_ROLE_UGG) \
	role(BT_GMAP_ROLE_UGT) \
	role(BT_GMAP_ROLE_BGS) \
	role(BT_GMAP_ROLE_BGR)

#define BT_GMAP_FEATURE_LIST(feature) \
	feature(BT_GMAP_UGG_MULTIPLEX) \
	feature(BT_GMAP_UGG_96KBPS_SOURCE) \
	feature(BT_GMAP_UGG_MULTISINK) \
	feature(BT_GMAP_UGT_SOURCE) \
	feature(BT_GMAP_UGT_80KBPS_SOURCE) \
	feature(BT_GMAP_UGT_SINK) \
	feature(BT_GMAP_UGT_64KBPS_SINK) \
	feature(BT_GMAP_UGT_MULTIPLEX) \
	feature(BT_GMAP_UGT_MULTISINK) \
	feature(BT_GMAP_UGT_MULTISOURCE) \
	feature(BT_GMAP_BGS_96KBPS) \
	feature(BT_GMAP_BGR_MULTISINK) \
	feature(BT_GMAP_BGR_MULTIPLEX)

struct bt_gmap;

typedef void (*bt_gmap_ready_func_t)(struct bt_gmap *gmap, void *user_data);
typedef void (*bt_gmap_destroy_func_t)(void *user_data);
typedef void (*bt_gmap_debug_func_t)(const char *str, void *user_data);

struct bt_gmap *bt_gmap_ref(struct bt_gmap *gmap);
void bt_gmap_unref(struct bt_gmap *gmap);

struct bt_gmap *bt_gmap_attach(struct bt_gatt_client *client,
				bt_gmap_ready_func_t ready, void *user_data);
struct bt_gmap *bt_gmap_find(struct gatt_db *db);
struct bt_gmap *bt_gmap_add_db(struct gatt_db *db);

uint8_t bt_gmap_get_role(struct bt_gmap *gmap);
uint32_t bt_gmap_get_features(struct bt_gmap *gmap);

void bt_gmap_set_role(struct bt_gmap *gmas, uint8_t role);
void bt_gmap_set_features(struct bt_gmap *gmas, uint32_t features);

bool bt_gmap_set_debug(struct bt_gmap *gmap, bt_gmap_debug_func_t cb,
			void *user_data, bt_gmap_destroy_func_t destroy);
