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

#define BT_TMAP_ROLE_CG			BIT(0)
#define BT_TMAP_ROLE_CT			BIT(1)
#define BT_TMAP_ROLE_UMS		BIT(2)
#define BT_TMAP_ROLE_UMR		BIT(3)
#define BT_TMAP_ROLE_BMS		BIT(4)
#define BT_TMAP_ROLE_BMR		BIT(5)
#define BT_TMAP_ROLE_MASK		(BIT(6) - 1)

#define BT_TMAP_ROLE_CG_STR		"cg"
#define BT_TMAP_ROLE_CT_STR		"ct"
#define BT_TMAP_ROLE_UMS_STR		"ums"
#define BT_TMAP_ROLE_UMR_STR		"umr"
#define BT_TMAP_ROLE_BMS_STR		"bms"
#define BT_TMAP_ROLE_BMR_STR		"bmr"

#define BT_TMAP_ROLE_LIST(role) \
	role(BT_TMAP_ROLE_CG) \
	role(BT_TMAP_ROLE_CT) \
	role(BT_TMAP_ROLE_UMS) \
	role(BT_TMAP_ROLE_UMR) \
	role(BT_TMAP_ROLE_BMS) \
	role(BT_TMAP_ROLE_BMR)

struct bt_tmap;

typedef void (*bt_tmap_ready_func_t)(struct bt_tmap *tmap, void *user_data);
typedef void (*bt_tmap_destroy_func_t)(void *user_data);
typedef void (*bt_tmap_debug_func_t)(const char *str, void *user_data);

struct bt_tmap *bt_tmap_ref(struct bt_tmap *tmap);
void bt_tmap_unref(struct bt_tmap *tmap);

struct bt_tmap *bt_tmap_attach(struct bt_gatt_client *client,
			bt_tmap_ready_func_t ready, void *user_data);
struct bt_tmap *bt_tmap_find(struct gatt_db *db);
struct bt_tmap *bt_tmap_add_db(struct gatt_db *db);

uint16_t bt_tmap_get_role(struct bt_tmap *tmap);
void bt_tmap_set_role(struct bt_tmap *tmas, uint16_t role);

bool bt_tmap_set_debug(struct bt_tmap *tmap, bt_tmap_debug_func_t cb,
			void *user_data, bt_tmap_destroy_func_t destroy);
