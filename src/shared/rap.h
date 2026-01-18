/*
 * BlueZ - Bluetooth protocol stack for Linux
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <stdbool.h>
#include <inttypes.h>

#include "src/shared/io.h"
#include "src/shared/gatt-client.h"
#include "src/shared/gatt-server.h"


struct bt_rap;

typedef void (*bt_rap_ready_func_t)(struct bt_rap *rap, void *user_data);
typedef void (*bt_rap_destroy_func_t)(void *user_data);
typedef void (*bt_rap_func_t)(struct bt_rap *rap, void *user_data);

struct bt_rap *bt_rap_ref(struct bt_rap *rap);
void bt_rap_unref(struct bt_rap *rap);

void bt_rap_add_db(struct gatt_db *db);

bool bt_rap_attach(struct bt_rap *rap, struct bt_gatt_client *client);
void bt_rap_detach(struct bt_rap *rap);

struct bt_att *bt_rap_get_att(struct bt_rap *rap);

bool bt_rap_set_user_data(struct bt_rap *rap, void *user_data);

/* session related functions */
unsigned int bt_rap_register(bt_rap_func_t attached, bt_rap_func_t detached,
					void *user_data);
unsigned int bt_rap_ready_register(struct bt_rap *rap,
				bt_rap_ready_func_t func, void *user_data,
				bt_rap_destroy_func_t destroy);
bool bt_rap_ready_unregister(struct bt_rap *rap, unsigned int id);

bool bt_rap_unregister(unsigned int id);

struct bt_rap *bt_rap_new(struct gatt_db *ldb, struct gatt_db *rdb);
