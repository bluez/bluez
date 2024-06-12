// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024  Asymptotic Inc.
 *
 *  Author: Arun Raghavan <arun@asymptotic.io>
 *
 *
 */

#

#include <stdbool.h>
#include <stdint.h>

enum bt_asha_state_t {
	ASHA_STOPPED = 0,
	ASHA_STARTING,
	ASHA_STARTED,
	ASHA_STOPPING,
};

typedef void (*bt_asha_cb_t)(int status, void *data);

struct bt_asha {
	struct bt_gatt_client *client;
	struct gatt_db *db;
	struct gatt_db_attribute *attr;
	uint16_t acp_handle;
	uint16_t volume_handle;
	unsigned int status_notify_id;

	uint16_t psm;
	bool right_side;
	bool binaural;
	bool csis_supported;
	bool coc_streaming_supported;
	uint8_t hisyncid[8];
	uint16_t render_delay;
	uint16_t codec_ids;
	int8_t volume;

	enum bt_asha_state_t state;
	bt_asha_cb_t cb;
	void *cb_user_data;
};

struct bt_asha *bt_asha_new(void);
void bt_asha_reset(struct bt_asha *asha);
void bt_asha_state_reset(struct bt_asha *asha);
void bt_asha_free(struct bt_asha *asha);

unsigned int bt_asha_start(struct bt_asha *asha, bt_asha_cb_t cb,
							void *user_data);
unsigned int bt_asha_stop(struct bt_asha *asha, bt_asha_cb_t cb,
							void *user_data);

bool bt_asha_set_volume(struct bt_asha *asha, int8_t volume);

bool bt_asha_probe(struct bt_asha *asha, struct gatt_db *db,
						struct bt_gatt_client *client);
