// SPDX-License-Identifier: GPL-2.0-or-later
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

#include <stdbool.h>
#include <stdint.h>

struct bt_asha_device;

enum bt_asha_state_t {
	ASHA_STOPPED = 0,
	ASHA_STARTING,
	ASHA_STARTED,
	ASHA_STOPPING,
};

typedef void (*bt_asha_cb_t)(int status, void *data);

struct bt_asha_device {
	struct btd_device *device;
	struct bt_gatt_client *client;
	struct gatt_db *db;
	struct gatt_db_attribute *attr;
	uint16_t acp_handle;
	uint16_t volume_handle;
	unsigned int status_notify_id;
	unsigned int volume_notify_id;

	uint16_t psm;
	bool right_side;
	bool binaural;
	bool csis_supported;
	bool coc_streaming_supported;
	uint8_t hisyncid[8];
	uint16_t render_delay;
	uint16_t codec_ids;
	int8_t volume;

	struct media_transport *transport;
	int fd;
	uint16_t imtu, omtu;
	enum bt_asha_state_t state;
	bt_asha_cb_t cb;
	void *cb_user_data;
	int resume_id;
};

struct bt_asha_device *bt_asha_device_new(void);
void bt_asha_device_reset(struct bt_asha_device *asha);
void bt_asha_state_reset(struct bt_asha_device *asha);
void bt_asha_device_free(struct bt_asha_device *asha);

uint16_t bt_asha_device_get_render_delay(struct bt_asha_device *asha);
enum bt_asha_state_t bt_asha_device_get_state(struct bt_asha_device *asha);
int bt_asha_device_get_fd(struct bt_asha_device *asha);
uint16_t bt_asha_device_get_omtu(struct bt_asha_device *asha);
uint16_t bt_asha_device_get_imtu(struct bt_asha_device *asha);

unsigned int bt_asha_device_start(struct bt_asha_device *asha, bt_asha_cb_t cb,
		void *user_data);
unsigned int bt_asha_device_stop(struct bt_asha_device *asha, bt_asha_cb_t cb,
		void *user_data);

int8_t bt_asha_device_get_volume(struct bt_asha_device *asha);
bool bt_asha_device_set_volume(struct bt_asha_device *asha, int8_t volume);

bool bt_asha_device_probe(struct bt_asha_device *asha);
