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

#include "src/shared/asha.h"

struct bt_asha_device;

unsigned int bt_asha_device_start(struct bt_asha_device *asha_dev,
					bt_asha_cb_t cb, void *user_data);
unsigned int bt_asha_device_stop(struct bt_asha_device *asha_dev,
					bt_asha_cb_t cb, void *user_data);

void bt_asha_device_state_reset(struct bt_asha_device *asha_dev);
unsigned int bt_asha_device_device_get_resume_id(
					struct bt_asha_device *asha_dev);

uint16_t bt_asha_device_get_render_delay(struct bt_asha_device *asha_dev);
enum bt_asha_state_t bt_asha_device_get_state(
					struct bt_asha_device *asha_dev);

int bt_asha_device_get_fd(struct bt_asha_device *asha_dev);
uint16_t bt_asha_device_get_omtu(struct bt_asha_device *asha_dev);
uint16_t bt_asha_device_get_imtu(struct bt_asha_device *asha_dev);

int8_t bt_asha_device_get_volume(struct bt_asha_device *asha_dev);
bool bt_asha_device_set_volume(struct bt_asha_device *asha_dev, int8_t volume);
