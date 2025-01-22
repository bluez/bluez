/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2024 StreamUnlimited Engineering GmbH
 *
 *
 */

uint8_t bt_audio_vcp_get_volume(struct btd_device *device);
bool bt_audio_vcp_set_volume(struct btd_device *device, uint8_t volume);
