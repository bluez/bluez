/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 *
 */

struct btd_adapter;
struct btd_device;
struct btd_ranging_provider_manager;

struct btd_ranging_provider_manager *
btd_ranging_provider_manager_create(struct btd_adapter *adapter);
void btd_ranging_provider_manager_destroy(
	struct btd_ranging_provider_manager *manager);
void btd_ranging_provider_manager_device_removed(
	struct btd_ranging_provider_manager *manager,
	struct btd_device *device);
