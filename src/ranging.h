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
struct btd_ranging;
struct btd_ranging_provider_manager;

struct btd_ranging *btd_ranging_register(
	struct btd_ranging_provider_manager *manager,
	const char *path, const char *provider_path);
bool btd_ranging_unregister(struct btd_ranging *ranging);
bool btd_ranging_update(struct btd_ranging *ranging,
	uint32_t distance_millimeters);

struct btd_ranging_provider_manager *
btd_ranging_provider_manager_create(struct btd_adapter *adapter);
void btd_ranging_provider_manager_destroy(
	struct btd_ranging_provider_manager *manager);
