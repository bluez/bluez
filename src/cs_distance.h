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
struct btd_cs_distance;
struct btd_cs_distance_provider_manager;

struct btd_cs_distance *btd_cs_distance_register(const char *path,
						 const char *provider_path);
bool btd_cs_distance_unregister(struct btd_cs_distance *distance);
bool btd_cs_distance_update(struct btd_cs_distance *distance, double meters);

struct btd_cs_distance_provider_manager *
btd_cs_distance_provider_manager_create(struct btd_adapter *adapter);
void btd_cs_distance_provider_manager_destroy(struct
	btd_cs_distance_provider_manager *manager);
