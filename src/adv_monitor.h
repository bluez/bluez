/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020 Google LLC
 *
 *
 */

#ifndef __ADV_MONITOR_H
#define __ADV_MONITOR_H

struct mgmt;
struct btd_adapter;
struct btd_adv_monitor_manager;

struct btd_adv_monitor_manager *btd_adv_monitor_manager_create(
						struct btd_adapter *adapter,
						struct mgmt *mgmt);
void btd_adv_monitor_manager_destroy(struct btd_adv_monitor_manager *manager);

#endif /* __ADV_MONITOR_H */
