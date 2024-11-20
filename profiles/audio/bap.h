/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright 2024 NXP
 *
 */

struct bt_bap *bap_get_session(struct btd_device *device);
void bap_scan_delegator_probe(struct btd_device *device);

void bap_iso_qos_to_bap_qos(struct bt_iso_qos *iso_qos,
				struct bt_bap_qos *bap_qos);
void bap_qos_to_iso_qos(struct bt_bap_qos *bap_qos,
				struct bt_iso_qos *iso_qos);
