/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Intel Corporation
 *
 *
 */

#define BTD_BEARER_BREDR_INTERFACE	"org.bluez.Bearer.BREDR1"
#define BTD_BEARER_LE_INTERFACE		"org.bluez.Bearer.LE1"

struct btd_bearer;

struct btd_bearer *btd_bearer_new(struct btd_device *device, uint8_t type);
void btd_bearer_destroy(struct btd_bearer *bearer);

void btd_bearer_paired(struct btd_bearer *bearer);
void btd_bearer_bonded(struct btd_bearer *bearer);
void btd_bearer_connected(struct btd_bearer *bearer);
void btd_bearer_disconnected(struct btd_bearer *bearer, uint8_t reason);
