/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

int server_start(const bdaddr_t *src, bool device_cable_pairing);
int server_set_cable_pairing(const bdaddr_t *src, bool device_cable_pairing);
void server_stop(const bdaddr_t *src);
