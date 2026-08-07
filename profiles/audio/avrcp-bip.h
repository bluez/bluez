/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  AVRCP 1.6 Cover Art Responder
 *
 *  Copyright (C) 2026 Jan-Michael Brummer <jan.brummer@tabos.org>
 *
 */

#ifndef __AVRCP_BIP_H
#define __AVRCP_BIP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

uint16_t avrcp_bip_server_start(void);

void avrcp_bip_server_stop(void);

bool avrcp_bip_server_active(void);

uint16_t avrcp_bip_server_get_psm(void);

const char *avrcp_bip_set_cover_art(const uint8_t *data, size_t len);

void avrcp_bip_clear_cover_art(void);

#endif /* __AVRCP_BIP_H */
