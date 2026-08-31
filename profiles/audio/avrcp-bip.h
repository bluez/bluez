/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  AVRCP 1.6 Cover Art Responder (BIP over OBEX/L2CAP, Target role)
 *
 *  Copyright (C) 2026  tabos.org
 *
 */

#ifndef __AVRCP_BIP_H
#define __AVRCP_BIP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Start the global BIP Cover Art responder. Reference counted, called
 * once per adapter using it. Returns the L2CAP PSM the OBEX server is
 * listening on, or 0 on failure.
 */
uint16_t avrcp_bip_server_start(void);

/* Drop one reference; the listener is closed with the last user. */
void avrcp_bip_server_stop(void);

/* Whether the responder is currently listening. */
bool avrcp_bip_server_active(void);

/* L2CAP PSM of the running responder (0 if inactive). */
uint16_t avrcp_bip_server_get_psm(void);

/*
 * Register the cover art of the current track. The data must be a
 * complete JPEG image. Returns the 7-digit BIP image handle to be
 * exposed as media attribute 0x08 (valid until replaced), or NULL
 * on error.
 */
const char *avrcp_bip_set_cover_art(const uint8_t *data, size_t len);

/* Remove all registered images (e.g. on playback stop). */
void avrcp_bip_clear_cover_art(void);

#endif /* __AVRCP_BIP_H */
