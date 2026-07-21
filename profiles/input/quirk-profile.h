/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Gamepad Quirk Support
 *
 *  External quirk profile loader. Reads JSON profiles from a system
 *  directory, verifies HMAC signatures, and registers them with the
 *  quirk dispatch layer.
 *
 *  Security model:
 *    - Profiles live in /var/lib/bluez/quirks/ (root:root 0755)
 *    - Each profile has a .sig sidecar with HMAC-SHA256
 *    - The HMAC key is machine-specific (.hmac_key, mode 0600)
 *    - bluetoothd validates signatures before loading
 *    - Descriptor size capped at 2048 bytes
 */

#ifndef __INPUT_QUIRK_PROFILE_H
#define __INPUT_QUIRK_PROFILE_H

/* Directory where installed (signed) profiles live */
#define QUIRK_PROFILE_DIR "/var/lib/bluez/quirks"

/* Maximum size of an HID report descriptor from a profile */
#define QUIRK_MAX_DESCRIPTOR_SIZE 2048

/* Load all verified external quirk profiles from the given directory.
 * Populates the external quirk registry. Safe to call with NULL or
 * a nonexistent directory (silently returns 0). */
int load_external_quirks(const char *dir);

/* Free all loaded external quirks. Called on shutdown. */
void free_external_quirks(void);

#endif
