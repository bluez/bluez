// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Red Hat Inc.
 *
 *
 */

#include <glib.h>
#include <inttypes.h>

#define NAME_MAX_LEN 255

gboolean parse_media_element_name(uint8_t *operands, uint16_t len,
					 char *name, uint16_t *namesize);
gboolean parse_media_folder_name(uint8_t *operands, uint16_t len,
					char *name);
