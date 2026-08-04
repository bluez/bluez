// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2026  Red Hat Inc.
 *
 *
 */

#include "avrcp-parse.h"
#include "src/shared/util.h"

gboolean parse_media_element_name(uint8_t *operands, uint16_t len,
					 char *name, uint16_t *namesize)
{
	uint16_t namelen;

	if (len < 13)
		return FALSE;

	memset(name, 0, NAME_MAX_LEN);
	*namesize = MIN(get_be16(&operands[11]), len - 13);
	namelen = MIN(*namesize, NAME_MAX_LEN - 1);

	if (len < 13 + *namesize)
		return FALSE;

	if (namelen > 0) {
		memcpy(name, &operands[13], namelen);
		strtoutf8(name, namelen);
	}

	return TRUE;
}

gboolean parse_media_folder_name(uint8_t *operands, uint16_t len,
					char *name)
{
	uint16_t namelen;

	if (len < 12)
		return FALSE;

	memset(name, 0, NAME_MAX_LEN);
	namelen = MIN(get_be16(&operands[12]), len - 14);
	namelen = MIN(namelen, NAME_MAX_LEN - 1);
	if (namelen > 0)
		memcpy(name, &operands[14], namelen);

	return TRUE;
}
