/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

struct gatt_primary {
	char uuid[MAX_LEN_UUID_STR + 1];
	gboolean changed;
	struct att_range range;
};

gboolean gatt_parse_record(const sdp_record_t *rec,
					uuid_t *prim_uuid, uint16_t *psm,
					uint16_t *start, uint16_t *end);
