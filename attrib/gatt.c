// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2010  Nokia Corporation
 *  Copyright (C) 2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/sdp.h"
#include "bluetooth/sdp_lib.h"
#include "bluetooth/uuid.h"

#include "att.h"
#include "gatt.h"

static sdp_data_t *proto_seq_find(sdp_list_t *proto_list)
{
	sdp_list_t *list;
	uuid_t proto;

	sdp_uuid16_create(&proto, ATT_UUID);

	for (list = proto_list; list; list = list->next) {
		sdp_list_t *p;
		for (p = list->data; p; p = p->next) {
			sdp_data_t *seq = p->data;
			if (seq && seq->dtd == SDP_UUID16 &&
				sdp_uuid16_cmp(&proto, &seq->val.uuid) == 0)
				return seq->next;
		}
	}

	return NULL;
}

static gboolean parse_proto_params(sdp_list_t *proto_list, uint16_t *psm,
						uint16_t *start, uint16_t *end)
{
	sdp_data_t *seq1, *seq2;

	if (psm)
		*psm = sdp_get_proto_port(proto_list, L2CAP_UUID);

	/* Getting start and end handle */
	seq1 = proto_seq_find(proto_list);
	if (!seq1 || seq1->dtd != SDP_UINT16)
		return FALSE;

	seq2 = seq1->next;
	if (!seq2 || seq2->dtd != SDP_UINT16)
		return FALSE;

	if (start)
		*start = seq1->val.uint16;

	if (end)
		*end = seq2->val.uint16;

	return TRUE;
}

gboolean gatt_parse_record(const sdp_record_t *rec,
					uuid_t *prim_uuid, uint16_t *psm,
					uint16_t *start, uint16_t *end)
{
	sdp_list_t *list;
	uuid_t uuid;
	gboolean ret;

	if (sdp_get_service_classes(rec, &list) < 0)
		return FALSE;

	memcpy(&uuid, list->data, sizeof(uuid));
	sdp_list_free(list, free);

	if (sdp_get_access_protos(rec, &list) < 0)
		return FALSE;

	ret = parse_proto_params(list, psm, start, end);

	sdp_list_foreach(list, (sdp_list_func_t) sdp_list_free, NULL);
	sdp_list_free(list, NULL);

	/* FIXME: replace by bt_uuid_t after uuid_t/sdp code cleanup */
	if (ret && prim_uuid)
		memcpy(prim_uuid, &uuid, sizeof(uuid_t));

	return ret;
}
