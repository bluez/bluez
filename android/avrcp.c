/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/log.h"
#include "bluetooth.h"
#include "avrcp.h"
#include "hal-msg.h"
#include "ipc.h"

#define L2CAP_PSM_AVCTP 0x17

#define AVRCP_FEATURE_CATEGORY_1	0x0001
#define AVRCP_FEATURE_CATEGORY_2	0x0002
#define AVRCP_FEATURE_CATEGORY_3	0x0004
#define AVRCP_FEATURE_CATEGORY_4	0x0008

static bdaddr_t adapter_addr;
static uint32_t record_id = 0;

static const struct ipc_handler cmd_handlers[] = {
};

static sdp_record_t *avrcp_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, l2cap, avctp, avrtg;
	sdp_profile_desc_t profile[1];
	sdp_list_t *aproto_control, *proto_control[2];
	sdp_record_t *record;
	sdp_data_t *psm, *version, *features;
	uint16_t lp = L2CAP_PSM_AVCTP;
	uint16_t avrcp_ver = 0x0100, avctp_ver = 0x0103;
	uint16_t feat = ( AVRCP_FEATURE_CATEGORY_1 |
					AVRCP_FEATURE_CATEGORY_2 |
					AVRCP_FEATURE_CATEGORY_3 |
					AVRCP_FEATURE_CATEGORY_4);

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	/* Service Class ID List */
	sdp_uuid16_create(&avrtg, AV_REMOTE_TARGET_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &avrtg);
	sdp_set_service_classes(record, svclass_id);

	/* Protocol Descriptor List */
	sdp_uuid16_create(&l2cap, L2CAP_UUID);
	proto_control[0] = sdp_list_append(NULL, &l2cap);
	psm = sdp_data_alloc(SDP_UINT16, &lp);
	proto_control[0] = sdp_list_append(proto_control[0], psm);
	apseq = sdp_list_append(NULL, proto_control[0]);

	sdp_uuid16_create(&avctp, AVCTP_UUID);
	proto_control[1] = sdp_list_append(NULL, &avctp);
	version = sdp_data_alloc(SDP_UINT16, &avctp_ver);
	proto_control[1] = sdp_list_append(proto_control[1], version);
	apseq = sdp_list_append(apseq, proto_control[1]);

	aproto_control = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto_control);

	/* Bluetooth Profile Descriptor List */
	sdp_uuid16_create(&profile[0].uuid, AV_REMOTE_PROFILE_ID);
	profile[0].version = avrcp_ver;
	pfseq = sdp_list_append(NULL, &profile[0]);
	sdp_set_profile_descs(record, pfseq);

	features = sdp_data_alloc(SDP_UINT16, &feat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	sdp_set_info_attr(record, "AVRCP TG", 0, 0);

	sdp_data_free(psm);
	sdp_data_free(version);
	sdp_list_free(proto_control[0], NULL);
	sdp_list_free(proto_control[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(aproto_control, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

bool bt_avrcp_register(const bdaddr_t *addr)
{
	sdp_record_t *rec;

	DBG("");

	bacpy(&adapter_addr, addr);

	rec = avrcp_record();
	if (!rec) {
		error("Failed to allocate AVRCP record");
		return false;
	}

	if (bt_adapter_add_record(rec, 0) < 0) {
		error("Failed to register AVRCP record");
		sdp_record_free(rec);
		return false;
	}
	record_id = rec->handle;

	ipc_register(HAL_SERVICE_ID_AVRCP, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_avrcp_unregister(void)
{
	DBG("");

	ipc_unregister(HAL_SERVICE_ID_AVRCP);

	bt_adapter_remove_record(record_id);
	record_id = 0;
}
