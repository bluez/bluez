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
#include "handsfree.h"
#include "bluetooth.h"
#include "src/log.h"
#include "hal-msg.h"
#include "ipc.h"

#define HFP_AG_CHANNEL 13
#define HFP_AG_FEATURES 0

static bdaddr_t adapter_addr;
static uint32_t record_id = 0;

static void handle_connect(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_CONNECT,
							HAL_STATUS_FAILED);
}

static void handle_disconnect(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_DISCONNECT,
							HAL_STATUS_FAILED);
}

static void handle_connect_audio(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_CONNECT_AUDIO,
							HAL_STATUS_FAILED);
}

static void handle_disconnect_audio(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE,
			HAL_OP_HANDSFREE_DISCONNECT_AUDIO, HAL_STATUS_FAILED);
}

static void handle_start_vr(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_START_VR,
							HAL_STATUS_FAILED);
}

static void handle_stop_vr(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_STOP_VR,
							HAL_STATUS_FAILED);
}

static void handle_volume_control(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_VOLUME_CONTROL,
							HAL_STATUS_FAILED);
}

static void handle_device_status_notif(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE,
					HAL_OP_HANDSFREE_DEVICE_STATUS_NOTIF,
					HAL_STATUS_FAILED);
}

static void handle_cops(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_COPS_RESPONSE,
							HAL_STATUS_FAILED);
}

static void handle_cind(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_CIND_RESPONSE,
							HAL_STATUS_FAILED);
}

static void handle_formatted_at_resp(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE,
					HAL_OP_HANDSFREE_FORMATTED_AT_RESPONSE,
					HAL_STATUS_FAILED);
}

static void handle_at_resp(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_AT_RESPONSE,
							HAL_STATUS_FAILED);
}

static void handle_clcc_resp(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE, HAL_OP_HANDSFREE_CLCC_RESPONSE,
							HAL_STATUS_FAILED);
}

static void handle_phone_state_change(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(HAL_SERVICE_ID_HANDSFREE,
					HAL_OP_HANDSFREE_PHONE_STATE_CHANGE,
					HAL_STATUS_FAILED);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_HANDSFREE_CONNECT */
	{ handle_connect, false, sizeof(struct hal_cmd_handsfree_connect)},
	/* HAL_OP_HANDSFREE_DISCONNECT */
	{handle_disconnect, false, sizeof(struct hal_cmd_handsfree_disconnect)},
	/*HAL_OP_HANDSFREE_CONNECT_AUDIO*/
	{handle_connect_audio, false,
			sizeof(struct hal_cmd_handsfree_connect_audio)},
	/*HAL_OP_HANDSFREE_DISCONNECT_AUDIO*/
	{handle_disconnect_audio, false,
			sizeof(struct hal_cmd_handsfree_disconnect_audio)},
	/* define HAL_OP_HANDSFREE_START_VR */
	{handle_start_vr, false, 0 },
	/* define HAL_OP_HANDSFREE_STOP_VR */
	{handle_stop_vr, false, 0 },
	/* HAL_OP_HANDSFREE_VOLUME_CONTROL */
	{handle_volume_control, false,
			sizeof(struct hal_cmd_handsfree_volume_control)},
	/* HAL_OP_HANDSFREE_DEVICE_STATUS_NOTIF */
	{handle_device_status_notif, false,
			sizeof(struct hal_cmd_handsfree_device_status_notif)},
	/* HAL_OP_HANDSFREE_COPS_RESPONSE */
	{handle_cops, true, sizeof(struct hal_cmd_handsfree_cops_response)},
	/* HAL_OP_HANDSFREE_CIND_RESPONSE */
	{ handle_cind, false, sizeof(struct hal_cmd_handsfree_cind_response)},
	/* HAL_OP_HANDSFREE_FORMATTED_AT_RESPONSE */
	{handle_formatted_at_resp, true,
			sizeof(struct hal_cmd_handsfree_formatted_at_response)},
	/* HAL_OP_HANDSFREE_AT_RESPONSE */
	{handle_at_resp, false, sizeof(struct hal_cmd_handsfree_at_response)},
	/* HAL_OP_HANDSFREE_CLCC_RESPONSE */
	{handle_clcc_resp, true,
			sizeof(struct hal_cmd_handsfree_clcc_response)},
	/* HAL_OP_HANDSFREE_PHONE_STATE_CHANGE */
	{handle_phone_state_change, true,
			sizeof(struct hal_cmd_handsfree_phone_state_change)},
};

static sdp_record_t *handsfree_ag_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *channel, *features;
	uint8_t netid = 0x01;
	uint16_t sdpfeat;
	sdp_data_t *network;
	uint8_t ch = HFP_AG_CHANNEL;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	network = sdp_data_alloc(SDP_UINT8, &netid);
	if (!network) {
		sdp_record_free(record);
		return NULL;
	}

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(0, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_AGW_SVCLASS_ID);
	svclass_id = sdp_list_append(0, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = 0x0106;
	pfseq = sdp_list_append(0, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(0, &l2cap_uuid);
	apseq = sdp_list_append(0, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(0, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	sdpfeat = HFP_AG_FEATURES;
	features = sdp_data_alloc(SDP_UINT16, &sdpfeat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(0, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Hands-Free Audio Gateway", 0, 0);

	sdp_attr_add(record, SDP_ATTR_EXTERNAL_NETWORK, network);

	sdp_data_free(channel);
	sdp_list_free(proto[0], 0);
	sdp_list_free(proto[1], 0);
	sdp_list_free(apseq, 0);
	sdp_list_free(pfseq, 0);
	sdp_list_free(aproto, 0);
	sdp_list_free(root, 0);
	sdp_list_free(svclass_id, 0);

	return record;
}

bool bt_handsfree_register(const bdaddr_t *addr)
{
	sdp_record_t *rec;

	DBG("");

	bacpy(&adapter_addr, addr);

	rec = handsfree_ag_record();
	if (!rec) {
		error("Failed to allocate Handsfree record");
		return false;
	}

	if (bt_adapter_add_record(rec, 0) < 0) {
		error("Failed to register Handsfree record");
		sdp_record_free(rec);
		return false;
	}
	record_id = rec->handle;

	ipc_register(HAL_SERVICE_ID_HANDSFREE, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_handsfree_unregister(void)
{
	DBG("");

	ipc_unregister(HAL_SERVICE_ID_HANDSFREE);

	bt_adapter_remove_record(record_id);
	record_id = 0;
}
