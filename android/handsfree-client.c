/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/sdp-client.h"
#include "src/shared/queue.h"
#include "ipc.h"
#include "ipc-common.h"
#include "src/log.h"
#include "utils.h"

#include "bluetooth.h"
#include "hal-msg.h"
#include "handsfree-client.h"

#define HFP_HF_CHANNEL 7

#define HFP_HF_FEAT_ECNR	0x00000001
#define HFP_HF_FEAT_3WAY	0x00000002
#define HFP_HF_FEAT_CLI		0x00000004
#define HFP_HF_FEAT_VR		0x00000008
#define HFP_HF_FEAT_RVC		0x00000010
#define HFP_HF_FEAT_ECS		0x00000020
#define HFP_HF_FEAT_ECC		0x00000040
#define HFP_HF_FEAT_CODEC	0x00000080
#define HFP_HF_FEAT_HF_IND	0x00000100
#define HFP_HF_FEAT_ESCO_S4_T2	0x00000200


#define HFP_HF_FEATURES (HFP_HF_FEAT_ECNR | HFP_HF_FEAT_3WAY |\
				HFP_HF_FEAT_CLI | HFP_HF_FEAT_VR |\
				HFP_HF_FEAT_RVC | HFP_HF_FEAT_ECS |\
				HFP_HF_FEAT_ECC)

static bdaddr_t adapter_addr;

static struct ipc *hal_ipc = NULL;

static uint32_t hfp_hf_features = 0;
static uint32_t hfp_hf_record_id = 0;
static struct queue *devices = NULL;

static void handle_connect(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
			HAL_OP_HF_CLIENT_CONNECT, HAL_STATUS_UNSUPPORTED);
}

static void handle_disconnect(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
			HAL_OP_HF_CLIENT_DISCONNECT, HAL_STATUS_UNSUPPORTED);
}

static void handle_connect_audio(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
			HAL_OP_HF_CLIENT_CONNECT_AUDIO, HAL_STATUS_UNSUPPORTED);
}

static void handle_disconnect_audio(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
					HAL_OP_HF_CLIENT_DISCONNECT_AUDIO,
					HAL_STATUS_UNSUPPORTED);
}

static void handle_start_vr(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
			HAL_OP_HF_CLIENT_START_VR, HAL_STATUS_UNSUPPORTED);
}

static void handle_stop_vr(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
			HAL_OP_HF_CLIENT_STOP_VR, HAL_STATUS_UNSUPPORTED);
}

static void handle_volume_control(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
					HAL_OP_HF_CLIENT_VOLUME_CONTROL,
					HAL_STATUS_UNSUPPORTED);
}

static void handle_dial(const void *buf, uint16_t len)
{
	const struct hal_cmd_hf_client_dial *cmd = buf;

	if (len != sizeof(*cmd) + cmd->number_len) {
		error("Malformed number data, size (%u bytes), terminating",
									len);
		raise(SIGTERM);
		return;
	}

	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_DIAL, HAL_STATUS_UNSUPPORTED);
}

static void handle_dial_memory(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
			HAL_OP_HF_CLIENT_DIAL_MEMORY, HAL_STATUS_UNSUPPORTED);
}

static void handle_call_action(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
			HAL_OP_HF_CLIENT_CALL_ACTION, HAL_STATUS_UNSUPPORTED);
}

static void handle_query_current_calls(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
					HAL_OP_HF_CLIENT_QUERY_CURRENT_CALLS,
					HAL_STATUS_UNSUPPORTED);
}

static void handle_query_operator_name(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
					HAL_OP_HF_CLIENT_QUERY_OPERATOR_NAME,
					HAL_STATUS_UNSUPPORTED);
}

static void handle_retrieve_subscr_info(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
					HAL_OP_HF_CLIENT_RETRIEVE_SUBSCR_INFO,
					HAL_STATUS_UNSUPPORTED);
}

static void handle_send_dtmf(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
			HAL_OP_HF_CLIENT_SEND_DTMF, HAL_STATUS_UNSUPPORTED);
}

static void handle_get_last_vc_tag_num(const void *buf, uint16_t len)
{
	DBG("Not Implemented");
	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT,
					HAL_OP_HF_CLIENT_GET_LAST_VOICE_TAG_NUM,
					HAL_STATUS_UNSUPPORTED);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_HF_CLIENT_CONNECT */
	{ handle_connect, false,
				sizeof(struct hal_cmd_hf_client_connect) },
	/* HAL_OP_HF_CLIENT_DISCONNECT */
	{ handle_disconnect, false,
				sizeof(struct hal_cmd_hf_client_disconnect) },
	/* HAL_OP_HF_CLIENT_CONNECT_AUDIO */
	{ handle_connect_audio, false,
			sizeof(struct hal_cmd_hf_client_connect_audio) },
	/* HAL_OP_HF_CLIENT_DISCONNECT_AUDIO */
	{ handle_disconnect_audio, false,
			sizeof(struct hal_cmd_hf_client_disconnect_audio) },
	/* define HAL_OP_HF_CLIENT_START_VR */
	{ handle_start_vr, false, 0 },
	/* define HAL_OP_HF_CLIENT_STOP_VR */
	{ handle_stop_vr, false, 0 },
	/* HAL_OP_HF_CLIENT_VOLUME_CONTROL */
	{ handle_volume_control, false,
			sizeof(struct hal_cmd_hf_client_volume_control) },
	/* HAL_OP_HF_CLIENT_DIAL */
	{ handle_dial, true, sizeof(struct hal_cmd_hf_client_dial) },
	/* HAL_OP_HF_CLIENT_DIAL_MEMORY */
	{ handle_dial_memory, false,
				sizeof(struct hal_cmd_hf_client_dial_memory) },
	/* HAL_OP_HF_CLIENT_CALL_ACTION */
	{ handle_call_action, false,
				sizeof(struct hal_cmd_hf_client_call_action) },
	/* HAL_OP_HF_CLIENT_QUERY_CURRENT_CALLS */
	{ handle_query_current_calls, false, 0 },
	/* HAL_OP_HF_CLIENT_QUERY_OPERATOR_NAME */
	{ handle_query_operator_name, false, 0 },
	/* HAL_OP_HF_CLIENT_RETRIEVE_SUBSCR_INFO */
	{ handle_retrieve_subscr_info, false, 0 },
	/* HAL_OP_HF_CLIENT_SEND_DTMF */
	{ handle_send_dtmf, false,
				sizeof(struct hal_cmd_hf_client_send_dtmf) },
	/* HAL_OP_HF_CLIENT_GET_LAST_VOICE_TAG_NUM */
	{ handle_get_last_vc_tag_num, false, 0 },
};

static sdp_record_t *hfp_hf_record(void)
{
	sdp_list_t *svclass_id, *pfseq, *apseq, *root;
	uuid_t root_uuid, svclass_uuid, ga_svclass_uuid;
	uuid_t l2cap_uuid, rfcomm_uuid;
	sdp_profile_desc_t profile;
	sdp_list_t *aproto, *proto[2];
	sdp_record_t *record;
	sdp_data_t *channel, *features;
	uint16_t sdpfeat;
	uint8_t ch = HFP_HF_CHANNEL;

	record = sdp_record_alloc();
	if (!record)
		return NULL;

	sdp_uuid16_create(&root_uuid, PUBLIC_BROWSE_GROUP);
	root = sdp_list_append(NULL, &root_uuid);
	sdp_set_browse_groups(record, root);

	sdp_uuid16_create(&svclass_uuid, HANDSFREE_SVCLASS_ID);
	svclass_id = sdp_list_append(NULL, &svclass_uuid);
	sdp_uuid16_create(&ga_svclass_uuid, GENERIC_AUDIO_SVCLASS_ID);
	svclass_id = sdp_list_append(svclass_id, &ga_svclass_uuid);
	sdp_set_service_classes(record, svclass_id);

	sdp_uuid16_create(&profile.uuid, HANDSFREE_PROFILE_ID);
	profile.version = 0x0106;
	pfseq = sdp_list_append(NULL, &profile);
	sdp_set_profile_descs(record, pfseq);

	sdp_uuid16_create(&l2cap_uuid, L2CAP_UUID);
	proto[0] = sdp_list_append(NULL, &l2cap_uuid);
	apseq = sdp_list_append(NULL, proto[0]);

	sdp_uuid16_create(&rfcomm_uuid, RFCOMM_UUID);
	proto[1] = sdp_list_append(NULL, &rfcomm_uuid);
	channel = sdp_data_alloc(SDP_UINT8, &ch);
	proto[1] = sdp_list_append(proto[1], channel);
	apseq = sdp_list_append(apseq, proto[1]);

	/* Codec Negotiation bit in SDP feature is different then in BRSF */
	sdpfeat = hfp_hf_features & 0x0000003F;
	if (hfp_hf_features & HFP_HF_FEAT_CODEC)
		sdpfeat |= 0x00000020;
	else
		sdpfeat &= ~0x00000020;

	features = sdp_data_alloc(SDP_UINT16, &sdpfeat);
	sdp_attr_add(record, SDP_ATTR_SUPPORTED_FEATURES, features);

	aproto = sdp_list_append(NULL, apseq);
	sdp_set_access_protos(record, aproto);

	sdp_set_info_attr(record, "Hands-Free unit", NULL, NULL);

	sdp_data_free(channel);
	sdp_list_free(proto[0], NULL);
	sdp_list_free(proto[1], NULL);
	sdp_list_free(apseq, NULL);
	sdp_list_free(pfseq, NULL);
	sdp_list_free(aproto, NULL);
	sdp_list_free(root, NULL);
	sdp_list_free(svclass_id, NULL);

	return record;
}

static bool enable_hf_client(void)
{
	sdp_record_t *rec;

	hfp_hf_features = HFP_HF_FEATURES;

	rec = hfp_hf_record();
	if (!rec) {
		error("hf-client: Could not create service record");
		return false;
	}

	if (bt_adapter_add_record(rec, 0) < 0) {
		error("hf-client: Failed to register service record");
		sdp_record_free(rec);
		return false;
	}

	hfp_hf_record_id = rec->handle;

	return true;
}

static void cleanup_hfp_hf(void)
{
	if (hfp_hf_record_id > 0) {
		bt_adapter_remove_record(hfp_hf_record_id);
		hfp_hf_record_id = 0;
	}
}

bool bt_hf_client_register(struct ipc *ipc, const bdaddr_t *addr)
{
	DBG("");

	devices = queue_new();
	if (!devices) {
		error("hf-client: Could not create devices list");
		goto failed;
	}

	bacpy(&adapter_addr, addr);

	if (!enable_hf_client())
		goto failed;

	hal_ipc = ipc;
	ipc_register(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;

failed:
	queue_destroy(devices, free);
	devices = NULL;

	return false;
}

void bt_hf_client_unregister(void)
{
	DBG("");

	cleanup_hfp_hf();

	queue_destroy(devices, free);
	devices = NULL;

	ipc_unregister(hal_ipc, HAL_SERVICE_ID_HANDSFREE);
	hal_ipc = NULL;
}
