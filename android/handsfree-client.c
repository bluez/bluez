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
#include "ipc.h"
#include "ipc-common.h"
#include "src/log.h"
#include "utils.h"

#include "hal-msg.h"
#include "handsfree-client.h"

static bdaddr_t adapter_addr;

static struct ipc *hal_ipc = NULL;

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

bool bt_hf_client_register(struct ipc *ipc, const bdaddr_t *addr)
{
	DBG("");

	bacpy(&adapter_addr, addr);

	hal_ipc = ipc;
	ipc_register(hal_ipc, HAL_SERVICE_ID_HANDSFREE_CLIENT, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_hf_client_unregister(void)
{
	DBG("");

	ipc_unregister(hal_ipc, HAL_SERVICE_ID_HANDSFREE);
	hal_ipc = NULL;
}
