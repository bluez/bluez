/*
 * Copyright (C) 2014 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <cutils/properties.h>

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "ipc-common.h"
#include "hal-ipc.h"

static const bthf_client_callbacks_t *cbs = NULL;

static bool interface_ready(void)
{
	return cbs != NULL;
}

/*
 * handlers will be called from notification thread context,
 * index in table equals to 'opcode - HAL_MINIMUM_EVENT'
 */
static const struct hal_ipc_handler ev_handlers[] = {
};

static bt_status_t init(bthf_client_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int ret;

	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	cbs = callbacks;

	hal_ipc_register(HAL_SERVICE_ID_HANDSFREE_CLIENT, ev_handlers,
				sizeof(ev_handlers)/sizeof(ev_handlers[0]));

	cmd.service_id = HAL_SERVICE_ID_HANDSFREE_CLIENT;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, NULL, NULL, NULL);

	if (ret != BT_STATUS_SUCCESS) {
		cbs = NULL;
		hal_ipc_unregister(HAL_SERVICE_ID_HANDSFREE_CLIENT);
	}

	return ret;
}

static bt_status_t hf_client_connect(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hf_client_connect cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_CONNECT, sizeof(cmd), &cmd,
				NULL, NULL, NULL);
}

static bt_status_t disconnect(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hf_client_disconnect cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_DISCONNECT, sizeof(cmd), &cmd,
				NULL, NULL, NULL);
}

static bt_status_t connect_audio(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hf_client_connect_audio cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_CONNECT_AUDIO, sizeof(cmd),
				&cmd, NULL, NULL, NULL);
}

static bt_status_t disconnect_audio(bt_bdaddr_t *bd_addr)
{
	struct hal_cmd_hf_client_disconnect_audio cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_DISCONNECT_AUDIO, sizeof(cmd),
				&cmd, NULL, NULL, NULL);
}

static bt_status_t start_voice_recognition(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_START_VR, 0, NULL, NULL, NULL,
				NULL);
}

static bt_status_t stop_voice_recognition(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_STOP_VR, 0, NULL, NULL, NULL,
				NULL);
}

static bt_status_t volume_control(bthf_client_volume_type_t type,
								int volume)
{
	struct hal_cmd_hf_client_volume_control cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.type = type;
	cmd.volume = volume;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_VOLUME_CONTROL, sizeof(cmd),
				&cmd, NULL, NULL, NULL);
}

static bt_status_t dial(const char *number)
{
	char buf[IPC_MTU];
	struct hal_cmd_hf_client_dial *cmd = (void *) buf;
	size_t len;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (number) {
		cmd->number_len = strlen(number) + 1;
		memcpy(cmd->number, number, cmd->number_len);
	} else {
		cmd->number_len = 0;
	}

	len = sizeof(*cmd) + cmd->number_len;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_DIAL, len, cmd, NULL, NULL,
				NULL);
}

static bt_status_t dial_memory(int location)
{
	struct hal_cmd_hf_client_dial_memory cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.location = location;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
					HAL_OP_HF_CLIENT_DIAL_MEMORY,
					sizeof(cmd), &cmd, NULL, NULL, NULL);
}

static bt_status_t call_action(bthf_client_call_action_t action, int index)
{
	struct hal_cmd_hf_client_call_action cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.action = action;
	cmd.index = index;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_CALL_ACTION, sizeof(cmd), &cmd,
				NULL, NULL, NULL);
}

static bt_status_t query_current_calls(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_QUERY_CURRENT_CALLS, 0, NULL,
				NULL, NULL, NULL);
}

static bt_status_t query_operator_name(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_QUERY_OPERATOR_NAME, 0, NULL,
				NULL, NULL, NULL);
}

static bt_status_t retrieve_subsr_info(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_RETRIEVE_SUBSCR_INFO, 0, NULL,
				NULL, NULL, NULL);
}

static bt_status_t send_dtmf(char tone)
{
	struct hal_cmd_hf_client_send_dtmf cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.tone = tone;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
				HAL_OP_HF_CLIENT_SEND_DTMF, sizeof(cmd), &cmd,
				NULL, NULL, NULL);
}

static bt_status_t request_last_voice_tag_number(void)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return hal_ipc_cmd(HAL_SERVICE_ID_HANDSFREE_CLIENT,
					HAL_OP_HF_CLIENT_GET_LAST_VOICE_TAG_NUM,
					0, NULL, NULL, NULL, NULL);
}

static void cleanup(void)
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	cbs = NULL;

	cmd.service_id = HAL_SERVICE_ID_HANDSFREE_CLIENT;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, NULL, NULL, NULL);

	hal_ipc_unregister(HAL_SERVICE_ID_HANDSFREE_CLIENT);
}

static bthf_client_interface_t iface = {
	.size = sizeof(iface),
	.init = init,
	.connect = hf_client_connect,
	.disconnect = disconnect,
	.connect_audio = connect_audio,
	.disconnect_audio = disconnect_audio,
	.start_voice_recognition = start_voice_recognition,
	.stop_voice_recognition = stop_voice_recognition,
	.volume_control = volume_control,
	.dial = dial,
	.dial_memory = dial_memory,
	.handle_call_action = call_action,
	.query_current_calls = query_current_calls,
	.query_current_operator_name = query_operator_name,
	.retrieve_subscriber_info = retrieve_subsr_info,
	.send_dtmf = send_dtmf,
	.request_last_voice_tag_number = request_last_voice_tag_number,
	.cleanup = cleanup
};

bthf_client_interface_t *bt_get_hf_client_interface(void)
{
	return &iface;
}
