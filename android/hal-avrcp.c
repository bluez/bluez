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

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

static const btrc_callbacks_t *cbs = NULL;

static bool interface_ready(void)
{
	return cbs != NULL;
}

static bt_status_t init(btrc_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int ret;

	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	cbs = callbacks;

	cmd.service_id = HAL_SERVICE_ID_AVRCP;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	if (ret != BT_STATUS_SUCCESS) {
		cbs = NULL;
		hal_ipc_unregister(HAL_SERVICE_ID_AVRCP);
	}

	return ret;
}

static bt_status_t get_play_status_rsp(btrc_play_status_t status,
					uint32_t song_len, uint32_t song_pos)
{
	struct hal_cmd_avrcp_get_play_status cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.status = status;
	cmd.duration = song_len;
	cmd.position = song_pos;

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP, HAL_OP_AVRCP_GET_PLAY_STATUS,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t list_player_app_attr_rsp(int num_attr,
						btrc_player_attr_t *p_attrs)
{
	char buf[BLUEZ_HAL_MTU];
	struct hal_cmd_avrcp_list_player_attrs *cmd = (void *) buf;
	size_t len;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (num_attr < 0)
		return BT_STATUS_PARM_INVALID;

	len = sizeof(*cmd) + num_attr;
	if (len > BLUEZ_HAL_MTU)
		return BT_STATUS_PARM_INVALID;

	cmd->number = num_attr;
	memcpy(cmd->attrs, p_attrs, num_attr);

	return hal_ipc_cmd(HAL_SERVICE_ID_AVRCP,
					HAL_OP_AVRCP_LIST_PLAYER_ATTRS,
					len, cmd, 0, NULL, NULL);
}

static void cleanup()
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	cbs = NULL;

	cmd.service_id = HAL_SERVICE_ID_AVRCP;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	hal_ipc_unregister(HAL_SERVICE_ID_AVRCP);
}

static btrc_interface_t iface = {
	.size = sizeof(iface),
	.init = init,
	.get_play_status_rsp = get_play_status_rsp,
	.list_player_app_attr_rsp = list_player_app_attr_rsp,
	.cleanup = cleanup
};

btrc_interface_t *bt_get_avrcp_interface()
{
	return &iface;
}
