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
#include "ipc-common.h"
#include "hal-ipc.h"

static const bthl_callbacks_t *cbacks = NULL;

static bool interface_ready(void)
{
	return cbacks != NULL;
}

/* handlers will be called from notification thread context,
 * index in table equals to 'opcode - HAL_MINIMUM_EVENT' */
static const struct hal_ipc_handler ev_handlers[] = {
};

static bt_status_t unregister_application(int app_id)
{
	struct hal_cmd_health_unreg_app cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.app_id = app_id;

	return hal_ipc_cmd(HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_UNREG_APP,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t connect_channel(int app_id, bt_bdaddr_t *bd_addr,
					int mdep_cfg_index, int *channel_id)
{
	struct hal_cmd_health_connect_channel cmd;
	struct hal_rsp_health_connect_channel rsp;
	size_t len = sizeof(rsp);
	bt_status_t status;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr || !channel_id)
		return BT_STATUS_PARM_INVALID;

	cmd.app_id = app_id;
	cmd.mdep_index = mdep_cfg_index;
	memcpy(cmd.bdaddr, bd_addr, sizeof(cmd.bdaddr));

	status = hal_ipc_cmd(HAL_SERVICE_ID_HEALTH,
					HAL_OP_HEALTH_CONNECT_CHANNEL,
					sizeof(cmd), &cmd, &len, &rsp, NULL);

	if (status == HAL_STATUS_SUCCESS)
		*channel_id = rsp.channel_id;

	return status;
}

static bt_status_t destroy_channel(int channel_id)
{
	struct hal_cmd_health_destroy_channel cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.channel_id = channel_id;

	return hal_ipc_cmd(HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_DESTROY_CHANNEL,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static bt_status_t init(bthl_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int ret;

	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	/* store reference to user callbacks */
	cbacks = callbacks;

	hal_ipc_register(HAL_SERVICE_ID_HEALTH, ev_handlers,
				sizeof(ev_handlers)/sizeof(ev_handlers[0]));

	cmd.service_id = HAL_SERVICE_ID_HEALTH;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	if (ret != BT_STATUS_SUCCESS) {
		cbacks = NULL;
		hal_ipc_unregister(HAL_SERVICE_ID_HEALTH);
	}

	return ret;
}

static void cleanup(void)
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	cbacks = NULL;

	cmd.service_id = HAL_SERVICE_ID_HEALTH;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	hal_ipc_unregister(HAL_SERVICE_ID_HEALTH);
}

static bthl_interface_t health_if = {
	.size = sizeof(health_if),
	.init = init,
	.register_application = NULL,
	.unregister_application = unregister_application,
	.connect_channel = connect_channel,
	.destroy_channel = destroy_channel,
	.cleanup = cleanup
};

bthl_interface_t *bt_get_health_interface(void)
{
	return &health_if;
}
