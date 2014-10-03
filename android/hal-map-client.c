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

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

static const btmce_callbacks_t *cbs = NULL;

static bool interface_ready(void)
{
	return cbs != NULL;
}

/* Event Handlers */

static void handle_remote_mas_instances(void *buf, uint16_t len, int fd)
{

}

/*
 * handlers will be called from notification thread context,
 * index in table equals to 'opcode - HAL_MINIMUM_EVENT'
 */
static const struct hal_ipc_handler ev_handlers[] = {
	/* HAL_EV_MCE_REMOTE_MAS_INSTANCES */
	{ handle_remote_mas_instances, true,
			sizeof(struct hal_ev_map_client_remote_mas_instances) }
};

/* API */

static bt_status_t get_remote_mas_instances(bt_bdaddr_t *bd_addr)
{
	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t init(btmce_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int ret;

	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	cbs = callbacks;

	hal_ipc_register(HAL_SERVICE_ID_MAP_CLIENT, ev_handlers,
				sizeof(ev_handlers)/sizeof(ev_handlers[0]));

	cmd.service_id = HAL_SERVICE_ID_MAP_CLIENT;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	if (ret != BT_STATUS_SUCCESS) {
		cbs = NULL;
		hal_ipc_unregister(HAL_SERVICE_ID_MAP_CLIENT);
	}

	return ret;
}

static btmce_interface_t iface = {
	.size = sizeof(iface),
	.init = init,
	.get_remote_mas_instances = get_remote_mas_instances
};

btmce_interface_t *bt_get_map_client_interface(void)
{
	return &iface;
}
