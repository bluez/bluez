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

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

static const bthf_callbacks_t *cbs = NULL;

static bool interface_ready(void)
{
	return cbs != NULL;
}

/* handlers will be called from notification thread context,
 * index in table equals to 'opcode - HAL_MINIMUM_EVENT' */
static const struct hal_ipc_handler ev_handlers[] = {

};

static bt_status_t init(bthf_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;
	int ret;

	DBG("");

	if (interface_ready())
		return BT_STATUS_DONE;

	cbs = callbacks;

	hal_ipc_register(HAL_SERVICE_ID_HANDSFREE, ev_handlers,
				sizeof(ev_handlers)/sizeof(ev_handlers[0]));

	cmd.service_id = HAL_SERVICE_ID_HANDSFREE;

	ret = hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	if (ret != BT_STATUS_SUCCESS) {
		cbs = NULL;
		hal_ipc_unregister(HAL_SERVICE_ID_HANDSFREE);
	}

	return ret;
}

static void cleanup(void)
{
	struct hal_cmd_unregister_module cmd;

	DBG("");

	if (!interface_ready())
		return;

	cbs = NULL;

	cmd.service_id = HAL_SERVICE_ID_HANDSFREE;

	hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_UNREGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);

	hal_ipc_unregister(HAL_SERVICE_ID_HANDSFREE);
}

static bthf_interface_t iface = {
	.size = sizeof(iface),
	.init = init,
	.cleanup = cleanup
};

bthf_interface_t *bt_get_handsfree_interface(void)
{
	return &iface;
}
