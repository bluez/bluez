/*
 * Copyright (C) 2013 Intel Corporation
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

#include "hal-log.h"
#include "hal.h"
#include "hal-msg.h"
#include "hal-ipc.h"

static const btpan_callbacks_t *cbs = NULL;

static bool interface_ready(void)
{
	return cbs != NULL;
}

static bt_status_t pan_enable(int local_role)
{
	struct hal_cmd_pan_enable cmd;

	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	cmd.local_role = local_role;

	return hal_ipc_cmd(HAL_SERVICE_ID_PAN, HAL_OP_PAN_ENABLE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static int pan_get_local_role(void)
{
	DBG("");

	if (!interface_ready())
		return BTPAN_ROLE_NONE;

	return BTPAN_ROLE_NONE;
}

static bt_status_t pan_connect(const bt_bdaddr_t *bd_addr, int local_role,
					int remote_role)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t pan_disconnect(const bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t pan_init(const btpan_callbacks_t *callbacks)
{
	struct hal_cmd_register_module cmd;

	DBG("");

	cbs = callbacks;

	cmd.service_id = HAL_SERVICE_ID_PAN;

	return hal_ipc_cmd(HAL_SERVICE_ID_CORE, HAL_OP_REGISTER_MODULE,
					sizeof(cmd), &cmd, 0, NULL, NULL);
}

static void pan_cleanup()
{
	DBG("");

	if (!interface_ready())
		return;

	/* TODO: disable service */

	/* TODO: stop PAN thread */

	cbs = NULL;
}

static btpan_interface_t pan_if = {
	.size = sizeof(pan_if),
	.init = pan_init,
	.enable = pan_enable,
	.get_local_role = pan_get_local_role,
	.connect = pan_connect,
	.disconnect = pan_disconnect,
	.cleanup = pan_cleanup
};

btpan_interface_t *bt_get_pan_interface()
{
	return &pan_if;
}
