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

static const btpan_callbacks_t *bt_pan_cbacks = NULL;

static bool interface_ready(void)
{
	return bt_pan_cbacks != NULL;
}

static bt_status_t bt_pan_enable(int local_role)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	return BT_STATUS_UNSUPPORTED;
}

static int bt_pan_get_local_role(void)
{
	DBG("");

	if (!interface_ready())
		return BTPAN_ROLE_NONE;

	return BTPAN_ROLE_NONE;
}

static bt_status_t bt_pan_connect(const bt_bdaddr_t *bd_addr, int local_role,
					int remote_role)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_pan_disconnect(const bt_bdaddr_t *bd_addr)
{
	DBG("");

	if (!interface_ready())
		return BT_STATUS_NOT_READY;

	if (!bd_addr)
		return BT_STATUS_PARM_INVALID;

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t bt_pan_init(const btpan_callbacks_t *callbacks)
{
	DBG("");

	bt_pan_cbacks = callbacks;

	/* TODO: start HID Host thread */

	/* TODO: enable service */

	return BT_STATUS_SUCCESS;
}

static void bt_pan_cleanup()
{
	DBG("");

	if (!interface_ready())
		return;

	/* TODO: disable service */

	/* TODO: stop PAN thread */

	bt_pan_cbacks = NULL;
}

static btpan_interface_t bt_pan_if = {
	.size = sizeof(bt_pan_if),
	.init = bt_pan_init,
	.enable = bt_pan_enable,
	.get_local_role = bt_pan_get_local_role,
	.connect = bt_pan_connect,
	.disconnect = bt_pan_disconnect,
	.cleanup = bt_pan_cleanup
};

btpan_interface_t *bt_get_pan_interface()
{
	return &bt_pan_if;
}
