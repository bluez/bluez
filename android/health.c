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

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <glib.h>

#include "lib/bluetooth.h"
#include "lib/sdp.h"
#include "lib/sdp_lib.h"
#include "src/log.h"

#include "hal-msg.h"
#include "ipc-common.h"
#include "ipc.h"
#include "utils.h"
#include "bluetooth.h"
#include "health.h"

static bdaddr_t adapter_addr;
static struct ipc *hal_ipc = NULL;

static void bt_health_register_app(const void *buf, uint16_t len)
{
	DBG("Not implemented");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_REG_APP,
							HAL_STATUS_UNSUPPORTED);
}

static void bt_health_mdep_cfg_data(const void *buf, uint16_t len)
{
	DBG("Not implemented");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_MDEP,
							HAL_STATUS_UNSUPPORTED);
}

static void bt_health_unregister_app(const void *buf, uint16_t len)
{
	DBG("Not implemented");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH, HAL_OP_HEALTH_UNREG_APP,
							HAL_STATUS_UNSUPPORTED);
}

static void bt_health_connect_channel(const void *buf, uint16_t len)
{
	DBG("Not implemented");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH,
			HAL_OP_HEALTH_CONNECT_CHANNEL, HAL_STATUS_UNSUPPORTED);
}

static void bt_health_destroy_channel(const void *buf, uint16_t len)
{
	DBG("Not implemented");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_HEALTH,
			HAL_OP_HEALTH_DESTROY_CHANNEL, HAL_STATUS_UNSUPPORTED);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_HEALTH_REG_APP */
	{ bt_health_register_app, true,
				sizeof(struct hal_cmd_health_reg_app) },
	/* HAL_OP_HEALTH_MDEP */
	{ bt_health_mdep_cfg_data, true,
				sizeof(struct hal_cmd_health_mdep) },
	/* HAL_OP_HEALTH_UNREG_APP */
	{ bt_health_unregister_app, false,
				sizeof(struct hal_cmd_health_unreg_app) },
	/* HAL_OP_HEALTH_CONNECT_CHANNEL */
	{ bt_health_connect_channel, false,
				sizeof(struct hal_cmd_health_connect_channel) },
	/* HAL_OP_HEALTH_DESTROY_CHANNEL */
	{ bt_health_destroy_channel, false,
				sizeof(struct hal_cmd_health_destroy_channel) },
};

bool bt_health_register(struct ipc *ipc, const bdaddr_t *addr, uint8_t mode)
{
	DBG("");

	bacpy(&adapter_addr, addr);

	hal_ipc = ipc;
	ipc_register(hal_ipc, HAL_SERVICE_ID_HEALTH, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_health_unregister(void)
{
	DBG("");

	ipc_unregister(hal_ipc, HAL_SERVICE_ID_HEALTH);
	hal_ipc = NULL;
}
