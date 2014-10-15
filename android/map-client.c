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

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <glib.h>

#include "ipc.h"
#include "lib/bluetooth.h"
#include "map-client.h"
#include "src/log.h"
#include "hal-msg.h"

static struct ipc *hal_ipc = NULL;
static bdaddr_t adapter_addr;

static void handle_get_instances(const void *buf, uint16_t len)
{
	DBG("");

	ipc_send_rsp(hal_ipc, HAL_SERVICE_ID_MAP_CLIENT,
			HAL_OP_MAP_CLIENT_GET_INSTANCES, HAL_STATUS_FAILED);
}

static const struct ipc_handler cmd_handlers[] = {
	/* HAL_OP_MAP_CLIENT_GET_INSTANCES */
	{ handle_get_instances, false,
			sizeof(struct hal_cmd_map_client_get_instances) },
};

bool bt_map_client_register(struct ipc *ipc, const bdaddr_t *addr, uint8_t mode)
{
	DBG("");

	bacpy(&adapter_addr, addr);

	hal_ipc = ipc;

	ipc_register(hal_ipc, HAL_SERVICE_ID_MAP_CLIENT, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_map_client_unregister(void)
{
	DBG("");

	ipc_unregister(hal_ipc, HAL_SERVICE_ID_MAP_CLIENT);
	hal_ipc = NULL;
}
