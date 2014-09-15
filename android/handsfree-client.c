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

static const struct ipc_handler cmd_handlers[] = {
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
