/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <glib.h>

#include "lib/bluetooth.h"
#include "src/log.h"
#include "avrcp.h"
#include "hal-msg.h"
#include "ipc.h"

static bdaddr_t adapter_addr;

static const struct ipc_handler cmd_handlers[] = {
};

bool bt_avrcp_register(const bdaddr_t *addr)
{
	DBG("");

	bacpy(&adapter_addr, addr);

	ipc_register(HAL_SERVICE_ID_AVRCP, cmd_handlers,
						G_N_ELEMENTS(cmd_handlers));

	return true;
}

void bt_avrcp_unregister(void)
{
	DBG("");

	ipc_unregister(HAL_SERVICE_ID_AVRCP);
}
