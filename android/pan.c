/*
 *  Copyright (C) 2013  Intel Corporation. All rights reserved.
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

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>

#include "lib/bluetooth.h"
#include "log.h"
#include "pan.h"
#include "hal-msg.h"
#include "ipc.h"

static int notification_sk = -1;

static uint8_t bt_pan_enable(struct hal_cmd_pan_enable *cmd, uint16_t len)
{
	DBG("Not Implemented");

	return HAL_STATUS_FAILED;
}

static uint8_t bt_pan_get_role(void *cmd, uint16_t len)
{
	DBG("Not Implemented");

	return HAL_STATUS_FAILED;
}

static uint8_t bt_pan_connect(struct hal_cmd_pan_connect *cmd, uint16_t len)
{
	DBG("Not Implemented");

	return HAL_STATUS_FAILED;
}

static uint8_t bt_pan_disconnect(struct hal_cmd_pan_connect *cmd, uint16_t len)
{
	DBG("Not Implemented");

	return HAL_STATUS_FAILED;
}

void bt_pan_handle_cmd(int sk, uint8_t opcode, void *buf, uint16_t len)
{
	uint8_t status = HAL_STATUS_FAILED;

	switch (opcode) {
	case HAL_OP_PAN_ENABLE:
		status = bt_pan_enable(buf, len);
		break;
	case HAL_OP_PAN_GET_ROLE:
		status = bt_pan_get_role(buf, len);
		break;
	case HAL_OP_PAN_CONNECT:
		status = bt_pan_connect(buf, len);
		break;
	case HAL_OP_PAN_DISCONNECT:
		status = bt_pan_disconnect(buf, len);
		break;
	default:
		DBG("Unhandled command, opcode 0x%x", opcode);
		break;
	}

	ipc_send_rsp(sk, HAL_SERVICE_ID_PAN, status);
}

bool bt_pan_register(int sk, const bdaddr_t *addr)
{
	DBG("");

	notification_sk = sk;

	return true;
}

void bt_pan_unregister(void)
{
	DBG("");

	notification_sk = -1;
}
