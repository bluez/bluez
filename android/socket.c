/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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

#include <glib.h>
#include <stdbool.h>
#include <errno.h>

#include "lib/bluetooth.h"
#include "btio/btio.h"
#include "lib/sdp.h"
#include "log.h"
#include "hal-msg.h"
#include "hal-ipc.h"
#include "ipc.h"
#include "socket.h"

#define OPP_DEFAULT_CHANNEL	9
#define PBAP_DEFAULT_CHANNEL	15

static bdaddr_t adapter_addr;

static struct profile_info {
	uint8_t		uuid[16];
	uint8_t		channel;
	uint8_t		svc_hint;
	BtIOSecLevel	sec_level;
	sdp_record_t *	(*create_record)(uint8_t chan);
} profiles[] = {
	{
		.uuid = {
			0x00, 0x00, 0x11, 0x2F, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
		},
		.channel = PBAP_DEFAULT_CHANNEL
	}, {
		.uuid = {
			0x00, 0x00, 0x11, 0x05, 0x00, 0x00, 0x10, 0x00,
			0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB
		  },
		.channel = OPP_DEFAULT_CHANNEL
	}
};

static struct profile_info *get_profile_by_uuid(const uint8_t *uuid)
{
	unsigned int i;

	for (i = 0; i < G_N_ELEMENTS(profiles); i++) {
		if (!memcmp(profiles[i].uuid, uuid, 16))
			return &profiles[i];
	}

	return NULL;
}

static int handle_listen(void *buf)
{
	struct hal_cmd_sock_listen *cmd = buf;
	struct profile_info *profile;
	int chan;

	DBG("");

	profile = get_profile_by_uuid(cmd->uuid);
	if (!profile)
		return -1;

	chan = profile->channel;

	DBG("rfcomm channel %d", chan);

	return -1;
}

static int handle_connect(void *buf)
{
	DBG("Not implemented");

	return -1;
}

void bt_sock_handle_cmd(int sk, uint8_t opcode, void *buf, uint16_t len)
{
	int fd;

	switch (opcode) {
	case HAL_OP_SOCK_LISTEN:
		fd = handle_listen(buf);
		if (fd < 0)
			break;

		ipc_send(sk, HAL_SERVICE_ID_SOCK, opcode, 0, NULL, fd);
		return;
	case HAL_OP_SOCK_CONNECT:
		fd = handle_connect(buf);
		if (fd < 0)
			break;

		ipc_send(sk, HAL_SERVICE_ID_SOCK, opcode, 0, NULL, fd);
		return;
	default:
		DBG("Unhandled command, opcode 0x%x", opcode);
		break;
	}

	ipc_send_rsp(sk, HAL_SERVICE_ID_SOCK, opcode, HAL_STATUS_FAILED);
}

bool bt_socket_register(int sk, const bdaddr_t *addr)
{
	DBG("");

	bacpy(&adapter_addr, addr);

	return true;
}

void bt_socket_unregister(void)
{
	DBG("");
}
