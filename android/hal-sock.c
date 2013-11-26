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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hal-ipc.h"
#include "hal-log.h"
#include "hal-msg.h"
#include "hal-utils.h"
#include "hal.h"

static bt_status_t sock_listen_rfcomm(const char *service_name,
					const uint8_t *uuid, int chan,
					int *sock, int flags)
{
	struct hal_cmd_sock_listen cmd;

	DBG("");

	memset(&cmd, 0, sizeof(cmd));

	cmd.flags = flags;
	cmd.type = BTSOCK_RFCOMM;
	cmd.channel = chan;

	if (uuid)
		memcpy(cmd.uuid, uuid, sizeof(cmd.uuid));

	if (service_name)
		memcpy(cmd.name, service_name, strlen(service_name));

	return hal_ipc_cmd(HAL_SERVICE_ID_SOCK, HAL_OP_SOCK_LISTEN,
				sizeof(cmd), &cmd, NULL, NULL, sock);
}

static bt_status_t sock_listen(btsock_type_t type, const char *service_name,
					const uint8_t *uuid, int chan,
					int *sock, int flags)
{
	if ((!uuid && chan <= 0) || !sock) {
		error("Invalid params: uuid %s, chan %d, sock %p",
						btuuid2str(uuid), chan, sock);
		return BT_STATUS_PARM_INVALID;
	}

	DBG("uuid %s chan %d sock %p type %d service_name %s flags 0x%02x",
		btuuid2str(uuid), chan, sock, type, service_name, flags);

	switch (type) {
	case BTSOCK_RFCOMM:
		return sock_listen_rfcomm(service_name, uuid, chan, sock,
									flags);
	default:
		error("%s: Socket type %d not supported", __func__, type);
		break;
	}

	return BT_STATUS_UNSUPPORTED;
}

static bt_status_t sock_connect(const bt_bdaddr_t *bdaddr, btsock_type_t type,
					const uint8_t *uuid, int chan,
					int *sock, int flags)
{
	struct hal_cmd_sock_connect cmd;

	if ((!uuid && chan <= 0) || !bdaddr || !sock) {
		error("Invalid params: bd_addr %s, uuid %s, chan %d, sock %p",
			bdaddr2str(bdaddr), btuuid2str(uuid), chan, sock);
		return BT_STATUS_PARM_INVALID;
	}

	DBG("bdaddr %s uuid %s chan %d sock %p type %d flags 0x%02x",
		bdaddr2str(bdaddr), btuuid2str(uuid), chan, sock, type, flags);

	if (type != BTSOCK_RFCOMM) {
		error("Socket type %u not supported", type);
		return BT_STATUS_UNSUPPORTED;
	}

	memset(&cmd, 0, sizeof(cmd));

	cmd.flags = flags;
	cmd.type = type;
	cmd.channel = chan;

	if (uuid)
		memcpy(cmd.uuid, uuid, sizeof(cmd.uuid));

	memcpy(cmd.bdaddr, bdaddr, sizeof(cmd.bdaddr));

	return hal_ipc_cmd(HAL_SERVICE_ID_SOCK, HAL_OP_SOCK_CONNECT,
					sizeof(cmd), &cmd, NULL, NULL, sock);
}

static btsock_interface_t sock_if = {
	sizeof(sock_if),
	sock_listen,
	sock_connect
};

btsock_interface_t *bt_get_sock_interface(void)
{
	return &sock_if;
}
