/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2023  Intel Corporation. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>
#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/appkey.h"
#include "mesh/model.h"
#include "mesh/mesh-config.h"
#include "mesh/prv-beacon.h"

#define NOT_SUPPORTED 0x02

static bool prvbec_srv_pkt(uint16_t src, uint16_t dst, uint16_t app_idx,
				uint16_t net_idx, const uint8_t *data,
				uint16_t size, const void *user_data)
{
	struct mesh_node *node = (struct mesh_node *) user_data;
	const uint8_t *pkt = data;
	uint32_t opcode;
	uint8_t msg[5];
	uint16_t n;
	uint8_t period;

	if (app_idx != APP_IDX_DEV_LOCAL)
		return false;

	if (mesh_model_opcode_get(pkt, size, &opcode, &n)) {
		size -= n;
		pkt += n;
	} else
		return false;

	l_debug("PRV-BEAC-SRV-opcode 0x%x size %u idx %3.3x", opcode, size,
								net_idx);

	n = 0;

	switch (opcode) {
	default:
		return false;

	case OP_PRIVATE_BEACON_SET:
		if (size == 1)
			node_mpb_mode_get(node, &period);
		else if (size == 2)
			period = pkt[1];
		else
			return true;

		if (pkt[0] > 1)
			return true;

		node_mpb_mode_set(node, !!pkt[0], period);

		/* fall through */

	case OP_PRIVATE_BEACON_GET:
		n = mesh_model_opcode_set(OP_PRIVATE_BEACON_STATUS, msg);

		msg[n++] = node_mpb_mode_get(node, &period);
		msg[n++] = period;

		l_debug("Get/Set Private Beacon (%d)", msg[n-2]);
		break;

	case OP_PRIVATE_GATT_PROXY_SET:
		/* fall through */
	case OP_PRIVATE_GATT_PROXY_GET:
		n = mesh_model_opcode_set(OP_PRIVATE_GATT_PROXY_STATUS, msg);
		msg[n++] = NOT_SUPPORTED;
		break;

	case OP_PRIVATE_NODE_ID_SET:
		/* fall through */
	case OP_PRIVATE_NODE_ID_GET:
		n = mesh_model_opcode_set(OP_PRIVATE_NODE_ID_STATUS, msg);
		msg[n++] = NOT_SUPPORTED;
		break;
	}

	if (n)
		mesh_model_send(node, dst, src, APP_IDX_DEV_LOCAL, net_idx,
						DEFAULT_TTL, false, n, msg);

	return true;
}

static void prvbec_srv_unregister(void *user_data)
{
}

static const struct mesh_model_ops ops = {
	.unregister = prvbec_srv_unregister,
	.recv = prvbec_srv_pkt,
	.bind = NULL,
	.sub = NULL,
	.pub = NULL
};

void prv_beacon_server_init(struct mesh_node *node, uint8_t ele_idx)
{
	l_debug("%2.2x", ele_idx);
	mesh_model_register(node, ele_idx, PRV_BEACON_SRV_MODEL, &ops, node);
}
