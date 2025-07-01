/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2015  ARRI Lighting. All rights reserved.
 *
 *
 */

#include <stdint.h>

struct mesh_net;

void proxy_cfg_msg_received(struct mesh_net *net, uint32_t net_key_id,
					uint32_t iv_index,
					const uint8_t *data, uint8_t size);
