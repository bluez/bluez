/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *  Lesser General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "src/shared/shell.h"
#include "src/shared/util.h"

#include "mesh/mesh-defs.h"
#include "tools/mesh/remote.h"

static struct l_queue *nodes;

void remote_add_node(const uint8_t uuid[16], uint16_t unicast,
					uint8_t ele_cnt, uint16_t net_idx)
{
	struct remote_node *rmt = l_new(struct remote_node, 1);

	memcpy(rmt->uuid, uuid, 16);
	rmt->unicast = unicast;
	rmt->num_ele = ele_cnt;
	rmt->net_keys = l_queue_new();

	l_queue_push_tail(rmt->net_keys, L_UINT_TO_PTR(net_idx));

	if (!nodes)
		nodes = l_queue_new();

	l_queue_push_tail(nodes, rmt);
}

static bool match_node_addr(const void *a, const void *b)
{
	const struct remote_node *rmt = a;
	uint16_t addr = L_PTR_TO_UINT(b);

	if (addr >= rmt->unicast &&
				addr <= (rmt->unicast + rmt->num_ele - 1))
		return true;

	return false;
}

uint16_t remote_get_subnet_idx(uint16_t addr)
{
	struct remote_node *rmt;
	uint32_t net_idx;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));

	if (!rmt || l_queue_isempty(rmt->net_keys))
		return NET_IDX_INVALID;

	net_idx = L_PTR_TO_UINT(l_queue_peek_head(rmt->net_keys));

	return (uint16_t) net_idx;
}

static void print_subnet(void *net_key, void *user_data)
{
	uint16_t net_idx = L_PTR_TO_UINT(net_key);

	bt_shell_printf("%3.3x ", net_idx);
}

static void print_node(void *rmt, void *user_data)
{
	struct remote_node *node = rmt;
	char *str;

	bt_shell_printf(COLOR_YELLOW "Mesh node:\n" COLOR_OFF);
	str = l_util_hexstring_upper(node->uuid, 16);
	bt_shell_printf("\t" COLOR_GREEN "UUID = %s\n" COLOR_OFF, str);
	l_free(str);
	bt_shell_printf("\t" COLOR_GREEN "primary = %4.4x\n" COLOR_OFF,
								node->unicast);
	bt_shell_printf("\t" COLOR_GREEN "elements = %u\n" COLOR_OFF,
								node->num_ele);
	bt_shell_printf("\t" COLOR_GREEN "net_keys = ");
	l_queue_foreach(node->net_keys, print_subnet, NULL);
	bt_shell_printf("\n" COLOR_OFF);
}

void remote_print_node(uint16_t addr)
{
	struct remote_node *rmt;

	if (!nodes)
		return;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));
	if (!rmt)
		return;

	print_node(rmt, NULL);
}

void remote_print_all(void)
{
	if (!nodes)
		return;

	l_queue_foreach(nodes, print_node, NULL);
}
