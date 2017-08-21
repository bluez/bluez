/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <wordexp.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <glib.h>

#include "src/shared/util.h"
#include "client/display.h"
#include "mesh/mesh-net.h"
#include "mesh/keys.h"
#include "mesh/net.h"
#include "mesh/node.h"
#include "mesh/prov-db.h"
#include "mesh/util.h"
#include "mesh/config-model.h"

#define MIN_COMPOSITION_LEN 16

static bool client_msg_recvd(uint16_t src, uint8_t *data,
				uint16_t len, void *user_data)
{
	uint32_t opcode;
	struct mesh_node *node;
	uint16_t app_idx, net_idx, addr;
	uint32_t mod_id;
	uint16_t primary;
	uint16_t ele_addr;
	uint8_t ele_idx;
	struct mesh_publication pub;
	int n;

	if (mesh_opcode_get(data, len, &opcode, &n)) {
		len -= n;
		data += n;
	} else
		return false;

	if (IS_UNICAST(src)) {
		node = node_find_by_addr(src);
	} else
		node = NULL;

	if (!node)
		return false;

	primary = node_get_primary(node);
	if (primary != src)
		return false;

	switch (opcode & ~OP_UNRELIABLE) {
	default:
		return false;

	case OP_DEV_COMP_STATUS:
		if (len < MIN_COMPOSITION_LEN || !node)
			break;
		if (node_parse_composition(node, data, len)) {
			if (!prov_db_add_node_composition(node, data, len))
				break;
		}

		if (node_get_composition(node))
			prov_db_print_node_composition(node);
		break;

	case OP_APPKEY_STATUS:
		if (len != 4)
			break;

		rl_printf("Node %4.4x AppKey Status %s\n", src,
						mesh_status_str(data[0]));
		net_idx = get_le16(data + 1) & 0xfff;
		app_idx = get_le16(data + 2) >> 4;

		rl_printf("\tNetKey %3.3x, AppKey %3.3x\n", net_idx, app_idx);

		if (data[0] != MESH_STATUS_SUCCESS &&
				data[0] != MESH_STATUS_IDX_ALREADY_STORED &&
				node_app_key_delete(node, net_idx, app_idx))
			prov_db_node_keys(node, node_get_app_keys(node),
								"appKeys");
		break;

	case OP_NETKEY_STATUS:
		if (len != 3)
			break;

		rl_printf("Node %4.4x NetKey Status %s\n", src,
						mesh_status_str(data[0]));
		net_idx = get_le16(data + 1) & 0xfff;

		rl_printf("\tNetKey %3.3x\n", net_idx);

		if (data[0] != MESH_STATUS_SUCCESS &&
				data[0] != MESH_STATUS_IDX_ALREADY_STORED &&
					node_net_key_delete(node, net_idx))
			prov_db_node_keys(node, node_get_net_keys(node),
								"netKeys");
		break;

	case OP_MODEL_APP_STATUS:
		if (len != 7 && len != 9)
			break;

		rl_printf("Node %4.4x Model App Status %s\n", src,
						mesh_status_str(data[0]));
		addr = get_le16(data + 1);
		app_idx = get_le16(data + 3);

		rl_printf("\tElement %4.4x AppIdx %3.3x\n ", addr, app_idx);

		if (len == 7) {
			mod_id = get_le16(data + 5);
			rl_printf("ModelId %4.4x\n", mod_id);
			mod_id = 0xffff0000 | mod_id;
		} else {
			mod_id = get_le16(data + 7);
			rl_printf("ModelId %4.4x %4.4x\n", get_le16(data + 5),
									mod_id);
			mod_id = get_le16(data + 5) << 16 | mod_id;
		}

		if (data[0] == MESH_STATUS_SUCCESS &&
			node_add_binding(node, addr - src, mod_id, app_idx))
			prov_db_add_binding(node, addr - src, mod_id, app_idx);
		break;

	case OP_CONFIG_DEFAULT_TTL_STATUS:
		if (len != 1)
			return true;
		rl_printf("Node %4.4x Default TTL %d\n", src, data[0]);
		if (node_set_default_ttl (node, data[0]))
			prov_db_node_set_ttl(node, data[0]);
		break;

	case OP_CONFIG_MODEL_PUB_STATUS:
		if (len != 12 && len != 14)
			return true;

		rl_printf("\nSet publication for node %4.4x status: %s\n", src,
				data[0] == MESH_STATUS_SUCCESS ? "Success" :
						mesh_status_str(data[0]));

		if (data[0] != MESH_STATUS_SUCCESS)
			return true;

		ele_addr = get_le16(data + 1);
		mod_id = get_le16(data + 10);
		if (len == 14)
			mod_id = (mod_id << 16)  | get_le16(data + 12);
		else
			mod_id |= 0xffff0000;

		pub.u.addr16 = get_le16(data + 3);
		pub.app_idx = get_le16(data + 5);
		pub.ttl = data[7];
		pub.period = data[8];
		n = (data[8] & 0x3f);
		switch (data[8] >> 6) {
		case 0:
			rl_printf("Period: %d ms\n", n * 100);
			break;
		case 2:
			n *= 10;
			/* fall through */
		case 1:
			rl_printf("Period: %d sec\n", n);
			break;
		case 3:
			rl_printf("Period: %d min\n", n * 10);
			break;
		}

		pub.retransmit = data[9];
		rl_printf("Retransmit count: %d\n", data[9] >> 5);
		rl_printf("Retransmit Interval Steps: %d\n", data[9] & 0x1f);

		ele_idx = ele_addr - node_get_primary(node);

		/* Local configuration is saved by server */
		if (node == node_get_local_node())
			break;

		if (node_model_pub_set(node, ele_idx, mod_id, &pub))
			prov_db_node_set_model_pub(node, ele_idx, mod_id,
				     node_model_pub_get(node, ele_idx, mod_id));
		break;
	}
	return true;
}

static uint32_t target;
static uint32_t parms[8];

static uint32_t read_input_parameters(const char *args)
{
	uint32_t i;

	if (!args)
		return 0;

	memset(parms, 0xff, sizeof(parms));

	for (i = 0; i < sizeof(parms)/sizeof(parms[0]); i++) {
		int n;

		sscanf(args, "%x", &parms[i]);
		if (parms[i] == 0xffffffff)
			break;

		n = strcspn(args, " \t");
		args = args + n + strspn(args + n, " \t");
	}

	return i;
}

static void cmd_set_node(const char *args)
{
	uint32_t dst;
	char *end;

	dst = strtol(args, &end, 16);
	if (end != (args + 4)) {
		rl_printf("Bad unicast address %s: "
					"expected format 4 digit hex\n", args);
		target = UNASSIGNED_ADDRESS;
	} else {
		rl_printf("Configuring node %4.4x\n", dst);
		target = dst;
		set_menu_prompt("config", args);
	}

}

static bool config_send(uint8_t *buf, uint16_t len)
{
	struct mesh_node *node = node_get_local_node();
	uint16_t primary;

	if(!node)
		return false;

	primary = node_get_primary(node);
	if (target != primary)
		return net_access_layer_send(DEFAULT_TTL, primary,
						target, APP_IDX_DEV, buf, len);

	node_local_data_handler(primary, target, node_get_iv_index(node),
				node_get_sequence_number(node), APP_IDX_DEV,
				buf, len);
	return true;

}

static void cmd_get_composition(const char *args)
{
	uint16_t n;
	uint8_t msg[32];
	struct mesh_node *node;

	if (IS_UNASSIGNED(target)) {
		rl_printf("Destination not set\n");
		return;
	}

	node = node_find_by_addr(target);

	if (!node)
		return;

	n = mesh_opcode_set(OP_DEV_COMP_GET, msg);

	/* By default, use page 0 */
	msg[n++] = (read_input_parameters(args) == 1) ? parms[0] : 0;

	if (!config_send(msg, n))
		rl_printf("Failed to send \"GET NODE COMPOSITION\"\n");
}

static void cmd_net_key(const char *args, uint32_t opcode)
{
	uint16_t n;
	uint8_t msg[32];
	uint16_t net_idx;
	uint8_t *key;
	struct mesh_node *node;

	if (IS_UNASSIGNED(target)) {
		rl_printf("Destination not set\n");
		return;
	}

	n = mesh_opcode_set(opcode, msg);

	if (read_input_parameters(args) != 1) {
		rl_printf("Bad arguments %s\n", args);
		return;
	}

	node = node_find_by_addr(target);
	if (!node) {
		rl_printf("Node %4.4x\n not found", target);
		return;
	}

	net_idx = parms[0];

	if (opcode != OP_NETKEY_DELETE) {

		key = keys_net_key_get(net_idx, true);
		if (!key) {
			rl_printf("Network key with index %4.4x not found\n",
								net_idx);
			return;
		}

		put_le16(net_idx, &msg[n]);
		n += 2;

		memcpy(msg + n, key, 16);
		n += 16;
	}

	if (!config_send(msg, n)) {
		rl_printf("Failed to send \"%s NET KEY\"\n",
				opcode == OP_NETKEY_ADD ? "ADD" : "DEL");
		return;
	}

	if (opcode != OP_NETKEY_DELETE) {
		if (node_net_key_add(node, net_idx))
			prov_db_node_keys(node, node_get_net_keys(node),
								"netKeys");
	} else {
		if (node_net_key_delete(node, net_idx))
			prov_db_node_keys(node, node_get_net_keys(node),
								"netKeys");
	}

}

static void cmd_add_net_key(const char *args)
{
	cmd_net_key(args, OP_NETKEY_ADD);
}

static void cmd_del_net_key(const char *args)
{
	cmd_net_key(args, OP_NETKEY_DELETE);
}

static void cmd_app_key(const char *args, uint32_t opcode)
{
	uint16_t n;
	uint8_t msg[32];
	uint16_t net_idx;
	uint16_t app_idx;
	uint8_t *key;
	struct mesh_node *node;

	if (IS_UNASSIGNED(target)) {
		rl_printf("Destination not set\n");
		return;
	}

	if (read_input_parameters(args) != 1) {
		rl_printf("Bad arguments %s\n", args);
		return;
	}

	node = node_find_by_addr(target);
	if (!node) {
		rl_printf("Node %4.4x\n not found", target);
		return;
	}

	n = mesh_opcode_set(opcode, msg);

	app_idx = parms[0];
	net_idx = keys_app_key_get_bound(app_idx);
	if (net_idx == NET_IDX_INVALID) {
		rl_printf("App key with index %4.4x not found\n", app_idx);
		return;
	}

	msg[n++] = net_idx & 0xf;
	msg[n++] = ((net_idx >> 8) & 0xf) |
		((app_idx << 4) & 0xf0);
	msg[n++] = app_idx >> 4;

	if (opcode != OP_APPKEY_DELETE) {
		key = keys_app_key_get(app_idx, true);
		if (!key) {
			rl_printf("App key %4.4x not found\n", net_idx);
			return;
		}

		memcpy(msg + n, key, 16);
		n += 16;
	}

	if (!config_send(msg, n)) {
		rl_printf("Failed to send \"ADD %s KEY\"\n",
				opcode == OP_APPKEY_ADD ? "ADD" : "DEL");
		return;
	}

	if (opcode != OP_APPKEY_DELETE) {
		if (node_app_key_add(node, app_idx))
			prov_db_node_keys(node, node_get_app_keys(node),
								"appKeys");
	} else {
		if (node_app_key_delete(node, net_idx, app_idx))
			prov_db_node_keys(node, node_get_app_keys(node),
								"appKeys");
	}
}

static void cmd_add_app_key(const char *args)
{
	cmd_app_key(args, OP_APPKEY_ADD);
}

static void cmd_del_app_key(const char *args)
{
	cmd_app_key(args, OP_APPKEY_DELETE);
}

static void cmd_bind(const char *args)
{
	uint16_t n;
	uint8_t msg[32];
	int parm_cnt;

	if (IS_UNASSIGNED(target)) {
		rl_printf("Destination not set\n");
		return;
	}

	parm_cnt = read_input_parameters(args);
	if (parm_cnt != 3 && parm_cnt != 4) {
		rl_printf("Bad arguments %s\n", args);
		return;
	}

	n = mesh_opcode_set(OP_MODEL_APP_BIND, msg);

	put_le16(target + parms[0], msg + n);
	n += 2;
	put_le16(parms[1], msg + n);
	n += 2;
	if (parm_cnt == 4) {
		put_le16(parms[3], msg + n);
		put_le16(parms[2], msg + n + 2);
		n += 4;
	} else {
		put_le16(parms[2], msg + n);
		n += 2;
	}

	if (!config_send(msg, n))
		rl_printf("Failed to send \"MODEL APP BIND\"\n");
}

static void cmd_set_ttl(const char *args)
{
	uint16_t n;
	uint8_t msg[32];
	int parm_cnt;
	uint8_t ttl;

	if (IS_UNASSIGNED(target)) {
		rl_printf("Destination not set\n");
		return;
	}

	n = mesh_opcode_set(OP_CONFIG_DEFAULT_TTL_SET, msg);

	parm_cnt = read_input_parameters(args);
	if (parm_cnt) {
		ttl = parms[0] & TTL_MASK;
	} else
		ttl = node_get_default_ttl(node_get_local_node());

	msg[n++] = ttl;

	if (!config_send(msg, n))
		rl_printf("Failed to send \"SET_DEFAULT TTL\"\n");
}

static void cmd_set_pub(const char *args)
{
	uint16_t n;
	uint8_t msg[32];
	int parm_cnt;

	if (IS_UNASSIGNED(target)) {
		rl_printf("Destination not set\n");
		return;
	}

	n = mesh_opcode_set(OP_CONFIG_MODEL_PUB_SET, msg);

	parm_cnt = read_input_parameters(args);
	if (parm_cnt != 5) {
		rl_printf("Bad arguments: %s\n", args);
		return;
	}

	put_le16(parms[0], msg + n);
	n += 2;
	/* Publish address */
	put_le16(parms[1], msg + n);
	n += 2;
	/* App key index + credential (set to 0) */
	put_le16(parms[2], msg + n);
	n += 2;
	/* TTL */
	msg[n++] = DEFAULT_TTL;
	/* Publish period  step count and step resolution */
	msg[n++] = parms[3];
	/* Publish retransmit count & interval steps */
	msg[n++] = (1 << 5) + 2;
	/* Model Id */
	if (parms[4] > 0xffff) {
		put_le16(parms[4] >> 16, msg + n);
		put_le16(parms[4], msg + n + 2);
		n += 4;
	} else {
		put_le16(parms[4], msg + n);
		n += 2;
	}

	if (!config_send(msg, n))
		rl_printf("Failed to send \"SET MODEL PUBLICATION\"\n");
}

static void cmd_default(uint32_t opcode)
{
	uint16_t n;
	uint8_t msg[32];

	if (IS_UNASSIGNED(target)) {
		rl_printf("Destination not set\n");
		return;
	}

	n = mesh_opcode_set(opcode, msg);

	if (!config_send(msg, n))
		rl_printf("Failed to send command (opcode 0x%x)\n", opcode);
}

static void cmd_get_ttl(const char *args)
{
	cmd_default(OP_CONFIG_DEFAULT_TTL_GET);
}

static void cmd_back(const char *args)
{
	cmd_menu_main(false);
}

static void cmd_help(const char *args);

static const struct menu_entry cfg_menu[] = {
	{"target",		"<unicast>",			cmd_set_node,
						"Set target node to configure"},
	{"get-composition",	"[<page_num>]",		cmd_get_composition,
						"Get Composition Data"},
	{"add-netkey",		"<net_idx>",			cmd_add_net_key,
						"Add network key"},
	{"del-netkey",		"<net_idx>",			cmd_del_net_key,
						"Delete network key"},
	{"add-appkey",		"<app_idx>",			cmd_add_app_key,
						"Add application key"},
	{"del-appkey",		"<app_idx>",			cmd_del_app_key,
						"Delete application key"},
	{"bind",		"<ele_idx> <app_idx> <mod_id> [cid]",
				cmd_bind,	"Bind app key to a model"},
	{"set-ttl",		"<ttl>",			cmd_set_ttl,
						"Set default TTL"},
	{"get-ttl",		NULL,			cmd_get_ttl,
						"Get default TTL"},
	{"set-pub", "<ele_addr> <pub_addr> <app_idx> "
						"<period (step|res)> <model>",
				cmd_set_pub,	"Set publication"},
	{"back",		NULL,				cmd_back,
						"Back to main menu"},
	{"help",		NULL,				cmd_help,
						"Config Commands"},
	{}
};

static void cmd_help(const char *args)
{
	rl_printf("Client Configuration Menu\n");
	print_cmd_menu(cfg_menu);
}

void config_set_node(const char *args)
{
	cmd_set_node(args);
}

void config_client_get_composition(uint32_t dst)
{
	uint32_t tmp = target;

	target = dst;
	cmd_get_composition("");
	target = tmp;
}

static struct mesh_model_ops client_cbs = {
	client_msg_recvd,
		NULL,
		NULL,
		NULL
};

bool config_client_init(void)
{
	if (!node_local_model_register(PRIMARY_ELEMENT_IDX,
						CONFIG_CLIENT_MODEL_ID,
						&client_cbs, NULL))
		return false;

	add_cmd_menu("configure", cfg_menu);

	return true;
}
