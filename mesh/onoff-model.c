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

#include "client/display.h"
#include "src/shared/util.h"
#include "mesh/mesh-net.h"
#include "mesh/keys.h"
#include "mesh/net.h"
#include "mesh/node.h"
#include "mesh/prov-db.h"
#include "mesh/util.h"
#include "mesh/onoff-model.h"

static uint8_t trans_id;
static uint16_t onoff_app_idx = APP_IDX_INVALID;

static int client_bind(uint16_t app_idx, int action)
{
	if (action == ACTION_ADD) {
		if (onoff_app_idx != APP_IDX_INVALID) {
			return MESH_STATUS_INSUFF_RESOURCES;
		} else {
			onoff_app_idx = app_idx;
			rl_printf("On/Off client model: new binding %4.4x\n",
								app_idx);
		}
	} else {
		if (onoff_app_idx == app_idx)
			onoff_app_idx = APP_IDX_INVALID;
	}
	return MESH_STATUS_SUCCESS;
}

static void print_remaining_time(uint8_t remaining_time)
{
	uint8_t step = (remaining_time & 0xc0) >> 6;
	uint8_t count = remaining_time & 0x3f;
	int secs = 0, msecs = 0, minutes = 0, hours = 0;

	switch (step) {
	case 0:
		msecs = 100 * count;
		secs = msecs / 60;
		msecs -= (secs * 60);
		break;
	case 1:
		secs = 1 * count;
		minutes = secs / 60;
		secs -= (minutes * 60);
		break;

	case 2:
		secs = 10 * count;
		minutes = secs / 60;
		secs -= (minutes * 60);
		break;
	case 3:
		minutes = 10 * count;
		hours = minutes / 60;
		minutes -= (hours * 60);
		break;

	default:
		break;
	}

	rl_printf("\n\t\tRemaining time: %d hrs %d mins %d secs %d msecs\n",
						hours, minutes, secs, msecs);

}

static bool client_msg_recvd(uint16_t src, uint8_t *data,
				uint16_t len, void *user_data)
{
	uint32_t opcode;
	int n;

	if (mesh_opcode_get(data, len, &opcode, &n)) {
		len -= n;
		data += n;
	} else
		return false;

	rl_printf("On Off Model Message received (%d) opcode %x\n",
								len, opcode);
	print_byte_array("\t",data, len);

	switch (opcode & ~OP_UNRELIABLE) {
	default:
		return false;

	case OP_GENERIC_ONOFF_STATUS:
		if (len != 1 && len != 3)
			break;

		rl_printf("Node %4.4x: Off Status present = %s",
						src, data[0] ? "ON" : "OFF");

		if (len == 3) {
			rl_printf(", target = %s", data[1] ? "ON" : "OFF");
			print_remaining_time(data[2]);
		} else
			rl_printf("\n");
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
						"expected format 4 digit hex\n",
			args);
		target = UNASSIGNED_ADDRESS;
	} else {
		rl_printf("Controlling ON/OFF for node %4.4x\n", dst);
		target = dst;
		set_menu_prompt("on/off", args);
	}
}

static bool send_cmd(uint8_t *buf, uint16_t len)
{
	struct mesh_node *node = node_get_local_node();
	uint8_t ttl;

	if(!node)
		return false;

	ttl = node_get_default_ttl(node);

	return net_access_layer_send(ttl, node_get_primary(node),
					target, onoff_app_idx, buf, len);
}

static void cmd_get_status(const char *args)
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

	n = mesh_opcode_set(OP_GENERIC_ONOFF_GET, msg);

	if (!send_cmd(msg, n))
		rl_printf("Failed to send \"GENERIC ON/OFF GET\"\n");
}

static void cmd_set(const char *args)
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

	if ((read_input_parameters(args) != 1) &&
					parms[0] != 0 && parms[0] != 1) {
		rl_printf("Bad arguments %s. Expecting \"0\" or \"1\"\n", args);
		return;
	}

	n = mesh_opcode_set(OP_GENERIC_ONOFF_SET, msg);
	msg[n++] = parms[0];
	msg[n++] = trans_id++;

	if (!send_cmd(msg, n))
		rl_printf("Failed to send \"GENERIC ON/OFF SET\"\n");

}

static void cmd_back(const char *args)
{
	cmd_menu_main(false);
}

static void cmd_help(const char *args);

static const struct menu_entry cfg_menu[] = {
	{"target",		"<unicast>",			cmd_set_node,
						"Set node to configure"},
	{"get",			NULL,				cmd_get_status,
						"Get ON/OFF status"},
	{"onoff",		"<0/1>",			cmd_set,
						"Send \"SET ON/OFF\" command"},
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

void onoff_set_node(const char *args) {
	cmd_set_node(args);
}

static struct mesh_model_ops client_cbs = {
	client_msg_recvd,
	client_bind,
	NULL,
	NULL
};

bool onoff_client_init(uint8_t ele)
{
	if (!node_local_model_register(ele, GENERIC_ONOFF_CLIENT_MODEL_ID,
					&client_cbs, NULL))
		return false;

	add_cmd_menu("onoff", cfg_menu);

	return true;
}
