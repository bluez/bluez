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
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <dbus/dbus.h>
#include <stdio.h>
#include <time.h>
#include <ell/ell.h>

#include "src/shared/shell.h"
#include "src/shared/util.h"

#include "mesh/mesh.h"
#include "mesh/mesh-defs.h"

#include "tools/mesh/agent.h"
#include "tools/mesh/cfgcli.h"
#include "tools/mesh/keys.h"
#include "tools/mesh/model.h"

#define PROMPT_ON	COLOR_BLUE "[mesh-cfgclient]" COLOR_OFF "# "
#define PROMPT_OFF	"Waiting to connect to bluetooth-meshd..."

#define CFG_SRV_MODEL	0x0000
#define CFG_CLI_MODEL	0x0001

#define UNPROV_SCAN_MAX_SECS	300

#define DEFAULT_START_ADDRESS	0x00aa
#define DEFAULT_NET_INDEX	0x0000

struct meshcfg_el {
	const char *path;
	uint8_t index;
	uint16_t mods[2];
};

struct meshcfg_app {
	const char *path;
	const char *agent_path;
	struct meshcfg_el ele;
	uint16_t cid;
	uint16_t pid;
	uint16_t vid;
	uint16_t crpl;
	uint8_t uuid[16];
};

struct meshcfg_node {
	const char *path;
	struct l_dbus_proxy *proxy;
	struct l_dbus_proxy *mgmt_proxy;
	union {
		uint64_t u64;
		uint8_t u8[8];
	} token;
};

struct unprov_device {
	time_t last_seen;
	int16_t rssi;
	uint8_t uuid[16];
};

struct remote_node {
	uint16_t unicast;
	uint16_t net_idx;
	uint8_t uuid[16];
	uint8_t num_ele;
};

static struct l_dbus *dbus;

static struct l_queue *node_proxies;
static struct l_dbus_proxy *net_proxy;
static struct meshcfg_node *local;
static struct model_info *cfgcli;

static struct l_queue *devices;
static struct l_queue *nodes;

static bool prov_in_progress;
static const char *caps[2] = {"out-numeric", "in-numeric"};

static struct meshcfg_app app = {
	.path = "/mesh/cfgclient",
	.agent_path = "/mesh/cfgclient/agent",
	.cid = 0x05f1,
	.pid = 0x0002,
	.vid = 0x0001,
	.crpl = 10,
	.ele = {
		.path = "/mesh/cfgclient/ele0",
		.index = 0,
		.mods = {CFG_SRV_MODEL, CFG_CLI_MODEL}
	}
};

static const struct option options[] = {
	{ "address",	optional_argument, 0, 'a' },
	{ "net-index",	optional_argument, 0, 'n' },
	{ 0, 0, 0, 0 }
};

static const char *address_opt;
static const char *net_idx_opt;

static uint16_t prov_address;
static uint16_t prov_net_idx;

static const char **optargs[] = {
	&address_opt,
	&net_idx_opt,
};

static const char *help[] = {
	"Starting unicast address for remote nodes",
	"Net index for provisioning subnet"
};

static const struct bt_shell_opt opt = {
	.options = options,
	.optno = sizeof(options) / sizeof(struct option),
	.optstr = "a:n:",
	.optarg = optargs,
	.help = help,
};

static const char *dbus_err_args = "org.freedesktop.DBus.Error.InvalidArgs";
static const char *dbus_err_fail = "org.freedesktop.DBus.Error.Failed";
static const char *dbus_err_support = "org.freedesktop.DBus.Error.NotSupported";

static bool parse_argument_on_off(int argc, char *argv[], bool *value)
{
	if (!strcmp(argv[1], "on") || !strcmp(argv[1], "yes")) {
		*value = TRUE;
		return TRUE;
	}

	if (!strcmp(argv[1], "off") || !strcmp(argv[1], "no")) {
		*value = FALSE;
		return TRUE;
	}

	bt_shell_printf("Invalid argument %s\n", argv[1]);
	return FALSE;
}

static bool match_device_uuid(const void *a, const void *b)
{
	const struct unprov_device *dev = a;
	const uint8_t *uuid = b;

	return (memcmp(dev->uuid, uuid, 16) == 0);
}

static void print_device(void *a, void *b)
{
	const struct unprov_device *dev = a;
	struct tm *tm = localtime(&dev->last_seen);
	char buf[80];
	char *str;

	assert(strftime(buf, sizeof(buf), "%c", tm));

	str = l_util_hexstring_upper(dev->uuid, sizeof(dev->uuid));
	bt_shell_printf("UUID: %s, RSSI %d, Seen: %s\n",
			str, dev->rssi, buf);

	l_free(str);
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

static uint16_t get_primary_subnet_idx(uint16_t addr)
{
	struct remote_node *rmt;

	rmt = l_queue_find(nodes, match_node_addr, L_UINT_TO_PTR(addr));

	if (!rmt) {
		bt_shell_printf("Net key not found: trying %4.4x\n",
			PRIMARY_NET_IDX);
		return prov_net_idx;
		/*
		 * TODO: When the remote node recovery from storage is
		 * implemented, return NET_IDX_INVALID" here.
		 */
	}

	return rmt->net_idx;
}

struct send_data {
	const char *ele_path;
	bool rmt;
	bool is_dev_key;
	uint16_t dst;
	uint16_t idx;
	uint8_t *data;
	uint16_t len;
};

struct key_data {
	const char *ele_path;
	uint16_t dst;
	uint16_t idx;
	uint16_t net_idx;
	bool update;
};

static void send_msg_setup(struct l_dbus_message *msg, void *user_data)
{
	struct send_data *req = user_data;
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'o', req->ele_path);
	l_dbus_message_builder_append_basic(builder, 'q', &req->dst);
	if (req->is_dev_key)
		l_dbus_message_builder_append_basic(builder, 'b', &req->rmt);
	l_dbus_message_builder_append_basic(builder, 'q', &req->idx);
	l_dbus_message_builder_enter_array(builder, "y");

	while (req->len) {
		l_dbus_message_builder_append_basic(builder, 'y', req->data);
		req->data++;
		req->len--;
	}

	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static bool send_msg(void *user_data, uint16_t dst, uint16_t idx,
						uint8_t *data, uint16_t len)
{
	struct send_data *req;
	uint16_t net_idx_tx = idx;
	bool is_dev_key;
	const char *method_name;

	is_dev_key = (idx == APP_IDX_DEV_REMOTE || idx == APP_IDX_DEV_LOCAL);
	method_name = is_dev_key ? "DevKeySend" : "Send";

	if (is_dev_key) {
		net_idx_tx = get_primary_subnet_idx(dst);
		if (net_idx_tx == NET_IDX_INVALID)
			return false;
	}

	req = l_new(struct send_data, 1);
	req->ele_path = user_data;
	req->dst = dst;
	req->idx = net_idx_tx;
	req->data = data;
	req->len = len;
	req->rmt = (idx == APP_IDX_DEV_REMOTE);
	req->is_dev_key = is_dev_key;

	return l_dbus_proxy_method_call(local->proxy, method_name,
					send_msg_setup, NULL, req, l_free) != 0;
}

static void send_key_setup(struct l_dbus_message *msg, void *user_data)
{
	struct key_data *req = user_data;
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'o', req->ele_path);
	l_dbus_message_builder_append_basic(builder, 'q', &req->dst);
	l_dbus_message_builder_append_basic(builder, 'q', &req->idx);
	l_dbus_message_builder_append_basic(builder, 'q', &req->net_idx);
	l_dbus_message_builder_append_basic(builder, 'b', &req->update);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static bool send_key(void *user_data, uint16_t dst, uint16_t key_idx,
						bool is_appkey, bool update)
{
	struct key_data *req;
	uint16_t net_idx;
	const char *method_name = (!is_appkey) ? "AddNetKey" : "AddAppKey";

	net_idx = get_primary_subnet_idx(dst);
	if (net_idx == NET_IDX_INVALID)
		return false;

	req = l_new(struct key_data, 1);
	req->ele_path = user_data;
	req->dst = dst;
	req->idx = key_idx;
	req->net_idx = net_idx;
	req->update = update;

	return l_dbus_proxy_method_call(local->proxy, method_name,
				send_key_setup, NULL, req, l_free) != 0;
}

static void client_init(void)
{
	cfgcli = cfgcli_init(send_key, (void *) app.ele.path);
	cfgcli->ops.set_send_func(send_msg, (void *) app.ele.path);
}

static bool caps_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	uint32_t i;

	if (!l_dbus_message_builder_enter_array(builder, "s"))
		return false;
	for (i = 0; i < L_ARRAY_SIZE(caps); i++)
		l_dbus_message_builder_append_basic(builder, 's', caps[i]);

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static struct l_dbus_message *disp_numeric_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	char *str;
	uint32_t n;

	if (!l_dbus_message_get_arguments(msg, "su", &str, &n)) {
		l_error("Cannot parse \"DisplayNumeric\" arguments");
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);
	}

	if (!str || strlen(str) != strlen("in-numeric") ||
			strncmp(str, "in-numeric", strlen("in-numeric")))
		return l_dbus_message_new_error(msg, dbus_err_support, NULL);

	bt_shell_printf(COLOR_YELLOW "Enter %u on remote device" COLOR_OFF, n);

	return l_dbus_message_new_method_return(msg);
}

static void agent_input_done(oob_type_t type, void *buf, uint16_t len,
								void *user_data)
{
	struct l_dbus_message *msg = user_data;
	struct l_dbus_message *reply;
	uint32_t val_u32;

	switch (type) {
	case NONE:
	case OUTPUT:
	case ASCII:
	case HEXADECIMAL:
	default:
		return;
	case DECIMAL:
		if (len >= 8) {
			bt_shell_printf("Bad input length");
			return;
		}

		val_u32 = l_get_be32(buf);
		reply = l_dbus_message_new_method_return(msg);
		l_dbus_message_set_arguments(reply, "u", val_u32);
		l_dbus_send(dbus, reply);
		break;
	}
}

static struct l_dbus_message *prompt_numeric_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	char *str;

	if (!l_dbus_message_get_arguments(msg, "s", &str)) {
		l_error("Cannot parse \"PromptNumeric\" arguments");
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);
	}

	if (!str || strlen(str) != strlen("out-numeric") ||
			strncmp(str, "out-numeric", strlen("out-numeric")))
		return l_dbus_message_new_error(msg, dbus_err_support, NULL);

	l_dbus_message_ref(msg);
	agent_input_request(DECIMAL, 8, agent_input_done, msg);

	return NULL;
}

static void setup_agent_iface(struct l_dbus_interface *iface)
{
	l_dbus_interface_property(iface, "Capabilities", 0, "as", caps_getter,
								NULL);
	/* TODO: Other properties */
	l_dbus_interface_method(iface, "DisplayNumeric", 0, disp_numeric_call,
						"", "su", "type", "number");
	l_dbus_interface_method(iface, "PromptNumeric", 0, prompt_numeric_call,
						"u", "s", "number", "type");

}

static bool register_agent(void)
{
	if (!l_dbus_register_interface(dbus, MESH_PROVISION_AGENT_INTERFACE,
					setup_agent_iface, NULL, false)) {
		l_error("Unable to register agent interface");
		return false;
	}

	if (!l_dbus_register_object(dbus, app.agent_path, NULL, NULL,
				MESH_PROVISION_AGENT_INTERFACE, NULL, NULL)) {
		l_error("Failed to register object %s", app.agent_path);
		return false;
	}

	return true;
}

static void try_set_node_proxy(void *a, void *b)
{
	struct l_dbus_proxy *proxy = a;
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	if (strcmp(local->path, path))
		return;

	if (!strcmp(interface, MESH_MANAGEMENT_INTERFACE))
		local->mgmt_proxy = proxy;
	else if (!strcmp(interface, MESH_NODE_INTERFACE))
		local->proxy = proxy;
}

static void attach_node_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct meshcfg_node *node = user_data;
	struct l_dbus_message_iter iter_cfg;

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to attach node: %s", name);
		goto fail;

	}

	if (!l_dbus_message_get_arguments(msg, "oa(ya(qa{sv}))",
						&local->path, &iter_cfg))
		goto fail;

	bt_shell_printf("Attached with path %s\n", local->path);

	/* Populate node's proxies */
	l_queue_foreach(node_proxies, try_set_node_proxy, node);

	/* Remove from orphaned proxies list */
	if (local->proxy)
		l_queue_remove(node_proxies, local->proxy);

	if (local->mgmt_proxy)
		l_queue_remove(node_proxies, local->mgmt_proxy);

	/* Inititalize config client model */
	client_init();

	return;

fail:
	l_free(node);
	node = NULL;
}

static void attach_node_setup(struct l_dbus_message *msg, void *user_data)
{
	l_dbus_message_set_arguments(msg, "ot", app.path,
						l_get_be64(local->token.u8));
}

static void create_net_reply(struct l_dbus_proxy *proxy,
						struct l_dbus_message *msg,
						void *user_data)
{
	char *str;
	uint64_t tmp;

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to create network: %s", name);
		return;

	}

	if (!l_dbus_message_get_arguments(msg, "t", &tmp))
		return;

	local = l_new(struct meshcfg_node, 1);
	local->token.u64 = l_get_be64(&tmp);
	str = l_util_hexstring(&local->token.u8[0], 8);
	bt_shell_printf("Created new node with token %s\n", str);
	l_free(str);

	keys_add_net_key(PRIMARY_NET_IDX);

	l_dbus_proxy_method_call(net_proxy, "Attach", attach_node_setup,
						attach_node_reply, NULL,
						NULL);
}

static void create_net_setup(struct l_dbus_message *msg, void *user_data)
{
	uint i;
	struct l_dbus_message_builder *builder;

	/* Generate random UUID */
	l_getrandom(app.uuid, sizeof(app.uuid));

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'o', app.path);
	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < L_ARRAY_SIZE(app.uuid); i++)
		l_dbus_message_builder_append_basic(builder, 'y',
								&(app.uuid[i]));

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void cmd_create_network(int argc, char *argv[])
{
	l_dbus_proxy_method_call(net_proxy, "CreateNetwork", create_net_setup,
						create_net_reply, NULL,
						NULL);

}

static void scan_reply(struct l_dbus_proxy *proxy, struct l_dbus_message *msg,
								void *user_data)
{
	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to start unprovisioned scan: %s", name);
		return;
	}

	bt_shell_printf("Unprovisioned scan started\n");
}

static void scan_setup(struct l_dbus_message *msg, void *user_data)
{
	int32_t secs = L_PTR_TO_UINT(user_data);

	l_dbus_message_set_arguments(msg, "q", (uint16_t) secs);
}

static void cmd_scan_unprov(int argc, char *argv[])
{
	uint32_t secs = 0;
	bool enable;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (parse_argument_on_off(argc, argv, &enable) == FALSE) {
		bt_shell_printf("Failed to parse input\n");
		return bt_shell_noninteractive_quit(EXIT_FAILURE);
	}

	if (argc == 3)
		sscanf(argv[2], "%u", &secs);

	if (secs > UNPROV_SCAN_MAX_SECS)
		secs = UNPROV_SCAN_MAX_SECS;

	if (enable)
		l_dbus_proxy_method_call(local->mgmt_proxy, "UnprovisionedScan",
						scan_setup, scan_reply,
						L_UINT_TO_PTR(secs), NULL);
	else
		l_dbus_proxy_method_call(local->mgmt_proxy,
						"UnprovisionedScanCancel",
						NULL, NULL, NULL, NULL);

}

static void cmd_list_unprov(int argc, char *argv[])
{
	bt_shell_printf(COLOR_YELLOW "Unprovisioned devices:\n" COLOR_OFF);
	l_queue_foreach(devices, print_device, NULL);
}

static void print_node(void *a, void *b)
{
	struct remote_node *node = a;
	char *str;

	bt_shell_printf(COLOR_YELLOW "Mesh node:\n" COLOR_OFF);
	str = l_util_hexstring_upper(node->uuid, 16);
	bt_shell_printf("\t" COLOR_GREEN "UUID = %s\n" COLOR_OFF, str);
	l_free(str);
	bt_shell_printf("\t" COLOR_GREEN "primary = %4.4x\n" COLOR_OFF,
								node->unicast);
	bt_shell_printf("\t" COLOR_GREEN "elements = %u\n" COLOR_OFF,
								node->num_ele);
	bt_shell_printf("\t" COLOR_GREEN "net_key_idx = %3.3x\n" COLOR_OFF,
								node->net_idx);
}

static void cmd_list_nodes(int argc, char *argv[])
{
	l_queue_foreach(nodes, print_node, NULL);
}

static void add_node_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	if (l_dbus_message_is_error(msg)) {
		const char *name;

		prov_in_progress = false;
		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to start provisioning: %s", name);
		return;
	}

	bt_shell_printf("Provisioning started\n");
}

static void add_node_setup(struct l_dbus_message *msg, void *user_data)
{
	int i;
	char *str = user_data;
	size_t sz;
	unsigned char *uuid;
	struct l_dbus_message_builder *builder;

	uuid = l_util_from_hexstring(str, &sz);
	if (!uuid || sz != 16) {
		l_error("Failed to generate UUID array from %s", str);
		return;
	}

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < (int)sz; i++)
		l_dbus_message_builder_append_basic(builder, 'y', &(uuid[i]));

	l_dbus_message_builder_leave_array(builder);

	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	l_free(uuid);
}

static void cmd_start_prov(int argc, char *argv[])
{
	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (prov_in_progress) {
		bt_shell_printf("Provisioning is already in progress\n");
		return;
	}

	if (!argv[1] || (strlen(argv[1]) != 32)) {
		bt_shell_printf(COLOR_RED "Requires UUID\n" COLOR_RED);
		return;
	}

	if (l_dbus_proxy_method_call(local->mgmt_proxy, "AddNode",
						add_node_setup, add_node_reply,
						argv[1], NULL))
		prov_in_progress = true;
}

static const struct bt_shell_menu main_menu = {
	.name = "main",
	.entries = {
	{ "create", NULL, cmd_create_network,
			"Create new mesh network with one initial node" },
	{ "discover-unprovisioned", "<on/off> [seconds]", cmd_scan_unprov,
			"Look for devices to provision" },
	{ "list-unprovisioned", NULL, cmd_list_unprov,
			"List unprovisioned devices" },
	{ "provision", "<uuid>", cmd_start_prov,
			"Initiate provisioning"},
	{ "list-nodes", NULL, cmd_list_nodes,
			"List remote mesh nodes"},
	{ } },
};

static void proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	bt_shell_printf("Proxy added: %s (%s)\n", interface, path);

	if (!strcmp(interface, MESH_NETWORK_INTERFACE)) {
		net_proxy = proxy;
		return;
	}

	if (!strcmp(interface, MESH_MANAGEMENT_INTERFACE)) {

		if (local && local->path) {
			if (!strcmp(local->path, path))
				local->mgmt_proxy = proxy;
		} else
			l_queue_push_tail(node_proxies, proxy);
		return;
	}

	if (!strcmp(interface, MESH_NODE_INTERFACE)) {

		if (local && local->path) {
			if (!strcmp(local->path, path))
				local->proxy = proxy;
		} else
			l_queue_push_tail(node_proxies, proxy);
	}
}

static void proxy_removed(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	bt_shell_printf("Proxy removed: %s (%s)\n", interface, path);

	if (!strcmp(interface, MESH_NETWORK_INTERFACE)) {
		bt_shell_printf("Mesh removed, terminating.\n");
		l_main_quit();
		return;
	}

	if (!strcmp(interface, MESH_NODE_INTERFACE)) {
		if (local && local->path && !strcmp(local->path, path))
			local->proxy = NULL;

		l_queue_remove(node_proxies, proxy);
		return;
	}

	if (!strcmp(interface, MESH_MANAGEMENT_INTERFACE)) {
		if (local && local->path && !strcmp(local->path, path))
			local->mgmt_proxy = NULL;

		l_queue_remove(node_proxies, proxy);
	}
}

static bool mod_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_enter_array(builder, "q");
	l_dbus_message_builder_append_basic(builder, 'q', &app.ele.mods[0]);
	l_dbus_message_builder_append_basic(builder, 'q', &app.ele.mods[1]);
	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool vmod_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_enter_array(builder, "(qq)");
	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool ele_idx_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_append_basic(builder, 'y', &app.ele.index);

	return true;
}

static struct l_dbus_message *dev_msg_recv_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter iter;
	uint16_t src, idx;
	uint8_t *data;
	uint32_t n;
	bool rmt;

	if (!l_dbus_message_get_arguments(msg, "qbqay", &src, &rmt, &idx,
								&iter)) {
		l_error("Cannot parse received message");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	if (!l_dbus_message_iter_get_fixed_array(&iter, &data, &n)) {
		l_error("Cannot parse received message: data");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	bt_shell_printf("Received dev key message (len %u):", n);

	/* Pass to the configuration client */
	if (cfgcli && cfgcli->ops.recv)
		cfgcli->ops.recv(src, APP_IDX_DEV_REMOTE, data, n);

	return l_dbus_message_new_method_return(msg);
}

static void setup_ele_iface(struct l_dbus_interface *iface)
{
	/* Properties */
	l_dbus_interface_property(iface, "Index", 0, "y", ele_idx_getter,
									NULL);
	l_dbus_interface_property(iface, "VendorModels", 0, "a(qq)",
							vmod_getter, NULL);
	l_dbus_interface_property(iface, "Models", 0, "aq", mod_getter, NULL);

	/* Methods */
	l_dbus_interface_method(iface, "DevKeyMessageReceived", 0,
				dev_msg_recv_call, "", "qbqay", "source",
				"remote", "net_index", "data");

	/* TODO: Other methods */
}

static struct l_dbus_message *scan_result_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter iter;
	int16_t rssi;
	uint32_t n;
	uint8_t *prov_data;
	char *str;
	struct unprov_device *dev;

	if (!l_dbus_message_get_arguments(msg, "nay", &rssi, &iter)) {
		l_error("Cannot parse scan results");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);

	}

	if (!l_dbus_message_iter_get_fixed_array(&iter, &prov_data, &n) ||
								n < 16) {
		l_error("Cannot parse scan result: data");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	bt_shell_printf("Scan result:\n");
	bt_shell_printf("\t" COLOR_GREEN "rssi = %d\n" COLOR_OFF, rssi);
	str = l_util_hexstring_upper(prov_data, 16);
	bt_shell_printf("\t" COLOR_GREEN "UUID = %s\n" COLOR_OFF, str);
	l_free(str);

	/* TODO: Handle the rest of provisioning data if present */

	dev = l_queue_find(devices, match_device_uuid, prov_data);
	if (!dev) {
		dev = l_new(struct unprov_device, 1);
		memcpy(dev->uuid, prov_data, sizeof(dev->uuid));
		/* TODO: timed self-destructor */
		l_queue_push_tail(devices, dev);
	}

	/* Update with the latest rssi */
	dev->rssi = rssi;
	dev->last_seen = time(NULL);

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *req_prov_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint8_t cnt;
	struct l_dbus_message *reply;

	if (!l_dbus_message_get_arguments(msg, "y", &cnt)) {
		l_error("Cannot parse request for prov data");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);

	}

	bt_shell_printf("Assign addresses for %u elements\n", cnt);
	reply = l_dbus_message_new_method_return(msg);

	l_dbus_message_set_arguments(reply, "qq", prov_net_idx, prov_address);

	return reply;
}

static void remove_device(uint8_t *uuid)
{
	struct unprov_device *dev;

	dev = l_queue_remove_if(devices, match_device_uuid, uuid);
	l_free(dev);
}

static struct l_dbus_message *add_node_cmplt_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter iter;
	int16_t unicast;
	uint8_t cnt;
	uint32_t n;
	uint8_t *uuid;
	struct remote_node *node;

	if (!prov_in_progress)
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);

	prov_in_progress = false;

	if (!l_dbus_message_get_arguments(msg, "ayqy", &iter, &unicast, &cnt)) {
		l_error("Cannot parse add node complete message");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);

	}

	if (!l_dbus_message_iter_get_fixed_array(&iter, &uuid, &n) ||
								n != 16) {
		l_error("Cannot parse add node complete message: uuid");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	node = l_new(struct remote_node, 1);
	memcpy(node->uuid, uuid, 16);
	node->unicast = unicast;
	node->num_ele = cnt;
	node->net_idx = prov_net_idx;

	bt_shell_printf("Provisioning done:\n");
	print_node(node, NULL);
	l_queue_push_tail(nodes, node);
	remove_device(uuid);

	prov_address = unicast + cnt;

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *add_node_fail_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter iter;
	uint32_t n;
	uint8_t *uuid;
	char *str, *reason;

	if (!prov_in_progress)
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);

	prov_in_progress = false;

	if (!l_dbus_message_get_arguments(msg, "ays", &iter, &reason)) {
		l_error("Cannot parse add node failed message");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);

	}

	if (!l_dbus_message_iter_get_fixed_array(&iter, &uuid, &n) ||
								n != 16) {
		l_error("Cannot parse add node failed message: uuid");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	bt_shell_printf("Provisioning failed:\n");
	str = l_util_hexstring_upper(uuid, 16);
	bt_shell_printf("\t" COLOR_RED "UUID = %s\n" COLOR_OFF, str);
	l_free(str);
	bt_shell_printf("\t" COLOR_RED "%s\n" COLOR_OFF, reason);

	remove_device(uuid);

	return l_dbus_message_new_method_return(msg);
}

static void setup_prov_iface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "ScanResult", 0, scan_result_call, "",
							"nay", "rssi", "data");

	l_dbus_interface_method(iface, "RequestProvData", 0, req_prov_call,
				"qq", "y", "net_index", "unicast", "count");

	l_dbus_interface_method(iface, "AddNodeComplete", 0,
					add_node_cmplt_call, "", "ayqy",
					"uuid", "unicast", "count");

	l_dbus_interface_method(iface, "AddNodeFailed", 0, add_node_fail_call,
					"", "ays", "uuid", "reason");
}

static bool cid_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_append_basic(builder, 'q', &app.cid);

	return true;
}

static bool pid_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_append_basic(builder, 'q', &app.pid);

	return true;
}

static bool vid_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_append_basic(builder, 'q', &app.vid);

	return true;
}
static bool crpl_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_append_basic(builder, 'q', &app.crpl);

	return true;
}

static void setup_app_iface(struct l_dbus_interface *iface)
{
	l_dbus_interface_property(iface, "CompanyID", 0, "q", cid_getter,
									NULL);
	l_dbus_interface_property(iface, "VersionID", 0, "q", vid_getter,
									NULL);
	l_dbus_interface_property(iface, "ProductID", 0, "q", pid_getter,
									NULL);
	l_dbus_interface_property(iface, "CRPL", 0, "q", crpl_getter, NULL);

	/* TODO: Methods */
}

static bool register_app(void)
{
	if (!l_dbus_register_interface(dbus, MESH_APPLICATION_INTERFACE,
						setup_app_iface, NULL, false)) {
		l_error("Failed to register interface %s",
						MESH_APPLICATION_INTERFACE);
		return false;
	}

	if (!l_dbus_register_interface(dbus, MESH_PROVISIONER_INTERFACE,
					setup_prov_iface, NULL, false)) {
		l_error("Failed to register interface %s",
						MESH_PROVISIONER_INTERFACE);
		return false;
	}

	if (!l_dbus_register_object(dbus, app.path, NULL, NULL,
					MESH_APPLICATION_INTERFACE, NULL,
					MESH_PROVISIONER_INTERFACE, NULL,
									NULL)) {
		l_error("Failed to register object %s", app.path);
		return false;
	}

	if (!register_agent())
		return false;

	if (!l_dbus_register_interface(dbus, MESH_ELEMENT_INTERFACE,
						setup_ele_iface, NULL, false)) {
		l_error("Failed to register interface %s",
						MESH_ELEMENT_INTERFACE);
		return false;
	}

	if (!l_dbus_register_object(dbus, app.ele.path, NULL, NULL,
				    MESH_ELEMENT_INTERFACE, NULL, NULL)) {
		l_error("Failed to register object %s", app.ele.path);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus, app.path,
					 L_DBUS_INTERFACE_OBJECT_MANAGER,
									NULL)) {
		l_error("Failed to add interface %s",
					L_DBUS_INTERFACE_OBJECT_MANAGER);
		return false;
	}

	return true;
}

static void client_ready(struct l_dbus_client *client, void *user_data)
{
	bt_shell_printf("D-Bus client ready\n");
	if (!register_app())
		bt_shell_quit(EXIT_FAILURE);

	bt_shell_attach(fileno(stdin));
}

static void client_connected(struct l_dbus *dbus, void *user_data)
{
	bt_shell_printf("D-Bus client connected\n");
	bt_shell_set_prompt(PROMPT_ON);
}

static void client_disconnected(struct l_dbus *dbus, void *user_data)
{
	bt_shell_printf("D-Bus client disconnected, exit\n");
	bt_shell_quit(EXIT_SUCCESS);
}

static void ready_callback(void *user_data)
{
	bt_shell_printf("Connected to D-Bus\n");
	if (!l_dbus_object_manager_enable(dbus, "/"))
		bt_shell_printf("Failed to register the ObjectManager\n");
}

int main(int argc, char *argv[])
{
	struct l_dbus_client *client;
	uint32_t val;
	int status;

	l_log_set_stderr();

	bt_shell_init(argc, argv, &opt);
	bt_shell_set_menu(&main_menu);
	bt_shell_set_prompt(PROMPT_OFF);

	if (address_opt && sscanf(address_opt, "%04x", &val) == 1)
		prov_address = (uint16_t) val;
	else
		prov_address = DEFAULT_START_ADDRESS;

	if (net_idx_opt && sscanf(net_idx_opt, "%04x", &val) == 1)
		prov_net_idx = (uint16_t) val;
	else
		prov_net_idx = DEFAULT_NET_INDEX;

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);

	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	client = l_dbus_client_new(dbus, BLUEZ_MESH_NAME, "/org/bluez/mesh");

	l_dbus_client_set_connect_handler(client, client_connected, NULL, NULL);
	l_dbus_client_set_disconnect_handler(client, client_disconnected, NULL,
									NULL);
	l_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
							NULL, NULL, NULL);
	l_dbus_client_set_ready_handler(client, client_ready, NULL, NULL);

	node_proxies = l_queue_new();
	devices = l_queue_new();
	nodes = l_queue_new();

	status = bt_shell_run();

	l_dbus_client_destroy(client);
	l_dbus_destroy(dbus);

	return status;
}
