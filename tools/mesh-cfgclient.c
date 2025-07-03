// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <dbus/dbus.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <time.h>

#include <sys/stat.h>

#include <ell/ell.h>

#include "src/shared/shell.h"
#include "src/shared/util.h"

#include "mesh/mesh.h"
#include "mesh/mesh-defs.h"

#include "tools/mesh/agent.h"
#include "tools/mesh/cfgcli.h"
#include "tools/mesh/keys.h"
#include "tools/mesh/mesh-db.h"
#include "tools/mesh/model.h"
#include "tools/mesh/remote.h"

#define PROMPT_ON	"[mesh-cfgclient]> "
#define PROMPT_OFF	"Waiting to connect to bluetooth-meshd..."

#define CFG_SRV_MODEL	0x0000
#define CFG_CLI_MODEL	0x0001
#define RPR_SVR_MODEL	0x0004
#define RPR_CLI_MODEL	0x0005
#define PRV_BEACON_SVR	0x0008
#define PRV_BEACON_CLI	0x0009

#define UNPROV_SCAN_MAX_SECS	300

#define DEFAULT_START_ADDRESS	0x00aa
#define DEFAULT_MAX_ADDRESS	(VIRTUAL_ADDRESS_LOW - 1)
#define DEFAULT_NET_INDEX	0x0000
#define MAX_CRPL_SIZE		0x7fff

#define DEFAULT_CFG_FILE	"config_db.json"
#define DEFAULT_EXPORT_FILE	"export_db.json"

struct meshcfg_el {
	const char *path;
	uint8_t index;
	uint16_t mods[4];
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
	int id;
	uint32_t uri_hash;
	uint8_t uuid[16];
	int16_t rssi;
	uint16_t server;
	uint16_t oob_info;
};

struct generic_request {
	uint32_t arg1;
	uint32_t arg2;
	uint32_t arg3;
	uint8_t *data1;
	uint8_t *data2;
	const char *str;
};

struct scan_data {
	uint16_t dst;
	uint16_t secs;
};

static void *finalized = L_UINT_TO_PTR(-1);

static struct l_dbus *dbus;

static struct l_timeout *scan_timeout;
static struct l_queue *node_proxies;
static struct l_dbus_proxy *net_proxy;
static struct meshcfg_node *local;
static struct model_info *cfgcli;

static struct l_queue *devices;

static bool prov_in_progress;
static const char * const caps[] = {"static-oob",
				"push",
				"twist",
				"blink",
				"beep",
				"vibrate",
				"public-oob",
				"out-alpha",
				"in-alpha",
				"out-numeric",
				"in-numeric"};

static bool have_config;

static struct meshcfg_app app = {
	.path = "/mesh/cfgclient",
	.agent_path = "/mesh/cfgclient/agent",
	.cid = 0x05f1,
	.pid = 0x0002,
	.vid = 0x0001,
	.crpl = MAX_CRPL_SIZE,
	.ele = {
		.path = "/mesh/cfgclient/ele0",
		.index = 0,
		.mods = {CFG_SRV_MODEL, CFG_CLI_MODEL,
					PRV_BEACON_SVR, PRV_BEACON_CLI}
	}
};

static const struct option options[] = {
	{ "config",		required_argument, 0, 'c' },
	{ "address-start",	required_argument, 0, 'a' },
	{ "address-range",	required_argument, 0, 'r' },
	{ "net-index",		required_argument, 0, 'n' },
	{ 0, 0, 0, 0 }
};

static const char *address_opt;
static const char *range_opt;
static const char *net_idx_opt;
static const char *config_opt;

static uint32_t iv_index;
static uint16_t low_addr;
static uint16_t high_addr;
static uint16_t prov_net_idx;
static const char *cfg_fname;

static const char **optargs[] = {
	&config_opt,
	&address_opt,
	&range_opt,
	&net_idx_opt,
};

static const char *help[] = {
	"Configuration file",
	"Starting unicast address for remote nodes",
	"Net index for provisioning subnet"
};

static const struct bt_shell_opt opt = {
	.options = options,
	.optno = sizeof(options) / sizeof(struct option),
	.optstr = "c:a:n:",
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

	if (a == finalized)
		return false;

	return memcmp(dev->uuid, b, 16) == 0;
}

static bool match_by_id(const void *a, const void *b)
{
	const struct unprov_device *dev = a;
	int id = L_PTR_TO_UINT(b);

	if (a == finalized)
		return false;

	l_info("test %d %d", dev->id, id);
	return dev->id == id;
}

static bool match_by_srv_uuid(const void *a, const void *b)
{
	const struct unprov_device *dev = a;
	const struct unprov_device *new_dev = b;

	if (a == finalized)
		return false;

	return (dev->server == new_dev->server) &&
				(memcmp(dev->uuid, new_dev->uuid, 16) == 0);
}

static void print_device(void *a, void *b)
{
	struct unprov_device *dev = a;
	int *cnt = b;
	struct tm *tm;
	char buf[80];
	char *str;

	if (a == finalized)
		return;

	tm = localtime(&dev->last_seen);
	assert(strftime(buf, sizeof(buf), "%c", tm));
	(*cnt)++;

	dev->id = *cnt;
	str = l_util_hexstring_upper(dev->uuid, sizeof(dev->uuid));
	bt_shell_printf(COLOR_YELLOW "#%d" COLOR_OFF
			" UUID: %s, RSSI %d, Server: %4.4x\n Seen: %s\n",
			*cnt, str, dev->rssi, dev->server, buf);

	l_free(str);
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

static void append_dict_entry_basic(struct l_dbus_message_builder *builder,
					const char *key, const char *signature,
					const void *data)
{
	if (!builder)
		return;

	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_append_basic(builder, 's', key);
	l_dbus_message_builder_enter_variant(builder, signature);
	l_dbus_message_builder_append_basic(builder, signature[0], data);
	l_dbus_message_builder_leave_variant(builder);
	l_dbus_message_builder_leave_dict(builder);
}

static void append_byte_array(struct l_dbus_message_builder *builder,
					unsigned char *data, unsigned int len)
{
	unsigned int i;

	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < len; i++)
		l_dbus_message_builder_append_basic(builder, 'y', &(data[i]));

	l_dbus_message_builder_leave_array(builder);
}

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

	/* Options */
	l_dbus_message_builder_enter_array(builder, "{sv}");
	l_dbus_message_builder_enter_dict(builder, "sv");
	l_dbus_message_builder_leave_dict(builder);
	l_dbus_message_builder_leave_array(builder);

	/* Data */
	append_byte_array(builder, req->data, req->len);
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
		net_idx_tx = remote_get_subnet_idx(dst);
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

	net_idx = remote_get_subnet_idx(dst);
	if (net_idx == NET_IDX_INVALID) {
		bt_shell_printf("Node %4.4x not found\n", dst);
		return false;
	}

	if (!is_appkey && !keys_subnet_exists(key_idx)) {
		bt_shell_printf("Local NetKey %u (0x%3.3x) not found\n",
							key_idx, key_idx);
		return false;
	}

	if (is_appkey && (keys_get_bound_key(key_idx) == NET_IDX_INVALID)) {
		bt_shell_printf("Local AppKey %u (0x%3.3x) not found\n",
							key_idx, key_idx);
		return false;
	}

	req = l_new(struct key_data, 1);
	req->ele_path = user_data;
	req->dst = dst;
	req->idx = key_idx;
	req->net_idx = net_idx;
	req->update = update;

	return l_dbus_proxy_method_call(local->proxy, method_name,
				send_key_setup, NULL, req, l_free) != 0;
}

static void delete_node_setup(struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t primary;
	uint8_t ele_cnt;

	primary = (uint16_t) req->arg1;
	ele_cnt = (uint8_t) req->arg2;

	l_dbus_message_set_arguments(msg, "qy", primary, ele_cnt);
}

static void delete_node(uint16_t primary, uint8_t ele_cnt)
{
	struct generic_request *req;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	req = l_new(struct generic_request, 1);
	req->arg1 = primary;
	req->arg2 = ele_cnt;

	l_dbus_proxy_method_call(local->mgmt_proxy, "DeleteRemoteNode",
				delete_node_setup, NULL, req, l_free);
}

static void client_init(void)
{
	cfgcli = cfgcli_init(send_key, delete_node, (void *) app.ele.path);
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

static void agent_input_done(oob_type_t type, void *buf, uint16_t len,
								void *user_data)
{
	struct l_dbus_message *msg = user_data;
	struct l_dbus_message *reply = NULL;
	struct l_dbus_message_builder *builder;
	uint32_t val_u32;
	uint8_t oob_data[64];

	switch (type) {
	case NONE:
	case OUTPUT:
	default:
		break;

	case ASCII:
		if (len > 8) {
			bt_shell_printf("Bad input length\n");
			break;
		}
		/* Fall Through */

	case HEXADECIMAL:
		if (len > sizeof(oob_data)) {
			bt_shell_printf("Bad input length\n");
			break;
		}
		memset(oob_data, 0, sizeof(oob_data));
		memcpy(oob_data, buf, len);
		reply = l_dbus_message_new_method_return(msg);
		builder = l_dbus_message_builder_new(reply);
		append_byte_array(builder, oob_data, len);
		l_dbus_message_builder_finalize(builder);
		l_dbus_message_builder_destroy(builder);
		break;

	case DECIMAL:
		if (len > 8) {
			bt_shell_printf("Bad input length\n");
			break;
		}

		val_u32 = l_get_be32(buf);
		reply = l_dbus_message_new_method_return(msg);
		l_dbus_message_set_arguments(reply, "u", val_u32);
		break;
	}

	if (!reply)
		reply = l_dbus_message_new_error(msg, dbus_err_fail, NULL);

	l_dbus_send(dbus, reply);
}

struct requested_action {
	const char *action;
	const char *description;
};

static struct requested_action display_numeric_table[] = {
	{ "push", "Push remote button %d times"},
	{ "twist", "Twist remote nob %d times"},
	{ "in-numeric", "Enter %d on remote device"},
	{ "out-numeric", "Enter %d on remote device"}
};

static struct requested_action prompt_numeric_table[] = {
	{ "blink", "Enter the number of times remote LED blinked"},
	{ "beep", "Enter the number of times remote device beeped"},
	{ "vibrate", "Enter the number of times remote device vibrated"},
	{ "in-numeric", "Enter the number displayed on remote device"},
	{ "out-numeric", "Enter the number displayed on remote device"}
};

static int get_action(char *str, bool prompt)
{
	struct requested_action *action_table;
	size_t len;
	int i, sz;

	if (!str)
		return -1;

	if (prompt) {
		len = strlen(str);
		sz = L_ARRAY_SIZE(prompt_numeric_table);
		action_table = prompt_numeric_table;
	} else {
		len = strlen(str);
		sz = L_ARRAY_SIZE(display_numeric_table);
		action_table = display_numeric_table;
	}

	for (i = 0; i < sz; ++i)
		if (len == strlen(action_table[i].action) &&
			!strcmp(str, action_table[i].action))
			return i;

	return -1;
}

static struct l_dbus_message *disp_numeric_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	char *str;
	uint32_t n;
	int action_index;

	if (!l_dbus_message_get_arguments(msg, "su", &str, &n)) {
		l_error("Cannot parse \"DisplayNumeric\" arguments");
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);
	}

	action_index = get_action(str, false);
	if (action_index < 0)
		return l_dbus_message_new_error(msg, dbus_err_support, NULL);

	str = l_strdup_printf(display_numeric_table[action_index].description,
									n);
	bt_shell_printf(COLOR_YELLOW "%s\n" COLOR_OFF, str);
	l_free(str);

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *disp_string_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	const char *prompt = "Enter AlphaNumeric code on remote device:";
	char *str;

	if (!l_dbus_message_get_arguments(msg, "s", &str)) {
		l_error("Cannot parse \"DisplayString\" arguments");
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);
	}

	bt_shell_printf(COLOR_YELLOW "%s %s\n" COLOR_OFF, prompt, str);

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *prompt_numeric_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	char *str;
	int action_index;
	const char *desc;

	if (!l_dbus_message_get_arguments(msg, "s", &str)) {
		l_error("Cannot parse \"PromptNumeric\" arguments");
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);
	}

	action_index = get_action(str, true);
	if (action_index < 0)
		return l_dbus_message_new_error(msg, dbus_err_support, NULL);

	desc = prompt_numeric_table[action_index].description;

	l_dbus_message_ref(msg);
	agent_input_request(DECIMAL, 8, desc, agent_input_done, msg);

	return NULL;
}

static struct l_dbus_message *prompt_public_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	l_dbus_message_ref(msg);
	agent_input_request(HEXADECIMAL, 64, "Enter 512 bit Public Key",
			agent_input_done, msg);
	return NULL;
}

static struct l_dbus_message *prompt_static_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	char *str;

	if (!l_dbus_message_get_arguments(msg, "s", &str) || !str) {
		l_error("Cannot parse \"PromptStatic\" arguments");
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);
	}

	if (!strcmp(str, "in-alpha") || !strcmp(str, "out-alpha")) {
		l_dbus_message_ref(msg);
		agent_input_request(ASCII, 8, "Enter displayed Ascii code",
							agent_input_done, msg);
	} else if (!strcmp(str, "static-oob")) {
		l_dbus_message_ref(msg);
		agent_input_request(HEXADECIMAL, 16, "Enter Static Key",
							agent_input_done, msg);
	} else
		return l_dbus_message_new_error(msg, dbus_err_support, NULL);

	return NULL;
}

static void setup_agent_iface(struct l_dbus_interface *iface)
{
	l_dbus_interface_property(iface, "Capabilities", 0, "as", caps_getter,
								NULL);
	/* TODO: Other properties */
	l_dbus_interface_method(iface, "DisplayString", 0, disp_string_call,
							"", "s", "value");
	l_dbus_interface_method(iface, "DisplayNumeric", 0, disp_numeric_call,
						"", "su", "type", "number");
	l_dbus_interface_method(iface, "PromptNumeric", 0, prompt_numeric_call,
						"u", "s", "number", "type");
	l_dbus_interface_method(iface, "PromptStatic", 0, prompt_static_call,
						"ay", "s", "data", "type");
	l_dbus_interface_method(iface, "PublicKey", 0, prompt_public_call,
							"ay", "", "data");
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

	if (!l_dbus_object_add_interface(dbus, app.agent_path,
					 L_DBUS_INTERFACE_PROPERTIES, NULL)) {
		l_error("Failed to add interface %s",
					L_DBUS_INTERFACE_PROPERTIES);
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
				struct l_dbus_message *msg, void *user_data)
{
	struct meshcfg_node *node = user_data;
	struct l_dbus_message_iter iter_cfg;
	uint32_t ivi;

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

	/* Initialize config client model */
	client_init();

	if (l_dbus_proxy_get_property(local->proxy, "IvIndex", "u", &ivi) &&
							ivi != iv_index) {
		iv_index = ivi;
		mesh_db_set_iv_index(ivi);
		remote_clear_rejected_addresses(ivi);
	}

	/* Read own node composition */
	if (!cfgcli_get_comp(0x0001, 128))
		l_error("Failed to read own composition");

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
				struct l_dbus_message *msg, void *user_data)
{
	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to create network: %s", name);
		return;
	}
}

static void create_net_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;

	/* Generate random UUID */
	l_uuid_v4(app.uuid);

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'o', app.path);
	append_byte_array(builder, app.uuid, 16);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void cmd_create_network(int argc, char *argv[])
{
	if (have_config) {
		l_error("Mesh network configuration exists (%s)", cfg_fname);
		return;
	}

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
	struct scan_data *data = user_data;
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(msg);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	append_dict_entry_basic(builder, "Seconds", "q", &data->secs);
	append_dict_entry_basic(builder, "Server", "q", &data->dst);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);

	/* Destination info not needed after call */
	l_free(data);
}

static void scan_start(void *user_data, uint16_t dst, uint32_t model)
{
	struct scan_data *data;

	if (model != (0xffff0000 | RPR_SVR_MODEL))
		return;

	data = l_malloc(sizeof(struct scan_data));
	data->secs = L_PTR_TO_UINT(user_data);
	data->dst = dst;

	if (!l_dbus_proxy_method_call(local->mgmt_proxy, "UnprovisionedScan",
					scan_setup, scan_reply, data, NULL))
		l_free(data);
}

static void scan_to(struct l_timeout *timeout, void *user_data)
{
	int cnt = 0;

	if (l_queue_peek_head(devices) != finalized)
		l_queue_push_head(devices, finalized);

	l_timeout_remove(timeout);
	scan_timeout = NULL;
	bt_shell_printf(COLOR_YELLOW "Unprovisioned devices:\n" COLOR_OFF);
	l_queue_foreach(devices, print_device, &cnt);
}

static void free_devices(void *a)
{
	if (a == finalized)
		return;

	l_free(a);
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

	if (argc == 3) {
		sscanf(argv[2], "%u", &secs);

		if (secs > UNPROV_SCAN_MAX_SECS)
			secs = UNPROV_SCAN_MAX_SECS;
	} else
		secs = 60;

	l_timeout_remove(scan_timeout);
	scan_timeout = NULL;

	if (enable) {
		l_queue_clear(devices, free_devices);
		remote_foreach_model(scan_start, L_UINT_TO_PTR(secs));
		scan_timeout = l_timeout_create(secs, scan_to, NULL, NULL);
	} else {
		/* Mark devices queue as finalized */
		l_queue_push_head(devices, finalized);
		l_dbus_proxy_method_call(local->mgmt_proxy,
						"UnprovisionedScanCancel",
						NULL, NULL, NULL, NULL);
	}
}

static uint8_t *parse_key(struct l_dbus_message_iter *iter, uint16_t id,
							const char *name)
{
	uint8_t *val;
	uint32_t len;

	if (!l_dbus_message_iter_get_fixed_array(iter, &val, &len)
								|| len != 16) {
		bt_shell_printf("Failed to parse %s %4.4x\n", name, id);
		return NULL;
	}

	return val;
}

static bool parse_app_keys(struct l_dbus_message_iter *iter, uint16_t net_idx,
								void *user_data)
{
	struct l_dbus_message_iter app_keys, app_key, opts;
	uint16_t app_idx;

	if (!l_dbus_message_iter_get_variant(iter, "a(qaya{sv})", &app_keys))
		return false;

	while (l_dbus_message_iter_next_entry(&app_keys, &app_idx, &app_key,
								&opts)) {
		struct l_dbus_message_iter var;
		uint8_t *val, *old_val = NULL;
		const char *key;

		val = parse_key(&app_key, app_idx, "AppKey");
		if (!val)
			return false;

		while (l_dbus_message_iter_next_entry(&opts, &key, &var)) {
			if (!strcmp(key, "OldKey")) {
				if (!l_dbus_message_iter_get_variant(&var, "ay",
								&app_key))
					return false;

				old_val = parse_key(&app_key, app_idx,
								"old NetKey");

				if (!old_val)
					return false;
			}
		}

		mesh_db_set_app_key(user_data, net_idx, app_idx, val, old_val);
	}

	return true;
}

static bool parse_net_keys(struct l_dbus_message_iter *iter, void *user_data)
{
	struct l_dbus_message_iter net_keys, net_key, opts;
	uint16_t idx;

	if (!l_dbus_message_iter_get_variant(iter, "a(qaya{sv})", &net_keys))
		return false;

	while (l_dbus_message_iter_next_entry(&net_keys, &idx, &net_key,
								&opts)) {
		struct l_dbus_message_iter var;
		uint8_t *val, *old_val = NULL;
		uint8_t phase = KEY_REFRESH_PHASE_NONE;
		const char *key;

		val = parse_key(&net_key, idx, "NetKey");
		if (!val)
			return false;

		while (l_dbus_message_iter_next_entry(&opts, &key, &var)) {
			if (!strcmp(key, "AppKeys")) {
				if (!parse_app_keys(&var, idx, user_data))
					return false;
			} else if (!strcmp(key, "Phase")) {
				if (!l_dbus_message_iter_get_variant(&var, "y",
									&phase))
					return false;
			} else if (!strcmp(key, "OldKey")) {
				if (!l_dbus_message_iter_get_variant(&var, "ay",
								&net_key))
					return false;

				old_val = parse_key(&net_key, idx,
								"old NetKey");

				if (!old_val)
					return false;
			}
		}

		mesh_db_set_net_key(user_data, idx, val, old_val, phase);
	}

	return true;
}

static bool parse_dev_keys(struct l_dbus_message_iter *iter, void *user_data)
{
	struct l_dbus_message_iter keys, dev_key;
	uint16_t unicast;

	if (!l_dbus_message_iter_get_variant(iter, "a(qay)", &keys))
		return false;

	while (l_dbus_message_iter_next_entry(&keys, &unicast, &dev_key)) {
		uint8_t *data;

		data = parse_key(&dev_key, unicast, "Device Key");
		if (!data)
			return false;

		mesh_db_set_device_key(user_data, unicast, data);
	}

	return true;
}

static void export_keys_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_iter iter, var;
	char *cfg_dir = NULL, *fname = NULL;
	const char *key;
	bool is_error = true;

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		bt_shell_printf("Failed to export keys: %s", name);
		goto done;

	}

	if (!l_dbus_message_get_arguments(msg, "a{sv}", &iter)) {
		bt_shell_printf("Malformed ExportKeys reply");
		goto done;
	}

	while (l_dbus_message_iter_next_entry(&iter, &key, &var)) {
		if (!strcmp(key, "NetKeys")) {
			if (!parse_net_keys(&var, user_data))
				goto done;
		} else if (!strcmp(key, "DevKeys")) {
			if (!parse_dev_keys(&var, user_data))
				goto done;
		}
	}

	is_error = false;

	cfg_dir = l_strdup(cfg_fname);
	cfg_dir = dirname(cfg_dir);

	fname = l_strdup_printf("%s/%s", cfg_dir, DEFAULT_EXPORT_FILE);

done:
	if (mesh_db_finish_export(is_error, user_data, fname)) {
		if (!is_error)
			bt_shell_printf("Config DB is exported to %s\n", fname);
	}

	l_free(cfg_dir);
	l_free(fname);
}

static void cmd_export_db(int argc, char *argv[])
{
	void *cfg_export;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	/* Generate a properly formatted DB from the local config */
	cfg_export = mesh_db_prepare_export();
	if (!cfg_export) {
		bt_shell_printf("Failed to prepare config db\n");
		return;
	}

	/* Export the keys from the daemon */
	l_dbus_proxy_method_call(local->mgmt_proxy, "ExportKeys", NULL,
					export_keys_reply, cfg_export, NULL);
}

static void cmd_list_unprov(int argc, char *argv[])
{
	int cnt = 0;

	bt_shell_printf(COLOR_YELLOW "Unprovisioned devices:\n" COLOR_OFF);
	l_queue_foreach(devices, print_device, &cnt);
}

static void cmd_list_nodes(int argc, char *argv[])
{
	remote_print_all();
}

static void cmd_keys(int argc, char *argv[])
{
	keys_print_keys();
}

static void free_generic_request(void *data)
{
	struct generic_request *req = data;

	l_free(req->data1);
	l_free(req->data2);
	l_free(req);
}

static void import_node_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t primary, net_idx;
	uint8_t ele_cnt;

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to import remote node: %s", name);
		return;
	}

	net_idx = (uint16_t) req->arg1;
	primary = (uint16_t) req->arg2;
	ele_cnt = (uint8_t) req->arg3;

	remote_add_node(req->data1, primary, ele_cnt, net_idx);
}

static void import_node_setup(struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t primary;
	uint8_t ele_cnt;
	struct l_dbus_message_builder *builder;

	primary = (uint16_t) req->arg2;
	ele_cnt = (uint8_t) req->arg3;

	builder = l_dbus_message_builder_new(msg);
	l_dbus_message_builder_append_basic(builder, 'q', &primary);
	l_dbus_message_builder_append_basic(builder, 'y', &ele_cnt);
	append_byte_array(builder, req->data2, 16);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void cmd_import_node(int argc, char *argv[])
{
	struct generic_request *req;
	size_t sz;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (argc < 6) {
		bt_shell_printf("UUID, element count and device key");
		bt_shell_printf("Unicast, element count and device key");
		bt_shell_printf("are required\n");
		return;
	}

	req = l_new(struct generic_request, 1);

	/* Device UUID */
	req->data1 = l_util_from_hexstring(argv[1], &sz);
	if (!req->data1 || sz != 16 || !l_uuid_is_valid(req->data1)) {
		l_error("Failed to generate UUID array from %s", argv[1]);
		goto fail;
	}

	/* NetKey Index*/
	if (sscanf(argv[2], "%04x", &req->arg1) != 1)
		goto fail;

	/* Unicast of the primary element */
	if (sscanf(argv[3], "%04x", &req->arg2) != 1)
		goto fail;

	/* Number of elements */
	if (sscanf(argv[4], "%u", &req->arg3) != 1)
		goto fail;

	/* DevKey */
	req->data2 = l_util_from_hexstring(argv[5], &sz);
	if (!req->data2 || sz != 16) {
		l_error("Failed to generate DevKey array from %s", argv[5]);
		goto fail;
	}

	l_dbus_proxy_method_call(local->mgmt_proxy, "ImportRemoteNode",
					import_node_setup, import_node_reply,
					req, free_generic_request);

	return;

fail:
	free_generic_request(req);
}

static void subnet_set_phase_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t net_idx;
	uint8_t phase;

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to set subnet phase: %s", name);
		return;
	}

	net_idx = (uint16_t) req->arg1;
	phase = (uint8_t) req->arg2;

	if (phase == KEY_REFRESH_PHASE_THREE)
		phase = KEY_REFRESH_PHASE_NONE;

	keys_set_net_key_phase(net_idx, phase, true);
}

static void subnet_set_phase_setup(struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t net_idx;
	uint8_t phase;

	net_idx = (uint16_t) req->arg1;
	phase = (uint8_t) req->arg2;

	l_dbus_message_set_arguments(msg, "qy", net_idx, phase);
}

static void cmd_subnet_set_phase(int argc, char *argv[])
{
	struct generic_request *req;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (argc < 3) {
		bt_shell_printf("NetKey index and phase are required\n");
		return;
	}

	req = l_new(struct generic_request, 1);

	if (sscanf(argv[1], "%04x", &req->arg1) != 1)
		goto fail;

	if (sscanf(argv[2], "%d", &req->arg2) != 1)
		goto fail;

	l_dbus_proxy_method_call(local->mgmt_proxy, "SetKeyPhase",
					subnet_set_phase_setup,
					subnet_set_phase_reply, req, l_free);

	return;

fail:
	l_free(req);
}

static void mgr_key_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t idx = (uint16_t) req->arg1;
	const char *method = req->str;

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Method %s returned error: %s", method, name);
		bt_shell_printf("Method %s returned error: %s\n", method, name);
		return;
	}

	if (!strcmp("CreateSubnet", method)) {
		keys_add_net_key(idx);
		mesh_db_add_net_key(idx);
	} else if (!strcmp("DeleteSubnet", method)) {
		keys_del_net_key(idx);
		mesh_db_del_net_key(idx);
	} else if (!strcmp("UpdateSubnet", method)) {
		keys_set_net_key_phase(idx, KEY_REFRESH_PHASE_ONE, true);
	} else if (!strcmp("DeleteAppKey", method)) {
		keys_del_app_key(idx);
		mesh_db_del_app_key(idx);
	}
}

static void mgr_key_setup(struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t idx = (uint16_t) req->arg1;

	l_dbus_message_set_arguments(msg, "q", idx);
}

static void mgr_key_cmd(int argc, char *argv[], const char *method_name)
{
	struct generic_request *req;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (argc < 2) {
		bt_shell_printf("Missing required arguments\n");
		return;
	}

	req = l_new(struct generic_request, 1);

	if (sscanf(argv[1], "%04x", &req->arg1) != 1) {
		l_free(req);
		return;
	}

	req->str = method_name;

	l_dbus_proxy_method_call(local->mgmt_proxy, method_name,
					mgr_key_setup, mgr_key_reply,
					req, l_free);
}

static void cmd_delete_appkey(int argc, char *argv[])
{
	mgr_key_cmd(argc, argv, "DeleteAppKey");
}

static void cmd_update_appkey(int argc, char *argv[])
{
	mgr_key_cmd(argc, argv, "UpdateAppKey");
}

static void cmd_delete_subnet(int argc, char *argv[])
{
	mgr_key_cmd(argc, argv, "DeleteSubnet");
}

static void cmd_update_subnet(int argc, char *argv[])
{
	mgr_key_cmd(argc, argv, "UpdateSubnet");
}

static void cmd_create_subnet(int argc, char *argv[])
{
	mgr_key_cmd(argc, argv, "CreateSubnet");
}

static void add_key_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t net_idx, app_idx;
	const char *method = req->str;

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("%s failed: %s", method, name);
		return;
	}

	net_idx = (uint16_t) req->arg1;

	if (!strcmp(method, "ImportSubnet")) {
		keys_add_net_key(net_idx);
		mesh_db_add_net_key(net_idx);
		return;
	}

	app_idx = (uint16_t) req->arg2;
	keys_add_app_key(net_idx, app_idx);
	mesh_db_add_app_key(net_idx, app_idx);
}

static void import_appkey_setup(struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t net_idx, app_idx;
	struct l_dbus_message_builder *builder;

	net_idx = (uint16_t) req->arg1;
	app_idx = (uint16_t) req->arg2;

	builder = l_dbus_message_builder_new(msg);
	l_dbus_message_builder_append_basic(builder, 'q', &net_idx);
	l_dbus_message_builder_append_basic(builder, 'q', &app_idx);
	append_byte_array(builder, req->data1, 16);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void cmd_import_appkey(int argc, char *argv[])
{
	struct generic_request *req;
	size_t sz;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (argc < 4) {
		bt_shell_printf("Netkey and AppKey indices and");
		bt_shell_printf("key value are required\n");
		return;
	}

	req = l_new(struct generic_request, 1);

	if (sscanf(argv[1], "%04x", &req->arg1) != 1)
		goto fail;

	if (sscanf(argv[2], "%04x", &req->arg2) != 1)
		goto fail;

	req->data1 = l_util_from_hexstring(argv[3], &sz);
	if (!req->data1 || sz != 16) {
		l_error("Failed to generate key array from %s", argv[3]);
		goto fail;
	}

	req->str = "ImportAppKey";

	l_dbus_proxy_method_call(local->mgmt_proxy, "ImportAppKey",
					import_appkey_setup, add_key_reply,
					req, free_generic_request);

	return;

fail:
	free_generic_request(req);
}

static void import_subnet_setup(struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t net_idx;
	struct l_dbus_message_builder *builder;

	net_idx = (uint16_t) req->arg1;

	builder = l_dbus_message_builder_new(msg);
	l_dbus_message_builder_append_basic(builder, 'q', &net_idx);
	append_byte_array(builder, req->data1, 16);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void cmd_import_subnet(int argc, char *argv[])
{
	struct generic_request *req;
	size_t sz;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (argc < 3) {
		bt_shell_printf("NetKey index and value are required\n");
		return;
	}

	req = l_new(struct generic_request, 1);

	if (sscanf(argv[1], "%04x", &req->arg1) != 1)
		goto fail;

	req->data1 = l_util_from_hexstring(argv[2], &sz);
	if (!req->data1 || sz != 16) {
		l_error("Failed to generate key array from %s", argv[2]);
		goto fail;
	}

	req->str = "ImportSubnet";

	l_dbus_proxy_method_call(local->mgmt_proxy, "ImportSubnet",
					import_subnet_setup, add_key_reply,
					req, free_generic_request);
	return;

fail:
	free_generic_request(req);
}

static void create_appkey_setup(struct l_dbus_message *msg, void *user_data)
{
	struct generic_request *req = user_data;
	uint16_t net_idx, app_idx;

	net_idx = (uint16_t) req->arg1;
	app_idx = (uint16_t) req->arg2;

	l_dbus_message_set_arguments(msg, "qq", net_idx, app_idx);
}

static void cmd_create_appkey(int argc, char *argv[])
{
	struct generic_request *req;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (argc < 3) {
		bt_shell_printf("AppKey index is required\n");
		return;
	}

	req = l_new(struct generic_request, 1);

	if (sscanf(argv[1], "%04x", &req->arg1) != 1)
		goto fail;

	if (sscanf(argv[2], "%04x", &req->arg2) != 1)
		goto fail;

	req->str = "CreateAppKey";

	l_dbus_proxy_method_call(local->mgmt_proxy, "CreateAppKey",
					create_appkey_setup, add_key_reply,
					req, l_free);
	return;

fail:
	l_free(req);
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

static void reprov_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	if (l_dbus_message_is_error(msg)) {
		const char *name;

		prov_in_progress = false;
		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to start provisioning: %s", name);
		return;
	}

	bt_shell_printf("Reprovisioning started\n");
}

static void reprovision_setup(struct l_dbus_message *msg, void *user_data)
{
	uint16_t target = L_PTR_TO_UINT(user_data);
	uint8_t nppi = L_PTR_TO_UINT(user_data) >> 16;
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(msg);
	l_dbus_message_builder_append_basic(builder, 'q', &target);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	/* TODO: populate with options when defined */
	append_dict_entry_basic(builder, "NPPI", "y", &nppi);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void add_node_setup(struct l_dbus_message *msg, void *user_data)
{
	struct unprov_device *dev = user_data;
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(msg);
	append_byte_array(builder, dev->uuid, 16);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	/* TODO: populate with options when defined */
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void cmd_start_prov(int argc, char *argv[])
{
	struct unprov_device *dev = NULL;
	int id;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (prov_in_progress) {
		bt_shell_printf("Provisioning is already in progress\n");
		return;
	}

	if (!argv[1]) {
		bt_shell_printf(COLOR_RED "Requires UUID\n" COLOR_RED);
		return;
	}

	if (*(argv[1]) == '#') {
		if (sscanf(argv[1] + 1, "%d", &id) == 1)
			dev = l_queue_find(devices, match_by_id,
							L_UINT_TO_PTR(id));

		if (!dev) {
			bt_shell_printf(COLOR_RED "unknown id\n" COLOR_RED);
			return;
		}
	} else if (strlen(argv[1]) == 32) {
		size_t sz;
		uint8_t *uuid = l_util_from_hexstring(argv[1], &sz);

		if (sz != 16) {
			bt_shell_printf(COLOR_RED "Invalid UUID\n" COLOR_RED);
			return;
		}

		dev = l_queue_find(devices, match_device_uuid, uuid);

		if (!dev) {
			dev = l_new(struct unprov_device, 1);
			memcpy(dev->uuid, uuid, 16);
			l_queue_push_tail(devices, dev);
		}

		l_free(uuid);

	} else {
		bt_shell_printf(COLOR_RED "Requires UUID\n" COLOR_RED);
		return;
	}

	if (l_dbus_proxy_method_call(local->mgmt_proxy, "AddNode",
						add_node_setup, add_node_reply,
						dev, NULL))
		prov_in_progress = true;
}

static void cmd_start_reprov(int argc, char *argv[])
{
	uint16_t target = 0;
	uint8_t nppi = 0;

	if (!local || !local->proxy || !local->mgmt_proxy) {
		bt_shell_printf("Node is not attached\n");
		return;
	}

	if (prov_in_progress) {
		bt_shell_printf("Provisioning is already in progress\n");
		return;
	}

	if (!argv[1]) {
		bt_shell_printf(COLOR_RED "Requires Unicast\n" COLOR_RED);
		return;
	}

	if (argv[2]) {
		char *end;

		nppi = strtol(argv[2], &end, 16);
	}

	if (strlen(argv[1]) == 4) {
		char *end;

		target = strtol(argv[1], &end, 16);

		if (end != (argv[1] + 4)) {
			bt_shell_printf(COLOR_RED "Invalid Unicast\n"
								COLOR_RED);
			return;
		}

	} else {
		bt_shell_printf(COLOR_RED "Requires Unicast\n" COLOR_RED);
		return;
	}

	if (l_dbus_proxy_method_call(local->mgmt_proxy, "Reprovision",
					reprovision_setup, reprov_reply,
					L_UINT_TO_PTR(target + (nppi << 16)),
					NULL))
		prov_in_progress = true;
}

static const struct bt_shell_menu main_menu = {
	.name = "main",
	.entries = {
	{ "create", "[unicast_range_low]", cmd_create_network,
			"Create new mesh network with one initial node" },
	{ "discover-unprovisioned", "<on/off> [seconds]", cmd_scan_unprov,
			"Look for devices to provision" },
	{ "appkey-create", "<net_idx> <app_idx>", cmd_create_appkey,
			"Create a new local AppKey" },
	{ "appkey-import", "<net_idx> <app_idx> <key>", cmd_import_appkey,
			"Import a new local AppKey" },
	{ "appkey-update", "<app_idx>", cmd_update_appkey,
			"Update local AppKey" },
	{ "appkey-delete", "<app_idx>", cmd_delete_appkey,
			"Delete local AppKey" },
	{ "subnet-create", "<net_idx>", cmd_create_subnet,
			"Create a new local subnet (NetKey)" },
	{ "subnet-import", "<net_idx> <key>", cmd_import_subnet,
			"Import a new local subnet (NetKey)" },
	{ "subnet-update", "<net_idx>", cmd_update_subnet,
			"Update local subnet (NetKey)" },
	{ "subnet-delete", "<net_idx>", cmd_delete_subnet,
			"Delete local subnet (NetKey)" },
	{ "subnet-set-phase", "<net_idx> <phase>", cmd_subnet_set_phase,
			"Set subnet (NetKey) phase" },
	{ "list-unprovisioned", NULL, cmd_list_unprov,
			"List unprovisioned devices" },
	{ "provision", "<uuid>", cmd_start_prov,
			"Initiate provisioning"},
	{ "reprovision", "<unicast> [0|1|2]", cmd_start_reprov,
			"Refresh Device Key"},
	{ "node-import", "<uuid> <net_idx> <primary> <ele_count> <dev_key>",
			cmd_import_node,
			"Import an externally provisioned remote node"},
	{ "list-nodes", NULL, cmd_list_nodes,
			"List remote mesh nodes"},
	{ "keys", NULL, cmd_keys,
			"List available keys"},
	{ "export-db", NULL, cmd_export_db,
			"Export mesh configuration database"},
	{ } },
};

static void proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	bt_shell_printf("Proxy added: %s (%s)\n", interface, path);

	if (!strcmp(interface, MESH_NETWORK_INTERFACE)) {
		net_proxy = proxy;

		/*
		 * If mesh network configuration has been read from
		 * storage, attach the provisioner/config-client node.
		 */
		if (local)
			l_dbus_proxy_method_call(net_proxy, "Attach",
						attach_node_setup,
						attach_node_reply, NULL,
						NULL);
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

static void build_model(struct l_dbus_message_builder *builder, uint16_t mod_id,
					bool pub_enable, bool sub_enable)
{
	l_dbus_message_builder_enter_struct(builder, "qa{sv}");
	l_dbus_message_builder_append_basic(builder, 'q', &mod_id);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	append_dict_entry_basic(builder, "Subscribe", "b", &sub_enable);
	append_dict_entry_basic(builder, "Publish", "b", &pub_enable);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_struct(builder);
}

static bool mod_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_enter_array(builder, "(qa{sv})");
	build_model(builder, app.ele.mods[0], false, false);
	build_model(builder, app.ele.mods[1], false, false);
	build_model(builder, app.ele.mods[2], false, false);
	build_model(builder, app.ele.mods[3], false, false);
	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool vmod_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	l_dbus_message_builder_enter_array(builder, "(qqa{sv})");
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
	l_dbus_interface_property(iface, "VendorModels", 0, "a(qqa{sv})",
							vmod_getter, NULL);
	l_dbus_interface_property(iface, "Models", 0, "a(qa{sv})", mod_getter,
									NULL);

	/* Methods */
	l_dbus_interface_method(iface, "DevKeyMessageReceived", 0,
				dev_msg_recv_call, "", "qbqay", "source",
				"remote", "net_index", "data");

	/* TODO: Other methods */
}

static int sort_rssi(const void *a, const void *b, void *user_data)
{
	const struct unprov_device *new_dev = a;
	const struct unprov_device *dev = b;

	if (b == finalized)
		return 1;

	return dev->rssi - new_dev->rssi;
}

static struct l_dbus_message *scan_result_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter iter, opts, var;
	struct unprov_device result, *dev;
	int16_t rssi;
	uint16_t server = 0;
	uint32_t n;
	uint8_t *prov_data;
	const char *key;
	const char *sig = "naya{sv}";

	if (finalized == l_queue_peek_head(devices))
		goto done;


	if (!l_dbus_message_get_arguments(msg, sig, &rssi, &iter, &opts)) {
		l_error("Cannot parse scan results");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	if (!l_dbus_message_iter_get_fixed_array(&iter, &prov_data, &n) ||
								n < 16) {
		l_error("Cannot parse scan result: data");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	while (l_dbus_message_iter_next_entry(&opts, &key, &var)) {
		if (!strcmp(key, "Server"))
			l_dbus_message_iter_get_variant(&var, "q", &server);
	}

	memcpy(result.uuid, prov_data, 16);
	result.server = server;
	result.rssi = rssi;
	result.id = 0;
	result.last_seen = time(NULL);

	if (n > 16 && n <= 18)
		result.oob_info = l_get_be16(prov_data + 16);
	else
		result.oob_info = 0;

	if (n > 18 && n <= 22)
		result.uri_hash = l_get_be32(prov_data + 18);
	else
		result.uri_hash = 0;

	dev = l_queue_remove_if(devices, match_by_srv_uuid, &result);

	if (!dev) {
		bt_shell_printf("\r" COLOR_YELLOW "Results = %d\n" COLOR_OFF,
						l_queue_length(devices) + 1);
		dev = l_malloc(sizeof(struct unprov_device));
		*dev = result;

	} else if (dev->rssi < result.rssi)
		*dev = result;

	l_queue_insert(devices, dev, sort_rssi, NULL);

done:
	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *req_reprov_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint8_t cnt;
	uint16_t unicast, original;
	struct l_dbus_message *reply;


	if (!l_dbus_message_get_arguments(msg, "qy", &original, &cnt) ||
							!IS_UNICAST(original)) {
		l_error("Cannot parse request for reprov data");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);

	}

	unicast = remote_get_next_unicast(low_addr, high_addr, cnt);

	bt_shell_printf("Assign addresses for %u elements\n", cnt);
	bt_shell_printf("Original: %4.4x New: %4.4x\n", original, unicast);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "q", unicast);

	return reply;
}

static struct l_dbus_message *req_prov_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint8_t cnt;
	uint16_t unicast;
	struct l_dbus_message *reply;

	/* Both calls handled identicaly except for parameter list */
	if (!l_dbus_message_get_arguments(msg, "y", &cnt)) {
		l_error("Cannot parse request for prov data");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);

	}

	unicast = remote_get_next_unicast(low_addr, high_addr, cnt);

	if (!IS_UNICAST(unicast)) {
		l_error("Failed to allocate addresses for %u elements\n", cnt);
		return l_dbus_message_new_error(msg,
					"org.freedesktop.DBus.Error."
					"Failed to allocate address", NULL);
	}

	bt_shell_printf("Assign addresses: %4.4x (cnt: %d)\n", unicast, cnt);

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "qq", prov_net_idx, unicast);

	return reply;
}

static void remove_device(uint8_t *uuid)
{
	struct unprov_device *dev;

	do {
		dev = l_queue_remove_if(devices, match_device_uuid, uuid);
		l_free(dev);
	} while (dev);
}

static struct l_dbus_message *prov_cmplt_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter iter;
	int16_t unicast;
	uint8_t cnt;
	uint32_t n;
	uint8_t *uuid;

	l_debug("ProvComplete");
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

	remote_add_node(uuid, unicast, cnt, prov_net_idx);

	bt_shell_printf("Provisioning done:\n");
	remote_print_node(unicast);

	remove_device(uuid);

	if (!mesh_db_add_node(uuid, cnt, unicast, prov_net_idx))
		l_error("Failed to store new remote node");

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *reprov_cmplt_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t unicast, original;
	uint8_t old_cnt, cnt, nppi;

	l_debug("ReprovComplete");
	if (!prov_in_progress)
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);

	prov_in_progress = false;

	if (!l_dbus_message_get_arguments(msg, "qyqy", &original, &nppi,
							&unicast, &cnt)) {
		l_error("Cannot parse reprov complete message");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);

	}

	l_debug("ReprovComplete org: %4.4x, nppi: %d, new: %4.4x, cnt: %d",
						original, nppi, unicast, cnt);
	old_cnt = remote_ele_cnt(original);

	if (nppi != 1 && (original != unicast || cnt != old_cnt)) {
		l_error("Invalid reprov complete message (NPPI == %d)", nppi);
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	if (nppi)
		remote_reset_node(original, unicast, cnt,
						mesh_db_get_iv_index());

	bt_shell_printf("Reprovisioning done (nppi: %d):\n", nppi);
	remote_print_node(unicast);

	if (!mesh_db_reset_node(original, unicast, cnt))
		l_error("Failed to reset remote node");

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *prov_fail_call(struct l_dbus *dbus,
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
		l_error("Cannot parse failed message");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	if (!l_dbus_message_iter_get_fixed_array(&iter, &uuid, &n) || n != 16) {
		l_error("Cannot parse failed message: uuid");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	bt_shell_printf("Provisioning failed:\n");

	str = l_util_hexstring_upper(uuid, 16);
	bt_shell_printf("\t" COLOR_RED "UUID = %s\n" COLOR_OFF, str);
	l_free(str);
	remove_device(uuid);
	bt_shell_printf("\t" COLOR_RED "%s\n" COLOR_OFF, reason);

	return l_dbus_message_new_method_return(msg);
}

static struct l_dbus_message *reprov_fail_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter iter;
	uint16_t original = UNASSIGNED_ADDRESS;
	char *reason;

	if (!prov_in_progress)
		return l_dbus_message_new_error(msg, dbus_err_fail, NULL);

	prov_in_progress = false;

	if (!l_dbus_message_get_arguments(msg, "qs", &iter, &reason) ||
							!IS_UNICAST(original)) {

		l_error("Cannot parse Reprov failed message");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	bt_shell_printf("Reprovisioning failed:\n");
	bt_shell_printf("\t" COLOR_RED "UNICAST = %4.4x\n" COLOR_OFF, original);
	bt_shell_printf("\t" COLOR_RED "%s\n" COLOR_OFF, reason);

	return l_dbus_message_new_method_return(msg);
}

static void setup_prov_iface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "ScanResult", 0, scan_result_call, "",
					"naya{sv}", "rssi", "data", "options");

	l_dbus_interface_method(iface, "RequestProvData", 0, req_prov_call,
				"qq", "y", "net_index", "unicast", "count");

	l_dbus_interface_method(iface, "RequestReprovData", 0, req_reprov_call,
					"q", "qy", "unicast",
					"original", "count");

	l_dbus_interface_method(iface, "AddNodeComplete", 0,
					prov_cmplt_call, "", "ayqy",
					"uuid", "unicast", "count");

	l_dbus_interface_method(iface, "ReprovComplete", 0,
					reprov_cmplt_call, "", "qyqy",
					"original", "nppi", "unicast", "count");

	l_dbus_interface_method(iface, "AddNodeFailed", 0, prov_fail_call,
					"", "ays", "uuid", "reason");

	l_dbus_interface_method(iface, "ReprovFailed", 0, reprov_fail_call,
					"", "qs", "unicast", "reason");
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

static void attach_node(void *user_data)
{
	l_dbus_proxy_method_call(net_proxy, "Attach", attach_node_setup,
						attach_node_reply, NULL,
						NULL);
}

static struct l_dbus_message *join_complete(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	char *str;
	uint64_t tmp;

	if (!l_dbus_message_get_arguments(message, "t", &tmp))
		return l_dbus_message_new_error(message, dbus_err_args, NULL);

	local = l_new(struct meshcfg_node, 1);
	local->token.u64 = l_get_be64(&tmp);
	str = l_util_hexstring(&local->token.u8[0], 8);
	bt_shell_printf("Created new node with token %s\n", str);
	l_free(str);

	if (!mesh_db_create(cfg_fname, local->token.u8,
					"Mesh Config Client Network")) {
		l_free(local);
		local = NULL;
		return l_dbus_message_new_error(message, dbus_err_fail, NULL);
	}

	keys_add_net_key(PRIMARY_NET_IDX);
	mesh_db_add_net_key(PRIMARY_NET_IDX);

	remote_add_node(app.uuid, 0x0001, 1, PRIMARY_NET_IDX);
	mesh_db_add_node(app.uuid, 0x0001, 1, PRIMARY_NET_IDX);

	mesh_db_add_provisioner("BlueZ mesh-cfgclient", app.uuid,
					low_addr, high_addr,
					GROUP_ADDRESS_LOW, GROUP_ADDRESS_HIGH);

	l_idle_oneshot(attach_node, NULL, NULL);

	return l_dbus_message_new_method_return(message);
}

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	if (strcmp(path, local->path))
		return;

	bt_shell_printf("Property changed: %s %s %s\n", name, path, interface);

	if (!strcmp(interface, "org.bluez.mesh.Node1")) {

		if (!strcmp(name, "IvIndex")) {
			uint32_t ivi;

			if (!l_dbus_message_get_arguments(msg, "u", &ivi))
				return;

			bt_shell_printf("New IV Index: %u\n", ivi);

			iv_index = ivi;
			mesh_db_set_iv_index(ivi);
			remote_clear_rejected_addresses(ivi);
		}
	}
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

	l_dbus_interface_method(iface, "JoinComplete", 0, join_complete,
							"", "t", "token");

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
	bt_shell_set_prompt(PROMPT_ON, COLOR_BLUE);
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

static bool setup_cfg_storage(void)
{
	struct stat st;

	if (!config_opt) {
		char *home;
		char *mesh_dir;

		home = getenv("XDG_CONFIG_HOME");

		if (home) {
			mesh_dir = l_strdup_printf("%s/meshcfg", home);
		} else {
			home = getenv("HOME");
			if (!home) {
				l_error("\"HOME\" not set\n");
				return false;
			}

			mesh_dir = l_strdup_printf("%s/.config/meshcfg", home);
		}

		if (!mesh_dir)
			return false;

		if (stat(mesh_dir, &st) == 0) {
			if (!S_ISDIR(st.st_mode)) {
				l_error("%s not a directory", mesh_dir);
				return false;
			}
		} else if (errno == ENOENT) {
			if (mkdir(mesh_dir, 0700) != 0) {
				l_error("Cannot create %s", mesh_dir);
				return false;
			}
		} else {
			perror("Cannot open config directory");
			return false;
		}

		cfg_fname = l_strdup_printf("%s/%s", mesh_dir,
							DEFAULT_CFG_FILE);
		l_free(mesh_dir);

	} else {
		cfg_fname = l_strdup_printf("%s", config_opt);
	}

	if (stat(cfg_fname, &st) == -1) {
		if (errno == ENOENT) {
			l_warn("\nWarning: config file \"%s\" not found",
								cfg_fname);
			return true;
		}

		perror("\nFailed to open config file");
		return false;
	}

	have_config = true;
	return true;
}

static bool read_mesh_config(void)
{
	uint16_t range_l, range_h;

	if (!mesh_db_load(cfg_fname)) {
		l_error("Failed to load config from %s", cfg_fname);
		return false;
	}

	local = l_new(struct meshcfg_node, 1);

	if (!mesh_db_get_token(local->token.u8)) {
		l_error("Failed to read the provisioner's token ID");
		l_error("Check config file %s", cfg_fname);
		l_free(local);
		local = NULL;

		return false;
	}

	l_info("Mesh configuration loaded from %s", cfg_fname);
	if (mesh_db_get_addr_range(&range_l, &range_h)) {
		low_addr = range_l;
		high_addr = range_h;
	}

	iv_index = mesh_db_get_iv_index();

	return true;
}

int main(int argc, char *argv[])
{
	struct l_dbus_client *client;
	uint32_t val;
	int status;

	bt_shell_init(argc, argv, &opt);
	bt_shell_set_menu(&main_menu);

	l_log_set_stderr();

	if (address_opt && sscanf(address_opt, "%04x", &val) == 1)
		low_addr = (uint16_t) val;

	if (low_addr > DEFAULT_MAX_ADDRESS) {
		l_error("Invalid start address");
			bt_shell_cleanup();
			return EXIT_FAILURE;
	}

	if (!low_addr)
		low_addr = DEFAULT_START_ADDRESS;

	if (range_opt && sscanf(address_opt, "%04x", &val) == 1) {
		if (val == 0) {
			l_error("Invalid address range");
			bt_shell_cleanup();
			return EXIT_FAILURE;
		}

		/* Inclusive */
		high_addr = low_addr + val - 1;
	}

	if (!high_addr || high_addr > DEFAULT_MAX_ADDRESS)
		high_addr = DEFAULT_MAX_ADDRESS;

	if (net_idx_opt && sscanf(net_idx_opt, "%04x", &val) == 1)
		prov_net_idx = (uint16_t) val;
	else
		prov_net_idx = DEFAULT_NET_INDEX;

	if (!setup_cfg_storage()) {
		bt_shell_cleanup();
		return EXIT_FAILURE;
	}

	if (have_config && !read_mesh_config()) {
		bt_shell_cleanup();
		return EXIT_FAILURE;
	}

	bt_shell_set_prompt(PROMPT_OFF, NULL);

	dbus = l_dbus_new_default(L_DBUS_SYSTEM_BUS);

	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	client = l_dbus_client_new(dbus, BLUEZ_MESH_NAME, "/org/bluez/mesh");

	l_dbus_client_set_connect_handler(client, client_connected, NULL, NULL);
	l_dbus_client_set_disconnect_handler(client, client_disconnected, NULL,
									NULL);
	l_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
						property_changed, NULL, NULL);
	l_dbus_client_set_ready_handler(client, client_ready, NULL, NULL);

	node_proxies = l_queue_new();
	devices = l_queue_new();

	status = bt_shell_run();

	l_dbus_client_destroy(client);
	l_dbus_destroy(dbus);

	cfgcli_cleanup();

	return status;
}
