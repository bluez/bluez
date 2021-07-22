// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
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
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <ell/ell.h>

#include "src/shared/util.h"

#include "mesh/mesh-defs.h"
#include "mesh/mesh.h"

#define MAX_CRPL_SIZE	0x7fff
#define CFG_SRV_MODEL	0x0000
#define CFG_CLI_MODEL	0x0001
#define DEFAULT_IV_INDEX 0x0000

#define IS_CONFIG_MODEL(x) ((x) == CFG_SRV_MODEL || (x) == CFG_CLI_MODEL)

struct meshcfg_el {
	const char *path;
	uint8_t index;
	uint16_t mods[2];
	uint32_t vmods[2];
};

struct meshcfg_app {
	const char *path;
	const char *agent_path;
	struct meshcfg_node *node;
	uint8_t num_ele;
	struct meshcfg_el ele[2];
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

struct msg_data {
	uint16_t len;
	uint8_t data[MAX_MSG_LEN];
};

struct key_data {
	uint16_t idx;
	bool update;
};

typedef void (*startup_func_t)(const void *data);
struct startup_entry {
	startup_func_t func;
	void *data;
};

struct test_data {
	const char *ele_path;
	uint16_t dst;
	uint16_t subnet;
	void *req;
};

static struct l_tester *tester;

static bool option_list;
static const char *option_prefix;
static const char *option_string;
static char *tester_name;

static bool init_done;
static bool init_failed;
static bool terminated;

static struct l_queue *startup_chain;

static struct l_dbus *dbus;
struct l_dbus_client *client;

static struct l_queue *node_proxies;
static struct l_dbus_proxy *net_proxy;
static char *test_dir;
static char *io;
static char *exe;

static uint32_t iv_index = DEFAULT_IV_INDEX;

static const char *dbus_err_args = "org.freedesktop.DBus.Error.InvalidArgs";
static const char *const cli_app_path = "/mesh/cfgtest/client";
static const char *const cli_agent_path = "/mesh/cfgtest/client/agent";
static const char *const cli_ele_path_00 = "/mesh/cfgtest/client/ele0";
static const char *const srv_app_path = "/mesh/cfgtest/server";
static const char *const srv_agent_path = "/mesh/cfgtest/server/agent";
static const char *const srv_ele_path_00 = "/mesh/cfgtest/server/ele0";
static const char *const srv_ele_path_01 = "/mesh/cfgtest/server/ele1";

static struct meshcfg_app client_app = {
	.path = cli_app_path,
	.agent_path = cli_agent_path,
	.cid = 0x05f1,
	.pid = 0x0002,
	.vid = 0x0001,
	.crpl = MAX_CRPL_SIZE,
	.num_ele = 1,
	.ele = {
		{
			.path = cli_ele_path_00,
			.index = PRIMARY_ELE_IDX,
			.mods = {CFG_SRV_MODEL, CFG_CLI_MODEL},
			.vmods = {0xffffffff, 0xffffffff}
		}
	}
};

static struct meshcfg_app server_app = {
	.path = srv_app_path,
	.agent_path = srv_agent_path,
	.cid = 0x05f1,
	.pid = 0x0002,
	.vid = 0x0001,
	.crpl = MAX_CRPL_SIZE,
	.num_ele = 2,
	.ele = {
		{
			.path = srv_ele_path_00,
			.index = PRIMARY_ELE_IDX,
			.mods = {CFG_SRV_MODEL, 0xffff},
			.vmods = {0xffffffff, 0xffffffff}
		},
		{
			.path = srv_ele_path_01,
			.index = PRIMARY_ELE_IDX + 1,
			.mods = {0x1000, 0xffff},
			.vmods = {0x5F10001, 0xffffffff}
		}
	}
};

static uint8_t import_devkey[16];
static uint8_t import_netkey[16];
static const uint16_t import_netkey_idx = 0x001;
static const uint16_t import_node_unicast = 0xbcd;

static void create_network(const void *data);
static struct startup_entry init_create_client = {
	.func = create_network,
	.data = NULL,
};

static void import_node(const void *data);
static struct startup_entry init_import_server = {
	.func = import_node,
	.data = NULL,
};

static void attach_node(const void *data);
static struct startup_entry init_attach_client = {
	.func = attach_node,
	.data = NULL,
};

static void import_subnet(const void *data);
static struct startup_entry init_import_subnet = {
	.func = import_subnet,
	.data = NULL,
};

static void import_remote(const void *data);
static struct startup_entry init_import_remote = {
	.func = import_remote,
	.data = NULL,
};

static struct msg_data init_add_netkey_rsp = {
	.len = 5,
	.data = {0x80, 0x44, 0x00, 0x01, 0x00}
};

static struct key_data init_add_netkey_req = {
	.idx = import_netkey_idx,
	.update = false
};

static struct test_data init_add_netkey_data = {
	.ele_path = cli_ele_path_00,
	.dst = 0x0001,
	.subnet = 0x0000,
	.req = &init_add_netkey_req
};

static void add_netkey(const void *data);
static struct startup_entry init_add_netkey = {
	.func = add_netkey,
	.data = &init_add_netkey_data
};

static struct msg_data init_add_appkey_rsp = {
	.len = 6,
	.data = {0x80, 0x03, 0x00, 0x01, 0x10, 0x00}
};

static struct key_data init_add_appkey_req = {
	.idx = 0x001,
	.update = false
};

static struct test_data init_add_appkey_data = {
	.ele_path = cli_ele_path_00,
	.dst = import_node_unicast,
	.subnet = import_netkey_idx,
	.req = &init_add_appkey_req,
};

static void create_appkey(const void *data);
static struct startup_entry init_create_appkey = {
	.func = create_appkey,
	.data = &init_add_appkey_data
};

static void add_appkey(const void *data);
static struct startup_entry init_add_appkey = {
	.func = add_appkey,
	.data = &init_add_appkey_data
};

static struct msg_data test_add_appkey_rsp = {
	.len = 6,
	.data = {0x80, 0x03, 0x00, 0x01, 0x20, 0x00}
};

static struct key_data test_add_appkey_req = {
	.idx = 0x002,
	.update = false
};

static struct test_data test_add_appkey = {
	.ele_path = cli_ele_path_00,
	.dst = import_node_unicast,
	.subnet = import_netkey_idx,
	.req = &test_add_appkey_req,
};

static struct test_data common_route = {
	.ele_path = cli_ele_path_00,
	.dst = import_node_unicast,
	.subnet = import_netkey_idx,
};

static struct msg_data test_set_ttl_rsp = {
	.len = 3,
	.data = { 0x80, 0x0E, 0x7}
};

static struct msg_data test_set_ttl_req = {
	.len = 3,
	.data = { 0x80, 0x0D, 0x7}
};

static struct msg_data test_bind_rsp = {
	.len = 9,
	.data = { 0x80, 0x3E, 0x00, 0xCE, 0x0B, 0x01, 0x00, 0x00, 0x10},
};

static struct msg_data test_bind_req = {
	.len = 8,
	.data = { 0x80, 0x3D, 0xCE, 0x0B, 0x01, 0x00, 0x00, 0x10}
};


static struct msg_data test_bind_inv_mod_rsp = {
	.len = 9,
	.data = { 0x80, 0x3E, 0x02, 0xCE, 0x0B, 0x01, 0x00, 0x00, 0x11},
};

static struct msg_data test_bind_inv_mod_req = {
	.len = 8,
	.data = { 0x80, 0x3D, 0xCE, 0x0B, 0x01, 0x00, 0x00, 0x11}
};

static struct msg_data test_dev_comp_rsp = {
	.len = 28,
	.data = { 0x02, 0x00, 0xf1, 0x05, 0x02, 0x00, 0x01, 0x00, 0xff, 0x7f,
			0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x01, 0x01, 0x00, 0x10, 0xf1, 0x05, 0x01, 0x00}
};

static struct msg_data test_dev_comp_req = {
	.len = 3,
	.data = {0x80, 0x08, 0x00}
};

static void append_byte_array(struct l_dbus_message_builder *builder,
					unsigned char *data, unsigned int len)
{
	unsigned int i;

	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < len; i++)
		l_dbus_message_builder_append_basic(builder, 'y', &(data[i]));

	l_dbus_message_builder_leave_array(builder);
}

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

static void init_continue(void *data)
{
	struct startup_entry *next_step;
	enum l_tester_stage stage = l_tester_get_stage(tester);

	if (l_queue_isempty(startup_chain) &&
					stage == L_TESTER_STAGE_PRE_SETUP) {
		l_tester_pre_setup_complete(tester);
		init_done = true;
		return;
	}

	next_step = l_queue_pop_head(startup_chain);

	next_step->func(next_step->data);
}

static void test_success(void *user_data)
{
	l_tester_test_passed(tester);
}

static void test_fail(void *user_data)
{
	l_tester_test_failed(tester);
}

static void try_set_node_proxy(void *a, void *b)
{
	struct l_dbus_proxy *proxy = a;
	struct meshcfg_node *node = b;
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	if (strcmp(node->path, path))
		return;

	if (!strcmp(interface, MESH_MANAGEMENT_INTERFACE))
		node->mgmt_proxy = proxy;
	else if (!strcmp(interface, MESH_NODE_INTERFACE))
		node->proxy = proxy;
}

static void generic_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("D-Bus call failed: %s", name);
		l_idle_oneshot(test_fail, NULL, NULL);
	}
}

static void send_cfg_msg_setup(struct l_dbus_message *msg, void *user_data)
{
	struct msg_data *req = user_data;
	struct l_dbus_message_builder *builder;
	bool remote = true;

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'o',
							common_route.ele_path);
	l_dbus_message_builder_append_basic(builder, 'q', &common_route.dst);
	l_dbus_message_builder_append_basic(builder, 'b', &remote);

	l_dbus_message_builder_append_basic(builder, 'q', &common_route.subnet);

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

static void send_cfg_msg(const void *data)
{
	struct meshcfg_node *node = client_app.node;

	l_dbus_proxy_method_call(node->proxy, "DevKeySend",
					send_cfg_msg_setup, generic_reply,
							(void *) data, NULL);
}

static void add_key_setup(struct l_dbus_message *msg, void *user_data)
{
	struct test_data *tst = user_data;
	struct key_data *req = tst->req;
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'o', tst->ele_path);
	l_dbus_message_builder_append_basic(builder, 'q', &tst->dst);
	l_dbus_message_builder_append_basic(builder, 'q', &req->idx);
	l_dbus_message_builder_append_basic(builder, 'q', &tst->subnet);
	l_dbus_message_builder_append_basic(builder, 'b', &req->update);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void add_appkey(const void *data)
{
	struct meshcfg_node *node = client_app.node;

	l_dbus_proxy_method_call(node->proxy, "AddAppKey", add_key_setup,
					generic_reply, (void *) data, NULL);
}

static void add_netkey(const void *data)
{
	struct meshcfg_node *node = client_app.node;

	l_dbus_proxy_method_call(node->proxy, "AddNetKey", add_key_setup,
					generic_reply, (void *) data, NULL);
}

static void create_appkey_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	enum l_tester_stage stage = l_tester_get_stage(tester);

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_info("Add key failed: %s", name);

		if (stage == L_TESTER_STAGE_PRE_SETUP) {
			init_failed = true;
			l_tester_pre_setup_failed(tester);
		} else
			l_tester_setup_failed(tester);
	} else {
		if (stage == L_TESTER_STAGE_PRE_SETUP)
			l_idle_oneshot(init_continue, NULL, NULL);
		else
			l_tester_setup_complete(tester);
	}
}

static void create_appkey_setup(struct l_dbus_message *msg, void *user_data)
{
	struct test_data *tst = user_data;
	struct key_data *req = tst->req;

	l_dbus_message_set_arguments(msg, "qq", tst->subnet, req->idx);
}

static void create_appkey(const void *data)
{
	struct meshcfg_node *node = client_app.node;

	if (!node || !node->proxy || !node->mgmt_proxy) {
		l_info("Node is not attached\n");
		l_tester_setup_failed(tester);
		return;
	}

	l_dbus_proxy_method_call(node->mgmt_proxy, "CreateAppKey",
				create_appkey_setup, create_appkey_reply,
							(void *) data, NULL);
}

static void import_remote_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	enum l_tester_stage stage = l_tester_get_stage(tester);

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_info("Import remote call failed: %s", name);

		if (stage == L_TESTER_STAGE_PRE_SETUP) {
			init_failed = true;
			l_tester_pre_setup_failed(tester);
		}

		return;
	}

	if (stage == L_TESTER_STAGE_PRE_SETUP)
		l_idle_oneshot(init_continue, NULL, NULL);
	else
		l_tester_test_abort(tester);
}

static void import_remote_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'q', &import_node_unicast);
	l_dbus_message_builder_append_basic(builder, 'y', &server_app.num_ele);
	append_byte_array(builder, import_devkey, 16);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void import_remote(const void *data)
{
	struct meshcfg_node *node = client_app.node;

	if (!node || !node->mgmt_proxy) {
		l_tester_test_abort(tester);
		return;
	}

	l_dbus_proxy_method_call(node->mgmt_proxy, "ImportRemoteNode",
				import_remote_setup, import_remote_reply,
								NULL, NULL);
}

static void import_subnet_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	enum l_tester_stage stage = l_tester_get_stage(tester);

	if (stage != L_TESTER_STAGE_PRE_SETUP)
		return;

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_info("Import subnet failed: %s", name);

		init_failed = true;
		return l_tester_pre_setup_failed(tester);
	}

	l_idle_oneshot(init_continue, NULL, NULL);
}

static void import_subnet_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'q', &import_netkey_idx);
	append_byte_array(builder, import_netkey, 16);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void import_subnet(const void *data)
{
	struct meshcfg_node *node = client_app.node;

	if (!node || !node->mgmt_proxy) {
		l_tester_test_abort(tester);
		return;
	}

	l_dbus_proxy_method_call(node->mgmt_proxy, "ImportSubnet",
				import_subnet_setup, import_subnet_reply,
								NULL, NULL);
}

static void attach_node_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	struct meshcfg_app *app = user_data;
	struct meshcfg_node *node = app->node;
	struct l_dbus_message_iter iter_cfg;
	uint32_t ivi;
	enum l_tester_stage stage = l_tester_get_stage(tester);

	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to attach node: %s", name);
		goto fail;
	}

	if (!l_dbus_message_get_arguments(msg, "oa(ya(qa{sv}))",
						&node->path, &iter_cfg))
		goto fail;

	l_info("Attached with path %s\n", node->path);

	/* Populate node's proxies */
	l_queue_foreach(node_proxies, try_set_node_proxy, node);

	/* Remove from orphaned proxies list */
	if (node->proxy)
		l_queue_remove(node_proxies, node->proxy);

	if (node->mgmt_proxy)
		l_queue_remove(node_proxies, node->mgmt_proxy);

	if (l_dbus_proxy_get_property(node->proxy, "IvIndex", "u", &ivi) &&
							ivi != iv_index)
		iv_index = ivi;

	if (stage == L_TESTER_STAGE_PRE_SETUP)
		l_idle_oneshot(init_continue, NULL, NULL);

	return;

fail:
	l_free(node);
	app->node = NULL;

	if (stage == L_TESTER_STAGE_PRE_SETUP) {
		init_failed = true;
		l_tester_pre_setup_failed(tester);
	}
}

static void attach_node_setup(struct l_dbus_message *msg, void *user_data)
{
	struct meshcfg_app *app = user_data;

	l_dbus_message_set_arguments(msg, "ot", app->path,
					l_get_be64(app->node->token.u8));
}

static void attach_node(const void *data)
{
	struct meshcfg_node *node = client_app.node;

	if (!node) {
		l_tester_test_abort(tester);
		return;
	}

	l_dbus_proxy_method_call(net_proxy, "Attach",
					attach_node_setup, attach_node_reply,
					&client_app, NULL);
}

static struct l_dbus_message *join_complete(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct meshcfg_app *app = user_data;
	uint64_t tmp;
	enum l_tester_stage stage = l_tester_get_stage(tester);

	if (!l_dbus_message_get_arguments(message, "t", &tmp)) {
		if (stage == L_TESTER_STAGE_PRE_SETUP) {
			init_failed = true;
			l_tester_pre_setup_failed(tester);
		} else
			l_idle_oneshot(test_fail, NULL, NULL);

		return l_dbus_message_new_error(message, dbus_err_args, NULL);
	}

	app->node = l_new(struct meshcfg_node, 1);
	app->node->token.u64 = l_get_be64(&tmp);

	if (stage == L_TESTER_STAGE_PRE_SETUP)
		l_idle_oneshot(init_continue, NULL, NULL);

	return l_dbus_message_new_method_return(message);
}

static void create_net_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to create network: %s", name);
		l_tester_setup_failed(tester);
	}
}

static void create_net_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;

	/* Generate random UUID */
	l_uuid_v4(client_app.uuid);

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'o', client_app.path);
	append_byte_array(builder, client_app.uuid, 16);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void create_network(const void *data)
{
	l_dbus_proxy_method_call(net_proxy, "CreateNetwork", create_net_setup,
						create_net_reply, &client_app,
						NULL);
}

static void import_node_reply(struct l_dbus_proxy *proxy,
				struct l_dbus_message *msg, void *user_data)
{
	if (l_dbus_message_is_error(msg)) {
		const char *name;

		l_dbus_message_get_error(msg, &name, NULL);
		l_error("Failed to import local node: %s", name);
		l_idle_oneshot(test_fail, NULL, NULL);
		return;
	}
}

static void import_node_setup(struct l_dbus_message *msg, void *user_data)
{
	struct l_dbus_message_builder *builder;
	bool iv_update = false;
	bool key_refresh = false;

	/* Generate random UUID, DevKey, NetKey */
	l_uuid_v4(server_app.uuid);
	l_getrandom(import_netkey, sizeof(import_netkey));
	l_getrandom(import_devkey, sizeof(import_devkey));

	builder = l_dbus_message_builder_new(msg);

	l_dbus_message_builder_append_basic(builder, 'o', server_app.path);
	append_byte_array(builder, server_app.uuid, 16);
	append_byte_array(builder, import_devkey, 16);
	append_byte_array(builder, import_netkey, 16);
	l_dbus_message_builder_append_basic(builder, 'q', &import_netkey_idx);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	append_dict_entry_basic(builder, "IvUpdate", "b", &iv_update);
	append_dict_entry_basic(builder, "KeyRefresh", "b", &key_refresh);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_append_basic(builder, 'u', &iv_index);
	l_dbus_message_builder_append_basic(builder, 'q', &import_node_unicast);
	l_dbus_message_builder_finalize(builder);
	l_dbus_message_builder_destroy(builder);
}

static void import_node(const void *data)
{
	l_dbus_proxy_method_call(net_proxy, "Import", import_node_setup,
						import_node_reply, &server_app,
						NULL);
}

static void proxy_added(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("Proxy added: %s (%s)\n", interface, path);

	if (!strcmp(interface, MESH_NETWORK_INTERFACE)) {
		net_proxy = proxy;
		return;
	}

	if (!strcmp(interface, MESH_MANAGEMENT_INTERFACE)) {
		if (client_app.node && client_app.node->path) {
			if (!strcmp(client_app.node->path, path)) {
				client_app.node->mgmt_proxy = proxy;
				return;
			}
		}

		if (server_app.node && server_app.node->path) {
			if (!strcmp(server_app.node->path, path)) {
				server_app.node->mgmt_proxy = proxy;
				return;
			}
		}

		l_queue_push_tail(node_proxies, proxy);
		return;
	}

	if (!strcmp(interface, MESH_NODE_INTERFACE)) {

		if (client_app.node && client_app.node->path) {
			if (!strcmp(client_app.node->path, path)) {
				client_app.node->proxy = proxy;
				return;
			}
		}

		if (server_app.node && server_app.node->path) {
			if (!strcmp(server_app.node->path, path)) {
				server_app.node->proxy = proxy;
				return;
			}
		}

		l_queue_push_tail(node_proxies, proxy);
	}
}

static void proxy_removed(struct l_dbus_proxy *proxy, void *user_data)
{
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	l_info("Proxy removed: %s (%s)\n", interface, path);

	if (!strcmp(interface, MESH_NETWORK_INTERFACE)) {
		l_info("Mesh removed, terminating.\n");
		l_main_quit();
		return;
	}

	l_queue_remove(node_proxies, proxy);
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
	struct meshcfg_el *ele = user_data;
	uint32_t i;

	l_dbus_message_builder_enter_array(builder, "(qa{sv})");

	for (i = 0; i < L_ARRAY_SIZE(ele->mods); i++) {
		bool is_cfg = IS_CONFIG_MODEL(ele->mods[i]);

		if (ele->mods[i] == 0xffff)
			continue;

		build_model(builder, ele->mods[i], !is_cfg, !is_cfg);
	}

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static void build_vmodel(struct l_dbus_message_builder *builder, uint16_t vid,
				uint16_t mod, bool pub_enable, bool sub_enable)
{
	l_dbus_message_builder_enter_struct(builder, "qqa{sv}");
	l_dbus_message_builder_append_basic(builder, 'q', &vid);
	l_dbus_message_builder_append_basic(builder, 'q', &mod);
	l_dbus_message_builder_enter_array(builder, "{sv}");
	append_dict_entry_basic(builder, "Subscribe", "b", &sub_enable);
	append_dict_entry_basic(builder, "Publish", "b", &pub_enable);
	l_dbus_message_builder_leave_array(builder);
	l_dbus_message_builder_leave_struct(builder);
}

static bool vmod_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct meshcfg_el *ele = user_data;
	uint32_t i;

	l_dbus_message_builder_enter_array(builder, "(qqa{sv})");

	for (i = 0; i < L_ARRAY_SIZE(ele->vmods); i++) {
		if (ele->vmods[i] == 0xffffffff)
			continue;

		build_vmodel(builder, ele->vmods[i] >> 16,
				ele->vmods[i] & 0xffff, true, true);
	}

	l_dbus_message_builder_leave_array(builder);

	return true;
}

static bool ele_idx_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct meshcfg_el *ele = user_data;

	l_dbus_message_builder_append_basic(builder, 'y', &ele->index);

	return true;
}

static struct l_dbus_message *dev_msg_recv_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct msg_data *rsp;
	struct l_dbus_message_iter iter;
	uint16_t src, idx;
	uint8_t *data;
	uint32_t n;
	bool rmt;
	enum l_tester_stage stage = l_tester_get_stage(tester);

	if (!l_dbus_message_get_arguments(msg, "qbqay", &src, &rmt, &idx,
								&iter)) {
		l_error("Cannot parse received message");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	if (!l_dbus_message_iter_get_fixed_array(&iter, &data, &n)) {
		l_error("Cannot parse received message: data");
		return l_dbus_message_new_error(msg, dbus_err_args, NULL);
	}

	printf("Received dev key message (len %u):", n);
	{
		uint32_t i;

		for (i = 0; i < n; i++)
			printf("%x ", data[i]);
		printf("\n");
	}

	if (stage == L_TESTER_STAGE_PRE_SETUP) {
		if (n == init_add_netkey_rsp.len &&
				!memcmp(data, init_add_netkey_rsp.data, n))
			l_idle_oneshot(init_continue, NULL, NULL);
		else if (n == init_add_appkey_rsp.len &&
				!memcmp(data, init_add_appkey_rsp.data, n))
			l_idle_oneshot(init_continue, NULL, NULL);
		else {
			init_failed = true;
			l_tester_pre_setup_failed(tester);
		}
	} else {
		rsp = l_tester_get_data(tester);

		if (rsp && rsp->len == n && !memcmp(data, rsp->data, n))
			l_idle_oneshot(test_success, NULL, NULL);
		else
			l_idle_oneshot(test_fail, NULL, NULL);
	}

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

	/* TODO: Other methods? */
}

static bool cid_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct meshcfg_app *app = user_data;

	l_dbus_message_builder_append_basic(builder, 'q', &app->cid);

	return true;
}

static bool pid_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct meshcfg_app *app = user_data;

	l_dbus_message_builder_append_basic(builder, 'q', &app->pid);

	return true;
}

static bool vid_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct meshcfg_app *app = user_data;

	l_dbus_message_builder_append_basic(builder, 'q', &app->vid);

	return true;
}
static bool crpl_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct meshcfg_app *app = user_data;

	l_dbus_message_builder_append_basic(builder, 'q', &app->crpl);

	return true;
}

static void property_changed(struct l_dbus_proxy *proxy, const char *name,
				struct l_dbus_message *msg, void *user_data)
{
	struct meshcfg_app *app = user_data;
	struct meshcfg_node *node = app->node;
	const char *interface = l_dbus_proxy_get_interface(proxy);
	const char *path = l_dbus_proxy_get_path(proxy);

	if (strcmp(path, node->path))
		return;

	printf("Property changed: %s %s %s\n", name, path, interface);

	if (!strcmp(interface, "org.bluez.mesh.Node1")) {

		if (!strcmp(name, "IvIndex")) {
			uint32_t ivi;

			if (!l_dbus_message_get_arguments(msg, "u", &ivi))
				return;

			printf("New IV Index: %u\n", ivi);
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

	/* TODO: Other methods? */
}

static bool register_app_iface(void)
{
	if (!l_dbus_register_interface(dbus, MESH_APPLICATION_INTERFACE,
						setup_app_iface, NULL, false)) {
		l_error("Failed to register interface %s",
						MESH_APPLICATION_INTERFACE);
		return false;
	}

	if (!l_dbus_register_interface(dbus, MESH_ELEMENT_INTERFACE,
						setup_ele_iface, NULL, false)) {
		l_error("Failed to register interface %s",
						MESH_ELEMENT_INTERFACE);
		return false;
	}

	return true;
}

static bool register_app(struct meshcfg_app *app)
{
	uint32_t i;

	if (!l_dbus_register_object(dbus, app->path, NULL, NULL,
					MESH_APPLICATION_INTERFACE, app,
									NULL)) {
		l_error("Failed to register object %s", app->path);
		return false;
	}

	for (i = 0; i < L_ARRAY_SIZE(app->ele) && i < app->num_ele; i++) {
		if (!l_dbus_register_object(dbus, app->ele[i].path, NULL, NULL,
				MESH_ELEMENT_INTERFACE, &app->ele[i], NULL)) {
			l_error("Failed to register obj %s", app->ele[i].path);
			l_dbus_unregister_interface(dbus,
							MESH_ELEMENT_INTERFACE);
			return false;
		}
	}

	if (!l_dbus_object_add_interface(dbus, app->path,
				L_DBUS_INTERFACE_OBJECT_MANAGER, NULL)) {
		l_error("Failed to add interface %s",
					L_DBUS_INTERFACE_OBJECT_MANAGER);
		return false;
	}

	return true;
}

static void client_ready(struct l_dbus_client *client, void *user_data)
{
	enum l_tester_stage stage = l_tester_get_stage(tester);

	printf("D-Bus client ready\n");

	if (!register_app_iface() || !register_app(&client_app) ||
					!register_app(&server_app))
		return;

	if (stage == L_TESTER_STAGE_PRE_SETUP)
		init_continue(NULL);
}

static void client_connected(struct l_dbus *dbus, void *user_data)
{
	printf("D-Bus client connected\n");
}

static void client_disconnected(struct l_dbus *dbus, void *user_data)
{
	printf("D-Bus client disconnected, exit\n");
	l_main_exit();
}

static void ready_callback(void *user_data)
{
	printf("Connected to D-Bus\n");

	if (l_dbus_object_manager_enable(dbus, "/"))
		return;

	printf("Failed to register the ObjectManager\n");
	init_failed = true;
	l_tester_pre_setup_failed(tester);
}

static void init_test(const void *data)
{
	if (init_failed) {
		l_tester_pre_setup_failed(tester);
		return;
	}

	if (init_done) {
		l_tester_pre_setup_complete(tester);
		return;
	}

	node_proxies = l_queue_new();

	dbus = l_dbus_new_default(L_DBUS_SESSION_BUS);

	l_dbus_set_ready_handler(dbus, ready_callback, NULL, NULL);
	client = l_dbus_client_new(dbus, BLUEZ_MESH_NAME, "/org/bluez/mesh");

	l_dbus_client_set_connect_handler(client, client_connected, NULL, NULL);
	l_dbus_client_set_disconnect_handler(client, client_disconnected, NULL,
									NULL);
	l_dbus_client_set_proxy_handlers(client, proxy_added, proxy_removed,
						property_changed, NULL, NULL);
	l_dbus_client_set_ready_handler(client, client_ready, NULL, NULL);

}

static void init_startup_chain(void)
{

	startup_chain = l_queue_new();

	l_queue_push_tail(startup_chain, &init_create_client);
	l_queue_push_tail(startup_chain, &init_import_server);
	l_queue_push_tail(startup_chain, &init_attach_client);
	l_queue_push_tail(startup_chain, &init_import_subnet);
	l_queue_push_tail(startup_chain, &init_import_remote);
	l_queue_push_tail(startup_chain, &init_add_netkey);
	l_queue_push_tail(startup_chain, &init_create_appkey);
	l_queue_push_tail(startup_chain, &init_add_appkey);
}

static int del_fobject(const char *fpath, const struct stat *sb, int typeflag,
						struct FTW *ftwbuf)
{
	switch (typeflag) {
	case FTW_DP:
		rmdir(fpath);
		break;

	case FTW_SL:
	default:
		remove(fpath);
		break;
	}

	return 0;
}

#define tester_add_with_response(name, test_data, test_func, rsp_data)	\
	l_tester_add_full(tester, name, test_data, init_test, NULL,	\
				test_func, NULL, NULL, 2, rsp_data, NULL)

static void signal_callback(unsigned int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		if (!terminated)
			l_main_quit();

		terminated = true;
		break;
	}
}

static void done_callback(struct l_tester *tester)
{
	if (terminated)
		return;

	l_main_quit();
	terminated = true;
}

static const struct option options[] = {
	{ "version",	no_argument,		NULL, 'v' },
	{ "list",	no_argument,		NULL, 'l' },
	{ "prefix",	required_argument,	NULL, 'p' },
	{ "string",	required_argument,	NULL, 's' },
	{ }
};

static void usage(void)
{
	fprintf(stderr,
		"Usage:\n"
		"\%s [options]\n", tester_name);
	fprintf(stderr,
		"Options:\n"
		"\t-v, --version	Show version information and exit\n"
		"\t-l, --list	Only list the tests to be run\n"
		"\t-p, --prefix	Run tests matching the provided prefix\n"
		"\t-s, --string	Run tests matching the provided string\n");
}

static void parse_options(int *argc, char ***argv)
{
	tester_name = strrchr(*argv[0], '/');

	for (;;) {
		int opt;

		opt = getopt_long(*argc, *argv, "s:p:vl", options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'v':
			printf("%s\n", VERSION);
			exit(EXIT_SUCCESS);
		case 'l':
			option_list = true;
			break;
		case 'p':
			option_prefix = optarg;
			break;
		case 's':
			option_string = optarg;
			break;
		default:
			usage();
			exit(0);
		}
	}
}

static bool setup_test_dir(void)
{
	char *bluez_dir;
	char buf[PATH_MAX];
	ssize_t len;

	len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);

	if (len == -1)
		return false;

	buf[len] = '\0';

	test_dir = l_strdup_printf("/tmp/mesh");
	nftw(test_dir, del_fobject, 5, FTW_DEPTH | FTW_PHYS);

	if (mkdir(test_dir, 0700) != 0) {
		printf("Failed to create dir %s\n", test_dir);
		l_free(test_dir);
		return false;
	}

	bluez_dir = dirname(dirname(buf));
	exe = l_strdup_printf("%s/mesh/bluetooth-meshd", bluez_dir);
	io = l_strdup_printf("unit:%s/%s", test_dir, "test_sk");

	return true;
}

int main(int argc, char *argv[])
{
	int status = EXIT_SUCCESS, pid = -1;

	if (!setup_test_dir())
		return EXIT_FAILURE;

	l_log_set_stderr();
	l_main_init();

	parse_options(&argc, &argv);

	if (!option_list) {

		pid = fork();
		if (pid < 0)
			return EXIT_FAILURE;

		if (pid == 0) {
			char *const dargs[] = {
				exe,
				"--io",
				io,
				"-s",
				test_dir,
				NULL
			};

			printf("spawning %s --io %s -s %s", exe, io, test_dir);
			execv(exe, dargs);
			return EXIT_SUCCESS;
		}
	}

	tester = l_tester_new(option_prefix, option_string, option_list);

	init_startup_chain();

	l_tester_add_full(tester, "Config AppKey Add: Success",
			&test_add_appkey, init_test, create_appkey, add_appkey,
				NULL, NULL, 2, &test_add_appkey_rsp, NULL);

	tester_add_with_response("Config Default TTL Set: Success",
					&test_set_ttl_req, send_cfg_msg,
							&test_set_ttl_rsp);

	tester_add_with_response("Config Get Device Composition: Success",
					&test_dev_comp_req, send_cfg_msg,
							&test_dev_comp_rsp);

	tester_add_with_response("Config Bind: Success",
					&test_bind_req, send_cfg_msg,
							&test_bind_rsp);

	tester_add_with_response("Config Bind: Error Invalid Model",
					&test_bind_inv_mod_req, send_cfg_msg,
							&test_bind_inv_mod_rsp);

	l_tester_start(tester, done_callback);

	if (!option_list && !terminated) {
		l_main_run_with_signal(signal_callback, NULL);

		if (!l_tester_summarize(tester))
			status = EXIT_FAILURE;
	}

	l_queue_destroy(startup_chain, NULL);
	l_queue_destroy(node_proxies, NULL);

	l_free(client_app.node);
	l_free(server_app.node);
	l_dbus_client_destroy(client);
	l_dbus_destroy(dbus);

	l_tester_destroy(tester);

	if (pid > 0)
		kill(pid, SIGTERM);

	l_free(test_dir);
	l_free(io);
	l_free(exe);

	return status;
}
