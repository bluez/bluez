/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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
#include <ell/ell.h>

#include "mesh/mesh-io.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/provision.h"
#include "mesh/model.h"
#include "mesh/dbus.h"
#include "mesh/error.h"
#include "mesh/agent.h"
#include "mesh/mesh.h"
#include "mesh/mesh-defs.h"

/*
 * The default values for mesh configuration. Can be
 * overwritten by values from mesh-main.conf
 */
#define DEFAULT_PROV_TIMEOUT 60
#define DEFAULT_CRPL 100
#define DEFAULT_FRIEND_QUEUE_SZ 32

#define DEFAULT_ALGORITHMS 0x0001

struct scan_filter {
	uint8_t id;
	const char *pattern;
};

struct bt_mesh {
	struct mesh_io *io;
	struct l_queue *filters;
	prov_rx_cb_t prov_rx;
	void *prov_data;
	uint32_t prov_timeout;
	bool beacon_enabled;
	bool friend_support;
	bool relay_support;
	bool lpn_support;
	bool proxy_support;
	uint16_t crpl;
	uint16_t algorithms;
	uint16_t req_index;
	uint8_t friend_queue_sz;
	uint8_t max_filters;
};

struct join_data{
	struct l_dbus_message *msg;
	struct mesh_agent *agent;
	char *sender;
	const char *app_path;
	struct mesh_node *node;
	uint32_t disc_watch;
	uint8_t *uuid;
};

struct mesh_init_request {
	mesh_ready_func_t cb;
	void *user_data;
};

static struct bt_mesh mesh = {
	.algorithms = DEFAULT_ALGORITHMS,
	.prov_timeout = DEFAULT_PROV_TIMEOUT,
	.beacon_enabled = true,
	.friend_support = true,
	.relay_support = true,
	.lpn_support = false,
	.proxy_support = false,
	.crpl = DEFAULT_CRPL,
	.friend_queue_sz = DEFAULT_FRIEND_QUEUE_SZ
};

/* We allow only one outstanding Join request */
static struct join_data *join_pending;

/* Pending method requests */
static struct l_queue *pending_queue;

static const char *storage_dir;

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

/* Used for any outbound traffic that doesn't have Friendship Constraints */
/* This includes Beacons, Provisioning and unrestricted Network Traffic */
bool mesh_send_pkt(uint8_t count, uint16_t interval,
					void *data, uint16_t len)
{
	struct mesh_io_send_info info = {
		.type = MESH_IO_TIMING_TYPE_GENERAL,
		.u.gen.cnt = count,
		.u.gen.interval = interval,
		.u.gen.max_delay = 0,
		.u.gen.min_delay = 0,
	};

	return mesh_io_send(mesh.io, &info, data, len);
}

bool mesh_send_cancel(const uint8_t *filter, uint8_t len)
{
	return mesh_io_send_cancel(mesh.io, filter, len);
}

static void prov_rx(void *user_data, struct mesh_io_recv_info *info,
					const uint8_t *data, uint16_t len)
{
	if (user_data != &mesh)
		return;

	if (mesh.prov_rx)
		mesh.prov_rx(mesh.prov_data, data, len);
}

bool mesh_reg_prov_rx(prov_rx_cb_t cb, void *user_data)
{
	uint8_t prov_filter[] = {MESH_AD_TYPE_PROVISION};

	if (mesh.prov_rx && mesh.prov_rx != cb)
		return false;

	mesh.prov_rx = cb;
	mesh.prov_data = user_data;

	return mesh_io_register_recv_cb(mesh.io, prov_filter,
					sizeof(prov_filter), prov_rx, &mesh);
}

void mesh_unreg_prov_rx(prov_rx_cb_t cb)
{
	uint8_t prov_filter[] = {MESH_AD_TYPE_PROVISION};

	if (mesh.prov_rx != cb)
		return;

	mesh.prov_rx = NULL;
	mesh.prov_data = NULL;
	mesh_io_deregister_recv_cb(mesh.io, prov_filter, sizeof(prov_filter));
}

static void io_ready_callback(void *user_data, bool result)
{
	struct mesh_init_request *req = user_data;

	if (result)
		node_attach_io_all(mesh.io);

	req->cb(req->user_data, result);

	l_free(req);
}

bool mesh_beacon_enabled(void)
{
	return mesh.beacon_enabled;
}

bool mesh_relay_supported(void)
{
	return mesh.relay_support;
}

bool mesh_friendship_supported(void)
{
	return mesh.friend_support;
}

uint16_t mesh_get_crpl(void)
{
	return mesh.crpl;
}

uint8_t mesh_get_friend_queue_size(void)
{
	return mesh.friend_queue_sz;
}

static void parse_settings(const char *mesh_conf_fname)
{
	struct l_settings *settings;
	char *str;
	uint32_t value;

	settings = l_settings_new();
	if (!l_settings_load_from_file(settings, mesh_conf_fname))
		return;

	str = l_settings_get_string(settings, "General", "Beacon");
	if (str) {
		if (!strcasecmp(str, "true"))
			mesh.beacon_enabled = true;
		l_free(str);
	}

	str = l_settings_get_string(settings, "General", "Relay");
	if (str) {
		if (!strcasecmp(str, "false"))
			mesh.relay_support = false;
		l_free(str);
	}

	str = l_settings_get_string(settings, "General", "Friendship");
	if (str) {
		if (!strcasecmp(str, "false"))
			mesh.friend_support = false;
		l_free(str);
	}

	if (l_settings_get_uint(settings, "General", "CRPL", &value) &&
							value <= 65535)
		mesh.crpl = value;

	if (l_settings_get_uint(settings, "General", "FriendQueueSize", &value)
								&& value < 127)
		mesh.friend_queue_sz = value;

	if (l_settings_get_uint(settings, "General", "ProvTimeout", &value))
		mesh.prov_timeout = value;
}

bool mesh_init(const char *config_dir, const char *mesh_conf_fname,
					enum mesh_io_type type, void *opts,
					mesh_ready_func_t cb, void *user_data)
{
	struct mesh_io_caps caps;
	struct mesh_init_request *req;

	if (mesh.io)
		return true;

	mesh_model_init();
	mesh_agent_init();

	/* TODO: read mesh.conf */
	mesh.prov_timeout = DEFAULT_PROV_TIMEOUT;
	mesh.algorithms = DEFAULT_ALGORITHMS;

	storage_dir = config_dir ? config_dir : MESH_STORAGEDIR;

	l_info("Loading node configuration from %s", storage_dir);

	if (!mesh_conf_fname)
		mesh_conf_fname = CONFIGDIR "/mesh-main.conf";

	parse_settings(mesh_conf_fname);

	if (!node_load_from_storage(storage_dir))
		return false;

	req = l_new(struct mesh_init_request, 1);
	req->cb = cb;
	req->user_data = user_data;

	mesh.io = mesh_io_new(type, opts, io_ready_callback, req);
	if (!mesh.io) {
		l_free(req);
		return false;
	}

	l_debug("io %p", mesh.io);
	mesh_io_get_caps(mesh.io, &caps);
	mesh.max_filters = caps.max_num_filters;

	return true;
}

static void pending_request_exit(void *data)
{
	struct l_dbus_message *reply;
	struct l_dbus_message *msg = data;

	reply = dbus_error(msg, MESH_ERROR_FAILED, "Failed. Exiting");
	l_dbus_send(dbus_get_bus(), reply);
}

static void free_pending_join_call(bool failed)
{
	if (!join_pending)
		return;

	if (join_pending->disc_watch)
		l_dbus_remove_watch(dbus_get_bus(),
						join_pending->disc_watch);

	mesh_agent_remove(join_pending->agent);

	if (failed)
		node_remove(join_pending->node);

	l_free(join_pending->sender);
	l_free(join_pending);
	join_pending = NULL;
}

void mesh_cleanup(void)
{
	struct l_dbus_message *reply;

	mesh_io_destroy(mesh.io);

	if (join_pending) {

		if (join_pending->msg) {
			reply = dbus_error(join_pending->msg, MESH_ERROR_FAILED,
							"Failed. Exiting");
			l_dbus_send(dbus_get_bus(), reply);
		}

		acceptor_cancel(&mesh);
		free_pending_join_call(true);
	}

	l_queue_destroy(pending_queue, pending_request_exit);
	node_cleanup_all();
	mesh_model_cleanup();

	l_dbus_object_remove_interface(dbus_get_bus(), BLUEZ_MESH_PATH,
							MESH_NETWORK_INTERFACE);
	l_dbus_unregister_interface(dbus_get_bus(), MESH_NETWORK_INTERFACE);
}

const char *mesh_status_str(uint8_t err)
{
	switch (err) {
	case MESH_STATUS_SUCCESS: return "Success";
	case MESH_STATUS_INVALID_ADDRESS: return "Invalid Address";
	case MESH_STATUS_INVALID_MODEL: return "Invalid Model";
	case MESH_STATUS_INVALID_APPKEY: return "Invalid AppKey";
	case MESH_STATUS_INVALID_NETKEY: return "Invalid NetKey";
	case MESH_STATUS_INSUFF_RESOURCES: return "Insufficient Resources";
	case MESH_STATUS_IDX_ALREADY_STORED: return "Key Idx Already Stored";
	case MESH_STATUS_INVALID_PUB_PARAM: return "Invalid Publish Parameters";
	case MESH_STATUS_NOT_SUB_MOD: return "Not a Subscribe Model";
	case MESH_STATUS_STORAGE_FAIL: return "Storage Failure";
	case MESH_STATUS_FEATURE_NO_SUPPORT: return "Feature Not Supported";
	case MESH_STATUS_CANNOT_UPDATE: return "Cannot Update";
	case MESH_STATUS_CANNOT_REMOVE: return "Cannot Remove";
	case MESH_STATUS_CANNOT_BIND: return "Cannot bind";
	case MESH_STATUS_UNABLE_CHANGE_STATE: return "Unable to change state";
	case MESH_STATUS_CANNOT_SET: return "Cannot set";
	case MESH_STATUS_UNSPECIFIED_ERROR: return "Unspecified error";
	case MESH_STATUS_INVALID_BINDING: return "Invalid Binding";

	default: return "Unknown";
	}
}

/* This is being called if the app exits unexpectedly */
static void prov_disc_cb(struct l_dbus *bus, void *user_data)
{
	if (!join_pending)
		return;

	if (join_pending->msg) {
		l_dbus_message_unref(join_pending->msg);
		join_pending->msg = NULL;
	}

	acceptor_cancel(&mesh);
	join_pending->disc_watch = 0;

	free_pending_join_call(true);
}

const char *mesh_prov_status_str(uint8_t status)
{
	switch (status) {
	case PROV_ERR_SUCCESS:
		return "success";
	case PROV_ERR_INVALID_PDU:
	case PROV_ERR_INVALID_FORMAT:
	case PROV_ERR_UNEXPECTED_PDU:
		return "bad-pdu";
	case PROV_ERR_CONFIRM_FAILED:
		return "confirmation-failed";
	case PROV_ERR_INSUF_RESOURCE:
		return "out-of-resources";
	case PROV_ERR_DECRYPT_FAILED:
		return "decryption-error";
	case PROV_ERR_CANT_ASSIGN_ADDR:
		return "cannot-assign-addresses";
	case PROV_ERR_TIMEOUT:
		return "timeout";
	case PROV_ERR_UNEXPECTED_ERR:
	default:
		return "unexpected-error";
	}
}

static void send_join_failed(const char *owner, const char *path,
							uint8_t status)
{
	struct l_dbus_message *msg;
	struct l_dbus *dbus = dbus_get_bus();

	msg = l_dbus_message_new_method_call(dbus, owner, path,
						MESH_APPLICATION_INTERFACE,
						"JoinFailed");

	l_dbus_message_set_arguments(msg, "s", mesh_prov_status_str(status));
	l_dbus_send(dbus_get_bus(), msg);

	free_pending_join_call(true);
}

static bool prov_complete_cb(void *user_data, uint8_t status,
					struct mesh_prov_node_info *info)
{
	struct l_dbus *dbus = dbus_get_bus();
	struct l_dbus_message *msg;
	const char *owner;
	const char *path;
	const uint8_t *token;

	l_debug("Provisioning complete %s", mesh_prov_status_str(status));

	if (!join_pending)
		return false;

	owner = join_pending->sender;
	path = join_pending->app_path;

	if (status == PROV_ERR_SUCCESS &&
	    !node_add_pending_local(join_pending->node, info))
		status = PROV_ERR_UNEXPECTED_ERR;

	if (status != PROV_ERR_SUCCESS) {
		send_join_failed(owner, path, status);
		return false;
	}

	node_attach_io(join_pending->node, mesh.io);
	token = node_get_token(join_pending->node);

	msg = l_dbus_message_new_method_call(dbus, owner, path,
						MESH_APPLICATION_INTERFACE,
						"JoinComplete");

	l_dbus_message_set_arguments(msg, "t", l_get_be64(token));

	l_dbus_send(dbus, msg);

	free_pending_join_call(false);

	return true;
}

static void node_init_cb(struct mesh_node *node, struct mesh_agent *agent)
{
	struct l_dbus_message *reply;
	uint8_t num_ele;

	if (!node) {
		reply = dbus_error(join_pending->msg, MESH_ERROR_FAILED,
				"Failed to create node from application");
		goto fail;
	}

	join_pending->node = node;
	num_ele = node_get_num_elements(node);

	if (!acceptor_start(num_ele, join_pending->uuid, mesh.algorithms,
				mesh.prov_timeout, agent, prov_complete_cb,
				&mesh))
	{
		reply = dbus_error(join_pending->msg, MESH_ERROR_FAILED,
				"Failed to start provisioning acceptor");
		goto fail;
	}

	reply = l_dbus_message_new_method_return(join_pending->msg);
	l_dbus_send(dbus_get_bus(), reply);
	join_pending->msg = NULL;

	/* Setup disconnect watch */
	join_pending->disc_watch = l_dbus_add_disconnect_watch(dbus_get_bus(),
						join_pending->sender,
						prov_disc_cb, NULL, NULL);

	return;

fail:
	l_dbus_send(dbus_get_bus(), reply);
	free_pending_join_call(true);
}

static struct l_dbus_message *join_network_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	const char *app_path, *sender;
	struct l_dbus_message_iter iter_uuid;
	uint32_t n;

	l_debug("Join network request");

	if (join_pending)
		return dbus_error(msg, MESH_ERROR_BUSY,
						"Provisioning in progress");

	if (!l_dbus_message_get_arguments(msg, "oay", &app_path,
								&iter_uuid))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	join_pending = l_new(struct join_data, 1);

	if (!l_dbus_message_iter_get_fixed_array(&iter_uuid,
						&join_pending->uuid, &n)
								|| n != 16) {
		l_free(join_pending);
		join_pending = NULL;
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad device UUID");
	}

	if (node_find_by_uuid(join_pending->uuid)) {
		l_free(join_pending);
		join_pending = NULL;
		return dbus_error(msg, MESH_ERROR_ALREADY_EXISTS,
							"Node already exists");
	}

	sender = l_dbus_message_get_sender(msg);

	join_pending->sender = l_strdup(sender);
	join_pending->msg = l_dbus_message_ref(msg);
	join_pending->app_path = app_path;

	/* Try to create a temporary node */
	node_join(app_path, sender, join_pending->uuid, node_init_cb);

	return NULL;
}

static struct l_dbus_message *cancel_join_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message *reply;

	l_debug("Cancel Join");

	if (!join_pending) {
		reply = dbus_error(msg, MESH_ERROR_DOES_NOT_EXIST,
							"No join in progress");
		goto done;
	}

	acceptor_cancel(&mesh);

	/* Return error to the original Join call */
	if (join_pending->msg) {
		reply = dbus_error(join_pending->msg, MESH_ERROR_FAILED, NULL);
		l_dbus_send(dbus_get_bus(), reply);
	}

	reply = l_dbus_message_new_method_return(msg);
	l_dbus_message_set_arguments(reply, "");

	free_pending_join_call(true);
done:
	return reply;
}

static void attach_ready_cb(void *user_data, int status, struct mesh_node *node)
{
	struct l_dbus_message *reply;
	struct l_dbus_message *pending_msg;

	pending_msg = l_queue_find(pending_queue, simple_match, user_data);
	if (!pending_msg)
		return;

	if (status != MESH_ERROR_NONE) {
		const char *desc = (status == MESH_ERROR_NOT_FOUND) ?
				"Node match not found" : "Attach failed";
		reply = dbus_error(pending_msg, status, desc);
		goto done;
	}

	reply = l_dbus_message_new_method_return(pending_msg);

	node_build_attach_reply(node, reply);

done:
	l_dbus_send(dbus_get_bus(), reply);
	l_queue_remove(pending_queue, pending_msg);
}

static struct l_dbus_message *attach_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint64_t token;
	const char *app_path, *sender;
	struct l_dbus_message *pending_msg;
	int status;

	l_debug("Attach");

	if (!l_dbus_message_get_arguments(msg, "ot", &app_path, &token))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	sender = l_dbus_message_get_sender(msg);

	pending_msg = l_dbus_message_ref(msg);
	if (!pending_queue)
		pending_queue = l_queue_new();

	l_queue_push_tail(pending_queue, pending_msg);

	status = node_attach(app_path, sender, token, attach_ready_cb,
								pending_msg);
	if (status == MESH_ERROR_NONE)
		return NULL;

	l_queue_remove(pending_queue, pending_msg);

	return dbus_error(msg, status, NULL);
}

static struct l_dbus_message *leave_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint64_t token;

	l_debug("Leave");

	if (!l_dbus_message_get_arguments(msg, "t", &token))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	node_remove(node_find_by_token(token));

	return l_dbus_message_new_method_return(msg);
}

static void create_node_ready_cb(void *user_data, int status,
							struct mesh_node *node)
{
	struct l_dbus_message *reply;
	struct l_dbus_message *pending_msg;
	const uint8_t *token;

	pending_msg = l_queue_find(pending_queue, simple_match, user_data);
	if (!pending_msg)
		return;

	if (status != MESH_ERROR_NONE) {
		reply = dbus_error(pending_msg, status, NULL);
		goto done;
	}

	node_attach_io(node, mesh.io);

	reply = l_dbus_message_new_method_return(pending_msg);
	token = node_get_token(node);

	l_debug();
	l_dbus_message_set_arguments(reply, "t", l_get_be64(token));

done:
	l_dbus_send(dbus_get_bus(), reply);
	l_queue_remove(pending_queue, pending_msg);
}

static struct l_dbus_message *create_network_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	const char *app_path, *sender;
	struct l_dbus_message_iter iter_uuid;
	struct l_dbus_message *pending_msg;
	uint8_t *uuid;
	uint32_t n;

	l_debug("Create network request");

	if (!l_dbus_message_get_arguments(msg, "oay", &app_path,
								&iter_uuid))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_uuid, &uuid, &n)
								|| n != 16)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad device UUID");

	sender = l_dbus_message_get_sender(msg);
	pending_msg = l_dbus_message_ref(msg);
	if (!pending_queue)
		pending_queue = l_queue_new();

	l_queue_push_tail(pending_queue, pending_msg);

	node_create(app_path, sender, uuid, create_node_ready_cb,
								pending_msg);

	return NULL;
}

static struct l_dbus_message *import_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	const char *app_path, *sender;
	struct l_dbus_message *pending_msg = NULL;
	struct l_dbus_message_iter iter_uuid;
	struct l_dbus_message_iter iter_dev_key;
	struct l_dbus_message_iter iter_net_key;
	struct l_dbus_message_iter iter_flags;
	const char *key;
	struct l_dbus_message_iter var;

	uint8_t *uuid;
	uint8_t *dev_key;
	uint8_t *net_key;
	uint16_t net_idx;
	bool kr = false;
	bool ivu = false;
	uint32_t iv_index;
	uint16_t unicast;
	uint32_t n;

	l_debug("Import local node request");

	if (!l_dbus_message_get_arguments(msg, "oayayayqa{sv}uq",
						&app_path, &iter_uuid,
						&iter_dev_key, &iter_net_key,
						&net_idx, &iter_flags,
						&iv_index,
						&unicast))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_uuid, &uuid, &n) ||
									n != 16)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, "Bad dev UUID");

	if (node_find_by_uuid(uuid))
		return dbus_error(msg, MESH_ERROR_ALREADY_EXISTS,
							"Node already exists");

	if (!l_dbus_message_iter_get_fixed_array(&iter_dev_key, &dev_key, &n) ||
									n != 16)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad dev key");

	if (!l_dbus_message_iter_get_fixed_array(&iter_net_key, &net_key, &n) ||
									n != 16)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad net key");

	if (net_idx > MAX_KEY_IDX)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad net index");

	while (l_dbus_message_iter_next_entry(&iter_flags, &key, &var)) {
		if (!strcmp(key, "IVUpdate")) {
			if (!l_dbus_message_iter_get_variant(&var, "b",
								&ivu))
				goto fail;
			continue;
		}

		if (!strcmp(key, "KeyRefresh")) {
			if (!l_dbus_message_iter_get_variant(&var, "b",
								&kr))
				goto fail;
			continue;
		}

		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad flags");
	}

	if (!IS_UNICAST(unicast))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad address");

	sender = l_dbus_message_get_sender(msg);
	pending_msg = l_dbus_message_ref(msg);

	if (!pending_queue)
		pending_queue = l_queue_new();

	l_queue_push_tail(pending_queue, pending_msg);

	if (!node_import(app_path, sender, uuid, dev_key, net_key, net_idx,
					kr, ivu, iv_index, unicast,
					create_node_ready_cb, pending_msg))
		goto fail;

	return NULL;

fail:
	if (pending_msg) {
		l_dbus_message_unref(msg);
		l_queue_remove(pending_queue, pending_msg);
	}

	return dbus_error(msg, MESH_ERROR_INVALID_ARGS, "Node import failed");
}

static void setup_network_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "Join", 0, join_network_call, "",
							"oay", "app", "uuid");

	l_dbus_interface_method(iface, "Cancel", 0, cancel_join_call, "", "");

	l_dbus_interface_method(iface, "Attach", 0, attach_call,
					"oa(ya(qa{sv}))", "ot", "node",
					"configuration", "app", "token");

	l_dbus_interface_method(iface, "Leave", 0, leave_call, "", "t",
								"token");

	l_dbus_interface_method(iface, "CreateNetwork", 0, create_network_call,
					"t", "oay", "token", "app", "uuid");

	l_dbus_interface_method(iface, "Import", 0,
					import_call,
					"t", "oayayayqa{sv}uq", "token",
					"app", "uuid", "dev_key", "net_key",
					"net_index", "flags", "iv_index",
					"unicast");
}

bool mesh_dbus_init(struct l_dbus *dbus)
{
	if (!l_dbus_register_interface(dbus, MESH_NETWORK_INTERFACE,
						setup_network_interface,
						NULL, false)) {
		l_info("Unable to register %s interface",
							MESH_NETWORK_INTERFACE);
		return false;
	}

	if (!l_dbus_object_add_interface(dbus, BLUEZ_MESH_PATH,
						MESH_NETWORK_INTERFACE, NULL)) {
		l_info("Unable to register the mesh object on '%s'",
							MESH_NETWORK_INTERFACE);
		l_dbus_unregister_interface(dbus, MESH_NETWORK_INTERFACE);
		return false;
	}

	l_info("Added Network Interface on %s", BLUEZ_MESH_PATH);

	return true;
}

const char *mesh_get_storage_dir(void)
{
	return storage_dir;
}
