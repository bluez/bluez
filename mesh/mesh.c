/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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
#include <json-c/json.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/mgmt.h"

#include "mesh/mesh-io.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/storage.h"
#include "mesh/provision.h"
#include "mesh/model.h"
#include "mesh/dbus.h"
#include "mesh/error.h"
#include "mesh/mesh.h"
#include "mesh/agent.h"

/*
 * The default values for mesh configuration. Can be
 * overwritten by values from mesh.conf
 */
#define DEFAULT_PROV_TIMEOUT 60
#define DEFAULT_ALGORITHMS 0x0001

/* TODO: add more default values */

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
	uint16_t algorithms;
	uint16_t req_index;
	uint8_t max_filters;
};

struct join_data{
	struct l_dbus_message *msg;
	struct mesh_agent *agent;
	const char *sender;
	const char *app_path;
	struct mesh_node *node;
	uint32_t disc_watch;
	uint8_t uuid[16];
};

struct attach_data {
	uint64_t token;
	struct l_dbus_message *msg;
	const char *app;
};

static struct bt_mesh mesh;
static struct l_queue *controllers;
static struct mgmt *mgmt_mesh;
static bool initialized;

/* We allow only one outstanding Join request */
static struct join_data *join_pending;

/* Pending Attach requests */
static struct l_queue *attach_queue;

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

static void start_io(uint16_t index)
{
	struct mesh_io *io;
	struct mesh_io_caps caps;

	l_debug("Starting mesh on hci %u", index);

	io = mesh_io_new(index, MESH_IO_TYPE_GENERIC);
	if (!io) {
		l_error("Failed to start mesh io (hci %u)", index);
		return;
	}

	mesh_io_get_caps(io, &caps);
	mesh.max_filters = caps.max_num_filters;

	mesh.io = io;

	l_debug("Started mesh (io %p) on hci %u", mesh.io, index);

	node_attach_io(io);
}

/* Used for any outbound traffic that doesn't have Friendship Constraints */
/* This includes Beacons, Provisioning and unrestricted Network Traffic */
bool mesh_send_pkt(uint8_t count, uint16_t interval,
					uint8_t *data, uint16_t len)
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
	if (mesh.prov_rx && mesh.prov_rx != cb)
		return false;

	mesh.prov_rx = cb;
	mesh.prov_data = user_data;

	return mesh_io_register_recv_cb(mesh.io, MESH_IO_FILTER_PROV,
							prov_rx, &mesh);
}

void mesh_unreg_prov_rx(prov_rx_cb_t cb)
{
	if (mesh.prov_rx != cb)
		return;

	mesh.prov_rx = NULL;
	mesh.prov_data = NULL;
	mesh_io_deregister_recv_cb(mesh.io, MESH_IO_FILTER_PROV);
}

static void read_info_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	uint16_t index = L_PTR_TO_UINT(user_data);
	const struct mgmt_rp_read_info *rp = param;
	uint32_t current_settings, supported_settings;

	if (mesh.io)
		/* Already initialized */
		return;

	l_debug("hci %u status 0x%02x", index, status);

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read info for hci index %u: %s (0x%02x)",
					index, mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read info response too short");
		return;
	}

	current_settings = btohl(rp->current_settings);
	supported_settings = btohl(rp->supported_settings);

	l_debug("settings: supp %8.8x curr %8.8x",
					supported_settings, current_settings);

	if (current_settings & MGMT_SETTING_POWERED) {
		l_info("Controller hci %u is in use", index);
		return;
	}

	if (!(supported_settings & MGMT_SETTING_LE)) {
		l_info("Controller hci %u does not support LE", index);
		return;
	}

	start_io(index);
}

static void index_added(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_debug("hci device %u", index);

	if (mesh.req_index != MGMT_INDEX_NONE &&
					index != mesh.req_index) {
		l_debug("Ignore index %d", index);
		return;
	}

	if (l_queue_find(controllers, simple_match, L_UINT_TO_PTR(index)))
		return;

	l_queue_push_tail(controllers, L_UINT_TO_PTR(index));

	if (mgmt_send(mgmt_mesh, MGMT_OP_READ_INFO, index, 0, NULL,
			read_info_cb, L_UINT_TO_PTR(index), NULL) > 0)
		return;

	l_queue_remove(controllers, L_UINT_TO_PTR(index));
}

static void index_removed(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_warn("Hci dev %4.4x removed", index);
	l_queue_remove(controllers, L_UINT_TO_PTR(index));
}

static void read_index_list_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	uint16_t num;
	int i;

	if (status != MGMT_STATUS_SUCCESS) {
		l_error("Failed to read index list: %s (0x%02x)",
						mgmt_errstr(status), status);
		return;
	}

	if (length < sizeof(*rp)) {
		l_error("Read index list response sixe too short");
		return;
	}

	num = btohs(rp->num_controllers);

	l_debug("Number of controllers: %u", num);

	if (num * sizeof(uint16_t) + sizeof(*rp) != length) {
		l_error("Incorrect packet size for index list response");
		return;
	}

	for (i = 0; i < num; i++) {
		uint16_t index;

		index = btohs(rp->index[i]);
		index_added(index, 0, NULL, user_data);
	}
}

static bool init_mgmt(void)
{
	mgmt_mesh = mgmt_new_default();
	if (!mgmt_mesh)
		return false;

	controllers = l_queue_new();
	if (!controllers)
		return false;

	mgmt_register(mgmt_mesh, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
						index_added, NULL, NULL);
	mgmt_register(mgmt_mesh, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
						index_removed, NULL, NULL);
	return true;
}

bool mesh_init(uint16_t index, const char *config_dir)
{
	if (initialized)
		return true;

	if (!init_mgmt()) {
		l_error("Failed to initialize mesh management");
		return false;
	}

	mesh.req_index = index;

	mesh_model_init();
	mesh_agent_init();

	/* TODO: read mesh.conf */
	mesh.prov_timeout = DEFAULT_PROV_TIMEOUT;
	mesh.algorithms = DEFAULT_ALGORITHMS;

	if (!config_dir)
		config_dir = MESH_STORAGEDIR;

	l_info("Loading node configuration from %s", config_dir);

	if (!storage_load_nodes(config_dir))
		return false;

	l_debug("send read index_list");
	if (mgmt_send(mgmt_mesh, MGMT_OP_READ_INDEX_LIST,
				MGMT_INDEX_NONE, 0, NULL,
				read_index_list_cb, NULL, NULL) <= 0)
		return false;

	return true;
}

static void attach_exit(void *data)
{
	struct l_dbus_message *reply;
	struct attach_data *pending = data;

	reply = dbus_error(pending->msg, MESH_ERROR_FAILED, "Failed. Exiting");
	l_dbus_send(dbus_get_bus(), reply);
	l_free(pending);
}

static void free_pending_join_call(bool failed)
{
	if (!join_pending)
		return;

	if (join_pending->disc_watch)
		l_dbus_remove_watch(dbus_get_bus(),
						join_pending->disc_watch);

	mesh_agent_remove(join_pending->agent);

	if (failed) {
		storage_remove_node_config(join_pending->node);
		node_free(join_pending->node);
	}

	l_free(join_pending);
	join_pending = NULL;
}

void mesh_cleanup(void)
{
	struct l_dbus_message *reply;

	mesh_io_destroy(mesh.io);
	mgmt_unref(mgmt_mesh);

	if (join_pending) {

		if (join_pending->msg) {
			reply = dbus_error(join_pending->msg, MESH_ERROR_FAILED,
							"Failed. Exiting");
			l_dbus_send(dbus_get_bus(), reply);
		}

		acceptor_cancel(&mesh);
		free_pending_join_call(true);
	}

	l_queue_destroy(attach_queue, attach_exit);
	node_cleanup_all();
	mesh_model_cleanup();

	l_queue_destroy(controllers, NULL);
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

	if (join_pending->msg)
		l_dbus_message_unref(join_pending->msg);

	acceptor_cancel(&mesh);
	join_pending->disc_watch = 0;

	free_pending_join_call(true);
}

static const char *prov_status_str(uint8_t status)
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

	l_dbus_message_set_arguments(msg, "s", prov_status_str(status));
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
	const uint8_t *dev_key;

	l_debug("Provisioning complete %s", prov_status_str(status));

	if (!join_pending)
		return false;

	owner = join_pending->sender;
	path = join_pending->app_path;

	if (status == PROV_ERR_SUCCESS &&
	    !node_add_pending_local(join_pending->node, info, mesh.io))
		status = PROV_ERR_UNEXPECTED_ERR;

	if (status != PROV_ERR_SUCCESS) {
		send_join_failed(owner, path, status);
		return false;
	}

	dev_key = node_get_device_key(join_pending->node);

	msg = l_dbus_message_new_method_call(dbus, owner, path,
						MESH_APPLICATION_INTERFACE,
						"JoinComplete");

	l_dbus_message_set_arguments(msg, "t", l_get_u64(dev_key));

	l_dbus_send(dbus_get_bus(), msg);

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
	uint8_t *uuid;
	uint32_t n;

	l_debug("Join network request");

	if (join_pending)
		return dbus_error(msg, MESH_ERROR_BUSY,
						"Provisioning in progress");

	if (!l_dbus_message_get_arguments(msg, "oay", &app_path,
								&iter_uuid))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	join_pending = l_new(struct join_data, 1);

	l_dbus_message_iter_get_fixed_array(&iter_uuid, &uuid, &n);

	if (n != 16) {
		l_free(join_pending);
		join_pending = NULL;
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad device UUID");
	}

	memcpy(join_pending->uuid, uuid, 16);

	sender = l_dbus_message_get_sender(msg);

	join_pending->sender = l_strdup(sender);
	join_pending->disc_watch = l_dbus_add_disconnect_watch(dbus, sender,
						prov_disc_cb, NULL, NULL);
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

static bool match_attach_request(const void *a, const void *b)
{
	const struct attach_data *pending = a;
	const uint64_t *token = b;

	return *token == pending->token;
}

static void attach_ready_cb(int status, char *node_path, uint64_t token)
{
	struct l_dbus_message *reply;
	struct attach_data *pending;

	pending = l_queue_find(attach_queue, match_attach_request, &token);
	if (!pending)
		return;

	if (status != MESH_ERROR_NONE) {
		const char *desc = (status == MESH_ERROR_NOT_FOUND) ?
				"Node match not found" : "Attach failed";
		reply = dbus_error(pending->msg, status, desc);
		goto done;
	}

	reply = l_dbus_message_new_method_return(pending->msg);

	node_build_attach_reply(reply, token);

done:
	l_dbus_send(dbus_get_bus(), reply);
	l_queue_remove(attach_queue, pending);
	l_free(pending);
}

static struct l_dbus_message *attach_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint64_t token = 1;
	const char *app_path, *sender;
	struct attach_data *pending;

	l_debug("Attach");

	if (!l_dbus_message_get_arguments(msg, "ot", &app_path, &token))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	sender = l_dbus_message_get_sender(msg);

	if (node_attach(app_path, sender, token, attach_ready_cb) !=
								MESH_ERROR_NONE)
		return dbus_error(msg, MESH_ERROR_NOT_FOUND,
						"Matching node not found");

	pending = l_new(struct attach_data, 1);

	pending->token = token;
	pending->msg = l_dbus_message_ref(msg);

	if (!attach_queue)
		attach_queue = l_queue_new();

	l_queue_push_tail(attach_queue, pending);

	return NULL;
}

static void setup_network_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "Join", 0, join_network_call, "",
				"oay", "app", "uuid");

	l_dbus_interface_method(iface, "Cancel", 0, cancel_join_call, "", "");

	l_dbus_interface_method(iface, "Attach", 0, attach_call,
				"oa(ya(qa{sv}))", "ot", "node", "configuration",
				"app", "token");

	/* TODO: Implement Leave method */
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
