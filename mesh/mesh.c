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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <time.h>
#include <ell/ell.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "src/shared/mgmt.h"

#include "mesh/mesh-defs.h"
#include "mesh/mesh-io.h"
#include "mesh/node.h"
#include "mesh/net.h"
#include "mesh/storage.h"
#include "mesh/cfgmod.h"
#include "mesh/model.h"
#include "mesh/mesh.h"

struct scan_filter {
	uint8_t id;
	const char *pattern;
};

struct bt_mesh {
	struct mesh_net *net;
	struct mesh_io *io;
	struct l_queue *filters;
	int ref_count;
	uint16_t index;
	uint16_t req_index;
	uint8_t max_filters;
};

static struct l_queue *controllers;
static struct l_queue *mesh_list;
static struct mgmt *mgmt_mesh;
static bool initialized;
static struct bt_mesh *current;

static bool simple_match(const void *a, const void *b)
{
	return a == b;
}

static void save_exit_config(struct bt_mesh *mesh)
{
	const char *cfg_filename;

	if (!mesh_net_cfg_file_get(mesh->net, &cfg_filename) || !cfg_filename)
		return;

	/* Preserve the last sequence number before saving configuration */
	storage_local_write_sequence_number(mesh->net,
					mesh_net_get_seq_num(mesh->net));

	if (storage_save_config(mesh->net, cfg_filename, true, NULL, NULL))
		l_info("Saved final configuration to %s", cfg_filename);
}

static void start_io(struct bt_mesh *mesh, uint16_t index)
{
	struct mesh_io *io;
	struct mesh_io_caps caps;

	l_debug("Starting mesh on hci %u", index);

	io = mesh_io_new(index, MESH_IO_TYPE_GENERIC);
	if (!io) {
		l_error("Failed to start mesh io (hci %u)", index);
		current = NULL;
		return;
	}

	mesh_io_get_caps(io, &caps);
	mesh->max_filters = caps.max_num_filters;

	mesh_net_attach(mesh->net, io);
	mesh_net_set_window_accuracy(mesh->net, caps.window_accuracy);
	mesh->io = io;
	mesh->index = index;

	current = NULL;

	l_debug("Started mesh (io %p) on hci %u", mesh->io, index);
}

static void read_info_cb(uint8_t status, uint16_t length,
					const void *param, void *user_data)
{
	uint16_t index = L_PTR_TO_UINT(user_data);
	const struct mgmt_rp_read_info *rp = param;
	uint32_t current_settings, supported_settings;

	if (!current)
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

	start_io(current, index);
}

static void index_added(uint16_t index, uint16_t length, const void *param,
							void *user_data)
{
	l_debug("hci device %u", index);

	if (!current)
		return;

	if (current->req_index != MGMT_INDEX_NONE &&
					index != current->req_index) {
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

static bool load_config(struct bt_mesh *mesh, const char *in_config_name)
{
	if (!mesh->net)
		return false;

	if (!storage_parse_config(mesh->net, in_config_name))
		return false;

	/* Register foundational models */
	mesh_config_srv_init(mesh->net, PRIMARY_ELE_IDX);

	return true;
}

static bool init_mesh(void)
{
	if (initialized)
		return true;

	controllers = l_queue_new();
	if (!controllers)
		return false;

	mesh_list = l_queue_new();
	if (!mesh_list)
		return false;

	mgmt_mesh = mgmt_new_default();
	if (!mgmt_mesh)
		goto fail;

	mgmt_register(mgmt_mesh, MGMT_EV_INDEX_ADDED, MGMT_INDEX_NONE,
						index_added, NULL, NULL);
	mgmt_register(mgmt_mesh, MGMT_EV_INDEX_REMOVED, MGMT_INDEX_NONE,
						index_removed, NULL, NULL);

	initialized = true;
	return true;

fail:
	l_error("Failed to initialize mesh management");

	l_queue_destroy(controllers, NULL);

	return false;
}

struct bt_mesh *mesh_new(uint16_t index, const char *config_file)
{
	struct bt_mesh *mesh;

	if (!init_mesh())
		return NULL;

	mesh = l_new(struct bt_mesh, 1);
	if (!mesh)
		return NULL;

	mesh->req_index = index;
	mesh->index = MGMT_INDEX_NONE;

	mesh->net = mesh_net_new(index);
	if (!mesh->net) {
		l_free(mesh);
		return NULL;
	}

	if (!load_config(mesh, config_file)) {
		l_error("Failed to load mesh configuration: %s", config_file);
		l_free(mesh);
		return NULL;
	}

	/*
	 * TODO: Check if another mesh is searching for io.
	 * If so, add to pending list and return.
	 */
	l_debug("send read index_list");
	if (mgmt_send(mgmt_mesh, MGMT_OP_READ_INDEX_LIST,
				MGMT_INDEX_NONE, 0, NULL,
				read_index_list_cb, mesh, NULL) > 0) {
		current = mesh;
		l_queue_push_tail(mesh_list, mesh);
		return mesh_ref(mesh);
	}

	l_free(mesh);

	return NULL;
}

struct bt_mesh *mesh_ref(struct bt_mesh *mesh)
{
	if (!mesh)
		return NULL;

	__sync_fetch_and_add(&mesh->ref_count, 1);

	return mesh;
}

void mesh_unref(struct bt_mesh *mesh)
{
	struct mesh_io *io;

	if (!mesh)
		return;

	if (__sync_sub_and_fetch(&mesh->ref_count, 1))
		return;

	if (mesh_net_provisioned_get(mesh->net))
		save_exit_config(mesh);

	node_cleanup(mesh->net);

	storage_release(mesh->net);
	io = mesh_net_detach(mesh->net);
	if (io)
		mesh_io_destroy(io);

	mesh_net_unref(mesh->net);
	l_queue_remove(mesh_list, mesh);
	l_free(mesh);
}

void mesh_cleanup(void)
{
	l_queue_destroy(controllers, NULL);
	l_queue_destroy(mesh_list, NULL);
	mgmt_unref(mgmt_mesh);
}

bool mesh_set_output(struct bt_mesh *mesh, const char *config_name)
{
	if (!config_name)
		return false;

	return mesh_net_cfg_file_set(mesh->net, config_name);
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

struct mesh_net *mesh_get_net(struct bt_mesh *mesh)
{
	return mesh->net;
}
