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

#include <time.h>
#include <ell/ell.h>

#include "lib/bluetooth.h"

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
	int ref_count;
	struct l_queue *filters;
	uint8_t max_filters;
};

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

struct bt_mesh *mesh_create(uint16_t index)
{
	struct bt_mesh *mesh;
	struct mesh_io *io;
	struct mesh_io_caps caps;

	mesh = l_new(struct bt_mesh, 1);
	if (!mesh)
		return NULL;

	mesh->net = mesh_net_new(index);
	if (!mesh->net) {
		l_free(mesh);
		return NULL;
	}

	io = mesh_io_new(index, MESH_IO_TYPE_GENERIC);
	if (!io) {
		mesh_net_unref(mesh->net);
		l_free(mesh);
		return NULL;
	}

	mesh_io_get_caps(io, &caps);
	mesh->max_filters = caps.max_num_filters;

	mesh_net_attach(mesh->net, io);
	mesh_net_set_window_accuracy(mesh->net, caps.window_accuracy);

	return mesh_ref(mesh);
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
	l_free(mesh);
}

bool mesh_load_config(struct bt_mesh *mesh, const char *in_config_name)
{
	if (!storage_parse_config(mesh->net, in_config_name))
		return false;

	/* Register foundational models */
	mesh_config_srv_init(mesh->net, PRIMARY_ELE_IDX);

	return true;
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
	if (!mesh)
		return NULL;

	return mesh->net;
}
