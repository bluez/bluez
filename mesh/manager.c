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
#include <ell/ell.h>

#include "mesh/dbus.h"
#include "mesh/error.h"
#include "mesh/mesh.h"
#include "mesh/manager.h"

static struct l_dbus_message *add_node_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	struct l_dbus_message_iter iter_uuid;
	uint8_t *uuid;
	uint32_t n;

	l_debug("Add node request");

	if (!l_dbus_message_get_arguments(msg, "ay", &iter_uuid))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_uuid, &uuid, &n)
								|| n != 16)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad device UUID");

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *delete_node_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t primary;
	uint8_t num_ele;

	if (!l_dbus_message_get_arguments(msg, "qy", &primary, &num_ele))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *start_scan_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t duration;

	if (!l_dbus_message_get_arguments(msg, "q", &duration))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *cancel_scan_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *create_subnet_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx;

	if (!l_dbus_message_get_arguments(msg, "q", &net_idx))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *update_subnet_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx;

	if (!l_dbus_message_get_arguments(msg, "q", &net_idx))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *delete_subnet_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx;

	if (!l_dbus_message_get_arguments(msg, "q", &net_idx))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *import_subnet_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx;
	struct l_dbus_message_iter iter_key;
	uint8_t *key;
	uint32_t n;

	if (!l_dbus_message_get_arguments(msg, "qay", &net_idx, &iter_key))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_key, &key, &n)
								|| n != 16)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad network key");

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *create_appkey_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx, app_idx;

	if (!l_dbus_message_get_arguments(msg, "qq", &net_idx, &app_idx))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *update_appkey_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx, app_idx;

	if (!l_dbus_message_get_arguments(msg, "qq", &net_idx, &app_idx))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *delete_appkey_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx, app_idx;

	if (!l_dbus_message_get_arguments(msg, "qq", &net_idx, &app_idx))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *import_appkey_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx, app_idx;
	struct l_dbus_message_iter iter_key;
	uint8_t *key;
	uint32_t n;

	if (!l_dbus_message_get_arguments(msg, "qqay", &net_idx, &app_idx,
								&iter_key))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	if (!l_dbus_message_iter_get_fixed_array(&iter_key, &key, &n)
								|| n != 16)
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS,
							"Bad application key");

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static struct l_dbus_message *set_key_phase_call(struct l_dbus *dbus,
						struct l_dbus_message *msg,
						void *user_data)
{
	uint16_t net_idx;
	uint8_t phase;

	if (!l_dbus_message_get_arguments(msg, "qy", &net_idx, &phase))
		return dbus_error(msg, MESH_ERROR_INVALID_ARGS, NULL);

	/* TODO */
	return dbus_error(msg, MESH_ERROR_NOT_IMPLEMENTED, NULL);
}

static void setup_management_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "AddNode", 0, add_node_call, "", "ay",
								"", "uuid");
	l_dbus_interface_method(iface, "DeleteRemodeNode", 0, delete_node_call,
					"", "qy", "", "primary", "count");
	l_dbus_interface_method(iface, "UnprovisionedScan", 0, start_scan_call,
							"", "q", "", "seconds");
	l_dbus_interface_method(iface, "UnprovisionedScanCancel", 0,
						cancel_scan_call, "", "");
	l_dbus_interface_method(iface, "CreateSubnet", 0, create_subnet_call,
						"", "q", "", "net_index");
	l_dbus_interface_method(iface, "UpdateSubnet", 0, update_subnet_call,
						"", "q", "", "net_index");
	l_dbus_interface_method(iface, "DeleteSubnet", 0, delete_subnet_call,
						"", "q", "", "net_index");
	l_dbus_interface_method(iface, "ImportSubnet", 0, import_subnet_call,
					"", "qay", "", "net_index", "net_key");
	l_dbus_interface_method(iface, "CreateAppKey", 0, create_appkey_call,
					"", "qq", "", "net_index", "app_index");
	l_dbus_interface_method(iface, "UpdateAppKey", 0, update_appkey_call,
					"", "qq", "", "net_index", "app_index");
	l_dbus_interface_method(iface, "DeleteAppKey", 0, delete_appkey_call,
					"", "qq", "", "net_index", "app_index");
	l_dbus_interface_method(iface, "ImportAppKey", 0, import_appkey_call,
				"", "qqay", "", "net_index", "app_index",
								"app_key");
	l_dbus_interface_method(iface, "SetKeyPhase", 0, set_key_phase_call,
					"", "qy", "", "net_index", "phase");
}

bool manager_dbus_init(struct l_dbus *bus)
{
	if (!l_dbus_register_interface(bus, MESH_MANAGEMENT_INTERFACE,
						setup_management_interface,
						NULL, false)) {
		l_info("Unable to register %s interface",
						MESH_MANAGEMENT_INTERFACE);
		return false;
	}

	return true;
}
