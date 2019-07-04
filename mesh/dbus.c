/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2018-2019 Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#include "mesh/mesh-defs.h"
#include "mesh/node.h"
#include "mesh/manager.h"
#include "mesh/mesh.h"
#include "mesh/error.h"
#include "mesh/dbus.h"

static struct l_dbus *dbus;

struct error_entry {
	const char *dbus_err;
	const char *default_desc;
};

/*
 * Important: The entries in this table follow the order of
 * enumerated values in mesh_error (file error.h)
 */
static struct error_entry const error_table[] =
{
	{ NULL, NULL },
	{ ERROR_INTERFACE ".Failed", "Operation failed" },
	{ ERROR_INTERFACE ".NotAuthorized", "Permission denied"},
	{ ERROR_INTERFACE ".NotFound", "Object not found"},
	{ ERROR_INTERFACE ".InvalidArgs", "Invalid arguments"},
	{ ERROR_INTERFACE ".InProgress", "Already in progress"},
	{ ERROR_INTERFACE ".AlreadyExists", "Already exists"},
	{ ERROR_INTERFACE ".DoesNotExist", "Does not exist"},
	{ ERROR_INTERFACE ".Canceled", "Operation canceled"},
	{ ERROR_INTERFACE ".NotImplemented", "Not implemented"},
};

struct l_dbus_message *dbus_error(struct l_dbus_message *msg, int err,
							const char *description)
{
	int array_len = L_ARRAY_SIZE(error_table);

	/* Default to ".Failed" */
	if (!err || err >= array_len)
		err = MESH_ERROR_FAILED;

	if (description)
		return l_dbus_message_new_error(msg,
				error_table[err].dbus_err,
				"%s", description);
	else
		return l_dbus_message_new_error(msg,
				error_table[err].dbus_err,
				"%s", error_table[err].default_desc);
}

struct l_dbus *dbus_get_bus(void)
{
	return dbus;
}

bool dbus_init(struct l_dbus *bus)
{
	/* Network interface */
	if (!mesh_dbus_init(bus))
		return false;

	/* Node interface */
	if (!node_dbus_init(bus))
		return false;

	/* Management interface */
	if (!manager_dbus_init(bus))
		return false;

	dbus = bus;

	return true;
}

bool dbus_match_interface(struct l_dbus_message_iter *interfaces,
							const char *match)
{
	const char *interface;
	struct l_dbus_message_iter properties;

	while (l_dbus_message_iter_next_entry(interfaces, &interface,
								&properties)) {
		if (!strcmp(match, interface))
			return true;
	}

	return false;
}

void dbus_append_byte_array(struct l_dbus_message_builder *builder,
						const uint8_t *data, int len)
{
	int i;

	if (!builder)
		return;

	l_dbus_message_builder_enter_array(builder, "y");

	for (i = 0; i < len; i++)
		l_dbus_message_builder_append_basic(builder, 'y', data + i);

	l_dbus_message_builder_leave_array(builder);
}

void dbus_append_dict_entry_basic(struct l_dbus_message_builder *builder,
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
