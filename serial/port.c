/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glib.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"

#include "error.h"
#include "manager.h"
#include "port.h"

#define SERIAL_PORT_INTERFACE	"org.bluez.serial.Port"

struct rfcomm_node {
	int16_t		id;	/* RFCOMM device id */
	bdaddr_t	dst;	/* Destination address */
	char		*name;	/* RFCOMM device name */
	DBusConnection	*conn;	/* for name listener handling */
	char		*owner; /* Bus name */
	GIOChannel	*io;	/* Connected node IO Channel */
	guint		io_id;	/* IO Channel ID */
};

static GSList *connected_nodes = NULL;
static GSList *bound_nodes = NULL;

static struct rfcomm_node *find_node_by_name(GSList *nodes, const char *name)
{
	GSList *l;

	for (l = nodes; l != NULL; l = l->next) {
		struct rfcomm_node *node = l->data;
		if (!strcmp(node->name, name))
			return node;
	}

	return NULL;
}

static DBusHandlerResult port_get_address(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct rfcomm_node *node = data;
	DBusMessage *reply;
	char bda[18];
	const char *pbda = bda;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	ba2str(&node->dst, bda);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pbda,
			DBUS_TYPE_INVALID);
	return send_message_and_unref(conn, reply);

}

static DBusHandlerResult port_get_info(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct rfcomm_node *node = data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	char bda[18];
	const char *pbda = bda;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dbus_message_iter_append_dict_entry(&dict, "name",
			DBUS_TYPE_STRING, &node->name);

	ba2str(&node->dst, bda);
	dbus_message_iter_append_dict_entry(&dict, "address",
			DBUS_TYPE_STRING, &pbda);

	dbus_message_iter_append_dict_entry(&dict, "dev_id",
			DBUS_TYPE_INT16, &node->id);

	dbus_message_iter_close_container(&iter, &dict);

	return send_message_and_unref(conn, reply);
}

static DBusMethodVTable port_methods[] = {
	{ "GetAddress",	port_get_address,	"",	"s"	},
	{ "GetInfo",	port_get_info,		"",	"{sv}"	},
	{ NULL, NULL, NULL, NULL },
};

static DBusSignalVTable port_signals[] = {
	{ NULL, NULL }
};

static void rfcomm_node_free(struct rfcomm_node *node)
{
	if (node->name)
		g_free(node->name);
	if (node->conn)
		dbus_connection_unref(node->conn);
	if (node->owner)
		g_free(node->owner);
	rfcomm_release(node->id);
	if (node->io) {
		g_source_remove(node->io_id);
		g_io_channel_unref(node->io);
	}
	g_free(node);
}

static void connection_owner_exited(const char *name, struct rfcomm_node *node)
{
	debug("Connect requestor %s exited. Releasing %s node",
						name, node->name);

	dbus_connection_emit_signal(node->conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceDisconnected" ,
			DBUS_TYPE_STRING, &node->name,
			DBUS_TYPE_INVALID);

	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);
}

static gboolean rfcomm_disconnect_cb(GIOChannel *io,
		GIOCondition cond, struct rfcomm_node *node)
{
	debug("RFCOMM node %s was disconnected", node->name);

	if (cond & (G_IO_ERR | G_IO_HUP))
		g_io_channel_close(io);

	name_listener_remove(node->conn, node->owner,
			(name_cb_t) connection_owner_exited, node);

	dbus_connection_emit_signal(node->conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceDisconnected" ,
			DBUS_TYPE_STRING, &node->name,
			DBUS_TYPE_INVALID);

	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);

	return FALSE;
}

static void port_handler_unregister(DBusConnection *conn, void *data)
{
	struct rfcomm_node *node = data;

	debug("Unregistered serial port: %s", node->name);

	bound_nodes = g_slist_remove(bound_nodes, node);
	rfcomm_node_free(node);
}

int port_add_listener(DBusConnection *conn, int id, bdaddr_t *dst,
			int fd, const char *name, const char *owner)
{
	struct rfcomm_node *node;

	node = g_new0(struct rfcomm_node, 1);
	bacpy(&node->dst, dst);
	node->id	= id;
	node->name	= g_strdup(name);
	node->conn	= dbus_connection_ref(conn);
	node->owner	= g_strdup(owner);
	node->io 	= g_io_channel_unix_new(fd);
	node->io_id = g_io_add_watch(node->io, G_IO_ERR | G_IO_NVAL | G_IO_HUP,
					(GIOFunc) rfcomm_disconnect_cb, node);

	connected_nodes = g_slist_append(connected_nodes, node);

	/* Service connection listener */
	return name_listener_add(conn, owner,
			(name_cb_t) connection_owner_exited, node);
}

int port_remove_listener(const char *owner, const char *name)
{
	struct rfcomm_node *node;

	node = find_node_by_name(connected_nodes, name);
	if (!node)
		return -ENOENT;
	if (strcmp(node->owner, owner) != 0)
		return -EPERM;

	name_listener_remove(node->conn, owner,
			(name_cb_t) connection_owner_exited, node);

	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);

	return 0;
}

int port_register(DBusConnection *conn, int id, bdaddr_t *dst,
					const char *name, char *ppath)
{
	char path[MAX_PATH_LENGTH];
	struct rfcomm_node *node;

	node = g_new0(struct rfcomm_node, 1);
	bacpy(&node->dst, dst);
	node->id	= id;
	node->name	= g_strdup(name);
	node->conn	= dbus_connection_ref(conn);

	snprintf(path, MAX_PATH_LENGTH, "%s/rfcomm%d", SERIAL_MANAGER_PATH, id);

	if (!dbus_connection_create_object_path(conn, path, node,
						port_handler_unregister)) {
		error("D-Bus failed to register %s path", path);
		rfcomm_node_free(node);
		return -1;
	}

	if (!dbus_connection_register_interface(conn, path,
				SERIAL_PORT_INTERFACE,
				port_methods,
				port_signals, NULL)) {
		error("D-Bus failed to register %s interface",
				SERIAL_PORT_INTERFACE);
		dbus_connection_destroy_object_path(conn, path);
		return -1;
	}

	info("Registered RFCOMM:%s, path:%s", name, path);

	if (ppath)
		strcpy(ppath, path);

	bound_nodes = g_slist_append(bound_nodes, node);

	return 0;
}

int port_unregister(const char *path)
{
	struct rfcomm_node *node;
	char name[16];
	int id;

	if (sscanf(path, SERIAL_MANAGER_PATH"/rfcomm%d", &id) != 1)
		return -ENOENT;

	snprintf(name, sizeof(name), "/dev/rfcomm%d", id);
	node = find_node_by_name(bound_nodes, name);
	if (!node)
		return -ENOENT;

	dbus_connection_destroy_object_path(node->conn, path);

	return 0;
}
