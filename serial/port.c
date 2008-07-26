/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>

#include <glib.h>
#include <gdbus.h>

#include "../hcid/dbus-common.h"

#include "logging.h"

#include "error.h"
#include "manager.h"
#include "storage.h"

#define SERIAL_PORT_INTERFACE	"org.bluez.serial.Port"

struct rfcomm_node {
	int16_t		id;		/* RFCOMM device id */
	bdaddr_t	src;		/* Source (local) address */
	bdaddr_t	dst;		/* Destination address */
	char		*svcname;	/* RFCOMM service name */
	char		*device;	/* RFCOMM device name */
	DBusConnection	*conn;		/* for name listener handling */
	char		*owner;		/* Bus name */
	GIOChannel	*io;		/* Connected node IO Channel */
	guint		io_id;		/* IO Channel ID */
	guint		listener_id;
};

static GSList *connected_nodes = NULL;
static GSList *bound_nodes = NULL;

static struct rfcomm_node *find_node_by_name(GSList *nodes, const char *dev)
{
	GSList *l;

	for (l = nodes; l != NULL; l = l->next) {
		struct rfcomm_node *node = l->data;
		if (!strcmp(node->device, dev))
			return node;
	}

	return NULL;
}

static DBusMessage *port_get_address(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct rfcomm_node *node = data;
	DBusMessage *reply;
	char bda[18];
	const char *pbda = bda;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	ba2str(&node->dst, bda);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pbda,
			DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *port_get_device(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct rfcomm_node *node = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &node->device,
			DBUS_TYPE_INVALID);

	return reply;

}

static DBusMessage *port_get_adapter(DBusConnection *conn,
				  DBusMessage *msg, void *data)
{
	struct rfcomm_node *node = data;
	DBusMessage *reply;
	char addr[18];
	const char *paddr = addr;

	ba2str(&node->src, addr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_INVALID);

	return reply;
}


static DBusMessage *port_get_name(DBusConnection *conn,
			       DBusMessage *msg, void *data)
{
	struct rfcomm_node *node = data;
	DBusMessage *reply;
	const char *pname;
	char *name = NULL;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	read_device_name(&node->src, &node->dst, &name);

	pname = (name ? name : "");
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pname,
			DBUS_TYPE_INVALID);

	if (name)
		g_free(name);

	return reply;
}

static DBusMessage *port_get_service_name(DBusConnection *conn,
				       DBusMessage *msg, void *data)
{
	struct rfcomm_node *node = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &node->svcname,
			DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *port_get_info(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct rfcomm_node *node = data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;
	char bda[18];
	const char *pbda = bda;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dbus_message_iter_append_dict_entry(&dict, "device",
			DBUS_TYPE_STRING, &node->device);

	ba2str(&node->dst, bda);
	dbus_message_iter_append_dict_entry(&dict, "address",
			DBUS_TYPE_STRING, &pbda);

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static GDBusMethodTable port_methods[] = {
	{ "GetAddress",		"",	"s",	port_get_address },
	{ "GetDevice",		"",	"s",	port_get_device },
	{ "GetAdapter",		"",	"s",	port_get_adapter },
	{ "GetName",		"",	"s",	port_get_name },
	{ "GetServiceName",	"",	"s",	port_get_service_name },
	{ "GetInfo",		"",	"a{sv}",port_get_info },
	{ NULL, NULL, NULL, NULL },
};

static GDBusSignalTable port_signals[] = {
	{ NULL, NULL }
};

static void rfcomm_node_free(struct rfcomm_node *node)
{
	if (node->device)
		g_free(node->device);
	if (node->conn)
		dbus_connection_unref(node->conn);
	if (node->owner)
		g_free(node->owner);
	if (node->svcname)
		g_free(node->svcname);
	if (node->io) {
		g_source_remove(node->io_id);
		g_io_channel_close(node->io);
		g_io_channel_unref(node->io);
	}
	rfcomm_release(node->id);
	g_free(node);
}

static void connection_owner_exited(void *user_data)
{
	struct rfcomm_node *node = user_data;

	debug("Connect requestor exited. Releasing %s node",
						node->device);

	g_dbus_emit_signal(node->conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceDisconnected" ,
			DBUS_TYPE_STRING, &node->device,
			DBUS_TYPE_INVALID);

	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);
}

static gboolean rfcomm_disconnect_cb(GIOChannel *io,
		GIOCondition cond, struct rfcomm_node *node)
{
	debug("RFCOMM node %s was disconnected", node->device);

	g_dbus_remove_watch(node->conn, node->listener_id);

	g_dbus_emit_signal(node->conn, SERIAL_MANAGER_PATH,
			SERIAL_MANAGER_INTERFACE, "ServiceDisconnected" ,
			DBUS_TYPE_STRING, &node->device,
			DBUS_TYPE_INVALID);

	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);

	return FALSE;
}

static void port_handler_unregister(void *data)
{
	struct rfcomm_node *node = data;

	debug("Unregistered serial port: %s", node->device);

	bound_nodes = g_slist_remove(bound_nodes, node);
	rfcomm_node_free(node);
}

void port_add_listener(DBusConnection *conn, int16_t id, bdaddr_t *dst,
			int fd, const char *dev, const char *owner)
{
	struct rfcomm_node *node;

	node = g_new0(struct rfcomm_node, 1);
	bacpy(&node->dst, dst);
	node->id	= id;
	node->device	= g_strdup(dev);
	node->conn	= dbus_connection_ref(conn);
	node->owner	= g_strdup(owner);
	node->io	= g_io_channel_unix_new(fd);
	node->io_id = g_io_add_watch(node->io, G_IO_ERR | G_IO_NVAL | G_IO_HUP,
					(GIOFunc) rfcomm_disconnect_cb, node);

	connected_nodes = g_slist_append(connected_nodes, node);

	/* Service connection listener */
	node->listener_id = g_dbus_add_disconnect_watch(conn, owner,
						connection_owner_exited, node,
						NULL);
}

int port_remove_listener(const char *owner, const char *dev)
{
	struct rfcomm_node *node;

	node = find_node_by_name(connected_nodes, dev);
	if (!node)
		return -ENOENT;
	if (strcmp(node->owner, owner) != 0)
		return -EPERM;

	g_dbus_remove_watch(node->conn, node->listener_id);

	connected_nodes = g_slist_remove(connected_nodes, node);
	rfcomm_node_free(node);

	return 0;
}

void port_release_all(void)
{
	struct rfcomm_node *node;
	GSList *l;

	for (l = connected_nodes; l; l = l->next) {
		node = l->data;

		connected_nodes = g_slist_remove(connected_nodes, node);
		rfcomm_node_free(node);
	}
}

int port_register(DBusConnection *conn, int16_t id, bdaddr_t *src,
		  bdaddr_t *dst, const char *dev, char *ppath, const char *svc)
{
	char path[MAX_PATH_LENGTH];
	struct rfcomm_node *node;

	node = g_new0(struct rfcomm_node, 1);
	bacpy(&node->dst, dst);
	bacpy(&node->src, src);
	node->id	= id;
	node->device	= g_strdup(dev);
	node->conn	= dbus_connection_ref(conn);
	node->svcname	= g_strdup(svc?:"Bluetooth RFCOMM port");

	snprintf(path, MAX_PATH_LENGTH, "%s/rfcomm%hd", SERIAL_MANAGER_PATH, id);


	if (!g_dbus_register_interface(conn, path,
				SERIAL_PORT_INTERFACE,
				port_methods, port_signals, NULL,
				node, port_handler_unregister)) {
		error("D-Bus failed to register %s interface",
				SERIAL_PORT_INTERFACE);
		rfcomm_node_free(node);
		return -1;
	}

	info("Registered RFCOMM:%s, path:%s", dev, path);

	if (ppath)
		strcpy(ppath, path);

	bound_nodes = g_slist_append(bound_nodes, node);

	return 0;
}

int port_unregister(const char *path)
{
	struct rfcomm_node *node;
	char dev[16];
	int16_t id;

	if (sscanf(path, SERIAL_MANAGER_PATH"/rfcomm%hd", &id) != 1)
		return -ENOENT;

	snprintf(dev, sizeof(dev), "/dev/rfcomm%hd", id);
	node = find_node_by_name(bound_nodes, dev);
	if (!node)
		return -ENOENT;

	g_dbus_unregister_interface(node->conn, path, SERIAL_PORT_INTERFACE);

	return 0;
}
