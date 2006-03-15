/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "list.h"
#include "glib-ectomy.h"
#include "dbus.h"

static int rfcomm_ctl = -1;

struct rfcomm_node {
	int16_t		id;		/* Device id */
	char		name[16];       /* Node filename */

	/* The following members are only valid for connected nodes */
	GIOChannel	*io;		/* IO Channel for the connection */
	char		*owner;		/* D-Bus name that created the node */
	int		canceled;	/* User canceled the connection */
};

static struct slist *bound_nodes = NULL;

static char *rfcomm_node_name_from_id(int16_t id, char *dev, size_t len)
{
    snprintf(dev, len, "/dev/rfcomm%d", id);
    return dev;
}

static struct rfcomm_node *find_node_by_name(struct slist *nodes, const char *name)
{
	struct slist *l;

	for (l = nodes; l != NULL; l = l->next) {
		struct rfcomm_node *node = l->data;
		if (!strcmp(node->name, name))
			return node;
	}

	return NULL;
}

static int rfcomm_release(struct rfcomm_node *node, int *err)
{
	struct rfcomm_dev_req req;

	debug("rfcomm_release(%s)", node->name);

	memset(&req, 0, sizeof(req));
	req.dev_id = node->id;

	if (ioctl(rfcomm_ctl, RFCOMMRELEASEDEV, &req) < 0) {
		if (err)
			*err = errno;
		error("Can't release device %d: %s (%d)", node->id,
				strerror(errno), errno);
		return -1;
	}

	bound_nodes = slist_remove(bound_nodes, node);

	free(node);

	return 0;
}

static struct rfcomm_node *rfcomm_bind(bdaddr_t *src, const char *bda, uint8_t ch, int *err)
{
	struct rfcomm_dev_req req;
	struct rfcomm_node *node;

	debug("rfcomm_bind(%s, %d)", bda, ch);

	memset(&req, 0, sizeof(req));
	req.dev_id = -1;
	req.flags = 0;
	bacpy(&req.src, src);

	str2ba(bda, &req.dst);
	req.channel = ch;

	node = malloc(sizeof(struct rfcomm_node));
	if (!node) {
		if (err)
			*err = ENOMEM;
		return NULL;
	}

	memset(node, 0, sizeof(struct rfcomm_node));

	node->id = ioctl(rfcomm_ctl, RFCOMMCREATEDEV, &req);
	if (node->id < 0) {
		if (err)
			*err = errno;
		error("RFCOMMCREATEDEV failed: %s (%d)", strerror(errno), errno);
		return NULL;
	}

	rfcomm_node_name_from_id(node->id, node->name, sizeof(node->name));
	bound_nodes = slist_append(bound_nodes, node);

	return node;
}


static DBusHandlerResult rfcomm_connect_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_cancel_connect_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_connect_by_ch_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_cancel_connect_by_ch_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_disconnect_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_bind_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult rfcomm_bind_by_ch_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	bdaddr_t bdaddr;
	DBusMessage *reply = NULL;
	uint8_t ch;
	int err;
	const char *dst, *name;
	struct hci_dbus_data *dbus_data = data;
	struct rfcomm_node *node = NULL;

	hci_devba(dbus_data->dev_id, &bdaddr);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &dst,
				DBUS_TYPE_BYTE, &ch,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);


	node = rfcomm_bind(&bdaddr, dst, ch, &err);
	if (!node)
		return error_failed(conn, msg, err);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto need_memory;

	name = node->name;
	if (!dbus_message_append_args(reply, DBUS_TYPE_STRING, &name,
					DBUS_TYPE_INVALID))
		goto need_memory;

	return send_reply_and_unref(conn, reply);

need_memory:
	if (reply)
		dbus_message_unref(reply);
	if (node)
		rfcomm_release(node, NULL);
	return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult rfcomm_release_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *name;
	struct rfcomm_node *node;
	int err;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	node = find_node_by_name(bound_nodes, name);
	if (!node)
		return error_binding_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (rfcomm_release(node, &err) < 0) {
		dbus_message_unref(reply);
		return error_failed(conn, msg, err);
	}

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult rfcomm_list_bindings_req(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	bdaddr_t bdaddr;
	DBusMessage *reply;
	DBusMessageIter iter, sub;
	struct hci_dbus_data *dbus_data = data;
	struct slist *l;

	hci_devba(dbus_data->dev_id, &bdaddr);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	if (!dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &sub)) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	for (l = bound_nodes; l != NULL; l = l->next) {
		struct rfcomm_node *node = l->data;
		struct rfcomm_dev_info di = { id: node->id };
		char *name = node->name;

		if (ioctl(rfcomm_ctl, RFCOMMGETDEVINFO, &di) < 0) {
			error("RFCOMMGETDEVINFO(%d): %s (%d)",
					node->id, strerror(errno), errno);
			continue;
		}

		/* Ignore nodes not specific to this adapter */
		if (bacmp(&di.src, &bdaddr))
			continue;

		dbus_message_iter_append_basic(&sub, DBUS_TYPE_STRING, &name);
	}

	if (!dbus_message_iter_close_container(&iter, &sub)) {
		dbus_message_unref(reply);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	return send_reply_and_unref(conn, reply);
}

static struct service_data rfcomm_services[] = {
	{ "Connect",			rfcomm_connect_req,			},
	{ "CancelConnect",		rfcomm_cancel_connect_req,		},
	{ "ConnectByChannel",		rfcomm_connect_by_ch_req,		},
	{ "CancelConnectByChannel",	rfcomm_cancel_connect_by_ch_req,	},
	{ "Disconnect",			rfcomm_disconnect_req,			},
	{ "Bind",			rfcomm_bind_req,			},
	{ "BindByChannel",		rfcomm_bind_by_ch_req,			},
	{ "Release",			rfcomm_release_req,			},
	{ "ListBindings",		rfcomm_list_bindings_req,		},
	{ NULL,				NULL,					}
};

DBusHandlerResult handle_rfcomm_method(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	service_handler_func_t handler;

	if (!data) {
		error("RFCOMM method called with NULL data pointer!");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	/* Initialize the RFCOMM control socket if has not yet been done */
	if (rfcomm_ctl < 0) {
		rfcomm_ctl = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_RFCOMM);
		if (rfcomm_ctl < 0)
			return error_failed(conn, msg, errno);
	}

	handler = find_service_handler(rfcomm_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
