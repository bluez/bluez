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

#include <stdlib.h>
#include <errno.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include "logging.h"
#include "dbus.h"
#include "error.h"

#define NETWORK_SERVER_INTERFACE "org.bluez.network.Server"

#include "common.h"
#include "server.h"

struct network_server {
	char		*iface;		/* Routing interface */
	char		*name;		/* Server service name */
	char		*path; 		/* D-Bus path */
	dbus_bool_t	secure;
	uint32_t	record_id;	/* Service record id */
	uint16_t	id;		/* Service class identifier */
};

static int create_server_record(sdp_buf_t *buf, uint16_t id)
{
	/* FIXME: service name must be configurable */

	/* FIXME: Create the service record */

	return -1;
}

static uint32_t add_server_record(DBusConnection *conn, uint16_t id)
{
	DBusMessage *msg, *reply;
	DBusError derr;
	dbus_uint32_t rec_id;
	sdp_buf_t buf;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
				"org.bluez.Database", "AddServiceRecord");
	if (!msg) {
		error("Can't allocate new method call");
		return 0;
	}

	if (create_server_record(&buf, id) < 0) {
		error("Unable to allocate new service record");
		dbus_message_unref(msg);
		return 0;
	}

	dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE,
				&buf.data, buf.data_size, DBUS_TYPE_INVALID);

	dbus_error_init(&derr);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &derr);

	free(buf.data);
	dbus_message_unref(msg);

	if (dbus_error_is_set(&derr) || dbus_set_error_from_message(&derr, reply)) {
		error("Adding service record failed: %s", derr.message);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_get_args(reply, &derr, DBUS_TYPE_UINT32, &rec_id,
				DBUS_TYPE_INVALID);

	if (dbus_error_is_set(&derr)) {
		error("Invalid arguments to AddServiceRecord reply: %s", derr.message);
		dbus_message_unref(reply);
		dbus_error_free(&derr);
		return 0;
	}

	dbus_message_unref(reply);

	debug("add_server_record: got record id 0x%x", rec_id);

	return rec_id;
}

static DBusHandlerResult get_uuid(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	const char *uuid;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	uuid = bnep_uuid(ns->id);
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &uuid,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult enable(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* Add the service record */
	ns->record_id = add_server_record(conn, ns->id);
	if (!ns->record_id) {
		error("Unable to register the server(0x%x) service record", ns->id);
		return err_failed(conn, msg, "Unable to register the service record");
	}

	/* FIXME: Check security */

	/* FIXME: Start listen */

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult disable(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult set_name(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	DBusError derr;
	const char *name;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (!name || (strlen(name) == 0))
		return err_invalid_args(conn, msg, "Invalid name");

	if (ns->name)
		g_free(ns->name);
	ns->name = g_strdup(name);

	/* FIXME: Update the service record attribute */

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_name(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	char name[] = "";
	const char *pname = (ns->name ? ns->name : name);
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &pname,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult set_address_range(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult set_routing(DBusConnection *conn, DBusMessage *msg,
					void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	DBusError derr;
	const char *iface;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &iface,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	/* FIXME: Check if the interface is valid/UP */
	if (!iface || (strlen(iface) == 0))
		return err_invalid_args(conn, msg, "Invalid interface");

	if (ns->iface)
		g_free(ns->iface);
	ns->iface = g_strdup(iface);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult set_security(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;
	DBusError derr;
	dbus_bool_t secure;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
				DBUS_TYPE_BOOLEAN, &secure,
				DBUS_TYPE_INVALID)) {
		err_invalid_args(conn, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	ns->secure = secure;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_security(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct network_server *ns = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_BOOLEAN, &ns->secure,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult server_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *iface, *member;

	iface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (strcmp(NETWORK_SERVER_INTERFACE, iface))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "GetUUID") == 0)
		return get_uuid(conn, msg, data);

	if (strcmp(member, "Enable") == 0)
		return enable(conn, msg, data);

	if (strcmp(member, "Disable") == 0)
		return disable(conn, msg, data);

	if (strcmp(member, "SetName") == 0)
		return set_name(conn, msg, data);

	if (strcmp(member, "GetName") == 0)
		return get_name(conn, msg, data);

	if (strcmp(member, "SetAddressRange") == 0)
		return set_address_range(conn, msg, data);

	if (strcmp(member, "SetRouting") == 0)
		return set_routing(conn, msg, data);

	if (strcmp(member, "SetSecurity") == 0)
		return set_security(conn, msg, data);

	if (strcmp(member, "GetSecurity") == 0)
		return get_security(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void server_free(struct network_server *ns)
{
	if (!ns)
		return;

	if (ns->iface)
		g_free(ns->iface);

	if (ns->name)
		g_free(ns->name);

	if (ns->path)
		g_free(ns->path);

	g_free(ns);
}

static void server_unregister(DBusConnection *conn, void *data)
{
	struct network_server *ns = data;

	info("Unregistered server path:%s", ns->path);

	server_free(ns);
}

/* Virtual table to handle server object path hierarchy */
static const DBusObjectPathVTable server_table = {
	.message_function = server_message,
	.unregister_function = server_unregister,
};

int server_register(DBusConnection *conn, const char *path, uint16_t id)
{
	struct network_server *ns;

	if (!conn)
		return -EINVAL;

	if (!path)
		return -EINVAL;

	ns = g_new0(struct network_server, 1);

	/* Register path */
	if (!dbus_connection_register_object_path(conn, path,
						&server_table, ns)) {
		error("D-Bus failed to register %s path", path);
		goto fail;
	}

	ns->path = g_strdup(path);
	ns->id = id;
	info("Registered server path:%s", ns->path);

	return 0;
fail:
	server_free(ns);
	return -1;
}
