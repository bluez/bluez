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
#include <unistd.h>
#include <stdlib.h>


#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"
#include "list.h"

struct service_call {
	DBusConnection *conn;
	DBusMessage *msg;
};

struct service_agent {
	char *id;	/* Connection id */
	char *name;
	char *description;
};

static struct slist *services;

static void service_call_free(void *data)
{
	struct service_call *call = data;
	if (call) {
		if (call->conn)
			dbus_connection_unref(call->conn);
		if(call->msg)
			dbus_message_unref(call->msg);
	}
}

static int service_agent_cmp(const struct service_agent *a, const struct service_agent *b)
{
	int ret;

	if (b->id) {
		if (!a->id)
			return -1;
		ret = strcmp(a->id, b->id);
		if (ret)
			return ret;
	}

	if (b->name) {
		if (!a->name)
			return -1;
		ret = strcmp(a->name, b->name);
		if (ret)
			return ret;
	}

	if (b->description) {
		if (!a->description)
			return -1;
		ret = strcmp(a->description, b->description);
		if (ret)
			return ret;
	}

	return 0;
}

static void service_agent_free(struct service_agent *agent)
{
	if (!agent)
		return;

	if (agent->id)
		free(agent->id);

	if (agent->name)
		free(agent->name);

	if (agent->description)
		free(agent->description);
	free(agent);
}

static struct service_agent *service_agent_new(const char *id, const char *name, const char *description)
{
	struct service_agent *agent = malloc(sizeof(struct service_agent));

	if (!agent)
		return NULL;

	memset(agent, 0, sizeof(struct service_agent));

	if (id) {	
		agent->id = strdup(id);
		if (!agent->id)
			goto mem_fail;
	}

	if (name) {
		agent->name = strdup(name);
		if (!agent->name)
			goto mem_fail;
	}

	if (description) {
		agent->description = strdup(description);
		if (!agent->description)
			goto mem_fail;
	}

	return agent;

mem_fail:
	service_agent_free(agent);
	return NULL;
}

static void service_agent_exit(const char *name, void *data)
{

	debug("Service Agent exited:%s", name);
	/* FIXME: free the dbus path data and unregister the path */
}

static void forward_reply(DBusPendingCall *call, void *udata)
{
	struct service_call *call_data = udata;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *source_reply;
	const char *sender;

	sender = dbus_message_get_sender(call_data->msg);

	source_reply = dbus_message_copy(reply);
	dbus_message_set_destination(source_reply, sender);
	dbus_message_set_no_reply(source_reply, TRUE);
	dbus_message_set_reply_serial(source_reply, dbus_message_get_serial(call_data->msg));

	/* FIXME: Handle send error */
	dbus_connection_send(call_data->conn, source_reply, NULL);

	dbus_message_unref(reply);
	dbus_message_unref(source_reply);
	dbus_pending_call_unref (call);
}

static DBusHandlerResult get_interface_names(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult get_connection_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct service_agent *agent;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	agent = (struct service_agent*) data;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &agent->id,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_name(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct service_agent *agent;
	const char *name = "";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	agent = (struct service_agent*) data;

	if (agent->name)
		name = agent->name;
	
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_description(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct service_agent *agent;
	const char *description = "";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	agent = (struct service_agent*) data;

	if (agent->description)
		description = agent->description;
	
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &description,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult start(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult stop(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult is_running(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult list_users(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


static DBusHandlerResult remove_user(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult set_trusted(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult is_trusted(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult remove_trust(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static struct service_data services_methods[] = {
	{ "GetInterfaceNames",	get_interface_names	},
	{ "GetConnectionName",	get_connection_name	},
	{ "GetName",		get_name		},
	{ "GetDescription",	get_description		},
	{ "Start",		start			},
	{ "Stop",		stop			},
	{ "IsRunning",		is_running		},
	{ "ListUsers",		list_users		},
	{ "RemoveUser",		remove_user		},
	{ "SetTrusted",		set_trusted		},
	{ "IsTrusted",		is_trusted		},
	{ "RemoveTrust",	remove_trust		},
	{ NULL, NULL }
};


static DBusHandlerResult msg_func_services(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	service_handler_func_t handler;
	const char *iface, *path, *sender;
	struct service_agent *agent;
	DBusPendingCall *pending;
	DBusMessage *forward;
	struct service_call *call_data;

	iface = dbus_message_get_interface(msg);
	path = dbus_message_get_path(msg);
	sender = dbus_message_get_sender(msg);

	handler = find_service_handler(services_methods, msg);
	if (handler)
		return handler(conn, msg, data);

	/* Forward to the real service object */
	if (!dbus_connection_get_object_path_data(conn, path, (void *) &agent))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	forward = dbus_message_copy(msg);
	dbus_message_set_destination(forward, agent->id);
	dbus_message_set_path(forward, path);

	call_data = malloc(sizeof(struct service_call));
	call_data->conn = dbus_connection_ref(conn);
	call_data->msg = dbus_message_ref(msg);

	if (dbus_connection_send_with_reply(conn, forward, &pending, -1) == FALSE) {
		/* FIXME: How handle this? */
		error("Can't foward the message.");
		dbus_message_unref(forward);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_pending_call_set_notify(pending, forward_reply, call_data, service_call_free);
	dbus_message_unref(forward);
	return DBUS_HANDLER_RESULT_HANDLED;
}

static const DBusObjectPathVTable services_vtable = {
	.message_function	= &msg_func_services,
	.unregister_function	= NULL
};

int register_service_agent(DBusConnection *conn, const char *sender ,const char *path)
{
	struct service_agent *agent;

	debug("Registering service object: %s", path);
	
	/* FIXME: the manager fallback '/org/bluez' should not return no such adapter */

	/* Check if the name is already used? */
	agent = service_agent_new(sender, NULL, NULL);
	if (!agent)
		return -ENOMEM;

	if (!dbus_connection_register_object_path(conn, path, &services_vtable, agent))
		return -1;

	services = slist_append(services, strdup(path));

	/* FIXME: only one listener per sender */
	name_listener_add(conn, sender, (name_cb_t) service_agent_exit, NULL);

	return 0;
}

int unregister_service_agent(DBusConnection *conn, const char *sender, const char *path)
{
	struct service_agent *agent;
	struct slist *l;

	debug("Unregistering service object: %s", path);
	
	if (!dbus_connection_get_object_path_data(conn, path, (void *) &agent))
		return -1;

	service_agent_free(agent);

	if (!dbus_connection_unregister_object_path (conn, path))
		return -1;

	l = slist_find(services, path, strcmp);
	if (l)
		services = slist_remove(services, l->data);

	return 0;
}

void append_available_services(DBusMessageIter *iter)
{
	struct slist *l = services;
	const char *path;
	while (l) {
		path = l->data;
		dbus_message_iter_append_basic(iter,
				DBUS_TYPE_STRING, &path);
		l = l->next;
	}
}
