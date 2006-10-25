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

void service_call_free(void *data)
{
	struct service_call *call = data;
	if (call) {
		if (call->conn)
			dbus_connection_unref(call->conn);
		if(call->msg)
			dbus_message_unref(call->msg);
	}
}

struct service_agent {
	char *name;
	char *path;
};

static struct slist *services;

static int service_agent_cmp(const struct service_agent *a, const struct service_agent *b)
{
	int ret;

	if (b->name) {
		if (!a->name)
			return -1;
		ret = strcmp(a->name, b->name);
		if (ret)
			return ret;
	}

	if (b->path) {
		if (!a->path)
			return -1;
		return strcmp(a->path, b->path);
	}

	return 0;
}

static void service_agent_free(struct service_agent *agent)
{
	if (!agent)
		return;
	
	if (agent->name)
		free(agent->name);

	if (agent->path)
		free(agent->path);

	free(agent);
}

static struct service_agent *service_agent_new(const char *name, const char *path)
{
	struct service_agent *agent = malloc(sizeof(struct service_agent));

	if (!agent)
		return NULL;

	memset(agent, 0, sizeof(struct service_agent));
	if (name) {
		agent->name = strdup(name);
		if (!agent->name)
			goto mem_fail;
	}

	if (path) {	
		agent->path = strdup(path);
		if (!agent->path)
			goto mem_fail;
	}
	return agent;
mem_fail:
	service_agent_free(agent);
	return NULL;
}

static void service_agent_exit(const char *name, void *data)
{

	struct slist *l = services;
	struct service_agent *agent;

	debug("exited:%s", name);
#if 0	
	while (l) {
		agent = l->data;
		l = l->next;

		if (strcmp(agent->name, name))
			continue;

		debug("Unregistering service: %s", name);
		services = slist_remove(services, agent);
		service_agent_free(agent);
	}
#endif
	
}

static void forward_reply(DBusPendingCall *call, void *udata)
{
	struct service_call *call_data = udata;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *ret;
	DBusError err;
	const char *sender;

	dbus_error_init (&err);
	if (dbus_set_error_from_message (&err, reply)) {
		error("forward reply: %s, %s",
				err.name, err.message);
		/* FIXME: reply the error */
		goto done;
	}

	sender = dbus_message_get_sender(call_data->msg);

	ret = dbus_message_copy(reply);
	dbus_message_set_destination(ret, sender);
	dbus_message_set_no_reply(ret, TRUE);
	dbus_message_set_reply_serial(ret, dbus_message_get_serial(call_data->msg));
	dbus_connection_send(call_data->conn, ret, NULL);
done:
	dbus_message_unref(reply);
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
	struct slist *match;
	const char *path;

	/* Check if the name is already used? */
	path = dbus_message_get_path(msg);

	agent = service_agent_new(dbus_message_get_sender(msg), path);
	if (!agent)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* FIXME: There is at least one service agent, right?  */
	match = slist_find(services, agent, (cmp_func_t) service_agent_cmp);

	reply = dbus_message_new_method_return(msg);

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &agent->name,
			DBUS_TYPE_INVALID);

	service_agent_free(agent);

	return send_message_and_unref(conn, reply);
}


static DBusHandlerResult get_name(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct service_agent *agent;
	struct slist *match;
	DBusPendingCall *pending;
	DBusMessage *forward = dbus_message_copy(msg);
	struct service_call *call_data;

	agent = service_agent_new(NULL, dbus_message_get_path(msg));
	if (!agent)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	match = slist_find(services, agent, (cmp_func_t) service_agent_cmp);

	service_agent_free(agent);
	/* FIXME: There is at least one agent */

	/* Forward the msg */
	agent = match->data;
	dbus_message_set_destination(forward, agent->name);
	dbus_message_set_path(forward, agent->path);
	dbus_message_set_member(forward, "Name");
	dbus_message_set_interface(forward, "org.bluez.ServiceAgent");

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

static DBusHandlerResult get_description(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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
	//{ "GetDescription",	get_description		},
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


DBusHandlerResult msg_func_services(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	service_handler_func_t handler;
	const char *iface, *path, *sender;
	struct service_agent *agent;
	struct slist *match;

	iface = dbus_message_get_interface(msg);
	path = dbus_message_get_path(msg);
	sender = dbus_message_get_sender(msg);

	handler = find_service_handler(services_methods, msg);
	if (handler)
		return handler(conn, msg, data);

	/* Forward the message to the real service object */
	agent = service_agent_new(NULL, path);
	if (!agent)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	match = slist_find(services, agent, (cmp_func_t) service_agent_cmp);

	service_agent_free(agent);

	if (match) {
		/* Forward the msg */
		DBusPendingCall *pending;
		DBusMessage *forward = dbus_message_copy(msg);
		struct service_call *call_data;

		agent = match->data;
		dbus_message_set_destination(forward, agent->name);
		dbus_message_set_path(forward, agent->path);

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

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
static const DBusObjectPathVTable services_vtable = {
	.message_function	= &msg_func_services,
	.unregister_function	= NULL
};

int register_service_agent(DBusConnection *conn, const char *sender ,const char *path)
{
	struct service_agent *agent;
	struct slist *match;

	if (!dbus_connection_register_object_path(conn, path, &services_vtable, NULL)) 
		return -1;

	/* Check if the name is already used? */
	agent = service_agent_new(sender, path);
	if (!agent)
		return -ENOMEM;

	match = slist_find(services, agent, (cmp_func_t) service_agent_cmp);

	services = slist_append(services, agent);

	if (match) {
		service_agent_free(agent);
		return -EALREADY;
	}

	/* FIXME: only one listener per sender */
	name_listener_add(conn, sender, (name_cb_t) service_agent_exit, NULL);

	return 0;
}

int unregister_service_agent(DBusConnection *conn, const char *sender, const char *path)
{
	struct service_agent *agent;
	struct slist *match;

	agent = service_agent_new(sender, path);
	if (!agent)
		return -ENOMEM;

	match = slist_find(services, agent, (cmp_func_t) service_agent_cmp);

	service_agent_free(agent);

	if (!match) /* FIXME: find a better name */
		return -ENODATA;

	/* Remove from the list */	
	agent = match->data;
	services = slist_remove(services, agent);
	service_agent_free(agent);

	/* Only remove the listener if there is no more services related to this owner */
	agent = service_agent_new(sender, NULL);
	if (!agent) /* FIXME: logic is not correct if the memory allocation fails */
		return -ENOMEM;
	
	match = slist_find(services, agent, (cmp_func_t) service_agent_cmp);

	service_agent_free(agent);

	if (!match)
		name_listener_remove(conn, sender,
				(name_cb_t) service_agent_exit, NULL);
	
	if (!dbus_connection_unregister_object_path (conn, path))
		return -1;

	return 0;
}

void append_available_services(DBusMessage *msg)
{
	if (!msg)
		return;

	struct slist *l = services;
	while (l) {
		const struct service_agent *agent = l->data;

		dbus_message_append_args(msg, DBUS_TYPE_STRING, &agent->path,
						DBUS_TYPE_INVALID);

		l = l->next;
	}

}

