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

#define START_REPLY_TIMEOUT	5000

#define SERVICE_RUNNING		1
#define SERVICE_NOT_RUNNING	0

struct service_call {
	DBusConnection *conn;
	DBusMessage *msg;
	struct service_agent *agent;
};

static struct slist *services = NULL;

static void service_call_free(void *data)
{
	struct service_call *call = data;

	if (!call)
		return;

	if (call->conn)
		dbus_connection_unref(call->conn);

	if(call->msg)
		dbus_message_unref(call->msg);
	
	free(call);
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

	/* by default when the service agent registers the service must not be running */
	agent->running = SERVICE_NOT_RUNNING;

	return agent;

mem_fail:
	service_agent_free(agent);
	return NULL;
}

static void service_agent_exit(const char *name, void *data)
{
	DBusConnection *conn = data;
	DBusMessage *message;
	struct slist *l, *lremove = NULL;
	struct service_agent *agent;
	const char *path;
	
	debug("Service Agent exited:%s", name);

	/* Remove all service agents assigned to this owner */
	for (l = services; l; l = l->next) {
		path = l->data;

		if (!dbus_connection_get_object_path_data(conn, path, (void *) &agent))
			continue;

		if (strcmp(name, agent->id))
			continue;

		service_agent_free(agent);

		dbus_connection_unregister_object_path(conn, path);

		message = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
						"ServiceUnregistered");
		dbus_message_append_args(message, DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);
		send_message_and_unref(conn, message);

		lremove = slist_append(lremove, l->data);
		services = slist_remove(services, l->data);
	}

	slist_foreach(lremove, (slist_func_t) free, NULL);
	slist_free(lremove);
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

	send_message_and_unref(call_data->conn, source_reply);

	dbus_message_unref(reply);
	dbus_pending_call_unref (call);
}

static DBusHandlerResult get_interface_names(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusPendingCall *pending;
	struct service_call *call_data;
	struct service_agent *agent  = data;
	DBusMessage *forward = dbus_message_copy(msg);
	const char *path = dbus_message_get_path(msg);

	dbus_message_set_destination(forward, agent->id);
	dbus_message_set_interface(forward, "org.bluez.ServiceAgent");
	dbus_message_set_path(forward, path);
	dbus_message_set_member(forward, "Interfaces");

	call_data = malloc(sizeof(struct service_call));
	call_data->conn = dbus_connection_ref(conn);
	call_data->msg = dbus_message_ref(msg);

	if (dbus_connection_send_with_reply(conn, forward, &pending, -1) == FALSE) {
		dbus_message_unref(forward);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_pending_call_set_notify(pending, forward_reply, call_data, service_call_free);
	dbus_message_unref(forward);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult get_connection_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct service_agent *agent = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &agent->id,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_name(DBusConnection *conn,
					DBusMessage *msg, void *data)
{

	struct service_agent *agent = data;
	DBusMessage *reply;
	const char *name = "";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

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
	struct service_agent *agent = data;
	DBusMessage *reply;
	const char *description = "";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (agent->description)
		description = agent->description;
	
	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &description,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static void start_reply(DBusPendingCall *call, void *udata)
{
	struct service_call *call_data = udata;
	DBusMessage *agent_reply = dbus_pending_call_steal_reply(call);
	DBusMessage *source_reply;
	DBusError err;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, agent_reply)) {
		call_data->agent->running = SERVICE_NOT_RUNNING;
		dbus_error_free(&err);
	} else {
		DBusMessage *message;
		call_data->agent->running = SERVICE_RUNNING;

		/* Send a signal to indicate that the service started properly */
		message = dbus_message_new_signal(dbus_message_get_path(call_data->msg),
							dbus_message_get_interface(call_data->msg),
							"Started");

		send_message_and_unref(call_data->conn, message);
	}

	source_reply = dbus_message_copy(agent_reply);
	dbus_message_set_destination(source_reply, dbus_message_get_sender(call_data->msg));
	dbus_message_set_no_reply(source_reply, TRUE);
	dbus_message_set_reply_serial(source_reply, dbus_message_get_serial(call_data->msg));

	send_message_and_unref(call_data->conn, source_reply);

	dbus_message_unref(agent_reply);
	dbus_pending_call_unref (call);
}

static DBusHandlerResult start(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusPendingCall *pending;
	struct service_call *call_data;
	struct service_agent *agent  = data;
	DBusMessage *forward;

	if (agent->running)
		return error_failed(conn, msg, EPERM);

	forward = dbus_message_copy(msg);
	if (!forward)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_set_destination(forward, agent->id);
	dbus_message_set_interface(forward, "org.bluez.ServiceAgent");
	dbus_message_set_path(forward, dbus_message_get_path(msg));

	call_data = malloc(sizeof(struct service_call));
	call_data->conn = dbus_connection_ref(conn);
	call_data->msg = dbus_message_ref(msg);
	call_data->agent = data;

	if (dbus_connection_send_with_reply(conn, forward, &pending, START_REPLY_TIMEOUT) == FALSE) {
		dbus_message_unref(forward);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_pending_call_set_notify(pending, start_reply, call_data, service_call_free);
	dbus_message_unref(forward);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static void stop_reply(DBusPendingCall *call, void *udata)
{
	struct service_call *call_data = udata;
	DBusMessage *agent_reply = dbus_pending_call_steal_reply(call);
	DBusMessage *source_reply;
	DBusError err;

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, agent_reply)) {
		/* Keep the old running value */
		dbus_error_free(&err);
	} else {
		DBusMessage *message;
		call_data->agent->running = SERVICE_NOT_RUNNING;

		/* Send a signal to indicate that the service started properly */
		message = dbus_message_new_signal(dbus_message_get_path(call_data->msg),
							dbus_message_get_interface(call_data->msg),
							"Stopped");

		send_message_and_unref(call_data->conn, message);
	}

	source_reply = dbus_message_copy(agent_reply);
	dbus_message_set_destination(source_reply, dbus_message_get_sender(call_data->msg));
	dbus_message_set_no_reply(source_reply, TRUE);
	dbus_message_set_reply_serial(source_reply, dbus_message_get_serial(call_data->msg));

	send_message_and_unref(call_data->conn, source_reply);

	dbus_message_unref(agent_reply);
	dbus_pending_call_unref (call);
}

static DBusHandlerResult stop(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	DBusPendingCall *pending;
	struct service_call *call_data;
	struct service_agent *agent  = data;
	DBusMessage *forward = dbus_message_copy(msg);

	dbus_message_set_destination(forward, agent->id);
	dbus_message_set_interface(forward, "org.bluez.ServiceAgent");
	dbus_message_set_path(forward, dbus_message_get_path(msg));

	call_data = malloc(sizeof(struct service_call));
	call_data->conn = dbus_connection_ref(conn);
	call_data->msg = dbus_message_ref(msg);
	call_data->agent = data;

	if (dbus_connection_send_with_reply(conn, forward, &pending, START_REPLY_TIMEOUT) == FALSE) {
		dbus_message_unref(forward);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	dbus_pending_call_set_notify(pending, stop_reply, call_data, service_call_free);
	dbus_message_unref(forward);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult is_running(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service_agent *agent = data;
	DBusMessage *reply;
	dbus_bool_t running;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	running = (agent->running ? TRUE : FALSE);

	dbus_message_append_args(reply,
			DBUS_TYPE_BOOLEAN, &running,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
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
	{ "GetName",		get_name		},
	{ "GetDescription",	get_description		},
	{ "GetInterfaceNames",  get_interface_names	},
	{ "GetConnectionName",	get_connection_name	},
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
	struct service_agent *agent = data;
	service_handler_func_t handler;
	DBusPendingCall *pending;
	DBusMessage *forward;
	struct service_call *call_data;
	const char *iface;

	iface = dbus_message_get_interface(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, iface) &&
			!strcmp("Introspect", dbus_message_get_member(msg))) {
		return simple_introspect(conn, msg, data);
	} else if (strcmp("org.bluez.Service", iface) == 0) {

		handler = find_service_handler(services_methods, msg);
		if (handler)
			return handler(conn, msg, data);

		forward = dbus_message_copy(msg);
		if(!forward)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		dbus_message_set_destination(forward, agent->id);
		dbus_message_set_path(forward, dbus_message_get_path(msg));

		call_data = malloc(sizeof(struct service_call));
		if (!call_data) {
			dbus_message_unref(forward);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		call_data->conn = dbus_connection_ref(conn);
		call_data->msg = dbus_message_ref(msg);

		if (dbus_connection_send_with_reply(conn, forward, &pending, -1) == FALSE) {
			service_call_free(call_data);
			dbus_message_unref(forward);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		dbus_pending_call_set_notify(pending, forward_reply, call_data, service_call_free);

		return send_message_and_unref(conn, forward);
	} else 
		return error_unknown_method(conn, msg);
}

static const DBusObjectPathVTable services_vtable = {
	.message_function	= &msg_func_services,
	.unregister_function	= NULL
};

int register_service_agent(DBusConnection *conn, const char *sender,
				const char *path, const char *name, const char *description)
{
	struct service_agent *agent;

	debug("Registering service object: %s", path);

	/* Check if the name is already used? */
	agent = service_agent_new(sender, name, description);
	if (!agent)
		return -ENOMEM;

	if (!dbus_connection_register_object_path(conn, path, &services_vtable, agent)) {
		free(agent);
		return -1;
	}

	services = slist_append(services, strdup(path));

	/* FIXME: only one listener per sender */
	name_listener_add(conn, sender, (name_cb_t) service_agent_exit, conn);

	return 0;
}

int unregister_service_agent(DBusConnection *conn, const char *sender, const char *path)
{
	struct service_agent *agent;
	struct slist *l;

	debug("Unregistering service object: %s", path);

	if (dbus_connection_get_object_path_data(conn, path, (void *) &agent))
		service_agent_free(agent);

	if (!dbus_connection_unregister_object_path(conn, path))
		return -1;

	l = slist_find(services, path, (cmp_func_t) strcmp);
	if (l) {
		void *p = l->data;
		services = slist_remove(services, l->data);
		free(p);
	}

	return 0;
}

void send_release(DBusConnection *conn, const char *id, const char *path)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(id, path,
				"org.bluez.ServiceAgent", "Release");
	if (!msg)
		return;

	dbus_message_set_no_reply(msg, TRUE);
	send_message_and_unref(conn, msg);
}

void release_service_agents(DBusConnection *conn)
{
	struct slist *l = services;
	struct service_agent *agent;
	const char *path;

	while (l) {
		path = l->data;

		l = l->next;

		if (dbus_connection_get_object_path_data(conn, path, (void *) &agent)) {
			send_release(conn, agent->id, path); 
			service_agent_free(agent);
		}

		dbus_connection_unregister_object_path(conn, path);
	}

	slist_foreach(services, (slist_func_t) free, NULL);
	slist_free(services);
	services = NULL;
}

void append_available_services(DBusMessageIter *array_iter)
{
	struct slist *l = services;
	const char *path;

	while (l) {
		path = l->data;
		dbus_message_iter_append_basic(array_iter,
					DBUS_TYPE_STRING, &path);
		l = l->next;
	}
}
