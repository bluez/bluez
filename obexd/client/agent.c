/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include "log.h"
#include "agent.h"

#define AGENT_INTERFACE  "org.openobex.Agent"

struct pending_request {
	DBusPendingCall *call;
	DBusPendingCallNotifyFunction function;
	void *data;
	DBusFreeFunction destroy;
};

struct obc_agent {
	DBusConnection *conn;
	char *name;
	char *path;
	guint watch;
	GFunc destroy;
	void *data;
	struct pending_request *pending;
};

static void pending_request_free(struct pending_request *req)
{
	if (req->call)
		dbus_pending_call_unref(req->call);

	if (req->destroy)
		req->destroy(req->data);

	g_free(req);
}

void obc_agent_free(struct obc_agent *agent)
{
	if (agent->watch)
		g_dbus_remove_watch(agent->conn, agent->watch);

	if (agent->pending) {
		if (agent->pending->call)
			dbus_pending_call_cancel(agent->pending->call);
		pending_request_free(agent->pending);
	}

	dbus_connection_unref(agent->conn);
	g_free(agent->name);
	g_free(agent->path);
	g_free(agent);
}

static void agent_disconnected(DBusConnection *connection, void *user_data)
{
	struct obc_agent *agent = user_data;

	agent->watch = 0;

	if (agent->destroy)
		agent->destroy(agent, agent->data);

	obc_agent_free(agent);
}

struct obc_agent *obc_agent_create(DBusConnection *conn, const char *name,
					const char *path, GFunc destroy,
					void *user_data)
{
	struct obc_agent *agent;

	agent = g_new0(struct obc_agent, 1);
	agent->conn = dbus_connection_ref(conn);
	agent->name = g_strdup(name);
	agent->path = g_strdup(path);
	agent->destroy = destroy;
	agent->data = user_data;

	agent->watch = g_dbus_add_disconnect_watch(conn, name,
							agent_disconnected,
							agent, NULL);

	return agent;
}

static void agent_request_reply(DBusPendingCall *call, void *user_data)
{
	struct obc_agent *agent = user_data;
	struct pending_request *req = agent->pending;

	agent->pending = NULL;

	if (req->function)
		req->function(call, req->data);

	pending_request_free(req);
}

int obc_agent_request(struct obc_agent *agent, const char *path,
				DBusPendingCallNotifyFunction function,
				void *user_data, DBusFreeFunction destroy)
{
	struct pending_request *req;
	DBusMessage *message;

	if (agent->pending)
		return -EBUSY;

	DBG("%s", path);

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Request");

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	req = g_new0(struct pending_request, 1);
	req->function = function;
	req->destroy = destroy;
	req->data = user_data;

	if (!dbus_connection_send_with_reply(agent->conn, message,
						&req->call, -1)) {
		g_free(req);
		dbus_message_unref(message);
		return -ENOMEM;
	}

	agent->pending = req;

	dbus_message_unref(message);

	dbus_pending_call_set_notify(req->call, agent_request_reply,
					agent, NULL);

	return 0;
}

void obc_agent_notify_progress(struct obc_agent *agent, const char *path,
							guint64 transferred)
{
	DBusMessage *message;

	DBG("%s", path);

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Progress");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_UINT64, &transferred,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(agent->conn, message);
}

void obc_agent_notify_complete(struct obc_agent *agent, const char *path)
{
	DBusMessage *message;

	DBG("%s", path);

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Complete");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(agent->conn, message);
}

void obc_agent_notify_error(struct obc_agent *agent, const char *path,
							const char *err)
{
	DBusMessage *message;

	DBG("%s", path);

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Error");
	if (message == NULL)
		return;

	dbus_message_set_no_reply(message, TRUE);

	dbus_message_append_args(message,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_STRING, &err,
			DBUS_TYPE_INVALID);

	g_dbus_send_message(agent->conn, message);
}

void obc_agent_release(struct obc_agent *agent)
{
	DBusMessage *message;

	DBG("");

	message = dbus_message_new_method_call(agent->name,
			agent->path, AGENT_INTERFACE, "Release");

	dbus_message_set_no_reply(message, TRUE);

	g_dbus_send_message(agent->conn, message);
}

const char *obc_agent_get_name(struct obc_agent *agent)
{
	return agent->name;
}

const char *obc_agent_get_path(struct obc_agent *agent)
{
	return agent->path;
}
