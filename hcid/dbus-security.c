/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2005-2007  Johan Hedberg <johan.hedberg@nokia.com>
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
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "adapter.h"

#include "dbus.h"
#include "dbus-helper.h"
#include "hcid.h"
#include "dbus-common.h"
#include "dbus-service.h"
#include "dbus-error.h"
#include "error.h"
#include "dbus-security.h"
#include "dbus-hci.h"

#define REQUEST_TIMEOUT (60 * 1000)		/* 60 seconds */
#define AGENT_TIMEOUT (10 * 60 * 1000)		/* 10 minutes */

struct passkey_agent {
	struct adapter *adapter;
	DBusConnection *conn;
	char *addr;
	char *name;
	char *path;
	GSList *pending_requests;
	int exited;
	guint timeout;
};

struct pending_agent_request {
	struct passkey_agent *agent;
	int dev;
	bdaddr_t sba;
	bdaddr_t bda;
	char *path;
	DBusPendingCall *call;
	int old_if;
	char *pin;
};

struct authorization_agent {
	DBusConnection *conn;
	char *name;
	char *path;
	GSList *pending_requests;
};

struct auth_agent_req {
	DBusMessage *msg;
	struct authorization_agent *agent;
	char *adapter_path;
	char *address;
	char *service_path;
	char *uuid;
	DBusPendingCall *call;
};

static struct passkey_agent *default_agent = NULL;
static struct authorization_agent *default_auth_agent = NULL;

static void release_agent(struct passkey_agent *agent);
static void send_cancel_request(struct pending_agent_request *req);

static void passkey_agent_free(struct passkey_agent *agent)
{
	GSList *l;

	if (!agent)
		return;

	for (l = agent->pending_requests; l != NULL; l = l->next) {
		struct pending_agent_request *req = l->data;

		hci_send_cmd(req->dev, OGF_LINK_CTL,
				OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);

		send_cancel_request(req);
	}

	if (agent->timeout)
		g_source_remove(agent->timeout);

	if (!agent->exited)
		release_agent(agent);

	g_free(agent->name);
	g_free(agent->path);
	g_free(agent->addr);

	if (agent->conn)
		dbus_connection_unref(agent->conn);

	g_slist_free(agent->pending_requests);

	g_free(agent);
}

static void agent_exited(const char *name, struct adapter *adapter)
{
	GSList *cur, *next;

	debug("Passkey agent %s exited without calling Unregister", name);

	for (cur = adapter->passkey_agents; cur != NULL; cur = next) {
		struct passkey_agent *agent = cur->data;

		next = cur->next;

		if (strcmp(agent->name, name))
			continue;

		agent->exited = 1;

		adapter->passkey_agents = g_slist_remove(adapter->passkey_agents, agent);
		passkey_agent_free(agent);
	}
}

static gboolean agent_timeout(struct passkey_agent *agent)
{
	struct adapter *adapter = agent->adapter;

	debug("Passkey Agent at %s, %s timed out", agent->name, agent->path);

	if (adapter)
		adapter->passkey_agents = g_slist_remove(adapter->passkey_agents, agent);

	agent->timeout = 0;

	passkey_agent_free(agent);

	return FALSE;
}

static void default_agent_exited(const char *name, void *data)
{
	debug("%s exited without unregistering the default passkey agent", name);

	if (!default_agent || strcmp(name, default_agent->name)) {
		/* This should never happen (there's a bug in the code if it does) */
		debug("default_agent_exited: mismatch with actual default_agent");
		return;
	}

	default_agent->exited = 1;

	passkey_agent_free(default_agent);
	default_agent = NULL;
}

static struct passkey_agent *passkey_agent_new(struct adapter *adapter, DBusConnection *conn,
						const char *name, const char *path,
						const char *addr)
{
	struct passkey_agent *agent;

	agent = g_new0(struct passkey_agent, 1);

	agent->adapter = adapter;

	agent->name = g_strdup(name);
	agent->path = g_strdup(path);

	if (addr)
		agent->addr = g_strdup(addr);

	agent->conn = dbus_connection_ref(conn);

	return agent;
}

static int agent_cmp(const struct passkey_agent *a, const struct passkey_agent *b)
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
		ret = strcmp(a->path, b->path);
		if (ret)
			return ret;
	}

	if (b->addr) {
		if (!a->addr)
			return -1;
		ret = strcmp(a->addr, b->addr);
		if (ret)
			return ret;
	}

	return 0;
}

static DBusHandlerResult register_passkey_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct passkey_agent *agent, ref;
	struct adapter *adapter;
	DBusMessage *reply;
	const char *path, *addr;

	if (!data) {
		error("register_passkey_agent called without any adapter info!");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	adapter = data;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if ((check_address(addr) < 0) || (path[0] != '/'))
		return error_invalid_arguments(conn, msg, NULL);

	memset(&ref, 0, sizeof(ref));

	ref.name = (char *) dbus_message_get_sender(msg);
	ref.addr = (char *) addr;
	ref.path = (char *) path;

	if (g_slist_find_custom(adapter->passkey_agents, &ref, (GCompareFunc) agent_cmp))
		return error_passkey_agent_already_exists(conn, msg);

	agent = passkey_agent_new(adapter, conn, ref.name, path, addr);
	if (!agent)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		agent->exited = 1;
		passkey_agent_free(agent);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	/* Only add a name listener if there isn't one already for this name */
	ref.addr = NULL;
	ref.path = NULL;
	if (!g_slist_find_custom(adapter->passkey_agents, &ref, (GCompareFunc) agent_cmp))
		name_listener_add(conn, ref.name, (name_cb_t) agent_exited, adapter);

	agent->timeout = g_timeout_add(AGENT_TIMEOUT, (GSourceFunc)agent_timeout, agent);

	adapter->passkey_agents = g_slist_append(adapter->passkey_agents, agent);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult unregister_passkey_agent(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct adapter *adapter;
	GSList *match;
	struct passkey_agent ref, *agent;
	DBusMessage *reply;
	const char *path, *addr;

	if (!data) {
		error("unregister_passkey_agent called without any adapter info!");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	adapter = data;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	memset(&ref, 0, sizeof(ref));

	ref.name = (char *) dbus_message_get_sender(msg);
	ref.path = (char *) path;
	ref.addr = (char *) addr;

	match = g_slist_find_custom(adapter->passkey_agents, &ref, (GCompareFunc) agent_cmp);
	if (!match)
		return error_passkey_agent_does_not_exist(conn, msg);

	agent = match->data;

	name_listener_remove(agent->conn, agent->name,
			(name_cb_t) agent_exited, adapter);

	adapter->passkey_agents = g_slist_remove(adapter->passkey_agents, agent);
	agent->exited = 1;
	passkey_agent_free(agent);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult register_default_passkey_agent(DBusConnection *conn,
							DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path;

	if (default_agent)
		return error_passkey_agent_already_exists(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	default_agent = passkey_agent_new(NULL, conn, dbus_message_get_sender(msg),
						path, NULL);
	if (!default_agent)
		goto need_memory;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto need_memory;

	name_listener_add(conn, default_agent->name,
			(name_cb_t) default_agent_exited, NULL);

	info("Default passkey agent (%s, %s) registered",
			default_agent->name, default_agent->path);

	return send_message_and_unref(conn, reply);

need_memory:
	if (default_agent) {
		default_agent->exited = 1;
		passkey_agent_free(default_agent);
		default_agent = NULL;
	}

	return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult unregister_default_passkey_agent(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path, *name;

	if (!default_agent)
		return error_passkey_agent_does_not_exist(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	name = dbus_message_get_sender(msg);

	if (strcmp(name, default_agent->name) || strcmp(path, default_agent->path))
		return error_passkey_agent_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	name_listener_remove(conn, default_agent->name,
			(name_cb_t) default_agent_exited, NULL);

	info("Default passkey agent (%s, %s) unregistered",
			default_agent->name, default_agent->path);

	default_agent->exited = 1;
	passkey_agent_free(default_agent);
	default_agent = NULL;

	return send_message_and_unref(conn, reply);
}

static struct auth_agent_req *auth_agent_req_new(DBusMessage *msg,
						struct authorization_agent *agent,
						const char *adapter_path,
						const char *address,
						const char *service_path,
						const char *uuid)
{
	struct auth_agent_req *req;

	req = g_new0(struct auth_agent_req, 1);

	req->agent = agent;
	req->msg = dbus_message_ref(msg);
	req->adapter_path = g_strdup(adapter_path);
	req->address = g_strdup(address);
	req->service_path = g_strdup(service_path);
	req->uuid = g_strdup(uuid);

	return req;
}

static void auth_agent_req_free(struct auth_agent_req *req)
{
	dbus_message_unref(req->msg);
	g_free(req->adapter_path);
	g_free(req->address);
	g_free(req->service_path);
	g_free(req->uuid);
	if (req->call)
		dbus_pending_call_unref(req->call);
	g_free(req);
}

static void auth_agent_req_cancel(struct auth_agent_req *req)
{
	dbus_pending_call_cancel(req->call);
	error_canceled(req->agent->conn, req->msg,
			"Authorization process was canceled");
}

static void auth_agent_cancel_requests(struct authorization_agent *agent)
{
	GSList *l;

	for (l = agent->pending_requests; l != NULL; l = l->next) {
		struct auth_agent_req *req = l->data;
		auth_agent_req_cancel(req);
		auth_agent_req_free(req);
	}
}

static void auth_agent_call_cancel(struct auth_agent_req *req)
{
	struct authorization_agent *agent = req->agent;
	DBusMessage *message;

	message = dbus_message_new_method_call(agent->name, agent->path,
				"org.bluez.AuthorizationAgent", "Cancel");
	if (!message) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	dbus_message_append_args(message,
				DBUS_TYPE_STRING, &req->adapter_path,
				DBUS_TYPE_STRING, &req->address,
				DBUS_TYPE_STRING, &req->service_path,
				DBUS_TYPE_STRING, &req->uuid,
				DBUS_TYPE_INVALID);

	dbus_message_set_no_reply(message, TRUE);
	send_message_and_unref(agent->conn, message);
}

static void auth_agent_free(struct authorization_agent *agent)
{
	g_free(agent->name);
	g_free(agent->path);
	dbus_connection_unref(agent->conn);
	g_slist_free(agent->pending_requests);
	g_free(agent);
}

static struct authorization_agent *auth_agent_new(DBusConnection *conn,
						const char *name,
						const char *path)
{
	struct authorization_agent *agent;

	agent = g_new0(struct authorization_agent, 1);

	agent->name = g_strdup(name);
	agent->path = g_strdup(path);

	agent->conn = dbus_connection_ref(conn);

	return agent;
}

static void default_auth_agent_exited(const char *name, void *data)
{
	debug("%s exited without unregistering the "
		"default authorization agent", name);

	if (!default_auth_agent || strcmp(name, default_auth_agent->name)) {
		/* This should never happen! */
		debug("default_auth_agent_exited: mismatch with "
			"actual default_auth_agent");
		return;
	}

	auth_agent_cancel_requests(default_auth_agent);
	auth_agent_free(default_auth_agent);
	default_auth_agent = NULL;
}

static void auth_agent_release(struct authorization_agent *agent)
{
	DBusMessage *message;

	debug("Releasing authorization agent %s, %s",
		agent->name, agent->path);

	message = dbus_message_new_method_call(agent->name, agent->path,
			"org.bluez.AuthorizationAgent", "Release");
	if (!message) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	dbus_message_set_no_reply(message, TRUE);
	send_message_and_unref(agent->conn, message);

	if (agent == default_auth_agent)
		name_listener_remove(agent->conn, agent->name,
				(name_cb_t) default_auth_agent_exited, NULL);
}

static DBusHandlerResult register_default_auth_agent(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	DBusMessage *reply;
	const char *path;

	if (default_auth_agent)
		return error_auth_agent_already_exists(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	default_auth_agent = auth_agent_new(conn,
					dbus_message_get_sender(msg), path);
	if (!default_auth_agent)
		goto need_memory;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto need_memory;

	name_listener_add(conn, default_auth_agent->name,
			(name_cb_t) default_auth_agent_exited, NULL);

	info("Default authorization agent (%s, %s) registered",
		default_auth_agent->name, default_auth_agent->path);

	return send_message_and_unref(conn, reply);

need_memory:
	if (default_auth_agent) {
		auth_agent_free(default_auth_agent);
		default_auth_agent = NULL;
	}

	return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult unregister_default_auth_agent(DBusConnection *conn,
							DBusMessage *msg,
							void *data)
{
	const char *path, *name;
	DBusMessage *reply;

	if (!default_auth_agent)
		return error_auth_agent_does_not_exist(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	name = dbus_message_get_sender(msg);

	if (strcmp(name, default_auth_agent->name) ||
		strcmp(path, default_auth_agent->path))
		return error_auth_agent_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	name_listener_remove(conn, default_auth_agent->name,
			(name_cb_t) default_auth_agent_exited, NULL);

	info("Default authorization agent (%s, %s) unregistered",
		default_auth_agent->name, default_auth_agent->path);

	auth_agent_cancel_requests(default_auth_agent);
	auth_agent_free(default_auth_agent);
	default_auth_agent = NULL;

	return send_message_and_unref(conn, reply);
}

static void auth_agent_req_reply(DBusPendingCall *call, void *data)
{
	struct auth_agent_req *req = data;
	struct authorization_agent *agent = req->agent;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *message;
	DBusError err;

	debug("authorize reply");

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		if (dbus_error_has_name(&err, DBUS_ERROR_NO_REPLY))
			auth_agent_call_cancel(req);
		error("Authorization agent replied with an error: %s, %s",
				err.name, err.message);
		dbus_error_free(&err);
		goto reject;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(reply, &err,	DBUS_TYPE_INVALID)) {
		error("Wrong authorization agent reply signature: %s",
			err.message);
		dbus_error_free(&err);
		goto reject;
	}

	message = dbus_message_new_method_return(req->msg);
	if (!message)
		goto reject;

	send_message_and_unref(agent->conn, message);

	debug("successfull reply was sent");

	goto done;

reject:
	error_rejected(agent->conn, req->msg);

done:
	dbus_message_unref(reply);

	agent->pending_requests = g_slist_remove(agent->pending_requests, req);

	auth_agent_req_free(req);

	debug("auth_agent_reply: returning");
}

static DBusPendingCall *auth_agent_call_authorize(struct authorization_agent *agent,
						const char *adapter_path,
						const char *service_path,
						const char *address,
						const char *path)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(agent->name, agent->path,
				"org.bluez.AuthorizationAgent", "Authorize");
	if (!message) {
		error("Couldn't allocate D-Bus message");
		return NULL;
	}

	dbus_message_append_args(message,
				DBUS_TYPE_STRING, &adapter_path,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_STRING, &service_path,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(agent->conn, message,
					&call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);
	return call;
}

DBusHandlerResult handle_authorize_request(DBusConnection *conn,
					DBusMessage *msg,
					struct service *service,
					const char *address,
					const char *uuid)
{
	struct auth_agent_req *req;
	char adapter_path[PATH_MAX];
	bdaddr_t bdaddr;
	int adapter_id;

	debug("handle_authorize_request");

	if (!default_auth_agent) {
		debug("no default agent");
		return error_auth_agent_does_not_exist(conn, msg);
	}

	str2ba(address, &bdaddr);

	adapter_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
	if (adapter_id < 0)
		return error_not_connected(conn, msg);

	debug("Found %s connected to hci%d", address, adapter_id);

	snprintf(adapter_path, sizeof(adapter_path), "/org/bluez/hci%d",
			adapter_id);

	req = auth_agent_req_new(msg, default_auth_agent, adapter_path,
					address, service->object_path, uuid);

	req->call = auth_agent_call_authorize(default_auth_agent, adapter_path,
						service->object_path, address,
						uuid);
	if (!req->call) {
		auth_agent_req_free(req);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_pending_call_set_notify(req->call, auth_agent_req_reply, req,
					NULL);
	default_auth_agent->pending_requests =
		g_slist_append(default_auth_agent->pending_requests, req);

	debug("authorize request was forwarded");

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult auth_agent_send_cancel(DBusMessage *msg,
					struct authorization_agent *agent,
					const char *adapter_path,
					struct service *service,
					const char *address,
					const char *path)
{
	struct auth_agent_req *req = NULL;
	DBusMessage *message;
	GSList *l;

	for (l = agent->pending_requests; l != NULL; l = l->next) {
		req = l->data;
		if (!strcmp(adapter_path, req->adapter_path) &&
			!strcmp(address, req->address) &&
			!strcmp(service->object_path, req->service_path) &&
			!strcmp(path, req->uuid))
			break;
	}

	if (!req)
		return error_does_not_exist(agent->conn, msg,
					"No such authorization process");

	message = dbus_message_new_method_return(msg);
	if (!message)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	auth_agent_call_cancel(req);
	auth_agent_req_cancel(req);
	agent->pending_requests = g_slist_remove(agent->pending_requests, req);
	auth_agent_req_free(req);

	return send_message_and_unref(agent->conn, message);
}

DBusHandlerResult cancel_authorize_request(DBusConnection *conn,
						DBusMessage *msg,
						struct service *service,
						const char *address,
						const char *path)
{
	char adapter_path[PATH_MAX];
	int adapter_id;
	bdaddr_t bdaddr;

	if (!default_auth_agent)
		return error_auth_agent_does_not_exist(conn, msg);

	str2ba(address, &bdaddr);

	adapter_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
	if (adapter_id < 0)
		return error_not_connected(conn, msg);

	snprintf(adapter_path, sizeof(adapter_path), "/org/bluez/hci%d",
			adapter_id);

	return auth_agent_send_cancel(msg, default_auth_agent, adapter_path,
						service, address, path);
}

static DBusMethodVTable security_methods[] = {
	{ "RegisterDefaultPasskeyAgent",		register_default_passkey_agent,
		"s",	""	},
	{ "UnregisterDefaultPasskeyAgent",		unregister_default_passkey_agent,
		"s",	""	},
	{ "RegisterPasskeyAgent",			register_passkey_agent,
		"ss",	""	},
	{ "UnregisterPasskeyAgent",			unregister_passkey_agent,
		"ss",	""	},
	{ "RegisterDefaultAuthorizationAgent",		register_default_auth_agent,
		"s",	""	},
	{ "UnregisterDefaultAuthorizationAgent",	unregister_default_auth_agent,
		"s",	""	},
	{ NULL, NULL, NULL, NULL }
};

dbus_bool_t security_init(DBusConnection *conn, const char *path)
{
	return dbus_connection_register_interface(conn, path, SECURITY_INTERFACE,
							security_methods,
							NULL, NULL);
}

static DBusPendingCall *agent_request(const char *path, bdaddr_t *bda,
					struct passkey_agent *agent,
					dbus_bool_t numeric, int old_if)
{
	DBusMessage *message;
	DBusPendingCall *call;
	char bda_str[18], *ptr = bda_str;

	message = dbus_message_new_method_call(agent->name, agent->path,
					"org.bluez.PasskeyAgent", "Request");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return NULL;
	}

	ba2str(bda, bda_str);

	if (old_if)
		dbus_message_append_args(message,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &ptr,
				DBUS_TYPE_INVALID);
	else
		dbus_message_append_args(message,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &ptr,
				DBUS_TYPE_BOOLEAN, &numeric,
				DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(agent->conn, message,
					&call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);
	return call;
}

static void passkey_agent_reply(DBusPendingCall *call, void *user_data)
{
	struct pending_agent_request *req = user_data;
	struct passkey_agent *agent = req->agent;
	pin_code_reply_cp pr;
	DBusMessage *message;
	DBusError err;
	size_t len;
	char *pin;

	/* steal_reply will always return non-NULL since the callback
	 * is only called after a reply has been received */
	message = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, message)) {
		if (!req->old_if && !strcmp(err.name, DBUS_ERROR_UNKNOWN_METHOD)) {
			debug("New Request API failed, trying old one");
			req->old_if = 1;
			dbus_error_free(&err);
			dbus_pending_call_unref(req->call);
			req->call = agent_request(req->path, &req->bda, agent,
							FALSE, 1);
			if (!req->call)
				goto fail;

			dbus_message_unref(message);

			dbus_pending_call_set_notify(req->call,
							passkey_agent_reply,
							req, NULL);
			return;
		}

		error("Passkey agent replied with an error: %s, %s",
				err.name, err.message);

		dbus_error_free(&err);
		goto fail;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(message, &err,
				DBUS_TYPE_STRING, &pin,
				DBUS_TYPE_INVALID)) {
		error("Wrong passkey reply signature: %s", err.message);
		dbus_error_free(&err);
		goto fail;
	}

	len = strlen(pin);

	if (len > 16 || len < 1) {
		error("Invalid passkey length from handler");
		goto fail;
	}

	set_pin_length(&req->sba, len);

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, &req->bda);
	memcpy(pr.pin_code, pin, len);
	pr.pin_len = len;
	hci_send_cmd(req->dev, OGF_LINK_CTL,
			OCF_PIN_CODE_REPLY, PIN_CODE_REPLY_CP_SIZE, &pr);

	goto done;

fail:
	hci_send_cmd(req->dev, OGF_LINK_CTL,
			OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);

done:
	if (message)
		dbus_message_unref(message);

	agent->pending_requests = g_slist_remove(agent->pending_requests, req);
	dbus_pending_call_cancel(req->call);
	if (req->call)
		dbus_pending_call_unref(req->call);
	g_free(req->path);
	g_free(req);

	if (agent != default_agent) {
		agent->adapter->passkey_agents = g_slist_remove(agent->adapter->passkey_agents,
								agent);
		passkey_agent_free(agent);
	}
}

static int call_passkey_agent(DBusConnection *conn,
				struct passkey_agent *agent, int dev,
				const char *path, bdaddr_t *sba,
				bdaddr_t *dba)
{
	struct pending_agent_request *req;

	if (!agent) {
		debug("call_passkey_agent(): no agent available");
		goto send;
	}

	debug("Calling PasskeyAgent.Request: name=%s, path=%s",
						agent->name, agent->path);

	req = g_new0(struct pending_agent_request, 1);
	req->dev = dev;
	bacpy(&req->sba, sba);
	bacpy(&req->bda, dba);
	req->agent = agent;
	req->path = g_strdup(path);

	req->call = agent_request(path, dba, agent, FALSE, 0);
	if (!req->call)
		goto failed;

	dbus_pending_call_set_notify(req->call, passkey_agent_reply, req, NULL);

	agent->pending_requests = g_slist_append(agent->pending_requests, req);

	return 0;

failed:
	g_free(req->path);
	g_free(req);

send:
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, dba);

	return -1;
}

int handle_passkey_request(DBusConnection *conn, int dev, const char *path,
					bdaddr_t *sba, bdaddr_t *dba)
{
	struct passkey_agent *agent = default_agent;
	struct adapter *adapter = NULL;
	GSList *l;
	char addr[18];
	void *data;

	dbus_connection_get_object_user_data(conn, path, &data);

	if (!data)
		goto done;

	adapter = data;

	if (!bacmp(&adapter->agents_disabled, dba))
		goto done;

	ba2str(dba, addr);

	for (l = adapter->passkey_agents; l != NULL; l = l->next) {
		struct passkey_agent *a = l->data;
		if (a != default_agent && g_slist_length(a->pending_requests) >= 1)
			continue;
		if (!strcmp(a->addr, addr)) {
			agent = a;
			break;
		}
	}

done:
	return call_passkey_agent(conn, agent, dev, path, sba, dba);
}

static DBusPendingCall *agent_confirm(const char *path, bdaddr_t *bda,
					struct passkey_agent *agent,
					const char *value)
{
	DBusMessage *message;
	DBusPendingCall *call;
	char bda_str[18], *ptr = bda_str;

	message = dbus_message_new_method_call(agent->name, agent->path,
					"org.bluez.PasskeyAgent", "Confirm");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return NULL;
	}

	ba2str(bda, bda_str);

	dbus_message_append_args(message,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &ptr,
				DBUS_TYPE_STRING, &value,
				DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(agent->conn, message,
					&call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);
	return call;
}

static void confirm_agent_reply(DBusPendingCall *call, void *user_data)
{
	struct pending_agent_request *req = user_data;
	struct passkey_agent *agent = req->agent;
	pin_code_reply_cp pr;
	DBusMessage *message;
	DBusError err;
	int len;

	/* steal_reply will always return non-NULL since the callback
	 * is only called after a reply has been received */
	message = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, message)) {

		error("Passkey agent replied with an error: %s, %s",
				err.name, err.message);

		dbus_error_free(&err);
		goto fail;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(message, &err, DBUS_TYPE_INVALID)) {
		error("Wrong confirm reply signature: %s", err.message);
		dbus_error_free(&err);
		goto fail;
	}

	len = strlen(req->pin);

	set_pin_length(&req->sba, len);

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, &req->bda);
	memcpy(pr.pin_code, req->pin, len);
	pr.pin_len = len;
	hci_send_cmd(req->dev, OGF_LINK_CTL,
			OCF_PIN_CODE_REPLY, PIN_CODE_REPLY_CP_SIZE, &pr);

	goto done;

fail:
	hci_send_cmd(req->dev, OGF_LINK_CTL,
			OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);

done:
	if (message)
		dbus_message_unref(message);

	agent->pending_requests = g_slist_remove(agent->pending_requests, req);
	dbus_pending_call_cancel(req->call);
	if (req->call)
		dbus_pending_call_unref(req->call);
	g_free(req->pin);
	g_free(req->path);
	g_free(req);

	if (agent != default_agent) {
		agent->adapter->passkey_agents = g_slist_remove(agent->adapter->passkey_agents,
								agent);
		passkey_agent_free(agent);
	}
}

static int call_confirm_agent(DBusConnection *conn,
				struct passkey_agent *agent, int dev,
				const char *path, bdaddr_t *sba,
				bdaddr_t *dba, const char *pin)
{
	struct pending_agent_request *req;

	if (!agent) {
		debug("call_passkey_agent(): no agent available");
		goto send;
	}

	debug("Calling PasskeyAgent.Confirm: name=%s, path=%s",
						agent->name, agent->path);

	req = g_new0(struct pending_agent_request, 1);
	req->dev = dev;
	bacpy(&req->sba, sba);
	bacpy(&req->bda, dba);
	req->agent = agent;
	req->path = g_strdup(path);
	req->pin = g_strdup(pin);

	req->call = agent_confirm(path, dba, agent, pin);
	if (!req->call)
		goto failed;

	dbus_pending_call_set_notify(req->call, confirm_agent_reply, req, NULL);

	agent->pending_requests = g_slist_append(agent->pending_requests, req);

	return 0;

failed:
	g_free(req->pin);
	g_free(req->path);
	g_free(req);

send:
	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, dba);

	return -1;
}

int handle_confirm_request(DBusConnection *conn, int dev, const char *path,
				bdaddr_t *sba, bdaddr_t *dba, const char *pin)
{
	struct passkey_agent *agent = default_agent;
	struct adapter *adapter = NULL;
	GSList *l;
	char addr[18];
	void *data;

	dbus_connection_get_object_user_data(conn, path, &data);

	if (!data)
		goto done;

	adapter = data;

	if (!bacmp(&adapter->agents_disabled, dba))
		goto done;

	ba2str(dba, addr);

	for (l = adapter->passkey_agents; l != NULL; l = l->next) {
		struct passkey_agent *a = l->data;
		if (a != default_agent && g_slist_length(a->pending_requests) >= 1)
			continue;
		if (!strcmp(a->addr, addr)) {
			agent = a;
			break;
		}
	}

done:
	return call_confirm_agent(conn, agent, dev, path, sba, dba, pin);
}

static void send_cancel_request(struct pending_agent_request *req)
{
	DBusMessage *message;
	char address[18], *ptr = address;

	message = dbus_message_new_method_call(req->agent->name, req->agent->path,
			"org.bluez.PasskeyAgent", "Cancel");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	ba2str(&req->bda, address);

	dbus_message_append_args(message,
			DBUS_TYPE_STRING, &req->path,
			DBUS_TYPE_STRING, &ptr,
			DBUS_TYPE_INVALID);

	dbus_message_set_no_reply(message, TRUE);

	send_message_and_unref(req->agent->conn, message);

	debug("PasskeyAgent.Request(%s, %s) was canceled", req->path, address);

	dbus_pending_call_cancel(req->call);
	dbus_pending_call_unref(req->call);
	g_free(req->pin);
	g_free(req->path);
	g_free(req);
}

static void release_agent(struct passkey_agent *agent)
{
	DBusMessage *message;

	debug("Releasing agent %s, %s", agent->name, agent->path);

	message = dbus_message_new_method_call(agent->name, agent->path,
			"org.bluez.PasskeyAgent", "Release");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	dbus_message_set_no_reply(message, TRUE);

	send_message_and_unref(agent->conn, message);

	if (agent == default_agent)
		name_listener_remove(agent->conn, agent->name,
				(name_cb_t) default_agent_exited, NULL);
	else {
		struct passkey_agent ref;

		/* Only remove the name listener if there are no more agents for this name */
		memset(&ref, 0, sizeof(ref));
		ref.name = agent->name;
		if (!g_slist_find_custom(agent->adapter->passkey_agents, &ref, (GCompareFunc) agent_cmp))
			name_listener_remove(agent->conn, ref.name,
					(name_cb_t) agent_exited, agent->adapter);
	}
}

void release_default_agent(void)
{
	if (!default_agent)
		return;

	passkey_agent_free(default_agent);
	default_agent = NULL;
}

void release_default_auth_agent(void)
{
	if (!default_auth_agent)
		return;

	auth_agent_cancel_requests(default_auth_agent);
	auth_agent_release(default_auth_agent);

	auth_agent_free(default_auth_agent);
	default_auth_agent = NULL;
}

void release_passkey_agents(struct adapter *adapter, bdaddr_t *bda)
{
	GSList *l, *next;

	for (l = adapter->passkey_agents; l != NULL; l = next) {
		struct passkey_agent *agent = l->data;
		next = l->next;

		if (bda && agent->addr) {
			bdaddr_t tmp;
			str2ba(agent->addr, &tmp);
			if (bacmp(&tmp, bda))
				continue;
		}

		adapter->passkey_agents = g_slist_remove(adapter->passkey_agents, agent);
		passkey_agent_free(agent);
	}
}

void cancel_passkey_agent_requests(GSList *agents, const char *path,
					bdaddr_t *addr)
{
	GSList *l, *next;

	/* First check the default agent */
	for (l = default_agent ? default_agent->pending_requests : NULL; l != NULL; l = next) {
		struct pending_agent_request *req = l->data;
		next = l->next;
		if (!strcmp(path, req->path) && (!addr || !bacmp(addr, &req->bda))) {
			send_cancel_request(req);
			default_agent->pending_requests = g_slist_remove(default_agent->pending_requests,
									req);
		}
	}

	/* and then the adapter specific agents */
	for (; agents != NULL; agents = agents->next) {
		struct passkey_agent *agent = agents->data;

		for (l = agent->pending_requests; l != NULL; l = next) {
			struct pending_agent_request *req = l->data;
			next = l->next;
			if (!strcmp(path, req->path) && (!addr || !bacmp(addr, &req->bda))) {
				send_cancel_request(req);
				agent->pending_requests = g_slist_remove(agent->pending_requests, req);
			}
		}
	}
}
