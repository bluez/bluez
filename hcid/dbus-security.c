/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2006  Marcel Holtmann <marcel@holtmann.org>
 *  Copyright (C) 2005-2006  Johan Hedberg <johan.hedberg@nokia.com>
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
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "hcid.h"

#define REQUEST_TIMEOUT (60 * 1000)		/* 60 seconds */
#define AGENT_TIMEOUT (10 * 60 * 1000)		/* 10 minutes */

static struct passkey_agent *default_agent = NULL;

static void release_agent(struct passkey_agent *agent);
static void send_cancel_request(struct pending_agent_request *req);

static void passkey_agent_free(struct passkey_agent *agent)
{
	struct slist *l;

	if (!agent)
		return;

	for (l = agent->pending_requests; l != NULL; l = l->next) {
		struct pending_agent_request *req = l->data;
		
		hci_send_cmd(req->dev, OGF_LINK_CTL,
				OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);

		send_cancel_request(req);
	}

	if (agent->timeout)
		g_timeout_remove(agent->timeout);

	if (!agent->exited)
		release_agent(agent);

	if (agent->name)
		free(agent->name);
	if (agent->path)
		free(agent->path);
	if (agent->addr)
		free(agent->addr);
	if (agent->conn)
		dbus_connection_unref(agent->conn);

	slist_free(agent->pending_requests);

	free(agent);
}

static void agent_exited(const char *name, struct hci_dbus_data *adapter)
{
	struct slist *cur, *next;

	debug("Passkey agent %s exited without calling Unregister", name);

	for (cur = adapter->passkey_agents; cur != NULL; cur = next) {
		struct passkey_agent *agent = cur->data;

		next = cur->next;

		if (strcmp(agent->name, name))
			continue;

		agent->exited = 1;

		adapter->passkey_agents = slist_remove(adapter->passkey_agents, agent);
		passkey_agent_free(agent);
	}
}

static gboolean agent_timeout(struct passkey_agent *agent)
{
	struct hci_dbus_data *pdata = agent->pdata;

	debug("Passkey Agent at %s, %s timed out", agent->name, agent->path);

	if (pdata)
		pdata->passkey_agents = slist_remove(pdata->passkey_agents, agent);

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

static struct passkey_agent *passkey_agent_new(struct hci_dbus_data *pdata, DBusConnection *conn,
						const char *name, const char *path,
						const char *addr)
{
	struct passkey_agent *agent;

	agent = malloc(sizeof(struct passkey_agent));
	if (!agent)
		return NULL;

	memset(agent, 0, sizeof(struct passkey_agent));

	agent->pdata = pdata;

	agent->name = strdup(name);
	if (!agent->name)
		goto mem_fail;

	agent->path = strdup(path);
	if (!agent->path)
		goto mem_fail;

	if (addr) {
		agent->addr = strdup(addr);
		if (!agent->addr)
			goto mem_fail;
	}

	agent->conn = dbus_connection_ref(conn);

	return agent;

mem_fail:
	/* So passkey_agent_free doesn't try to call Relese */
	agent->exited = 1;
	passkey_agent_free(agent);
	return NULL;
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

static DBusHandlerResult register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	char *path, *addr;
	struct passkey_agent *agent, ref;
	struct hci_dbus_data *adapter;
	DBusMessage *reply;

	if (!data) {
		error("register_agent called without any adapter info!");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	adapter = data;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	memset(&ref, 0, sizeof(ref));

	ref.name = (char *)dbus_message_get_sender(msg);
	ref.addr = addr;
	ref.path = path;

	if (slist_find(adapter->passkey_agents, &ref, (cmp_func_t)agent_cmp))
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
	if (!slist_find(adapter->passkey_agents, &ref, (cmp_func_t)agent_cmp))
		name_listener_add(conn, ref.name, (name_cb_t)agent_exited, adapter);

	agent->timeout = g_timeout_add(AGENT_TIMEOUT, (GSourceFunc)agent_timeout, agent);

	adapter->passkey_agents = slist_append(adapter->passkey_agents, agent);

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult unregister_agent(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char *path, *addr;
	struct hci_dbus_data *adapter;
	struct slist *match;
	struct passkey_agent ref, *agent;
	DBusMessage *reply;

	if (!data) {
		error("uregister_agent called without any adapter info!");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	adapter = data;

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_STRING, &addr,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	memset(&ref, 0, sizeof(ref));

	ref.name = (char *)dbus_message_get_sender(msg);
	ref.path = path;
	ref.addr = addr;

	match = slist_find(adapter->passkey_agents, &ref, (cmp_func_t)agent_cmp);
	if (!match)
		return error_passkey_agent_does_not_exist(conn, msg);

	agent = match->data;

	name_listener_remove(agent->conn, agent->name,
			(name_cb_t)agent_exited, adapter);

	adapter->passkey_agents = slist_remove(adapter->passkey_agents, agent);
	agent->exited = 1;
	passkey_agent_free(agent);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_reply_and_unref(conn, reply);
}

static DBusHandlerResult register_default_agent(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	char *path;
	DBusMessage *reply;

	if (default_agent)
		return error_passkey_agent_already_exists(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	default_agent = passkey_agent_new(NULL, conn, dbus_message_get_sender(msg), path, NULL);
	if (!default_agent)
		goto need_memory;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto need_memory;

	name_listener_add(conn, default_agent->name,
			(name_cb_t)default_agent_exited, NULL);

	info("Default passkey agent (%s, %s) registered",
			default_agent->name, default_agent->path);

	return send_reply_and_unref(conn, reply);

need_memory:
	if (default_agent) {
		default_agent->exited = 1;
		passkey_agent_free(default_agent);
		default_agent = NULL;
	}

	return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult unregister_default_agent(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	char *path;
	const char *name;

	if (!default_agent)
		return error_passkey_agent_does_not_exist(conn, msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	name = dbus_message_get_sender(msg);

	if (strcmp(name, default_agent->name) || strcmp(path, default_agent->path))
		return error_passkey_agent_does_not_exist(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	name_listener_remove(conn, default_agent->name,
			(name_cb_t)default_agent_exited, NULL);

	info("Default passkey agent (%s, %s) unregistered",
			default_agent->name, default_agent->path);

	default_agent->exited = 1;
	passkey_agent_free(default_agent);
	default_agent = NULL;


	return send_reply_and_unref(conn, reply);
}

static struct service_data sec_services[] = {
	{ "RegisterDefaultPasskeyAgent",	register_default_agent		},
	{ "UnregisterDefaultPasskeyAgent",	unregister_default_agent	},
	{ "RegisterPasskeyAgent",		register_agent			},
	{ "UnregisterPasskeyAgent",		unregister_agent		},
	{ NULL, NULL }
};

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

	agent->pending_requests = slist_remove(agent->pending_requests, req);
	dbus_pending_call_cancel(req->call);
	dbus_pending_call_unref(req->call);
	free(req->path);
	free(req);

	if (agent != default_agent) {
		agent->pdata->passkey_agents = slist_remove(agent->pdata->passkey_agents,
								agent);
		passkey_agent_free(agent);
	}
}

static int call_passkey_agent(DBusConnection *conn,
				struct passkey_agent *agent, int dev,
				const char *path, bdaddr_t *sba,
				bdaddr_t *dba)
{
	DBusMessage *message = NULL;
	struct pending_agent_request *req = NULL;
	char bda[18];
	char *ptr = bda;

	ba2str(dba, bda);

	if (!agent) {
		debug("call_passkey_agent(): no agent registered");
		goto failed;
	}

	debug("Calling PasskeyAgent.Request: name=%s, path=%s",
						agent->name, agent->path);

	message = dbus_message_new_method_call(agent->name, agent->path,
					"org.bluez.PasskeyAgent", "Request");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		goto failed;
	}

	req = malloc(sizeof(struct pending_agent_request));
	if (!req)
		goto failed;
	memset(req, 0, sizeof(struct pending_agent_request));
	req->dev = dev;
	bacpy(&req->sba, sba);
	bacpy(&req->bda, dba);
	req->agent = agent;
	req->path = strdup(path);
	if (!req->path)
		goto failed;

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(conn, message,
				&req->call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		goto failed;
	}

	dbus_pending_call_set_notify(req->call, passkey_agent_reply, req, NULL);

	agent->pending_requests = slist_append(agent->pending_requests, req);

	dbus_message_unref(message);

	return 0;

failed:
	if (message)
		dbus_message_unref(message);

	if (req) {
		free(req->path);
		free(req);
	}

	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, dba);

	return -1;
}

DBusHandlerResult handle_security_method(DBusConnection *conn, DBusMessage *msg, void *data)
{
	service_handler_func_t handler;

	handler = find_service_handler(sec_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return error_unknown_method(conn, msg);
}

int handle_passkey_request(DBusConnection *conn, int dev, const char *path,
					bdaddr_t *sba, bdaddr_t *dba)
{
	struct passkey_agent *agent = default_agent;
	struct hci_dbus_data *adapter = NULL;
	struct slist *l;
	char addr[18];
	void *data;

	dbus_connection_get_object_path_data(conn, path, &data);

	if (!data)
		goto done;

	adapter = data;

	ba2str(dba, addr);

	for (l = adapter->passkey_agents; l != NULL; l = l->next) {
		struct passkey_agent *a = l->data;
		if (a != default_agent && slist_length(a->pending_requests) >= 1)
			continue;
		if (!strcmp(a->addr, addr)) {
			agent = a;
			break;
		}
	}

done:
	return call_passkey_agent(conn, agent, dev, path, sba, dba);
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

	send_reply_and_unref(req->agent->conn, message);

	debug("PasskeyAgent.Request(%s, %s) was canceled", req->path, address);

	dbus_pending_call_cancel(req->call);
	dbus_pending_call_unref(req->call);
	free(req->path);
	free(req);
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

	send_reply_and_unref(agent->conn, message);

	if (agent == default_agent)
		name_listener_remove(agent->conn, agent->name,
				(name_cb_t)default_agent_exited, NULL);
	else {
		struct passkey_agent ref;

		/* Only remove the name listener if there are no more agents for this name */
		memset(&ref, 0, sizeof(ref));
		ref.name = agent->name;
		ref.addr = NULL;
		ref.path = NULL;
		if (!slist_find(agent->pdata->passkey_agents, &ref, (cmp_func_t)agent_cmp))
			name_listener_remove(agent->conn, ref.name,
					(name_cb_t)agent_exited, agent->pdata);
	}
}

void release_default_agent(void)
{
	if (!default_agent)
		return;

	passkey_agent_free(default_agent);
	default_agent = NULL;
}

void release_passkey_agents(struct hci_dbus_data *pdata, bdaddr_t *bda)
{
	struct slist *l, *next;

	for (l = pdata->passkey_agents; l != NULL; l = next) {
		struct passkey_agent *agent = l->data;
		next = l->next;
		
		if (bda && agent->addr) {
			bdaddr_t tmp;
			str2ba(agent->addr, &tmp);
			if (bacmp(&tmp, bda))
				continue;
		}

		pdata->passkey_agents = slist_remove(pdata->passkey_agents, agent);
		passkey_agent_free(agent);
	}
}

void cancel_passkey_agent_requests(struct slist *agents, const char *path,
					bdaddr_t *addr)
{
	struct slist *l, *next;

	/* First check the default agent */
	for (l = default_agent ? default_agent->pending_requests : NULL; l != NULL; l = next) {
		struct pending_agent_request *req = l->data;
		next = l->next;
		if (!strcmp(path, req->path) && (!addr || !bacmp(addr, &req->bda))) {
			send_cancel_request(req);
			default_agent->pending_requests = slist_remove(default_agent->pending_requests,
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
				agent->pending_requests = slist_remove(agent->pending_requests, req);
			}
		}
	}
}
