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

#define TIMEOUT (30 * 1000)		/* 30 seconds */

struct pin_request {
	int dev;
	bdaddr_t sba;
	bdaddr_t bda;
};

static struct passkey_agent *default_agent = NULL;

static void default_agent_exited(const char *name, void *data)
{
	debug("%s exited without unregistering the default passkey agent", name);

	if (!default_agent || strcmp(name, default_agent->name)) {
		/* This should never happen (there's a bug in the code if it does) */
		debug("default_agent_exited: mismatch with actual default_agent");
		return;
	}

	free(default_agent->path);
	free(default_agent->name);
	free(default_agent);
	default_agent = NULL;
}

static void passkey_agent_free(struct passkey_agent *agent)
{
	if (!agent)
		return;
	if (agent->name)
		free(agent->name);
	if (agent->path)
		free(agent->path);
	if (agent->addr)
		free(agent->addr);
	free(agent);
}

static struct passkey_agent *passkey_agent_new(const char *name,
					const char *path, const char *addr)
{
	struct passkey_agent *agent;

	agent = malloc(sizeof(struct passkey_agent));
	if (!agent)
		return NULL;

	memset(agent, 0, sizeof(struct passkey_agent));

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

	return agent;

mem_fail:
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

static void agent_exited(const char *name, struct hci_dbus_data *adapter)
{
	struct slist *cur, *next;

	debug("Passkey agent %s exited without calling Unregister", name);

	for (cur = adapter->passkey_agents; cur != NULL; cur = next) {
		struct passkey_agent *agent = cur->data;

		next = cur->next;

		if (strcmp(agent->name, name))
			continue;

		adapter->passkey_agents = slist_remove(adapter->passkey_agents, agent);
		passkey_agent_free(agent);
	}
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

	ref.name = (char *)dbus_message_get_sender(msg);
	ref.addr = addr;
	ref.path = path;

	if (slist_find(adapter->passkey_agents, &ref, (cmp_func_t)agent_cmp))
		return error_passkey_agent_already_exists(conn, msg);

	agent = passkey_agent_new(ref.name, path, addr);
	if (!agent)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		passkey_agent_free(agent);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	/* Only add a name listener if there isn't one already for this name */
	ref.addr = NULL;
	ref.path = NULL;
	if (!slist_find(adapter->passkey_agents, &ref, (cmp_func_t)agent_cmp))
		name_listener_add(conn, ref.name, (name_cb_t)agent_exited, adapter);

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

	ref.name = (char *)dbus_message_get_sender(msg);
	ref.path = path;
	ref.addr = addr;

	match = slist_find(adapter->passkey_agents, &ref, (cmp_func_t)agent_cmp);
	if (!match)
		return error_passkey_agent_does_not_exist(conn, msg);

	agent = match->data;

	adapter->passkey_agents = slist_remove(adapter->passkey_agents, agent);
	passkey_agent_free(agent);

	/* Only remove the name listener if there are no more agents for this name */
	ref.addr = NULL;
	ref.path = NULL;
	if (!slist_find(adapter->passkey_agents, &ref, (cmp_func_t)agent_cmp))
		name_listener_remove(conn, ref.name, (name_cb_t)agent_exited, adapter);

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

	default_agent = passkey_agent_new(dbus_message_get_sender(msg), path, NULL);
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
	struct pin_request *req = (struct pin_request *) user_data;
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
		hci_send_cmd(req->dev, OGF_LINK_CTL,
				OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(message, &err,
				DBUS_TYPE_STRING, &pin,
				DBUS_TYPE_INVALID)) {
		error("Wrong passkey reply signature: %s", err.message);
		dbus_error_free(&err);
		hci_send_cmd(req->dev, OGF_LINK_CTL,
				OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);
		goto done;
	}

	len = strlen(pin);

	if (len > 16) {
		error("Too long (%d char) passkey from handler", len);
		goto done;
	}

	set_pin_length(&req->sba, len);

	memset(&pr, 0, sizeof(pr));
	bacpy(&pr.bdaddr, &req->bda);
	memcpy(pr.pin_code, pin, len);
	pr.pin_len = len;
	hci_send_cmd(req->dev, OGF_LINK_CTL,
			OCF_PIN_CODE_REPLY, PIN_CODE_REPLY_CP_SIZE, &pr);

done:
	if (message)
		dbus_message_unref(message);

	dbus_pending_call_unref(call);
}

static int call_passkey_agent(struct passkey_agent *agent, int dev, const char *path,
				bdaddr_t *sba, bdaddr_t *dba)
{
	DBusMessage *message = NULL;
	DBusPendingCall *pending = NULL;
	DBusConnection *connection;
	struct pin_request *req;
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

	req = malloc(sizeof(*req));
	if (!req)
		goto failed;
	req->dev = dev;
	bacpy(&req->sba, sba);
	bacpy(&req->bda, dba);

	connection = get_dbus_connection();

	dbus_message_append_args(message,
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
				&pending, TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		goto failed;
	}

	dbus_pending_call_set_notify(pending, passkey_agent_reply, req, free);

	dbus_message_unref(message);

	return 0;

failed:
	if (message)
		dbus_message_unref(message);

	hci_send_cmd(dev, OGF_LINK_CTL, OCF_PIN_CODE_NEG_REPLY, 6, dba);

	return -1;
}

DBusHandlerResult handle_security_method(DBusConnection *conn, DBusMessage *msg, void *data)
{
	service_handler_func_t handler;

	handler = find_service_handler(sec_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

int handle_passkey_request(int dev, const char *path, bdaddr_t *sba, bdaddr_t *dba)
{
	struct passkey_agent *agent = default_agent;
	struct hci_dbus_data *adapter = NULL;
	struct slist *l;
	char addr[18];
	void *data;

	dbus_connection_get_object_path_data(get_dbus_connection(), path, &data);

	if (!data)
		goto done;

	adapter = data;

	ba2str(dba, addr);

	for (l = adapter->passkey_agents; l != NULL; l = l->next) {
		struct passkey_agent *a = l->data;
		if (!strcmp(a->addr, addr)) {
			agent = a;
			break;
		}
	}

done:
	return call_passkey_agent(agent, dev, path, sba, dba);
}
