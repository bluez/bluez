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

	default_agent = malloc(sizeof(struct passkey_agent));
	if (!default_agent)
		goto need_memory;

	memset(default_agent, 0, sizeof(struct passkey_agent));

	default_agent->name = strdup(dbus_message_get_sender(msg));
	if (!default_agent->name)
		goto need_memory;

	default_agent->path = strdup(path);
	if (!default_agent->path)
		goto need_memory;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		goto need_memory;

	name_listener_add(conn, default_agent->name,
			(name_cb_t)default_agent_exited, NULL);

	info("Default passkey agent (%s, %s) registered",
			default_agent->name, default_agent->path);

	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;

need_memory:
	if (default_agent) {
		if (default_agent->name)
			free(default_agent->name);
		if (default_agent->path)
			free(default_agent->path);
		free(default_agent);
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

	free(default_agent->path);
	free(default_agent->name);
	free(default_agent);
	default_agent = NULL;

	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static struct service_data sec_services[] = {
	{ "RegisterDefaultPasskeyAgent",	register_default_agent		},
	{ "UnregisterDefaultPasskeyAgent",	unregister_default_agent	},
	{ NULL, NULL }
};

static void passkey_agent_reply(DBusPendingCall *call, void *user_data)
{
	struct pin_request *req = (struct pin_request *) user_data;
	pin_code_reply_cp pr;
	DBusMessage *message;
	DBusMessageIter iter;
	int arg_type;
	int msg_type;
	size_t len;
	char *pin;
	const char *error_msg;

	message = dbus_pending_call_steal_reply(call);

	if (!message)
		goto done;

	msg_type = dbus_message_get_type(message);
	dbus_message_iter_init(message, &iter);

	if (msg_type == DBUS_MESSAGE_TYPE_ERROR) {
		dbus_message_iter_get_basic(&iter, &error_msg);

		/* handling WRONG_ARGS_ERROR, DBUS_ERROR_NO_REPLY, DBUS_ERROR_SERVICE_UNKNOWN */
		error("%s: %s", dbus_message_get_error_name(message), error_msg);
		hci_send_cmd(req->dev, OGF_LINK_CTL,
					OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);

		goto done;
	}

	/* check signature */
	arg_type = dbus_message_iter_get_arg_type(&iter);
	if (arg_type != DBUS_TYPE_STRING) {
		error("Wrong reply signature: expected PIN");
		hci_send_cmd(req->dev, OGF_LINK_CTL,
					OCF_PIN_CODE_NEG_REPLY, 6, &req->bda);
	} else {
		dbus_message_iter_get_basic(&iter, &pin);
		len = strlen(pin);

		set_pin_length(&req->sba, len);

		memset(&pr, 0, sizeof(pr));
		bacpy(&pr.bdaddr, &req->bda);
		memcpy(pr.pin_code, pin, len);
		pr.pin_len = len;
		hci_send_cmd(req->dev, OGF_LINK_CTL,
			OCF_PIN_CODE_REPLY, PIN_CODE_REPLY_CP_SIZE, &pr);
	}

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

	ba2str(sba, bda);

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

int call_default_passkey_agent(int dev, const char *path, bdaddr_t *sba, bdaddr_t *dba)
{
	return call_passkey_agent(default_agent, dev, path, sba, dba);
}
