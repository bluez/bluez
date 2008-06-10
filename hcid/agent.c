/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2008  Nokia Corporation
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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
#include <gdbus.h>

#include "hcid.h"
#include "dbus-common.h"
#include "dbus-service.h"
#include "dbus-error.h"
#include "error.h"
#include "adapter.h"
#include "dbus-hci.h"
#include "device.h"
#include "agent.h"

#define REQUEST_TIMEOUT (60 * 1000)		/* 60 seconds */
#define AGENT_TIMEOUT (10 * 60 * 1000)		/* 10 minutes */

typedef enum {
	AGENT_REQUEST_PASSKEY,
	AGENT_REQUEST_CONFIRMATION,
	AGENT_REQUEST_PINCODE,
	AGENT_REQUEST_AUTHORIZE,
	AGENT_REQUEST_CONFIRM_MODE
} agent_request_type_t;

struct agent {
	struct adapter *adapter;
	char *name;
	char *path;
	uint8_t capability;
	struct agent_request *request;
	int exited;
	agent_remove_cb remove_cb;
	void *remove_cb_data;
	guint listener_id;
};

struct agent_request {
	agent_request_type_t type;
	struct agent *agent;
	DBusPendingCall *call;
	void *cb;
	void *user_data;
};

static DBusConnection *connection = NULL;

static void agent_release(struct agent *agent)
{
	DBusMessage *message;

	debug("Releasing agent %s, %s", agent->name, agent->path);

	if (agent->request)
		agent_cancel(agent);

	message = dbus_message_new_method_call(agent->name, agent->path,
			"org.bluez.Agent", "Release");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	dbus_message_set_no_reply(message, TRUE);

	dbus_connection_send(connection, message, NULL);

	dbus_message_unref(message);
}

static int send_cancel_request(struct agent_request *req)
{
	DBusMessage *message;

	message = dbus_message_new_method_call(req->agent->name, req->agent->path,
						"org.bluez.Agent", "Cancel");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return -ENOMEM;
	}

	dbus_message_set_no_reply(message, TRUE);

	dbus_connection_send(connection, message, NULL);

	dbus_message_unref(message);

	return 0;
}

static void agent_request_free(struct agent_request *req)
{
	if (req->call)
		dbus_pending_call_unref(req->call);
	if (req->agent && req->agent->request)
		req->agent->request = NULL;
	g_free(req);
}

static void agent_exited(void *user_data)
{
	struct agent *agent = user_data;

	debug("Agent exited without calling Unregister");

	agent_destroy(agent, TRUE);
}

static void agent_free(struct agent *agent)
{
	if (!agent)
		return;

	if (agent->remove_cb)
		agent->remove_cb(agent, agent->remove_cb_data);

	if (agent->request) {
		DBusError err;
		agent_pincode_cb pincode_cb;
		agent_cb cb;

		dbus_error_init(&err);
		dbus_set_error_const(&err, "org.bluez.Error.Failed", "Canceled");

		switch (agent->request->type) {
		case AGENT_REQUEST_PINCODE:
			pincode_cb = agent->request->cb;
			pincode_cb(agent, &err, NULL, agent->request->user_data);
			break;
		default:
			cb = agent->request->cb;
			cb(agent, &err, agent->request->user_data);
		}

		dbus_error_free(&err);

		agent_cancel(agent);
	}

	if (!agent->exited) {
		g_dbus_remove_watch(connection, agent->listener_id);
		agent_release(agent);
	}

	g_free(agent->name);
	g_free(agent->path);

	g_free(agent);
}

struct agent *agent_create(struct adapter *adapter, const char *name,
				const char *path, uint8_t capability,
				agent_remove_cb cb, void *remove_cb_data)
{
	struct agent *agent;

	if (adapter->agent && g_str_equal(adapter->agent->name, name))
		return NULL;

	agent = g_new0(struct agent, 1);

	agent->adapter = adapter;
	agent->name = g_strdup(name);
	agent->path = g_strdup(path);
	agent->capability = capability;
	agent->remove_cb = cb;
	agent->remove_cb_data = remove_cb_data;

	agent->listener_id = g_dbus_add_disconnect_watch(connection, name,
							agent_exited, agent,
							NULL);

	return agent;
}

int agent_destroy(struct agent *agent, gboolean exited)
{
	agent->exited = exited;
	agent_free(agent);
	return 0;
}

static struct agent_request *agent_request_new(struct agent *agent,
						agent_request_type_t type,
						void *cb,
						void *user_data)
{
	struct agent_request *req;

	req = g_new0(struct agent_request, 1);

	req->agent = agent;
	req->type = type;
	req->cb = cb;
	req->user_data = user_data;

	return req;
}

int agent_cancel(struct agent *agent)
{
	if (!agent->request)
		return -EINVAL;

	if (agent->request->call)
		dbus_pending_call_cancel(agent->request->call);

	if (!agent->exited)
		send_cancel_request(agent->request);

	agent_request_free(agent->request);
	agent->request = NULL;

	return 0;
}

static DBusPendingCall *agent_call_authorize(struct agent *agent,
						const char *device_path,
						const char *uuid)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(agent->name, agent->path,
				"org.bluez.Agent", "Authorize");
	if (!message) {
		error("Couldn't allocate D-Bus message");
		return NULL;
	}

	dbus_message_append_args(message,
				DBUS_TYPE_OBJECT_PATH, &device_path,
				DBUS_TYPE_STRING, &uuid,
				DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
					&call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);
	return call;
}

static void simple_agent_reply(DBusPendingCall *call, void *user_data)
{
	struct agent_request *req = user_data;
	struct agent *agent = req->agent;
	DBusMessage *message;
	DBusError err;
	agent_cb cb = req->cb;

	/* steal_reply will always return non-NULL since the callback
	 * is only called after a reply has been received */
	message = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, message)) {

		error("Agent replied with an error: %s, %s",
				err.name, err.message);

		cb(agent, &err, req->user_data);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(message, &err, DBUS_TYPE_INVALID)) {
		error("Wrong reply signature: %s", err.message);
		cb(agent, &err, req->user_data);
		dbus_error_free(&err);
		goto done;
	}

	cb(agent, NULL, req->user_data);
done:
	dbus_message_unref(message);

	agent->request = NULL;
	agent_request_free(req);
}

int agent_authorize(struct agent *agent,
			const char *path,
			const char *uuid,
			agent_cb cb,
			void *user_data)
{
	struct agent_request *req;

	if (agent->request)
		return -EBUSY;

	req = agent_request_new(agent, AGENT_REQUEST_AUTHORIZE, cb, user_data);

	req->call = agent_call_authorize(agent, path, uuid);
	if (!req->call) {
		agent_request_free(req);
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_pending_call_set_notify(req->call, simple_agent_reply, req, NULL);
	agent->request = req;

	debug("authorize request was sent for %s", path);

	return 0;
}

static DBusPendingCall *pincode_request_new(struct agent *agent,
						const char *device_path,
						dbus_bool_t numeric)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(agent->name, agent->path,
					"org.bluez.Agent", "RequestPinCode");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return NULL;
	}

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &device_path,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
					&call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);
	return call;
}

static void pincode_reply(DBusPendingCall *call, void *user_data)
{
	struct agent_request *req = user_data;
	struct agent *agent = req->agent;
	struct adapter *adapter = agent->adapter;
	agent_pincode_cb cb = req->cb;
	DBusMessage *message;
	DBusError err;
	bdaddr_t sba;
	size_t len;
	char *pin;

	/* steal_reply will always return non-NULL since the callback
	 * is only called after a reply has been received */
	message = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, message)) {
		error("Agent replied with an error: %s, %s",
				err.name, err.message);

		cb(agent, &err, NULL, req->user_data);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(message, &err,
				DBUS_TYPE_STRING, &pin,
				DBUS_TYPE_INVALID)) {
		error("Wrong passkey reply signature: %s", err.message);
		cb(agent, &err, NULL, req->user_data);
		dbus_error_free(&err);
		goto done;
	}

	len = strlen(pin);

	dbus_error_init(&err);
	if (len > 16 || len < 1) {
		error("Invalid passkey length from handler");
		dbus_set_error_const(&err, "org.bluez.Error.InvalidArgs",
					"Invalid passkey length");
		cb(agent, &err, NULL, req->user_data);
		dbus_error_free(&err);
		goto done;
	}

	str2ba(adapter->address, &sba);

	set_pin_length(&sba, len);

	cb(agent, NULL, pin, req->user_data);

done:
	if (message)
		dbus_message_unref(message);

	dbus_pending_call_cancel(req->call);
	agent_request_free(req);
}

int agent_request_pincode(struct agent *agent, struct device *device,
				agent_pincode_cb cb, void *user_data)
{
	struct agent_request *req;

	if (agent->request)
		return -EBUSY;

	req = agent_request_new(agent, AGENT_REQUEST_PINCODE, cb, user_data);

	req->call = pincode_request_new(agent, device->path, FALSE);
	if (!req->call)
		goto failed;

	dbus_pending_call_set_notify(req->call, pincode_reply, req, NULL);

	agent->request = req;

	return 0;

failed:
	g_free(req);
	return -1;
}

static DBusPendingCall *confirm_mode_change_request_new(struct agent *agent,
							const char *mode)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(agent->name, agent->path,
				"org.bluez.Agent", "ConfirmModeChange");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return NULL;
	}

	dbus_message_append_args(message,
				DBUS_TYPE_STRING, &mode,
				DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
					&call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);

	return call;
}

int agent_confirm_mode_change(struct agent *agent, const char *new_mode,
				agent_cb cb, void *user_data)
{
	struct agent_request *req;

	if (agent->request)
		return -EBUSY;

	debug("Calling Agent.ConfirmModeChange: name=%s, path=%s, mode=%s",
			agent->name, agent->path, new_mode);

	req = agent_request_new(agent, AGENT_REQUEST_CONFIRM_MODE,
				cb, user_data);

	req->call = confirm_mode_change_request_new(agent, new_mode);
	if (!req->call)
		goto failed;

	dbus_pending_call_set_notify(req->call, simple_agent_reply, req, NULL);

	agent->request = req;

	return 0;

failed:
	agent_request_free(req);
	return -1;
}

static DBusPendingCall *passkey_request_new(struct agent *agent,
						const char *device_path)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(agent->name, agent->path,
					"org.bluez.Agent", "RequestPasskey");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return NULL;
	}

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &device_path,
					DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
					&call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);
	return call;
}

static void passkey_reply(DBusPendingCall *call, void *user_data)
{
	struct agent_request *req = user_data;
	struct agent *agent = req->agent;
	agent_passkey_cb cb = req->cb;
	DBusMessage *message;
	DBusError err;
	uint32_t passkey;

	/* steal_reply will always return non-NULL since the callback
	 * is only called after a reply has been received */
	message = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, message)) {
		error("Agent replied with an error: %s, %s",
				err.name, err.message);
		cb(agent, &err, 0, req->user_data);
		dbus_error_free(&err);
		goto done;
	}

	dbus_error_init(&err);
	if (!dbus_message_get_args(message, &err,
				DBUS_TYPE_UINT32, &passkey,
				DBUS_TYPE_INVALID)) {
		error("Wrong passkey reply signature: %s", err.message);
		cb(agent, &err, 0, req->user_data);
		dbus_error_free(&err);
		goto done;
	}

	cb(agent, NULL, passkey, req->user_data);

done:
	if (message)
		dbus_message_unref(message);

	dbus_pending_call_cancel(req->call);
	agent_request_free(req);
}

int agent_request_passkey(struct agent *agent, struct device *device,
				agent_passkey_cb cb, void *user_data)
{
	struct agent_request *req;

	if (agent->request)
		return -EBUSY;

	debug("Calling Agent.RequestPasskey: name=%s, path=%s",
			agent->name, agent->path);

	req = agent_request_new(agent, AGENT_REQUEST_PASSKEY, cb, user_data);

	req->call = passkey_request_new(agent, device->path);
	if (!req->call)
		goto failed;

	dbus_pending_call_set_notify(req->call, passkey_reply, req, NULL);

	agent->request = req;

	return 0;

failed:
	agent_request_free(req);
	return -1;
}

static DBusPendingCall *confirmation_request_new(struct agent *agent,
						const char *device_path,
						uint32_t passkey)
{
	DBusMessage *message;
	DBusPendingCall *call;

	message = dbus_message_new_method_call(agent->name, agent->path,
				"org.bluez.Agent", "RequestConfirmation");
	if (message == NULL) {
		error("Couldn't allocate D-Bus message");
		return NULL;
	}

	dbus_message_append_args(message,
				DBUS_TYPE_OBJECT_PATH, &device_path,
				DBUS_TYPE_UINT32, &passkey,
				DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(connection, message,
					&call, REQUEST_TIMEOUT) == FALSE) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return NULL;
	}

	dbus_message_unref(message);

	return call;
}

int agent_request_confirmation(struct agent *agent, struct device *device,
				uint32_t passkey, agent_cb cb,
				void *user_data)
{
	struct agent_request *req;

	if (agent->request)
		return -EBUSY;

	debug("Calling Agent.RequestConfirmation: name=%s, path=%s, passkey=%06u",
			agent->name, agent->path, passkey);

	req = agent_request_new(agent, AGENT_REQUEST_CONFIRMATION, cb,
				user_data);

	req->call = confirmation_request_new(agent, device->path, passkey);
	if (!req->call)
		goto failed;

	dbus_pending_call_set_notify(req->call, simple_agent_reply, req, NULL);

	agent->request = req;

	return 0;

failed:
	agent_request_free(req);
	return -1;
}

int agent_display_passkey(struct agent *agent, struct device *device,
				uint32_t passkey)
{
	DBusMessage *message;

	message = dbus_message_new_method_call(agent->name, agent->path,
				"org.bluez.Agent", "DisplayPasskey");
	if (!message) {
		error("Couldn't allocate D-Bus message");
		return -1;
	}

	dbus_message_append_args(message,
				DBUS_TYPE_OBJECT_PATH, &device->path,
				DBUS_TYPE_UINT32, &passkey,
				DBUS_TYPE_INVALID);

	if (!g_dbus_send_message(connection, message)) {
		error("D-Bus send failed");
		dbus_message_unref(message);
		return -1;
	}

	return 0;
}

uint8_t agent_get_io_capability(struct agent *agent)
{
	return agent->capability;
}

gboolean agent_matches(struct agent *agent, const char *name, const char *path)
{
	if (g_str_equal(agent->name, name) && g_str_equal(agent->path, path))
		return TRUE;

	return FALSE;
}

void agent_exit(void)
{
	dbus_connection_unref(connection);
}

void agent_init(void)
{
	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
}
