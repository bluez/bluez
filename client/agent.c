/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Intel Corporation. All rights reserved.
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
#include <readline/readline.h>
#include <gdbus.h>

#include "display.h"
#include "agent.h"

#define AGENT_PATH "/org/bluez/agent"
#define AGENT_INTERFACE "org.bluez.Agent1"

static gboolean agent_registered = FALSE;
static const char *agent_capability = NULL;
static DBusMessage *pending_message = NULL;

dbus_bool_t agent_completion(void)
{
	if (!pending_message)
		return FALSE;

	return TRUE;
}

static void pincode_response(DBusConnection *conn, const char *input)
{
	g_dbus_send_reply(conn, pending_message, DBUS_TYPE_STRING, &input,
							DBUS_TYPE_INVALID);
}

static void confirm_response(DBusConnection *conn, const char *input)
{
	if (!strcmp(input, "yes"))
		g_dbus_send_reply(conn, pending_message, DBUS_TYPE_INVALID);
	else if (!strcmp(input, "no"))
		g_dbus_send_error(conn, pending_message,
					"org.bluez.Error.Rejected", NULL);
	else
		g_dbus_send_error(conn, pending_message,
					"org.bluez.Error.Canceled", NULL);
}

dbus_bool_t agent_input(DBusConnection *conn, const char *input)
{
	const char *member;

	rl_clear_message();

	if (!pending_message)
		return FALSE;

	member = dbus_message_get_member(pending_message);

	if (!strcmp(member, "RequestPinCode"))
		pincode_response(conn, input);
	else if (!strcmp(member, "RequestConfirmation"))
		confirm_response(conn, input);
	else if (!strcmp(member, "RequestAuthorization"))
		confirm_response(conn, input);
	else if (!strcmp(member, "AuthorizeService"))
		confirm_response(conn, input);
	else
		g_dbus_send_error(conn, pending_message,
					"org.bluez.Error.Canceled", NULL);

	dbus_message_unref(pending_message);
	pending_message = NULL;

	return TRUE;
}

static DBusMessage *release_agent(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	if (pending_message)
		rl_clear_message();

	agent_registered = FALSE;
	agent_capability = NULL;

	rl_printf("Agent released\n");

	if (pending_message) {
		dbus_message_unref(pending_message);
		pending_message = NULL;
	}

	g_dbus_unregister_interface(conn, AGENT_PATH, AGENT_INTERFACE);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *request_pincode(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *device;

	rl_printf("Request PIN code\n");

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &device,
							DBUS_TYPE_INVALID);

	rl_message("Enter PIN code: ");

	pending_message = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *request_confirmation(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *device;
	dbus_uint32_t passkey;
	char *str;

	rl_printf("Request confirmation\n");

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &device,
				DBUS_TYPE_UINT32, &passkey, DBUS_TYPE_INVALID);

	str = g_strdup_printf("Confirm passkey %06u (yes/no): ", passkey);
	rl_message(str);
	g_free(str);

	pending_message = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *request_authorization(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *device;

	rl_printf("Request authorization\n");

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &device,
							DBUS_TYPE_INVALID);

	rl_message("Accept pairing (yes/no): ");

	pending_message = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *authorize_service(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	const char *device, *uuid;
	char *str;

	rl_printf("Authorize service\n");

	dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &device,
				DBUS_TYPE_STRING, &uuid, DBUS_TYPE_INVALID);

	str = g_strdup_printf("Authorize service %s (yes/no): ", uuid);
	rl_message(str);
	g_free(str);

	pending_message = dbus_message_ref(msg);

	return NULL;
}

static DBusMessage *cancel_request(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	rl_clear_message();

	rl_printf("Request canceled\n");

	dbus_message_unref(pending_message);
	pending_message = NULL;

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_METHOD("Release", NULL, NULL, release_agent) },
	{ GDBUS_ASYNC_METHOD("RequestPinCode",
			GDBUS_ARGS({ "device", "o" }),
			GDBUS_ARGS({ "pincode", "s" }), request_pincode) },
	{ GDBUS_ASYNC_METHOD("RequestConfirmation",
			GDBUS_ARGS({ "device", "o" }, { "passkey", "u" }),
			NULL, request_confirmation) },
	{ GDBUS_ASYNC_METHOD("RequestAuthorization",
			GDBUS_ARGS({ "device", "o" }),
			NULL, request_authorization) },
	{ GDBUS_ASYNC_METHOD("AuthorizeService",
			GDBUS_ARGS({ "device", "o" }, { "uuid", "s" }),
			NULL,  authorize_service) },
	{ GDBUS_METHOD("Cancel", NULL, NULL, cancel_request) },
	{ }
};

static void register_agent_setup(DBusMessageIter *iter, void *user_data)
{
	const char *path = AGENT_PATH;
	const char *capability = agent_capability;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &capability);
}

static void register_agent_reply(DBusMessage *message, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == FALSE) {
		agent_registered = TRUE;
		rl_printf("Agent registered\n");
	} else {
		rl_printf("Failed to register agent: %s\n", error.name);
		dbus_error_free(&error);

		if (g_dbus_unregister_interface(conn, AGENT_PATH,
						AGENT_INTERFACE) == FALSE)
			rl_printf("Failed to unregister agent object\n");
	}
}

void agent_register(DBusConnection *conn, GDBusProxy *manager,
						const char *capability)

{
	if (agent_registered == TRUE) {
		rl_printf("Agent is already registered\n");
		return;
	}

	agent_capability = capability;

	if (g_dbus_register_interface(conn, AGENT_PATH,
					AGENT_INTERFACE, methods,
					NULL, NULL, NULL, NULL) == FALSE) {
		rl_printf("Failed to register agent object\n");
		return;
	}

	if (g_dbus_proxy_method_call(manager, "RegisterAgent",
						register_agent_setup,
						register_agent_reply,
						conn, NULL) == FALSE) {
		rl_printf("Failed to call register agent method\n");
		return;
	}

	agent_capability = NULL;
}

static void unregister_agent_setup(DBusMessageIter *iter, void *user_data)
{
	const char *path = AGENT_PATH;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static void unregister_agent_reply(DBusMessage *message, void *user_data)
{
	DBusConnection *conn = user_data;
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, message) == FALSE) {
		agent_registered = FALSE;
		agent_capability = NULL;
		rl_printf("Agent unregistered\n");

		if (g_dbus_unregister_interface(conn, AGENT_PATH,
						AGENT_INTERFACE) == FALSE)
			rl_printf("Failed to unregister agent object\n");
	} else {
		rl_printf("Failed to unregister agent: %s\n", error.name);
		dbus_error_free(&error);
	}
}

void agent_unregister(DBusConnection *conn, GDBusProxy *manager)
{
	if (agent_registered == FALSE) {
		rl_printf("No agent is registered\n");
		return;
	}

	if (g_dbus_proxy_method_call(manager, "UnregisterAgent",
						unregister_agent_setup,
						unregister_agent_reply,
						conn, NULL) == FALSE) {
		rl_printf("Failed to call unregister agent method\n");
		return;
	}
}
