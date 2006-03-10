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

#include <dbus/dbus.h>

#include "dbus.h"
#include "hcid.h"

static struct passkey_agent *default_agent = NULL;

static void default_agent_exited(const char *name, void *data)
{
	debug("%s exited without unregistering the default passkey agent", name);

	if (!default_agent || strcmp(name, default_agent->name)) {
		/* This should never happen (there's a bug in the code if it does */
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

	if (default_agent) {
		reply = error_passkey_agent_already_exists(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		goto done;
	}

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		reply = error_invalid_arguments(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		goto done;
	}

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

	reply = dbus_message_new_method_return();
	if (!reply)
		goto need_memory;

	name_listener_add(conn, default_agent->name,
			(name_cb_t)default_agent_exited, NULL);

	info("Default passkey agent (%s, %s) registered",
			default_agent->name, default_agent->path);

done:
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
	char *name, *path;

	if (!default_agent) {
		reply = error_does_not_exist(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		goto done;
	}

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_STRING, &path,
				DBUS_TYPE_INVALID)) {
		reply = error_invalid_arguments(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		goto done;
	}

	if (strcmp(name, default_agent->name) || strcmp(path, default_agent->path)) {
		reply = error_does_not_exist(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		goto done;
	}

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

done:
	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static struct service_data sec_services[] = {
	{ "RegisterDefault",	register_default_agent		},
	{ "UnregisterDefault",	unregister_default_agent	},
	{ NULL, NULL }
};

DBusHandlerResult handle_security_method(DBusConnection *conn, DBusMessage *msg, void *data)
{
	service_handler_func_t *handler;

	handler = find_service_handler(sec_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

