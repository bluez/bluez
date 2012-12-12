/*
 *
 *  D-Bus helper library
 *
 *  Copyright (C) 2004-2011  Marcel Holtmann <marcel@holtmann.org>
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

#include <glib.h>
#include <dbus/dbus.h>

#include "gdbus.h"

struct GDBusClient {
	gint ref_count;
	DBusConnection *dbus_conn;
	char *service_name;
	char *unique_name;
	char *base_path;
	char *match_rules[4];
	DBusPendingCall *pending_call;
	GDBusWatchFunction connect_func;
	void *connect_data;
	GDBusWatchFunction disconn_func;
	void *disconn_data;
	GDBusMessageFunction signal_func;
	void *signal_data;
};

static void modify_match_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError error;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE)
		dbus_error_free(&error);

	dbus_message_unref(reply);
}

static gboolean modify_match(DBusConnection *conn, const char *member,
							const char *rule)
{
	DBusMessage *msg;
	DBusPendingCall *call;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
					DBUS_INTERFACE_DBUS, member);
	if (!msg)
		return FALSE;

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &rule,
						DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(conn, msg, &call, -1) == FALSE) {
		dbus_message_unref(msg);
		return FALSE;
	}

	dbus_pending_call_set_notify(call, modify_match_reply, NULL, NULL);
	dbus_pending_call_unref(call);

	dbus_message_unref(msg);

	return TRUE;
}

static void get_name_owner_reply(DBusPendingCall *call, void *user_data)
{
	GDBusClient *client = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError error;
	const char *name;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply) == TRUE) {
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_get_args(reply, NULL, DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID) == FALSE)
		goto done;

	g_free(client->unique_name);
	client->unique_name = g_strdup(name);

	if (client->connect_func)
		client->connect_func(client->dbus_conn, client->connect_data);

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(client->pending_call);
	client->pending_call = NULL;
}

static void get_name_owner(GDBusClient *client, const char *name)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
					DBUS_INTERFACE_DBUS, "GetNameOwner");
	if (!msg)
		return;

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &name,
						DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(client->dbus_conn, msg,
					&client->pending_call, -1) == FALSE) {
		dbus_message_unref(msg);
		return;
	}

	dbus_pending_call_set_notify(client->pending_call,
					get_name_owner_reply, client, NULL);

	dbus_message_unref(msg);
}

static DBusHandlerResult message_filter(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	GDBusClient *client = user_data;
	const char *sender;

	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_SIGNAL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	sender = dbus_message_get_sender(message);

	if (g_str_equal(sender, DBUS_SERVICE_DBUS) == TRUE) {
		const char *interface, *member;
		const char *name, *old, *new;

		interface = dbus_message_get_interface(message);

		if (g_str_equal(interface, DBUS_INTERFACE_DBUS) == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		member = dbus_message_get_member(message);

		if (g_str_equal(member, "NameOwnerChanged") == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		if (dbus_message_get_args(message, NULL,
						DBUS_TYPE_STRING, &name,
						DBUS_TYPE_STRING, &old,
						DBUS_TYPE_STRING, &new,
						DBUS_TYPE_INVALID) == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		if (g_str_equal(name, client->service_name) == FALSE)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		if (*new == '\0') {
			if (client->disconn_func)
				client->disconn_func(client->dbus_conn,
							client->disconn_data);
			g_free(client->unique_name);
			client->unique_name = NULL;
		} else if (*old == '\0') {
			if (client->connect_func)
				client->connect_func(client->dbus_conn,
							client->connect_data);
			g_free(client->unique_name);
			client->unique_name = g_strdup(new);
		}

		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (client->unique_name == NULL)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (g_str_equal(sender, client->unique_name) == TRUE) {
		if (client->signal_func)
			client->signal_func(client->dbus_conn,
					message, client->signal_data);
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

GDBusClient *g_dbus_client_new(DBusConnection *connection,
					const char *service, const char *path)
{
	GDBusClient *client;
	int i;

	if (connection == NULL)
		return NULL;

	client = g_try_new0(GDBusClient, 1);
	if (client == NULL)
		return NULL;

	if (dbus_connection_add_filter(connection, message_filter,
						client, NULL) == FALSE) {
		g_free(client);
		return NULL;
	}

	client->dbus_conn = dbus_connection_ref(connection);
	client->service_name = g_strdup(service);
	client->base_path = g_strdup(path);

	get_name_owner(client, client->service_name);

	client->match_rules[0] = g_strdup_printf("type='signal',sender='%s',"
				"path='%s',interface='%s',"
				"member='NameOwnerChanged',arg0='%s'",
				DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
				DBUS_INTERFACE_DBUS, client->service_name);
	client->match_rules[1] = g_strdup_printf("type='signal',sender='%s',"
				"path='/',interface='%s.ObjectManager',"
				"member='InterfacesAdded'",
				client->service_name, DBUS_INTERFACE_DBUS);
	client->match_rules[2] = g_strdup_printf("type='signal',sender='%s',"
				"path='/',interface='%s.ObjectManager',"
				"member='InterfacesRemoved'",
				client->service_name, DBUS_INTERFACE_DBUS);
	client->match_rules[3] = g_strdup_printf("type='signal',sender='%s',"
				"path_namespace='%s'",
				client->service_name, client->base_path);

	for (i = 0; i < 4; i++)
		modify_match(client->dbus_conn, "AddMatch",
						client->match_rules[i]);

	return g_dbus_client_ref(client);
}

GDBusClient *g_dbus_client_ref(GDBusClient *client)
{
	if (client == NULL)
		return NULL;

	g_atomic_int_inc(&client->ref_count);

	return client;
}

void g_dbus_client_unref(GDBusClient *client)
{
	int i;

	if (client == NULL)
		return;

	if (g_atomic_int_dec_and_test(&client->ref_count) == FALSE)
		return;

	if (client->pending_call != NULL) {
		dbus_pending_call_cancel(client->pending_call);
		dbus_pending_call_unref(client->pending_call);
	}

	for (i = 0; i < 4; i++) {
		modify_match(client->dbus_conn, "RemoveMatch",
						client->match_rules[i]);
		g_free(client->match_rules[i]);
	}

	dbus_connection_remove_filter(client->dbus_conn,
						message_filter, client);

	if (client->disconn_func)
		client->disconn_func(client->dbus_conn, client->disconn_data);

	dbus_connection_unref(client->dbus_conn);

	g_free(client->service_name);
	g_free(client->unique_name);
	g_free(client->base_path);

	g_free(client);
}

gboolean g_dbus_client_set_connect_watch(GDBusClient *client,
				GDBusWatchFunction function, void *user_data)
{
	if (client == NULL)
		return FALSE;

	client->connect_func = function;
	client->connect_data = user_data;

	return TRUE;
}

gboolean g_dbus_client_set_disconnect_watch(GDBusClient *client,
				GDBusWatchFunction function, void *user_data)
{
	if (client == NULL)
		return FALSE;

	client->disconn_func = function;
	client->disconn_data = user_data;

	return TRUE;
}

gboolean g_dbus_client_set_signal_watch(GDBusClient *client,
				GDBusMessageFunction function, void *user_data)
{
	if (client == NULL)
		return FALSE;

	client->signal_func = function;
	client->signal_data = user_data;

	return TRUE;
}
