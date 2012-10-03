/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Tieto Poland
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
#include <gdbus.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/sdp.h>

#include "plugin.h"
#include "log.h"
#include "dbus-common.h"
#include "adapter.h"

#define NEARD_NAME "org.neard"
#define NEARD_PATH "/"
#define NEARD_MANAGER_INTERFACE "org.neard.Manager"
#define AGENT_INTERFACE "org.neard.HandoverAgent"
#define AGENT_PATH "/org/bluez/neard_handover_agent"
#define ERROR_INTERFACE "org.neard.HandoverAgent.Error"

static guint watcher_id = 0;
static gboolean agent_registered = FALSE;

static DBusMessage *error_failed(DBusMessage *msg, int error)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed",
							"%s", strerror(error));
}

static void register_agent_cb(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError err;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&err);
	if (dbus_set_error_from_message(&err, reply)) {
		error("neard manager replied with an error: %s, %s",
						err.name, err.message);
		dbus_error_free(&err);
		dbus_message_unref(reply);

		g_dbus_unregister_interface(btd_get_dbus_connection(),
						AGENT_PATH, AGENT_INTERFACE);
		return;
	}

	dbus_message_unref(reply);
	agent_registered = TRUE;
}

static void register_agent(void)
{
	DBusMessage *message;
	DBusPendingCall *call;
	const gchar *path = AGENT_PATH;

	message = dbus_message_new_method_call(NEARD_NAME, NEARD_PATH,
			NEARD_MANAGER_INTERFACE, "RegisterHandoverAgent");
	if (!message) {
		error("Couldn't allocate D-Bus message");
		return;
	}

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(btd_get_dbus_connection(),
							message, &call, -1)) {
		error("D-Bus send failed");
		return;
	}

	dbus_pending_call_set_notify(call, register_agent_cb, NULL, NULL);
	dbus_pending_call_unref(call);
}

static void unregister_agent(void)
{
	DBusMessage *message;
	const gchar *path = AGENT_PATH;

	agent_registered = FALSE;

	message = dbus_message_new_method_call(NEARD_NAME, NEARD_PATH,
			NEARD_MANAGER_INTERFACE, "UnregisterHandoverAgent");

	if (!message) {
		error("Couldn't allocate D-Bus message");
		goto unregister;
	}

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID);

	if (!g_dbus_send_message(btd_get_dbus_connection(), message))
		error("D-Bus send failed");

unregister:
	g_dbus_unregister_interface(btd_get_dbus_connection(), AGENT_PATH,
							AGENT_INTERFACE);
}

static DBusMessage *push_oob(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	DBG("");

	return error_failed(msg, ENOTSUP);
}

static DBusMessage *request_oob(DBusConnection *conn, DBusMessage *msg,
								void *data)
{
	DBG("");

	return error_failed(msg, ENOTSUP);
}

static DBusMessage *release(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	DBG("");

	agent_registered = FALSE;
	g_dbus_unregister_interface(conn, AGENT_PATH, AGENT_INTERFACE);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static const GDBusMethodTable neard_methods[] = {
	{ GDBUS_ASYNC_METHOD("RequestOOB",
			GDBUS_ARGS({ "data", "a{sv}" }),
			GDBUS_ARGS({ "data", "a{sv}" }), request_oob) },
	{ GDBUS_ASYNC_METHOD("PushOOB",
			GDBUS_ARGS({ "data", "a{sv}"}), NULL, push_oob) },
	{ GDBUS_METHOD("Release", NULL, NULL, release) },
	{ }
};

static void neard_appeared(DBusConnection *conn, void *user_data)
{
	DBG("");

	if (!g_dbus_register_interface(conn, AGENT_PATH, AGENT_INTERFACE,
						neard_methods,
						NULL, NULL, NULL, NULL)) {
		error("neard interface init failed on path " AGENT_PATH);
		return;
	}

	register_agent();
}

static void neard_vanished(DBusConnection *conn, void *user_data)
{
	DBG("");

	/* neard existed without unregistering agent */
	if (agent_registered) {
		agent_registered = FALSE;
		g_dbus_unregister_interface(conn, AGENT_PATH, AGENT_INTERFACE);
	}
}

static int neard_init(void)
{
	DBG("Setup neard plugin");

	watcher_id = g_dbus_add_service_watch(btd_get_dbus_connection(),
						NEARD_NAME, neard_appeared,
						neard_vanished, NULL, NULL);
	if (watcher_id == 0)
		return -ENOMEM;

	return 0;
}

static void neard_exit(void)
{
	DBG("Cleanup neard plugin");

	g_dbus_remove_watch(btd_get_dbus_connection(), watcher_id);
	watcher_id = 0;

	if (agent_registered)
		unregister_agent();
}

BLUETOOTH_PLUGIN_DEFINE(neard, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
						neard_init, neard_exit)
