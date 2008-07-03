/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>

#include <string.h>
#include <errno.h>
#include <gdbus.h>
#include <sys/socket.h>

#include "obexd.h"
#include "logging.h"

#define TRANSFER_INTERFACE OPENOBEX_SERVICE ".Transfer"
#define SESSION_INTERFACE OPENOBEX_SERVICE ".Session"

#define TIMEOUT 60*1000 /* Timeout for user response (miliseconds) */

struct agent {
	gchar		*bus_name;
	gchar		*path;
	gboolean	auth_pending;
	gchar		*new_name;
	gchar		*new_folder;
};

static struct agent *agent = NULL;

static void agent_free(struct agent *agent)
{
	g_free(agent->new_folder);
	g_free(agent->new_name);
	g_free(agent->bus_name);
	g_free(agent->path);
	g_free(agent);
}

static inline DBusMessage *invalid_args(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".InvalidArguments",
			"Invalid arguments in method call");
}

static inline DBusMessage *agent_already_exists(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".AlreadyExists",
			"Agent already exists");
}

static inline DBusMessage *agent_does_not_exist(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".DoesNotExist",
			"Agent does not exist");
}

static inline DBusMessage *not_authorized(DBusMessage *msg)
{
	return g_dbus_create_error(msg,
			ERROR_INTERFACE ".NotAuthorized",
			"Not authorized");
}

static void agent_disconnected(void *user_data)
{
	debug("Agent exited");
	agent_free(agent);
	agent = NULL;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const gchar *path, *sender;

	if (agent)
		return agent_already_exists(msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return invalid_args(msg);

	sender = dbus_message_get_sender(msg);
	agent = g_new0(struct agent, 1);
	agent->bus_name = g_strdup(sender);
	agent->path = g_strdup(path);

	g_dbus_add_disconnect_watch(conn, sender,
			agent_disconnected, NULL, NULL);

	debug("Agent registered");

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const gchar *path, *sender;

	if (!agent)
		return agent_does_not_exist(msg);

	if (!dbus_message_get_args(msg, NULL,
				DBUS_TYPE_OBJECT_PATH, &path,
				DBUS_TYPE_INVALID))
		return invalid_args(msg);

	if (strcmp(agent->path, path) != 0)
		return agent_does_not_exist(msg);

	sender = dbus_message_get_sender(msg);
	if (strcmp(agent->bus_name, sender) != 0)
		return not_authorized(msg);

	agent_free(agent);
	agent = NULL;

	return dbus_message_new_method_return(msg);
}

static DBusMessage *get_properties(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	/* FIXME: */
	return NULL;
}

static GDBusMethodTable manager_methods[] = {
	{ "RegisterAgent",	"o",	"",	register_agent		},
	{ "UnregisterAgent",	"o",	"",	unregister_agent	},
	{ }
};

static GDBusSignalTable manager_signals[] = {
	{ "TransferStarted", 	"o" 	},
	{ "TransferCompleted", 	"ob" 	},
	{ "SessionCreated", 	"o" 	},
	{ "SessionRemoved",	"o"	},
	{ }
};

static GDBusMethodTable transfer_methods[] = {
	{ "Cancel",	""	},
	{ }
};

static GDBusSignalTable transfer_signals[] = {
	{ "Progress",	"ii"	},
	{ }
};

static GDBusMethodTable session_methods[] = {
	{ "GetProperties",	"",	"{sv}",	get_properties	},
	{ }
};

static DBusConnection *connection = NULL;

gboolean manager_init(DBusConnection *conn)
{
	DBG("conn %p", conn);

	connection = dbus_connection_ref(conn);
	if (connection == NULL)
		return FALSE;

	return g_dbus_register_interface(connection, OPENOBEX_MANAGER_PATH,
					OPENOBEX_MANAGER_INTERFACE,
					manager_methods, manager_signals, NULL,
					NULL, NULL);
}

void manager_cleanup(void)
{
	DBG("conn %p", connection);

	g_dbus_unregister_interface(connection, OPENOBEX_MANAGER_PATH,
						OPENOBEX_MANAGER_INTERFACE);

	/* FIXME: Release agent? */

	if (agent)
		agent_free(agent);

	dbus_connection_unref(connection);
}

void emit_session_created(guint32 id)
{
	gchar *path = g_strdup_printf("/session%u", id);

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "SessionCreated",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	g_free(path);
}

void emit_session_removed(guint32 id)
{
	gchar *path = g_strdup_printf("/session%u", id);

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "SessionRemoved",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	g_free(path);
}

void emit_transfer_started(guint32 id)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "TransferStarted",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	g_free(path);
}

void emit_transfer_completed(guint32 id, gboolean success)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "TransferCompleted",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_BOOLEAN, &success,
			DBUS_TYPE_INVALID);

	g_free(path);
}

void emit_transfer_progress(guint32 id, guint32 total, guint32 transfered)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

	g_dbus_emit_signal(connection, path,
			TRANSFER_INTERFACE, "Progress",
			DBUS_TYPE_INT32, &total,
			DBUS_TYPE_INT32, &transfered,
			DBUS_TYPE_INVALID);

	g_free(path);
}

void register_transfer(guint32 id)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

	if (!g_dbus_register_interface(connection, path,
				TRANSFER_INTERFACE,
				transfer_methods, transfer_signals,
				NULL, NULL, NULL)) {
		error("Cannot register Transfer interface.");
		g_free(path);
		return;
	}

	g_free(path);
}

void unregister_transfer(guint32 id)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

	g_dbus_unregister_interface(connection, path,
				TRANSFER_INTERFACE);

	g_free(path);
}

static void agent_reply(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const gchar *name;
	DBusError derr;

	agent->auth_pending = FALSE;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Agent replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		return;
	}

	if (dbus_message_get_args(reply, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID)) {
		/* Splits folder and name */
		const gchar *slash = strrchr(name, '/');
		if (!slash) {
			agent->new_name = g_strdup(name);
			agent->new_folder = NULL;
		} else {
			agent->new_name = g_strdup(slash + 1);
			agent->new_folder = g_strndup(name, slash - name);
		}
	}
}

int request_authorization(gint32 cid, int fd, const gchar *filename,
			const gchar *type, gint32 length, gint32 time,
			gchar **new_folder, gchar **new_name)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	struct sockaddr_rc addr;
	socklen_t addrlen;
	gchar address[18];
	const gchar *bda = address;
	gchar *path;

	if (!agent)
		return -1;

	if (agent->auth_pending)
		return -EPERM;

	if (!new_folder || !new_name)
		return -EINVAL;

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	if (getpeername(fd, (struct sockaddr *) &addr, &addrlen) < 0)
		return -1;

	ba2str(&addr.rc_bdaddr, address);

	path = g_strdup_printf("/transfer%d", cid);

	msg = dbus_message_new_method_call(agent->bus_name, agent->path,
					"org.openobex.Agent", "Authorize");

	dbus_message_append_args(msg,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_STRING, &bda,
			DBUS_TYPE_STRING, &filename,
			DBUS_TYPE_STRING, &type,
			DBUS_TYPE_INT32, &length,
			DBUS_TYPE_INT32, &time,
			DBUS_TYPE_INVALID);

	g_free(path);

	if (!dbus_connection_send_with_reply(connection,
					msg, &call, TIMEOUT))
		return -EPERM;

	dbus_message_unref(msg);

	agent->auth_pending = TRUE;

	dbus_pending_call_set_notify(call, agent_reply, NULL, NULL);
	dbus_pending_call_unref(call);

	/* Workaround: process events while agent doesn't reply */
	while (agent->auth_pending)
		g_main_context_iteration(NULL, TRUE);

	if (!agent->new_name) {
		return -EPERM;
	}

	*new_folder = agent->new_folder;
	*new_name = agent->new_name;
	agent->new_folder = NULL;
	agent->new_name = NULL;

	return 0;
}

void register_session(guint32 id)
{
	gchar *path = g_strdup_printf("/session%u", id);

	if (!g_dbus_register_interface(connection, path,
				SESSION_INTERFACE,
				session_methods, NULL,
				NULL, NULL, NULL)) {
		error("Cannot register Session interface.");
		g_free(path);
		return;
	}

	g_free(path);
}

void unregister_session(guint32 id)
{
	gchar *path = g_strdup_printf("/session%u", id);

	g_dbus_unregister_interface(connection, path,
				SESSION_INTERFACE);

	g_free(path);
}
