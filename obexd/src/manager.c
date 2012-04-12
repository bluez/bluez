/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2010  Marcel Holtmann <marcel@holtmann.org>
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <gdbus.h>
#include <sys/socket.h>
#include <inttypes.h>

#include <gobex.h>

#include "obexd.h"
#include "obex.h"
#include "obex-priv.h"
#include "server.h"
#include "manager.h"
#include "log.h"
#include "btio.h"
#include "service.h"

#define OPENOBEX_MANAGER_PATH "/"
#define OPENOBEX_MANAGER_INTERFACE OPENOBEX_SERVICE ".Manager"
#define ERROR_INTERFACE OPENOBEX_SERVICE ".Error"
#define TRANSFER_INTERFACE OPENOBEX_SERVICE ".Transfer"
#define SESSION_INTERFACE OPENOBEX_SERVICE ".Session"

#define TIMEOUT 60*1000 /* Timeout for user response (miliseconds) */

struct agent {
	char *bus_name;
	char *path;
	gboolean auth_pending;
	char *new_name;
	char *new_folder;
	unsigned int watch_id;
};

static struct agent *agent = NULL;

static DBusConnection *connection = NULL;

static void agent_free(struct agent *agent)
{
	if (!agent)
		return;

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

static void dbus_message_iter_append_variant(DBusMessageIter *iter,
						int type, void *val)
{
	DBusMessageIter value;
	DBusMessageIter array;
	const char *sig;

	switch (type) {
	case DBUS_TYPE_STRING:
		sig = DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_BYTE:
		sig = DBUS_TYPE_BYTE_AS_STRING;
		break;
	case DBUS_TYPE_INT16:
		sig = DBUS_TYPE_INT16_AS_STRING;
		break;
	case DBUS_TYPE_UINT16:
		sig = DBUS_TYPE_UINT16_AS_STRING;
		break;
	case DBUS_TYPE_INT32:
		sig = DBUS_TYPE_INT32_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		sig = DBUS_TYPE_UINT32_AS_STRING;
		break;
	case DBUS_TYPE_BOOLEAN:
		sig = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DBUS_TYPE_ARRAY:
		sig = DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING;
		break;
	case DBUS_TYPE_OBJECT_PATH:
		sig = DBUS_TYPE_OBJECT_PATH_AS_STRING;
		break;
	default:
		error("Could not append variant with type %d", type);
		return;
	}

	dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, sig, &value);

	if (type == DBUS_TYPE_ARRAY) {
		int i;
		const char ***str_array = val;

		dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
			DBUS_TYPE_STRING_AS_STRING, &array);

		for (i = 0; (*str_array)[i]; i++)
			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING,
							&((*str_array)[i]));

		dbus_message_iter_close_container(&value, &array);
	} else
		dbus_message_iter_append_basic(&value, type, val);

	dbus_message_iter_close_container(iter, &value);
}

static void dbus_message_iter_append_dict_entry(DBusMessageIter *dict,
					const char *key, int type, void *val)
{
	DBusMessageIter entry;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
					NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

	dbus_message_iter_append_variant(&entry, type, val);

	dbus_message_iter_close_container(dict, &entry);
}

static void agent_disconnected(DBusConnection *conn, void *user_data)
{
	DBG("Agent exited");
	agent_free(agent);
	agent = NULL;
}

static DBusMessage *register_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path, *sender;

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

	agent->watch_id = g_dbus_add_disconnect_watch(conn, sender,
					agent_disconnected, NULL, NULL);

	DBG("Agent registered");

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_agent(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *path, *sender;

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

	g_dbus_remove_watch(conn, agent->watch_id);

	agent_free(agent);
	agent = NULL;

	DBG("Agent unregistered");

	return dbus_message_new_method_return(msg);
}

static char *target2str(const uint8_t *t)
{
	if (!t)
		return NULL;

	return g_strdup_printf("%02X%02X%02X%02X-%02X%02X-%02X%02X-"
				"%02X%02X-%02X%02X%02X%02X%02X%02X",
				t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7],
				t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15]);
}

static DBusMessage *get_properties(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct obex_session *os = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	char *uuid;
	const char *root;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	/* Target */
	uuid = target2str(os->service->target);
	dbus_message_iter_append_dict_entry(&dict, "Target",
					DBUS_TYPE_STRING, &uuid);
	g_free(uuid);

	/* Root folder */
	root = obex_option_root_folder();
	dbus_message_iter_append_dict_entry(&dict, "Root",
					DBUS_TYPE_STRING, &root);

	/* FIXME: Added Remote Address or USB */

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *transfer_cancel(DBusConnection *connection,
				DBusMessage *msg, void *user_data)
{
	struct obex_session *os = user_data;
	const char *sender;

	if (!os)
		return invalid_args(msg);

	sender = dbus_message_get_sender(msg);
	if (strcmp(agent->bus_name, sender) != 0)
		return not_authorized(msg);

	os->aborted = TRUE;

	return dbus_message_new_method_return(msg);
}

static GDBusMethodTable manager_methods[] = {
	{ "RegisterAgent",	"o",	"",	register_agent		},
	{ "UnregisterAgent",	"o",	"",	unregister_agent	},
	{ }
};

static GDBusSignalTable manager_signals[] = {
	{ "TransferStarted",	"o"	},
	{ "TransferCompleted",	"ob"	},
	{ "SessionCreated",	"o"	},
	{ "SessionRemoved",	"o"	},
	{ }
};

static GDBusMethodTable transfer_methods[] = {
	{ "Cancel",	"",	"",	transfer_cancel	},
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

gboolean manager_init(void)
{
	DBusError err;

	DBG("");

	dbus_error_init(&err);

	connection = g_dbus_setup_bus(DBUS_BUS_SESSION, OPENOBEX_SERVICE,
									&err);
	if (connection == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with session bus\n");
		return FALSE;
	}

	return g_dbus_register_interface(connection, OPENOBEX_MANAGER_PATH,
					OPENOBEX_MANAGER_INTERFACE,
					manager_methods, manager_signals, NULL,
					NULL, NULL);
}

void manager_cleanup(void)
{
	DBG("");

	g_dbus_unregister_interface(connection, OPENOBEX_MANAGER_PATH,
						OPENOBEX_MANAGER_INTERFACE);

	/* FIXME: Release agent? */

	if (agent)
		agent_free(agent);

	dbus_connection_unref(connection);
}

void manager_emit_transfer_started(struct obex_session *os)
{
	char *path = g_strdup_printf("/transfer%u", os->id);

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "TransferStarted",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	g_free(path);
}

static void emit_transfer_completed(struct obex_session *os, gboolean success)
{
	char *path = g_strdup_printf("/transfer%u", os->id);

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "TransferCompleted",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_BOOLEAN, &success,
			DBUS_TYPE_INVALID);

	g_free(path);
}

static void emit_transfer_progress(struct obex_session *os, uint32_t total,
							uint32_t transfered)
{
	char *path = g_strdup_printf("/transfer%u", os->id);

	g_dbus_emit_signal(connection, path,
			TRANSFER_INTERFACE, "Progress",
			DBUS_TYPE_INT32, &total,
			DBUS_TYPE_INT32, &transfered,
			DBUS_TYPE_INVALID);

	g_free(path);
}

void manager_register_transfer(struct obex_session *os)
{
	char *path = g_strdup_printf("/transfer%u", os->id);

	if (!g_dbus_register_interface(connection, path,
				TRANSFER_INTERFACE,
				transfer_methods, transfer_signals,
				NULL, os, NULL)) {
		error("Cannot register Transfer interface.");
		g_free(path);
		return;
	}

	g_free(path);
}

void manager_unregister_transfer(struct obex_session *os)
{
	char *path = g_strdup_printf("/transfer%u", os->id);

	/* Got an error during a transfer. */
	if (os->object)
		emit_transfer_completed(os, os->offset == os->size);

	g_dbus_unregister_interface(connection, path,
				TRANSFER_INTERFACE);

	g_free(path);
}

static void agent_cancel(void)
{
	DBusMessage *msg;

	if (agent == NULL)
		return;

	msg = dbus_message_new_method_call(agent->bus_name, agent->path,
					"org.openobex.Agent", "Cancel");

	g_dbus_send_message(connection, msg);
}

static void agent_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const char *name;
	DBusError derr;
	gboolean *got_reply = user_data;

	*got_reply = TRUE;

	/* Received a reply after the agent exited */
	if (!agent)
		return;

	agent->auth_pending = FALSE;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Agent replied with an error: %s, %s",
				derr.name, derr.message);

		if (dbus_error_has_name(&derr, DBUS_ERROR_NO_REPLY))
			agent_cancel();

		dbus_error_free(&derr);
		dbus_message_unref(reply);
		return;
	}

	if (dbus_message_get_args(reply, NULL,
				DBUS_TYPE_STRING, &name,
				DBUS_TYPE_INVALID)) {
		/* Splits folder and name */
		const char *slash = strrchr(name, '/');
		DBG("Agent replied with %s", name);
		if (!slash) {
			agent->new_name = g_strdup(name);
			agent->new_folder = NULL;
		} else {
			agent->new_name = g_strdup(slash + 1);
			agent->new_folder = g_strndup(name, slash - name);
		}
	}

	dbus_message_unref(reply);
}

static gboolean auth_error(GIOChannel *io, GIOCondition cond, void *user_data)
{
	agent->auth_pending = FALSE;

	return FALSE;
}

int manager_request_authorization(struct obex_session *os, int32_t time,
					char **new_folder, char **new_name)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	const char *filename = os->name ? os->name : "";
	const char *type = os->type ? os->type : "";
	char *path, *address;
	unsigned int watch;
	gboolean got_reply;
	int err;

	if (!agent)
		return -1;

	if (agent->auth_pending)
		return -EPERM;

	if (!new_folder || !new_name)
		return -EINVAL;

	err = obex_getpeername(os, &address);
	if (err < 0)
		return err;

	path = g_strdup_printf("/transfer%u", os->id);

	msg = dbus_message_new_method_call(agent->bus_name, agent->path,
					"org.openobex.Agent", "Authorize");

	dbus_message_append_args(msg,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &filename,
			DBUS_TYPE_STRING, &type,
			DBUS_TYPE_INT32, &os->size,
			DBUS_TYPE_INT32, &time,
			DBUS_TYPE_INVALID);

	g_free(path);
	g_free(address);

	if (!dbus_connection_send_with_reply(connection,
					msg, &call, TIMEOUT)) {
		dbus_message_unref(msg);
		return -EPERM;
	}

	dbus_message_unref(msg);

	agent->auth_pending = TRUE;
	got_reply = FALSE;

	/* Catches errors before authorization response comes */
	watch = g_io_add_watch_full(os->io, G_PRIORITY_DEFAULT,
			G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			auth_error, NULL, NULL);

	dbus_pending_call_set_notify(call, agent_reply, &got_reply, NULL);

	/* Workaround: process events while agent doesn't reply */
	while (agent && agent->auth_pending)
		g_main_context_iteration(NULL, TRUE);

	g_source_remove(watch);

	if (!got_reply) {
		dbus_pending_call_cancel(call);
		agent_cancel();
	}

	dbus_pending_call_unref(call);

	if (!agent || !agent->new_name)
		return -EPERM;

	*new_folder = agent->new_folder;
	*new_name = agent->new_name;
	agent->new_folder = NULL;
	agent->new_name = NULL;

	return 0;
}

void manager_register_session(struct obex_session *os)
{
	char *path = g_strdup_printf("/session%u", GPOINTER_TO_UINT(os));

	if (!g_dbus_register_interface(connection, path,
				SESSION_INTERFACE,
				session_methods, NULL,
				NULL, os, NULL)) {
		error("Cannot register Session interface.");
		goto done;
	}

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "SessionCreated",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

done:
	g_free(path);
}

void manager_unregister_session(struct obex_session *os)
{
	char *path = g_strdup_printf("/session%u", GPOINTER_TO_UINT(os));

	g_dbus_emit_signal(connection, OPENOBEX_MANAGER_PATH,
			OPENOBEX_MANAGER_INTERFACE, "SessionRemoved",
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	g_dbus_unregister_interface(connection, path,
				SESSION_INTERFACE);

	g_free(path);
}

void manager_emit_transfer_progress(struct obex_session *os)
{
	emit_transfer_progress(os, os->size, os->offset);
}

void manager_emit_transfer_completed(struct obex_session *os)
{
	if (os->object)
		emit_transfer_completed(os, !os->aborted);
}

DBusConnection *manager_dbus_get_connection(void)
{
	if (connection == NULL)
		return NULL;

	return dbus_connection_ref(connection);
}
