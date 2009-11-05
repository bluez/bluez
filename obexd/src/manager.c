/*
 *
 *  OBEX Server
 *
 *  Copyright (C) 2007-2009  Marcel Holtmann <marcel@holtmann.org>
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

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <gdbus.h>
#include <sys/socket.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>

#include <openobex/obex.h>

#include "bluetooth.h"
#include "obexd.h"
#include "obex.h"
#include "dbus.h"
#include "logging.h"
#include "btio.h"
#include "service.h"

#define TRANSFER_INTERFACE OPENOBEX_SERVICE ".Transfer"
#define SESSION_INTERFACE OPENOBEX_SERVICE ".Session"

#define TIMEOUT 60*1000 /* Timeout for user response (miliseconds) */

struct agent {
	gchar		*bus_name;
	gchar		*path;
	gboolean	auth_pending;
	gchar		*new_name;
	gchar		*new_folder;
	guint		watch_id;
};

static struct agent *agent = NULL;

struct pending_request {
	DBusPendingCall *call;
	struct server *server;
	gchar *adapter_path;
	char address[18];
	guint watch;
	GIOChannel *io;
};

struct adapter_any {
	char *path;		/* Adapter ANY path */
	GSList *servers;	/* List of servers to register records */
};

static DBusConnection *connection = NULL;
static DBusConnection *system_conn = NULL;
static struct adapter_any *any = NULL;
static guint listener_id = 0;

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

	agent->watch_id = g_dbus_add_disconnect_watch(conn, sender,
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

	g_dbus_remove_watch(conn, agent->watch_id);

	agent_free(agent);
	agent = NULL;

	debug("Agent unregistered");

	return dbus_message_new_method_return(msg);
}

static char *target2str(const uint8_t *t)
{
	if (!t)
		return NULL;

	return g_strdup_printf("%02X%02X%02X%02X-%02X%02X-%02X%02X-"
				"%02X%02X-%02X%02X%02X%02X%02X%02X",
				t[0], t[1], t[2], t[3], t[4], t[5], t[6],t[7],
				t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15]);
}

static DBusMessage *get_properties(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct obex_session *os = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	gchar *uuid;

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
	dbus_message_iter_append_dict_entry(&dict, "Root",
					DBUS_TYPE_STRING, &os->server->folder);

	/* FIXME: Added Remote Address or USB */

	dbus_message_iter_close_container(&iter, &dict);

	return reply;
}

static DBusMessage *transfer_cancel(DBusConnection *connection,
				DBusMessage *msg, void *user_data)
{
	struct obex_session *os = user_data;
	const gchar *sender;

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

static void add_record_reply(DBusPendingCall *call, gpointer user_data)
{
	struct server *server = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	uint32_t handle;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		handle = 0;
	} else {
		struct obex_service_driver *driver;

		dbus_message_get_args(reply, NULL,
				DBUS_TYPE_UINT32, &handle,
				DBUS_TYPE_INVALID);
		server->handle = handle;

		driver = (struct obex_service_driver *) server->drivers->data;

		debug("Registered: %s, handle: 0x%x, folder: %s",
				driver->name, handle, server->folder);
	}

	dbus_message_unref(reply);
}

static gint add_record(const gchar *path,
		const gchar *xml, struct server *server)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	gint ret = 0;

	msg = dbus_message_new_method_call("org.bluez", path,
					"org.bluez.Service", "AddRecord");

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &xml,
			DBUS_TYPE_INVALID);

	if (dbus_connection_send_with_reply(system_conn,
				msg, &call, -1) == FALSE) {
		ret = -1;
		goto failed;
	}

	dbus_pending_call_set_notify(call, add_record_reply, server, NULL);
	dbus_pending_call_unref(call);

failed:
	dbus_message_unref(msg);
	return ret;
}

void register_record(struct server *server, gpointer user_data)
{
	struct obex_service_driver *driver;
	gchar *xml;
	gint ret;

	if (system_conn == NULL)
		return;

	if (any->path == NULL) {
		/* Adapter ANY is not available yet: Add record later */
		any->servers = g_slist_append(any->servers, server);
		return;
	}

	driver = (struct obex_service_driver *) server->drivers->data;
	xml = g_markup_printf_escaped(driver->record, driver->channel,
					driver->name);
	ret = add_record(any->path, xml, server);
	g_free(xml);
}

static void find_adapter_any_reply(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const char *path;
	gchar *xml;
	GSList *l;
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		bluetooth_stop();
		goto done;
	}

	dbus_message_get_args(reply, NULL,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);
	any->path = g_strdup(path);

	for (l = any->servers; l; l = l->next) {
		struct server *server = l->data;
		struct obex_service_driver *driver;

		driver = (struct obex_service_driver *) server->drivers->data;
		xml = g_markup_printf_escaped(driver->record, driver->channel,
						driver->name);
		add_record(path, xml, server);
		g_free(xml);
	}

done:
	g_slist_free(any->servers);
	any->servers = NULL;

	dbus_message_unref(reply);
}

static DBusPendingCall *find_adapter(const char *pattern,
				DBusPendingCallNotifyFunction function,
				gpointer user_data)
{
	DBusMessage *msg;
	DBusPendingCall *call;

	debug("FindAdapter(%s)", pattern);

	msg = dbus_message_new_method_call("org.bluez", "/",
					"org.bluez.Manager", "FindAdapter");
	if (!msg)
		return NULL;

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &pattern,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(system_conn, msg, &call, -1)) {
		dbus_message_unref(msg);
		return NULL;
	}

	dbus_pending_call_set_notify(call, function, user_data, NULL);

	dbus_message_unref(msg);

	return call;
}

static void name_acquired(DBusConnection *conn, void *user_data)
{
	DBusPendingCall *call;

	call = find_adapter("any", find_adapter_any_reply, NULL);
	if (call)
		dbus_pending_call_unref(call);

	bluetooth_start();
}

static void name_released(DBusConnection *conn, void *user_data)
{
	g_free(any->path);
	any->path = NULL;
	bluetooth_stop();
}

gboolean manager_init(void)
{
	DBusError err;

	DBG("");

	any = g_new0(struct adapter_any, 1);

	dbus_error_init(&err);

	connection = g_dbus_setup_bus(DBUS_BUS_SESSION, OPENOBEX_SERVICE, &err);
	if (connection == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with session bus\n");
		return FALSE;
	}

	system_conn = g_dbus_setup_bus(DBUS_BUS_SYSTEM, NULL, NULL);
	if (system_conn == NULL)
		return FALSE;

	listener_id = g_dbus_add_service_watch(system_conn, "org.bluez",
				name_acquired, name_released, NULL, NULL);

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

	g_dbus_remove_watch(system_conn, listener_id);

	if (any) {
		g_free(any->path);
		g_free(any);
	}

	if (system_conn)
		dbus_connection_unref(system_conn);

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

void register_transfer(guint32 id, struct obex_session *os)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

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

void unregister_transfer(guint32 id)
{
	gchar *path = g_strdup_printf("/transfer%u", id);

	g_dbus_unregister_interface(connection, path,
				TRANSFER_INTERFACE);

	g_free(path);
}

static void agent_cancel()
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call(agent->bus_name, agent->path,
					"org.openobex.Agent", "Cancel");

	g_dbus_send_message(connection, msg);
}

static void agent_reply(DBusPendingCall *call, gpointer user_data)
{
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	const gchar *name;
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
		const gchar *slash = strrchr(name, '/');
		debug("Agent replied with %s", name);
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

static gboolean auth_error(GIOChannel *io, GIOCondition cond,
			gpointer user_data)
{
	agent->auth_pending = FALSE;

	return FALSE;
}

int request_authorization(gint32 cid, int fd, const gchar *filename,
			const gchar *type, gint32 length, gint32 time,
			gchar **new_folder, gchar **new_name)
{
	DBusMessage *msg;
	DBusPendingCall *call;
	GIOChannel *io;
	struct sockaddr_rc addr;
	socklen_t addrlen;
	gchar address[18];
	const gchar *bda = address;
	gchar *path;
	guint watch;
	gboolean got_reply;

	if (!agent)
		return -1;

	if (agent->auth_pending)
		return -EPERM;

	if (!new_folder || !new_name)
		return -EINVAL;

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	if (getpeername(fd, (struct sockaddr *) &addr, &addrlen) < 0)
		return -errno;

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
					msg, &call, TIMEOUT)) {
		dbus_message_unref(msg);
		return -EPERM;
	}

	dbus_message_unref(msg);

	agent->auth_pending = TRUE;
	got_reply = FALSE;

	/* Catches errors before authorization response comes */
	io = g_io_channel_unix_new(fd);
	watch = g_io_add_watch_full(io, G_PRIORITY_DEFAULT,
			G_IO_HUP | G_IO_ERR | G_IO_NVAL,
			auth_error, NULL, NULL);
	g_io_channel_unref(io);

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

static void service_cancel(struct pending_request *pending)
{
	DBusMessage *msg;

	msg = dbus_message_new_method_call("org.bluez",
					pending->adapter_path,
					"org.bluez.Service",
					"CancelAuthorization");

	g_dbus_send_message(system_conn, msg);
}

void obex_connect_cb(GIOChannel *io, GError *err, gpointer user_data)
{
	struct server *server = user_data;

	if (err) {
		error("%s", err->message);
		g_io_channel_shutdown(io, TRUE, NULL);
		return;
	}

	if (obex_session_start(io, server) < 0)
		g_io_channel_shutdown(io, TRUE, NULL);
}

static void pending_request_free(struct pending_request *pending)
{
	if (pending->call)
		dbus_pending_call_unref(pending->call);
	g_io_channel_unref(pending->io);
	g_free(pending->adapter_path);
	g_free(pending);
}

static void service_reply(DBusPendingCall *call, gpointer user_data)
{
	struct pending_request *pending = user_data;
	GIOChannel *io = pending->io;
	struct server *server = pending->server;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusError derr;
	GError *err = NULL;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("RequestAuthorization error: %s, %s",
				derr.name, derr.message);

		if (dbus_error_has_name(&derr, DBUS_ERROR_NO_REPLY))
			service_cancel(pending);

		dbus_error_free(&derr);
		g_io_channel_shutdown(io, TRUE, NULL);
		goto done;
	}

	debug("RequestAuthorization succeeded");

	if (!bt_io_accept(io, obex_connect_cb, server, NULL, &err)) {
		error("%s", err->message);
		g_error_free(err);
		g_io_channel_shutdown(io, TRUE, NULL);
	}

done:
	g_source_remove(pending->watch);
	pending_request_free(pending);
	dbus_message_unref(reply);
}

static gboolean service_error(GIOChannel *io, GIOCondition cond,
			gpointer user_data)
{
	struct pending_request *pending = user_data;

	service_cancel(pending);

	dbus_pending_call_cancel(pending->call);

	pending_request_free(pending);

	return FALSE;
}

static void find_adapter_reply(DBusPendingCall *call, gpointer user_data)
{
	struct pending_request *pending = user_data;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *msg;
	DBusPendingCall *pcall;
	const char *path, *paddr = pending->address;
	DBusError derr;

	dbus_error_init(&derr);
	if (dbus_set_error_from_message(&derr, reply)) {
		error("Replied with an error: %s, %s",
				derr.name, derr.message);
		dbus_error_free(&derr);
		goto failed;
	}

	dbus_message_get_args(reply, NULL,
			DBUS_TYPE_OBJECT_PATH, &path,
			DBUS_TYPE_INVALID);

	debug("FindAdapter -> %s", path);
	pending->adapter_path = g_strdup(path);
	dbus_message_unref(reply);

	msg = dbus_message_new_method_call("org.bluez", path,
			"org.bluez.Service", "RequestAuthorization");

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &paddr,
			DBUS_TYPE_UINT32, &pending->server->handle,
			DBUS_TYPE_INVALID);

	if (!dbus_connection_send_with_reply(system_conn,
					msg, &pcall, TIMEOUT)) {
		dbus_message_unref(msg);
		goto failed;
	}

	dbus_message_unref(msg);

	debug("RequestAuthorization(%s, %x)", paddr, pending->server->handle);

	if (!dbus_pending_call_set_notify(pcall, service_reply, pending,
								NULL)) {
		dbus_pending_call_unref(pcall);
		goto failed;
	}

	dbus_pending_call_unref(pending->call);
	pending->call = pcall;

	/* Catches errors before authorization response comes */
	pending->watch = g_io_add_watch(pending->io,
					G_IO_HUP | G_IO_ERR | G_IO_NVAL,
					service_error, pending);

	return;

failed:
	g_io_channel_shutdown(pending->io, TRUE, NULL);
	pending_request_free(pending);
}

gint request_service_authorization(struct server *server, GIOChannel *io,
					const char *address)
{
	struct pending_request *pending;
	char source[18];
	GError *err = NULL;

	if (system_conn == NULL || any->path == NULL)
		return -1;

	bt_io_get(io, BT_IO_RFCOMM, &err,
			BT_IO_OPT_SOURCE, source,
			BT_IO_OPT_INVALID);
	if (err) {
		error("%s", err->message);
		g_error_free(err);
		return -EINVAL;
	}

	pending = g_new0(struct pending_request, 1);
	pending->call = find_adapter(source, find_adapter_reply, pending);
	if (!pending->call) {
		g_free(pending);
		return -ENOMEM;
	}

	pending->server = server;
	pending->io = g_io_channel_ref(io);
	memcpy(pending->address, address, sizeof(pending->address));


	return 0;
}

void register_session(guint32 id, struct obex_session *os)
{
	gchar *path = g_strdup_printf("/session%u", id);

	if (!g_dbus_register_interface(connection, path,
				SESSION_INTERFACE,
				session_methods, NULL,
				NULL, os, NULL)) {
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


