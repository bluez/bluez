/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <bluetooth/sdp.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "hcid.h"
#include "notify.h"
#include "server.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "error.h"
#include "manager.h"
#include "adapter.h"
#include "dbus-service.h"
#include "dbus-hci.h"

#define SERVICE_INTERFACE "org.bluez.Service"

#define STARTUP_TIMEOUT (10 * 1000) /* 10 seconds */
#define SHUTDOWN_TIMEOUT (2 * 1000) /* 2 seconds */

#define SERVICE_SUFFIX ".service"
#define SERVICE_GROUP "Bluetooth Service"

#define NAME_MATCH "interface=" DBUS_INTERFACE_DBUS ",member=NameOwnerChanged"

static GSList *services = NULL;
static GSList *removed = NULL;

static void service_free(struct service *service)
{
	if (!service)
		return;

	if (service->action)
		dbus_message_unref(service->action);

	g_free(service->bus_name);
	g_free(service->filename);
	g_free(service->object_path);
	g_free(service->name);
	g_free(service->descr);
	g_free(service->ident);

	g_free(service);
}

static void service_exit(const char *name, struct service *service)
{
	DBusConnection *conn = get_dbus_connection();

	debug("Service owner exited: %s", name);

	dbus_connection_emit_signal(conn, service->object_path,
					SERVICE_INTERFACE, "Stopped",
					DBUS_TYPE_INVALID);

	if (service->action) {
		DBusMessage *reply;
		reply = dbus_message_new_method_return(service->action);
		send_message_and_unref(conn, reply);
		dbus_message_unref(service->action);
		service->action = NULL;
	}

	g_free(service->bus_name);
	service->bus_name = NULL;
}

static void external_service_exit(const char *name, struct service *service)
{
	DBusConnection *conn = get_dbus_connection();

	if (!conn)
		return;

	service_exit(name, service);

	dbus_connection_emit_signal(conn, BASE_PATH, MANAGER_INTERFACE,
					"ServiceRemoved",
					DBUS_TYPE_STRING, &service->object_path,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_destroy_object_path(conn, service->object_path))
		return;

	services = g_slist_remove(services, service);
	service_free(service);
}

static DBusHandlerResult get_info(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	dbus_bool_t running;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dbus_message_iter_append_dict_entry(&dict, "identifier",
			DBUS_TYPE_STRING, &service->ident);

	dbus_message_iter_append_dict_entry(&dict, "name",
			DBUS_TYPE_STRING, &service->name);

	dbus_message_iter_append_dict_entry(&dict, "description",
			DBUS_TYPE_STRING, &service->descr);

	running = (service->external || service->bus_name) ? TRUE : FALSE;

	dbus_message_iter_append_dict_entry(&dict, "running",
			DBUS_TYPE_BOOLEAN, &running);

	dbus_message_iter_close_container(&iter, &dict);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_identifier(DBusConnection *conn,
					DBusMessage *msg, void *data)
{

	struct service *service = data;
	DBusMessage *reply;
	const char *identifier = "";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (service->ident)
		identifier = service->ident;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &identifier,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_name(DBusConnection *conn,
					DBusMessage *msg, void *data)
{

	struct service *service = data;
	DBusMessage *reply;
	const char *name = "";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (service->name)
		name = service->name;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_description(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;
	const char *description = "";

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (service->descr)
		description = service->descr;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &description,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult get_bus_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;

	if (!service->bus_name)
		return error_not_available(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &service->bus_name,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static void service_setup(gpointer data)
{
	/* struct service *service = data; */
}

static DBusHandlerResult service_filter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	DBusError err;
	struct service *service = data;
	const char *name, *old, *new;
	unsigned long pid;

	if (!dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &old,
				DBUS_TYPE_STRING, &new, DBUS_TYPE_INVALID)) {
		error("Invalid arguments for NameOwnerChanged signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (*new == '\0' || *old != '\0' || *new != ':')
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_bus_get_unix_process_id(conn, new, &pid)) {
		error("Could not get PID of %s", new);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if ((GPid) pid != service->pid)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	debug("Child PID %d got the unique bus name %s", service->pid, new);

	service->bus_name = g_strdup(new);

	dbus_error_init(&err);
	dbus_bus_remove_match(conn, NAME_MATCH, &err);
	if (dbus_error_is_set(&err)) {
		error("Remove match \"%s\" failed: %s" NAME_MATCH, err.message);
		dbus_error_free(&err);
	}
	dbus_connection_remove_filter(conn, service_filter, service);

	if (service->action) {
		msg = dbus_message_new_method_return(service->action);
		if (msg) {
			if (dbus_message_is_method_call(service->action, MANAGER_INTERFACE,
							"ActivateService"))
				dbus_message_append_args(msg, DBUS_TYPE_STRING, &new,
							DBUS_TYPE_INVALID);
			send_message_and_unref(conn, msg);
		}

		dbus_message_unref(service->action);
		service->action = NULL;
	}

	if (service->startup_timer) {
		g_source_remove(service->startup_timer);
		service->startup_timer = 0;
	} else
		debug("service_filter: timeout was already removed!");

	name_listener_add(conn, new, (name_cb_t) service_exit, service);

	dbus_connection_emit_signal(conn, service->object_path,
					SERVICE_INTERFACE, "Started",
					DBUS_TYPE_INVALID);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void abort_startup(struct service *service, DBusConnection *conn, int ecode)
{
	DBusError err;

	if (conn) {
		dbus_error_init(&err);
		dbus_bus_remove_match(conn, NAME_MATCH, &err);
		if (dbus_error_is_set(&err)) {
			error("Remove match \"%s\" failed: %s" NAME_MATCH, err.message);
		dbus_error_free(&err);
		}

		dbus_connection_remove_filter(conn, service_filter, service);
	}

	g_source_remove(service->startup_timer);
	service->startup_timer = 0;

	if (service->action) {
		if (conn)
			error_failed_errno(conn, service->action, ecode);
		dbus_message_unref(service->action);
		service->action = NULL;
	}

	if (service->pid > 0 && kill(service->pid, SIGKILL) < 0)
		error("kill(%d, SIGKILL): %s (%d)", service->pid,
				strerror(errno), errno);
}

static void service_died(GPid pid, gint status, gpointer data)
{
	struct service *service = data;

	if (WIFEXITED(status))
		debug("%s (%s) exited with status %d", service->name,
				service->ident, WEXITSTATUS(status));
	else
		debug("%s (%s) was killed by signal %d", service->name,
				service->ident, WTERMSIG(status));

	g_spawn_close_pid(pid);
	service->pid = 0;

	if (service->startup_timer)
		abort_startup(service, get_dbus_connection(), ECANCELED);

	if (service->shutdown_timer) {
		g_source_remove(service->shutdown_timer);
		service->shutdown_timer = 0;
	}

	if (g_slist_find(removed, service)) {
		removed = g_slist_remove(removed, service);
		service_free(service);
	}
}

static gboolean service_shutdown_timeout(gpointer data)
{
	struct service *service = data;

	if (service->pid > 0) {
		debug("SIGKILL for \"%s\" (PID %d) since it didn't exit yet",
			service->name, service->pid);

		if (kill(service->pid, SIGKILL) < 0)
			error("kill(%d, SIGKILL): %s (%d)", service->pid,
						strerror(errno), errno);
	}

	service->shutdown_timer = 0;

	return FALSE;
}

static void stop_service(struct service *service, gboolean remove)
{
	if (service->pid > 0 && kill(service->pid, SIGTERM) < 0)
		error("kill(%d, SIGTERM): %s (%d)", service->pid,
				strerror(errno), errno);

	service->shutdown_timer = g_timeout_add(SHUTDOWN_TIMEOUT,
						service_shutdown_timeout,
						service);

	if (remove) {
		services = g_slist_remove(services, service);
		removed = g_slist_append(removed, service);
	}
}

static gboolean service_startup_timeout(gpointer data)
{
	struct service *service = data;

	debug("Killing \"%s\" (PID %d) because it did not connect to D-Bus in time",
			service->name, service->pid);

	abort_startup(service, get_dbus_connection(), ETIME);

	return FALSE;
}

int service_start(struct service *service, DBusConnection *conn)
{
	DBusError derr;
	char *addr, *argv[2], *envp[2], command[PATH_MAX], address[256];

	if (!dbus_connection_add_filter(conn, service_filter, service, NULL)) {
		error("Unable to add signal filter");
		return -1;
	}

	dbus_error_init(&derr);
	dbus_bus_add_match(conn, NAME_MATCH, &derr);
	if (dbus_error_is_set(&derr)) {
		error("Add match \"%s\" failed: %s", derr.message);
		dbus_error_free(&derr);
		dbus_connection_remove_filter(conn, service_filter, service);
		return -1;
	}

	snprintf(command, sizeof(command) - 1, "%s/bluetoothd-service-%s",
						SERVICEDIR, service->ident);
	argv[0] = command;
	argv[1] = NULL;

	addr = get_local_server_address();

	snprintf(address, sizeof(address) - 1, "BLUETOOTHD_ADDRESS=%s", addr);
	envp[0] = address;
	envp[1] = NULL;

	dbus_free(addr);

	if (!g_spawn_async(SERVICEDIR, argv, envp, G_SPAWN_DO_NOT_REAP_CHILD,
				service_setup, service, &service->pid, NULL)) {
		error("Unable to execute %s", argv[0]);
		dbus_connection_remove_filter(conn, service_filter, service);
		dbus_bus_remove_match(conn, NAME_MATCH, NULL);
		return -1;
	}

	g_child_watch_add(service->pid, service_died, service);

	debug("%s executed with PID %d", argv[0], service->pid);

	service->startup_timer = g_timeout_add(STARTUP_TIMEOUT,
						service_startup_timeout,
						service);

	return 0;
}

static DBusHandlerResult start(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct service *service = data;

	if (service->external || service->pid)
		return error_failed_errno(conn, msg, EALREADY);

	if (service_start(service, conn) < 0)
		return error_failed_errno(conn, msg, ENOEXEC);

	service->action = dbus_message_ref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult stop(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct service *service  = data;

	if (service->external || !service->bus_name)
		return error_failed_errno(conn, msg, EPERM);

	stop_service(service, FALSE);

	service->action = dbus_message_ref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult is_running(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;
	dbus_bool_t running;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	running = (service->external || service->bus_name) ? TRUE : FALSE;

	dbus_message_append_args(reply,
			DBUS_TYPE_BOOLEAN, &running,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult is_external(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_BOOLEAN, &service->external,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult set_trusted(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;
	const char *address;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	write_trust(BDADDR_ANY, address, service->ident, TRUE);

	dbus_connection_emit_signal(conn, service->object_path,
					SERVICE_INTERFACE, "TrustAdded",
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_trusted(DBusConnection *conn,
                                        DBusMessage *msg, void *data)
{
        struct service *service = data;
        DBusMessage *reply;
        GSList *trusts, *l;
        char **addrs;
        int len;

        reply = dbus_message_new_method_return(msg);
        if (!reply)
                return DBUS_HANDLER_RESULT_NEED_MEMORY;
        trusts = list_trusts(BDADDR_ANY, service->ident);

        addrs = g_new(char *, g_slist_length(trusts));

        for (l = trusts, len = 0; l; l = l->next, len++)
                addrs[len] = l->data;

        dbus_message_append_args(reply,
                        DBUS_TYPE_ARRAY, DBUS_TYPE_STRING,
                        &addrs, len,
                        DBUS_TYPE_INVALID);

        g_free(addrs);
        g_slist_foreach(trusts, (GFunc) g_free, NULL);
        g_slist_free(trusts);

        return send_message_and_unref(conn, reply);
}

static DBusHandlerResult is_trusted(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;
	const char *address;
	dbus_bool_t trusted;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	trusted = read_trust(BDADDR_ANY, address, service->ident);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
				DBUS_TYPE_BOOLEAN, &trusted,
				DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult remove_trust(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;
	const char *address;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg, NULL);

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg, NULL);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	write_trust(BDADDR_ANY, address, service->ident, FALSE);

	dbus_connection_emit_signal(conn, service->object_path,
					SERVICE_INTERFACE, "TrustRemoved",
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusMethodVTable service_methods[] = {
	{ "GetInfo",		get_info,		"",	"a{sv}"	},
	{ "GetIdentifier",	get_identifier,		"",	"s"	},
	{ "GetName",		get_name,		"",	"s"	},
	{ "GetDescription",	get_description,	"",	"s"	},
	{ "GetBusName",		get_bus_name,		"",	"s"	},
	{ "Start",		start,			"",	""	},
	{ "Stop",		stop,			"",	""	},
	{ "IsRunning",		is_running,		"",	"b"	},
	{ "IsExternal",		is_external,		"",	"b"	},
	{ "SetTrusted",		set_trusted,		"s",	""	},
	{ "IsTrusted",		is_trusted,		"s",	"b"	},
	{ "RemoveTrust",	remove_trust,		"s",	""	},
	{ "ListTrusts",		list_trusted,		"",	"as"	},
	{ NULL, NULL, NULL, NULL }
};

static DBusSignalVTable service_signals[] = {
	{ "Started",		""	},
	{ "Stopped",		""	},
	{ "TrustAdded",		"s"	},
	{ "TrustRemoved",	"s"	},
	{ NULL, NULL }
};

static dbus_bool_t service_init(DBusConnection *conn, const char *path)
{
	return dbus_connection_register_interface(conn, path, SERVICE_INTERFACE,
							service_methods,
							service_signals, NULL);
}

static int service_cmp_path(struct service *service, const char *path)
{
	return strcmp(service->object_path, path);
}

static int service_cmp_ident(struct service *service, const char *ident)
{
	return strcmp(service->ident, ident);
}

static int register_service(struct service *service)
{
	char obj_path[PATH_MAX], *suffix;
	DBusConnection *conn = get_dbus_connection();
	int i;

	if (g_slist_find_custom(services, service->ident,
				(GCompareFunc) service_cmp_ident)
			|| !strcmp(service->ident, GLOBAL_TRUST))
		return -EADDRINUSE;

	if (service->external) {
		snprintf(obj_path, sizeof(obj_path) - 1,
				"/org/bluez/external_%s", service->ident);
	} else {
		snprintf(obj_path, sizeof(obj_path) - 1,
				"/org/bluez/service_%s", service->filename);

		/* Don't include the .service part in the path */
		suffix = strstr(obj_path, SERVICE_SUFFIX);
		*suffix = '\0';
	}

	/* Make the path valid for D-Bus */
	for (i = strlen("/org/bluez/"); obj_path[i]; i++) {
		if (!isalnum(obj_path[i]))
			obj_path[i] = '_';
	}

	if (g_slist_find_custom(services, obj_path,
				(GCompareFunc) service_cmp_path))
		return -EADDRINUSE;

	debug("Registering service object: ident=%s, name=%s (%s)",
			service->ident, service->name, obj_path);


	if (!dbus_connection_create_object_path(conn, obj_path,
						service, NULL)) {
		error("D-Bus failed to register %s object", obj_path);
		return -1;
	}

	if (!service_init(conn, obj_path)) {
		error("Service init failed");
		return -1;
	}

	service->object_path = g_strdup(obj_path);

	services = g_slist_append(services, service);

	dbus_connection_emit_signal(conn, BASE_PATH, MANAGER_INTERFACE,
					"ServiceAdded",
					DBUS_TYPE_STRING, &service->object_path,
					DBUS_TYPE_INVALID);

	return 0;
}

static int unregister_service_for_connection(DBusConnection *connection,
						struct service *service)
{
	DBusConnection *conn = get_dbus_connection();

	debug("Unregistering service object: %s", service->object_path);

	if (!conn)
		goto cleanup;

	if (service->bus_name) {
		name_cb_t cb = (name_cb_t) (service->external ?
				external_service_exit : service_exit);
		name_listener_remove(connection, service->bus_name,
					cb, service);
	}

	dbus_connection_emit_signal(conn, service->object_path,
					SERVICE_INTERFACE,
					"Stopped", DBUS_TYPE_INVALID);

	dbus_connection_emit_signal(conn, BASE_PATH, MANAGER_INTERFACE,
					"ServiceRemoved",
					DBUS_TYPE_STRING, &service->object_path,
					DBUS_TYPE_INVALID);

	if (!dbus_connection_destroy_object_path(conn, service->object_path)) {
		error("D-Bus failed to unregister %s object", service->object_path);
		return -1;
	}

cleanup:
	if (service->pid) {
		if (service->startup_timer) {
			abort_startup(service, conn, ECANCELED);
			services = g_slist_remove(services, service);
			removed = g_slist_append(removed, service);
		} else if (!service->shutdown_timer)
			stop_service(service, TRUE);
	} else {
		services = g_slist_remove(services, service);
		service_free(service);
	}

	return 0;
}

static int unregister_service(struct service *service)
{
	return unregister_service_for_connection(get_dbus_connection(), service);
}

void release_services(DBusConnection *conn)
{
	debug("release_services");

	g_slist_foreach(services, (GFunc) unregister_service, NULL);
	g_slist_free(services);
	services = NULL;
}

struct service *search_service(DBusConnection *conn, const char *pattern)
{
	GSList *l;

	for (l = services; l != NULL; l = l->next) {
		struct service *service = l->data;

		if (service->ident && !strcmp(service->ident, pattern))
			return service;

		if (service->bus_name && !strcmp(service->bus_name, pattern))
			return service;
	}

	return NULL;
}

void append_available_services(DBusMessageIter *array_iter)
{
	GSList *l;

	for (l = services; l != NULL; l = l->next) {
		struct service *service = l->data;

		dbus_message_iter_append_basic(array_iter,
					DBUS_TYPE_STRING, &service->object_path);
	}
}

static struct service *create_service(const char *file)
{
	GKeyFile *keyfile;
	GError *err = NULL;
	struct service *service;
	gboolean autostart;
	const char *slash;

	service = g_try_new0(struct service, 1);
	if (!service) {
		error("OOM while allocating new service");
		return NULL;
	}

	service->external = FALSE;

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
		error("Parsing %s failed: %s", file, err->message);
		g_error_free(err);
		goto failed;
	}

	service->ident = g_key_file_get_string(keyfile, SERVICE_GROUP,
						"Identifier", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		goto failed;
	}

	service->name = g_key_file_get_string(keyfile, SERVICE_GROUP,
						"Name", &err);
	if (!service->name) {
		error("%s: %s", file, err->message);
		g_error_free(err);
		goto failed;
	}

	slash = strrchr(file, '/');
	if (!slash) {
		error("No slash in service file path!?");
		goto failed;
	}

	service->filename = g_strdup(slash + 1);

	service->descr = g_key_file_get_string(keyfile, SERVICE_GROUP,
						"Description", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	}

	autostart = g_key_file_get_boolean(keyfile, SERVICE_GROUP,
						"Autostart", &err);
	if (err) {
		debug("%s: %s", file, err->message);
		g_error_free(err);
		err = NULL;
	} else
		service->autostart = autostart;

	g_key_file_free(keyfile);

	return service;

failed:
	g_key_file_free(keyfile);
	service_free(service);
	return NULL;
}

static gint service_filename_cmp(struct service *service, const char *filename)
{
	return strcmp(service->filename, filename);
}

static void service_notify(int action, const char *name, void *user_data)
{
	GSList *l;
	struct service *service;
	size_t len;
	char fullpath[PATH_MAX];

	debug("Received notify event %d for %s", action, name);

	len = strlen(name);
	if (len < (strlen(SERVICE_SUFFIX) + 1))
		return;

	if (strcmp(name + (len - strlen(SERVICE_SUFFIX)), SERVICE_SUFFIX))
		return;

	switch (action) {
	case NOTIFY_CREATE:
		debug("%s was created", name);
		snprintf(fullpath, sizeof(fullpath) - 1, "%s/%s", CONFIGDIR, name);
		service = create_service(fullpath);
		if (!service) {
			error("Unable to read %s", fullpath);
			break;
		}

		if (register_service(service) < 0) {
			error("Unable to register service");
			service_free(service);
			break;
		}

		if (service->autostart)
			service_start(service, get_dbus_connection());

		break;
	case NOTIFY_DELETE:
		debug("%s was deleted", name);
		l = g_slist_find_custom(services, name,
					(GCompareFunc) service_filename_cmp);
		if (l)
			unregister_service(l->data);
		break;
	case NOTIFY_MODIFY:
		debug("%s was modified", name);
		break;
	default:
		debug("Unknown notify action %d", action);
		break;
	}
}

int init_services(const char *path)
{
	DIR *d;
	struct dirent *e;

	d = opendir(path);
	if (!d) {
		error("Unable to open service dir %s: %s", path, strerror(errno));
		return -1;
	}

	while ((e = readdir(d)) != NULL) {
		char full_path[PATH_MAX];
		struct service *service;
		size_t len = strlen(e->d_name);

		if (len < (strlen(SERVICE_SUFFIX) + 1))
			continue;

		/* Skip if the file doesn't end in .service */
		if (strcmp(&e->d_name[len - strlen(SERVICE_SUFFIX)], SERVICE_SUFFIX))
			continue;

		snprintf(full_path, sizeof(full_path) - 1, "%s/%s", path, e->d_name);

		service = create_service(full_path);
		if (!service) {
			error("Unable to read %s", full_path);
			continue;
		}

		if (register_service(service) < 0) {
			error("Unable to register service");
			service_free(service);
			continue;
		}

		if (service->autostart)
			service_start(service, get_dbus_connection());
	}

	closedir(d);

	notify_add(path, service_notify, NULL);

	return 0;
}

static struct service *create_external_service(const char *ident,
				const char *name, const char *description)
{
	struct service *service;

	service = g_try_new0(struct service, 1);
	if (!service) {
		error("OOM while allocating new external service");
		return NULL;
	}

	service->filename = NULL;
	service->name = g_strdup(name);
	service->descr = g_strdup(description);
	service->ident = g_strdup(ident);

	service->external = TRUE;

	return service;
}

int service_register(DBusConnection *conn, const char *bus_name, const char *ident,
				const char *name, const char *description)
{
	struct service *service;

	if (!conn)
		return -1;

	service = create_external_service(ident, name, description);
	if (!service)
		return -1;

	service->bus_name = g_strdup(bus_name);

	if (register_service(service) < 0) {
		service_free(service);
		return -1;
	}

	name_listener_add(conn, bus_name, (name_cb_t) external_service_exit,
				service);

	dbus_connection_emit_signal(get_dbus_connection(), service->object_path,
					SERVICE_INTERFACE, "Started",
					DBUS_TYPE_INVALID);

	return 0;
}

int service_unregister(DBusConnection *conn, struct service *service)
{
	return unregister_service_for_connection(conn, service);
}
