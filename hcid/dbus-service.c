/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2007  Marcel Holtmann <marcel@holtmann.org>
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
#include <sys/types.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"
#include "notify.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "dbus-manager.h"
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

struct binary_record *binary_record_new()
{
	struct binary_record *rec;
	rec = malloc(sizeof(struct binary_record));
	if (!rec)
		return NULL;

	memset(rec, 0, sizeof(struct binary_record));
	rec->ext_handle = 0xffffffff;
	rec->handle = 0xffffffff;

	return rec;
}

void binary_record_free(struct binary_record *rec)
{
	if (!rec)
		return;

	if (rec->buf) {
		if (rec->buf->data)
			free(rec->buf->data);
		free(rec->buf);
	}
	
	free(rec);
}

int binary_record_cmp(struct binary_record *rec, uint32_t *handle)
{
	return (rec->ext_handle - *handle);
}


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
	g_free(service->opts);

	if (service->trusted_devices) {
		g_slist_foreach(service->trusted_devices, (GFunc) g_free, NULL);
		g_slist_free(service->trusted_devices);
	}

	if (service->records) {
		g_slist_foreach(service->records, (GFunc) binary_record_free, NULL);
		g_slist_free(service->records);
	}

	g_free(service);
}

static int unregister_service_records(GSList *lrecords)
{
	while (lrecords) {
		struct binary_record *rec = lrecords->data;
		lrecords = lrecords->next;

		if (!rec || rec->handle == 0xffffffff)
			continue;

		if (unregister_sdp_record(rec->handle) < 0) {
			/* FIXME: If just one of the service record registration fails */
			error("Service Record unregistration failed:(%s, %d)",
				strerror(errno), errno);
		}

		rec->handle = 0xffffffff;
	}

	return 0;
}

static void service_exit(const char *name, struct service *service)
{
	DBusConnection *conn = get_dbus_connection();
	DBusMessage *msg;
	
	debug("Service owner exited: %s", name);

	if (service->records)
		unregister_service_records(service->records);

	msg = dbus_message_new_signal(service->object_path,
					SERVICE_INTERFACE, "Stopped");
	send_message_and_unref(conn, msg);

	if (service->action) {
		msg = dbus_message_new_method_return(service->action);
		send_message_and_unref(conn, msg);
		dbus_message_unref(service->action);
		service->action = NULL;
	}

	g_free(service->bus_name);
	service->bus_name = NULL;
}

static DBusHandlerResult get_connection_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;
	const char *bus_name;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	if (service->bus_name)
		bus_name = service->bus_name;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &bus_name,
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
		g_timeout_remove(service->startup_timer);
		service->startup_timer = 0;
	} else
		debug("service_filter: timeout was already removed!");

	name_listener_add(conn, new, (name_cb_t) service_exit, service);

	msg = dbus_message_new_signal(service->object_path,
					SERVICE_INTERFACE, "Started");
	if (msg)
		send_message_and_unref(conn, msg);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void abort_startup(struct service *service, DBusConnection *conn, int ecode)
{
	DBusError err;

	dbus_error_init(&err);
	dbus_bus_remove_match(get_dbus_connection(), NAME_MATCH, &err);
	if (dbus_error_is_set(&err)) {
		error("Remove match \"%s\" failed: %s" NAME_MATCH, err.message);
		dbus_error_free(&err);
	}

	dbus_connection_remove_filter(get_dbus_connection(),
			service_filter, service);

	g_timeout_remove(service->startup_timer);
	service->startup_timer = 0;

	if (service->action) {
		error_failed(get_dbus_connection(), service->action, ecode);
		dbus_message_unref(service->action);
		service->action = NULL;
	}

	if (service->pid && kill(service->pid, SIGKILL) < 0)
		error("kill(%d, SIGKILL): %s (%d)", service->pid,
				strerror(errno), errno);
}

static void service_died(GPid pid, gint status, gpointer data)
{
	struct service *service = data;

	debug("%s (%s) exited with status %d", service->name,
			service->ident, status);

	g_spawn_close_pid(pid);
	service->pid = 0;

	if (service->startup_timer)
		abort_startup(service, get_dbus_connection(), ECANCELED);

	if (service->shutdown_timer) {
		g_timeout_remove(service->shutdown_timer);
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

	debug("Sending SIGKILL to \"%s\" (PID %d) since it didn't exit yet",
			service->name, service->pid);

	if (kill(service->pid, SIGKILL) < 0)
		error("kill(%d, SIGKILL): %s (%d)", service->pid,
				strerror(errno), errno);

	service->shutdown_timer = 0;

	return FALSE;
}

static void stop_service(struct service *service, gboolean remove)
{
	if (kill(service->pid, SIGTERM) < 0)
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
	GError *err = NULL;
	DBusError derr;
	char **argv, *cmdline;
	int argc;

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

	cmdline = g_strdup_printf("%s/bluetoothd-service-%s %s",
				SERVICEDIR, service->ident,
				service->opts ? service->opts : "");

	g_shell_parse_argv(cmdline, &argc, &argv, &err);
	if (err != NULL) {
		error("Unable to parse cmdline \"%s\": %s", cmdline,
				err->message);
		g_error_free(err);
		dbus_connection_remove_filter(conn, service_filter, service);
		dbus_bus_remove_match(conn, NAME_MATCH, NULL);
		g_free(cmdline);
		return -1;
	}

	g_free(cmdline);

	if (!g_spawn_async(SERVICEDIR, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
				service_setup, service, &service->pid, NULL)) {
		error("Unable to execute %s", argv[0]);
		dbus_connection_remove_filter(conn, service_filter, service);
		dbus_bus_remove_match(conn, NAME_MATCH, NULL);
		g_strfreev(argv);
		return -1;
	}

	g_child_watch_add(service->pid, service_died, service);

	debug("%s executed with PID %d", argv[0], service->pid);

	g_strfreev(argv);

	service->startup_timer = g_timeout_add(STARTUP_TIMEOUT,
						service_startup_timeout,
						service);

	return 0;
}

static DBusHandlerResult start(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct service *service = data;

	if (service->pid)
		return error_failed(conn, msg, EALREADY);

	if (service_start(service, conn) < 0)
		return error_failed(conn, msg, ENOEXEC);

	service->action = dbus_message_ref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult stop(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct service *service  = data;

	if (!service->bus_name)
		return error_failed(conn, msg, EPERM);

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

	running = service->bus_name ? TRUE : FALSE;

	dbus_message_append_args(reply,
			DBUS_TYPE_BOOLEAN, &running,
			DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult list_users(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult remove_user(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult set_trusted(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	GSList *l;
	DBusMessage *reply;
	const char *address;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	if (check_address(address) < 0)
		return error_invalid_arguments(conn, msg);

	l = g_slist_find_custom(service->trusted_devices, address, (GCompareFunc) strcasecmp);
	if (l)
		return error_trusted_device_already_exists(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	service->trusted_devices = g_slist_append(service->trusted_devices, g_strdup(address));

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult is_trusted(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	GSList *l;
	DBusMessage *reply;
	const char *address;
	dbus_bool_t trusted;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	l = g_slist_find_custom(service->trusted_devices, address, (GCompareFunc) strcasecmp);
	trusted = (l? TRUE : FALSE);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(msg,
				DBUS_TYPE_BOOLEAN, &trusted,
				DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult remove_trust(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service *service = data;
	GSList *l;
	DBusMessage *reply;
	const char *address;
	void *paddress;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &address,
			DBUS_TYPE_INVALID))
		return error_invalid_arguments(conn, msg);

	l = g_slist_find_custom(service->trusted_devices, address, (GCompareFunc) strcasecmp);
	if (!l)
		return error_trusted_device_does_not_exists(conn, msg);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	paddress = l->data;
	service->trusted_devices = g_slist_remove(service->trusted_devices, l->data);
	g_free(paddress);

	return send_message_and_unref(conn, reply);
}

static struct service_data services_methods[] = {
	{ "GetName",		get_name		},
	{ "GetDescription",	get_description		},
	{ "GetConnectionName",	get_connection_name	},
	{ "Start",		start			},
	{ "Stop",		stop			},
	{ "IsRunning",		is_running		},
	{ "ListUsers",		list_users		},
	{ "RemoveUser",		remove_user		},
	{ "SetTrusted",		set_trusted		},
	{ "IsTrusted",		is_trusted		},
	{ "RemoveTrust",	remove_trust		},
	{ NULL, NULL }
};

static DBusHandlerResult msg_func_services(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	service_handler_func_t handler;
	const char *iface;

	iface = dbus_message_get_interface(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, iface) &&
			!strcmp("Introspect", dbus_message_get_member(msg))) {
		return simple_introspect(conn, msg, data);
	} else if (strcmp(SERVICE_INTERFACE, iface) == 0) {

		handler = find_service_handler(services_methods, msg);
		if (handler)
			return handler(conn, msg, data);

		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	} else
		return error_unknown_method(conn, msg);
}

static const DBusObjectPathVTable services_vtable = {
	.message_function	= &msg_func_services,
	.unregister_function	= NULL
};

static int register_service(struct service *service)
{
	char obj_path[PATH_MAX], *suffix;
	DBusConnection *conn = get_dbus_connection();
	DBusMessage *signal;

	snprintf(obj_path, sizeof(obj_path) - 1, "/org/bluez/service_%s",
			service->filename);

	/* Don't include the .service part in the path */
	suffix = strstr(obj_path, SERVICE_SUFFIX);
	*suffix = '\0';

	debug("Registering service object: ident=%s, name=%s (%s)",
			service->ident, service->name, obj_path);

	if (!dbus_connection_register_object_path(conn, obj_path,
						&services_vtable, service))
		return -ENOMEM;

	service->object_path = g_strdup(obj_path);

	services = g_slist_append(services, service);

	signal = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
						"ServiceAdded");
	if (!signal) {
		dbus_connection_unregister_object_path(conn, service->object_path);
		return -ENOMEM;
	}

	dbus_message_append_args(signal,
				DBUS_TYPE_STRING, &service->object_path,
				DBUS_TYPE_INVALID);

	send_message_and_unref(conn, signal);

	return 0;
}

static int unregister_service(struct service *service)
{
	DBusMessage *signal;
	DBusConnection *conn = get_dbus_connection();

	debug("Unregistering service object: %s", service->object_path);

	if (!dbus_connection_unregister_object_path(conn, service->object_path))
		return -ENOMEM;

	if (service->records)
		unregister_service_records(service->records);

	if (service->bus_name)
		name_listener_remove(get_dbus_connection(), service->bus_name,
					(name_cb_t) service_exit, service);

	signal = dbus_message_new_signal(service->object_path,
					SERVICE_INTERFACE, "Stopped");
	send_message_and_unref(conn, signal);

	signal = dbus_message_new_signal(BASE_PATH, MANAGER_INTERFACE,
						"ServiceRemoved");
	if (signal) {
		dbus_message_append_args(signal,
					DBUS_TYPE_STRING, &service->object_path,
					DBUS_TYPE_INVALID);
		send_message_and_unref(conn, signal);
	}


	if (service->pid) {
		if (service->startup_timer) {
			abort_startup(service, get_dbus_connection(), ECANCELED);
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

	service->opts = g_key_file_get_string(keyfile, SERVICE_GROUP,
						"Options", &err);
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

static gboolean startup_services(gpointer user_data)
{
	GSList *l;

	for (l = services; l != NULL; l = l->next) {
		struct service *service = l->data;

		if (service->autostart)
			service_start(service, get_dbus_connection());

	}

	return FALSE;
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
	}

	closedir(d);

	notify_add(path, service_notify, NULL);

	g_idle_add(startup_services, NULL);

	return 0;
}

