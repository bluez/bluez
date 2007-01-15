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

#include <dbus/dbus.h>

#include "hcid.h"
#include "dbus.h"
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

static GSList *services = NULL;

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


struct service_call *service_call_new(DBusConnection *conn, DBusMessage *msg,
					struct service *service)
{
	struct service_call *call;
	call = malloc(sizeof(struct service_call));
	if (!call)
		return NULL;
	memset(call, 0, sizeof(struct service_call));
	call->conn = dbus_connection_ref(conn);
	call->msg = dbus_message_ref(msg);
	call->service = service;

	return call;
}

void service_call_free(void *data)
{
	struct service_call *call = data;

	if (!call)
		return;

	if (call->conn)
		dbus_connection_unref(call->conn);

	if(call->msg)
		dbus_message_unref(call->msg);
	
	free(call);
}

static void service_free(struct service *service)
{
	if (!service)
		return;

	if (service->object_path)
		free(service->object_path);

	if (service->action)
		dbus_message_unref(service->action);

	if (service->bus_name)
		free(service->bus_name);

	if (service->exec)
		free(service->exec);

	if (service->name)
		free(service->name);

	if (service->descr)
		free(service->descr);

	if (service->trusted_devices) {
		g_slist_foreach(service->trusted_devices, (GFunc) free, NULL);
		g_slist_free(service->trusted_devices);
	}

	if (service->records) {
		g_slist_foreach(service->records, (GFunc) binary_record_free, NULL);
		g_slist_free(service->records);
	}

	free(service);
}

int register_service_records(GSList *lrecords)
{
	while (lrecords) {
		struct binary_record *rec = lrecords->data;
		lrecords = lrecords->next;
		uint32_t handle = 0;

		if (!rec || !rec->buf || rec->handle != 0xffffffff)
			continue;

		if (register_sdp_record(rec->buf->data, rec->buf->data_size, &handle) < 0) {
			/* FIXME: If just one of the service record registration fails */
			error("Service Record registration failed:(%s, %d)",
				strerror(errno), errno);
		}

		rec->handle = handle;
	}

	return 0;
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

	free(service->bus_name);
	service->bus_name = NULL;
}

static void forward_reply(DBusPendingCall *call, void *udata)
{
	struct service_call *call_data = udata;
	DBusMessage *reply = dbus_pending_call_steal_reply(call);
	DBusMessage *source_reply;
	const char *sender;

	sender = dbus_message_get_sender(call_data->msg);

	source_reply = dbus_message_copy(reply);
	dbus_message_set_destination(source_reply, sender);
	dbus_message_set_no_reply(source_reply, TRUE);
	dbus_message_set_reply_serial(source_reply, dbus_message_get_serial(call_data->msg));

	send_message_and_unref(call_data->conn, source_reply);

	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
}

static DBusHandlerResult get_connection_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct service *service = data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply,
			DBUS_TYPE_STRING, &service->bus_name,
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

static void service_died(GPid pid, gint status, gpointer data)
{
	struct service *service = data;

	debug("%s (%s) exited with status %d", service->exec, service->name,
			status);

	if (service->startup_timer) {
		g_timeout_remove(service->startup_timer);
		service->startup_timer = 0;

		if (service->action) {
			error_failed(get_dbus_connection(), service->action,
					ECANCELED);
			dbus_message_unref(service->action);
			service->action = NULL;
		}
	}

	if (service->shutdown_timer) {
		g_timeout_remove(service->shutdown_timer);
		service->shutdown_timer = 0;
	}

	g_spawn_close_pid(pid);

	service->pid = 0;
}

#define NAME_MATCH "interface=" DBUS_INTERFACE_DBUS ",member=NameOwnerChanged"

static DBusHandlerResult service_filter(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
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

	service->bus_name = strdup(new);

	dbus_bus_remove_match(conn, NAME_MATCH, NULL);
	dbus_connection_remove_filter(conn, service_filter, service);

	msg = dbus_message_new_signal(service->object_path,
					SERVICE_INTERFACE, "Started");
	if (msg) {
		dbus_message_append_args(msg, DBUS_TYPE_STRING, &new,
					DBUS_TYPE_INVALID);
		send_message_and_unref(conn, msg);
	}

	if (service->action) {
		msg = dbus_message_new_method_return(service->action);
		if (msg) {
			dbus_message_append_args(msg, DBUS_TYPE_STRING, &new,
						DBUS_TYPE_INVALID);
			send_message_and_unref(conn, msg);
		}

		dbus_message_unref(service->action);
		service->action = NULL;
	}

	g_timeout_remove(service->startup_timer);
	service->startup_timer = 0;

	name_listener_add(conn, new, (name_cb_t) service_exit, service);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static gboolean service_shutdown_timeout(gpointer data)
{
	struct service *service = data;

	debug("Sending SIGKILL to %s since it didn't exit yet",
			service->exec);

	kill(service->pid, SIGKILL);

	service->shutdown_timer = 0;

	return FALSE;
}

static void stop_service(struct service *service)
{
	kill(service->pid, SIGTERM);
	service->shutdown_timer = g_timeout_add(SHUTDOWN_TIMEOUT,
						service_shutdown_timeout,
						service);
}

static gboolean service_startup_timeout(gpointer data)
{
	struct service *service = data;

	debug("Killing %s because it did not connect to D-Bus in time",
			service->exec);

	if (service->action) {
		error_failed(get_dbus_connection(), service->action, ETIME);
		dbus_message_unref(service->action);
		service->action = NULL;
	}

	stop_service(service);

	service->startup_timer = 0;

	return FALSE;
}

static DBusHandlerResult start(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	GError *err = NULL;
	struct service *service = data;
	char **argv;
	int argc;

	if (service->pid)
		return error_failed(conn, msg, EALREADY);

	g_shell_parse_argv(service->exec, &argc, &argv, &err);

	if (err != NULL) {
		error("Unable to parse exec line \"%s\": %s", service->exec, err->message);
		g_error_free(err);
		return error_failed(conn, msg, ENOEXEC);
	}

	if (!g_spawn_async(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
				service_setup, service, &service->pid, NULL)) {
		error("Unable to execute %s", service->exec);
		g_strfreev(argv);
		return error_failed(conn, msg, ENOEXEC);
	}

	g_strfreev(argv);

	service->watch_id = g_child_watch_add(service->pid, service_died,
						service);

	debug("%s executed with PID %d", service->exec, service->pid);

	if (!dbus_connection_add_filter(conn, service_filter, service, NULL)) {
		error("Unable to add signal filter");
		kill(service->pid, SIGKILL);
	}

	dbus_bus_add_match(conn, NAME_MATCH, NULL);

	service->startup_timer = g_timeout_add(STARTUP_TIMEOUT,
						service_startup_timeout,
						service);

	service->action = dbus_message_ref(msg);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult stop(DBusConnection *conn,
				DBusMessage *msg, void *data)
{
	struct service *service  = data;

	if (!service->bus_name)
		return error_failed(conn, msg, EPERM);

	stop_service(service);

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

	service->trusted_devices = g_slist_append(service->trusted_devices, strdup(address));

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
	free(paddress);

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
	struct service *service = data;
	service_handler_func_t handler;
	DBusPendingCall *pending;
	DBusMessage *forward;
	struct service_call *call_data;
	const char *iface;

	if (!hcid_dbus_use_experimental())
		return error_unknown_method(conn, msg);

	iface = dbus_message_get_interface(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, iface) &&
			!strcmp("Introspect", dbus_message_get_member(msg))) {
		return simple_introspect(conn, msg, data);
	} else if (strcmp(SERVICE_INTERFACE, iface) == 0) {

		handler = find_service_handler(services_methods, msg);
		if (handler)
			return handler(conn, msg, data);

		forward = dbus_message_copy(msg);
		if(!forward)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		dbus_message_set_destination(forward, service->bus_name);
		dbus_message_set_path(forward, dbus_message_get_path(msg));

		call_data = service_call_new(conn, msg, service);
		if (!call_data) {
			dbus_message_unref(forward);
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		}

		if (dbus_connection_send_with_reply(conn, forward, &pending, -1) == FALSE) {
			service_call_free(call_data);
			dbus_message_unref(forward);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		dbus_pending_call_set_notify(pending, forward_reply, call_data, service_call_free);

		dbus_message_unref(forward);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else
		return error_unknown_method(conn, msg);
}

static const DBusObjectPathVTable services_vtable = {
	.message_function	= &msg_func_services,
	.unregister_function	= NULL
};

int register_service(char *path, struct service *service)
{
	char obj_path[PATH_MAX], *slash;
	DBusConnection *conn = get_dbus_connection();

	path[strlen(path) - strlen(SERVICE_SUFFIX)] = '\0';
	slash = strrchr(path, '/');

	snprintf(obj_path, sizeof(obj_path) - 1, "/org/bluez/service_%s", slash + 1);

	debug("Registering service object: exec=%s, name=%s (%s)",
			service->exec, service->name, obj_path);

	if (!dbus_connection_register_object_path(conn, obj_path,
						&services_vtable, service))
		return -ENOMEM;

	service->object_path = strdup(obj_path);

	services = g_slist_append(services, strdup(obj_path));

	return 0;
}

int unregister_service(const char *sender, const char *path)
{
	struct service *service;
	DBusConnection *conn = get_dbus_connection();
	GSList *l;

	debug("Unregistering service object: %s", path);

	if (dbus_connection_get_object_path_data(conn, path, (void *) &service)) {
		/* No data assigned to this path or it is not the owner */
		if (!service || strcmp(sender, service->bus_name))
			return -EPERM;

		if (service->records)
			unregister_service_records(service->records);

		service_free(service);
	}

	if (!dbus_connection_unregister_object_path(conn, path))
		return -ENOMEM;

	name_listener_remove(conn, sender, (name_cb_t) service_exit, service);

	l = g_slist_find_custom(services, path, (GCompareFunc) strcmp);
	if (l) {
		void *p = l->data;
		services = g_slist_remove(services, l->data);
		free(p);
	}

	return 0;
}

static void release_service(struct service *service)
{
	if (service->records)
		unregister_service_records(service->records);

	if (service->bus_name)
		name_listener_remove(get_dbus_connection(), service->bus_name,
					(name_cb_t) service_exit, service);

	if (service->watch_id)
		g_source_remove(service->watch_id);

	if (service->pid)
		kill(service->pid, SIGKILL);

	if (service->startup_timer)
		g_timeout_remove(service->startup_timer);

	if (service->shutdown_timer)
		g_timeout_remove(service->shutdown_timer);

	service_free(service);
}

void release_services(DBusConnection *conn)
{
	GSList *l = services;
	struct service *service;
	const char *path;

	debug("release_services");

	while (l) {
		path = l->data;

		l = l->next;

		if (dbus_connection_get_object_path_data(conn, path, (void *) &service)) {
			if (!service)
				continue;

			release_service(service);
		}

		dbus_connection_unregister_object_path(conn, path);
	}

	g_slist_foreach(services, (GFunc) free, NULL);
	g_slist_free(services);
	services = NULL;
}

void append_available_services(DBusMessageIter *array_iter)
{
	GSList *l;

	for (l = services; l != NULL; l = l->next)
		dbus_message_iter_append_basic(array_iter,
					DBUS_TYPE_STRING, &l->data);
}

static struct service *create_service(const char *file)
{
	GKeyFile *keyfile;
	struct service *service;

	service = malloc(sizeof(struct service));
	if (!service) {
		error("Unable to allocate new service");
		return NULL;
	}

	memset(service, 0, sizeof(struct service));

	keyfile = g_key_file_new();

	if (!g_key_file_load_from_file(keyfile, file, 0, NULL)) {
		error("Parsing %s failed", file);
		goto failed;
	}

	service->exec = g_key_file_get_string(keyfile, SERVICE_GROUP,
						"Exec", NULL);
	if (!service->exec) {
		error("%s doesn't contain a Exec attribute", file);
		goto failed;
	}

	service->name = g_key_file_get_string(keyfile, SERVICE_GROUP,
						"Name", NULL);
	if (!service->name) {
		error("%s doesn't contain a Name attribute", file);
		goto failed;
	}

	service->descr = g_key_file_get_string(keyfile, SERVICE_GROUP,
						"Description", NULL);

	g_key_file_free(keyfile);

	return service;

failed:
	g_key_file_free(keyfile);
	service_free(service);
	return NULL;
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

		register_service(full_path, service);
	}

	closedir(d);

	return 0;
}


