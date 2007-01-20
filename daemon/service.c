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

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus-helper.h"
#include "logging.h"
#include "notify.h"

#include "system.h"
#include "service.h"

#define SERVICE_INTERFACE "org.bluez.Service"

static DBusConnection *connection = NULL;

static char *test_conn_name = NULL;
static GPid test_service_pid = 0;
static guint test_watch_id = -1;

DBusHandlerResult manager_list_services(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;
	const char path[] = "/org/bluez/service", *ptr = path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);

	dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &ptr);

	dbus_message_iter_close_container(&iter, &array);

	return dbus_connection_send_and_unref(conn, reply);
}

DBusHandlerResult manager_find_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *pattern;
	const char path[] = "/org/bluez/service", *ptr = path;

	dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &pattern, DBUS_TYPE_INVALID);

	debug("Searching service with pattern \"%s\"", pattern);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

DBusHandlerResult manager_activate_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *pattern;

	dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &pattern, DBUS_TYPE_INVALID);

	debug("Activating service with pattern \"%s\"", pattern);

	reply = dbus_message_new_error(msg, ERROR_INTERFACE ".NotFound",
						"Service does not exists");
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult service_get_name(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char name[] = "Demo service", *ptr = name;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult service_get_description(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char text[] = "Demo service for testing", *ptr = text;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static void service_died(GPid pid, gint status, gpointer data)
{
	debug("Child with PID %d died with status %d", pid, status);

	g_spawn_close_pid(pid);
	test_service_pid = 0;
}

static DBusHandlerResult service_start(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	GPid pid;
	char **argv;
	int argc;

	debug("Starting service");

	if (test_conn_name) {
		reply = dbus_message_new_error(msg, ERROR_INTERFACE ".AlreadyRunning",
						"Service is already running");
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	} else {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		test_conn_name = strdup("org.bluez.service");
		if (!test_conn_name)
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

		dbus_message_append_args(reply, DBUS_TYPE_INVALID);

		g_shell_parse_argv("/data/bluez/utils/daemon/bluetoothd_echo", &argc, &argv, NULL);

		g_spawn_async(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, NULL);

		g_strfreev(argv);

		test_watch_id = g_child_watch_add(pid, service_died, NULL);

		debug("New process with PID %d executed", pid);

		test_service_pid = pid;
	}

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult service_stop(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	debug("Stopping service");

	if (test_conn_name) {
		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		free(test_conn_name);
		test_conn_name = NULL;

		kill(test_service_pid, SIGTERM);
		test_service_pid = 0;

		dbus_message_append_args(reply, DBUS_TYPE_INVALID);
	} else {
		reply = dbus_message_new_error(msg, ERROR_INTERFACE ".NotRunning",
						"Service is not running");
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult service_is_running(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_bool_t running;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	running = test_conn_name ? TRUE : FALSE;

	dbus_message_append_args(reply, DBUS_TYPE_BOOLEAN, &running,
					DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusMethodVTable service_table[] = {
	{ "GetName", service_get_name,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ "GetDescription", service_get_description,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_STRING_AS_STRING },
	{ "Start", service_start,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_INVALID_AS_STRING },
	{ "Stop", service_stop,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_INVALID_AS_STRING },
	{ "IsRunning", service_is_running,
		DBUS_TYPE_INVALID_AS_STRING, DBUS_TYPE_BOOLEAN_AS_STRING },
	{ }
};

static void config_notify(int action, const char *name, void *data)
{
	switch (action) {
	case NOTIFY_CREATE:
		debug("File %s/%s created", CONFIGDIR, name);
		break;

	case NOTIFY_DELETE:
		debug("File %s/%s deleted", CONFIGDIR, name);
		break;

	case NOTIFY_MODIFY:
		debug("File %s/%s modified", CONFIGDIR, name);
		break;
	}
}

int service_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	info("Starting service framework");

	notify_add(CONFIGDIR, config_notify, NULL);

	if (dbus_connection_create_object_path(connection,
				"/org/bluez/service", NULL, NULL) == FALSE) {
		error("Service path registration failed");
		dbus_connection_unref(connection);
		return -1;
	}

	if (dbus_connection_register_interface(connection, "/org/bluez/service",
			SERVICE_INTERFACE, service_table, NULL) == FALSE) {
		error("Service interface registration failed");
		dbus_connection_destroy_object_path(connection, "/org/bluez/service");
		dbus_connection_unref(connection);
		return -1;
	}

	return 0;
}

void service_exit(void)
{
	info("Stopping service framework");

	notify_remove(CONFIGDIR);

	dbus_connection_unregister_interface(connection,
				"/org/bluez/service", SERVICE_INTERFACE);

	dbus_connection_destroy_object_path(connection, "/org/bluez/service");

	dbus_connection_unref(connection);

	connection = NULL;
}
