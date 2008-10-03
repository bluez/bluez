/*
 *
 *  OBEX Client
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <glib.h>
#include <gdbus.h>

#define CLIENT_SERVICE  "org.openobex.client"

#define CLIENT_INTERFACE  "org.openobex.Client"
#define CLIENT_PATH       "/"

static DBusMessage *send_files(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBusMessageIter iter, array;
	const char *agent;

	dbus_message_iter_init(message, &iter);

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key, *val;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		dbus_message_iter_recurse(&entry, &value);

		switch (dbus_message_iter_get_arg_type(&value)) {
		case DBUS_TYPE_STRING:
			dbus_message_iter_get_basic(&value, &val);
			printf("%s %s\n", key, val);
			break;
		}

		dbus_message_iter_next(&array);
	}

	dbus_message_iter_next(&iter);

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		const char *file;

		dbus_message_iter_get_basic(&array, &file);
		printf("  Filename %s\n", file);

		dbus_message_iter_next(&array);
	}

	dbus_message_iter_next(&iter);

	dbus_message_iter_get_basic(&iter, &agent);
	printf("  Agent %s\n", agent);

	return dbus_message_new_method_return(message);
}

static GDBusMethodTable client_methods[] = {
	{ "SendFiles", "a{sv}aso", "",send_files },
	{ }
};

static GMainLoop *event_loop = NULL;

static void sig_term(int sig)
{
	g_main_loop_quit(event_loop);
}

int main(int argc, char *argv[])
{
	struct sigaction sa;
	DBusConnection *conn;
	DBusError err;

	dbus_error_init(&err);

	conn = g_dbus_setup_bus(DBUS_BUS_SESSION, CLIENT_SERVICE, &err);
	if (conn == NULL) {
		if (dbus_error_is_set(&err) == TRUE) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		} else
			fprintf(stderr, "Can't register with session bus\n");
		exit(EXIT_FAILURE);
	}

	if (g_dbus_register_interface(conn, CLIENT_PATH, CLIENT_INTERFACE,
						client_methods, NULL, NULL,
							NULL, NULL) == FALSE) {
		fprintf(stderr, "Can't register client interface\n");
		dbus_connection_unref(conn);
		exit(EXIT_FAILURE);
	}

	event_loop = g_main_loop_new(NULL, FALSE);

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_term;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	g_main_loop_run(event_loop);

	g_dbus_unregister_interface(conn, CLIENT_PATH, CLIENT_INTERFACE);

	dbus_connection_unref(conn);

	g_main_loop_unref(event_loop);

	return 0;
}
