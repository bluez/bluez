/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
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
#include <signal.h>
#include <getopt.h>
#include <string.h>

#include <dbus/dbus.h>

#define INTERFACE "org.bluez.Security"

static volatile sig_atomic_t __io_canceled = 0;
static volatile sig_atomic_t __io_terminated = 0;

static void sig_term(int sig)
{
	__io_canceled = 1;
}

static DBusHandlerResult agent_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *name, *old, *new;

	if (!dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &old,
				DBUS_TYPE_STRING, &new, DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for NameOwnerChanged signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!strcmp(name, "org.bluez") && *new == '\0') {
		fprintf(stderr, "Authorization service has been terminated\n");
		__io_terminated = 1;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult authorize_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *adapter, *address, *service, *string;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &adapter, DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &service, DBUS_TYPE_STRING, &string,
							DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for passkey Confirm method");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	printf("Authorization request for device %s\n", address);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		fprintf(stderr, "Can't create reply message\n");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_connection_flush(conn);

	dbus_message_unref(reply);
	
	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult cancel_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *adapter, *address, *service, *string;

	if (!dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &adapter, DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &service, DBUS_TYPE_STRING, &string,
							DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for passkey Confirm method");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	printf("Request canceled for device %s\n", address);

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		fprintf(stderr, "Can't create reply message\n");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_connection_flush(conn);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult release_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for Release method");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!__io_canceled)
		fprintf(stderr, "Authorization agent has been released\n");

	__io_terminated = 1;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		fprintf(stderr, "Can't create reply message\n");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	dbus_connection_send(conn, reply, NULL);

	dbus_connection_flush(conn);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult auth_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	if (dbus_message_is_method_call(msg, "org.bluez.AuthorizationAgent", "Authorize"))
		return authorize_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.AuthorizationAgent", "Cancel"))
		return cancel_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.AuthorizationAgent", "Release"))
		return release_message(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable auth_table = {
	.message_function = auth_message,
};

static int register_auth(DBusConnection *conn, const char *auth_path)
{
	DBusMessage *msg, *reply;
	DBusError err;

	if (!dbus_connection_register_object_path(conn, auth_path,
							&auth_table, NULL)) {
		fprintf(stderr, "Can't register object path for agent\n");
		return -1;
	}

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
			INTERFACE, "RegisterDefaultAuthorizationAgent");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return -1;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &auth_path,
							DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr, "Can't register authorization agent\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return -1;
	}

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	return 0;
}

static int unregister_auth(DBusConnection *conn, const char *auth_path)
{
	DBusMessage *msg, *reply;
	DBusError err;

	msg = dbus_message_new_method_call("org.bluez", "/org/bluez",
			INTERFACE, "UnregisterDefaultAuthorizationAgent");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		dbus_connection_unref(conn);
		exit(1);
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &auth_path,
							DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr, "Can't unregister authorization agent\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return -1;
	}

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	dbus_connection_unregister_object_path(conn, auth_path);

	return 0;
}

static void usage(void)
{
	printf("Bluetooth authorization agent ver %s\n\n", VERSION);

	printf("Usage:\n"
		"\tauth-agent [--path auth-path]\n"
		"\n");
}

static struct option main_options[] = {
	{ "path",		1, 0, 'p' },
	{ "help",		0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	struct sigaction sa;
	DBusConnection *conn;
	char match_string[128], default_path[128], *auth_path = NULL;
	int opt;

	snprintf(default_path, sizeof(default_path),
				"/org/bluez/auth_agent_%d", getpid());

	while ((opt = getopt_long(argc, argv, "+p:h", main_options, NULL)) != EOF) {
		switch(opt) {
		case 'p':
			if (optarg[0] != '/') {
				fprintf(stderr, "Invalid path\n");
				exit(1);
			}
			auth_path = strdup(optarg);
			break;
		case 'h':
			usage();
			exit(0);
		default:
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (!auth_path)
		auth_path = strdup(default_path);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		fprintf(stderr, "Can't get on system bus");
		exit(1);
	}

	if (register_auth(conn, auth_path) < 0) {
		dbus_connection_unref(conn);
		exit(1);
	}

	if (!dbus_connection_add_filter(conn, agent_filter, NULL, NULL))
		fprintf(stderr, "Can't add signal filter");

	snprintf(match_string, sizeof(match_string),
			"interface=%s,member=NameOwnerChanged,arg0=%s",
					DBUS_INTERFACE_DBUS, "org.bluez");

	dbus_bus_add_match(conn, match_string, NULL);

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags   = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT,  &sa, NULL);

	while (!__io_canceled && !__io_terminated) {
		if (dbus_connection_read_write_dispatch(conn, 500) != TRUE)
			break;
	}

	if (!__io_terminated)
		unregister_auth(conn, auth_path);

	dbus_connection_unref(conn);

	return 0;
}
