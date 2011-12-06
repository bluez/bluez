/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

static char *passkey_value = NULL;
static int passkey_delay = 0;
static int do_reject = 0;

static volatile sig_atomic_t __io_canceled = 0;
static volatile sig_atomic_t __io_terminated = 0;
static volatile sig_atomic_t exit_on_release = 1;

static void sig_term(int sig)
{
	__io_canceled = 1;
}

static DBusHandlerResult agent_filter(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *name, *old, *new;

	if (!dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS,
						"NameOwnerChanged"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_get_args(msg, NULL,
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_STRING, &old,
					DBUS_TYPE_STRING, &new,
					DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for NameOwnerChanged signal");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (!strcmp(name, "org.bluez") && *new == '\0') {
		fprintf(stderr, "Agent has been terminated\n");
		__io_terminated = 1;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult request_pincode_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path;

	if (!passkey_value)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for RequestPinCode method");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (do_reject) {
		reply = dbus_message_new_error(msg, "org.bluez.Error.Rejected", "");
		goto send;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		fprintf(stderr, "Can't create reply message\n");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	printf("Pincode request for device %s\n", path);

	if (passkey_delay) {
		printf("Waiting for %d seconds\n", passkey_delay);
		sleep(passkey_delay);
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &passkey_value,
							DBUS_TYPE_INVALID);

send:
	dbus_connection_send(conn, reply, NULL);

	dbus_connection_flush(conn);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult request_passkey_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path;
	unsigned int passkey;

	if (!passkey_value)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
							DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for RequestPasskey method");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (do_reject) {
		reply = dbus_message_new_error(msg, "org.bluez.Error.Rejected", "");
		goto send;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		fprintf(stderr, "Can't create reply message\n");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	printf("Passkey request for device %s\n", path);

	if (passkey_delay) {
		printf("Waiting for %d seconds\n", passkey_delay);
		sleep(passkey_delay);
	}

	passkey = strtoul(passkey_value, NULL, 10);

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &passkey,
							DBUS_TYPE_INVALID);

send:
	dbus_connection_send(conn, reply, NULL);

	dbus_connection_flush(conn);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult request_confirmation_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path;
	unsigned int passkey;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_UINT32, &passkey,
							DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for RequestPasskey method");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (do_reject) {
		reply = dbus_message_new_error(msg, "org.bluez.Error.Rejected", "");
		goto send;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		fprintf(stderr, "Can't create reply message\n");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	printf("Confirmation request of %u for device %s\n", passkey, path);

	if (passkey_delay) {
		printf("Waiting for %d seconds\n", passkey_delay);
		sleep(passkey_delay);
	}

send:
	dbus_connection_send(conn, reply, NULL);

	dbus_connection_flush(conn);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult authorize_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *path, *uuid;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_STRING, &uuid,
							DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for Authorize method");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (do_reject) {
		reply = dbus_message_new_error(msg, "org.bluez.Error.Rejected", "");
		goto send;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		fprintf(stderr, "Can't create reply message\n");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	printf("Authorizing request for %s\n", path);

send:
	dbus_connection_send(conn, reply, NULL);

	dbus_connection_flush(conn);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult cancel_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;

	if (!dbus_message_get_args(msg, NULL, DBUS_TYPE_INVALID)) {
		fprintf(stderr, "Invalid arguments for passkey Confirm method");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	printf("Request canceled\n");

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
		fprintf(stderr, "Agent has been released\n");

	if (exit_on_release)
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

static DBusHandlerResult agent_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	if (dbus_message_is_method_call(msg, "org.bluez.Agent",
							"RequestPinCode"))
		return request_pincode_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.Agent",
							"RequestPasskey"))
		return request_passkey_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.Agent",
							"RequestConfirmation"))
		return request_confirmation_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.Agent", "Authorize"))
		return authorize_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.Agent", "Cancel"))
		return cancel_message(conn, msg, data);

	if (dbus_message_is_method_call(msg, "org.bluez.Agent", "Release"))
		return release_message(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable agent_table = {
	.message_function = agent_message,
};

static int register_agent(DBusConnection *conn, const char *adapter_path,
						const char *agent_path,
						const char *capabilities)
{
	DBusMessage *msg, *reply;
	DBusError err;

	msg = dbus_message_new_method_call("org.bluez", adapter_path,
					"org.bluez.Adapter", "RegisterAgent");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return -1;
	}

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &agent_path,
					DBUS_TYPE_STRING, &capabilities,
					DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr, "Can't register agent\n");
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

static int unregister_agent(DBusConnection *conn, const char *adapter_path,
							const char *agent_path)
{
	DBusMessage *msg, *reply;
	DBusError err;

	msg = dbus_message_new_method_call("org.bluez", adapter_path,
					"org.bluez.Adapter", "UnregisterAgent");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return -1;
	}

	dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &agent_path,
							DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr, "Can't unregister agent\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return -1;
	}

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	dbus_connection_unregister_object_path(conn, agent_path);

	return 0;
}

static void create_paired_device_reply(DBusPendingCall *pending,
							void *user_data)
{
	__io_terminated = 1;
	return;
}

static int create_paired_device(DBusConnection *conn, const char *adapter_path,
						const char *agent_path,
						const char *capabilities,
						const char *device)
{
	dbus_bool_t success;
	DBusMessage *msg;
	DBusPendingCall *pending;

	msg = dbus_message_new_method_call("org.bluez", adapter_path,
						"org.bluez.Adapter",
						"CreatePairedDevice");
	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return -1;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &device,
					DBUS_TYPE_OBJECT_PATH, &agent_path,
					DBUS_TYPE_STRING, &capabilities,
					DBUS_TYPE_INVALID);

	exit_on_release = 0;
	success = dbus_connection_send_with_reply(conn, msg, &pending, -1);
	if (pending)
		dbus_pending_call_set_notify(pending,
						create_paired_device_reply,
						NULL, NULL);

	dbus_message_unref(msg);

	if (!success) {
		fprintf(stderr, "Not enough memory for message send\n");
		return -1;
	}

	dbus_connection_flush(conn);

	return 0;
}

static char *get_default_adapter_path(DBusConnection *conn)
{
	DBusMessage *msg, *reply;
	DBusError err;
	const char *reply_path;
	char *path;

	msg = dbus_message_new_method_call("org.bluez", "/",
					"org.bluez.Manager", "DefaultAdapter");

	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return NULL;
	}

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr,
			"Can't get default adapter\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	if (!dbus_message_get_args(reply, &err,
					DBUS_TYPE_OBJECT_PATH, &reply_path,
					DBUS_TYPE_INVALID)) {
		fprintf(stderr,
			"Can't get reply arguments\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		dbus_message_unref(reply);
		return NULL;
	}

	path = strdup(reply_path);

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	return path;
}

static char *get_adapter_path(DBusConnection *conn, const char *adapter)
{
	DBusMessage *msg, *reply;
	DBusError err;
	const char *reply_path;
	char *path;

	if (!adapter)
		return get_default_adapter_path(conn);

	msg = dbus_message_new_method_call("org.bluez", "/",
					"org.bluez.Manager", "FindAdapter");

	if (!msg) {
		fprintf(stderr, "Can't allocate new method call\n");
		return NULL;
	}

	dbus_message_append_args(msg, DBUS_TYPE_STRING, &adapter,
					DBUS_TYPE_INVALID);

	dbus_error_init(&err);

	reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

	dbus_message_unref(msg);

	if (!reply) {
		fprintf(stderr,
			"Can't find adapter %s\n", adapter);
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		return NULL;
	}

	if (!dbus_message_get_args(reply, &err,
					DBUS_TYPE_OBJECT_PATH, &reply_path,
					DBUS_TYPE_INVALID)) {
		fprintf(stderr,
			"Can't get reply arguments\n");
		if (dbus_error_is_set(&err)) {
			fprintf(stderr, "%s\n", err.message);
			dbus_error_free(&err);
		}
		dbus_message_unref(reply);
		return NULL;
	}

	path = strdup(reply_path);

	dbus_message_unref(reply);

	dbus_connection_flush(conn);

	return path;
}

static void usage(void)
{
	printf("Bluetooth agent ver %s\n\n", VERSION);

	printf("Usage:\n"
		"\tagent [--adapter adapter-path] [--path agent-path] <passkey> [<device>]\n"
		"\n");
}

static struct option main_options[] = {
	{ "adapter",	1, 0, 'a' },
	{ "path",	1, 0, 'p' },
	{ "capabilites",1, 0, 'c' },
	{ "delay",	1, 0, 'd' },
	{ "reject",	0, 0, 'r' },
	{ "help",	0, 0, 'h' },
	{ 0, 0, 0, 0 }
};

int main(int argc, char *argv[])
{
	const char *capabilities = "DisplayYesNo";
	struct sigaction sa;
	DBusConnection *conn;
	char match_string[128], default_path[128], *adapter_id = NULL;
	char *adapter_path = NULL, *agent_path = NULL, *device = NULL;
	int opt;

	snprintf(default_path, sizeof(default_path),
					"/org/bluez/agent_%d", getpid());

	while ((opt = getopt_long(argc, argv, "+a:p:c:d:rh", main_options, NULL)) != EOF) {
		switch(opt) {
		case 'a':
			adapter_id = optarg;
			break;
		case 'p':
			if (optarg[0] != '/') {
				fprintf(stderr, "Invalid path\n");
				exit(1);
			}
			agent_path = strdup(optarg);
			break;
		case 'c':
			capabilities = optarg;
			break;
		case 'd':
			passkey_delay = atoi(optarg);
			break;
		case 'r':
			do_reject = 1;
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

	if (argc < 1) {
		usage();
		exit(1);
	}

	passkey_value = strdup(argv[0]);

	if (argc > 1)
		device = strdup(argv[1]);

	if (!agent_path)
		agent_path = strdup(default_path);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		fprintf(stderr, "Can't get on system bus");
		exit(1);
	}

	adapter_path = get_adapter_path(conn, adapter_id);
	if (!adapter_path)
		exit(1);

	if (!dbus_connection_register_object_path(conn, agent_path,
							&agent_table, NULL)) {
		fprintf(stderr, "Can't register object path for agent\n");
		exit(1);
	}

	if (device) {
		if (create_paired_device(conn, adapter_path, agent_path,
						capabilities, device) < 0) {
			dbus_connection_unref(conn);
			exit(1);
		}
	} else {
		if (register_agent(conn, adapter_path, agent_path,
							capabilities) < 0) {
			dbus_connection_unref(conn);
			exit(1);
		}
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

	if (!__io_terminated && !device)
		unregister_agent(conn, adapter_path, agent_path);

	free(adapter_path);
	free(agent_path);

	free(passkey_value);

	dbus_connection_unref(conn);

	return 0;
}
