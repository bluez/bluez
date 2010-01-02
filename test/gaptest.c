/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <dbus/dbus.h>

#define BLUEZ_SERVICE	"org.bluez"

#define MANAGER_PATH	"/"
#define MANAGER_INTF	BLUEZ_SERVICE ".Manager"
#define ADAPTER_INTF	BLUEZ_SERVICE ".Adapter"

static char *get_adapter(DBusConnection *conn)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;
	char *result = NULL;

	message = dbus_message_new_method_call(BLUEZ_SERVICE, MANAGER_PATH,
					MANAGER_INTF, "DefaultAdapter");
	if (!message)
		return NULL;

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, &error);

	dbus_message_unref(message);

	if (!reply) {
		if (dbus_error_is_set(&error) == TRUE) {
			fprintf(stderr, "%s\n", error.message);
			dbus_error_free(&error);
		} else
			fprintf(stderr, "Failed to set property\n");
		return NULL;
	}

	if (dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE)
		goto done;

	printf("Using default adapter %s\n", path);

	result = strdup(path);

done:
	dbus_message_unref(reply);

	return result;
}

static char *find_device(DBusConnection *conn, const char *adapter,
							const char *address)
{
	DBusMessage *message, *reply;
	DBusError error;
	const char *path;
	char *result = NULL;

	message = dbus_message_new_method_call(BLUEZ_SERVICE, adapter,
					ADAPTER_INTF, "FindDevice");
	if (!message)
		return NULL;

	dbus_message_append_args(message, DBUS_TYPE_STRING, &address,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, &error);

	dbus_message_unref(message);

	if (!reply) {
		if (dbus_error_is_set(&error) == TRUE) {
			fprintf(stderr, "%s\n", error.message);
			dbus_error_free(&error);
		} else
			fprintf(stderr, "Failed to set property\n");
		return NULL;
	}

	if (dbus_message_get_args(reply, NULL, DBUS_TYPE_OBJECT_PATH, &path,
						DBUS_TYPE_INVALID) == FALSE)
		goto done;

	printf("Using device %s for address %s\n", path, address);

	result = strdup(path);

done:
	dbus_message_unref(reply);

	return result;
}

static int remove_device(DBusConnection *conn, const char *adapter,
							const char *device)
{
	DBusMessage *message, *reply;
	DBusError error;

	message = dbus_message_new_method_call(BLUEZ_SERVICE, adapter,
					ADAPTER_INTF, "RemoveDevice");
	if (!message)
		return -ENOMEM;

	dbus_message_append_args(message, DBUS_TYPE_OBJECT_PATH, &device,
							DBUS_TYPE_INVALID);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, &error);

	dbus_message_unref(message);

	if (!reply) {
		if (dbus_error_is_set(&error) == TRUE) {
			fprintf(stderr, "%s\n", error.message);
			dbus_error_free(&error);
		} else
			fprintf(stderr, "Failed to set property\n");
		return -EIO;
	}

	dbus_message_unref(reply);

	printf("Removed device %s\n", device);

	return 0;
}

static int set_property(DBusConnection *conn, const char *adapter,
					const char *key, int type, void *val)
{
	DBusMessage *message, *reply;
	DBusMessageIter array, value;
	DBusError error;
	const char *signature;

	message = dbus_message_new_method_call(BLUEZ_SERVICE, adapter,
						ADAPTER_INTF, "SetProperty");
	if (!message)
		return -ENOMEM;

	switch (type) {
	case DBUS_TYPE_BOOLEAN:
		signature = DBUS_TYPE_BOOLEAN_AS_STRING;
		break;
	case DBUS_TYPE_UINT32:
		signature = DBUS_TYPE_UINT32_AS_STRING;
		break;
	default:
		return -EILSEQ;
	}

	dbus_message_iter_init_append(message, &array);

	dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &key);

	dbus_message_iter_open_container(&array, DBUS_TYPE_VARIANT,
							signature, &value);
	dbus_message_iter_append_basic(&value, type, val);
	dbus_message_iter_close_container(&array, &value);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(conn,
							message, -1, &error);

	dbus_message_unref(message);

	if (!reply) {
		if (dbus_error_is_set(&error) == TRUE) {
			fprintf(stderr, "%s\n", error.message);
			dbus_error_free(&error);
		} else
			fprintf(stderr, "Failed to set property\n");
		return -EIO;
	}

	dbus_message_unref(reply);

	printf("Set property %s for %s\n", key, adapter);

	return 0;
}

static void usage(void)
{
	printf("gaptest - GAP testing\n"
		"Usage:\n");
	printf("\tgaptest [options]\n");
	printf("Options:\n"
		"\t-T <timeout>        Set timeout\n"
		"\t-P <powered>        Set powered\n"
		"\t-D <discoverable>   Set discoverable\n"
		"\t-B <pairable>       Set pairable\n"
		"\t-C <address>        Create device\n"
		"\t-R <address>        Remove device\n");
}

int main(int argc, char *argv[])
{
	DBusConnection *conn;
	char *adapter, *device;
	const char *create = NULL, *remove = NULL;
	int opt, timeout = -1, powered = -1, discoverable = -1, pairable = -1;

	while ((opt = getopt(argc, argv, "T:P:D:B:C:R:h")) != EOF) {
		switch (opt) {
		case 'T':
			timeout = atoi(optarg);
			break;
		case 'P':
			powered = atoi(optarg);
			break;
		case 'D':
			discoverable = atoi(optarg);
			break;
		case 'B':
			pairable = atoi(optarg);
			break;
		case 'C':
			create = optarg;
			break;
		case 'R':
			remove = optarg;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			usage();
			exit(1);
		}
	}

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		fprintf(stderr, "Can't get on system bus\n");
		exit(1);
	}

	adapter = get_adapter(conn);
	if (!adapter) {
		fprintf(stderr, "Can't get default adapter\n");
		exit(1);
	}

	if (powered >= 0) {
		set_property(conn, adapter, "Powered",
					DBUS_TYPE_BOOLEAN, &powered);
	}

	if (discoverable >= 0) {
		set_property(conn, adapter, "Discoverable",
					DBUS_TYPE_BOOLEAN, &discoverable);

		if (timeout >= 0)
			set_property(conn, adapter, "DiscoverableTimeout",
						DBUS_TYPE_UINT32, &timeout);
	}

	if (pairable >= 0) {
		set_property(conn, adapter, "Pairable",
					DBUS_TYPE_BOOLEAN, &pairable);

		if (timeout >= 0)
			set_property(conn, adapter, "PairableTimeout",
						DBUS_TYPE_UINT32, &timeout);
	}

	if (create) {
		device = find_device(conn, adapter, create);
		if (!device) {
			fprintf(stderr, "Can't find device\n");
			exit(1);
		}

		free(device);
	}

	if (remove) {
		device = find_device(conn, adapter, remove);
		if (!device) {
			fprintf(stderr, "Can't find device\n");
			exit(1);
		}

		remove_device(conn, adapter, device);

		free(device);
	}

	free(adapter);

	dbus_connection_unref(conn);

	return 0;
}
