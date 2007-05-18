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
#include <stdint.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "logging.h"

#include "ipc.h"
#include "headset.h"
#include "manager.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define SOCKET_NAME "/org/bluez/audio"

static DBusConnection *connection = NULL;

static audio_device_t *default_hs = NULL;

static GSList *devices = NULL;

static int unix_sock = -1;

/* FIXME: Remove these once global error functions exist */
static DBusHandlerResult error_reply(DBusConnection *conn, DBusMessage *msg,
					const char *name, const char *descr)
{
	DBusMessage *derr;

	if (!conn || !msg)
		return DBUS_HANDLER_RESULT_HANDLED;

	derr = dbus_message_new_error(msg, name, descr);
	if (!derr) {
		error("Unable to allocate new error return");
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	}

	return send_message_and_unref(conn, derr);
}

static DBusHandlerResult err_invalid_args(DBusConnection *conn, DBusMessage *msg,
						const char *descr)
{
	return error_reply(conn, msg, "org.bluez.audio.Error.InvalidArguments",
			descr ? descr : "Invalid arguments in method call");
}

static gboolean unix_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	struct sockaddr_un addr;
	socklen_t addrlen;
	unsigned char buf[128];
	int sk, len;

	debug("chan %p cond %td data %p", chan, cond, data);

	if (cond & G_IO_NVAL)
		return FALSE;

	if (cond & (G_IO_HUP | G_IO_ERR)) {
		g_io_channel_close(chan);
		return FALSE;
	}

	sk = g_io_channel_unix_get_fd(chan);

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);

	len = recvfrom(sk, buf, sizeof(buf), 0, (struct sockaddr *) &addr, &addrlen);

	debug("path %s len %d", addr.sun_path + 1, len);

	return TRUE;
}

static audio_device_t *find_device(bdaddr_t *bda)
{
	GSList *l;

	for (l = devices; l != NULL; l = l->next) {
		audio_device_t *device = l->data;
		if (bacmp(&device->bda, bda) == 0)
			return device;
	}

	return NULL;
}

static DBusHandlerResult device_get_address(DBusConnection *conn, DBusMessage *msg,
						void *data)
{
	audio_device_t *device = data;
	DBusMessage *reply;
	char address[18], *ptr = address;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	ba2str(&device->bda, address);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &ptr,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusMethodVTable device_methods[] = {
	{ "GetAddress",	device_get_address,	"",	"s"	},
	{ NULL, NULL, NULL, NULL }
};

static audio_device_t *add_device(bdaddr_t *bda)
{
	static int device_id = 0;
	audio_device_t *device;

	device = g_new0(audio_device_t, 1);

	bacpy(&device->bda, bda);

	snprintf(device->object_path, sizeof(device->object_path) - 1,
			"%s/device%d", AUDIO_MANAGER_PATH, device_id++);

	if (!dbus_connection_create_object_path(connection, device->object_path,
						device, NULL)) {
		error("D-Bus failed to register %s path", device->object_path);
		g_free(device);
		return NULL;
	}

	if (!dbus_connection_register_interface(connection, device->object_path,
						AUDIO_DEVICE_INTERFACE,
						device_methods, NULL, NULL)) {
		error("Failed to register %s interface to %s",
				AUDIO_DEVICE_INTERFACE, device->object_path);
		dbus_connection_destroy_object_path(connection,
							device->object_path);
		g_free(device);
		return NULL;
	}

	devices = g_slist_append(devices, device);

	return device;
}

static void remove_device(audio_device_t *device)
{
	devices = g_slist_remove(devices, device);
	dbus_connection_destroy_object_path(connection, device->object_path);
	g_free(device->headset);
	g_free(device);
}

audio_device_t *manager_headset_connected(bdaddr_t *bda)
{
	audio_device_t *device;
	const char *path;

	device = find_device(bda);
	if (device && device->headset)
		return device;

	if (!device)
		device = add_device(bda);

	if (!device)
		return NULL;

	if (!device->headset)
		device->headset = headset_init(device->object_path);

	if (!device->headset)
		return NULL;

	path = device->object_path;

	dbus_connection_emit_signal(connection, AUDIO_MANAGER_PATH,
					AUDIO_MANAGER_INTERFACE,
					"HeadsetCreated",
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	if (!default_hs) {
		default_hs = device;
		dbus_connection_emit_signal(connection, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DefaultHeadsetChanged",
						DBUS_TYPE_STRING, &path,
						DBUS_TYPE_INVALID);
	}

	return device;
}

static DBusHandlerResult am_create_device(DBusConnection *conn, DBusMessage *msg,
						void *data)
{
	const char *address;
	bdaddr_t bda;
	audio_device_t *device;
	DBusError derr;
	DBusMessageIter iter, array_iter;

	dbus_error_init(&derr);
	dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID);
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	str2ba(address, &bda);

	device = find_device(&bda);
	if (device) {
		const char *iface, *path = device->object_path;
		DBusMessage *reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;
		dbus_message_iter_init_append(reply, &iter);
		dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &path);
		dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
							"s", &array_iter);
		if (device->headset) {
			iface = AUDIO_HEADSET_INTERFACE;
			dbus_message_iter_append_basic(&array_iter,
							DBUS_TYPE_STRING, &iface);
		}

		dbus_message_iter_close_container(&iter, &array_iter);

		return send_message_and_unref(conn, reply);
	}

	device = add_device(&bda);
	/*
	resolve_services(conn, device, msg);
	*/

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult am_remove_device(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult am_list_devices(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult am_connected_devices(DBusConnection *conn,
						DBusMessage *msg,
						void *data)
{
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult am_create_headset(DBusConnection *conn, DBusMessage *msg,
						void *data)
{
	const char *path, *address;
	bdaddr_t bda;
	DBusMessage *reply;
	DBusError derr;
	audio_device_t *device;

	dbus_error_init(&derr);
	dbus_message_get_args(msg, &derr,
				DBUS_TYPE_STRING, &address,
				DBUS_TYPE_INVALID);
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	str2ba(address, &bda);

	device = find_device(&bda);
	if (!device)
		device = add_device(&bda);

	if (!device)
		return error_reply(connection, msg,
					"org.bluez.audio.Error.Failed",
					"Unable to create new audio device");

	device->headset = headset_init(device->object_path);
	if (!device->headset)
		return error_reply(connection, msg,
					"org.bluez.audio.Error.Failed",
					"Unable to init Headset interface");

	path = device->object_path;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;


	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static gint device_path_cmp(gconstpointer a, gconstpointer b)
{
	const audio_device_t *device = a;
	const char *path = b;

	return strcmp(device->object_path, path);
}

static DBusHandlerResult am_remove_headset(DBusConnection *conn, DBusMessage *msg,
						void *data)
{
	DBusError derr;
	DBusMessage *reply;
	GSList *match;
	const char *path;
	audio_device_t *device;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID)) {
		err_invalid_args(connection, msg, derr.message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	match = g_slist_find_custom(devices, path, device_path_cmp);
	if (!match)
		return error_reply(connection, msg,
					"org.bluez.audio.Error.DoesNotExist",
					"The headset does not exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	device = match->data;

	remove_device(device);

	if (default_hs == device) {
		const char *param;
		GSList *l;

		default_hs = NULL;

		for (l = devices; l != NULL; l = l->next) {
			device = l->data;

			if (device->headset)
				default_hs = device;
		}

		param = default_hs ? default_hs->object_path : "";

		dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						"DefaultHeadsetChanged",
						DBUS_TYPE_STRING, &param,
						DBUS_TYPE_INVALID);
	}

	dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
					AUDIO_MANAGER_INTERFACE,
					"HeadsetRemoved",
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_list_headsets(DBusConnection *conn, DBusMessage *msg,
						void *data)
{
	DBusMessageIter iter;
	DBusMessageIter array_iter;
	DBusMessage *reply;
	GSList *l;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);

	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
				DBUS_TYPE_STRING_AS_STRING, &array_iter);

	for (l = devices; l != NULL; l = l->next) {
		audio_device_t *device = l->data;
		const char *path;

		if (!device->headset)
			continue;

		path = device->object_path;

		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_get_default_headset(DBusConnection *conn, DBusMessage *msg,
						void *data)
{
	DBusMessage *reply;
	const char *path;

	if (!default_hs)
		return error_reply(connection, msg,
					"org.bluez.audio.Error.DoesNotExist",
					"There is no default headset");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	path = default_hs->object_path;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_change_default_headset(DBusConnection *conn, DBusMessage *msg,
							void *data)
{
	DBusError derr;
	DBusMessage *reply;
	GSList *match;
	const char *path;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID)) {
		err_invalid_args(connection, msg, derr.message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	match = g_slist_find_custom(devices, path, device_path_cmp);
	if (!match)
		return error_reply(connection, msg,
					"org.bluez.audio.Error.DoesNotExist",
					"The headset does not exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	default_hs = match->data;

	path = default_hs->object_path;

	dbus_connection_emit_signal(conn, AUDIO_MANAGER_PATH,
					AUDIO_MANAGER_INTERFACE,
					"DefaultHeadsetChanged",
					DBUS_TYPE_STRING, &path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusMethodVTable manager_methods[] = {
	{ "CreateDevice",		am_create_device,
		"s",	"sas"		},
	{ "RemoveDevice",		am_remove_device,
		"s",	""		},
	{ "ListDevices",		am_list_devices,
		"",	"a(sas)"	},
	{ "GetConnectedDevices",	am_connected_devices,
		"",	"a(sas)"	},	
	{ "CreateHeadset",		am_create_headset,
		"s",	"s"		},
	{ "RemoveHeadset",		am_remove_headset,
		"s",	""		},
	{ "ListHeadsets",		am_list_headsets,
		"",	"as"		},
	{ "DefaultHeadset",		am_get_default_headset,
		"",	"s"		},
	{ "ChangeDefaultHeadset",	am_change_default_headset,
		"s",	""	},
	{ NULL, NULL, NULL, NULL },
};

static DBusSignalVTable manager_signals[] = {
	{ "DeviceCreated",		"sas"	},
	{ "DeviceRemoved",		"s"	},
	{ "HeadsetCreated",		"s"	},
	{ "HeadsetRemoved",		"s"	},
	{ "DefaultHeadsetChanged",	"s"	},
	{ NULL, NULL }
};

int audio_init(DBusConnection *conn)
{
	GIOChannel *io;
	struct sockaddr_un addr;
	int sk;

	sk = socket(PF_LOCAL, SOCK_DGRAM, 0);
	if (sk < 0) {
		error("Can't create unix socket: %s (%d)", strerror(errno), errno);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path + 1, UNIX_PATH_MAX - 2, "%s", SOCKET_NAME);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("Can't bind unix socket: %s (%d)", strerror(errno), errno);
		close(sk);
		return -1;
	}

	set_nonblocking(sk);

	unix_sock = sk;

	io = g_io_channel_unix_new(sk);

	g_io_add_watch(io, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
							unix_event, NULL);

	g_io_channel_unref(io);

	if (!dbus_connection_create_object_path(conn, AUDIO_MANAGER_PATH,
						NULL, NULL)) {
		error("D-Bus failed to register %s path", AUDIO_MANAGER_PATH);
		close(sk);
		return -1;
	}

	if (!dbus_connection_register_interface(conn, AUDIO_MANAGER_PATH,
						AUDIO_MANAGER_INTERFACE,
						manager_methods,
						manager_signals, NULL)) {
		error("Failed to register %s interface to %s",
				AUDIO_MANAGER_INTERFACE, AUDIO_MANAGER_PATH);
		dbus_connection_destroy_object_path(conn,
							AUDIO_MANAGER_PATH);
		close(sk);
		return -1;
	}

	connection = dbus_connection_ref(conn);

	return 0;
}

void audio_exit(void)
{
	close(unix_sock);

	unix_sock = -1;

	g_slist_foreach(devices, (GFunc) remove_device, NULL);
	g_slist_free(devices);
	devices = NULL;

	dbus_connection_unref(connection);

	connection = NULL;
}
