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
#include "logging.h"

#include "ipc.h"
#include "headset.h"
#include "manager.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define SOCKET_NAME "/org/bluez/audio"

static DBusConnection *connection = NULL;

static char *default_hs = NULL;

static GSList *headsets = NULL;

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

static void manager_signal(DBusConnection *conn, const char *name,
				const char *param)
{
	DBusMessage *signal;

	signal = dbus_message_new_signal("/org/bluez/audio",
						"org.bluez.audio.Manager",
						name);
	if (!signal) {
		error("Unable to create new D-Bus signal");
		return;
	}

	dbus_message_append_args(signal, DBUS_TYPE_STRING, &param,
					DBUS_TYPE_INVALID);

	send_message_and_unref(conn, signal);
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

void manager_add_headset(const char *path)
{
	char *my_path = g_strdup(path);

	headsets = g_slist_append(headsets, my_path);

	manager_signal(connection, "HeadsetCreated", my_path);

	if (!default_hs) {
		default_hs = my_path;
		manager_signal(connection, "DefaultHeadsetChanged", my_path);
	}
}

static void manager_remove_headset(char *path)
{
	headset_remove(path);
	g_free(path);
}

static DBusHandlerResult am_create_headset(DBusMessage *msg)
{
	const char *hs_path;
	const char *address;
	bdaddr_t bda;
	DBusMessage *reply;
	DBusError derr;

	dbus_error_init(&derr);
	if (!dbus_message_get_args(msg, &derr,
					DBUS_TYPE_STRING, &address,
					DBUS_TYPE_INVALID)) {
		err_invalid_args(connection, msg, derr.message);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	if (dbus_error_is_set(&derr)) {
		err_invalid_args(connection, msg, derr.message);
		dbus_error_free(&derr);
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	str2ba(address, &bda);

	hs_path = headset_get(&bda);
	if (!hs_path) {
		hs_path = headset_add(&bda);
		if (!hs_path)
			return error_reply(connection, msg,
					"org.bluez.audio.Error.Failed",
					"Unable to create new headset object");
		manager_add_headset(hs_path);
	}

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &hs_path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_remove_headset(DBusMessage *msg)
{
	DBusError derr;
	DBusMessage *reply;
	GSList *match;
	char *path;

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

	match = g_slist_find_custom(headsets, path, (GCompareFunc) strcmp);
	if (!match)
		return error_reply(connection, msg,
					"org.bluez.audio.Error.DoesNotExist",
					"The headset does not exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	path = match->data;

	headsets = g_slist_remove(headsets, path);

	if (default_hs == path) {
		if (!headsets)
			default_hs = NULL;
		else
			default_hs = headsets->data;

		manager_signal(connection, "DefaultHeadsetChanged",
				default_hs ? default_hs : "");
	}

	manager_signal(connection, "HeadsetRemoved", path);

	headset_remove(path);

	g_free(path);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_list_headsets(DBusMessage *msg)
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

	for (l = headsets; l != NULL; l = l->next)
		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &l->data);

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_get_default_headset(DBusMessage *msg)
{
	DBusMessage *reply;

	if (!default_hs)
		return error_reply(connection, msg,
					"org.bluez.audio.Error.DoesNotExist",
					"There is no default headset");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &default_hs,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_change_default_headset(DBusMessage *msg)
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

	match = g_slist_find_custom(headsets, path, (GCompareFunc) strcmp);
	if (!match)
		return error_reply(connection, msg,
					"org.bluez.audio.Error.DoesNotExist",
					"The headset does not exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	default_hs = match->data;

	manager_signal(connection, "DefaultHeadsetChanged", default_hs);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_message(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	const char *interface, *member;

	interface = dbus_message_get_interface(msg);
	member = dbus_message_get_member(msg);

	if (!strcmp(DBUS_INTERFACE_INTROSPECTABLE, interface) &&
			!strcmp("Introspect", member))
		return simple_introspect(conn, msg, data);

	if (strcmp(interface, "org.bluez.audio.Manager") != 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (strcmp(member, "CreateHeadset") == 0)
		return am_create_headset(msg);

	if (strcmp(member, "RemoveHeadset") == 0)
		return am_remove_headset(msg);

	if (strcmp(member, "ListHeadsets") == 0)
		return am_list_headsets(msg);

	if (strcmp(member, "DefaultHeadset") == 0)
		return am_get_default_headset(msg);

	if (strcmp(member, "ChangeDefaultHeadset") == 0)
		return am_change_default_headset(msg);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static const DBusObjectPathVTable am_table = {
	.message_function = am_message,
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

	if (!dbus_connection_register_object_path(conn, AUDIO_MANAGER_PATH,
							&am_table, NULL)) {
		error("D-Bus failed to register %s path", AUDIO_MANAGER_PATH);
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

	if (headsets) {
		g_slist_foreach(headsets, (GFunc) manager_remove_headset, NULL);
		g_slist_free(headsets);
		headsets = NULL;
	}

	dbus_connection_unref(connection);

	connection = NULL;
}
