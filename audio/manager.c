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

static GIOChannel *hs_server = NULL;

static uint32_t hs_record_id;
static struct headset *default_hs;

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
	return error_reply(conn, msg, "org.bluez.Error.InvalidArguments",
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

static GIOChannel *server_socket(uint8_t *channel)
{
	int sock, lm;
	struct sockaddr_rc addr;
	socklen_t sa_len;
	GIOChannel *io;

	sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sock < 0) {
		error("server socket: %s (%d)", strerror(errno), errno);
		return NULL;
	}

	lm = RFCOMM_LM_SECURE;
	if (setsockopt(sock, SOL_RFCOMM, RFCOMM_LM, &lm, sizeof(lm)) < 0) {
		error("server setsockopt: %s (%d)", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, BDADDR_ANY);
	addr.rc_channel = 0;

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		error("server bind: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	if (listen(sock, 1) < 0) {
		error("server listen: %s", strerror(errno), errno);
		close(sock);
		return NULL;
	}

	sa_len = sizeof(struct sockaddr_rc);
	getsockname(sock, (struct sockaddr *) &addr, &sa_len);
	*channel = addr.rc_channel;

	io = g_io_channel_unix_new(sock);
	if (!io) {
		error("Unable to allocate new io channel");
		close(sock);
		return NULL;
	}

	return io;
}

static gboolean manager_create_headset_server(uint8_t chan)
{
	if (hs_server) {
		error("Server socket already created");
		return FALSE;
	}

	hs_server = server_socket(&chan);
	if (!hs_server)
		return FALSE;

	if (!hs_record_id)
		hs_record_id = headset_add_ag_record(connection, chan);

	if (!hs_record_id) {
		error("Unable to register service record");
		g_io_channel_unref(hs_server);
		hs_server = NULL;
		return FALSE;
	}

	g_io_add_watch(hs_server, G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
				(GIOFunc) headset_server_io_cb, NULL);

	return TRUE;
}

struct headset *manager_find_headset_by_bda(bdaddr_t *bda)
{
	GSList *elem;

	elem = g_slist_find_custom(headsets, bda, headset_bda_cmp);

	return elem ? elem->data : NULL;
}

void manager_add_headset(struct headset *hs)
{
	assert(hs);

	headsets = g_slist_append(headsets, hs);

	manager_signal(connection, "HeadsetCreated", headset_get_path(hs));

	if (!default_hs) {
		default_hs = hs;
		manager_signal(connection, "DefaultHeadsetChanged",
							headset_get_path(hs));
	}
}

static DBusHandlerResult am_create_headset(DBusMessage *msg)
{
	const char *object_path;
	const char *address;
	struct headset *hs;
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
	hs = manager_find_headset_by_bda(&bda);
	if (!hs) {
		hs = headset_new(connection, &bda);
		if (!hs)
			return error_reply(connection, msg,
					"org.bluez.Error.Failed",
					"Unable to create new headset object");
		manager_add_headset(hs);
	}

	object_path = headset_get_path(hs);
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &object_path,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_remove_headset(DBusMessage *msg)
{
	DBusError derr;
	DBusMessage *reply;
	GSList *match;
	struct headset *hs;
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

	match = g_slist_find_custom(headsets, path, headset_path_cmp);
	if (!match)
		return error_reply(connection, msg, "org.bluez.Error.DoesNotExist",
					"The headset does not exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	hs = match->data;

	headsets = g_slist_remove(headsets, hs);

	if (default_hs == hs) {
		if (!headsets)
			default_hs = NULL;
		else
			default_hs = headsets->data;

		manager_signal(connection, "DefaultHeadsetChanged",
				default_hs ? headset_get_path(default_hs) : "");
	}

	manager_signal(connection, "HeadsetRemoved", headset_get_path(hs));

	headset_unref(hs);

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

	for (l = headsets; l != NULL; l = l->next) {
		struct headset *hs = l->data;
		const char *path = headset_get_path(hs);

		dbus_message_iter_append_basic(&array_iter,
						DBUS_TYPE_STRING, &path);
	}

	dbus_message_iter_close_container(&iter, &array_iter);

	return send_message_and_unref(connection, reply);
}

static DBusHandlerResult am_get_default_headset(DBusMessage *msg)
{
	DBusMessage *reply;
	const char *opath;

	if (!default_hs)
		return error_reply(connection, msg, "org.bluez.Error.DoesNotExist",
					"There is no default headset");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	opath = headset_get_path(default_hs);

	dbus_message_append_args(reply, DBUS_TYPE_STRING, &opath,
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

	match = g_slist_find_custom(headsets, path, headset_path_cmp);
	if (!match)
		return error_reply(connection, msg, "org.bluez.Error.DoesNotExist",
					"The headset does not exist");

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	default_hs = match->data;

	manager_signal(connection, "DefaultHeadsetChanged",
					headset_get_path(default_hs));

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

DBusConnection *manager_get_dbus_conn(void)
{
	return connection;
}

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

	manager_create_headset_server(12);

	return 0;
}

void audio_exit(void)
{
	close(unix_sock);

	unix_sock = -1;

	if (hs_record_id) {
		headset_remove_ag_record(connection, hs_record_id);
		hs_record_id = 0;
	}

	if (hs_server) {
		g_io_channel_unref(hs_server);
		hs_server = NULL;
	}

	if (headsets) {
		g_slist_foreach(headsets, (GFunc) headset_unref, NULL);
		g_slist_free(headsets);
		headsets = NULL;
	}

	dbus_connection_unref(connection);

	connection = NULL;
}
