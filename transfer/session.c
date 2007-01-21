/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Marcel Holtmann <marcel@holtmann.org>
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

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "logging.h"

#include "process.h"
#include "session.h"

static DBusHandlerResult cancel_message(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct session_data *session = data;

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	debug("Cancel of session at %s", session->identifier);

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	dbus_connection_send(conn, reply, NULL);

	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult session_handler(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	if (dbus_message_is_method_call(msg, "org.bluez.transfer.Session", "Cancel"))
		return cancel_message(conn, msg, data);

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusObjectPathVTable session_table = {
	.message_function = session_handler,
};

struct session_data *session_create(DBusConnection *conn, DBusMessage *msg)
{
	struct session_data *session;

	session = malloc(sizeof(*session));
	if (!session)
		return NULL;

	memset(session, 0, sizeof(*session));

	session->conn = dbus_connection_ref(conn);

	session->msg = dbus_message_ref(msg);

	return session;
}

void session_destroy(struct session_data *session)
{
	if (!session)
		return;

	if (session->identifier) {
		dbus_connection_unregister_object_path(session->conn,
							session->identifier);
		free(session->identifier);
	}

	dbus_message_unref(session->msg);

	dbus_connection_unref(session->conn);

	free(session);
}

static gboolean connect_callback(GIOChannel *chan,
					GIOCondition cond, gpointer data)
{
	struct session_data *session = data;
	int sk;

	debug("Connection for session %s established", session->identifier);

	sk = g_io_channel_unix_get_fd(session->rfcomm_io);

	close(sk);

	return FALSE;
}

static int rfcomm_connect(struct session_data *session)
{
	struct sockaddr_rc addr;
	long arg;
	int sk;

	sk = socket(PF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
	if (sk < 0)
		return -1;

	arg = fcntl(sk, F_GETFL);
	if (arg < 0) {
		close(sk);
		return -1;
	}

	arg |= O_NONBLOCK;

	if (fcntl(sk, F_SETFL, arg) < 0) {
		close(sk);
		return -1;
	}

	session->rfcomm_io = g_io_channel_unix_new(sk);
	if (!session->rfcomm_io) {
		close(sk);
		return -1;
	}

	g_io_channel_set_close_on_unref(session->rfcomm_io, TRUE);

	memset(&addr, 0, sizeof(addr));
	addr.rc_family = AF_BLUETOOTH;
	bacpy(&addr.rc_bdaddr, &session->bdaddr);
	addr.rc_channel = session->channel;

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		if (errno != EAGAIN && errno != EINPROGRESS) {
			close(sk);
			return -1;
		}
	}

	g_io_add_watch(session->rfcomm_io, G_IO_OUT, connect_callback, session);

	return 0;
}

static gboolean data_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	unsigned char buf[64];
	gsize len;
	GIOError err;
	int i;

	debug("Data event");

	if (cond & (G_IO_HUP | G_IO_ERR))
		return FALSE;

	memset(buf, 0, sizeof(buf));

	err = g_io_channel_read(chan, (gchar *) buf, sizeof(buf) - 1, &len);
	if (err == G_IO_ERROR_AGAIN)
		return TRUE;

	for (i = 0; i < len; i++)
		if (!isprint(buf[i]))
			buf[i] = '.';

	debug("%s", buf);

	return TRUE;
}

const char *session_connect(struct session_data *session,
				const char *address, const char *pathname)
{
	const char *sender;
	char path[128];

	sender = dbus_message_get_sender(session->msg);

	session->uid = dbus_bus_get_unix_user(session->conn, sender, NULL);

	debug("Request by user %d", session->uid);

	create_reader(session->uid, pathname, data_event, NULL);

	str2ba(address, &session->bdaddr);

	session->channel = 1;

	snprintf(path, sizeof(path), "/org/bluez/transfer/%d%d",
						session->uid, rand());

	session->identifier = strdup(path);
	if (!session->identifier)
		return NULL;

	if (dbus_connection_register_object_path(session->conn, path,
					&session_table, session) == FALSE) {
		free(session->identifier);
		session->identifier = NULL;
		return NULL;
	}

	if (rfcomm_connect(session) < 0)
		return NULL;

	return session->identifier;
}
