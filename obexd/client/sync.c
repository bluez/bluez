/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2007-2010  Intel Corporation
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

#include <glib.h>
#include <gdbus.h>

#include "transfer.h"
#include "session.h"
#include "sync.h"

#define SYNC_INTERFACE	"org.openobex.Synchronization"
#define ERROR_INF SYNC_INTERFACE ".Error"

struct sync_data {
	struct obc_session *session;
	char *phonebook_path;
	DBusConnection *conn;
	DBusMessage *msg;
};

static DBusMessage *sync_setlocation(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	struct sync_data *sync = user_data;
	const char *location;
	char *path = NULL, *tmp;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &location,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
			ERROR_INF ".InvalidArguments", NULL);

	if (!g_ascii_strcasecmp(location, "INT") ||
			!g_ascii_strcasecmp(location, "INTERNAL"))
		path = g_strdup("telecom/pb.vcf");
	else if (!g_ascii_strncasecmp(location, "SIM", 3)) {
		tmp = g_ascii_strup(location, 4);
		path = g_build_filename(tmp, "telecom/pb.vcf", NULL);
		g_free(tmp);
	} else
		return g_dbus_create_error(message,
			ERROR_INF ".InvalidArguments", "InvalidPhonebook");

	g_free(sync->phonebook_path);
	sync->phonebook_path = path;

	return dbus_message_new_method_return(message);
}

static void sync_getphonebook_callback(struct obc_session *session,
					GError *err, void *user_data)
{
	struct obc_transfer *transfer = obc_session_get_transfer(session);
	struct sync_data *sync = user_data;
	DBusMessage *reply;
	const char *buf;
	int size;

	reply = dbus_message_new_method_return(sync->msg);

	buf = obc_transfer_get_buffer(transfer, &size);
	if (size == 0)
		buf = "";

	dbus_message_append_args(reply,
		DBUS_TYPE_STRING, &buf,
		DBUS_TYPE_INVALID);

	g_dbus_send_message(sync->conn, reply);
	dbus_message_unref(sync->msg);
	sync->msg = NULL;
}

static DBusMessage *sync_getphonebook(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	struct sync_data *sync = user_data;

	if (sync->msg)
		return g_dbus_create_error(message,
			ERROR_INF ".InProgress", "Transfer in progress");

	/* set default phonebook_path to memory internal phonebook */
	if (!sync->phonebook_path)
		sync->phonebook_path = g_strdup("telecom/pb.vcf");

	if (obc_session_get(sync->session, "phonebook", sync->phonebook_path, NULL,
				NULL, 0, sync_getphonebook_callback, sync) < 0)
		return g_dbus_create_error(message,
			ERROR_INF ".Failed", "Failed");

	sync->msg = dbus_message_ref(message);

	return NULL;
}

static DBusMessage *sync_putphonebook(DBusConnection *connection,
			DBusMessage *message, void *user_data)
{
	struct sync_data *sync = user_data;
	const char *buf;
	char *buffer;

	if (dbus_message_get_args(message, NULL,
			DBUS_TYPE_STRING, &buf,
			DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
			ERROR_INF ".InvalidArguments", NULL);

	/* set default phonebook_path to memory internal phonebook */
	if (!sync->phonebook_path)
		sync->phonebook_path = g_strdup("telecom/pb.vcf");

	buffer = g_strdup(buf);

	if (obc_session_put(sync->session, buffer, sync->phonebook_path) < 0)
		return g_dbus_create_error(message,
				ERROR_INF ".Failed", "Failed");

	return dbus_message_new_method_return(message);
}

static GDBusMethodTable sync_methods[] = {
	{ "SetLocation", "s", "", sync_setlocation },
	{ "GetPhonebook", "", "s", sync_getphonebook,
			G_DBUS_METHOD_FLAG_ASYNC },
	{ "PutPhonebook", "s", "", sync_putphonebook,
			G_DBUS_METHOD_FLAG_ASYNC },
	{}
};

static void sync_free(void *data)
{
	struct sync_data *sync = data;

	obc_session_unref(sync->session);
	dbus_connection_unref(sync->conn);
	g_free(sync->phonebook_path);
	g_free(sync);
}

gboolean sync_register_interface(DBusConnection *connection, const char *path,
							void *user_data)
{
	struct obc_session *session = user_data;
	struct sync_data *sync;

	sync = g_try_new0(struct sync_data, 1);
	if (!sync)
		return FALSE;

	sync->session = obc_session_ref(session);
	sync->conn = dbus_connection_ref(connection);

	if (g_dbus_register_interface(connection, path, SYNC_INTERFACE,
				sync_methods, NULL, NULL, sync, sync_free)) {
		sync_free(sync);
		return FALSE;
	}

	return TRUE;
}

void sync_unregister_interface(DBusConnection *connection, const char *path)
{
	g_dbus_unregister_interface(connection, path, SYNC_INTERFACE);
}
