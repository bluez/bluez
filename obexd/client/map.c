/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2011  Bartosz Szatkowski <bulislaw@linux.com> for Comarch
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
#include <string.h>
#include <glib.h>
#include <gdbus.h>

#include "log.h"

#include "map.h"
#include "transfer.h"
#include "session.h"
#include "driver.h"

#define OBEX_MAS_UUID \
	"\xBB\x58\x2B\x40\x42\x0C\x11\xDB\xB0\xDE\x08\x00\x20\x0C\x9A\x66"
#define OBEX_MAS_UUID_LEN 16

#define MAP_INTERFACE  "org.openobex.MessageAccess"
#define MAS_UUID "00001132-0000-1000-8000-00805f9b34fb"

struct map_data {
	struct obc_session *session;
	DBusMessage *msg;
};

static DBusConnection *conn = NULL;

static void simple_cb(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	DBusMessage *reply;
	struct map_data *map = user_data;

	if (err != NULL)
		reply = g_dbus_create_error(map->msg,
						"org.openobex.Error.Failed",
						"%s", err->message);
	else
		reply = dbus_message_new_method_return(map->msg);

	g_dbus_send_message(conn, reply);
	dbus_message_unref(map->msg);
}

static DBusMessage *map_setpath(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct map_data *map = user_data;
	const char *folder;
	GError *err = NULL;

	if (dbus_message_get_args(message, NULL, DBUS_TYPE_STRING, &folder,
						DBUS_TYPE_INVALID) == FALSE)
		return g_dbus_create_error(message,
					"org.openobex.Error.InvalidArguments",
					NULL);

	obc_session_setpath(map->session, folder, simple_cb, map, &err);
	if (err != NULL) {
		DBusMessage *reply;
		reply =  g_dbus_create_error(message,
						"org.openobex.Error.Failed",
						"%s", err->message);
		g_error_free(err);
		return reply;
	}

	map->msg = dbus_message_ref(message);

	return NULL;
}

static void buffer_cb(struct obc_session *session,
						struct obc_transfer *transfer,
						GError *err, void *user_data)
{
	struct map_data *map = user_data;
	DBusMessage *reply;
	char *contents;
	size_t size;
	int perr;

	if (err != NULL) {
		reply = g_dbus_create_error(map->msg,
						"org.openobex.Error.Failed",
						"%s", err->message);
		goto done;
	}

	perr = obc_transfer_get_contents(transfer, &contents, &size);
	if (perr < 0) {
		reply = g_dbus_create_error(map->msg,
						"org.openobex.Error.Failed",
						"Error reading contents: %s",
						strerror(-perr));
		goto done;
	}

	reply = g_dbus_create_reply(map->msg, DBUS_TYPE_STRING, &contents,
							DBUS_TYPE_INVALID);

	g_free(contents);
done:
	g_dbus_send_message(conn, reply);
	dbus_message_unref(map->msg);
}

static DBusMessage *map_get_folder_listing(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct map_data *map = user_data;
	struct obc_transfer *transfer;
	GError *err = NULL;
	DBusMessage *reply;

	transfer = obc_transfer_get("x-obex/folder-listing", NULL, NULL, &err);
	if (transfer == NULL)
		goto fail;

	if (obc_session_queue(map->session, transfer, buffer_cb, map, &err)) {
		map->msg = dbus_message_ref(message);
		return NULL;
	}

fail:
	reply = g_dbus_create_error(message, "org.openobex.Error.Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static DBusMessage *map_get_message_listing(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct map_data *map = user_data;
	struct obc_transfer *transfer;
	const char *folder;
	DBusMessageIter msg_iter;
	GError *err = NULL;
	DBusMessage *reply;

	dbus_message_iter_init(message, &msg_iter);

	if (dbus_message_iter_get_arg_type(&msg_iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				"org.openobex.Error.InvalidArguments", NULL);

	dbus_message_iter_get_basic(&msg_iter, &folder);

	transfer = obc_transfer_get("x-bt/MAP-msg-listing", folder, NULL, &err);
	if (transfer == NULL)
		goto fail;

	if (obc_session_queue(map->session, transfer, buffer_cb, map, &err)) {
		map->msg = dbus_message_ref(message);
		return NULL;
	}

fail:
	reply = g_dbus_create_error(message, "org.openobex.Error.Failed", "%s",
								err->message);
	g_error_free(err);
	return reply;
}

static GDBusMethodTable map_methods[] = {
	{ "SetFolder",		"s", "",	map_setpath,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetFolderListing",	"a{ss}", "s",	map_get_folder_listing,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ "GetMessageListing",	"sa{ss}", "s",	map_get_message_listing,
						G_DBUS_METHOD_FLAG_ASYNC },
	{ }
};

static void map_free(void *data)
{
	struct map_data *map = data;

	obc_session_unref(map->session);
	g_free(map);
}

static int map_probe(struct obc_session *session)
{
	struct map_data *map;
	const char *path;

	path = obc_session_get_path(session);

	DBG("%s", path);

	map = g_try_new0(struct map_data, 1);
	if (!map)
		return -ENOMEM;

	map->session = obc_session_ref(session);

	if (!g_dbus_register_interface(conn, path, MAP_INTERFACE, map_methods,
					NULL, NULL, map, map_free)) {
		map_free(map);

		return -ENOMEM;
	}

	return 0;
}

static void map_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, MAP_INTERFACE);
}

static struct obc_driver map = {
	.service = "MAP",
	.uuid = MAS_UUID,
	.target = OBEX_MAS_UUID,
	.target_len = OBEX_MAS_UUID_LEN,
	.probe = map_probe,
	.remove = map_remove
};

int map_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&map);
	if (err < 0) {
		dbus_connection_unref(conn);
		conn = NULL;
		return err;
	}

	return 0;
}

void map_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&map);
}
