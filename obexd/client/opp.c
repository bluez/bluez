/*
 *
 *  OBEX Client
 *
 *  Copyright (C) 2011 Intel Corporation
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
#include <gdbus.h>

#include "log.h"

#include "transfer.h"
#include "session.h"
#include "driver.h"
#include "opp.h"

#define OPP_UUID "00001105-0000-1000-8000-00805f9b34fb"
#define OPP_INTERFACE "org.openobex.ObjectPush"
#define ERROR_INF OPP_INTERFACE ".Error"

struct opp_data {
	struct obc_session *session;
};

static DBusConnection *conn = NULL;

static DBusMessage *opp_send_files(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct opp_data *opp = user_data;
	DBusMessageIter iter, array;
	DBusMessage *reply;
	GError *err = NULL;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		char *filename;
		char *basename;
		struct obc_transfer *transfer;

		dbus_message_iter_get_basic(&array, &filename);
		basename = g_path_get_basename(filename);

		transfer = obc_transfer_put(NULL, basename, filename, NULL, 0,
									&err);

		g_free(basename);

		if (transfer == NULL)
			goto fail;

		if (!obc_session_queue(opp->session, transfer, NULL, NULL,
									&err))
			goto fail;

		dbus_message_iter_next(&array);
	}

	return dbus_message_new_method_return(message);

fail:
	reply = g_dbus_create_error(message,
				ERROR_INF ".Failed", "%s", err->message);
	g_error_free(err);
	return reply;

}

static void pull_complete_callback(struct obc_session *session,
					struct obc_transfer *transfer,
					GError *err, void *user_data)
{
	DBusMessage *message = user_data;

	if (err != NULL) {
		DBusMessage *error = g_dbus_create_error(message,
					"org.openobex.Error.Failed",
					"%s", err->message);
		g_dbus_send_message(conn, error);
		goto done;
	}

	g_dbus_send_reply(conn, message, DBUS_TYPE_INVALID);

done:
	dbus_message_unref(message);
}

static DBusMessage *opp_pull_business_card(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	struct opp_data *opp = user_data;
	struct obc_transfer *pull;
	DBusMessageIter iter;
	DBusMessage *reply;
	const char *filename = NULL;
	GError *err = NULL;

	dbus_message_iter_init(message, &iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return g_dbus_create_error(message,
				ERROR_INF ".InvalidArguments", NULL);

	dbus_message_iter_get_basic(&iter, &filename);

	pull = obc_transfer_get("text/x-vcard", NULL, filename, &err);
	if (pull == NULL)
		goto fail;

	if (!obc_session_queue(opp->session, pull, pull_complete_callback,
								message, &err))
		goto fail;

	dbus_message_ref(message);

	return NULL;

fail:
	reply = g_dbus_create_error(message,
				ERROR_INF ".Failed", "%s", err->message);
	g_error_free(err);
	return reply;
}

static DBusMessage *opp_exchange_business_cards(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	return g_dbus_create_error(message, "org.openobex.Error.Failed", NULL);
}

static const GDBusMethodTable opp_methods[] = {
	{ GDBUS_METHOD("SendFiles",
		GDBUS_ARGS({ "files", "as" }),
		NULL,
		opp_send_files) },
	{ GDBUS_ASYNC_METHOD("PullBusinessCard",
		GDBUS_ARGS({ "targetfile", "s" }),
		NULL,
		opp_pull_business_card) },
	{ GDBUS_ASYNC_METHOD("ExchangeBusinessCards",
		GDBUS_ARGS({ "clientfile", "s" }, { "targetfile", "s" }),
		NULL,
		opp_exchange_business_cards) },
	{ }
};

static void opp_free(void *data)
{
	struct opp_data *opp = data;

	obc_session_unref(opp->session);
	g_free(opp);
}

static int opp_probe(struct obc_session *session)
{
	struct opp_data *opp;
	const char *path;

	path = obc_session_get_path(session);

	DBG("%s", path);

	opp = g_try_new0(struct opp_data, 1);
	if (!opp)
		return -ENOMEM;

	opp->session = obc_session_ref(session);

	if (!g_dbus_register_interface(conn, path, OPP_INTERFACE, opp_methods,
						NULL, NULL, opp, opp_free)) {
		opp_free(opp);
		return -ENOMEM;
	}

	return 0;
}

static void opp_remove(struct obc_session *session)
{
	const char *path = obc_session_get_path(session);

	DBG("%s", path);

	g_dbus_unregister_interface(conn, path, OPP_INTERFACE);
}

static struct obc_driver opp = {
	.service = "OPP",
	.uuid = OPP_UUID,
	.probe = opp_probe,
	.remove = opp_remove
};

int opp_init(void)
{
	int err;

	DBG("");

	conn = dbus_bus_get(DBUS_BUS_SESSION, NULL);
	if (!conn)
		return -EIO;

	err = obc_driver_register(&opp);
	if (err < 0) {
		dbus_connection_unref(conn);
		conn = NULL;
		return err;
	}

	return 0;
}

void opp_exit(void)
{
	DBG("");

	dbus_connection_unref(conn);
	conn = NULL;

	obc_driver_unregister(&opp);
}
