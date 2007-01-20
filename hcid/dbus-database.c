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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "hcid.h"
#include "sdpd.h"
#include "sdp-xml.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "dbus-database.h"

static int sdp_server_enable = 0;

static GSList *records = NULL;

struct record_data {
	uint32_t handle;
	char *sender;
};

static struct record_data *find_record(uint32_t handle, const char *sender)
{
	GSList *list;

	for (list = records; list; list = list->next) {
		struct record_data *data = list->data;
		if (handle == data->handle && !strcmp(sender, data->sender))
			return data;
	}

	return NULL;
}

static void exit_callback(const char *name, void *user_data)
{
	struct record_data *user_record = user_data;

	records = g_slist_remove(records, user_record);

	if (sdp_server_enable)
		remove_record_from_server(user_record->handle);
	else
		unregister_sdp_record(user_record->handle);

	free(user_record);
}

static DBusHandlerResult add_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;
	const char *sender;
	struct record_data *user_record;
	const uint8_t *record;
	int len = -1;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	dbus_message_iter_get_fixed_array(&array, &record, &len);
	if (len <= 0)
		return error_invalid_arguments(conn, msg);

	user_record = malloc(sizeof(*user_record));
	if (!user_record)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	memset(user_record, 0, sizeof(*user_record));

	if (sdp_server_enable) {
		return error_failed(conn, msg, EIO);
	} else {
		uint32_t size = len;

		if (register_sdp_binary((uint8_t *) record, size,
						&user_record->handle) < 0) {
			error("Failed to register service record");
			free(user_record);
			return error_failed(conn, msg, errno);
		}
	}

	sender = dbus_message_get_sender(msg);

	user_record->sender = strdup(sender);

	records = g_slist_append(records, user_record);

	name_listener_add(conn, sender, exit_callback, user_record);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &user_record->handle,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult add_service_record_from_xml(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *sender, *record;
	struct record_data *user_record;
	sdp_record_t *sdp_record;

	if (dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &record, DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg);

	user_record = malloc(sizeof(*user_record));
	if (!user_record)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	memset(user_record, 0, sizeof(*user_record));

	sdp_record = sdp_xml_parse_record(record, strlen(record));
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		free(user_record);
		return error_failed(conn, msg, EIO);
	}

	if (sdp_server_enable) {
		if (add_record_to_server(sdp_record) < 0) {
			error("Failed to register service record");
			free(user_record);
			sdp_record_free(sdp_record);
			return error_failed(conn, msg, EIO);
		}
	} else {
		if (register_sdp_record(sdp_record) < 0) {
			error("Failed to register service record");
			free(user_record);
			sdp_record_free(sdp_record);
			return error_failed(conn, msg, EIO);
		}
	}

	sender = dbus_message_get_sender(msg);

	user_record->handle = sdp_record->handle;
	user_record->sender = strdup(sender);

	records = g_slist_append(records, user_record);

	name_listener_add(conn, sender, exit_callback, user_record);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &user_record->handle,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult remove_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t handle;
	const char *sender;
	struct record_data *user_record;

	if (dbus_message_get_args(msg, NULL,
			DBUS_TYPE_UINT32, &handle, DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg);

	sender = dbus_message_get_sender(msg);

	user_record = find_record(handle, sender);
	if (!user_record)
		return error_not_available(conn, msg);

	name_listener_remove(conn, sender, exit_callback, user_record);

	if (sdp_server_enable)
		remove_record_from_server(handle);
	else
		unregister_sdp_record(handle);

	free(user_record);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_message_and_unref(conn, reply);
}

static struct service_data database_services[] = {
	{ "AddServiceRecord",		add_service_record		},
	{ "AddServiceRecordFromXML",	add_service_record_from_xml	},
	{ "RemoveServiceRecord",	remove_service_record		},
	{ NULL, NULL }
};

DBusHandlerResult handle_database_method(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	service_handler_func_t handler;

	handler = find_service_handler(database_services, msg);

	if (handler)
		return handler(conn, msg, data);

	return error_unknown_method(conn, msg);
}

void set_sdp_server_enable(void)
{
	sdp_server_enable = 1;
}
