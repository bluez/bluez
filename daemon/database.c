/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2004-2008  Marcel Holtmann <marcel@holtmann.org>
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

#include <stdlib.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus.h>

#include "sdp-xml.h"
#include "logging.h"

#include "sdpd.h"

#include "system.h"
#include "database.h"

#define DATABASE_INTERFACE "org.bluez.Database"

static DBusConnection *connection = NULL;

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

	remove_record_from_server(user_record->handle);

	free(user_record);
}

static DBusHandlerResult add_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter, array;
	dbus_uint32_t handle = 0x12345;
	const uint8_t *record;
	int i, len = -1;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	dbus_message_iter_get_fixed_array(&array, &record, &len);
	if (len < 0)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	for (i = 0; i < len; i++)
		debug("0x%02x", record[i]);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &handle,
					DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult add_service_record_from_xml(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *sender, *record;
	struct record_data *user_record;
	sdp_record_t *sdp_record;

	dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &record, DBUS_TYPE_INVALID);

	user_record = malloc(sizeof(*user_record));
	if (!user_record)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	sdp_record = sdp_xml_parse_record(record, strlen(record));
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		free(user_record);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (add_record_to_server(BDADDR_ANY, sdp_record) < 0) {
		error("Failed to register service record");
		free(user_record);
		sdp_record_free(sdp_record);
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
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

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusHandlerResult remove_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	dbus_uint32_t handle;
	const char *sender;
	struct record_data *user_record;

	dbus_message_get_args(msg, NULL,
			DBUS_TYPE_UINT32, &handle, DBUS_TYPE_INVALID);

	sender = dbus_message_get_sender(msg);

	user_record = find_record(handle, sender);
	if (!user_record)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	name_listener_remove(conn, sender, exit_callback, user_record);

	remove_record_from_server(handle);

	free(user_record);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_INVALID);

	return dbus_connection_send_and_unref(conn, reply);
}

static DBusMethodVTable database_table[] = {
	{ "AddServiceRecord", add_service_record,
		DBUS_TYPE_BYTE_ARRAY_AS_STRING, DBUS_TYPE_UINT32_AS_STRING },
	{ "AddServiceRecordFromXML", add_service_record_from_xml,
		DBUS_TYPE_STRING_AS_STRING, DBUS_TYPE_UINT32_AS_STRING },
	{ "RemoveServiceRecord", remove_service_record,
		DBUS_TYPE_UINT32_AS_STRING, DBUS_TYPE_INVALID_AS_STRING },
	{ }
};

int database_init(DBusConnection *conn)
{
	connection = dbus_connection_ref(conn);

	info("Starting database interface");

	if (dbus_connection_register_interface(connection, SYSTEM_PATH,
			DATABASE_INTERFACE, database_table, NULL, NULL) == FALSE) {
		error("Database interface registration failed");
		dbus_connection_unref(connection);
		return -1;
	}

	return 0;
}

void database_exit(void)
{
	info("Stopping database interface");

	dbus_connection_unregister_interface(connection,
					SYSTEM_PATH, DATABASE_INTERFACE);

	dbus_connection_unref(connection);

	connection = NULL;
}
