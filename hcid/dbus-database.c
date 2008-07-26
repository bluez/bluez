/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2007  Nokia Corporation
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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <gdbus.h>

#include "hcid.h"
#include "sdpd.h"
#include "sdp-xml.h"
#include "manager.h"
#include "adapter.h"
#include "dbus-hci.h"
#include "dbus-common.h"
#include "error.h"
#include "dbus-service.h"
#include "dbus-security.h"
#include "dbus-database.h"

static GSList *records = NULL;

struct record_data {
	uint32_t handle;
	char *sender;
	guint listener_id;
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

static void exit_callback(void *user_data)
{
	struct record_data *user_record = user_data;

	debug("remove record");

	records = g_slist_remove(records, user_record);

	remove_record_from_server(user_record->handle);

	g_free(user_record->sender);
	g_free(user_record);
}

static inline DBusMessage *invalid_arguments(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".InvalidArguments",
					"Invalid arguments in method call");
}

static inline DBusMessage *not_available(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".NotAvailable",
							"Not Available");
}

static inline DBusMessage *failed(DBusMessage *msg)
{
	return g_dbus_create_error(msg, ERROR_INTERFACE ".Failed", "Failed");
}

static DBusMessage *add_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessageIter iter, array;
	const char *sender;
	struct record_data *user_record;
	sdp_record_t *sdp_record;
	const uint8_t *record;
	int scanned, len = -1;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_recurse(&iter, &array);

	dbus_message_iter_get_fixed_array(&array, &record, &len);
	if (len <= 0)
		return invalid_arguments(msg);

	sdp_record = sdp_extract_pdu_safe(record, len, &scanned);
	if (!sdp_record) {
		error("Parsing of service record failed");
		return failed(msg);
	}

	if (scanned != len) {
		error("Size mismatch of service record");
		sdp_record_free(sdp_record);
		return failed(msg);
	}

	if (add_record_to_server(BDADDR_ANY, sdp_record) < 0) {
		error("Failed to register service record");
		sdp_record_free(sdp_record);
		return failed(msg);
	}

	user_record = g_new0(struct record_data, 1);

	user_record->handle = sdp_record->handle;

	sender = dbus_message_get_sender(msg);

	user_record->sender = g_strdup(sender);

	records = g_slist_append(records, user_record);

	user_record->listener_id = g_dbus_add_disconnect_watch(conn, sender,
								exit_callback,
								user_record,
								NULL);

	debug("listener_id %d", user_record->listener_id);

	return g_dbus_create_reply(msg, DBUS_TYPE_UINT32, &user_record->handle,
							DBUS_TYPE_INVALID);
}

int add_xml_record(DBusConnection *conn, const char *sender, bdaddr_t *src,
				const char *record, dbus_uint32_t *handle)
{
	struct record_data *user_record;
	sdp_record_t *sdp_record;

	sdp_record = sdp_xml_parse_record(record, strlen(record));
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		return -EIO;
	}

	if (add_record_to_server(src, sdp_record) < 0) {
		error("Failed to register service record");
		sdp_record_free(sdp_record);
		return -EIO;
	}

	user_record = g_new0(struct record_data, 1);

	user_record->handle = sdp_record->handle;

	user_record->sender = g_strdup(sender);

	records = g_slist_append(records, user_record);

	user_record->listener_id = g_dbus_add_disconnect_watch(conn, sender,
					exit_callback, user_record, NULL);

	debug("listener_id %d", user_record->listener_id);

	*handle = user_record->handle;

	return 0;
}

static DBusMessage *add_service_record_from_xml(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *sender, *record;
	dbus_uint32_t handle;
	int err;

	if (dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &record, DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	sender = dbus_message_get_sender(msg);

	err = add_xml_record(conn, sender, BDADDR_ANY, record, &handle);
	if (err < 0)
		return failed(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_UINT32, &handle,
							DBUS_TYPE_INVALID);
}

static DBusMessage *update_record(DBusConnection *conn, DBusMessage *msg,
		bdaddr_t *src, dbus_uint32_t handle, sdp_record_t *sdp_record)
{
	int err;

	if (remove_record_from_server(handle) < 0) {
		sdp_record_free(sdp_record);
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAvailable",
				"Not Available");
	}

	sdp_record->handle = handle;
	err = add_record_to_server(src, sdp_record);
	if (err < 0) {
		sdp_record_free(sdp_record);
		error("Failed to update the service record");
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				strerror(EIO));
	}

	return dbus_message_new_method_return(msg);
}

static DBusMessage *update_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct record_data *user_record;
	DBusMessageIter iter, array;
	sdp_record_t *sdp_record;
	dbus_uint32_t handle;
	const uint8_t *bin_record;
	int scanned, size = -1;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &handle);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &array);

	dbus_message_iter_get_fixed_array(&array, &bin_record, &size);
	if (size <= 0)
		return invalid_arguments(msg);

	user_record = find_record(handle, dbus_message_get_sender(msg));
	if (!user_record)
		return not_available(msg);

	sdp_record = sdp_extract_pdu_safe(bin_record, size, &scanned);
	if (!sdp_record) {
		error("Parsing of service record failed");
		return invalid_arguments(msg);
	}

	if (scanned != size) {
		error("Size mismatch of service record");
		sdp_record_free(sdp_record);
		return invalid_arguments(msg);
	}

	return update_record(conn, msg, BDADDR_ANY, handle, sdp_record);
}

DBusMessage *update_xml_record(DBusConnection *conn,
				DBusMessage *msg, bdaddr_t *src)
{
	struct record_data *user_record;
	sdp_record_t *sdp_record;
	const char *record;
	dbus_uint32_t handle;
	int len;

	if (dbus_message_get_args(msg, NULL,
				DBUS_TYPE_UINT32, &handle,
				DBUS_TYPE_STRING, &record,
				DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	len = (record ? strlen(record) : 0);
	if (len == 0)
		return invalid_arguments(msg);

	user_record = find_record(handle, dbus_message_get_sender(msg));
	if (!user_record)
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".NotAvailable",
				"Not Available");

	sdp_record = sdp_xml_parse_record(record, len);
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		sdp_record_free(sdp_record);
		return g_dbus_create_error(msg,
				ERROR_INTERFACE ".Failed",
				strerror(EIO));
	}

	return update_record(conn, msg, src, handle, sdp_record);
}

static DBusMessage *update_service_record_from_xml(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	return update_xml_record(conn, msg, BDADDR_ANY);
}

int remove_record(DBusConnection *conn, const char *sender,
						dbus_uint32_t handle)
{
	struct record_data *user_record;

	debug("remove record 0x%x", handle);

	user_record = find_record(handle, sender);
	if (!user_record)
		return -1;

	debug("listner_id %d", user_record->listener_id);

	g_dbus_remove_watch(conn, user_record->listener_id);

	exit_callback(user_record);

	return 0;
}

static DBusMessage *remove_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	dbus_uint32_t handle;
	const char *sender;

	if (dbus_message_get_args(msg, NULL,
			DBUS_TYPE_UINT32, &handle, DBUS_TYPE_INVALID) == FALSE)
		return NULL;

	sender = dbus_message_get_sender(msg);

	if (remove_record(conn, sender, handle) < 0)
		return not_available(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static GDBusMethodTable database_methods[] = {
	{ "AddServiceRecord",		"ay",  "u",	add_service_record		},
	{ "AddServiceRecordFromXML",	"s",   "u",	add_service_record_from_xml	},
	{ "UpdateServiceRecord",	"uay", "",	update_service_record		},
	{ "UpdateServiceRecordFromXML",	"us",  "",	update_service_record_from_xml	},
	{ "RemoveServiceRecord",	"u",   "",	remove_service_record		},
	{ }
};

dbus_bool_t database_init(DBusConnection *conn, const char *path)
{
	return g_dbus_register_interface(conn, path, DATABASE_INTERFACE,
				database_methods, NULL, NULL, NULL, NULL);
}

void database_cleanup(DBusConnection *conn, const char *path)
{
	g_dbus_unregister_interface(conn, path, DATABASE_INTERFACE);
}
