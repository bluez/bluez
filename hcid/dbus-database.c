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
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <glib.h>

#include <dbus/dbus.h>

#include "dbus.h"
#include "dbus-helper.h"
#include "hcid.h"
#include "sdpd.h"
#include "sdp-xml.h"
#include "dbus-hci.h"
#include "dbus-common.h"
#include "dbus-error.h"
#include "dbus-service.h"
#include "dbus-security.h"
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

	if (user_record->sender)
		g_free(user_record->sender);

	g_free(user_record);
}

static DBusHandlerResult add_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
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
		return error_invalid_arguments(conn, msg);

	user_record = g_new0(struct record_data, 1);

	if (sdp_server_enable) {
		sdp_record = sdp_extract_pdu(record, &scanned);
		if (!sdp_record) {
			error("Parsing of service record failed");
			g_free(user_record);
			return error_failed(conn, msg, EIO);
		}

		if (scanned != len) {
			error("Size mismatch of service record");
			g_free(user_record);
			sdp_record_free(sdp_record);
			return error_failed(conn, msg, EIO);
		}

		if (add_record_to_server(sdp_record) < 0) {
			error("Failed to register service record");
			g_free(user_record);
			sdp_record_free(sdp_record);
			return error_failed(conn, msg, EIO);
		}

		user_record->handle = sdp_record->handle;
	} else {
		uint32_t size = len;

		if (register_sdp_binary((uint8_t *) record, size,
						&user_record->handle) < 0) {
			error("Failed to register service record");
			g_free(user_record);
			return error_failed(conn, msg, errno);
		}
	}

	sender = dbus_message_get_sender(msg);

	user_record->sender = g_strdup(sender);

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

	user_record = g_new0(struct record_data, 1);

	sdp_record = sdp_xml_parse_record(record, strlen(record));
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		g_free(user_record);
		return error_failed(conn, msg, EIO);
	}

	if (sdp_server_enable) {
		if (add_record_to_server(sdp_record) < 0) {
			error("Failed to register service record");
			g_free(user_record);
			sdp_record_free(sdp_record);
			return error_failed(conn, msg, EIO);
		}

		user_record->handle = sdp_record->handle;
	} else {
		if (register_sdp_record(sdp_record) < 0) {
			error("Failed to register service record");
			g_free(user_record);
			sdp_record_free(sdp_record);
			return error_failed(conn, msg, EIO);
		}

		user_record->handle = sdp_record->handle;

		sdp_record_free(sdp_record);
	}

	sender = dbus_message_get_sender(msg);

	user_record->sender = g_strdup(sender);

	records = g_slist_append(records, user_record);

	name_listener_add(conn, sender, exit_callback, user_record);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &user_record->handle,
					DBUS_TYPE_INVALID);

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult update_service_record(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct record_data *user_record;
	DBusMessageIter iter, array;
	sdp_record_t *sdp_record;
	dbus_uint32_t handle;
	const uint8_t *bin_record;
	int err, scanned, size = -1;

	dbus_message_iter_init(msg, &iter);
	dbus_message_iter_get_basic(&iter, &handle);
	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &array);

	dbus_message_iter_get_fixed_array(&array, &bin_record, &size);
	if (size <= 0)
		return error_invalid_arguments(conn, msg);

	user_record = find_record(handle, dbus_message_get_sender(msg));
	if (!user_record)
		return error_not_available(conn, msg);

	sdp_record = sdp_extract_pdu(bin_record, &scanned);
	if (!sdp_record) {
		error("Parsing of service record failed");
		return error_invalid_arguments(conn, msg);
	}

	if (scanned != size) {
		error("Size mismatch of service record");
		sdp_record_free(sdp_record);
		return error_invalid_arguments(conn, msg);
	}

	if (sdp_server_enable) {
		if (remove_record_from_server(handle) < 0)
			return error_not_available(conn, msg);

		sdp_record->handle = handle;
		err = add_record_to_server(sdp_record);
		if (err < 0) {
			sdp_record_free(sdp_record);
			error("Failed to update the service record");
			return error_failed(conn, msg, EIO);
		}
	} else {
		sdp_data_t *d = sdp_data_alloc(SDP_UINT32, &handle);
		sdp_attr_replace(sdp_record, SDP_ATTR_RECORD_HANDLE, d);

		err = update_sdp_record(handle, sdp_record);
		sdp_record_free(sdp_record);
		if (err < 0) {
			error("Failed to update the service record");
			return error_failed(conn, msg, EIO);
		}
	}

	return send_message_and_unref(conn,
			dbus_message_new_method_return(msg));
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

	records = g_slist_remove(records, user_record);

	if (sdp_server_enable)
		remove_record_from_server(handle);
	else
		unregister_sdp_record(handle);

	if (user_record->sender)
		g_free(user_record->sender);

	g_free(user_record);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult register_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *sender, *ident, *name, *desc;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &ident,
			DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &desc,
						DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg);

	sender = dbus_message_get_sender(msg);

	if (service_register(sender, ident, name, desc) < 0)
		return error_failed(conn, msg, EIO);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult unregister_service(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	const char *sender, *ident;
	struct service *service;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &ident,
						DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg);

	sender = dbus_message_get_sender(msg);

	service = search_service(conn, ident);
	if (!service)
		return error_service_does_not_exist(conn, msg);

	if (!service->external || strcmp(sender, service->bus_name))
		return error_not_authorized(conn, msg);

	if (service_unregister(service) < 0)
		return error_failed(conn, msg, EIO);

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	return send_message_and_unref(conn, reply);
}

static DBusHandlerResult request_authorization(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *sender, *address, *path;
	struct service *service;
	bdaddr_t bdaddr;
	gboolean trusted;
	int adapter_id;

	debug("RequestAuthorization");

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg);

	sender = dbus_message_get_sender(msg);

	service = search_service(conn, sender);
	if (!service)
		return error_not_authorized(conn, msg);

	str2ba(address, &bdaddr);
	adapter_id = hci_for_each_dev(HCI_UP, find_conn, (long) &bdaddr);
	if (adapter_id < 0)
		return error_not_connected(conn, msg);

	hci_devba(adapter_id, &bdaddr);

	trusted = read_trust(&bdaddr, address, GLOBAL_TRUST);
	if (!trusted)
		trusted = read_trust(BDADDR_ANY, address, service->ident);

	if (trusted) {
		DBusMessage *reply;

		reply = dbus_message_new_method_return(msg);
		if (!reply)
			return DBUS_HANDLER_RESULT_NEED_MEMORY;

		return send_message_and_unref(conn, reply);
	}

	return handle_authorize_request(conn, msg, service, address, path);
}

static DBusHandlerResult cancel_authorization_request(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	const char *sender, *address, *path;
	struct service *service;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
			DBUS_TYPE_STRING, &path, DBUS_TYPE_INVALID) == FALSE)
		return error_invalid_arguments(conn, msg);

	sender = dbus_message_get_sender(msg);

	service = search_service(conn, sender);
	if (!service)
		return error_not_authorized(conn, msg);

	return cancel_authorize_request(conn, msg, service, address, path);
}

static DBusMethodVTable database_methods[] = {
	{ "AddServiceRecord",		add_service_record,		"ay",	"u"	},	
	{ "AddServiceRecordFromXML",	add_service_record_from_xml,	"s",	"u"	},
	{ "UpdateServiceRecord",	update_service_record,		"uay",	""	},
	{ "RemoveServiceRecord",	remove_service_record,		"u",	""	},
	{ "RegisterService",		register_service,		"sss",	""	},
	{ "UnregisterService",		unregister_service,		"s",	""	},
	{ "RequestAuthorization",	request_authorization,		"ss",	""	},
	{ "CancelAuthorizationRequest",	cancel_authorization_request,	"ss",	""	},
	{ NULL, NULL, NULL, NULL }
};

dbus_bool_t database_init(DBusConnection *conn, const char *path)
{
	return dbus_connection_register_interface(conn, path,
							DATABASE_INTERFACE,
							database_methods,
							NULL, NULL);
}

void set_sdp_server_enable(void)
{
	sdp_server_enable = 1;
}
