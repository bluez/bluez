/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2006-2010  Nokia Corporation
 *  Copyright (C) 2004-2010  Marcel Holtmann <marcel@holtmann.org>
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

#include <gdbus/gdbus.h>

#include "dbus-common.h"
#include "sdpd.h"
#include "sdp-xml.h"
#include "plugin.h"
#include "adapter.h"
#include "error.h"
#include "log.h"

#define SERVICE_INTERFACE "org.bluez.Service"
#define get_address(adp) \
	(adp->adapter ? adapter_get_address(adp->adapter) : BDADDR_ANY)

struct record_data {
	uint32_t handle;
	char *sender;
	guint listener_id;
	struct service_adapter *serv_adapter;
};

struct pending_auth {
	DBusMessage *msg;
	char *sender;
	bdaddr_t dst;
	char uuid[MAX_LEN_UUID_STR];
	guint id;
};

struct service_adapter {
	struct btd_adapter *adapter;
	GSList *pending_list;
	GSList *records;
};

static struct service_adapter *serv_adapter_any = NULL;

static struct record_data *find_record(struct service_adapter *serv_adapter,
					uint32_t handle, const char *sender)
{
	GSList *list;

	for (list = serv_adapter->records; list; list = list->next) {
		struct record_data *data = list->data;
		if (handle == data->handle && !strcmp(sender, data->sender))
			return data;
	}

	return NULL;
}

static struct pending_auth *next_pending(struct service_adapter *serv_adapter)
{
	GSList *l = serv_adapter->pending_list;

	if (l) {
		struct pending_auth *auth = l->data;
		return auth;
	}

	return NULL;
}

static struct pending_auth *find_pending_by_sender(
			struct service_adapter *serv_adapter,
			const char *sender)
{
	GSList *l = serv_adapter->pending_list;

	for (; l; l = l->next) {
		struct pending_auth *auth = l->data;
		if (g_str_equal(auth->sender, sender))
			return auth;
	}

	return NULL;
}

static void exit_callback(DBusConnection *conn, void *user_data)
{
	struct record_data *user_record = user_data;
	struct service_adapter *serv_adapter = user_record->serv_adapter;
	struct pending_auth *auth;

	DBG("remove record");

	serv_adapter->records = g_slist_remove(serv_adapter->records,
						user_record);

	auth = find_pending_by_sender(serv_adapter, user_record->sender);
	if (auth) {
		serv_adapter->pending_list = g_slist_remove(serv_adapter->pending_list,
							auth);
		g_free(auth);
	}

	remove_record_from_server(user_record->handle);

	g_free(user_record->sender);
	g_free(user_record);
}

static int add_xml_record(const char *sender,
			struct service_adapter *serv_adapter,
			const char *record, dbus_uint32_t *handle)
{
	struct record_data *user_record;
	sdp_record_t *sdp_record;

	sdp_record = sdp_xml_parse_record(record, strlen(record));
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		return -EIO;
	}

	if (add_record_to_server(get_address(serv_adapter), sdp_record) < 0) {
		error("Failed to register service record");
		sdp_record_free(sdp_record);
		return -EIO;
	}

	user_record = g_new0(struct record_data, 1);
	user_record->handle = sdp_record->handle;
	user_record->sender = g_strdup(sender);
	user_record->serv_adapter = serv_adapter;
	user_record->listener_id =
		g_dbus_add_disconnect_watch(btd_get_dbus_connection(), sender,
					exit_callback, user_record, NULL);

	serv_adapter->records = g_slist_append(serv_adapter->records,
								user_record);

	DBG("listener_id %d", user_record->listener_id);

	*handle = user_record->handle;

	return 0;
}

static DBusMessage *update_record(DBusMessage *msg,
				struct service_adapter *serv_adapter,
				dbus_uint32_t handle, sdp_record_t *sdp_record)
{
	int err;

	if (remove_record_from_server(handle) < 0) {
		sdp_record_free(sdp_record);
		return btd_error_not_available(msg);
	}

	sdp_record->handle = handle;
	err = add_record_to_server(get_address(serv_adapter), sdp_record);
	if (err < 0) {
		sdp_record_free(sdp_record);
		error("Failed to update the service record");
		return btd_error_failed(msg, strerror(-err));
	}

	return dbus_message_new_method_return(msg);
}

static DBusMessage *update_xml_record(DBusMessage *msg,
					struct service_adapter *serv_adapter)
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
		return btd_error_invalid_args(msg);

	len = (record ? strlen(record) : 0);
	if (len == 0)
		return btd_error_invalid_args(msg);

	user_record = find_record(serv_adapter, handle,
				dbus_message_get_sender(msg));
	if (!user_record)
		return btd_error_not_available(msg);

	sdp_record = sdp_xml_parse_record(record, len);
	if (!sdp_record) {
		error("Parsing of XML service record failed");
		return btd_error_failed(msg,
					"Parsing of XML service record failed");
	}

	return update_record(msg, serv_adapter, handle, sdp_record);
}

static int remove_record(const char *sender,
				struct service_adapter *serv_adapter,
				dbus_uint32_t handle)
{
	DBusConnection *conn = btd_get_dbus_connection();
	struct record_data *user_record;

	DBG("remove record 0x%x", handle);

	user_record = find_record(serv_adapter, handle, sender);
	if (!user_record)
		return -1;

	DBG("listner_id %d", user_record->listener_id);

	g_dbus_remove_watch(conn, user_record->listener_id);

	exit_callback(conn, user_record);

	return 0;
}

static DBusMessage *add_service_record(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service_adapter *serv_adapter = data;
	DBusMessage *reply;
	const char *sender, *record;
	dbus_uint32_t handle;
	int err;

	if (dbus_message_get_args(msg, NULL,
			DBUS_TYPE_STRING, &record, DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	sender = dbus_message_get_sender(msg);
	err = add_xml_record(sender, serv_adapter, record, &handle);
	if (err < 0)
		return btd_error_failed(msg, strerror(-err));

	reply = dbus_message_new_method_return(msg);
	if (!reply)
		return NULL;

	dbus_message_append_args(reply, DBUS_TYPE_UINT32, &handle,
							DBUS_TYPE_INVALID);

	return reply;
}

static DBusMessage *update_service_record(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service_adapter *serv_adapter = data;

	return update_xml_record(msg, serv_adapter);
}

static DBusMessage *remove_service_record(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct service_adapter *serv_adapter = data;
	dbus_uint32_t handle;
	const char *sender;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_UINT32, &handle,
						DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	sender = dbus_message_get_sender(msg);

	if (remove_record(sender, serv_adapter, handle) < 0)
		return btd_error_not_available(msg);

	return dbus_message_new_method_return(msg);
}

static void auth_cb(DBusError *derr, void *user_data)
{
	DBusConnection *conn = btd_get_dbus_connection();
	struct service_adapter *serv_adapter = user_data;
	DBusMessage *reply;
	struct pending_auth *auth;

	auth = next_pending(serv_adapter);
	if (auth == NULL) {
		info("Authorization cancelled: Client exited");
		return;
	}

	if (derr) {
		error("Access denied: %s", derr->message);

		reply = btd_error_not_authorized(auth->msg);
		g_dbus_send_message(conn, reply);
		goto done;
	}

	g_dbus_send_reply(conn, auth->msg, DBUS_TYPE_INVALID);

done:
	serv_adapter->pending_list = g_slist_remove(serv_adapter->pending_list,
									auth);
	dbus_message_unref(auth->msg);
	g_free(auth);

	auth = next_pending(serv_adapter);
	if (auth == NULL)
		return;

	auth->id = btd_request_authorization(get_address(serv_adapter),
							&auth->dst, auth->uuid,
							auth_cb, serv_adapter);
}

static DBusMessage *request_authorization(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	struct record_data *user_record;
	struct service_adapter *serv_adapter = data;
	sdp_record_t *record;
	sdp_list_t *services;
	const char *sender;
	dbus_uint32_t handle;
	const char *address;
	struct pending_auth *auth;
	char uuid_str[MAX_LEN_UUID_STR];
	uuid_t *uuid, *uuid128;

	if (dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &address,
					DBUS_TYPE_UINT32, &handle,
					DBUS_TYPE_INVALID) == FALSE)
		return btd_error_invalid_args(msg);

	sender = dbus_message_get_sender(msg);
	if (find_pending_by_sender(serv_adapter, sender))
		return btd_error_does_not_exist(msg);

	user_record = find_record(serv_adapter, handle, sender);
	if (!user_record) {
		user_record = find_record(serv_adapter_any, handle, sender);
		if (!user_record)
			return btd_error_not_authorized(msg);
	}

	record = sdp_record_find(user_record->handle);
	if (record == NULL)
		return btd_error_not_authorized(msg);

	if (sdp_get_service_classes(record, &services) < 0) {
		sdp_record_free(record);
		return btd_error_not_authorized(msg);
	}

	if (services == NULL)
		return btd_error_not_authorized(msg);

	uuid = services->data;
	uuid128 = sdp_uuid_to_uuid128(uuid);

	sdp_list_free(services, bt_free);

	if (sdp_uuid2strn(uuid128, uuid_str, MAX_LEN_UUID_STR) < 0) {
		bt_free(uuid128);
		return btd_error_not_authorized(msg);
	}
	bt_free(uuid128);

	auth = g_new0(struct pending_auth, 1);
	auth->msg = dbus_message_ref(msg);
	auth->sender = user_record->sender;
	memcpy(auth->uuid, uuid_str, MAX_LEN_UUID_STR);
	str2ba(address, &auth->dst);

	serv_adapter->pending_list = g_slist_append(serv_adapter->pending_list,
									auth);

	auth = next_pending(serv_adapter);
	if (auth == NULL)
		return btd_error_does_not_exist(msg);

	auth->id = btd_request_authorization(get_address(serv_adapter),
							&auth->dst, auth->uuid,
							auth_cb, serv_adapter);
	if (auth->id == 0) {
		serv_adapter->pending_list = g_slist_remove(serv_adapter->pending_list,
									auth);
		g_free(auth);
		return btd_error_not_authorized(msg);
	}

	return NULL;
}

static DBusMessage *cancel_authorization(DBusConnection *conn,
						DBusMessage *msg, void *data)
{
	DBusMessage *reply;
	struct service_adapter *serv_adapter = data;
	struct pending_auth *auth;
	const gchar *sender;

	sender = dbus_message_get_sender(msg);

	auth = find_pending_by_sender(serv_adapter, sender);
	if (auth == NULL)
		return btd_error_does_not_exist(msg);

	btd_cancel_authorization(auth->id);

	reply = btd_error_not_authorized(auth->msg);
	dbus_message_unref(auth->msg);
	g_dbus_send_message(btd_get_dbus_connection(), reply);

	serv_adapter->pending_list = g_slist_remove(serv_adapter->pending_list,
									auth);
	g_free(auth);

	auth = next_pending(serv_adapter);
	if (auth == NULL)
		goto done;

	auth->id = btd_request_authorization(get_address(serv_adapter),
							&auth->dst, auth->uuid,
							auth_cb, serv_adapter);

done:
	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable service_methods[] = {
	{ GDBUS_METHOD("AddRecord",
		GDBUS_ARGS({ "record", "s" }),
		GDBUS_ARGS({ "handle", "u" }),
		add_service_record) },
	{ GDBUS_METHOD("UpdateRecord",
		GDBUS_ARGS({ "handle", "u" }, { "record", "s" }), NULL,
		update_service_record) },
	{ GDBUS_METHOD("RemoveRecord",
		GDBUS_ARGS({ "handle", "u" }), NULL,
		remove_service_record) },
	{ GDBUS_ASYNC_METHOD("RequestAuthorization",
		GDBUS_ARGS({ "address", "s" }, { "handle", "u"}), NULL,
		request_authorization) },
	{ GDBUS_METHOD("CancelAuthorization",
		NULL, NULL, cancel_authorization) },
	{ }
};

static void path_unregister(void *data)
{
	DBusConnection *conn = btd_get_dbus_connection();
	struct service_adapter *serv_adapter = data;
	GSList *l, *next = NULL;

	for (l = serv_adapter->records; l != NULL; l = next) {
		struct record_data *user_record = l->data;

		next = l->next;

		g_dbus_remove_watch(conn, user_record->listener_id);
		exit_callback(conn, user_record);
	}

	if (serv_adapter->adapter != NULL)
		btd_adapter_unref(serv_adapter->adapter);

	g_free(serv_adapter);
}

static int register_interface(const char *path, struct btd_adapter *adapter)
{
	struct service_adapter *serv_adapter;

	DBG("path %s", path);

	serv_adapter = g_try_new0(struct service_adapter, 1);
	if (serv_adapter == NULL)
		return -ENOMEM;

	if (adapter != NULL)
		serv_adapter->adapter = btd_adapter_ref(adapter);

	serv_adapter->pending_list = NULL;

	if (g_dbus_register_interface(btd_get_dbus_connection(),
				path, SERVICE_INTERFACE,
				service_methods, NULL, NULL, serv_adapter,
						path_unregister) == FALSE) {
		error("D-Bus failed to register %s interface",
							SERVICE_INTERFACE);
		g_free(serv_adapter);
		return -EIO;
	}

	DBG("Registered interface %s on path %s", SERVICE_INTERFACE, path);

	if (serv_adapter->adapter == NULL)
		serv_adapter_any = serv_adapter;

	return 0;
}

static void unregister_interface(const char *path)
{
	DBG("path %s", path);

	g_dbus_unregister_interface(btd_get_dbus_connection(),
						path, SERVICE_INTERFACE);
}

static int service_probe(struct btd_adapter *adapter)
{
	register_interface(adapter_get_path(adapter), adapter);

	return 0;
}

static void service_remove(struct btd_adapter *adapter)
{
	unregister_interface(adapter_get_path(adapter));
}

static struct btd_adapter_driver service_driver = {
	.name	= "service",
	.probe	= service_probe,
	.remove	= service_remove,
};

static const char *any_path;

static int service_init(void)
{
	any_path = btd_adapter_any_request_path();
	if (any_path != NULL) {
		if (register_interface(any_path, NULL) < 0) {
			btd_adapter_any_release_path();
			any_path = NULL;
		}
	}

	return btd_register_adapter_driver(&service_driver);
}

static void service_exit(void)
{
	btd_unregister_adapter_driver(&service_driver);

	if (any_path != NULL) {
		unregister_interface(any_path);

		btd_adapter_any_release_path();
		any_path = NULL;
	}
}

BLUETOOTH_PLUGIN_DEFINE(service, VERSION,
		BLUETOOTH_PLUGIN_PRIORITY_HIGH, service_init, service_exit)
