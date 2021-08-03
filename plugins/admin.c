// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2021 Google LLC
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "lib/bluetooth.h"
#include "lib/uuid.h"

#include "src/adapter.h"
#include "src/dbus-common.h"
#include "src/device.h"
#include "src/error.h"
#include "src/log.h"
#include "src/plugin.h"

#include "src/shared/queue.h"

#define ADMIN_POLICY_SET_INTERFACE	"org.bluez.AdminPolicySet1"
#define ADMIN_POLICY_STATUS_INTERFACE	"org.bluez.AdminPolicyStatus1"

#define DBUS_BLUEZ_SERVICE		"org.bluez"
#define BTD_DEVICE_INTERFACE		"org.bluez.Device1"

static DBusConnection *dbus_conn;
static struct queue *devices; /* List of struct device_data objects */

/* |policy_data| has the same life cycle as btd_adapter */
static struct btd_admin_policy {
	struct btd_adapter *adapter;
	uint16_t adapter_id;
	struct queue *service_allowlist;
} *policy_data = NULL;

struct device_data {
	struct btd_device *device;
	char *path;
	bool affected;
};

static struct btd_admin_policy *admin_policy_new(struct btd_adapter *adapter)
{
	struct btd_admin_policy *admin_policy = NULL;

	admin_policy = g_try_malloc(sizeof(*admin_policy));
	if (!admin_policy) {
		btd_error(btd_adapter_get_index(adapter),
				"Failed to allocate memory for admin_policy");
		return NULL;
	}

	admin_policy->adapter = adapter;
	admin_policy->adapter_id = btd_adapter_get_index(adapter);
	admin_policy->service_allowlist = NULL;

	return admin_policy;
}

static void free_service_allowlist(struct queue *q)
{
	queue_destroy(q, g_free);
}

static void admin_policy_free(void *data)
{
	struct btd_admin_policy *admin_policy = data;

	free_service_allowlist(admin_policy->service_allowlist);
	g_free(admin_policy);
}

static struct queue *parse_allow_service_list(struct btd_adapter *adapter,
							DBusMessage *msg)
{
	DBusMessageIter iter, arr_iter;
	struct queue *uuid_list = NULL;

	dbus_message_iter_init(msg, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return NULL;

	uuid_list = queue_new();
	dbus_message_iter_recurse(&iter, &arr_iter);
	do {
		const int type = dbus_message_iter_get_arg_type(&arr_iter);
		char *uuid_param;
		bt_uuid_t *uuid;

		if (type == DBUS_TYPE_INVALID)
			break;

		if (type != DBUS_TYPE_STRING)
			goto failed;

		dbus_message_iter_get_basic(&arr_iter, &uuid_param);

		uuid = g_try_malloc(sizeof(*uuid));
		if (!uuid)
			goto failed;

		if (bt_string_to_uuid(uuid, uuid_param)) {
			g_free(uuid);
			goto failed;
		}

		queue_push_head(uuid_list, uuid);

		dbus_message_iter_next(&arr_iter);
	} while (true);

	return uuid_list;

failed:
	queue_destroy(uuid_list, g_free);
	return NULL;
}

static bool service_allowlist_set(struct btd_admin_policy *admin_policy,
							struct queue *uuid_list)
{
	struct btd_adapter *adapter = admin_policy->adapter;

	if (!btd_adapter_set_allowed_uuids(adapter, uuid_list))
		return false;

	free_service_allowlist(admin_policy->service_allowlist);
	admin_policy->service_allowlist = uuid_list;

	return true;
}

static void update_device_affected(void *data, void *user_data)
{
	struct device_data *dev_data = data;
	bool affected;

	if (!dev_data) {
		error("Unexpected NULL device_data when updating device");
		return;
	}

	affected = !btd_device_all_services_allowed(dev_data->device);

	if (affected == dev_data->affected)
		return;

	dev_data->affected = affected;

	g_dbus_emit_property_changed(dbus_conn, dev_data->path,
			ADMIN_POLICY_STATUS_INTERFACE, "AffectedByPolicy");
}

static DBusMessage *set_service_allowlist(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct btd_admin_policy *admin_policy = user_data;
	struct btd_adapter *adapter = admin_policy->adapter;
	struct queue *uuid_list = NULL;
	const char *sender = dbus_message_get_sender(msg);

	DBG("sender %s", sender);

	/* Parse parameters */
	uuid_list = parse_allow_service_list(adapter, msg);
	if (!uuid_list) {
		btd_error(admin_policy->adapter_id,
				"Failed on parsing allowed service list");
		return btd_error_invalid_args(msg);
	}

	if (!service_allowlist_set(admin_policy, uuid_list)) {
		free_service_allowlist(uuid_list);
		return btd_error_failed(msg, "service_allowlist_set failed");
	}

	g_dbus_emit_property_changed(dbus_conn,
					adapter_get_path(policy_data->adapter),
					ADMIN_POLICY_STATUS_INTERFACE,
					"ServiceAllowList");

	queue_foreach(devices, update_device_affected, NULL);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable admin_policy_adapter_methods[] = {
	{ GDBUS_METHOD("SetServiceAllowList", GDBUS_ARGS({ "UUIDs", "as" }),
						NULL, set_service_allowlist) },
	{ }
};

static void append_service_uuid(void *data, void *user_data)
{
	bt_uuid_t *uuid = data;
	DBusMessageIter *entry = user_data;
	char uuid_str[MAX_LEN_UUID_STR];
	const char *uuid_str_ptr = uuid_str;

	if (!uuid) {
		error("Unexpected NULL uuid data in service_allowlist");
		return;
	}

	bt_uuid_to_string(uuid, uuid_str, MAX_LEN_UUID_STR);
	dbus_message_iter_append_basic(entry, DBUS_TYPE_STRING, &uuid_str_ptr);
}

static gboolean property_get_service_allowlist(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct btd_admin_policy *admin_policy = user_data;
	DBusMessageIter entry;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &entry);
	queue_foreach(admin_policy->service_allowlist, append_service_uuid,
									&entry);
	dbus_message_iter_close_container(iter, &entry);

	return TRUE;
}

static const GDBusPropertyTable admin_policy_adapter_properties[] = {
	{ "ServiceAllowList", "as", property_get_service_allowlist },
	{ }
};

static bool device_data_match(const void *a, const void *b)
{
	const struct device_data *data = a;
	const struct btd_device *dev = b;

	if (!data) {
		error("Unexpected NULL device_data");
		return false;
	}

	return data->device == dev;
}

static gboolean property_get_affected_by_policy(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *user_data)
{
	struct device_data *data = user_data;

	if (!data) {
		error("Unexpected error: device_data is NULL");
		return FALSE;
	}

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN,
							&data->affected);

	return TRUE;
}

static const GDBusPropertyTable admin_policy_device_properties[] = {
	{ "AffectedByPolicy", "b", property_get_affected_by_policy },
	{ }
};

static void free_device_data(void *data)
{
	struct device_data *device_data = data;

	g_free(device_data->path);
	g_free(device_data);
}

static void remove_device_data(void *data)
{
	struct device_data *device_data = data;

	DBG("device_data for %s removing", device_data->path);

	queue_remove(devices, device_data);
	free_device_data(device_data);
}

static int admin_policy_adapter_probe(struct btd_adapter *adapter)
{
	const char *adapter_path;

	if (policy_data) {
		btd_warn(policy_data->adapter_id,
						"Policy data already exists");
		admin_policy_free(policy_data);
		policy_data = NULL;
	}

	policy_data = admin_policy_new(adapter);
	if (!policy_data)
		return -ENOMEM;

	adapter_path = adapter_get_path(adapter);

	if (!g_dbus_register_interface(dbus_conn, adapter_path,
					ADMIN_POLICY_SET_INTERFACE,
					admin_policy_adapter_methods, NULL,
					NULL, policy_data, admin_policy_free)) {
		btd_error(policy_data->adapter_id,
			"Admin Policy Set interface init failed on path %s",
								adapter_path);
		return -EINVAL;
	}

	btd_info(policy_data->adapter_id,
				"Admin Policy Set interface registered");

	if (!g_dbus_register_interface(dbus_conn, adapter_path,
					ADMIN_POLICY_STATUS_INTERFACE,
					NULL, NULL,
					admin_policy_adapter_properties,
					policy_data, admin_policy_free)) {
		btd_error(policy_data->adapter_id,
			"Admin Policy Status interface init failed on path %s",
								adapter_path);
		return -EINVAL;
	}

	btd_info(policy_data->adapter_id,
				"Admin Policy Status interface registered");

	return 0;
}

static void admin_policy_device_added(struct btd_adapter *adapter,
						struct btd_device *device)
{
	struct device_data *data;

	if (queue_find(devices, device_data_match, device))
		return;

	data = g_new0(struct device_data, 1);
	if (!data) {
		btd_error(btd_adapter_get_index(adapter),
				"Failed to allocate memory for device_data");
		return;
	}

	data->device = device;
	data->path = g_strdup(device_get_path(device));
	data->affected = !btd_device_all_services_allowed(data->device);

	if (!g_dbus_register_interface(dbus_conn, data->path,
					ADMIN_POLICY_STATUS_INTERFACE,
					NULL, NULL,
					admin_policy_device_properties,
					data, remove_device_data)) {
		btd_error(btd_adapter_get_index(adapter),
			"Admin Policy Status interface init failed on path %s",
						device_get_path(device));
		free_device_data(data);
		return;
	}

	queue_push_tail(devices, data);

	DBG("device_data for %s added", data->path);
}

static void unregister_device_data(void *data, void *user_data)
{
	struct device_data *dev_data = data;

	g_dbus_unregister_interface(dbus_conn, dev_data->path,
						ADMIN_POLICY_STATUS_INTERFACE);
}

static void admin_policy_device_removed(struct btd_adapter *adapter,
						struct btd_device *device)
{
	struct device_data *data;

	data = queue_find(devices, device_data_match, device);

	if (data)
		unregister_device_data(data, NULL);
}

static struct btd_adapter_driver admin_policy_driver = {
	.name	= "admin_policy",
	.probe	= admin_policy_adapter_probe,
	.resume = NULL,
	.device_resolved = admin_policy_device_added,
	.device_removed = admin_policy_device_removed
};

static int admin_init(void)
{
	DBG("");

	dbus_conn = btd_get_dbus_connection();
	devices = queue_new();

	return btd_register_adapter_driver(&admin_policy_driver);
}

static void admin_exit(void)
{
	DBG("");

	btd_unregister_adapter_driver(&admin_policy_driver);
	queue_foreach(devices, unregister_device_data, NULL);
	queue_destroy(devices, g_free);

	if (policy_data)
		admin_policy_free(policy_data);
}

BLUETOOTH_PLUGIN_DEFINE(admin, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			admin_init, admin_exit)
