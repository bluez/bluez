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

#include <stdlib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <errno.h>

#include "lib/bluetooth.h"
#include "lib/uuid.h"

#include "src/adapter.h"
#include "src/dbus-common.h"
#include "src/device.h"
#include "src/error.h"
#include "src/log.h"
#include "src/plugin.h"
#include "src/textfile.h"

#include "src/shared/queue.h"

#define ADMIN_POLICY_SET_INTERFACE	"org.bluez.AdminPolicySet1"
#define ADMIN_POLICY_STATUS_INTERFACE	"org.bluez.AdminPolicyStatus1"
#define ADMIN_POLICY_STORAGE		STORAGEDIR "/admin_policy_settings"

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
	admin_policy->service_allowlist = queue_new();

	return admin_policy;
}

static void free_service_allowlist(struct queue *q)
{
	queue_destroy(q, free);
}

static void admin_policy_free(void *data)
{
	struct btd_admin_policy *admin_policy = data;

	free_service_allowlist(admin_policy->service_allowlist);
	g_free(admin_policy);
}

static void admin_policy_destroy(struct btd_admin_policy *admin_policy)
{
	const char *path = adapter_get_path(admin_policy->adapter);

	g_dbus_unregister_interface(dbus_conn, path,
						ADMIN_POLICY_SET_INTERFACE);
	g_dbus_unregister_interface(dbus_conn, path,
						ADMIN_POLICY_STATUS_INTERFACE);
	admin_policy_free(admin_policy);
}

static bool uuid_match(const void *data, const void *match_data)
{
	const bt_uuid_t *uuid = data;
	const bt_uuid_t *match_uuid = match_data;

	return bt_uuid_cmp(uuid, match_uuid) == 0;
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

		dbus_message_iter_next(&arr_iter);

		if (queue_find(uuid_list, uuid_match, uuid)) {
			g_free(uuid);
			continue;
		}

		queue_push_head(uuid_list, uuid);

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

static void free_uuid_strings(char **uuid_strs, gsize num)
{
	gsize i;

	for (i = 0; i < num; i++)
		g_free(uuid_strs[i]);
	g_free(uuid_strs);
}

static char **new_uuid_strings(struct queue *allowlist, gsize *num)
{
	const struct queue_entry *entry = NULL;
	bt_uuid_t *uuid = NULL;
	char **uuid_strs = NULL;
	gsize i = 0, allowlist_num;

	allowlist_num = queue_length(allowlist);
	if (!allowlist_num) {
		*num = 0;
		return NULL;
	}

	/* Set num to a non-zero number so that whoever call this could know if
	 * this function success or not
	 */
	*num = 1;

	uuid_strs = g_try_malloc_n(allowlist_num, sizeof(char *));
	if (!uuid_strs)
		return NULL;

	for (entry = queue_get_entries(allowlist); entry != NULL;
							entry = entry->next) {
		uuid = entry->data;
		uuid_strs[i] = g_try_malloc0(MAX_LEN_UUID_STR * sizeof(char));

		if (!uuid_strs[i])
			goto failed;

		bt_uuid_to_string(uuid, uuid_strs[i], MAX_LEN_UUID_STR);
		i++;
	}

	*num = allowlist_num;
	return uuid_strs;

failed:
	free_uuid_strings(uuid_strs, i);

	return NULL;
}

static void store_policy_settings(struct btd_admin_policy *admin_policy)
{
	GKeyFile *key_file = NULL;
	GError *gerr = NULL;
	char *filename = ADMIN_POLICY_STORAGE;
	char *key_file_data = NULL;
	char **uuid_strs = NULL;
	gsize length, num_uuids;

	key_file = g_key_file_new();

	uuid_strs = new_uuid_strings(admin_policy->service_allowlist,
								&num_uuids);

	if (!uuid_strs && num_uuids) {
		btd_error(admin_policy->adapter_id,
					"Failed to allocate uuid strings");
		goto failed;
	}

	g_key_file_set_string_list(key_file, "General", "ServiceAllowlist",
					(const gchar * const *)uuid_strs,
					num_uuids);

	if (create_file(ADMIN_POLICY_STORAGE, 0600) < 0) {
		btd_error(admin_policy->adapter_id, "create %s failed, %s",
						filename, strerror(errno));
		goto failed;
	}

	key_file_data = g_key_file_to_data(key_file, &length, NULL);
	if (!g_file_set_contents(ADMIN_POLICY_STORAGE, key_file_data, length,
								&gerr)) {
		error("Unable set contents for %s: (%s)", ADMIN_POLICY_STORAGE,
								gerr->message);
		g_error_free(gerr);
	}

	g_free(key_file_data);
	free_uuid_strings(uuid_strs, num_uuids);

failed:
	g_key_file_free(key_file);
}

static void key_file_load_service_allowlist(GKeyFile *key_file,
					struct btd_admin_policy *admin_policy)
{
	GError *gerr = NULL;
	struct queue *uuid_list = NULL;
	gchar **uuids = NULL;
	gsize num, i;

	uuids = g_key_file_get_string_list(key_file, "General",
					"ServiceAllowlist", &num, &gerr);

	if (gerr) {
		btd_error(admin_policy->adapter_id,
					"Failed to load ServiceAllowlist");
		g_error_free(gerr);
		return;
	}

	uuid_list = queue_new();
	for (i = 0; i < num; i++) {
		bt_uuid_t *uuid = g_try_malloc(sizeof(*uuid));

		if (!uuid)
			goto failed;

		if (bt_string_to_uuid(uuid, uuids[i])) {

			btd_error(admin_policy->adapter_id,
					"Failed to convert '%s' to uuid struct",
					*uuids);

			g_free(uuid);
			goto failed;
		}

		queue_push_tail(uuid_list, uuid);
	}

	if (!service_allowlist_set(admin_policy, uuid_list))
		goto failed;

	g_strfreev(uuids);

	return;
failed:
	g_strfreev(uuids);
	free_service_allowlist(uuid_list);
}

static void load_policy_settings(struct btd_admin_policy *admin_policy)
{
	GKeyFile *key_file;
	GError *gerr = NULL;
	char *filename = ADMIN_POLICY_STORAGE;
	struct stat st;

	if (stat(filename, &st) < 0)
		store_policy_settings(policy_data);

	key_file = g_key_file_new();

	if (!g_key_file_load_from_file(key_file, filename, 0, &gerr)) {
		error("Unable to load key file from %s: (%s)", filename,
								gerr->message);
		g_error_free(gerr);
	}

	key_file_load_service_allowlist(key_file, admin_policy);

	g_key_file_free(key_file);
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

	if (service_allowlist_set(admin_policy, uuid_list)) {
		store_policy_settings(admin_policy);
	} else {
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

	if (!devices)
		devices = queue_new();

	if (policy_data) {
		btd_warn(policy_data->adapter_id,
						"Policy data already exists");
		admin_policy_free(policy_data);
		policy_data = NULL;
	}

	policy_data = admin_policy_new(adapter);
	if (!policy_data)
		return -ENOMEM;

	load_policy_settings(policy_data);
	adapter_path = adapter_get_path(adapter);

	if (!g_dbus_register_interface(dbus_conn, adapter_path,
					ADMIN_POLICY_SET_INTERFACE,
					admin_policy_adapter_methods, NULL,
					NULL, policy_data, NULL)) {
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
					policy_data, NULL)) {
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

static void admin_policy_remove(struct btd_adapter *adapter)
{
	DBG("");

	queue_foreach(devices, unregister_device_data, NULL);
	queue_destroy(devices, g_free);
	devices = NULL;

	if (policy_data) {
		admin_policy_destroy(policy_data);
		policy_data = NULL;
	}
}

static struct btd_adapter_driver admin_policy_driver = {
	.name	= "admin_policy",
	.probe	= admin_policy_adapter_probe,
	.resume = NULL,
	.remove = admin_policy_remove,
	.device_resolved = admin_policy_device_added,
	.device_removed = admin_policy_device_removed
};

static int admin_init(void)
{
	DBG("");

	dbus_conn = btd_get_dbus_connection();

	return btd_register_adapter_driver(&admin_policy_driver);
}

static void admin_exit(void)
{
	DBG("");

	btd_unregister_adapter_driver(&admin_policy_driver);
}

BLUETOOTH_PLUGIN_DEFINE(admin, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			admin_init, admin_exit)
