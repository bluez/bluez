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
#include "src/error.h"
#include "src/log.h"
#include "src/plugin.h"

#include "src/shared/queue.h"

#define ADMIN_POLICY_SET_INTERFACE	"org.bluez.AdminPolicySet1"

static DBusConnection *dbus_conn;

/* |policy_data| has the same life cycle as btd_adapter */
static struct btd_admin_policy {
	struct btd_adapter *adapter;
	uint16_t adapter_id;
	struct queue *service_allowlist;
} *policy_data = NULL;

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

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable admin_policy_adapter_methods[] = {
	{ GDBUS_METHOD("SetServiceAllowList", GDBUS_ARGS({ "UUIDs", "as" }),
						NULL, set_service_allowlist) },
	{ }
};

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
	return 0;
}

static struct btd_adapter_driver admin_policy_driver = {
	.name	= "admin_policy",
	.probe	= admin_policy_adapter_probe,
	.resume = NULL,
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

	if (policy_data)
		admin_policy_free(policy_data);
}

BLUETOOTH_PLUGIN_DEFINE(admin, VERSION,
			BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
			admin_init, admin_exit)
