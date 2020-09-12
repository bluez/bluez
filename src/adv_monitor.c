/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020 Google LLC
 *
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <glib.h>
#include <dbus/dbus.h>
#include <gdbus/gdbus.h>

#include "lib/bluetooth.h"
#include "lib/mgmt.h"

#include "adapter.h"
#include "dbus-common.h"
#include "log.h"
#include "src/error.h"
#include "src/shared/mgmt.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"

#include "adv_monitor.h"

#define ADV_MONITOR_MGR_INTERFACE	"org.bluez.AdvertisementMonitorManager1"

struct btd_adv_monitor_manager {
	struct btd_adapter *adapter;
	struct mgmt *mgmt;
	uint16_t adapter_id;

	uint32_t supported_features;	/* MGMT_ADV_MONITOR_FEATURE_MASK_* */
	uint32_t enabled_features;	/* MGMT_ADV_MONITOR_FEATURE_MASK_* */
	uint16_t max_num_monitors;
	uint8_t max_num_patterns;

	struct queue *apps;	/* apps who registered for Adv monitoring */
};

struct adv_monitor_app {
	struct btd_adv_monitor_manager *manager;
	char *owner;
	char *path;

	DBusMessage *reg;
	GDBusClient *client;
};

struct app_match_data {
	const char *owner;
	const char *path;
};

/* Replies to an app's D-Bus message and unref it */
static void app_reply_msg(struct adv_monitor_app *app, DBusMessage *reply)
{
	if (!app || !app->reg || !reply)
		return;

	g_dbus_send_message(btd_get_dbus_connection(), reply);
	dbus_message_unref(app->reg);
	app->reg = NULL;
}

/* Destroys an app object along with related D-Bus handlers */
static void app_destroy(void *data)
{
	struct adv_monitor_app *app = data;

	if (!app)
		return;

	DBG("Destroy Adv Monitor app %s at path %s", app->owner, app->path);

	if (app->reg) {
		app_reply_msg(app, btd_error_failed(app->reg,
						"Adv Monitor app destroyed"));
	}

	if (app->client) {
		g_dbus_client_set_disconnect_watch(app->client, NULL, NULL);
		g_dbus_client_set_proxy_handlers(app->client, NULL, NULL, NULL,
							NULL);
		g_dbus_client_set_ready_watch(app->client, NULL, NULL);
		g_dbus_client_unref(app->client);
	}

	g_free(app->owner);
	g_free(app->path);

	free(app);
}

/* Handles a D-Bus disconnection event of an app */
static void app_disconnect_cb(DBusConnection *conn, void *user_data)
{
	struct adv_monitor_app *app = user_data;

	btd_info(app->manager->adapter_id, "Adv Monitor app %s disconnected "
			"from D-Bus", app->owner);
	if (app && queue_remove(app->manager->apps, app))
		app_destroy(app);
}

/* Creates an app object, initiates it and sets D-Bus event handlers */
static struct adv_monitor_app *app_create(DBusConnection *conn,
					const char *sender, const char *path,
					struct btd_adv_monitor_manager *manager)
{
	struct adv_monitor_app *app;

	if (!path || !sender || !manager)
		return NULL;

	app = new0(struct adv_monitor_app, 1);
	if (!app)
		return NULL;

	app->owner = g_strdup(sender);
	app->path = g_strdup(path);
	app->manager = manager;
	app->reg = NULL;

	app->client = g_dbus_client_new(conn, sender, path);
	if (!app->client) {
		app_destroy(app);
		return NULL;
	}

	g_dbus_client_set_disconnect_watch(app->client, app_disconnect_cb, app);
	g_dbus_client_set_proxy_handlers(app->client, NULL, NULL, NULL, NULL);
	g_dbus_client_set_ready_watch(app->client, NULL, NULL);

	return app;
}

/* Matches an app based on its owner and path */
static bool app_match(const void *a, const void *b)
{
	const struct adv_monitor_app *app = a;
	const struct app_match_data *match = b;

	if (match->owner && strcmp(app->owner, match->owner))
		return false;

	if (match->path && strcmp(app->path, match->path))
		return false;

	return true;
}

/* Handles a RegisterMonitor D-Bus call */
static DBusMessage *register_monitor(DBusConnection *conn, DBusMessage *msg,
					void *user_data)
{
	DBusMessageIter args;
	struct app_match_data match;
	struct adv_monitor_app *app;
	struct btd_adv_monitor_manager *manager = user_data;

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &match.path);

	if (!strlen(match.path) || !g_str_has_prefix(match.path, "/"))
		return btd_error_invalid_args(msg);

	match.owner = dbus_message_get_sender(msg);

	if (queue_find(manager->apps, app_match, &match))
		return btd_error_already_exists(msg);

	app = app_create(conn, match.owner, match.path, manager);
	if (!app) {
		btd_error(manager->adapter_id,
				"Failed to reserve %s for Adv Monitor app %s",
				match.path, match.owner);
		return btd_error_failed(msg,
					"Failed to create Adv Monitor app");
	}

	queue_push_tail(manager->apps, app);

	btd_info(manager->adapter_id, "Path %s reserved for Adv Monitor app %s",
			match.path, match.owner);

	return dbus_message_new_method_return(msg);
}

/* Handles UnregisterMonitor D-Bus call */
static DBusMessage *unregister_monitor(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBusMessageIter args;
	struct app_match_data match;
	struct adv_monitor_app *app;
	struct btd_adv_monitor_manager *manager = user_data;

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &match.path);

	if (!strlen(match.path) || !g_str_has_prefix(match.path, "/"))
		return btd_error_invalid_args(msg);

	match.owner = dbus_message_get_sender(msg);

	app = queue_find(manager->apps, app_match, &match);
	if (!app)
		return btd_error_does_not_exist(msg);

	queue_remove(manager->apps, app);
	app_destroy(app);

	btd_info(manager->adapter_id, "Path %s removed along with Adv Monitor "
			"app %s", match.path, match.owner);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable adv_monitor_methods[] = {
	{ GDBUS_EXPERIMENTAL_METHOD("RegisterMonitor",
					GDBUS_ARGS({ "application", "o" }),
					NULL, register_monitor) },
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("UnregisterMonitor",
					GDBUS_ARGS({ "application", "o" }),
					NULL, unregister_monitor) },
	{ }
};

enum monitor_type {
	MONITOR_TYPE_OR_PATTERNS,
};

const struct adv_monitor_type {
	enum monitor_type type;
	const char *name;
} supported_types[] = {
	{ MONITOR_TYPE_OR_PATTERNS, "or_patterns" },
	{ },
};

/* Gets SupportedMonitorTypes property */
static gboolean get_supported_monitor_types(const GDBusPropertyTable *property,
						DBusMessageIter *iter,
						void *data)
{
	DBusMessageIter entry;
	const struct adv_monitor_type *t;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_STRING_AS_STRING,
						&entry);

	for (t = supported_types; t->name; t++) {
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
						&t->name);
	}

	dbus_message_iter_close_container(iter, &entry);

	return TRUE;
}

const struct adv_monitor_feature {
	uint32_t mask;
	const char *name;
} supported_features[] = {
	{ MGMT_ADV_MONITOR_FEATURE_MASK_OR_PATTERNS, "controller-patterns" },
	{ }
};

/* Gets SupportedFeatures property */
static gboolean get_supported_features(const GDBusPropertyTable *property,
						DBusMessageIter *iter,
						void *data)
{
	DBusMessageIter entry;
	const struct adv_monitor_feature *f;
	struct btd_adv_monitor_manager *manager = data;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
						DBUS_TYPE_STRING_AS_STRING,
						&entry);

	for (f = supported_features; f->name; f++) {
		if (manager->supported_features & f->mask) {
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING,
							&f->name);
		}
	}

	dbus_message_iter_close_container(iter, &entry);

	return TRUE;
}

static const GDBusPropertyTable adv_monitor_properties[] = {
	{"SupportedMonitorTypes", "as", get_supported_monitor_types, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL},
	{"SupportedFeatures", "as", get_supported_features, NULL, NULL,
					G_DBUS_PROPERTY_FLAG_EXPERIMENTAL},
	{ }
};

/* Allocates a manager object */
static struct btd_adv_monitor_manager *manager_new(
						struct btd_adapter *adapter,
						struct mgmt *mgmt)
{
	struct btd_adv_monitor_manager *manager;

	if (!adapter || !mgmt)
		return NULL;

	manager = new0(struct btd_adv_monitor_manager, 1);
	if (!manager)
		return NULL;

	manager->adapter = adapter;
	manager->mgmt = mgmt_ref(mgmt);
	manager->adapter_id = btd_adapter_get_index(adapter);
	manager->apps = queue_new();

	return manager;
}

/* Frees a manager object */
static void manager_free(struct btd_adv_monitor_manager *manager)
{
	mgmt_unref(manager->mgmt);

	queue_destroy(manager->apps, app_destroy);

	free(manager);
}

/* Destroys a manager object and unregisters its D-Bus interface */
static void manager_destroy(struct btd_adv_monitor_manager *manager)
{
	if (!manager)
		return;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
					adapter_get_path(manager->adapter),
					ADV_MONITOR_MGR_INTERFACE);

	manager_free(manager);
}

/* Initiates manager's members based on the return of
 * MGMT_OP_READ_ADV_MONITOR_FEATURES
 */
static void read_adv_monitor_features_cb(uint8_t status, uint16_t length,
						const void *param,
						void *user_data)
{
	const struct mgmt_rp_read_adv_monitor_features *rp = param;
	struct btd_adv_monitor_manager *manager = user_data;

	if (status != MGMT_STATUS_SUCCESS || !param) {
		btd_error(manager->adapter_id, "Failed to Read Adv Monitor "
				"Features with status 0x%02x", status);
		return;
	}

	if (length < sizeof(*rp)) {
		btd_error(manager->adapter_id,
				"Wrong size of Read Adv Monitor Features "
				"response");
		return;
	}

	manager->supported_features = le32_to_cpu(rp->supported_features);
	manager->enabled_features = le32_to_cpu(rp->enabled_features);
	manager->max_num_monitors = le16_to_cpu(rp->max_num_handles);
	manager->max_num_patterns = rp->max_num_patterns;

	btd_info(manager->adapter_id, "Adv Monitor Manager created with "
			"supported features:0x%08x, enabled features:0x%08x, "
			"max number of supported monitors:%d, "
			"max number of supported patterns:%d",
			manager->supported_features, manager->enabled_features,
			manager->max_num_monitors, manager->max_num_patterns);
}

/* Creates a manager and registers its D-Bus interface */
struct btd_adv_monitor_manager *btd_adv_monitor_manager_create(
						struct btd_adapter *adapter,
						struct mgmt *mgmt)
{
	struct btd_adv_monitor_manager *manager;

	manager = manager_new(adapter, mgmt);
	if (!manager)
		return NULL;

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					adapter_get_path(manager->adapter),
					ADV_MONITOR_MGR_INTERFACE,
					adv_monitor_methods, NULL,
					adv_monitor_properties, manager,
					NULL)) {
		btd_error(manager->adapter_id,
				"Failed to register "
				ADV_MONITOR_MGR_INTERFACE);
		manager_free(manager);
		return NULL;
	}

	if (!mgmt_send(manager->mgmt, MGMT_OP_READ_ADV_MONITOR_FEATURES,
			manager->adapter_id, 0, NULL,
			read_adv_monitor_features_cb, manager, NULL)) {
		btd_error(manager->adapter_id,
				"Failed to send Read Adv Monitor Features");
		manager_destroy(manager);
		return NULL;
	}

	return manager;
}

/* Destroys a manager and unregisters its D-Bus interface */
void btd_adv_monitor_manager_destroy(struct btd_adv_monitor_manager *manager)
{
	if (!manager)
		return;

	btd_info(manager->adapter_id, "Destroy Adv Monitor Manager");

	manager_destroy(manager);
}
