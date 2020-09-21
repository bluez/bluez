// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020 Google LLC
 *
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
#include "src/shared/ad.h"
#include "src/shared/mgmt.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"

#include "adv_monitor.h"

#define ADV_MONITOR_INTERFACE		"org.bluez.AdvertisementMonitor1"
#define ADV_MONITOR_MGR_INTERFACE	"org.bluez.AdvertisementMonitorManager1"

#define ADV_MONITOR_UNSET_RSSI		127	/* dBm */
#define ADV_MONITOR_MAX_RSSI		20	/* dBm */
#define ADV_MONITOR_MIN_RSSI		-127	/* dBm */
#define ADV_MONITOR_UNSET_TIMER		0	/* second */
#define ADV_MONITOR_MIN_TIMER		1	/* second */
#define ADV_MONITOR_MAX_TIMER		300	/* second */

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

	struct queue *monitors;
};

enum monitor_type {
	MONITOR_TYPE_NONE,
	MONITOR_TYPE_OR_PATTERNS,
};

enum monitor_state {
	MONITOR_STATE_NEW,	/* New but not yet init'ed with actual values */
	MONITOR_STATE_FAILED,	/* Failed to be init'ed */
	MONITOR_STATE_INITED,	/* Init'ed but not yet sent to kernel */
	MONITOR_STATE_HONORED,	/* Accepted by kernel */
};

struct pattern {
	uint8_t ad_type;
	uint8_t offset;
	uint8_t length;
	uint8_t value[BT_AD_MAX_DATA_LEN];
};

struct adv_monitor {
	struct adv_monitor_app *app;
	GDBusProxy *proxy;
	char *path;

	enum monitor_state state;	/* MONITOR_STATE_* */

	int8_t high_rssi;		/* high RSSI threshold */
	uint16_t high_rssi_timeout;	/* high RSSI threshold timeout */
	int8_t low_rssi;		/* low RSSI threshold */
	uint16_t low_rssi_timeout;	/* low RSSI threshold timeout */

	enum monitor_type type;		/* MONITOR_TYPE_* */
	struct queue *patterns;
};

struct app_match_data {
	const char *owner;
	const char *path;
};

const struct adv_monitor_type {
	enum monitor_type type;
	const char *name;
} supported_types[] = {
	{ MONITOR_TYPE_OR_PATTERNS, "or_patterns" },
	{ },
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

/* Frees a pattern */
static void pattern_free(void *data)
{
	struct pattern *pattern = data;

	if (!pattern)
		return;

	free(pattern);
}

/* Frees a monitor object */
static void monitor_free(void *data)
{
	struct adv_monitor *monitor = data;

	if (!monitor)
		return;

	g_dbus_proxy_unref(monitor->proxy);
	g_free(monitor->path);

	queue_destroy(monitor->patterns, pattern_free);

	free(monitor);
}

/* Calls Release() method of the remote Adv Monitor */
static void monitor_release(void *data, void *user_data)
{
	struct adv_monitor *monitor = data;

	if (!monitor)
		return;

	DBG("Calling Release() on Adv Monitor of owner %s at path %s",
		monitor->app->owner, monitor->path);

	g_dbus_proxy_method_call(monitor->proxy, "Release", NULL, NULL, NULL,
					NULL);
}

/* Destroys an app object along with related D-Bus handlers */
static void app_destroy(void *data)
{
	struct adv_monitor_app *app = data;

	if (!app)
		return;

	DBG("Destroy Adv Monitor app %s at path %s", app->owner, app->path);

	queue_foreach(app->monitors, monitor_release, NULL);
	queue_destroy(app->monitors, monitor_free);

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

/* Handles the ready signal of Adv Monitor app */
static void app_ready_cb(GDBusClient *client, void *user_data)
{
	struct adv_monitor_app *app = user_data;
	uint16_t adapter_id = app->manager->adapter_id;

	btd_info(adapter_id, "Path %s reserved for Adv Monitor app %s",
			app->path, app->owner);

	app_reply_msg(app, dbus_message_new_method_return(app->reg));
}

/* Allocates an Adv Monitor */
static struct adv_monitor *monitor_new(struct adv_monitor_app *app,
						GDBusProxy *proxy)
{
	struct adv_monitor *monitor;

	if (!app || !proxy)
		return NULL;

	monitor = new0(struct adv_monitor, 1);
	if (!monitor)
		return NULL;

	monitor->app = app;
	monitor->proxy = g_dbus_proxy_ref(proxy);
	monitor->path = g_strdup(g_dbus_proxy_get_path(proxy));

	monitor->state = MONITOR_STATE_NEW;

	monitor->high_rssi = ADV_MONITOR_UNSET_RSSI;
	monitor->high_rssi_timeout = ADV_MONITOR_UNSET_TIMER;
	monitor->low_rssi = ADV_MONITOR_UNSET_RSSI;
	monitor->low_rssi_timeout = ADV_MONITOR_UNSET_TIMER;

	monitor->type = MONITOR_TYPE_NONE;
	monitor->patterns = NULL;

	return monitor;
}

/* Matches a monitor based on its D-Bus path */
static bool monitor_match(const void *a, const void *b)
{
	const GDBusProxy *proxy = b;
	const struct adv_monitor *monitor = a;

	if (!proxy || !monitor)
		return false;

	if (g_strcmp0(g_dbus_proxy_get_path(proxy), monitor->path) != 0)
		return false;

	return true;
}

/* Retrieves Type from the remote Adv Monitor object, verifies the value and
 * update the local Adv Monitor
 */
static bool parse_monitor_type(struct adv_monitor *monitor, const char *path)
{
	DBusMessageIter iter;
	const struct adv_monitor_type *t;
	const char *type_str;
	uint16_t adapter_id = monitor->app->manager->adapter_id;

	if (!g_dbus_proxy_get_property(monitor->proxy, "Type", &iter)) {
		btd_error(adapter_id, "Failed to retrieve property Type from "
			"the Adv Monitor at path %s", path);
		return false;
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		goto failed;

	dbus_message_iter_get_basic(&iter, &type_str);

	for (t = supported_types; t->name; t++) {
		if (strcmp(t->name, type_str) == 0) {
			monitor->type = t->type;
			return true;
		}
	}

failed:
	btd_error(adapter_id, "Invalid argument of property Type of the Adv "
			"Monitor at path %s", path);

	return false;
}

/* Retrieves RSSIThresholdsAndTimers from the remote Adv Monitor object,
 * verifies the values and update the local Adv Monitor
 */
static bool parse_rssi_and_timeout(struct adv_monitor *monitor,
					const char *path)
{
	DBusMessageIter prop_struct, iter;
	int16_t h_rssi, l_rssi;
	uint16_t h_rssi_timer, l_rssi_timer;
	uint16_t adapter_id = monitor->app->manager->adapter_id;

	/* Property RSSIThresholdsAndTimers is optional */
	if (!g_dbus_proxy_get_property(monitor->proxy,
					"RSSIThresholdsAndTimers",
					&prop_struct)) {
		DBG("Adv Monitor at path %s provides no RSSI thresholds and "
			"timeouts", path);
		return true;
	}

	if (dbus_message_iter_get_arg_type(&prop_struct) != DBUS_TYPE_STRUCT)
		goto failed;

	dbus_message_iter_recurse(&prop_struct, &iter);

	/* Extract HighRSSIThreshold */
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT16)
		goto failed;
	dbus_message_iter_get_basic(&iter, &h_rssi);
	if (!dbus_message_iter_next(&iter))
		goto failed;

	/* Extract HighRSSIThresholdTimer */
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT16)
		goto failed;
	dbus_message_iter_get_basic(&iter, &h_rssi_timer);
	if (!dbus_message_iter_next(&iter))
		goto failed;

	/* Extract LowRSSIThreshold */
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT16)
		goto failed;
	dbus_message_iter_get_basic(&iter, &l_rssi);
	if (!dbus_message_iter_next(&iter))
		goto failed;

	/* Extract LowRSSIThresholdTimer */
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT16)
		goto failed;
	dbus_message_iter_get_basic(&iter, &l_rssi_timer);

	/* Verify the values of RSSIs and their timers. For simplicity, we
	 * enforce the all-or-none rule to these fields. In other words, either
	 * all are set to the unset values or all are set within valid ranges.
	 */
	if (h_rssi == ADV_MONITOR_UNSET_RSSI &&
		l_rssi == ADV_MONITOR_UNSET_RSSI &&
		h_rssi_timer == ADV_MONITOR_UNSET_TIMER &&
		l_rssi_timer == ADV_MONITOR_UNSET_TIMER) {
		goto done;
	}

	if (h_rssi < ADV_MONITOR_MIN_RSSI || h_rssi > ADV_MONITOR_MAX_RSSI ||
		l_rssi < ADV_MONITOR_MIN_RSSI ||
		l_rssi > ADV_MONITOR_MAX_RSSI || h_rssi <= l_rssi) {
		goto failed;
	}

	if (h_rssi_timer < ADV_MONITOR_MIN_TIMER ||
		h_rssi_timer > ADV_MONITOR_MAX_TIMER ||
		l_rssi_timer < ADV_MONITOR_MIN_TIMER ||
		l_rssi_timer > ADV_MONITOR_MAX_TIMER) {
		goto failed;
	}

	monitor->high_rssi = h_rssi;
	monitor->low_rssi = l_rssi;
	monitor->high_rssi_timeout = h_rssi_timer;
	monitor->low_rssi_timeout = l_rssi_timer;

done:
	DBG("Adv Monitor at %s initiated with high RSSI threshold %d, high "
		"RSSI threshold timeout %d, low RSSI threshold %d, low RSSI "
		"threshold timeout %d", path, monitor->high_rssi,
		monitor->high_rssi_timeout, monitor->low_rssi,
		monitor->low_rssi_timeout);

	return true;

failed:
	monitor->high_rssi = ADV_MONITOR_UNSET_RSSI;
	monitor->low_rssi = ADV_MONITOR_UNSET_RSSI;
	monitor->high_rssi_timeout = ADV_MONITOR_UNSET_TIMER;
	monitor->low_rssi_timeout = ADV_MONITOR_UNSET_TIMER;

	btd_error(adapter_id, "Invalid argument of property "
			"RSSIThresholdsAndTimers of the Adv Monitor at path %s",
			path);

	return false;
}

/* Retrieves Patterns from the remote Adv Monitor object, verifies the values
 * and update the local Adv Monitor
 */
static bool parse_patterns(struct adv_monitor *monitor, const char *path)
{
	DBusMessageIter array, array_iter;
	uint16_t adapter_id = monitor->app->manager->adapter_id;

	if (!g_dbus_proxy_get_property(monitor->proxy, "Patterns", &array)) {
		btd_error(adapter_id, "Failed to retrieve property Patterns "
				"from the Adv Monitor at path %s", path);
		return false;
	}

	monitor->patterns = queue_new();

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY ||
		dbus_message_iter_get_element_type(&array) !=
		DBUS_TYPE_STRUCT) {
		goto failed;
	}

	dbus_message_iter_recurse(&array, &array_iter);

	while (dbus_message_iter_get_arg_type(&array_iter) ==
		DBUS_TYPE_STRUCT) {
		int value_len;
		uint8_t *value;
		uint8_t offset, ad_type;
		struct pattern *pattern;
		DBusMessageIter struct_iter, value_iter;

		dbus_message_iter_recurse(&array_iter, &struct_iter);

		// Extract start position
		if (dbus_message_iter_get_arg_type(&struct_iter) !=
			DBUS_TYPE_BYTE) {
			goto failed;
		}
		dbus_message_iter_get_basic(&struct_iter, &offset);
		if (!dbus_message_iter_next(&struct_iter))
			goto failed;

		// Extract AD data type
		if (dbus_message_iter_get_arg_type(&struct_iter) !=
			DBUS_TYPE_BYTE) {
			goto failed;
		}
		dbus_message_iter_get_basic(&struct_iter, &ad_type);
		if (!dbus_message_iter_next(&struct_iter))
			goto failed;

		// Extract value of a pattern
		if (dbus_message_iter_get_arg_type(&struct_iter) !=
			DBUS_TYPE_ARRAY) {
			goto failed;
		}
		dbus_message_iter_recurse(&struct_iter, &value_iter);
		dbus_message_iter_get_fixed_array(&value_iter, &value,
							&value_len);

		// Verify the values
		if (offset > BT_AD_MAX_DATA_LEN - 1)
			goto failed;

		if ((ad_type > BT_AD_3D_INFO_DATA &&
			ad_type != BT_AD_MANUFACTURER_DATA) ||
			ad_type < BT_AD_FLAGS) {
			goto failed;
		}

		if (!value || value_len <= 0 || value_len > BT_AD_MAX_DATA_LEN)
			goto failed;

		pattern = new0(struct pattern, 1);
		if (!pattern)
			goto failed;

		pattern->ad_type = ad_type;
		pattern->offset = offset;
		pattern->length = value_len;
		memcpy(pattern->value, value, pattern->length);

		queue_push_tail(monitor->patterns, pattern);

		dbus_message_iter_next(&array_iter);
	}

	/* There must be at least one pattern. */
	if (queue_isempty(monitor->patterns))
		goto failed;

	return true;

failed:
	queue_destroy(monitor->patterns, pattern_free);
	monitor->patterns = NULL;

	btd_error(adapter_id, "Invalid argument of property Patterns of the "
			"Adv Monitor at path %s", path);

	return false;
}

/* Processes the content of the remote Adv Monitor */
static bool monitor_process(struct adv_monitor *monitor,
				struct adv_monitor_app *app)
{
	const char *path = g_dbus_proxy_get_path(monitor->proxy);

	monitor->state = MONITOR_STATE_FAILED;

	if (!parse_monitor_type(monitor, path))
		goto done;

	if (!parse_rssi_and_timeout(monitor, path))
		goto done;

	if (monitor->type == MONITOR_TYPE_OR_PATTERNS &&
		parse_patterns(monitor, path)) {
		monitor->state = MONITOR_STATE_INITED;
	}

done:
	return monitor->state != MONITOR_STATE_FAILED;
}

/* Handles an Adv Monitor D-Bus proxy added event */
static void monitor_proxy_added_cb(GDBusProxy *proxy, void *user_data)
{
	struct adv_monitor *monitor;
	struct adv_monitor_app *app = user_data;
	uint16_t adapter_id = app->manager->adapter_id;
	const char *path = g_dbus_proxy_get_path(proxy);
	const char *iface = g_dbus_proxy_get_interface(proxy);

	if (strcmp(iface, ADV_MONITOR_INTERFACE) != 0 ||
		!g_str_has_prefix(path, app->path)) {
		return;
	}

	if (queue_find(app->monitors, monitor_match, proxy)) {
		btd_error(adapter_id, "Adv Monitor proxy already exists with "
				"path %s", path);
		return;
	}

	monitor = monitor_new(app, proxy);
	if (!monitor) {
		btd_error(adapter_id, "Failed to allocate an Adv Monitor for "
				"the object at %s", path);
		return;
	}

	if (!monitor_process(monitor, app)) {
		monitor_release(monitor, NULL);
		monitor_free(monitor);
		DBG("Adv Monitor at path %s released due to invalid content",
			path);
		return;
	}

	queue_push_tail(app->monitors, monitor);

	DBG("Adv Monitor allocated for the object at path %s", path);
}

/* Handles the removal of an Adv Monitor D-Bus proxy */
static void monitor_proxy_removed_cb(GDBusProxy *proxy, void *user_data)
{
	struct adv_monitor *monitor;
	struct adv_monitor_app *app = user_data;

	monitor = queue_remove_if(app->monitors, monitor_match, proxy);
	if (monitor) {
		DBG("Adv Monitor removed for the object at path %s",
			monitor->path);

		/* The object was gone, so we don't need to call Release() */
		monitor_free(monitor);
	}
}

/* Creates an app object, initiates it and sets D-Bus event handlers */
static struct adv_monitor_app *app_create(DBusConnection *conn,
					DBusMessage *msg, const char *sender,
					const char *path,
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

	app->monitors = queue_new();

	g_dbus_client_set_disconnect_watch(app->client, app_disconnect_cb, app);

	/* Note that any property changes on a monitor object would not affect
	 * the content of the corresponding monitor.
	 */
	g_dbus_client_set_proxy_handlers(app->client, monitor_proxy_added_cb,
						monitor_proxy_removed_cb, NULL,
						app);

	g_dbus_client_set_ready_watch(app->client, app_ready_cb, app);

	app->reg = dbus_message_ref(msg);

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

	app = app_create(conn, msg, match.owner, match.path, manager);
	if (!app) {
		btd_error(manager->adapter_id,
				"Failed to reserve %s for Adv Monitor app %s",
				match.path, match.owner);
		return btd_error_failed(msg,
					"Failed to create Adv Monitor app");
	}

	queue_push_tail(manager->apps, app);

	return NULL;
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
