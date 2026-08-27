// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

#include "gdbus/gdbus.h"
#include "bluetooth/bluetooth.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "ranging.h"
#include "dbus-common.h"
#include "adapter.h"
#include "device.h"
#include "log.h"
#include "error.h"

#define RANGING_INTERFACE "org.bluez.Ranging1"
#define RANGING_PROVIDER_INTERFACE "org.bluez.RangingProvider1"
#define RANGING_PROVIDER_MANAGER_INTERFACE \
	"org.bluez.RangingProviderManager1"

struct btd_ranging {
	struct btd_ranging_provider_manager *manager; /* Does not own pointer */
	char *path; /* D-Bus object path */
	uint32_t distance_millimeters; /* Estimated distance to remote device */
	bool has_value; /* false until the first estimate is reported */
	char *provider_path; /* The provider root path, if any */
};

struct btd_ranging_provider_manager {
	struct btd_adapter *adapter; /* Does not own pointer */
	struct queue *providers;
	struct queue *rangings;
};

struct ranging_provider {
	struct btd_ranging_provider_manager *manager; /* Does not own */

	char *owner; /* Owner D-Bus address */
	char *path; /* D-Bus object path */

	GDBusClient *client;
};

static void provider_disconnect_cb(DBusConnection *conn, void *user_data);

static void ranging_add(struct btd_ranging *ranging)
{
	queue_push_head(ranging->manager->rangings, ranging);
}

static void ranging_remove(struct btd_ranging *ranging)
{
	queue_remove(ranging->manager->rangings, ranging);
}

static bool match_path(const void *data, const void *user_data)
{
	const struct btd_ranging *ranging = data;
	const char *path = user_data;

	return g_strcmp0(ranging->path, path) == 0;
}

static struct btd_ranging *ranging_new(
	struct btd_ranging_provider_manager *manager,
	const char *path, const char *provider_path)
{
	struct btd_ranging *ranging;

	ranging = new0(struct btd_ranging, 1);
	ranging->manager = manager;
	ranging->path = g_strdup(path);
	if (provider_path)
		ranging->provider_path = g_strdup(provider_path);

	return ranging;
}

static void ranging_free(struct btd_ranging *ranging)
{
	g_free(ranging->path);
	g_free(ranging->provider_path);

	free(ranging);
}

static gboolean property_distance_get(const GDBusPropertyTable *property,
				      DBusMessageIter *iter, void *data)
{
	struct btd_ranging *ranging = data;

	return dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
					      &ranging->distance_millimeters);
}

static gboolean property_distance_exists(const GDBusPropertyTable *property,
					 void *data)
{
	struct btd_ranging *ranging = data;

	return ranging->has_value;
}

static const GDBusPropertyTable ranging_properties[] = {
	{ "Distance", "u", property_distance_get, NULL,
	  property_distance_exists },
	{}
};

static struct btd_ranging *btd_ranging_register(
	struct btd_ranging_provider_manager *manager,
	const char *path, const char *provider_path)
{
	struct btd_ranging *ranging;

	DBG("path = %s", path);

	if (queue_find(manager->rangings, match_path, path)) {
		error("error registering ranging: path exists");
		return NULL;
	}

	if (!g_str_has_prefix(path, "/")) {
		error("error registering ranging: "
		      "invalid D-Bus object path");
		return NULL;
	}

	ranging = ranging_new(manager, path, provider_path);
	ranging_add(ranging);

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
				       ranging->path, RANGING_INTERFACE,
				       NULL, NULL, ranging_properties,
				       ranging, NULL)) {
		error("error registering D-Bus interface for %s",
		      ranging->path);

		ranging_remove(ranging);
		ranging_free(ranging);

		return NULL;
	}

	DBG("registered Ranging object: %s", ranging->path);

	return ranging;
}

static bool btd_ranging_unregister(struct btd_ranging *ranging)
{
	bool ret = true;

	DBG("path = %s", ranging->path);

	if (!queue_find(ranging->manager->rangings, NULL, ranging)) {
		error("error unregistering ranging: "
		      "ranging %s is not registered",
		      ranging->path);
		return false;
	}

	if (!g_dbus_unregister_interface(btd_get_dbus_connection(),
					 ranging->path,
					 RANGING_INTERFACE)) {
		error("error unregistering ranging %s from "
		      "D-Bus interface", ranging->path);
		ret = false;
	}

	ranging_remove(ranging);
	ranging_free(ranging);

	return ret;
}

static bool btd_ranging_update(struct btd_ranging *ranging,
	uint32_t distance_millimeters)
{
	DBG("path = %s", ranging->path);

	if (!queue_find(ranging->manager->rangings, NULL, ranging)) {
		error("error updating ranging: ranging is not "
		      "registered");
		return false;
	}

	ranging->distance_millimeters = distance_millimeters;
	ranging->has_value = true;

	DBG("Ranging distance updated: path = %s, millimeters = %u",
	     ranging->path, distance_millimeters);

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				     ranging->path, RANGING_INTERFACE,
				     "Distance");

	return true;
}

static struct btd_ranging *find_ranging_by_path(
	struct btd_ranging_provider_manager *manager, const char *path)
{
	return queue_find(manager->rangings, match_path, path);
}

static void provider_distance_property_changed_cb(GDBusProxy *proxy,
						   const char *name,
						   DBusMessageIter *iter,
						   void *user_data)
{
	struct ranging_provider *provider = user_data;
	struct btd_ranging *ranging;
	uint32_t distance_millimeters;
	const char *export_path;
	const char *path = g_dbus_proxy_get_path(proxy);
	DBusMessageIter dev_iter;

	if (strcmp(name, "Distance") != 0)
		return;

	/* A NULL iter means the provider invalidated Distance rather than
	 * reporting a new estimate. There is no value to publish, so leave
	 * the last one in place instead of reporting a bogus 0 mm.
	 */
	if (!iter) {
		DBG("Distance invalidated on %s, keeping last estimate", path);
		return;
	}

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT32) {
		warn("Ignoring Distance update on %s: "
		     "expected type uint32", path);
		return;
	}

	dbus_message_iter_get_basic(iter, &distance_millimeters);

	if (g_dbus_proxy_get_property(proxy, "Device", &dev_iter) == FALSE) {
		warn("Ignoring Distance update on %s: "
		     "no Device property", path);
		return;
	}

	if (dbus_message_iter_get_arg_type(&dev_iter) !=
			DBUS_TYPE_OBJECT_PATH) {
		warn("Ignoring Distance update on %s: "
		     "invalid Device property type", path);
		return;
	}

	dbus_message_iter_get_basic(&dev_iter, &export_path);

	DBG("Ranging distance changed on %s, millimeters = %u",
	    path, distance_millimeters);

	ranging = find_ranging_by_path(provider->manager, export_path);
	if (!ranging)
		return;

	btd_ranging_update(ranging, distance_millimeters);
}

/* Check that path is root itself or sits below it, so that a provider
 * rooted at /org/example does not claim /org/example_other.
 */
static bool path_has_root(const char *path, const char *root)
{
	size_t len;

	if (!g_str_has_prefix(path, root))
		return false;

	/* "/" is the root of every valid object path */
	if (!strcmp(root, "/"))
		return true;

	len = strlen(root);

	return path[len] == '\0' || path[len] == '/';
}

static void provider_distance_added_cb(GDBusProxy *proxy, void *user_data)
{
	struct ranging_provider *provider = user_data;
	struct btd_ranging *ranging;
	struct btd_device *device;
	const char *path = g_dbus_proxy_get_path(proxy);
	const char *export_path;
	uint32_t distance_millimeters;
	DBusMessageIter iter;

	if (strcmp(g_dbus_proxy_get_interface(proxy),
		   RANGING_PROVIDER_INTERFACE) != 0)
		return;

	if (!path_has_root(path, provider->path)) {
		warn("Ignoring ranging object %s outside provider root %s",
		     path, provider->path);
		return;
	}

	if (g_dbus_proxy_get_property(proxy, "Device", &iter) == FALSE) {
		warn("Ranging object %s does not specify device path",
		     path);
		return;
	}

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH) {
		warn("Ranging object %s has invalid Device property type",
		     path);
		return;
	}

	dbus_message_iter_get_basic(&iter, &export_path);

	device = btd_adapter_find_device_by_path(provider->manager->adapter,
						 export_path);
	if (!device || device_is_temporary(device)) {
		warn("Ignoring non-existent device path for ranging %s",
		     export_path);
		return;
	}

	if (find_ranging_by_path(provider->manager, export_path)) {
		DBG("Ranging for %s is already provided, ignoring the "
		    "new one", export_path);
		return;
	}

	ranging = btd_ranging_register(provider->manager, export_path,
					provider->path);
	if (!ranging)
		return;

	g_dbus_proxy_set_property_watch(proxy,
		provider_distance_property_changed_cb, provider);

	DBG("provided ranging added %s", path);

	/* Distance property may not be immediately available,
	 * that's okay since we monitor changes to this property.
	 */
	if (g_dbus_proxy_get_property(proxy, "Distance",
				      &iter) == FALSE)
		return;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
		warn("Ignoring Distance property on %s: "
		     "expected type uint32", path);
		return;
	}

	dbus_message_iter_get_basic(&iter, &distance_millimeters);

	btd_ranging_update(ranging, distance_millimeters);
}

static void provider_distance_removed_cb(GDBusProxy *proxy, void *user_data)
{
	struct ranging_provider *provider = user_data;
	struct btd_ranging *ranging;
	const char *export_path;
	DBusMessageIter iter;

	if (strcmp(g_dbus_proxy_get_interface(proxy),
		   RANGING_PROVIDER_INTERFACE) != 0)
		return;

	if (g_dbus_proxy_get_property(proxy, "Device", &iter) == FALSE)
		return;

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_OBJECT_PATH)
		return;

	dbus_message_iter_get_basic(&iter, &export_path);

	DBG("provided ranging removed %s", g_dbus_proxy_get_path(proxy));

	ranging = find_ranging_by_path(provider->manager, export_path);
	if (!ranging)
		return;

	if (g_strcmp0(ranging->provider_path, provider->path) != 0)
		return;

	g_dbus_proxy_set_property_watch(proxy, NULL, NULL);

	btd_ranging_unregister(ranging);
}

static bool match_provider_path(const void *data, const void *user_data)
{
	const struct ranging_provider *provider = data;
	const char *path = user_data;

	return strcmp(provider->path, path) == 0;
}

static bool match_ranging_provider_path(const void *data,
					const void *user_data)
{
	const struct btd_ranging *ranging = data;
	const struct ranging_provider *provider = user_data;

	return g_strcmp0(ranging->provider_path, provider->path) == 0;
}

static void ranging_destroy(void *data)
{
	struct btd_ranging *ranging = data;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
				    ranging->path, RANGING_INTERFACE);
	ranging_free(ranging);
}

static void ranging_destroy_warn(void *data)
{
	struct btd_ranging *ranging = data;

	warn("Ranging %s still registered at manager destroy",
	     ranging->path);

	ranging_destroy(data);
}

void btd_ranging_provider_manager_device_removed(
	struct btd_ranging_provider_manager *manager,
	struct btd_device *device)
{
	struct btd_ranging *ranging;
	const char *path;

	if (!manager || !device)
		return;

	path = device_get_path(device);

	ranging = queue_find(manager->rangings, match_path, path);
	if (!ranging)
		return;

	/* The device object is going away, so drop the Ranging interface
	 * with it. Leaving it behind would keep the object path alive on
	 * the bus with nothing but Ranging on it, and would make a later
	 * re-registration for the same device fail as already present.
	 */
	DBG("removing ranging for departing device %s", path);

	queue_remove(manager->rangings, ranging);
	ranging_destroy(ranging);
}

static void ranging_provider_free(gpointer data)
{
	struct ranging_provider *provider = data;

	/* Unregister rangings under the root path of provider->path */
	queue_remove_all(provider->manager->rangings,
			 match_ranging_provider_path, provider,
			 ranging_destroy);

	g_free(provider->owner);
	g_free(provider->path);

	if (provider->client) {
		g_dbus_client_set_disconnect_watch(provider->client, NULL,
						   NULL);
		g_dbus_client_set_proxy_handlers(provider->client, NULL, NULL,
						 NULL, NULL);
		g_dbus_client_unref(provider->client);
	}

	free(provider);
}

static struct ranging_provider *
ranging_provider_new(DBusConnection *conn,
		     struct btd_ranging_provider_manager *manager,
		     const char *path, const char *sender)
{
	struct ranging_provider *provider;

	provider = new0(struct ranging_provider, 1);
	provider->manager = manager;
	provider->owner = g_strdup(sender);
	provider->path = g_strdup(path);

	provider->client = g_dbus_client_new_full(conn, sender, path, path);

	if (!provider->client) {
		error("error creating D-Bus client %s", path);
		ranging_provider_free(provider);
		return NULL;
	}

	g_dbus_client_set_disconnect_watch(provider->client,
					   provider_disconnect_cb, provider);

	g_dbus_client_set_proxy_handlers(provider->client,
					 provider_distance_added_cb,
					 provider_distance_removed_cb, NULL,
					 provider);

	return provider;
}

static void provider_disconnect_cb(DBusConnection *conn, void *user_data)
{
	struct ranging_provider *provider = user_data;
	struct btd_ranging_provider_manager *manager = provider->manager;

	DBG("Ranging provider client disconnected %s root path %s",
	    provider->owner, provider->path);

	if (!queue_find(manager->providers, NULL, provider)) {
		warn("Disconnection on a non-existing provider %s",
		     provider->path);
		return;
	}

	queue_remove(manager->providers, provider);
	ranging_provider_free(provider);
}

static DBusMessage *register_ranging_provider(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	struct btd_ranging_provider_manager *manager = user_data;
	const char *sender = dbus_message_get_sender(msg);
	DBusMessageIter args;
	const char *path;
	struct ranging_provider *provider;

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &path);

	DBG("register ranging provider path = %s", path);

	if (!g_str_has_prefix(path, "/"))
		return btd_error_invalid_args(msg);

	/* Only one ranging provider may be registered at a time: allowing
	 * concurrent providers means whichever claims a device first wins,
	 * silently locking out any other provider for that device. Reject
	 * up front instead, with a clear error, regardless of which side
	 * (bluetoothctl's reference provider or a real ranging daemon)
	 * registered first.
	 */
	if (!queue_isempty(manager->providers)) {
		return dbus_message_new_error(msg,
					      ERROR_INTERFACE ".AlreadyExists",
					      "Provider already exists");
	}

	provider = ranging_provider_new(conn, manager, path, sender);
	if (!provider)
		return btd_error_failed(msg, "failed to create provider");

	queue_push_head(manager->providers, provider);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_ranging_provider(DBusConnection *conn,
						  DBusMessage *msg,
						  void *user_data)
{
	struct btd_ranging_provider_manager *manager = user_data;
	const char *sender = dbus_message_get_sender(msg);
	DBusMessageIter args;
	const char *path;
	struct ranging_provider *provider;

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &path);

	DBG("unregister ranging provider path = %s", path);

	provider = queue_find(manager->providers, match_provider_path, path);
	if (!provider || strcmp(provider->owner, sender) != 0) {
		return dbus_message_new_error(msg,
					      ERROR_INTERFACE ".DoesNotExist",
					      "Provider does not exist");
	}

	queue_remove(manager->providers, provider);
	ranging_provider_free(provider);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_METHOD("RegisterRangingProvider",
				    GDBUS_ARGS({ "provider", "o" }), NULL,
				    register_ranging_provider) },
	{ GDBUS_METHOD("UnregisterRangingProvider",
				    GDBUS_ARGS({ "provider", "o" }), NULL,
				    unregister_ranging_provider) },
	{}
};

static struct btd_ranging_provider_manager *
manager_new(struct btd_adapter *adapter)
{
	struct btd_ranging_provider_manager *manager;

	DBG("");

	manager = new0(struct btd_ranging_provider_manager, 1);
	manager->adapter = adapter;
	manager->providers = queue_new();
	manager->rangings = queue_new();

	return manager;
}

static void manager_free(struct btd_ranging_provider_manager *manager)
{
	if (!manager)
		return;

	DBG("");

	queue_destroy(manager->providers, ranging_provider_free);
	queue_destroy(manager->rangings, ranging_destroy_warn);

	free(manager);
}

struct btd_ranging_provider_manager *
btd_ranging_provider_manager_create(struct btd_adapter *adapter)
{
	struct btd_ranging_provider_manager *manager;

	if (!adapter)
		return NULL;

	manager = manager_new(adapter);
	if (!manager)
		return NULL;

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
				       adapter_get_path(manager->adapter),
				       RANGING_PROVIDER_MANAGER_INTERFACE,
				       methods, NULL, NULL, manager, NULL)) {
		error("error registering "
		      RANGING_PROVIDER_MANAGER_INTERFACE " interface");
		manager_free(manager);
		return NULL;
	}

	info("Ranging Provider Manager created");

	return manager;
}

void btd_ranging_provider_manager_destroy(
	struct btd_ranging_provider_manager *manager)
{
	if (!manager)
		return;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
				    adapter_get_path(manager->adapter),
				    RANGING_PROVIDER_MANAGER_INTERFACE);

	info("Ranging Provider Manager destroyed");

	manager_free(manager);
}
