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

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <glib.h>

#include "gdbus/gdbus.h"
#include "bluetooth/bluetooth.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "cs_distance.h"
#include "dbus-common.h"
#include "adapter.h"
#include "device.h"
#include "log.h"
#include "error.h"

#define CS_DISTANCE_INTERFACE "org.bluez.CSDistance1"
#define CS_DISTANCE_PROVIDER_INTERFACE "org.bluez.CSDistanceProvider1"
#define CS_DISTANCE_PROVIDER_MANAGER_INTERFACE \
	"org.bluez.CSDistanceProviderManager1"

struct btd_cs_distance {
	char *path; /* D-Bus object path */
	double meters; /* Estimated distance to the remote device */
	bool has_value; /* false until the first estimate is reported */
	char *provider_path; /* The provider root path, if any */
};

struct btd_cs_distance_provider_manager {
	struct btd_adapter *adapter; /* Does not own pointer */
	struct queue *providers;
};

struct cs_distance_provider {
	struct btd_cs_distance_provider_manager *manager; /* Does not own */

	char *owner; /* Owner D-Bus address */
	char *path; /* D-Bus object path */

	GDBusClient *client;
};

static struct queue *distances;

static void provider_disconnect_cb(DBusConnection *conn, void *user_data);

static void distance_add(struct btd_cs_distance *distance)
{
	if (!distances)
		distances = queue_new();

	queue_push_head(distances, distance);
}

static void distance_remove(struct btd_cs_distance *distance)
{
	queue_remove(distances, distance);
	if (queue_isempty(distances)) {
		queue_destroy(distances, NULL);
		distances = NULL;
	}
}

static bool match_path(const void *data, const void *user_data)
{
	const struct btd_cs_distance *distance = data;
	const char *path = user_data;

	return g_strcmp0(distance->path, path) == 0;
}

static struct btd_cs_distance *distance_new(const char *path,
					    const char *provider_path)
{
	struct btd_cs_distance *distance;

	distance = new0(struct btd_cs_distance, 1);
	distance->path = g_strdup(path);
	if (provider_path)
		distance->provider_path = g_strdup(provider_path);

	return distance;
}

static void distance_free(struct btd_cs_distance *distance)
{
	if (distance->path)
		g_free(distance->path);

	if (distance->provider_path)
		g_free(distance->provider_path);

	free(distance);
}

static gboolean property_distance_get(const GDBusPropertyTable *property,
				      DBusMessageIter *iter, void *data)
{
	struct btd_cs_distance *distance = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_DOUBLE,
				       &distance->meters);

	return TRUE;
}

static gboolean property_distance_exists(const GDBusPropertyTable *property,
					 void *data)
{
	struct btd_cs_distance *distance = data;

	return distance->has_value;
}

static const GDBusPropertyTable cs_distance_properties[] = {
	{ "DistanceMeters", "d", property_distance_get, NULL,
	  property_distance_exists },
	{}
};

struct btd_cs_distance *btd_cs_distance_register(const char *path,
						 const char *provider_path)
{
	struct btd_cs_distance *distance;

	DBG("path = %s", path);

	if (queue_find(distances, match_path, path)) {
		error("error registering CS distance: path exists");
		return NULL;
	}

	if (!g_str_has_prefix(path, "/")) {
		error("error registering CS distance: "
		      "invalid D-Bus object path");
		return NULL;
	}

	distance = distance_new(path, provider_path);
	distance_add(distance);

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
				       distance->path, CS_DISTANCE_INTERFACE,
				       NULL, NULL, cs_distance_properties,
				       distance, NULL)) {
		error("error registering D-Bus interface for %s",
		      distance->path);

		distance_remove(distance);
		distance_free(distance);

		return NULL;
	}

	DBG("registered CSDistance object: %s", distance->path);

	return distance;
}

bool btd_cs_distance_unregister(struct btd_cs_distance *distance)
{
	DBG("path = %s", distance->path);

	if (!queue_find(distances, NULL, distance)) {
		error("error unregistering CS distance: "
		      "distance %s is not registered",
		      distance->path);
		return false;
	}

	if (!g_dbus_unregister_interface(btd_get_dbus_connection(),
					 distance->path,
					 CS_DISTANCE_INTERFACE)) {
		error("error unregistering CS distance %s from "
		      "D-Bus interface", distance->path);
		return false;
	}

	distance_remove(distance);
	distance_free(distance);

	return true;
}

bool btd_cs_distance_update(struct btd_cs_distance *distance, double meters)
{
	DBG("path = %s", distance->path);

	if (!queue_find(distances, NULL, distance)) {
		error("error updating CS distance: distance is not "
		      "registered");
		return false;
	}

	distance->meters = meters;
	distance->has_value = true;

	info("CS distance updated: path = %s, meters = %f", distance->path,
	     meters);
	fprintf(stderr, "CS distance updated: path = %s, meters = %f\n",
		distance->path, meters);

	g_dbus_emit_property_changed(btd_get_dbus_connection(),
				     distance->path, CS_DISTANCE_INTERFACE,
				     "DistanceMeters");

	return true;
}

static struct btd_cs_distance *find_distance_by_path(const char *path)
{
	return queue_find(distances, match_path, path);
}

static void provided_distance_property_changed_cb(GDBusProxy *proxy,
						   const char *name,
						   DBusMessageIter *iter,
						   void *user_data)
{
	double meters = 0;
	const char *export_path;
	DBusMessageIter dev_iter;

	if (g_dbus_proxy_get_property(proxy, "Device", &dev_iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&dev_iter, &export_path);

	if (strcmp(name, "DistanceMeters") != 0)
		return;

	if (iter) {
		if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_DOUBLE)
			return;

		dbus_message_iter_get_basic(iter, &meters);
	}

	DBG("CS distance changed on %s, meters = %f",
	    g_dbus_proxy_get_path(proxy), meters);

	btd_cs_distance_update(find_distance_by_path(export_path), meters);
}

static void provided_distance_added_cb(GDBusProxy *proxy, void *user_data)
{
	struct cs_distance_provider *provider = user_data;
	struct btd_cs_distance *distance;
	struct btd_device *device;
	const char *path = g_dbus_proxy_get_path(proxy);
	const char *export_path;
	double meters;
	DBusMessageIter iter;

	if (strcmp(g_dbus_proxy_get_interface(proxy),
		   CS_DISTANCE_PROVIDER_INTERFACE) != 0)
		return;

	if (g_dbus_proxy_get_property(proxy, "Device", &iter) == FALSE) {
		warn("CS distance object %s does not specify device path",
		     path);
		return;
	}

	dbus_message_iter_get_basic(&iter, &export_path);

	device = btd_adapter_find_device_by_path(provider->manager->adapter,
						 export_path);
	if (!device || device_is_temporary(device)) {
		warn("Ignoring non-existent device path for CS distance %s",
		     export_path);
		return;
	}

	if (find_distance_by_path(export_path)) {
		DBG("CS distance for %s is already provided, ignoring the "
		    "new one", export_path);
		return;
	}

	g_dbus_proxy_set_property_watch(proxy,
		provided_distance_property_changed_cb, provider);

	distance = btd_cs_distance_register(export_path, provider->path);

	DBG("provided CS distance added %s", path);

	/* DistanceMeters property may not be immediately available, that's
	 * okay since we monitor changes to this property.
	 */
	if (g_dbus_proxy_get_property(proxy, "DistanceMeters", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &meters);

	btd_cs_distance_update(distance, meters);
}

static void provided_distance_removed_cb(GDBusProxy *proxy, void *user_data)
{
	struct cs_distance_provider *provider = user_data;
	struct btd_cs_distance *distance;
	const char *export_path;
	DBusMessageIter iter;

	if (strcmp(g_dbus_proxy_get_interface(proxy),
		   CS_DISTANCE_PROVIDER_INTERFACE) != 0)
		return;

	if (g_dbus_proxy_get_property(proxy, "Device", &iter) == FALSE)
		return;

	dbus_message_iter_get_basic(&iter, &export_path);

	DBG("provided CS distance removed %s", g_dbus_proxy_get_path(proxy));

	distance = find_distance_by_path(export_path);
	if (!distance)
		return;

	if (g_strcmp0(distance->provider_path, provider->path) != 0)
		return;

	g_dbus_proxy_set_property_watch(proxy, NULL, NULL);

	btd_cs_distance_unregister(distance);
}

static bool match_provider_path(const void *data, const void *user_data)
{
	const struct cs_distance_provider *provider = data;
	const char *path = user_data;

	return strcmp(provider->path, path) == 0;
}

static void unregister_if_path_has_prefix(void *data, void *user_data)
{
	struct btd_cs_distance *distance = data;
	struct cs_distance_provider *provider = user_data;

	if (g_strcmp0(distance->provider_path, provider->path) == 0)
		btd_cs_distance_unregister(distance);
}

static void cs_distance_provider_free(gpointer data)
{
	struct cs_distance_provider *provider = data;

	/* Unregister distances under the root path of provider->path */
	queue_foreach(distances, unregister_if_path_has_prefix, provider);

	if (provider->owner)
		g_free(provider->owner);

	if (provider->path)
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

static struct cs_distance_provider *
cs_distance_provider_new(DBusConnection *conn,
			 struct btd_cs_distance_provider_manager *manager,
			 const char *path, const char *sender)
{
	struct cs_distance_provider *provider;

	provider = new0(struct cs_distance_provider, 1);
	provider->manager = manager;
	provider->owner = g_strdup(sender);
	provider->path = g_strdup(path);

	provider->client = g_dbus_client_new_full(conn, sender, path, path);

	if (!provider->client) {
		error("error creating D-Bus client %s", path);
		cs_distance_provider_free(provider);
		return NULL;
	}

	g_dbus_client_set_disconnect_watch(provider->client,
					   provider_disconnect_cb, provider);

	g_dbus_client_set_proxy_handlers(provider->client,
					 provided_distance_added_cb,
					 provided_distance_removed_cb, NULL,
					 provider);

	return provider;
}

static void provider_disconnect_cb(DBusConnection *conn, void *user_data)
{
	struct cs_distance_provider *provider = user_data;
	struct btd_cs_distance_provider_manager *manager = provider->manager;

	DBG("CS distance provider client disconnected %s root path %s",
	    provider->owner, provider->path);

	if (!queue_find(manager->providers, NULL, provider)) {
		warn("Disconnection on a non-existing provider %s",
		     provider->path);
		return;
	}

	queue_remove(manager->providers, provider);
	cs_distance_provider_free(provider);
}

static DBusMessage *register_distance_provider(DBusConnection *conn,
						DBusMessage *msg,
						void *user_data)
{
	struct btd_cs_distance_provider_manager *manager = user_data;
	const char *sender = dbus_message_get_sender(msg);
	DBusMessageIter args;
	const char *path;
	struct cs_distance_provider *provider;

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &path);

	DBG("register CS distance provider path = %s", path);

	if (!g_str_has_prefix(path, "/"))
		return btd_error_invalid_args(msg);

	if (queue_find(manager->providers, match_provider_path, path)) {
		return dbus_message_new_error(msg,
					      ERROR_INTERFACE ".AlreadyExists",
					      "Provider already exists");
	}

	provider = cs_distance_provider_new(conn, manager, path, sender);
	queue_push_head(manager->providers, provider);

	return dbus_message_new_method_return(msg);
}

static DBusMessage *unregister_distance_provider(DBusConnection *conn,
						  DBusMessage *msg,
						  void *user_data)
{
	struct btd_cs_distance_provider_manager *manager = user_data;
	const char *sender = dbus_message_get_sender(msg);
	DBusMessageIter args;
	const char *path;
	struct cs_distance_provider *provider;

	if (!dbus_message_iter_init(msg, &args))
		return btd_error_invalid_args(msg);

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH)
		return btd_error_invalid_args(msg);

	dbus_message_iter_get_basic(&args, &path);

	DBG("unregister CS distance provider path = %s", path);

	provider = queue_find(manager->providers, match_provider_path, path);
	if (!provider || strcmp(provider->owner, sender) != 0) {
		return dbus_message_new_error(msg,
					      ERROR_INTERFACE ".DoesNotExist",
					      "Provider does not exist");
	}

	queue_remove(manager->providers, provider);
	cs_distance_provider_free(provider);

	return dbus_message_new_method_return(msg);
}

static const GDBusMethodTable methods[] = {
	{ GDBUS_METHOD("RegisterDistanceProvider",
				    GDBUS_ARGS({ "provider", "o" }), NULL,
				    register_distance_provider) },
	{ GDBUS_METHOD("UnregisterDistanceProvider",
				    GDBUS_ARGS({ "provider", "o" }), NULL,
				    unregister_distance_provider) },
	{}
};

static struct btd_cs_distance_provider_manager *
manager_new(struct btd_adapter *adapter)
{
	struct btd_cs_distance_provider_manager *manager;

	DBG("");

	manager = new0(struct btd_cs_distance_provider_manager, 1);
	manager->adapter = adapter;
	manager->providers = queue_new();

	return manager;
}

static void manager_free(struct btd_cs_distance_provider_manager *manager)
{
	if (!manager)
		return;

	DBG("");

	queue_destroy(manager->providers, cs_distance_provider_free);

	free(manager);
}

struct btd_cs_distance_provider_manager *
btd_cs_distance_provider_manager_create(struct btd_adapter *adapter)
{
	struct btd_cs_distance_provider_manager *manager;

	if (!adapter)
		return NULL;

	manager = manager_new(adapter);
	if (!manager)
		return NULL;

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
				       adapter_get_path(manager->adapter),
				       CS_DISTANCE_PROVIDER_MANAGER_INTERFACE,
				       methods, NULL, NULL, manager, NULL)) {
		error("error registering "
		      CS_DISTANCE_PROVIDER_MANAGER_INTERFACE " interface");
		manager_free(manager);
		return NULL;
	}

	info("CS Distance Provider Manager created");

	return manager;
}

void btd_cs_distance_provider_manager_destroy(struct
	btd_cs_distance_provider_manager *manager)
{
	if (!manager)
		return;

	g_dbus_unregister_interface(btd_get_dbus_connection(),
				    adapter_get_path(manager->adapter),
				    CS_DISTANCE_PROVIDER_MANAGER_INTERFACE);

	info("CS Distance Provider Manager destroyed");

	manager_free(manager);
}
