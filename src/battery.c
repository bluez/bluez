// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2020  Google LLC
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <glib.h>

#include "gdbus/gdbus.h"
#include "lib/bluetooth.h"
#include "src/shared/queue.h"
#include "src/shared/util.h"
#include "battery.h"
#include "dbus-common.h"
#include "adapter.h"
#include "log.h"

#define BATTERY_INTERFACE "org.bluez.Battery1"

#define BATTERY_MAX_PERCENTAGE 100

struct btd_battery {
	char *path; /* D-Bus object path */
	uint8_t percentage; /* valid between 0 to 100 inclusively */
	char *source; /* Descriptive source of the battery info */
};

static struct queue *batteries = NULL;

static void battery_add(struct btd_battery *battery)
{
	if (!batteries)
		batteries = queue_new();

	queue_push_head(batteries, battery);
}

static void battery_remove(struct btd_battery *battery)
{
	queue_remove(batteries, battery);
	if (queue_isempty(batteries)) {
		queue_destroy(batteries, NULL);
		batteries = NULL;
	}
}

static bool match_path(const void *data, const void *user_data)
{
	const struct btd_battery *battery = data;
	const char *path = user_data;

	return g_strcmp0(battery->path, path) == 0;
}

static struct btd_battery *battery_new(const char *path, const char *source)
{
	struct btd_battery *battery;

	battery = new0(struct btd_battery, 1);
	battery->path = g_strdup(path);
	battery->percentage = UINT8_MAX;
	if (source)
		battery->source = g_strdup(source);

	return battery;
}

static void battery_free(struct btd_battery *battery)
{
	if (battery->path)
		g_free(battery->path);

	if (battery->source)
		g_free(battery->source);

	free(battery);
}

static gboolean property_percentage_get(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_battery *battery = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BYTE,
				       &battery->percentage);

	return TRUE;
}

static gboolean property_percentage_exists(const GDBusPropertyTable *property,
					   void *data)
{
	struct btd_battery *battery = data;

	return battery->percentage <= BATTERY_MAX_PERCENTAGE;
}

static gboolean property_source_get(const GDBusPropertyTable *property,
				    DBusMessageIter *iter, void *data)
{
	struct btd_battery *battery = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
				       &battery->source);

	return TRUE;
}

static gboolean property_source_exists(const GDBusPropertyTable *property,
				       void *data)
{
	struct btd_battery *battery = data;

	return battery->source != NULL;
}

static const GDBusPropertyTable battery_properties[] = {
	{ "Percentage", "y", property_percentage_get, NULL,
	  property_percentage_exists },
	{ "Source", "s", property_source_get, NULL, property_source_exists,
	  G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{}
};

struct btd_battery *btd_battery_register(const char *path, const char *source)
{
	struct btd_battery *battery;

	DBG("path = %s", path);

	if (queue_find(batteries, match_path, path)) {
		error("error registering battery: path exists");
		return NULL;
	}

	if (!g_str_has_prefix(path, "/")) {
		error("error registering battery: invalid D-Bus object path");
		return NULL;
	}

	battery = battery_new(path, source);
	battery_add(battery);

	if (!g_dbus_register_interface(btd_get_dbus_connection(), battery->path,
				       BATTERY_INTERFACE, NULL, NULL,
				       battery_properties, battery, NULL)) {
		error("error registering D-Bus interface for %s",
		      battery->path);

		battery_remove(battery);
		battery_free(battery);

		return NULL;
	}

	DBG("registered Battery object: %s", battery->path);

	return battery;
}

bool btd_battery_unregister(struct btd_battery *battery)
{
	DBG("path = %s", battery->path);

	if (!queue_find(batteries, NULL, battery)) {
		error("error unregistering battery: "
		      "battery %s is not registered",
		      battery->path);
		return false;
	}

	if (!g_dbus_unregister_interface(btd_get_dbus_connection(),
					 battery->path, BATTERY_INTERFACE)) {
		error("error unregistering battery %s from D-Bus interface",
		      battery->path);
		return false;
	}

	battery_remove(battery);
	battery_free(battery);

	return true;
}

bool btd_battery_update(struct btd_battery *battery, uint8_t percentage)
{
	DBG("path = %s", battery->path);

	if (!queue_find(batteries, NULL, battery)) {
		error("error updating battery: battery is not registered");
		return false;
	}

	if (percentage > BATTERY_MAX_PERCENTAGE) {
		error("error updating battery: percentage is not valid");
		return false;
	}

	if (battery->percentage == percentage)
		return true;

	battery->percentage = percentage;
	g_dbus_emit_property_changed(btd_get_dbus_connection(), battery->path,
				     BATTERY_INTERFACE, "Percentage");

	return true;
}
