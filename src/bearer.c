// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2025  Intel Corporation
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>

#include <glib.h>
#include <dbus/dbus.h>

#include "bluetooth/bluetooth.h"
#include "bluetooth/mgmt.h"

#include "gdbus/gdbus.h"
#include "src/shared/util.h"

#include "log.h"
#include "error.h"
#include "adapter.h"
#include "device.h"
#include "dbus-common.h"
#include "bearer.h"

struct btd_bearer {
	struct btd_device *device;
	uint8_t type;
	const char *path;
};

static void bearer_free(void *data)
{
	struct btd_bearer *bearer = data;

	free(bearer);
}

static DBusMessage *bearer_connect(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	/* TODO */
	return NULL;
}

static DBusMessage *bearer_disconnect(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	/* TODO */
	return NULL;
}

static const GDBusMethodTable bearer_methods[] = {
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("Connect", NULL, NULL,
						bearer_connect) },
	{ GDBUS_EXPERIMENTAL_ASYNC_METHOD("Disconnect", NULL, NULL,
						bearer_disconnect) },
	{}
};

static gboolean bearer_get_adapter(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	struct btd_adapter *adapter = device_get_adapter(bearer->device);
	const char *path = adapter_get_path(adapter);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);

	return TRUE;
}

static gboolean bearer_get_paired(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	dbus_bool_t paired = device_is_paired(bearer->device, bearer->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &paired);

	return TRUE;
}

static gboolean bearer_get_bonded(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	dbus_bool_t bonded = device_is_bonded(bearer->device, bearer->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &bonded);

	return TRUE;
}

static gboolean bearer_get_connected(const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct btd_bearer *bearer = data;
	dbus_bool_t connected = btd_device_bdaddr_type_connected(bearer->device,
								bearer->type);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &connected);

	return TRUE;
}

static const GDBusSignalTable bearer_signals[] = {
	{ GDBUS_SIGNAL("Disconnected",
			GDBUS_ARGS({ "name", "s" }, { "message", "s" })) },
	{ }
};

static const GDBusPropertyTable bearer_properties[] = {
	{ "Adapter", "o", bearer_get_adapter, NULL, NULL,
			G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Paired", "b", bearer_get_paired, NULL, NULL,
			G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Bonded", "b", bearer_get_bonded, NULL, NULL,
			G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{ "Connected", "b", bearer_get_connected, NULL, NULL,
			G_DBUS_PROPERTY_FLAG_EXPERIMENTAL },
	{}
};

static const char *bearer_interface(uint8_t type)
{
	if (type == BDADDR_BREDR)
		return BTD_BEARER_BREDR_INTERFACE;
	else
		return BTD_BEARER_LE_INTERFACE;
}

struct btd_bearer *btd_bearer_new(struct btd_device *device, uint8_t type)
{
	struct btd_bearer *bearer;

	bearer = new0(struct btd_bearer, 1);
	bearer->device = device;
	bearer->type = type;
	bearer->path = device_get_path(device);

	if (!g_dbus_register_interface(btd_get_dbus_connection(),
					bearer->path, bearer_interface(type),
					bearer_methods, bearer_signals,
					bearer_properties,
					bearer, bearer_free)) {
		error("Unable to register BREDR interface");
		bearer->path = NULL;
	}

	return bearer;
}

void btd_bearer_destroy(struct btd_bearer *bearer)
{
	if (!bearer)
		return;

	if (!bearer->path) {
		bearer_free(bearer);
		return;
	}

	g_dbus_unregister_interface(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type));
}

void btd_bearer_paired(struct btd_bearer *bearer)
{
	if (!bearer || !bearer->path)
		return;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Paired");
}

void btd_bearer_bonded(struct btd_bearer *bearer)
{
	if (!bearer || !bearer->path)
		return;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Bonded");
}

void btd_bearer_connected(struct btd_bearer *bearer)
{
	if (!bearer || !bearer->path)
		return;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Connected");
}

void btd_bearer_disconnected(struct btd_bearer *bearer, uint8_t reason)
{
	const char *name;
	const char *message;

	if (!bearer || !bearer->path)
		return;

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Connected");

	switch (reason) {
	case MGMT_DEV_DISCONN_UNKNOWN:
		name = "org.bluez.Reason.Unknown";
		message = "Unspecified";
		break;
	case MGMT_DEV_DISCONN_TIMEOUT:
		name = "org.bluez.Reason.Timeout";
		message = "Connection timeout";
		break;
	case MGMT_DEV_DISCONN_LOCAL_HOST:
		name = "org.bluez.Reason.Local";
		message = "Connection terminated by local host";
		break;
	case MGMT_DEV_DISCONN_REMOTE:
		name = "org.bluez.Reason.Remote";
		message = "Connection terminated by remote user";
		break;
	case MGMT_DEV_DISCONN_AUTH_FAILURE:
		name = "org.bluez.Reason.Authentication";
		message = "Connection terminated due to authentication failure";
		break;
	case MGMT_DEV_DISCONN_LOCAL_HOST_SUSPEND:
		name = "org.bluez.Reason.Suspend";
		message = "Connection terminated by local host for suspend";
		break;
	default:
		warn("Unknown disconnection value: %u", reason);
		name = "org.bluez.Reason.Unknown";
		message = "Unspecified";
	}

	g_dbus_emit_signal(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Disconnected",
					DBUS_TYPE_STRING, &name,
					DBUS_TYPE_STRING, &message,
					DBUS_TYPE_INVALID);
}
