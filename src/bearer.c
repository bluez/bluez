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
#include "bluetooth/uuid.h"

#include "gdbus/gdbus.h"
#include "src/shared/util.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"

#include "log.h"
#include "error.h"
#include "adapter.h"
#include "device.h"
#include "profile.h"
#include "service.h"
#include "dbus-common.h"
#include "bearer.h"

#define DISCONNECT_TIMER	2

struct btd_bearer {
	struct btd_device *device;
	uint8_t type;
	const char *path;
	unsigned int disconn_timer;
	struct queue *disconnects; /* disconnects message */

	/* Connect() is defined as a single in-flight operation. To preserve
	 * the API semantics of org.bluez.Device1.Connect(), we do not queue
	 * additional connect messages.
	 */
	DBusMessage *connect; /* connect message */
};

static void bearer_free_dbus_message(void *data)
{
	dbus_message_unref((DBusMessage *)data);
}

static void bearer_free(void *data)
{
	struct btd_bearer *bearer = data;

	free(bearer);
}

static void bearer_disconnect_service(struct btd_service *service,
						void *user_data)
{
	uint8_t bdaddr_type = *(uint8_t *)user_data;
	struct btd_profile *profile = btd_service_get_profile(service);
	struct btd_device *device = btd_service_get_device(service);

	if (!profile || !device)
		return;

	if (bdaddr_type == BDADDR_BREDR) {
		if (profile->bearer == BTD_PROFILE_BEARER_LE)
			return;
	} else {
		if (profile->bearer == BTD_PROFILE_BEARER_BREDR)
			return;
	}

	DBG("Disconnecting profile %s for bearer addr type %u",
	profile->name ?: "(unknown)", bdaddr_type);

	btd_service_disconnect(service);
}


static bool bearer_disconnect_link(gpointer user_data)
{
	struct btd_bearer *bearer = user_data;
	struct btd_device *device = bearer->device;

	bearer->disconn_timer = 0;

	if (btd_device_bdaddr_type_connected(device, bearer->type))
		btd_adapter_disconnect_device(device_get_adapter(device),
						device_get_address(device),
						bearer->type);
	return FALSE;
}

static DBusMessage *bearer_connect(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct btd_bearer *bearer = user_data;
	struct btd_device *device = bearer->device;
	int err;

	if (btd_device_bdaddr_type_connected(device, bearer->type)) {
		if (msg)
			return btd_error_already_connected(msg);
		return NULL;
	}

	if (device_is_bonding(device, NULL)) {
		if (msg)
			return btd_error_in_progress(msg);
		return NULL;
	}

	if (device_is_connecting(device) ||
		bearer->connect) {
		if (msg)
			return btd_error_in_progress(msg);
		return NULL;
	}

	if (msg)
		bearer->connect = dbus_message_ref(msg);

	if (bearer->type == BDADDR_BREDR)
		return device_connect_profiles(device, BDADDR_BREDR,
								msg, NULL);
	else {
		btd_device_set_temporary(device, false);
		err = device_connect_le(device);
		if (err < 0)
			return btd_error_failed(msg, strerror(-err));
	}

	return NULL;
}

static DBusMessage *bearer_disconnect(DBusConnection *conn, DBusMessage *msg,
							void *user_data)
{
	struct btd_bearer *bearer = user_data;
	struct btd_device *device = bearer->device;

	if (!btd_device_bdaddr_type_connected(device, bearer->type)) {
		if (msg)
			return btd_error_not_connected(msg);
		return NULL;
	}

	/* org.bluez.Device1.Disconnect() is in progress. Since it tears down
	 * both LE and BR/EDR bearers, it takes precedence over bearer-level
	 * disconnects. Ignore any bearer-specific disconnect requests here.
	 */
	if (device_is_disconnecting(device)) {
		if (msg)
			return btd_error_in_progress(msg);
		return NULL;
	}

	if (msg)
		queue_push_tail(bearer->disconnects, dbus_message_ref(msg));

	device_cancel_bonding(device, MGMT_STATUS_DISCONNECTED);

	device_cancel_browse(device, bearer->type);

	btd_device_foreach_service(device, bearer_disconnect_service,
							&bearer->type);

	device_remove_pending_services(device, bearer->type);

	if (bearer->disconn_timer)
		return NULL;

	bearer->disconn_timer = timeout_add_seconds(DISCONNECT_TIMER,
							bearer_disconnect_link,
							bearer, NULL);

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
	bearer->disconnects = queue_new();

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

	if (bearer->disconnects) {
		queue_destroy(bearer->disconnects, bearer_free_dbus_message);
		bearer->disconnects = NULL;
	}

	if (bearer->connect) {
		dbus_message_unref(bearer->connect);
		bearer->connect = NULL;
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

void btd_bearer_connected(struct btd_bearer *bearer, int err)
{
	DBusMessage *reply;

	if (!bearer || !bearer->path)
		return;

	if (bearer->connect) {
		if (err)
			reply = bearer->type == BDADDR_BREDR ?
				btd_error_bredr_errno(bearer->connect, err) :
				btd_error_le_errno(bearer->connect, err);
		else
			reply = dbus_message_new_method_return(
							bearer->connect);

		g_dbus_send_message(btd_get_dbus_connection(), reply);
		dbus_message_unref(bearer->connect);
		bearer->connect = NULL;
	}

	g_dbus_emit_property_changed(btd_get_dbus_connection(), bearer->path,
					bearer_interface(bearer->type),
					"Connected");
}

void btd_bearer_disconnected(struct btd_bearer *bearer, uint8_t reason)
{
	const char *name;
	const char *message;
	DBusMessage *msg;
	const struct queue_entry *entry;

	if (!bearer || !bearer->path)
		return;

	if (!btd_device_is_connected(bearer->device))
		device_disconnect_watches_callback(bearer->device);

	while (!queue_isempty(bearer->disconnects)) {
		entry = queue_get_entries(bearer->disconnects);
		msg = entry->data;
		g_dbus_send_reply(btd_get_dbus_connection(), msg,
						DBUS_TYPE_INVALID);
		queue_remove(bearer->disconnects, msg);
		dbus_message_unref(msg);
	}

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
